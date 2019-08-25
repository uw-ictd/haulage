package main

import (
	"io/ioutil"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/jessevdk/go-flags"
	log "github.com/sirupsen/logrus"
	"github.com/uw-ictd/haulage/internal/classify"
	"gopkg.in/yaml.v2"
)

// The flow logs generate new records each time, and should be on a longer timer to save disk space.

// User logs result in an update and can occur more frequently.

type FlowType int

const (
	LOCAL_UP   FlowType = 0
	LOCAL_DOWN FlowType = 1
	EXT_UP     FlowType = 2
	EXT_DOWN   FlowType = 3
)

type usageEvent struct {
	trafficType FlowType
	amount      int
}

type flowEvent struct {
	flow   classify.FiveTuple
	amount int
}

var opts struct {
	ConfigPath string `short:"c" long:"config" description:"The path to the configuration file" required:"true" default:"/etc/haulage/config.yml"`
}

var config struct {
	FlowLogInterval time.Duration `yaml:"flowLogInterval"`
	UserLogInterval time.Duration `yaml:"userLogInterval"`
	Interface       string        `yaml:"interface"`
	Custom          CustomConfig  `yaml:"custom"`
}

var (
	ctx             Context
	snapshotLen     int32 = 1024
	promiscuous           = true
	snapshotTimeout       = 5 * time.Second
	handle          *pcap.Handle
	flowHandlers    = new(sync.Map)
	userAggregators = new(sync.Map)
)

// Parse the network layer of the packet and push it to the appropriate channel for each flow.
func classifyPacket(packet gopacket.Packet, wg *sync.WaitGroup) {
	// Only support ethernet link layers.
	if (packet.LinkLayer() != nil) && (packet.LinkLayer().LayerType() != layers.LayerTypeEthernet) {
		log.WithField("LayerType", packet.LinkLayer().LayerType()).Info("Non-ethernet is not supported")
		return
	}

	if packet.NetworkLayer() == nil {
		log.WithField("Packet", packet).Debug(
			"Packet has no network layer and will not be counted")
		return
	}

	if packet.TransportLayer() == nil {
		log.WithField("Packet", packet).Debug(
			"Packet has no transport layer and will not be counted")
		return
	}

	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		log.Debug("Error decoding some part of the packet:", err)
	}

	// 255 is IANA reserved, and if logged will signal an unhandled network protocol.
	var transportProtocol uint8 = 255
	netLayer := packet.NetworkLayer()

	if (netLayer.LayerType() != layers.LayerTypeIPv4) && (netLayer.LayerType() != layers.LayerTypeIPv6) {
		log.WithField("LayerType", netLayer.LayerType()).Warning("Non-IP is not supported")
	}

	if netLayer.LayerType() == layers.LayerTypeIPv4 {
		ipPacket, ok := netLayer.(*layers.IPv4)
		if !ok {
			log.Error("IPv4 Decoding Failed")
			return
		}

		transportProtocol = uint8(ipPacket.Protocol)
	}

	if netLayer.LayerType() == layers.LayerTypeIPv6 {
		ipPacket, ok := netLayer.(*layers.IPv6)
		if !ok {
			log.Error("IPv6 Decoding Failed")
			return
		}

		transportProtocol = uint8(ipPacket.NextHeader)
	}

	flow := classify.FiveTuple{
		Network:           packet.NetworkLayer().NetworkFlow(),
		Transport:         packet.TransportLayer().TransportFlow(),
		TransportProtocol: transportProtocol,
	}

	sendToFlowHandler(flowEvent{flow, len(packet.NetworkLayer().LayerPayload())}, wg)
	var msg classify.DnsMsg
	if err := classify.ParseDns(packet, flow, &msg); err == nil {
		// Errors are expected, since most packets are not valid DNS.
		LogDNS(&msg, wg)
	}
}

func sendToFlowHandler(event flowEvent, wg *sync.WaitGroup) {
	if flowChannel, ok := flowHandlers.Load(event.flow.MakeCanonical()); ok {
		flowChannel.(chan flowEvent) <- event
	} else {
		// Attempt to allocate a new flow channel atomically. This can race between the check above and when the channel
		// is created.
		newChannel, existed := flowHandlers.LoadOrStore(event.flow.MakeCanonical(), make(chan flowEvent))
		if !existed {
			wg.Add(1)
			go flowHandler(newChannel.(chan flowEvent), event.flow, wg)
		}
		newChannel.(chan flowEvent) <- event
	}
}

func flowHandler(ch chan flowEvent, flow classify.FiveTuple, wg *sync.WaitGroup) {
	defer wg.Done()
	defer close(ch)
	defer flowHandlers.Delete(flow.MakeCanonical())
	// The flow logger will receive events from both A->B and B->A
	endNetA := flow.Network.Src()
	endTransportA := flow.Transport.Src()
	bytesAB := 0
	bytesBA := 0
	intervalStart := time.Now()
	ticker := time.NewTicker(config.FlowLogInterval)
	defer ticker.Stop()

	for {
		select {
		case event := <-ch:
			if (event.flow.Network.Src() == endNetA) && (event.flow.Transport.Src() == endTransportA) {
				bytesAB += event.amount
			} else {
				bytesBA += event.amount
			}
			// Esther:
			// Add event amount to servicelogs table if it belongs to a service of interest.
			// Assuming only one of the src or dst can be a service.
			srcService := FindService(event.flow.Network.Src())
			dstService := FindService(event.flow.Network.Dst())
			if srcService != "" {
				LogServiceUsage(srcService, event.amount)
			}
			if dstService != "" {
				LogServiceUsage(dstService, event.amount)
			}
			// Esther: end of inserted code
			// Usage events are based on network layer address (IP) only for now.
			generateUsageEvents(event.flow.Network, event.amount, wg)
		case <-ticker.C:
			if (bytesAB == 0) && (bytesBA == 0) {
				// Reclaim handlers and channels from flows idle an entire period.
				log.WithField("Flow", flow).Debug("Reclaiming")
				return
			}

			intervalEnd := time.Now()
			wg.Add(1)
			// TODO(matt9j) Sniff and lookup the hostnames as needed.
			go LogFlowPeriodic(intervalStart, intervalEnd, flow, bytesAB, bytesBA, wg)
			intervalStart = intervalEnd
			log.WithField("Flow", flow).Debug(bytesAB, bytesBA)
			bytesAB = 0
			bytesBA = 0
		}
	}
}

func generateUsageEvents(flow gopacket.Flow, amount int, wg *sync.WaitGroup) {
	if classify.User(flow.Src()) {
		if classify.Local(flow.Dst()) {
			sendToUserAggregator(flow.Src(), usageEvent{LOCAL_UP, amount}, wg)
		} else {
			sendToUserAggregator(flow.Src(), usageEvent{EXT_UP, amount}, wg)
		}
	}

	if classify.User(flow.Dst()) {
		if classify.Local(flow.Src()) {
			sendToUserAggregator(flow.Dst(), usageEvent{LOCAL_DOWN, amount}, wg)
		} else {
			sendToUserAggregator(flow.Dst(), usageEvent{EXT_DOWN, amount}, wg)
		}
	}
}

func sendToUserAggregator(user gopacket.Endpoint, event usageEvent, wg *sync.WaitGroup) {
	userChannel, ok := userAggregators.Load(user)

	if !ok {
		// Attempt to allocate a new user channel atomically. This can race between the check above and when the channel
		// is created, hence the atomic check here.
		var existed bool
		userChannel, existed = userAggregators.LoadOrStore(user, make(chan usageEvent))
		if !existed {
			wg.Add(1)
			go aggregateUser(userChannel.(chan usageEvent), user, wg)
		}
	}

	userChannel.(chan usageEvent) <- event
}

func aggregateUser(ch chan usageEvent, user gopacket.Endpoint, wg *sync.WaitGroup) {
	defer wg.Done()
	defer close(ch)
	defer userAggregators.Delete(user)
	localUpBytes := int64(0)
	localDownBytes := int64(0)
	extUpBytes := int64(0)
	extDownBytes := int64(0)
	logTick := time.NewTicker(config.UserLogInterval)
	defer logTick.Stop()
	customContext := UserContext{DataBalance: 0}
	customContext.Init(user)

	for {
		select {
		case newEvent := <-ch:
			delta := int64(newEvent.amount)
			switch newEvent.trafficType {
			case LOCAL_UP:
				localUpBytes += delta
			case LOCAL_DOWN:
				localDownBytes += delta
			case EXT_UP:
				extUpBytes += delta
			case EXT_DOWN:
				extDownBytes += delta
			}

			// TODO(gh/8) Reduce duplication below with user context cleanup.
			if customContext.ShouldLogNow(extUpBytes + extDownBytes) {
				log.WithField("User", user).Debug(localUpBytes, localDownBytes, extUpBytes, extDownBytes)
				LogUserPeriodic(user, localUpBytes, localDownBytes, extUpBytes, extDownBytes)
				localUpBytes = 0
				localDownBytes = 0
				extUpBytes = 0
				extDownBytes = 0
			}
		case <-logTick.C:
			if (localUpBytes == 0) && (localDownBytes == 0) && (extUpBytes == 0) && (extDownBytes == 0) {
				// Reclaim handlers and channels from users that have finished.
				log.WithField("User", user).Info("Reclaiming")
				return
			}
			log.WithField("User", user).Debug(localUpBytes, localDownBytes, extUpBytes, extDownBytes)
			LogUserPeriodic(user, localUpBytes, localDownBytes, extUpBytes, extDownBytes)
			localUpBytes = 0
			localDownBytes = 0
			extUpBytes = 0
			extDownBytes = 0
		}
	}
}

func parseConfig(path string) {
	configBytes, err := ioutil.ReadFile(path)
	if err != nil {
		log.WithField("path", path).WithError(err).Fatal("Failed to load configuration")
	}

	log.Debug("Parsing" + path)
	err = yaml.Unmarshal(configBytes, &config)
	if err != nil {
		log.WithError(err).Fatal("Failed to parse configuration")
	}
}

func main() {
	log.Info("Starting haulage")

	// Setup flags
	_, err := flags.Parse(&opts)
	if err != nil {
		log.Fatal(err)
	}

	parseConfig(opts.ConfigPath)

	params := Parameters{
		config.Custom.DBLocation,
		config.Custom.DBUser,
		config.Custom.DBPass,
		config.FlowLogInterval,
		config.UserLogInterval,
		config.Custom.ReenableUserPollInterval,
	}
	log.WithField("Parameters", config).Info("Parsed parameters")

	// Open device
	//handle, err = pcap.OpenLive(config.Interface, snapshotLen, promiscuous, snapshotTimeout)
	// Open file
	log.Info("Loading from test data only")
	handle, err = pcap.OpenOffline("testdata/small.pcap")
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	log.Info("Initializing context")
	OnStart(&ctx, params)
	log.Info("Context initialization complete")
	// Esther: commented out starting the radius server.
	//start_radius_server(ctx.db)
	log.Info("Skipped radius server start")
	defer Cleanup(&ctx)
	//log.Info("Context initialization complete")

	var processingGroup sync.WaitGroup

	// Setup interrupt catching to cleanup connections
	sigintChan := make(chan os.Signal, 1)
	signal.Notify(sigintChan, os.Interrupt)
	go func() {
		<-sigintChan
		handle.Close()
		OnStop(&ctx)
		<-sigintChan
		log.Fatal("Terminating Uncleanly! Connections may be orphaned.")
	}()

	// Skip directly to decoding IPv4 on the tunneled packets.
	// TODO(matt9j) Make this smarter to use ip4 or ip6 based on the tunnel address and type?
	layers.LinkTypeMetadata[12] = layers.EnumMetadata{
		DecodeWith: layers.LayerTypeIPv4,
		Name:       "tun",
	}

	log.Info("Beginning packet by packet operation")
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Do something with a packet here.
		classifyPacket(packet, &processingGroup)
	}

	processingGroup.Wait()
}
