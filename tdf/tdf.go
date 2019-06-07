package main

import (
	"context"
	"encoding/binary"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	log "github.com/sirupsen/logrus"
	"github.com/uw-ictd/haulage/tdf/internal/classify"
	"github.com/uw-ictd/haulage/tdf/internal/types"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

type FlowType int

const (
	LOCAL_UP   FlowType = 0
	LOCAL_DOWN FlowType = 1
	EXT_UP     FlowType = 2
	EXT_DOWN   FlowType = 3
)

const (
	SNAPSHOT_LEN     int32 = 1024
	PROMISCUOUS            = true
	SNAPSHOT_TIMEOUT       = 5 * time.Second
)

type UsageEvent struct {
	trafficType FlowType
	amount      int
}

type FlowEvent struct {
	flow   classify.FiveTuple
	amount int
}

type TrafficDetector struct {
	handle          *pcap.Handle
	waitGroup       sync.WaitGroup
	flowHandlers    map[classify.FiveTuple]chan FlowEvent
	flowMux         sync.Mutex
	userAggregators map[gopacket.Endpoint]chan UsageEvent
	usageMux        sync.Mutex
	flowLogInterval time.Duration
	userLogInterval time.Duration
}

type Config struct {
	FlowLogInterval time.Duration `yaml:"flowLogInterval"`
	UserLogInterval time.Duration `yaml:"userLogInterval"`
	Interface       string        `yaml:"interface"`
}

/** Creates a Traffic Detector based around the given config */
func CreateTDF(config Config, waitGroup sync.WaitGroup) (TrafficDetector, error) {
	var tdf TrafficDetector
	tdf.flowLogInterval = config.FlowLogInterval
	tdf.userLogInterval = config.UserLogInterval
	tdf.flowHandlers = make(map[classify.FiveTuple]chan FlowEvent)
	tdf.userAggregators = make(map[gopacket.Endpoint]chan UsageEvent)
	// Open device
	// handle, err := pcap.OpenLive(config.Interface, SNAPSHOT_LEN, PROMISCUOUS, SNAPSHOT_TIMEOUT)
	// Open file
	handle, err := pcap.OpenOffline("testdata/large.pcap")
	if err != nil {
		log.Fatal(err)
	} else {
		tdf.handle = handle
	}
	return tdf, err
}

/** Starts collecting packets from the Interface given when created */
func (tdf *TrafficDetector) StartDetection() {
	// Skip directly to decoding IPv4 on the tunneled packets.
	// TODO Make this smarter to use ip4 or ip6 based on the tunnel address and type?
	layers.LinkTypeMetadata[12] = layers.EnumMetadata{
		DecodeWith: layers.LayerTypeIPv4,
		Name:       "tun",
	}

	log.Info("Beginning packet by packet operation")
	packetSource := gopacket.NewPacketSource(tdf.handle, tdf.handle.LinkType())
	for packet := range packetSource.Packets() {
		// Do something with a packet here.
		tdf.classifyPacket(packet)
	}
}

// Parse the network layer of the packet and push it to the appropriate channel
// for each flow.
func (tdf *TrafficDetector) classifyPacket(packet gopacket.Packet) {
	// Only support ethernet link layers.
	if (packet.LinkLayer() != nil) &&
		(packet.LinkLayer().LayerType() != layers.LayerTypeEthernet) {
		log.WithField("LayerType", packet.LinkLayer().LayerType()).Info("Non-ethernet is not supported")
		return
	}

	if packet.NetworkLayer() == nil {
		log.WithField("Packet", packet).Debug("Packet has no network layer and will not be counted")
		return
	}

	if packet.TransportLayer() == nil {
		log.WithField("Packet", packet).Debug("Packet has no transport layer and will not be counted")
		return
	}

	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		log.Debug("Error decoding some part of the packet:", err)
	}

	// 255 is IANA reserved, and if logged will signal an unhandled network protocol.
	var transportProtocol uint8 = 255
	netLayer := packet.NetworkLayer()

	if netLayer.LayerType() == layers.LayerTypeIPv4 {
		ipPacket, ok := netLayer.(*layers.IPv4)
		if !ok {
			log.Error("IPv4 Decoding Failed")
			return
		}

		transportProtocol = uint8(ipPacket.Protocol)

	} else if netLayer.LayerType() == layers.LayerTypeIPv6 {
		ipPacket, ok := netLayer.(*layers.IPv6)
		if !ok {
			log.Error("IPv6 Decoding Failed")
			return
		}

		transportProtocol = uint8(ipPacket.NextHeader)
	} else {
		// Packet isn't IP4 or IP6
		log.WithField("LayerType", netLayer.LayerType()).Warning("Non-IP is not supported")
	}

	flow := classify.FiveTuple{
		Network:           packet.NetworkLayer().NetworkFlow(),
		Transport:         packet.TransportLayer().TransportFlow(),
		TransportProtocol: transportProtocol,
	}

	bytesUsed := len(packet.NetworkLayer().LayerPayload())
	tdf.sendToFlowHandler(FlowEvent{flow, bytesUsed})
	// This was logging DNS messages to the SQL database, which is not part of
	// the tdf functionality.  Maybe NetFlow will do similar logging?
	//
	// var msg classify.DnsMsg
	// if err := classify.ParseDns(packet, flow, &msg); err == nil {
	// 	// Errors are expected, since most packets are not valid DNS.
	// 	LogDNS(&msg, tdf.waitGroup)
	// }
}

func (tdf *TrafficDetector) sendToFlowHandler(event FlowEvent) {
	tdf.flowMux.Lock()
	canonicalFlow := event.flow.MakeCanonical()
	flowChannel, channelExists := tdf.flowHandlers[canonicalFlow]

	if !channelExists {
		flowChannel = make(chan FlowEvent)
		tdf.flowHandlers[canonicalFlow] = make(chan FlowEvent)
		tdf.waitGroup.Add(1)
		go tdf.flowHandler(flowChannel, event.flow)
	}
	tdf.flowMux.Unlock()

	flowChannel <- event
}

func (tdf *TrafficDetector) flowHandler(ch chan FlowEvent, flow classify.FiveTuple) {
	defer tdf.cleanupFlow(ch, flow)
	// The flow logger will receive events from both A->B and B->A
	endNetA := flow.Network.Src()
	endTransportA := flow.Transport.Src()
	bytesAB := 0
	bytesBA := 0
	ticker := time.NewTicker(tdf.flowLogInterval)
	defer ticker.Stop()

	for {
		select {
		case event := <-ch:
			if (event.flow.Network.Src() == endNetA) &&
				(event.flow.Transport.Src() == endTransportA) {
				bytesAB += event.amount
			} else {
				bytesBA += event.amount
			}
			// Usage events are based on network layer address (IP) only for now.

			tdf.generateUsageEvents(event.flow.Network, event.amount)

		case <-ticker.C:
			if (bytesAB == 0) && (bytesBA == 0) {
				// Reclaim handlers and channels from flows idle an entire period.
				log.WithField("Flow", flow).Debug("Reclaiming")
				return
			}

			log.WithField("Flow", flow).Debug(bytesAB, bytesBA)
			bytesAB = 0
			bytesBA = 0
		}
	}
}

func (tdf *TrafficDetector) cleanupFlow(ch chan FlowEvent, flow classify.FiveTuple) {
	tdf.waitGroup.Done()
	close(ch)
	tdf.flowMux.Lock()
	delete(tdf.flowHandlers, flow.MakeCanonical())
	tdf.flowMux.Unlock()
}

func (tdf *TrafficDetector) generateUsageEvents(flow gopacket.Flow, amount int) {
	if classify.User(flow.Src()) {
		if classify.Local(flow.Dst()) {
			tdf.sendToUserAggregator(flow.Src(), UsageEvent{LOCAL_UP, amount})
		} else {
			tdf.sendToUserAggregator(flow.Src(), UsageEvent{EXT_UP, amount})
		}
	}

	if classify.User(flow.Dst()) {
		if classify.Local(flow.Src()) {
			tdf.sendToUserAggregator(flow.Dst(), UsageEvent{LOCAL_DOWN, amount})
		} else {
			tdf.sendToUserAggregator(flow.Dst(), UsageEvent{EXT_DOWN, amount})
		}
	}
}

func (tdf *TrafficDetector) sendToUserAggregator(user gopacket.Endpoint, event UsageEvent) {
	tdf.usageMux.Lock()
	userChannel, ok := tdf.userAggregators[user]

	if !ok {
		userChannel = make(chan UsageEvent)
		tdf.userAggregators[user] = userChannel
		tdf.waitGroup.Add(1)
		go tdf.aggregateUser(userChannel, user)
	}
	tdf.usageMux.Unlock()
	userChannel <- event
}

func (tdf *TrafficDetector) aggregateUser(ch chan UsageEvent, user gopacket.Endpoint) {
	defer tdf.cleanupAggregator(ch, user)
	localUpBytes := int64(0)
	localDownBytes := int64(0)
	extUpBytes := int64(0)
	extDownBytes := int64(0)
	logTick := time.NewTicker(tdf.userLogInterval)
	defer logTick.Stop()

	// Keep track of the user and how much data they've used
	customContext := types.UserContext{DataBalance: 0}
	//customContext.Init(user)

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
				tdf.sendUsage(user, localUpBytes, localDownBytes, extUpBytes, extDownBytes)
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
			tdf.sendUsage(user, localUpBytes, localDownBytes, extUpBytes, extDownBytes)
			localUpBytes = 0
			localDownBytes = 0
			extUpBytes = 0
			extDownBytes = 0
		}
	}
}

func (tdf *TrafficDetector) sendUsage(user gopacket.Endpoint, localUpBytes int64, localDownBytes int64, extUpBytes int64, extDownBytes int64) {
	packet := radius.New(radius.CodeAccessRequest, []byte(`secret`))
	rfc2865.UserName_SetString(packet, user.String())
	dataBytes := make([]byte, 32)
	binary.LittleEndian.PutUint64(dataBytes[0:8], uint64(localUpBytes))
	binary.LittleEndian.PutUint64(dataBytes[8:16], uint64(localDownBytes))
	binary.LittleEndian.PutUint64(dataBytes[16:24], uint64(extUpBytes))
	binary.LittleEndian.PutUint64(dataBytes[24:32], uint64(extDownBytes))
	rfc2865.State_Set(packet, dataBytes)
	_, err := radius.Exchange(context.Background(), packet, "localhost:1812")
	if err != nil {
		log.Fatal(err)
	}
}

func (tdf *TrafficDetector) cleanupAggregator(ch chan UsageEvent, user gopacket.Endpoint) {
	tdf.waitGroup.Done()
	close(ch)
	tdf.usageMux.Lock()
	delete(tdf.userAggregators, user)
	tdf.usageMux.Unlock()
}

func (tdf *TrafficDetector) Close() {
	tdf.handle.Close()
}
