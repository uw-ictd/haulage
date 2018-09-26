package main

import (
	"database/sql"
	_ "github.com/go-sql-driver/mysql"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	log "github.com/sirupsen/logrus"
	"github.com/uw-ictd/haulage/internal/classify"
	"github.com/uw-ictd/haulage/internal/iptables"
	"github.com/uw-ictd/haulage/internal/storage"
	"net"
	"os"
	"os/signal"
	"sync"
	"time"
)

// The flow logs generate new records each time, and should be on a longer timer to save disk space.
const FLOW_LOG_INTERVAL = 20 * time.Minute

// User logs result in an update and can occur more frequently.
const USER_LOG_INTERVAL = 1 * time.Minute

const REENABLE_USER_POLL_INTERVAL = 5 * time.Second

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
	flow   gopacket.Flow
	amount int
}

var (
	device                = "gtp0"
	snapshot_len    int32 = 1024
	promiscuous           = true
	snapshotTimeout       = 5 * time.Second
	err             error
	handle          *pcap.Handle
	flowHandlers    = new(sync.Map)
	userAggregators = new(sync.Map)
	db              *sql.DB
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

	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		log.Error("Error decoding some part of the packet:", err)
	}

	sendToFlowHandler(flowEvent{packet.NetworkLayer().NetworkFlow(), len(packet.NetworkLayer().LayerPayload())}, wg)
}

func sendToFlowHandler(event flowEvent, wg *sync.WaitGroup) {
	if flowChannel, ok := flowHandlers.Load(event.flow.FastHash()); ok {
		flowChannel.(chan flowEvent) <- event
	} else {
		// Attempt to allocate a new flow channel atomically. This can race between the check above and when the channel
		// is created.
		newChannel, existed := flowHandlers.LoadOrStore(event.flow.FastHash(), make(chan flowEvent))
		if !existed {
			wg.Add(1)
			go flowHandler(newChannel.(chan flowEvent), event.flow, wg)
		}
		newChannel.(chan flowEvent) <- event
	}
}

func flowHandler(ch chan flowEvent, flow gopacket.Flow, wg *sync.WaitGroup) {
	defer wg.Done()
	defer close(ch)
	defer flowHandlers.Delete(flow.FastHash())
	// The flow logger will receive events from both A->B and B->A
	endA := flow.Src()
	bytesAB := 0
	bytesBA := 0
	intervalStart := time.Now()
	logTime := time.After(FLOW_LOG_INTERVAL)
	for {
		select {
		case event := <-ch:
			if event.flow.Src() == endA {
				bytesAB += event.amount
			} else {
				bytesBA += event.amount
			}
			generateUsageEvents(event.flow, event.amount, wg)
		case <-logTime:
			if (bytesAB == 0) && (bytesBA == 0) {
				// Reclaim handlers and channels from flows idle an entire period.
				log.WithField("Flow", flow).Info("Reclaiming")
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
			logTime = time.After(FLOW_LOG_INTERVAL)
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
	logTime := time.After(USER_LOG_INTERVAL)

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
		case <-logTime:
			logTime = time.After(USER_LOG_INTERVAL)
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

func main() {
	// Open device
	log.Info("Starting haulage")
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, snapshotTimeout)
	// Open file
	// handle, err = pcap.OpenOffline("testdata/small.pcap")
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	params := Parameters{"colte_db", "colte", "horse", FLOW_LOG_INTERVAL, USER_LOG_INTERVAL, REENABLE_USER_POLL_INTERVAL}
	var ctx Context
	OnStart(ctx, params)
	defer Cleanup(ctx)

	var processingGroup sync.WaitGroup

	// Setup interrupt catching to cleanup connections
	sigintChan := make(chan os.Signal, 1)
	signal.Notify(sigintChan, os.Interrupt)
	go func() {
		<-sigintChan
		handle.Close()
		OnStop(ctx)
		<-sigintChan
		log.Fatal("Terminating Uncleanly! Connections may be orphaned.")
	}()

	// Skip directly to decoding IPv4 on the tunneled packets.
	// TODO(matt9j) Make this smarter to use ip4 or ip6 based on the tunnel address and type?
	layers.LinkTypeMetadata[12] = layers.EnumMetadata{
		DecodeWith: layers.LayerTypeIPv4,
		Name:       "tun",
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Do something with a packet here.
		classifyPacket(packet, &processingGroup)
	}

	processingGroup.Wait()
}
