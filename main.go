package main

import (
	log "github.com/sirupsen/logrus"
	"time"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
    "sync"
    _ "github.com/go-sql-driver/mysql"
    "database/sql"
    "github.com/uw-ictd/haulage/internal/classify"
)

const FLOW_LOG_INTERVAL = 5 * time.Second
const USER_LOG_INTERVAL = 10 * time.Second

type FlowType int
const (
    LOCAL_UP FlowType = 0
    LOCAL_DOWN FlowType = 1
    EXT_UP FlowType = 2
    EXT_DOWN FlowType = 3
)

type usageEvent struct {
    trafficType FlowType
    amount int
}

var (
    device          = "gtp0"
    snapshot_len    int32  = 1024
    promiscuous     = true
    snapshotTimeout = 5 * time.Second
    err             error
    handle          *pcap.Handle
    flowHandlers    = new(sync.Map)
    userAggregators = new(sync.Map)
)

// Parse the network layer of the packet and push it to the appropriate channel for each flow.
func classifyPacket(packet gopacket.Packet, wg *sync.WaitGroup) {
    // Only support ethernet link layers.
    if (packet.LinkLayer() != nil) && (packet.LinkLayer().LayerType() != layers.LayerTypeEthernet){
        log.WithField("LayerType", packet.LinkLayer().LayerType()).Info("Non-ethernet is not supported")
        return
    }

    if packet.NetworkLayer() == nil {
        log.WithField("Packet", packet).Info(
            "Packet has no network layer and will not be counted")
        return
    }

    // Check for errors
    if err := packet.ErrorLayer(); err != nil {
        log.Error("Error decoding some part of the packet:", err)
    }

    sendToFlowHandler(packet, wg)
}

func sendToFlowHandler(packet gopacket.Packet, wg *sync.WaitGroup) {
    if flowChannel, ok := flowHandlers.Load(packet.NetworkLayer().NetworkFlow()); ok {
        flowChannel.(chan int) <- len(packet.NetworkLayer().LayerPayload())
    } else {
        // Attempt to allocate a new flow channel atomically. This can race between the check above and when the channel
        // is created.
        newChannel, existed := flowHandlers.LoadOrStore(packet.NetworkLayer().NetworkFlow(), make(chan int))
        if !existed {
            wg.Add(1)
            go flowHandler(newChannel.(chan int), packet.NetworkLayer().NetworkFlow(), wg)
        }
        newChannel.(chan int) <- len(packet.NetworkLayer().LayerPayload())
    }
}

func flowHandler(ch chan int, flow gopacket.Flow, wg *sync.WaitGroup) {
    defer wg.Done()
    defer close(ch)
    defer flowHandlers.Delete(flow)
    byteCount := 0
    logTime := time.After(FLOW_LOG_INTERVAL)
    for {
        select {
        case newBytes := <-ch:
            byteCount += newBytes
            generateUsageEvents(flow, newBytes, wg)
        case <-logTime:
            // TODO(matt9j) Report the flow statistics to the database for long term logging
            // TODO(matt9j) Ensure the flow has a consistent direction with appropriate up/down assigned
            logTime = time.After(FLOW_LOG_INTERVAL)
            if byteCount == 0 {
                // Reclaim handlers and channels from flows idle an entire period.
                log.WithField("Flow", flow).Info("Reclaiming")
                return
            }
            log.WithField("Flow", flow).Info(byteCount)
            byteCount = 0
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
    localUpBytes := 0
    localDownBytes := 0
    extUpBytes := 0
    extDownBytes := 0
    logTime := time.After(USER_LOG_INTERVAL)

    for {
        select {
        case newEvent := <-ch:
            switch newEvent.trafficType {
            case LOCAL_UP:
                localUpBytes += newEvent.amount
            case LOCAL_DOWN:
                localDownBytes += newEvent.amount
            case EXT_UP:
                extUpBytes += newEvent.amount
            case EXT_DOWN:
                extDownBytes += newEvent.amount
            }
        case <-logTime:
            logTime = time.After(USER_LOG_INTERVAL)
            if (localUpBytes == 0) && (localDownBytes == 0) && (extUpBytes == 0) && (extDownBytes == 0) {
                // Reclaim handlers and channels from users that have finished.
                log.WithField("User", user).Info("Reclaiming")
                return
            }
            // TODO(matt9j) Report the user statistics to the database for long term logging
            log.WithField("User", user).Info(localUpBytes, localDownBytes, extUpBytes, extDownBytes)
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
    //handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, snapshotTimeout)
    // Open file
    handle, err = pcap.OpenOffline("testdata/testDump.pcap")
    if err != nil {
        log.Fatal(err)
    }
    defer handle.Close()

    db, err := sql.Open("mysql", "colte:horse@/colte_db")
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()

    err = db.Ping()
    if err != nil {
        log.Fatal(err)
    }

    trx, err := db.Begin()
    if err!= nil {
        // TODO(matt9j) put a more verbose log message here
        log.Fatal(err)
    }

    statement, err := trx.Prepare("select imsi from static_ips where ip=?")
    if err != nil {
        log.Fatal(err)
    }

    var imsi int64
    err = statement.QueryRow("192.168.151.2").Scan(&imsi)
    if err != nil {
        // TODO(matt9j) Handle no row returned b/c the IP is not known
        log.Fatal(err)
    }

    statement2, err := trx.Prepare("SELECT raw_down, raw_up, data_balance, balance, bridged, enabled FROM customers WHERE imsi =? ")
    if err != nil {
        log.Fatal(err)
    }

    var (
        raw_down int64
        raw_up int64
        data_balance int64
        balance float32
        bridged bool
        enabled bool
    )

    err = statement2.QueryRow(imsi).Scan(&raw_down, &raw_up, &data_balance, &balance, &bridged, &enabled)
    if err!= nil {
        // TODO(matt9j) put a more verbose log message here
        log.Fatal(err)
    }

    log.Info(imsi)
    log.Info(raw_up, raw_down)

    trx.Exec("UPDATE customers SET raw_down = ?, raw_up = ?, data_balance = ?, enabled = ?, bridged = ? WHERE imsi = ?",
        raw_down + 10, raw_up + 10, data_balance - 10, enabled, bridged, imsi)

    trx.Commit()

    var rawResultUp int64
    var rawResultDown int64
    err = db.QueryRow("SELECT raw_down, raw_up FROM customers WHERE imsi =? ", imsi).Scan(&rawResultDown, &rawResultUp)
    if err!= nil {
        // TODO(matt9j) put a more verbose log message here
        log.Fatal(err)
    }

    log.Warn(rawResultUp, rawResultDown)

    var processingGroup sync.WaitGroup

    // Skip directly to decoding IPv4 on the tunneled packets.
    // TODO(matt9j) Make this smarter to use ip4 or ip6 based on the tunnel address and type?
    layers.LinkTypeMetadata[12] = layers.EnumMetadata{
        DecodeWith: layers.LayerTypeIPv4,
        Name: "tun",
    }

    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSource.Packets() {
        // Do something with a packet here.
        classifyPacket(packet, &processingGroup)
    }

    processingGroup.Wait()
}
