package main

import (
	log "github.com/sirupsen/logrus"
	"time"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
    "sync"
    "net"
)

const FLOW_LOG_INTERVAL = 5 * time.Second
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
    device                                        = "wlp1s0"
    snapshot_len    int32  = 1024
    promiscuous                    = false
    err             error
    handle          *pcap.Handle
    flowHandlers    = new(sync.Map)
    userAggregators = new(sync.Map)
)

var privateIPBlocks []*net.IPNet

func init() {
    for _, cidr := range []string {
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
    } {
        _, block, _ := net.ParseCIDR(cidr)
        privateIPBlocks = append(privateIPBlocks, block)
    }
}

func isPrivateIP(ip net.IP) bool {
    for _, block := range privateIPBlocks {
        if block.Contains(ip) {
            return true
        }
    }
    return !net.IP.IsGlobalUnicast(ip)
}

// Deployment specific logic to determine if traffic is from a user.
func isUser(endpoint gopacket.Endpoint) bool {
    ip := net.ParseIP(endpoint.String())
    if ip == nil {
        log.WithField("Endpoint", endpoint).Error("Endpoint is not IP parseable")
        return false
    }

    _, userBlock, _ := net.ParseCIDR("192.168.151.0/24")

    return userBlock.Contains(ip)
}

// Deployment specific logic to determine if traffic is local only
func isLocal(endpoint gopacket.Endpoint) bool {
    ip := net.ParseIP(endpoint.String())
    if ip == nil {
        log.WithField("Endpoint", endpoint).Error("Endpoint is not IP parseable")
        return false
    }
    return isPrivateIP(ip)
}

// Parse the network layer of the packet and push it to the appropriate channel for each flow.
func classifyPacket(packet gopacket.Packet, wg *sync.WaitGroup) {
    if packet.LinkLayer().LayerType() != layers.LayerTypeEthernet {
        log.WithField("LayerType", packet.LinkLayer().LayerType()).Info("Non-ethernet is not supported")
        return
    }

    if packet.NetworkLayer() == nil {
        ethernetPacket, _ := packet.LinkLayer().(*layers.Ethernet)
        log.WithField("EthernetType", ethernetPacket.EthernetType).Info(
            "Packet is link layer only and will not be counted")
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
    for {
        select {
        case newBytes := <-ch:
            byteCount += newBytes
            // TODO(matt9j) Need to dispatch out to the appropriate user based on traffic type!
        case <-time.After(FLOW_LOG_INTERVAL):
            if byteCount == 0 {
                // Reclaim handlers and channels from flows that have finished.
                log.WithField("Flow", flow).Info("Reclaiming")
                return
            }
            // TODO(matt9j) Report the flow statistics to the database for long term logging
            log.WithField("Flow", flow).Info(byteCount)
            byteCount = 0
        }

    }
}

func sendToUserAggregator(user gopacket.Endpoint, event usageEvent, wg *sync.WaitGroup) {
    var userChannel interface{}
    var ok bool
    userChannel, ok = userAggregators.Load(user)

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

}

func main() {
    // Open device
    //handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
    var processingGroup sync.WaitGroup

    // Open file
    handle, err = pcap.OpenOffline("testdata/small.pcap")
    if err != nil {
        log.Fatal(err)
    }
    defer handle.Close()

    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSource.Packets() {
        // Do something with a packet here.
        classifyPacket(packet, &processingGroup)
    }

    processingGroup.Wait()
}
