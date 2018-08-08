package classify

import (
    "github.com/google/gopacket"
    log "github.com/sirupsen/logrus"
    "net"
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
func User(endpoint gopacket.Endpoint) bool {
    ip := net.ParseIP(endpoint.String())
    if ip == nil {
        log.WithField("Endpoint", endpoint).Error("Endpoint is not IP parseable")
        return false
    }

    // Exclude specific IPs assigned to our network hardware in the user subnet.
    if ip.Equal(net.ParseIP("192.168.151.1")) {
        return false
    }

    _, userBlock, _ := net.ParseCIDR("192.168.151.0/24")

    return userBlock.Contains(ip)
}

// Deployment specific logic to determine if traffic is local only
func Local(endpoint gopacket.Endpoint) bool {
    ip := net.ParseIP(endpoint.String())
    if ip == nil {
        log.WithField("Endpoint", endpoint).Error("Endpoint is not IP parseable")
        return false
    }
    return isPrivateIP(ip)
}
