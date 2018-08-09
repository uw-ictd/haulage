package iptables

import (
    "os/exec"
    "net"
    log "github.com/sirupsen/logrus"
)

func EnableForwardingFilter(addr net.IP) {
    //cmd := exec.Command("iptables", "-I", "FORWARD", "-s", addr.String(), "-j", "REJECT")
    cmd := exec.Command("echo", "Filtered IP " + addr.String())
    output, err := cmd.CombinedOutput()
    if err != nil {
        log.WithError(err).Error("Failed to run ip address insert filter and capture output")
    }

    if len(output) != 0 {
        log.Warnf("Iptables generated output: %s", output)
    }
}

func DisableForwardingFilter(addr net.IP) {
    //cmd := exec.Command("iptables", "-D", "FORWARD", "-s", addr.String(), "-j", "REJECT")
    cmd := exec.Command("echo", "Unfiltered IP " + addr.String())
    output, err := cmd.CombinedOutput()
    if err != nil {
        log.WithError(err).Error("Failed to run ip address remove filter and capture output")
    }

    if len(output) != 0 {
        log.Warnf("Iptables generated output: %s", output)
    }
}
