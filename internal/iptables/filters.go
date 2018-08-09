package iptables

import (
    "os/exec"
    "net"
    log "github.com/sirupsen/logrus"
)

func EnableForwardingFilter(addr net.IP) {
    // Check if the rule is already present before adding another one! IPTables holds state outside the lifetime of this
    // program. The `-C` option will return success if the rule is present, and 1 if it is not.
    cmd := exec.Command("iptables", "-C", "FORWARD", "-s", addr.String(), "-j", "REJECT")
    err := cmd.Run()
    if err == nil {
        // The rule is already present in the chain! Do not double insert, as this will require delete to run multiple
        // times and break the delete implementation
        log.WithField("address", addr).Warn("Filter rule already present.")
        return
    }

    cmd = exec.Command("iptables", "-I", "FORWARD", "-s", addr.String(), "-j", "REJECT")
    //cmd := exec.Command("echo", "Filtered IP " + addr.String())
    output, err := cmd.CombinedOutput()
    if err != nil {
        log.WithError(err).Error("Failed to run ip address insert filter and capture output")
    }

    if len(output) != 0 {
        log.Warnf("Iptables generated output: %s", output)
    }
}

func DisableForwardingFilter(addr net.IP) {
    cmd := exec.Command("iptables", "-D", "FORWARD", "-s", addr.String(), "-j", "REJECT")
    //cmd := exec.Command("echo", "Unfiltered IP " + addr.String())
    output, err := cmd.CombinedOutput()
    if err != nil {
        log.WithError(err).Error("Failed to run ip address remove filter and capture output")
    }

    if len(output) != 0 {
        log.Warnf("Iptables generated output: %s", output)
    }
}
