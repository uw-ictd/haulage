package iptables

import (
	log "github.com/sirupsen/logrus"
	"net"
	"os/exec"
	"strings"
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

	cmd := exec.Command("iptables", "-I", "FORWARD", "-s", addr.String(), "-j", "REJECT")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.WithError(err).Error("Failed to run ip address insert filter and capture output")
	}

	if len(output) != 0 {
		log.WithField("stdio", strings.TrimSpace(string(output))).Infof("Iptables generated output")
	}
}

func DisableForwardingFilter(addr net.IP) {
	cmd := exec.Command("iptables", "-D", "FORWARD", "-s", addr.String(), "-j", "REJECT")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.WithError(err).Warn("Failed to run ip address remove filter")
	}

	if len(output) != 0 {
		log.WithField("stdio", strings.TrimSpace(string(output))).Infof("Iptables generated output")
	}
}
