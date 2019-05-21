package pcef

import (
	"net"
)

type PCEFInterface interface {
	ForwardingFilterPresent(addr net.IP) bool
	EnableForwardingFilter(addr net.IP)
	DisableForwadingFilter(addr net.IP)
}
