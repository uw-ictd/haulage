package classify

import (
	"github.com/google/gopacket"
)

// Completely describes a transport level network flow.
type FiveTuple struct {
	Network           gopacket.Flow
	Transport         gopacket.Flow
	TransportProtocol uint8
}

// True if the other FiveTuple flow is in the same bidirectional flow.
func (original FiveTuple) SameBidirectionalFlow(other FiveTuple) bool {
	// Same direction case
	if original.Network == other.Network {
		return (original.TransportProtocol == other.TransportProtocol) &&
			(original.Transport == other.Transport)
	}

	// Reverse direction case
	if original.Network.Reverse() == other.Network {
		return (original.TransportProtocol == other.TransportProtocol) &&
			(original.Transport.Reverse() == other.Transport)
	}

	return false
}

// Represent the flow in an ordered form, possibly flipping the source and destination.
//
// Two five tuples representing both directions of a flow will have the same canonical form.
func (original FiveTuple) MakeCanonical() FiveTuple {
	// Handle loopback separately to order by the Transport endpoints
	if original.Network.Src() == original.Network.Dst() {
		if original.Transport.Src().LessThan(original.Transport.Dst()) {
			return original
		}

		return FiveTuple{original.Network.Reverse(), original.Transport.Reverse(), original.TransportProtocol}
	}

	// Otherwise order by the Network layer endpoints
	if original.Network.Src().LessThan(original.Network.Dst()) {
		return original
	}

	return FiveTuple{original.Network.Reverse(), original.Transport.Reverse(), original.TransportProtocol}
}

