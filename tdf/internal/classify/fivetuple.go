package classify

import (
	"bytes"
	"encoding/binary"
	"github.com/google/gopacket"
)

// Completely describes a transport level network flow.
type FiveTuple struct {
	Network           gopacket.Flow
	Transport         gopacket.Flow
	TransportProtocol uint8
}

// True if the other FiveTuple flow is in the same bidirectional flow.
func (t FiveTuple) SameBidirectionalFlow(other FiveTuple) bool {
	// Same direction case
	if t.Network == other.Network {
		return (t.TransportProtocol == other.TransportProtocol) &&
			(t.Transport == other.Transport)
	}

	// Reverse direction case
	if t.Network.Reverse() == other.Network {
		return (t.TransportProtocol == other.TransportProtocol) &&
			(t.Transport.Reverse() == other.Transport)
	}

	return false
}

// Represent the flow in an ordered form, possibly flipping the source and destination.
//
// Two five tuples representing both directions of a flow will have the same canonical form.
func (t FiveTuple) MakeCanonical() FiveTuple {
	// Handle loopback separately to order by the Transport endpoints
	if t.Network.Src() == t.Network.Dst() {
		if t.Transport.Src().LessThan(t.Transport.Dst()) {
			return t
		}

		return FiveTuple{t.Network.Reverse(), t.Transport.Reverse(), t.TransportProtocol}
	}

	// Otherwise order by the Network layer endpoints
	if t.Network.Src().LessThan(t.Network.Dst()) {
		return t
	}

	return FiveTuple{t.Network.Reverse(), t.Transport.Reverse(), t.TransportProtocol}
}

// Extract the transport src port number from the transport flow. This may not be valid for all transports.
func (t FiveTuple) TransportSrcPort() (uint16, error) {
	return endpointToUint16(t.Transport.Src())
}

// Extract the transport dst port number from the transport flow. This may not be valid for all transports.
func (t FiveTuple) TransportDstPort() (uint16, error) {
	return endpointToUint16(t.Transport.Dst())
}

// Convert a gopacket.endpoint to a uint16
func endpointToUint16(endpoint gopacket.Endpoint) (uint16, error) {
	var result uint16
	reader := bytes.NewReader(endpoint.Raw())
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		return 0, err
	}

	return result, nil
}