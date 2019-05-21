package classify

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	log "github.com/sirupsen/logrus"

	"fmt"
	"net"
	"time"
)

type DnsMsg struct {
	Timestamp       time.Time
	Flow            FiveTuple
	DnsQuery        string
	DnsOpCode       uint16
	DnsResponseCode uint16
	NumberOfAnswers uint16
	DnsAnswerTTL    []uint32
	DnsAnswer       []net.IP
}

// Attempts to parse a dns payload from the provided packet.
//
// Nominally returns a parsed DnsMsg struct with the DNS information.
// If no DNS information is detected in the packet returns a NoDNSError.
// Otherwise returns generic error codes for parsing failure.
func ParseDns(pkt gopacket.Packet, flow FiveTuple, msg *DnsMsg) error {
	dnsLayer := pkt.Layer(layers.LayerTypeDNS)

	if dnsLayer == nil {
		return fmt.Errorf("No DNS payload detected")
	}

	var dns layers.DNS
	var df gopacket.DecodeFeedback
	err := dns.DecodeFromBytes(dnsLayer.LayerContents(), df)
	if err != nil {
		return err
	}

	if len(dns.Questions) != 1 {
		log.Warningf("DNS layer is malformed with %d questions", len(dns.Questions))
		return fmt.Errorf("DNS layer is malformed")
	}

	dnsQuestion := dns.Questions[0]

	msg.Timestamp = time.Now()
	msg.Flow = flow
	msg.DnsQuery = string(dnsQuestion.Name)
	msg.DnsOpCode = uint16(dns.OpCode)
	msg.DnsResponseCode = uint16(dns.ResponseCode)
	msg.NumberOfAnswers = dns.ANCount

	if dns.ANCount > 0 {
		for _, dnsAnswer := range dns.Answers {
			if dnsAnswer.IP.String() != "<nil>" {
				msg.DnsAnswerTTL = append(msg.DnsAnswerTTL, dnsAnswer.TTL)
				msg.DnsAnswer = append(msg.DnsAnswer, dnsAnswer.IP)
			}
		}
	}
	return nil
}