package assembler

import (
	"github.com/google/gopacket/layers"
	"net"
)

type Condition struct {
	Reject         bool
	SrcIPV4List    []net.IP
	DstIPV4List    []net.IP
	SrcIPV6List    []net.IP
	DstIPV6List    []net.IP
	IPProtocolList []layers.IPProtocol
	PortList       []int
}
