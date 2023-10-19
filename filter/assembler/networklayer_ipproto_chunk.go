package assembler

import (
	"errors"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/bpf"
)

type IPProtoChunk struct {
	BaseChunk
}

func (t *IPProtoChunk) setCells(ipProtoList []layers.IPProtocol) error {
	return errors.New("invalid function")
}

func (t *IPProtoChunk) buildInstructions(reject bool, instructions *[]bpf.Instruction, retAllowIndex int) error {
	return nil
}

func CheckAndCreateIPProtoChunk(idx int, cond *Condition) (IChunk, error) {
	if len(cond.IPProtocolList) <= 0 && len(cond.PortList) <= 0 {
		return nil, nil
	}

	var ipProtoList []layers.IPProtocol
	ipProtoList = append(ipProtoList, cond.IPProtocolList...)
	if len(ipProtoList) <= 0 {
		ipProtoList = append(ipProtoList, layers.IPProtocolTCP, layers.IPProtocolUDP)
	}

	chunk := &IPProtoChunk{
		BaseChunk{
			idx: idx + 1,
		},
	}
	if err := chunk.setCells(ipProtoList); err != nil {
		return nil, err
	}

	return chunk, nil
}

type IPProtoCell struct {
	BaseCell
	Proto layers.IPProtocol
}

func (t *IPProtoCell) BuildInstructions(reject bool, chunk IChunk, instructions *[]bpf.Instruction, retAllowIndex int) error {

	return nil
}
