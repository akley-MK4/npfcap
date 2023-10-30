package assembler

import (
	np "github.com/akley-MK4/npfcap/npacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/bpf"
)

func NewIPProtocolIPV4Chunk(index int) *IPProtocolIPV4Chunk {
	chunk := &IPProtocolIPV4Chunk{}
	chunk.idx = index
	return chunk
}

type IPProtocolIPV4Chunk struct {
	BaseChunk
}

func (t *IPProtocolIPV4Chunk) setCells(ipProtoList []layers.IPProtocol) error {
	t.cellLink.rest()

	t.cellLink.addCell(NewLoadAbsoluteCell(t.idx, np.IPProtocolIPV4AbsoluteOffIndex, np.IPProtoSize))
	for idx, proto := range ipProtoList {
		cell, err := NewIPProtoCell(t.idx+idx+1, proto)
		if err != nil {
			return err
		}
		t.cellLink.addCell(cell)
	}

	t.instructionsNum = t.cellLink.getLength()
	return nil
}

func (t *IPProtocolIPV4Chunk) buildInstructions(reject bool, instructions *[]bpf.Instruction, retAllowIndex int) (retErr error) {
	t.cellLink.scanCells(func(cell ICell) bool {
		if err := cell.BuildInstructions(reject, t, instructions, retAllowIndex); err != nil {
			retErr = err
			return false
		}
		return true
	})

	return
}

func CheckAndCreateIPProtoIPV4Chunk(idx int, cond *Condition) (IChunk, error) {
	if (len(cond.SrcIPV6List) > 0 || len(cond.DstIPV6List) > 0) && (len(cond.SrcIPV4List) <= 0 && len(cond.DstIPV4List) <= 0) {
		return nil, nil
	}

	if len(cond.IPProtocolList) <= 0 && len(cond.PortList) <= 0 {
		return nil, nil
	}

	var ipProtoList []layers.IPProtocol
	ipProtoList = append(ipProtoList, cond.IPProtocolList...)
	if len(ipProtoList) <= 0 {
		ipProtoList = append(ipProtoList, layers.IPProtocolTCP, layers.IPProtocolUDP)
	}

	chunk := NewIPProtocolIPV4Chunk(idx)
	if err := chunk.setCells(ipProtoList); err != nil {
		return nil, err
	}

	return chunk, nil
}
