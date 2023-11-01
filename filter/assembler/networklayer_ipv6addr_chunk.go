package assembler

import (
	np "github.com/akley-MK4/npfcap/npacket"
	"golang.org/x/net/bpf"
	"net"
)

type IPV6AddrChunk struct {
	BaseChunk
	newCellFunc func(index int, nIP net.IP) ICell
}

func (t *IPV6AddrChunk) setCells(nIPV6List []net.IP) error {
	t.cellLink.rest()
	for i, nIP := range nIPV6List {
		cellIdx := t.idx + (i * np.IPV6ValuePartsNum * np.IPV6AddrCellInstrNum)
		t.cellLink.addCell(t.newCellFunc(cellIdx, nIP))
	}

	t.instructionsNum = t.cellLink.getLength() * np.OneIPV6AddrInstrNum
	return nil
}

func (t *IPV6AddrChunk) buildInstructions(reject bool, instructions *[]bpf.Instruction, retAllowIndex int) (retErr error) {
	t.cellLink.scanCells(func(cell ICell) bool {
		if err := cell.BuildInstructions(reject, t, instructions, retAllowIndex); err != nil {
			retErr = err
			return false
		}
		return true
	})

	return
}

func NewSrcIPV6AddrChunk(index int) *SrcIPV6AddrChunk {
	chunk := &SrcIPV6AddrChunk{}
	chunk.idx = index
	chunk.newCellFunc = NewSrcIPV6AddrValueCell

	return chunk
}

type SrcIPV6AddrChunk struct {
	IPV6AddrChunk
}

func CheckAndCreateSrcIPV6AddrChunk(idx int, cond *Condition) (IChunk, error) {
	if len(cond.SrcIPV6List) <= 0 {
		return nil, nil
	}

	chunk := NewSrcIPV6AddrChunk(idx)
	if err := chunk.setCells(cond.SrcIPV6List); err != nil {
		return nil, err
	}

	return chunk, nil
}

func NewDstIPV6AddrChunk(index int) *DstIPV6AddrChunk {
	chunk := &DstIPV6AddrChunk{}
	chunk.idx = index
	chunk.newCellFunc = NewDstIPV6AddrValueCell

	return chunk
}

type DstIPV6AddrChunk struct {
	IPV6AddrChunk
}

func CheckAndCreateDstIPV6AddrChunk(idx int, cond *Condition) (IChunk, error) {
	if len(cond.DstIPV6List) <= 0 {
		return nil, nil
	}

	chunk := NewDstIPV6AddrChunk(idx)
	if err := chunk.setCells(cond.DstIPV6List); err != nil {
		return nil, err
	}

	return chunk, nil
}
