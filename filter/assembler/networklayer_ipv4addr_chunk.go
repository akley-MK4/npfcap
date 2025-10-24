package assembler

import (
	np "github.com/akley-MK4/npfcap/npacket"
	"golang.org/x/net/bpf"
	"net"
)

type IPV4AddrChunk struct {
	BaseChunk
	ldOff uint32
}

func (t *IPV4AddrChunk) setCells(nIPV4List []net.IP) error {
	t.cellLink.rest()
	t.cellLink.addCell(NewLoadAbsoluteCell(t.idx, t.ldOff, np.IPV4Size))
	for idx, nIP := range nIPV4List {
		t.cellLink.addCell(NewIPV4AddrValueCell(t.idx+idx+1, nIP))
	}

	t.instructionsNum = t.cellLink.getLength()
	return nil
}

func (t *IPV4AddrChunk) buildInstructions(reject bool, instructions *[]bpf.Instruction, retAllowIndex int) (retErr error) {
	t.cellLink.scanCells(func(cell ICell) bool {
		if err := cell.BuildInstructions(reject, t, instructions, retAllowIndex); err != nil {
			retErr = err
			return false
		}
		return true
	})

	return
}

func NewSrcIPV4Chunk(index int) *SrcIPV4AddrChunk {
	chunk := &SrcIPV4AddrChunk{}
	chunk.idx = index
	chunk.ldOff = np.SrcIPV4AbsoluteOffIndex
	return chunk
}

type SrcIPV4AddrChunk struct {
	IPV4AddrChunk
}

func CheckAndCreateSrcIPV4AddrChunk(idx int, cond *Condition) (IChunk, error) {
	if len(cond.SrcIPV4List) <= 0 {
		return nil, nil
	}

	chunk := NewSrcIPV4Chunk(idx)
	if err := chunk.setCells(cond.SrcIPV4List); err != nil {
		return nil, err
	}

	return chunk, nil
}

func NewDstIPV4Chunk(index int) *DstIPV4AddrChunk {
	chunk := &DstIPV4AddrChunk{}
	chunk.idx = index
	chunk.ldOff = np.DstIPV4AbsoluteOffIndex
	return chunk
}

type DstIPV4AddrChunk struct {
	IPV4AddrChunk
}

func CheckAndCreateDstIPV4AddrChunk(idx int, cond *Condition) (IChunk, error) {
	if len(cond.DstIPV4List) <= 0 {
		return nil, nil
	}

	chunk := NewDstIPV4Chunk(idx)
	if err := chunk.setCells(cond.DstIPV4List); err != nil {
		return nil, err
	}

	return chunk, nil
}
