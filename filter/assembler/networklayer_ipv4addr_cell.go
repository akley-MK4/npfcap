package assembler

import (
	"golang.org/x/net/bpf"
	"net"
)

func getIPV4Value(nIP []byte) uint32 {
	return (uint32(nIP[0]) << 24) | (uint32(nIP[1]) << 16) | (uint32(nIP[2]) << 8) | (uint32(nIP[3]) << 0)
}

func NewIPV4AddrValueCell(index int, nIP net.IP) ICell {
	cell := &IPV4AddrValueCell{}
	cell.index = index
	cell.IPValue = getIPV4Value(nIP.To4())

	return cell
}

type IPV4AddrValueCell struct {
	BaseCell
	IPValue uint32
}

func (t *IPV4AddrValueCell) BuildInstructions(reject bool, chunk IChunk, instructions *[]bpf.Instruction,
	retAllowIndex int) (retErr error) {
	jumpIf := bpf.JumpIf{Cond: bpf.JumpEqual, Val: t.IPValue}

	defer func() {
		if retErr != nil {
			return
		}
		*instructions = append(*instructions, jumpIf)
	}()

	allInstrNum := retAllowIndex - t.index - 1 - 1
	skipToAllowNum := uint8(allInstrNum)
	skipToRejectNum := uint8(allInstrNum) + 1

	nextChunk := chunk.GetNextChunk()
	if nextChunk == nil {
		setJumpIfWithLastChunk(&jumpIf, reject, t, skipToAllowNum, skipToRejectNum)
		return
	}

	nextNonIPChunkIdx := -1
	scanChunks(chunk.GetNextChunk(), func(c IChunk) bool {
		if _, ok := c.(*SrcIPV4AddrChunk); ok {
			return true
		}
		if _, ok := c.(*DstIPV4AddrChunk); ok {
			return true
		}
		if _, ok := c.(*SrcIPV6AddrChunk); ok {
			return true
		}
		if _, ok := c.(*DstIPV6AddrChunk); ok {
			return true
		}

		nextNonIPChunkIdx = c.GetFirstCellIndex()
		return false
	})

	if nextNonIPChunkIdx < 0 {
		if reject {
			jumpIf.SkipTrue = skipToRejectNum
		} else {
			jumpIf.SkipTrue = skipToAllowNum
		}
		return
	}

	jumpIf.SkipTrue = uint8(nextNonIPChunkIdx - chunk.GetFirstCellIndex() - 1)
	return
}
