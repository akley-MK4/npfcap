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

	skipToAllowNum, skipToRejectNum := t.GetSkipRetConstantIndex(retAllowIndex)

	nextChunk := chunk.GetNextChunk()
	if nextChunk == nil {
		setJumpIfWithLastChunk(&jumpIf, reject, t, skipToAllowNum, skipToRejectNum)
		return
	}

	setIPV4AddrJumpIfWithoutLastChunk(&jumpIf, reject, chunk, t, skipToAllowNum, skipToRejectNum)
	return
}

func setIPV4AddrJumpIfWithoutLastChunk(jumpIf *bpf.JumpIf, reject bool, chunk IChunk, cell ICell, skipToAllowNum, skipToRejectNum uint8) {
	var nextIPV4AddrChunk, nextNonIPVAddrChunk IChunk
	scanChunks(chunk.GetNextChunk(), func(c IChunk) bool {
		if _, ok := c.(*SrcIPV4AddrChunk); ok {
			nextIPV4AddrChunk = c
			return true
		}
		if _, ok := c.(*DstIPV4AddrChunk); ok {
			nextIPV4AddrChunk = c
			return true
		}
		if _, ok := c.(*SrcIPV6AddrChunk); ok {
			return true
		}
		if _, ok := c.(*DstIPV6AddrChunk); ok {
			return true
		}

		nextNonIPVAddrChunk = c
		return false
	})

	if reject {
		setIPV4AddrRejectJumpIfWithoutLastChunk(jumpIf, nextIPV4AddrChunk, nextNonIPVAddrChunk, cell, skipToAllowNum, skipToRejectNum)
		return
	}
	setIPV4AddrAllowJumpIfWithoutLastChunk(jumpIf, nextIPV4AddrChunk, nextNonIPVAddrChunk, cell, skipToAllowNum, skipToRejectNum)
}

func setIPV4AddrRejectJumpIfWithoutLastChunk(jumpIf *bpf.JumpIf, nextIPV4AddrChunk, nextNonIPAddrChunk IChunk, cell ICell, skipToAllowNum, skipToRejectNum uint8) {
	nextCell := cell.GetNextCell()

	if nextNonIPAddrChunk == nil {
		jumpIf.SkipTrue = skipToRejectNum
		if nextCell == nil {
			if nextIPV4AddrChunk == nil {
				jumpIf.SkipFalse = skipToAllowNum
			} else {
				jumpIf.SkipFalse, _ = calculateJumpIndex(cell.GetIndex(), nextIPV4AddrChunk.GetFirstCellIndex())
			}

			return
		}

		return
	}

	if nextCell == nil {
		jumpIf.SkipTrue, _ = calculateJumpIndex(cell.GetIndex(), nextNonIPAddrChunk.GetFirstCellIndex())
		if nextIPV4AddrChunk != nil {
			jumpIf.SkipFalse, _ = calculateJumpIndex(cell.GetIndex(), nextIPV4AddrChunk.GetFirstCellIndex())
		} else {
			jumpIf.SkipFalse = skipToAllowNum
		}

		return
	}

	jumpIf.SkipFalse, _ = calculateJumpIndex(cell.GetIndex(), nextCell.GetIndex())
	jumpIf.SkipTrue, _ = calculateJumpIndex(cell.GetIndex(), nextNonIPAddrChunk.GetFirstCellIndex())
}

func setIPV4AddrAllowJumpIfWithoutLastChunk(jumpIf *bpf.JumpIf, nextIPV4AddrChunk, nextNonIPAddrChunk IChunk, cell ICell, skipToAllowNum, skipToRejectNum uint8) {
	nextCell := cell.GetNextCell()

	if nextNonIPAddrChunk == nil {
		jumpIf.SkipTrue = skipToAllowNum
		if nextCell == nil {
			if nextIPV4AddrChunk == nil {
				jumpIf.SkipFalse = skipToRejectNum
			} else {
				jumpIf.SkipFalse, _ = calculateJumpIndex(cell.GetIndex(), nextIPV4AddrChunk.GetFirstCellIndex())
			}

			return
		}

		return
	}

	if nextCell == nil {
		jumpIf.SkipTrue, _ = calculateJumpIndex(cell.GetIndex(), nextNonIPAddrChunk.GetFirstCellIndex())
		if nextIPV4AddrChunk == nil {
			jumpIf.SkipFalse = skipToRejectNum
		}
		return
	}

	jumpIf.SkipFalse, _ = calculateJumpIndex(cell.GetIndex(), nextCell.GetIndex())
	jumpIf.SkipTrue, _ = calculateJumpIndex(cell.GetIndex(), nextNonIPAddrChunk.GetFirstCellIndex())

}
