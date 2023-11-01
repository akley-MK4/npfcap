package assembler

import (
	np "github.com/akley-MK4/npfcap/npacket"
	"golang.org/x/net/bpf"
	"net"
)

func getIPV6Values(nIP []byte) (retList []uint32) {
	begIdx := 0
	endIdx := np.IPV4Size
	for i := 0; i < np.IPV6Size/np.IPV4Size; i++ {
		retList = append(retList, getIPV4Value(nIP[begIdx:endIdx]))
		begIdx += np.IPV4Size
		endIdx += np.IPV4Size
	}

	return
}

func getIPV6CellJumpIfValueIndex(cell ICell, nIPValueIndex int) int {
	return cell.GetIndex() + np.IPV6AddrCellInstrNum + nIPValueIndex*np.IPV6AddrCellInstrNum
}

func setIPV6AddrJumpIfWithLastChunk(jumpIf *bpf.JumpIf, reject bool, nIPValIdx int, cell ICell, skipToAllowNum, skipToRejectNum uint8) {
	if reject {
		setIPV6AddrRejectJumpIfWithLastChunk(jumpIf, nIPValIdx, cell, skipToAllowNum, skipToRejectNum)
		return
	}
	setIPV6AddrAllowJumpIfWithLastChunk(jumpIf, nIPValIdx, cell, skipToAllowNum, skipToRejectNum)
}

func setIPV6AddrRejectJumpIfWithLastChunk(jumpIf *bpf.JumpIf, nIPValIdx int, cell ICell, skipToAllowNum, skipToRejectNum uint8) {
	tailIPVal := (nIPValIdx + 1) == np.IPV6ValuePartsNum
	nextCell := cell.GetNextCell()
	if nextCell == nil {
		jumpIf.SkipFalse = skipToAllowNum
		if tailIPVal {
			jumpIf.SkipTrue = skipToRejectNum
			return
		}

		return
	}

	if tailIPVal {
		jumpIf.SkipTrue = skipToRejectNum
		return
	}

	jumpIf.SkipFalse = uint8(nextCell.GetIndex() - getIPV6CellJumpIfValueIndex(cell, nIPValIdx))
}

func setIPV6AddrAllowJumpIfWithLastChunk(jumpIf *bpf.JumpIf, nIPValIdx int, cell ICell, skipToAllowNum, skipToRejectNum uint8) {
	tailIPVal := (nIPValIdx + 1) == np.IPV6ValuePartsNum
	nextCell := cell.GetNextCell()
	if nextCell == nil {
		jumpIf.SkipFalse = skipToRejectNum
		if tailIPVal {
			jumpIf.SkipTrue = skipToAllowNum
			return
		}

		return
	}

	if tailIPVal {
		jumpIf.SkipTrue = skipToAllowNum
		return
	}

	jumpIf.SkipFalse = uint8(nextCell.GetIndex() - getIPV6CellJumpIfValueIndex(cell, nIPValIdx))
}

func setIPV6AddrJumpIfWithoutLastChunk(jumpIf *bpf.JumpIf, nextChunk IChunk, reject bool, nIPValIdx int, cell ICell, skipToAllowNum, skipToRejectNum uint8) {
	if reject {
		setIPV6AddrRejectJumpIfWithoutLastChunk(jumpIf, nextChunk, nIPValIdx, cell, skipToAllowNum, skipToRejectNum)
		return
	}
	setIPV6AddrAllowJumpIfWithoutLastChunk(jumpIf, nextChunk, nIPValIdx, cell, skipToAllowNum, skipToRejectNum)
}

func setIPV6AddrRejectJumpIfWithoutLastChunk(jumpIf *bpf.JumpIf, nextChunk IChunk, nIPValIdx int, cell ICell, skipToAllowNum, skipToRejectNum uint8) {
	var nextIPAddrChunk, nextNonIPAddrChunk IChunk
	cellIPValIndex := cell.GetIndex() + 1 + nIPValIdx*np.IPV6AddrCellInstrNum
	tailIPVal := (nIPValIdx + 1) == np.IPV6ValuePartsNum

	scanChunks(nextChunk, func(c IChunk) bool {
		if _, ok := c.(*SrcIPV6AddrChunk); ok {
			if nextIPAddrChunk == nil {
				nextIPAddrChunk = c
			}
			return true
		}
		if _, ok := c.(*DstIPV6AddrChunk); ok {
			if nextIPAddrChunk == nil {
				nextIPAddrChunk = c
			}
			return true
		}

		nextNonIPAddrChunk = c
		return false
	})

	nextCell := cell.GetNextCell()

	if tailIPVal {
		if nextNonIPAddrChunk != nil {
			jumpIf.SkipTrue, _ = calculateJumpIndex(cellIPValIndex, nextNonIPAddrChunk.GetFirstCellIndex())
		} else {
			jumpIf.SkipTrue = skipToRejectNum
		}
	}

	if nextCell == nil {
		if nextIPAddrChunk != nil {
			jumpIf.SkipFalse = uint8(nextIPAddrChunk.GetFirstCellIndex() - getIPV6CellJumpIfValueIndex(cell, nIPValIdx))
		} else {
			jumpIf.SkipFalse = skipToAllowNum
		}
		return
	}

	jumpIf.SkipFalse = uint8(nextCell.GetIndex() - getIPV6CellJumpIfValueIndex(cell, nIPValIdx))
}

func setIPV6AddrAllowJumpIfWithoutLastChunk(jumpIf *bpf.JumpIf, nextChunk IChunk, nIPValIdx int, cell ICell, skipToAllowNum, skipToRejectNum uint8) {
	var nextIPVAddrChunk, nextNonIPAddrChunk IChunk
	cellIPValIndex := cell.GetIndex() + 1 + nIPValIdx*np.IPV6AddrCellInstrNum
	tailIPVal := (nIPValIdx + 1) == np.IPV6ValuePartsNum

	scanChunks(nextChunk, func(c IChunk) bool {
		if _, ok := c.(*SrcIPV6AddrChunk); ok {
			if nextIPVAddrChunk == nil {
				nextIPVAddrChunk = c
			}
			return true
		}
		if _, ok := c.(*DstIPV6AddrChunk); ok {
			if nextIPVAddrChunk == nil {
				nextIPVAddrChunk = c
			}
			return true
		}

		nextNonIPAddrChunk = c
		return false
	})

	nextCell := cell.GetNextCell()

	if tailIPVal {
		if nextNonIPAddrChunk != nil {
			jumpIf.SkipTrue, _ = calculateJumpIndex(cellIPValIndex, nextNonIPAddrChunk.GetFirstCellIndex())
		} else {
			jumpIf.SkipTrue = skipToAllowNum
		}
	}

	if nextCell == nil {
		if nextIPVAddrChunk != nil {
			jumpIf.SkipFalse = uint8(nextIPVAddrChunk.GetFirstCellIndex() - getIPV6CellJumpIfValueIndex(cell, nIPValIdx))
		} else {
			jumpIf.SkipFalse = skipToRejectNum
		}
		return
	}

	jumpIf.SkipFalse = uint8(nextCell.GetIndex() - getIPV6CellJumpIfValueIndex(cell, nIPValIdx))
}

type IPV6AddrValueCell struct {
	BaseCell
	nIPValues []uint32
	ldOff     uint32
}

func (t *IPV6AddrValueCell) BuildInstructions(reject bool, chunk IChunk, instructions *[]bpf.Instruction, retAllowIndex int) (retErr error) {
	nextChunk := chunk.GetNextChunk()

	for nIPValIdx, nIPVal := range t.nIPValues {
		allInstrNum := retAllowIndex - t.index - 1 - 1 - nIPValIdx*np.IPV6AddrCellInstrNum
		skipToAllowNum := uint8(allInstrNum)
		skipToRejectNum := uint8(allInstrNum) + 1

		ldAbs := bpf.LoadAbsolute{Off: t.ldOff + uint32(nIPValIdx*np.IPV4Size), Size: np.IPV4Size}
		*instructions = append(*instructions, ldAbs)
		jumpIf := bpf.JumpIf{Cond: bpf.JumpEqual, Val: nIPVal}

		if nextChunk == nil {
			setIPV6AddrJumpIfWithLastChunk(&jumpIf, reject, nIPValIdx, t, skipToAllowNum, skipToRejectNum)
		} else {
			setIPV6AddrJumpIfWithoutLastChunk(&jumpIf, nextChunk, reject, nIPValIdx, t, skipToAllowNum, skipToRejectNum)
		}

		*instructions = append(*instructions, jumpIf)
	}

	return
}

func NewSrcIPV6AddrValueCell(index int, nIP net.IP) ICell {
	cell := &SrcIPV6AddrValueCell{}
	cell.index = index
	cell.nIPValues = getIPV6Values(nIP.To16())
	cell.ldOff = np.SrcIPV6AbsoluteOffIndex

	return cell
}

type SrcIPV6AddrValueCell struct {
	IPV6AddrValueCell
}

func NewDstIPV6AddrValueCell(index int, nIP net.IP) ICell {
	cell := &DstIPV6AddrValueCell{}
	cell.index = index
	cell.nIPValues = getIPV6Values(nIP.To16())
	cell.ldOff = np.DstIPV6AbsoluteOffIndex

	return cell
}

type DstIPV6AddrValueCell struct {
	IPV6AddrValueCell
}
