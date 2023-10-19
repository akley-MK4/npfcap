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

	// jump to next cell
	//jumpIf.SkipFalse = uint8(nextCell.GetIndex() - cell.GetIndex() - IPV6AddrCellInstrNum - nIPValIdx*IPV6AddrCellInstrNum)
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

	//jumpIf.SkipFalse = uint8(nextCell.GetIndex() - (cell.GetIndex() + IPV6AddrCellInstrNum + nIPValIdx*IPV6AddrCellInstrNum))
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
	var matchIPAddrChunk, nonIPAddrChunk IChunk
	tailIPVal := (nIPValIdx + 1) == np.IPV6ValuePartsNum

	scanChunks(nextChunk, func(c IChunk) bool {
		if _, ok := c.(*SrcIPV6AddrChunk); ok {
			if matchIPAddrChunk == nil {
				matchIPAddrChunk = c
			}
			return true
		}
		if _, ok := c.(*DstIPV6AddrChunk); ok {
			if matchIPAddrChunk == nil {
				matchIPAddrChunk = c
			}
			return true
		}

		nonIPAddrChunk = c
		return true
	})

	if tailIPVal && nonIPAddrChunk == nil {
		jumpIf.SkipTrue = skipToRejectNum
		return
	}

	nextCell := cell.GetNextCell()
	if nextCell == nil {
		if matchIPAddrChunk != nil {
			jumpIf.SkipFalse = uint8(matchIPAddrChunk.GetFirstCellIndex() - getIPV6CellJumpIfValueIndex(cell, nIPValIdx))
			return
		}

		jumpIf.SkipFalse = skipToAllowNum
		return
	}

	//if tailIPVal && nonIPAddrChunk == nil {
	//	jumpIf.SkipTrue = skipToRejectNum
	//	return
	//}

	jumpIf.SkipFalse = uint8(nextCell.GetIndex() - getIPV6CellJumpIfValueIndex(cell, nIPValIdx))
}

func setIPV6AddrAllowJumpIfWithoutLastChunk(jumpIf *bpf.JumpIf, nextChunk IChunk, nIPValIdx int, cell ICell, skipToAllowNum, skipToRejectNum uint8) {
	var matchIPAddrChunk, nonIPAddrChunk IChunk
	tailIPVal := (nIPValIdx + 1) == np.IPV6ValuePartsNum

	scanChunks(nextChunk, func(c IChunk) bool {
		if _, ok := c.(*SrcIPV6AddrChunk); ok {
			if matchIPAddrChunk == nil {
				matchIPAddrChunk = c
			}
			return true
		}
		if _, ok := c.(*DstIPV6AddrChunk); ok {
			if matchIPAddrChunk == nil {
				matchIPAddrChunk = c
			}
			return true
		}

		nonIPAddrChunk = c
		return true
	})

	if tailIPVal && nonIPAddrChunk == nil {
		jumpIf.SkipTrue = skipToAllowNum
		return
	}

	nextCell := cell.GetNextCell()
	if nextCell == nil {
		if matchIPAddrChunk != nil {
			//jumpIf.SkipFalse = uint8(matchIPAddrChunk.GetFirstCellIndex() - (cell.GetIndex() + IPV6AddrCellInstrNum + nIPValIdx*IPV6AddrCellInstrNum))
			jumpIf.SkipFalse = uint8(matchIPAddrChunk.GetFirstCellIndex() - getIPV6CellJumpIfValueIndex(cell, nIPValIdx))
		} else {
			jumpIf.SkipFalse = skipToRejectNum
		}

		if tailIPVal {
			jumpIf.SkipTrue = skipToAllowNum
			return
		}

		return
	}

	//if tailIPVal && nonIPAddrChunk == nil {
	//	jumpIf.SkipTrue = skipToAllowNum
	//	return
	//}

	//jumpIf.SkipFalse = uint8(nextCell.GetIndex() - cell.GetIndex() - IPV6AddrCellInstrNum - nIPValIdx*IPV6AddrCellInstrNum)
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

		allInstrNum := retAllowIndex - t.index - 1 - 1 - nIPValIdx*2
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
