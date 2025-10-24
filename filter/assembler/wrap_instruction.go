package assembler

import "golang.org/x/net/bpf"

func setJumpIfWithLastChunk(jumpIf *bpf.JumpIf, reject bool, cell ICell, skipToAllowNum, skipToRejectNum uint8) {
	nextCell := cell.GetNextCell()
	if nextCell == nil {
		if reject {
			jumpIf.SkipTrue = skipToRejectNum
			jumpIf.SkipFalse = skipToAllowNum
		} else {
			jumpIf.SkipTrue = skipToAllowNum
			jumpIf.SkipFalse = skipToRejectNum
		}
		return
	}

	if reject {
		jumpIf.SkipTrue = skipToRejectNum
	} else {
		jumpIf.SkipTrue = skipToAllowNum
	}
}
