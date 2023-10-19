package assembler

import "golang.org/x/net/bpf"

func setJumpIfWithLastChunk(jumpIf *bpf.JumpIf, reject, tailCellTag bool, skipToAllowNum, skipToRejectNum uint8) {
	if tailCellTag {
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
