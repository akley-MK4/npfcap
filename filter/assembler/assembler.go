package assembler

import (
	cap "github.com/akley-MK4/npfcap/capturer"
	"golang.org/x/net/bpf"
)

func BuildRawInstructions(cond Condition) (retList []bpf.RawInstruction, retErr error) {
	assembler := &Assembler{
		reject:        cond.Reject,
		ethLayerChunk: NewEthernetLayerChunk(),
	}

	if err := assembler.parseCondition(&cond); err != nil {
		retErr = err
		return
	}

	if err := assembler.buildChunk(); err != nil {
		retErr = err
		return
	}

	return assembler.dumpRawInstructions()
}

type Assembler struct {
	reject bool

	ethLayerChunk *EthernetLayerChunk

	retAllowIndex  int
	retRejectIndex int

	instructions []bpf.Instruction
}

//func (t *Assembler) getAllowRetConstantValue() uint8 {
//	return t.instrTotalNum - uint8(len(t.instructions)) - 1 - 2
//}

//func (t *Assembler) getRejectRetConstantValue() uint8 {
//	return t.instrTotalNum - uint8(len(t.instructions)) - 1 - 1
//}

func (t *Assembler) parseCondition(cond *Condition) error {
	if err := t.ethLayerChunk.checkAndAppendCells(cond); err != nil {
		return err
	}

	var previousChunk IChunk = t.ethLayerChunk

	idx := t.ethLayerChunk.GetInstructionsNum()
	for _, f := range []func(idx int, cond *Condition) (IChunk, error){
		CheckAndCreateSrcIPV4AddrChunk,
		CheckAndCreateDstIPV4AddrChunk,
		CheckAndCreateSrcIPV6AddrChunk,
		CheckAndCreateDstIPV6AddrChunk,
		CheckAndCreateIPProtoChunk,
	} {
		nextChunk, nextChunkErr := f(idx, cond)
		if nextChunkErr != nil {
			return nextChunkErr
		}

		if nextChunk == nil {
			continue
		}

		t.retAllowIndex += nextChunk.GetInstructionsNum()
		idx += nextChunk.GetInstructionsNum()
		previousChunk.SetNextChunk(nextChunk)
		previousChunk = nextChunk

	}

	t.retAllowIndex += t.ethLayerChunk.GetInstructionsNum()
	t.retRejectIndex = t.retAllowIndex + 1

	return nil
}

func (t *Assembler) dumpRawInstructions() (retList []bpf.RawInstruction, retErr error) {
	if len(t.instructions) <= 0 {
		return
	}

	instructions := t.instructions
	instructions = append(instructions, bpf.RetConstant{
		Val: cap.DefaultCaptureSize,
	})
	instructions = append(instructions, bpf.RetConstant{
		Val: 0,
	})

	retList, retErr = bpf.Assemble(instructions)
	return
}

func (t *Assembler) buildChunk() error {
	var chunk IChunk = t.ethLayerChunk
	for ; chunk != nil; chunk = chunk.GetNextChunk() {
		if err := chunk.buildInstructions(t.reject, &t.instructions, t.retAllowIndex); err != nil {
			return err
		}
	}

	return nil
}
