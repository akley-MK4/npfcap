package assembler

import (
	"errors"
	"golang.org/x/net/bpf"
)

type IChunk interface {
	GetFirstCellIndex() int
	GetCellLinkLen() int

	GetPreviousChunk() IChunk
	GetNextChunk() IChunk
	SetNextChunk(chunk IChunk)
	SetPreviousChunk(chunk IChunk)
	buildInstructions(reject bool, instructions *[]bpf.Instruction, retAllowIndex int) error
	GetInstructionsNum() int
}

type BaseChunk struct {
	idx             int
	instructionsNum int
	//cells           []ICell

	cellLink      CellLink
	previousChunk IChunk
	nextChunk     IChunk
}

func (t *BaseChunk) GetInstructionsNum() int {
	return t.instructionsNum
}

func (t *BaseChunk) GetFirstCellIndex() (retIdx int) {
	head := t.cellLink.getHead()
	if head == nil {
		return
	}

	return head.GetIndex()
}

func (t *BaseChunk) GetCellLinkLen() int {
	return t.cellLink.getLength()
}

func (t *BaseChunk) GetNextChunk() IChunk {
	return t.nextChunk
}

func (t *BaseChunk) GetPreviousChunk() IChunk {
	return t.previousChunk
}

func (t *BaseChunk) SetNextChunk(chunk IChunk) {
	t.nextChunk = chunk
}

func (t *BaseChunk) SetPreviousChunk(chunk IChunk) {
	t.previousChunk = chunk
}

func (t *BaseChunk) BuildInstructions(reject bool, instructions *[]bpf.Instruction) error {
	return errors.New("invalid function")
}

func CalculateChunkLinkInstructionsNumBy(chunk IChunk) (retNum int) {
	for ; chunk != nil; chunk = chunk.GetNextChunk() {
		retNum += chunk.GetInstructionsNum()
	}

	return
}

func scanChunks(chunk IChunk, f func(c IChunk) bool) {
	for ; chunk != nil; chunk = chunk.GetNextChunk() {
		if !f(chunk) {
			break
		}
	}
}
