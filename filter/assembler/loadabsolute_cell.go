package assembler

import (
	"golang.org/x/net/bpf"
)

func NewLoadAbsoluteCell(index int, off uint32, size int) ICell {
	cell := &LoadAbsoluteCell{}
	cell.index = index
	cell.off = off
	cell.size = size

	return cell
}

type LoadAbsoluteCell struct {
	BaseCell
	off  uint32
	size int
}

func (t *LoadAbsoluteCell) BuildInstructions(reject bool, chunk IChunk, instructions *[]bpf.Instruction, retAllowIndex int) (retErr error) {
	*instructions = append(*instructions, bpf.LoadAbsolute{Off: t.off, Size: t.size})

	return
}
