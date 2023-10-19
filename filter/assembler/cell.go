package assembler

import (
	"golang.org/x/net/bpf"
)

type ICell interface {
	GetIndex() int
	IsTailCell() bool
	GetNextCell() ICell
	SetNextCell(cell ICell)
	BuildInstructions(reject bool, chunk IChunk, instructions *[]bpf.Instruction, retAllowIndex int) error
}

type BaseCell struct {
	index    int
	nextCell ICell
}

func (t *BaseCell) GetIndex() int {
	return t.index
}

func (t *BaseCell) IsTailCell() bool {
	return t.nextCell == nil
}

func (t *BaseCell) GetNextCell() ICell {
	return t.nextCell
}

func (t *BaseCell) SetNextCell(cell ICell) {
	t.nextCell = cell
}

func NewCellLink() *CellLink {
	return &CellLink{}
}

type CellLink struct {
	length int
	head   ICell
	tail   ICell
}

func (t *CellLink) getLength() int {
	return t.length
}

func (t *CellLink) getHead() ICell {
	return t.head
}

func (t *CellLink) rest() {
	t.head = nil
	t.tail = nil
	t.length = 0
}

func (t *CellLink) addCell(cell ICell) {
	t.length += 1

	if t.head == nil {
		t.head = cell
		t.tail = cell
		return
	}

	t.tail.SetNextCell(cell)
	t.tail = cell
}

func (t *CellLink) scanCells(f func(cell ICell) bool) {
	for cell := t.head; cell != nil; cell = cell.GetNextCell() {
		if !f(cell) {
			return
		}
	}
}
