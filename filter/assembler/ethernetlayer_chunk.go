package assembler

import (
	"errors"
	np "github.com/akley-MK4/npfcap/npacket"
	"golang.org/x/net/bpf"
)

func NewEthernetLayerChunk() *EthernetLayerChunk {
	return &EthernetLayerChunk{}
}

type EthernetLayerChunk struct {
	BaseChunk
}

func (t *EthernetLayerChunk) checkAndAppendCells(cond *Condition) (retErr error) {
	var newCellFs []func(int) ICell

	defer func() {
		if retErr != nil {
			return
		}

		newCellFsLen := len(newCellFs)
		if newCellFsLen <= 0 {
			return
		}

		for i, f := range newCellFs {
			cell := f(t.idx + i + 1)
			t.cellLink.addCell(cell)
		}

		t.instructionsNum = t.cellLink.getLength() + 1
	}()

	if len(cond.SrcIPV4List) > 0 || len(cond.DstIPV4List) > 0 {
		newCellFs = append(newCellFs, NewEthTypeIPV4Cell)
	}

	if len(cond.SrcIPV6List) > 0 || len(cond.DstIPV6List) > 0 {
		newCellFs = append(newCellFs, NewEthTypeIPV6Cell)
	}

	if len(newCellFs) > 0 {
		return
	}

	if len(cond.IPProtocolList) <= 0 && len(cond.PortList) <= 0 {
		retErr = errors.New("")
		return
	}

	newCellFs = append(newCellFs, NewEthTypeIPV4Cell, NewEthTypeIPV6Cell)
	return
}

func (t *EthernetLayerChunk) buildInstructions(reject bool, instructions *[]bpf.Instruction, retAllowIndex int) (retErr error) {
	*instructions = append(*instructions, bpf.LoadAbsolute{Off: np.EthAbsoluteOffIndex, Size: np.EthTypeSize})

	t.cellLink.scanCells(func(cell ICell) bool {
		if err := cell.BuildInstructions(reject, t, instructions, retAllowIndex); err != nil {
			retErr = err
			return false
		}
		return true
	})

	return
}
