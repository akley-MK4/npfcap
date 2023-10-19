package assembler

import (
	"github.com/google/gopacket/layers"
	"golang.org/x/net/bpf"
)

type EthTypeCell struct {
	BaseCell
	ethType          layers.EthernetType
	matchToSkipChunk func(chunk IChunk) IChunk
}

func (t *EthTypeCell) BuildInstructions(reject bool, chunk IChunk, instructions *[]bpf.Instruction, retAllowIndex int) (retErr error) {
	jumpIf := bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(t.ethType)}

	defer func() {
		if retErr != nil {
			return
		}

		*instructions = append(*instructions, jumpIf)
	}()

	allInstrNum := retAllowIndex - t.index - 1
	skipToAllowNum := uint8(allInstrNum)
	skipToRejectNum := uint8(allInstrNum) + 1

	nextChunk := t.matchToSkipChunk(chunk.GetNextChunk())
	if nextChunk == nil {
		setJumpIfWithLastChunk(&jumpIf, reject, t, skipToAllowNum, skipToRejectNum)
		return
	}

	jumpIf.SkipTrue = uint8(nextChunk.GetFirstCellIndex() - t.index - 1)
	if t.IsTailCell() {
		if reject {
			jumpIf.SkipFalse = skipToAllowNum
		} else {
			jumpIf.SkipFalse = skipToRejectNum
		}

	}
	return
}

func NewEthTypeIPV4Cell(index int) ICell {
	chunk := &EthTypeIPV4Cell{}
	chunk.index = index
	chunk.ethType = layers.EthernetTypeIPv4
	chunk.matchToSkipChunk = func(chunk IChunk) (retChunk IChunk) {
		scanChunks(chunk, func(c IChunk) bool {
			if _, ok := c.(*SrcIPV4AddrChunk); ok {
				retChunk = c
				return false
			}
			if _, ok := c.(*DstIPV4AddrChunk); ok {
				retChunk = c
				return false
			}

			retChunk = c
			return true
		})
		return
	}

	return chunk
}

type EthTypeIPV4Cell struct {
	EthTypeCell
}

func NewEthTypeIPV6Cell(index int) ICell {
	chunk := &EthTypeIPV4Cell{}
	chunk.index = index
	chunk.ethType = layers.EthernetTypeIPv6
	chunk.matchToSkipChunk = func(chunk IChunk) (retChunk IChunk) {
		scanChunks(chunk, func(c IChunk) bool {
			if _, ok := c.(*SrcIPV6AddrChunk); ok {
				retChunk = c
				return false
			}
			if _, ok := c.(*DstIPV6AddrChunk); ok {
				retChunk = c
				return false
			}

			retChunk = c
			return true
		})
		return
	}

	return chunk
}

type EthTypeIPV6Cell struct {
	EthTypeCell
}
