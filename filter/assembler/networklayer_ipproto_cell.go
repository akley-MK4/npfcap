package assembler

import (
	"errors"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/bpf"
)

type IPProtoCell struct {
	BaseCell
	proto            layers.IPProtocol
	matchToSkipChunk func(chunk IChunk) IChunk
}

func (t *IPProtoCell) BuildInstructions(reject bool, chunk IChunk, instructions *[]bpf.Instruction, retAllowIndex int) (retErr error) {
	jumpIf := bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(t.proto)}

	defer func() {
		if retErr != nil {
			return
		}

		*instructions = append(*instructions, jumpIf)
	}()

	skipToAllowNum, skipToRejectNum := t.GetSkipRetConstantIndex(retAllowIndex)

	nextChunk := t.matchToSkipChunk(chunk.GetNextChunk())
	if nextChunk == nil {
		setJumpIfWithLastChunk(&jumpIf, reject, t, skipToAllowNum, skipToRejectNum)
		return
	}

	jumpIf.SkipTrue, _ = calculateJumpIndex(t.index, nextChunk.GetFirstCellIndex())
	if t.IsTailCell() {
		if reject {
			jumpIf.SkipFalse = skipToAllowNum
		} else {
			jumpIf.SkipFalse = skipToRejectNum
		}

	}

	return
}

func NewIPProtoCell(index int, proto layers.IPProtocol) (ICell, error) {
	switch proto {
	case layers.IPProtocolTCP:
		return NewIPProtoTCPCell(index, proto), nil
	case layers.IPProtocolUDP:
		return NewIPProtoUDPCell(index, proto), nil
	case layers.IPProtocolIPv6Fragment:
		return NewIPProtoIPV6FragCell(index, proto), nil
	}

	return nil, errors.New("")
}

func NewIPProtoTCPCell(index int, proto layers.IPProtocol) ICell {
	cell := &IPProtoCell{}
	cell.index = index
	cell.proto = proto
	cell.matchToSkipChunk = func(chunk IChunk) (retChunk IChunk) {
		scanChunks(chunk, func(c IChunk) bool {
			if _, ok := c.(*TCPProtocolChunk); ok {
				retChunk = c
				return false
			}
			return true
		})
		return
	}

	return cell
}

func NewIPProtoUDPCell(index int, proto layers.IPProtocol) ICell {
	cell := &IPProtoCell{}
	cell.index = index
	cell.proto = proto
	cell.matchToSkipChunk = func(chunk IChunk) (retChunk IChunk) {
		scanChunks(chunk, func(c IChunk) bool {
			if _, ok := c.(*UDPProtocolChunk); ok {
				retChunk = c
				return false
			}
			return true
		})
		return
	}

	return cell
}

func NewIPProtoIPV6FragCell(index int, proto layers.IPProtocol) ICell {
	cell := &IPProtoCell{}
	cell.index = index
	cell.proto = proto

	cell.matchToSkipChunk = func(chunk IChunk) (retChunk IChunk) {
		scanChunks(chunk, func(c IChunk) bool {
			if _, ok := c.(*IPProtocolIPv6FragChunk); ok {
				retChunk = c
				return false
			}

			return true
		})
		return
	}

	return cell
}
