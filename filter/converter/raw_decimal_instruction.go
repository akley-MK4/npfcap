package converter

import (
	"errors"
	"fmt"
	"github.com/akley-MK4/npfcap/logger"
	"golang.org/x/net/bpf"
	"math"
	"strconv"
	"strings"
)

type setRawInstructionFieldFunc func(instruction *bpf.RawInstruction, val uint64) error

var (
	setRawInstructionFieldFuncMap = map[int]setRawInstructionFieldFunc{
		rawDecimalInstrLineIndexOp: func(instruction *bpf.RawInstruction, val uint64) error {
			if val > math.MaxUint16 {
				return strconv.ErrRange
			}
			instruction.Op = uint16(val)
			return nil
		},
		rawDecimalInstrLineIndexJt: func(instruction *bpf.RawInstruction, val uint64) error {
			if val > math.MaxUint8 {
				return strconv.ErrRange
			}
			instruction.Jt = uint8(val)
			return nil
		},
		rawDecimalInstrLineIndexJf: func(instruction *bpf.RawInstruction, val uint64) error {
			if val > math.MaxUint8 {
				return strconv.ErrRange
			}
			instruction.Jf = uint8(val)
			return nil
		},
		rawDecimalInstrLineIndexK: func(instruction *bpf.RawInstruction, val uint64) error {
			if val > math.MaxUint32 {
				return strconv.ErrRange
			}
			instruction.K = uint32(val)
			return nil
		},
	}
)

// UnmarshalRawDecimalString converts a raw instruction string into a RawInstruction list
// Example:
// Expression: src 1.1.1.1 and tcp
// Decimal: 40 0 0 12 21 0 5 2048 32 0 0 26 21 0 3 16843009 48 0 0 23 21 0 1 6 6 0 0 262144 6 0 0 0
func UnmarshalRawDecimalString(rawString string) (retList []bpf.RawInstruction, retErr error) {
	if rawString == "" {
		return
	}
	instrStrList := strings.Split(strings.TrimSpace(rawString), " ")
	instrStrListLen := len(instrStrList)
	linesNum := instrStrListLen / rawDecimalInstrLineOpNum
	if linesNum <= 0 {
		retErr = errors.New("line num less than 1")
		return
	}
	if (instrStrListLen % rawDecimalInstrLineOpNum) != 0 {
		retErr = errors.New("(Split len % 4) != 0")
		return
	}

	begIdx := 0
	endIdx := rawDecimalInstrLineOpNum
	for lineNum := 0; lineNum < linesNum; lineNum++ {

		var instruction bpf.RawInstruction
		if err := parseRawDecimalLineString(lineNum, instrStrList[begIdx:endIdx], &instruction); err != nil {
			return nil, fmt.Errorf("parseRawDecimalLineString error: %v", err)
		}
		begIdx += rawDecimalInstrLineOpNum
		endIdx += rawDecimalInstrLineOpNum

		retList = append(retList, instruction)
	}

	return
}

// UnmarshalTCPDUMPRawDecimalData converts a raw instruction string into a RawInstruction list
// Example:
// Expression: src 1.1.1.1 and tcp
// Decimal: 8\n40 0 0 12\n21 0 5 2048\n32 0 0 26\n21 0 3 16843009\n48 0 0 23\n21 0 1 6\n6 0 0 262144\n6 0 0 0\n
func UnmarshalTCPDUMPRawDecimalData(rawData []byte, separator string) ([]bpf.RawInstruction, error) {
	lineStrList := strings.Split(strings.TrimSpace(string(rawData)), separator)
	if len(lineStrList) < minRawDecimalInstrLineNum {
		return nil, fmt.Errorf("line num less than %d", minRawDecimalInstrLineNum)
	}

	var retList []bpf.RawInstruction
	var instructionNum int

	for lineNum, lineStr := range lineStrList {
		lineInstrStrList := strings.Split(lineStr, " ")
		strListLen := len(lineInstrStrList)

		// check first line
		if lineNum == 0 {
			allInstrLinesNum, parseFirstLineErr := parseRawDecimalFirstLine(lineInstrStrList)
			if parseFirstLineErr != nil {
				return nil, fmt.Errorf("parseRawDecimalFirstLine error: %v", parseFirstLineErr)
			}
			instructionNum = int(allInstrLinesNum)
			continue
		}

		// check other line
		if lineNum != 0 && strListLen < rawDecimalInstrLineOpNum {
			return nil, fmt.Errorf("unknown format, LineNum: %d, LineStr: %v", lineNum, lineStr)
		}

		var instruction bpf.RawInstruction
		if err := parseRawDecimalLineString(lineNum, lineInstrStrList, &instruction); err != nil {
			return nil, fmt.Errorf("parseRawDecimalLineString error: %v", err)
		}

		retList = append(retList, instruction)
	}

	if instructionNum != len(retList) {
		logger.GetLoggerInstance().WarningF("The number of raw instruction lines is not equal to the number of build instruction lines, %d != %d",
			instructionNum, len(retList))
	}

	return retList, nil
}

func parseRawDecimalLineString(lineNum int, lineInstrStrList []string, instruction *bpf.RawInstruction) (retErr error) {
	for instrIdx, instrStr := range lineInstrStrList {
		instrStr = strings.TrimSpace(instrStr)
		if instrStr == "" {
			continue
		}

		instrVal, err := strconv.ParseUint(instrStr, 0, 32)
		if err != nil {
			retErr = fmt.Errorf("strconv.ParseUint error, LineNum: %d, instrIdx: %v, Value: %v",
				lineNum, instrIdx, instrStr)
			return
		}

		setFieldFunc, exist := setRawInstructionFieldFuncMap[instrIdx]
		if !exist {
			retErr = fmt.Errorf("not found setFieldFunc, LineNum: %d, instrIdx: %v, Value: %v",
				lineNum, instrIdx, instrVal)
			return
		}

		if setErr := setFieldFunc(instruction, instrVal); setErr != nil {
			retErr = fmt.Errorf("unable to set fields for the RawInstruction, LineNum: %d, instrIdx: %v, Value: %v, Err: %v",
				lineNum, instrIdx, instrVal, err)
			return
		}
	}

	return
}

func parseRawDecimalFirstLine(lineInstrStrList []string) (retAllInstrNum uint64, retErr error) {
	strListLen := len(lineInstrStrList)
	if strListLen != firstRawDecimalLineInstrNum {
		retErr = errors.New("unknown first line format")
		return
	}

	instrStr := lineInstrStrList[0]
	instrStr = strings.TrimSpace(instrStr)
	if instrStr == "" {
		retErr = errors.New("first line is empty")
		return
	}

	retAllInstrNum, retErr = strconv.ParseUint(instrStr, 0, 32)
	return
}
