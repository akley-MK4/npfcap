package expression

import (
	"errors"
	"github.com/akley-MK4/npfcap/filter/converter"
	"github.com/akley-MK4/npfcap/logger"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/bpf"
	"net"
	"strings"
	"time"
)

type DirectionArgsInfo struct {
	IPArg string
	Port  string
}

type Condition struct {
	LO         LogicalOperatorType
	Direction  DirectionType
	NIP        net.IP
	IPProtocol layers.IPProtocol
	Port       int
}

func BuildRawInstructionsByExpression(cmdTimeoutSec time.Duration, conditions ...Condition) (retList []bpf.RawInstruction, retErr error) {
	argsContent, argsContentErr := buildTCPDumpCmdArgsContent(conditions...)
	if argsContentErr != nil {
		retErr = argsContentErr
		return
	}

	stdoutData, stderrData, execErr := ExecTCPDumpCommandline(cmdTimeoutSec, "-ddd", argsContent)
	if execErr != nil {
		retErr = execErr
		return
	}

	stderrStr := strings.TrimSpace(string(stderrData))
	if stderrStr != "" && len(stdoutData) <= 0 {
		retErr = errors.New(stderrStr)
		return
	}

	logger.GetLoggerInstance().WarningF("Exec tcpdump cmd %v", stderrStr)

	retList, retErr = converter.UnmarshalTCPDUMPRawDecimalData(stdoutData, "\n")
	return
}
