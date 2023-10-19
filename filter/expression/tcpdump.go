package expression

import (
	"context"
	"fmt"
	"github.com/akley-MK4/npfcap/logger"
	"io/ioutil"
	"os/exec"
	"time"
)

func ExecTCPDumpCommandline(cmdTimeout time.Duration, args ...string) (retStdoutData, retStderrData []byte, retErr error) {
	ctx, cancelFunc := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancelFunc()

	handle := exec.CommandContext(ctx, "tcpdump", args...)

	logger.GetLoggerInstance().InfoF("exec tcpdump commandline: %v", handle.String())

	stdoutPip, stdoutPipErr := handle.StdoutPipe()
	stderrPip, stderrPipErr := handle.StderrPipe()

	defer func() {
		if err := stdoutPip.Close(); err != nil {
			logger.GetLoggerInstance().WarningF("Failed to close stdout pip, %v", err)
		}
		if err := stderrPip.Close(); err != nil {
			logger.GetLoggerInstance().WarningF("Failed to close stderr pip, %v", err)
		}

		if err := handle.Wait(); err != nil {
			logger.GetLoggerInstance().WarningF("Wait command line, %v", err)
		}
	}()

	if stdoutPipErr != nil {
		retErr = stdoutPipErr
		return
	}
	if stderrPipErr != nil {
		retErr = stderrPipErr
		return
	}

	startErr := handle.Start()
	if startErr != nil {
		retErr = startErr
		return
	}

	retStderrData, retErr = ioutil.ReadAll(stderrPip)
	if retErr != nil {
		return
	}
	//if len(retStderrData) > 0 {
	//	retErr = errors.New(strings.TrimSpace(string(retStderrData)))
	//	return
	//}

	retStdoutData, retErr = ioutil.ReadAll(stdoutPip)

	return
}

func buildTCPDumpCmdArgsContent(conditions ...Condition) (retContent string, retErr error) {
	retContent = ""
	appendNum := 0

	for _, filter := range conditions {
		dtArgsInfo := dtArgsInfoMap[filter.Direction]
		if dtArgsInfo == nil {
			retErr = fmt.Errorf("unknown Direction type %v", filter.Direction)
			return
		}

		lgOp := logicalOperatorTypeMap[filter.LO]
		if lgOp == "" {
			retErr = fmt.Errorf("unknown LogicalOperator type %v", filter.LO)
			return
		}

		if filter.NIP == nil && filter.IPProtocol == 0 && filter.Port <= 0 {
			continue
		}

		protoStr := ipProtoInfoMap[filter.IPProtocol]
		if filter.IPProtocol > 0 && protoStr == "" {
			retErr = fmt.Errorf("unsupported protocol type %v", filter.IPProtocol)
			return
		}

		if filter.LO == LogicalOperatorNot {
			if appendNum > 0 {
				retContent = retContent + " and "
			}
			if filter.NIP != nil {
				retContent = retContent + fmt.Sprintf("%v %v %v", lgOp, dtArgsInfo.IPArg, filter.NIP.String())
				if protoStr != "" {
					retContent = retContent + " and "
				}
			}
			if protoStr != "" {
				retContent = retContent + fmt.Sprintf("%v %v", lgOp, protoStr)
				if filter.Port > 0 {
					retContent = retContent + " and "
				}
			}
			if filter.Port > 0 {
				retContent = retContent + fmt.Sprintf("%v %v %v", lgOp, dtArgsInfo.Port, filter.Port)
			}
			appendNum += 1
			continue
		}

		if appendNum > 0 {
			retContent = retContent + fmt.Sprintf(" %v ", lgOp)
		}
		appendNum += 1

		if filter.NIP != nil {
			retContent = retContent + fmt.Sprintf("%v %v", dtArgsInfo.IPArg, filter.NIP.String())
			if protoStr != "" {
				//retContent = retContent + fmt.Sprintf(" %v ", lgOp)
				retContent = retContent + " and "
			}
		}
		if protoStr != "" {
			retContent = retContent + fmt.Sprintf("%v", protoStr)
			if filter.Port > 0 {
				//retContent = retContent + fmt.Sprintf(" %v ", lgOp)
				retContent = retContent + " and "
			}
		}
		if filter.Port > 0 {
			retContent = retContent + fmt.Sprintf("%v %v", dtArgsInfo.Port, filter.Port)
		}
	}

	return
}
