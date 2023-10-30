package filter_assembler

import (
	"fmt"
	"github.com/akley-MK4/npfcap/filter/assembler"
	"net"
	"testing"
)

func TestAllowAssemblerWithSingleSrcIPV4Addr(t *testing.T) {
	cond := assembler.Condition{
		Reject: false,
		SrcIPV4List: []net.IP{
			net.ParseIP("1.1.1.1"),
		},
	}

	instrList, buildErr := assembler.BuildRawInstructions(cond)
	if buildErr != nil {
		t.Errorf("Failed to build raw instructions, %v", buildErr)
		return
	}

	correctInstrListStr := "[{40 0 0 12} {21 0 3 2048} {32 0 0 26} {21 0 1 16843009} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestAllowAssemblerWithSingleDstIPV4Addr(t *testing.T) {
	cond := assembler.Condition{
		Reject: false,
		DstIPV4List: []net.IP{
			net.ParseIP("1.1.1.1"),
		},
	}

	instrList, buildErr := assembler.BuildRawInstructions(cond)
	if buildErr != nil {
		t.Errorf("Failed to build raw instructions, %v", buildErr)
		return
	}

	correctInstrListStr := "[{40 0 0 12} {21 0 3 2048} {32 0 0 30} {21 0 1 16843009} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestRejectAssemblerWithSingleSrcIPV4Addr(t *testing.T) {
	cond := assembler.Condition{
		Reject: true,
		SrcIPV4List: []net.IP{
			net.ParseIP("1.1.1.1"),
		},
	}

	instrList, buildErr := assembler.BuildRawInstructions(cond)
	if buildErr != nil {
		t.Errorf("Failed to build raw instructions, %v", buildErr)
		return
	}

	correctInstrListStr := "[{40 0 0 12} {21 0 2 2048} {32 0 0 26} {21 1 0 16843009} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestRejectAssemblerWithSingleDstIPV4Addr(t *testing.T) {
	cond := assembler.Condition{
		Reject: true,
		DstIPV4List: []net.IP{
			net.ParseIP("1.1.1.1"),
		},
	}

	instrList, buildErr := assembler.BuildRawInstructions(cond)
	if buildErr != nil {
		t.Errorf("Failed to build raw instructions, %v", buildErr)
		return
	}

	correctInstrListStr := "[{40 0 0 12} {21 0 2 2048} {32 0 0 30} {21 1 0 16843009} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestAllowAssemblerWithMultipleSrcIPV4Addr(t *testing.T) {
	cond := assembler.Condition{
		Reject: false,
		SrcIPV4List: []net.IP{
			net.ParseIP("1.1.1.1"),
			net.ParseIP("1.1.1.2"),
		},
	}

	instrList, buildErr := assembler.BuildRawInstructions(cond)
	if buildErr != nil {
		t.Errorf("Failed to build raw instructions, %v", buildErr)
		return
	}

	correctInstrListStr := "[{40 0 0 12} {21 0 4 2048} {32 0 0 26} {21 1 0 16843009} {21 0 1 16843010} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestAllowAssemblerWithMultipleDstIPV4Addr(t *testing.T) {
	cond := assembler.Condition{
		Reject: false,
		DstIPV4List: []net.IP{
			net.ParseIP("1.1.1.1"),
			net.ParseIP("1.1.1.2"),
		},
	}

	instrList, buildErr := assembler.BuildRawInstructions(cond)
	if buildErr != nil {
		t.Errorf("Failed to build raw instructions, %v", buildErr)
		return
	}

	correctInstrListStr := "[{40 0 0 12} {21 0 4 2048} {32 0 0 30} {21 1 0 16843009} {21 0 1 16843010} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestRejectAssemblerWithMultipleSrcIPV4Addr(t *testing.T) {
	cond := assembler.Condition{
		Reject: true,
		SrcIPV4List: []net.IP{
			net.ParseIP("1.1.1.1"),
			net.ParseIP("1.1.1.2"),
		},
	}

	instrList, buildErr := assembler.BuildRawInstructions(cond)
	if buildErr != nil {
		t.Errorf("Failed to build raw instructions, %v", buildErr)
		return
	}

	correctInstrListStr := "[{40 0 0 12} {21 0 3 2048} {32 0 0 26} {21 2 0 16843009} {21 1 0 16843010} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestRejectAssemblerWithMultipleDstIPV4Addr(t *testing.T) {
	cond := assembler.Condition{
		Reject: true,
		DstIPV4List: []net.IP{
			net.ParseIP("1.1.1.1"),
			net.ParseIP("1.1.1.2"),
		},
	}

	instrList, buildErr := assembler.BuildRawInstructions(cond)
	if buildErr != nil {
		t.Errorf("Failed to build raw instructions, %v", buildErr)
		return
	}

	correctInstrListStr := "[{40 0 0 12} {21 0 3 2048} {32 0 0 30} {21 2 0 16843009} {21 1 0 16843010} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestAllowAssemblerWithSingleSrcDstIPV4Addr(t *testing.T) {
	cond := assembler.Condition{
		Reject: false,
		SrcIPV4List: []net.IP{
			net.ParseIP("1.1.1.1"),
		},
		DstIPV4List: []net.IP{
			net.ParseIP("1.1.1.1"),
		},
	}

	instrList, buildErr := assembler.BuildRawInstructions(cond)
	if buildErr != nil {
		t.Errorf("Failed to build raw instructions, %v", buildErr)
		return
	}

	correctInstrListStr := "[{40 0 0 12} {21 0 5 2048} {32 0 0 26} {21 2 0 16843009} {32 0 0 30} {21 0 1 16843009} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestRejectAssemblerWithSingleSrcDstIPV4Addr(t *testing.T) {
	cond := assembler.Condition{
		Reject: true,
		SrcIPV4List: []net.IP{
			net.ParseIP("1.1.1.1"),
		},
		DstIPV4List: []net.IP{
			net.ParseIP("1.1.1.1"),
		},
	}

	instrList, buildErr := assembler.BuildRawInstructions(cond)
	if buildErr != nil {
		t.Errorf("Failed to build raw instructions, %v", buildErr)
		return
	}

	correctInstrListStr := "[{40 0 0 12} {21 0 4 2048} {32 0 0 26} {21 3 0 16843009} {32 0 0 30} {21 1 0 16843009} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestAllowAssemblerWithMultipleSrcDstIPV4Addr(t *testing.T) {
	cond := assembler.Condition{
		Reject: false,
		SrcIPV4List: []net.IP{
			net.ParseIP("1.1.1.1"),
			net.ParseIP("1.1.1.2"),
		},
		DstIPV4List: []net.IP{
			net.ParseIP("1.1.1.1"),
			net.ParseIP("1.1.1.2"),
		},
	}

	instrList, buildErr := assembler.BuildRawInstructions(cond)
	if buildErr != nil {
		t.Errorf("Failed to build raw instructions, %v", buildErr)
		return
	}

	correctInstrListStr := "[{40 0 0 12} {21 0 7 2048} {32 0 0 26} {21 4 0 16843009} {21 3 0 16843010} {32 0 0 30} {21 1 0 16843009} {21 0 1 16843010} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestRejectAssemblerWithMultipleSrcDstIPV4Addr(t *testing.T) {
	cond := assembler.Condition{
		Reject: true,
		SrcIPV4List: []net.IP{
			net.ParseIP("1.1.1.1"),
			net.ParseIP("1.1.1.2"),
		},
		DstIPV4List: []net.IP{
			net.ParseIP("1.1.1.1"),
			net.ParseIP("1.1.1.2"),
		},
	}

	instrList, buildErr := assembler.BuildRawInstructions(cond)
	if buildErr != nil {
		t.Errorf("Failed to build raw instructions, %v", buildErr)
		return
	}

	correctInstrListStr := "[{40 0 0 12} {21 0 6 2048} {32 0 0 26} {21 5 0 16843009} {21 4 0 16843010} {32 0 0 30} {21 2 0 16843009} {21 1 0 16843010} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}
