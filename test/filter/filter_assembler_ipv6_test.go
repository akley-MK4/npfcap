package filter

import (
	"fmt"
	"github.com/akley-MK4/npfcap/filter/assembler"
	"net"
	"testing"
)

func TestAllowAssemblerWithSingleSrcIPV6Addr(t *testing.T) {
	cond := assembler.Condition{
		Reject: false,
		SrcIPV6List: []net.IP{
			net.ParseIP("24:22:26::1001"),
		},
	}

	instrList, buildErr := assembler.BuildRawInstructions(cond)
	if buildErr != nil {
		t.Errorf("Failed to build raw instructions, %v", buildErr)
		return
	}

	correctInstrListStr := "[{40 0 0 12} {21 0 9 34525} {32 0 0 22} {21 0 7 2359330} {32 0 0 26} {21 0 5 2490368} {32 0 0 30} {21 0 3 0} {32 0 0 34} {21 0 1 4097} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestAllowAssemblerWithSingleDstIPV6Addr(t *testing.T) {
	cond := assembler.Condition{
		Reject: false,
		DstIPV6List: []net.IP{
			net.ParseIP("24:22:26::1001"),
		},
	}

	instrList, buildErr := assembler.BuildRawInstructions(cond)
	if buildErr != nil {
		t.Errorf("Failed to build raw instructions, %v", buildErr)
		return
	}

	correctInstrListStr := "[{40 0 0 12} {21 0 9 34525} {32 0 0 38} {21 0 7 2359330} {32 0 0 42} {21 0 5 2490368} {32 0 0 46} {21 0 3 0} {32 0 0 50} {21 0 1 4097} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestRejectAssemblerWithSingleSrcIPV6Addr(t *testing.T) {
	cond := assembler.Condition{
		Reject: true,
		SrcIPV6List: []net.IP{
			net.ParseIP("24:22:26::1001"),
		},
	}

	instrList, buildErr := assembler.BuildRawInstructions(cond)
	if buildErr != nil {
		t.Errorf("Failed to build raw instructions, %v", buildErr)
		return
	}

	correctInstrListStr := "[{40 0 0 12} {21 0 8 34525} {32 0 0 22} {21 0 6 2359330} {32 0 0 26} {21 0 4 2490368} {32 0 0 30} {21 0 2 0} {32 0 0 34} {21 1 0 4097} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestRejectAssemblerWithSingleDstIPV6Addr(t *testing.T) {
	cond := assembler.Condition{
		Reject: true,
		DstIPV6List: []net.IP{
			net.ParseIP("24:22:26::1001"),
		},
	}

	instrList, buildErr := assembler.BuildRawInstructions(cond)
	if buildErr != nil {
		t.Errorf("Failed to build raw instructions, %v", buildErr)
		return
	}

	correctInstrListStr := "[{40 0 0 12} {21 0 8 34525} {32 0 0 38} {21 0 6 2359330} {32 0 0 42} {21 0 4 2490368} {32 0 0 46} {21 0 2 0} {32 0 0 50} {21 1 0 4097} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestAllowAssemblerWithMultipleSrcIPV6Addr(t *testing.T) {
	cond := assembler.Condition{
		Reject: false,
		SrcIPV6List: []net.IP{
			net.ParseIP("24:22:26::1001"),
			net.ParseIP("24:22:26::1002"),
		},
	}

	instrList, buildErr := assembler.BuildRawInstructions(cond)
	if buildErr != nil {
		t.Errorf("Failed to build raw instructions, %v", buildErr)
		return
	}

	correctInstrListStr := "[{40 0 0 12} {21 0 17 34525} {32 0 0 22} {21 0 6 2359330} {32 0 0 26} {21 0 4 2490368} {32 0 0 30} {21 0 2 0} {32 0 0 34} {21 8 0 4097} {32 0 0 22} {21 0 7 2359330} {32 0 0 26} {21 0 5 2490368} {32 0 0 30} {21 0 3 0} {32 0 0 34} {21 0 1 4098} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestAllowAssemblerWithMultipleDstIPV6Addr(t *testing.T) {
	cond := assembler.Condition{
		Reject: false,
		DstIPV6List: []net.IP{
			net.ParseIP("24:22:26::1001"),
			net.ParseIP("24:22:26::1002"),
		},
	}

	instrList, buildErr := assembler.BuildRawInstructions(cond)
	if buildErr != nil {
		t.Errorf("Failed to build raw instructions, %v", buildErr)
		return
	}

	correctInstrListStr := "[{40 0 0 12} {21 0 17 34525} {32 0 0 38} {21 0 6 2359330} {32 0 0 42} {21 0 4 2490368} {32 0 0 46} {21 0 2 0} {32 0 0 50} {21 8 0 4097} {32 0 0 38} {21 0 7 2359330} {32 0 0 42} {21 0 5 2490368} {32 0 0 46} {21 0 3 0} {32 0 0 50} {21 0 1 4098} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestRejectAssemblerWithMultipleSrcIPV6Addr(t *testing.T) {
	cond := assembler.Condition{
		Reject: true,
		SrcIPV6List: []net.IP{
			net.ParseIP("24:22:26::1001"),
			net.ParseIP("24:22:26::1002"),
		},
	}

	instrList, buildErr := assembler.BuildRawInstructions(cond)
	if buildErr != nil {
		t.Errorf("Failed to build raw instructions, %v", buildErr)
		return
	}

	correctInstrListStr := "[{40 0 0 12} {21 0 16 34525} {32 0 0 22} {21 0 6 2359330} {32 0 0 26} {21 0 4 2490368} {32 0 0 30} {21 0 2 0} {32 0 0 34} {21 9 0 4097} {32 0 0 22} {21 0 6 2359330} {32 0 0 26} {21 0 4 2490368} {32 0 0 30} {21 0 2 0} {32 0 0 34} {21 1 0 4098} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestRejectAssemblerWithMultipleDstIPV6Addr(t *testing.T) {
	cond := assembler.Condition{
		Reject: true,
		DstIPV6List: []net.IP{
			net.ParseIP("24:22:26::1001"),
			net.ParseIP("24:22:26::1002"),
		},
	}

	instrList, buildErr := assembler.BuildRawInstructions(cond)
	if buildErr != nil {
		t.Errorf("Failed to build raw instructions, %v", buildErr)
		return
	}

	correctInstrListStr := "[{40 0 0 12} {21 0 16 34525} {32 0 0 38} {21 0 6 2359330} {32 0 0 42} {21 0 4 2490368} {32 0 0 46} {21 0 2 0} {32 0 0 50} {21 9 0 4097} {32 0 0 38} {21 0 6 2359330} {32 0 0 42} {21 0 4 2490368} {32 0 0 46} {21 0 2 0} {32 0 0 50} {21 1 0 4098} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestAllowAssemblerWithSingleSrcDstIPV6Addr(t *testing.T) {
	cond := assembler.Condition{
		Reject: false,
		SrcIPV6List: []net.IP{
			net.ParseIP("24:22:26::1001"),
		},
		DstIPV6List: []net.IP{
			net.ParseIP("24:22:26::1001"),
		},
	}

	instrList, buildErr := assembler.BuildRawInstructions(cond)
	if buildErr != nil {
		t.Errorf("Failed to build raw instructions, %v", buildErr)
		return
	}

	correctInstrListStr := "[{40 0 0 12} {21 0 17 34525} {32 0 0 22} {21 0 6 2359330} {32 0 0 26} {21 0 4 2490368} {32 0 0 30} {21 0 2 0} {32 0 0 34} {21 8 0 4097} {32 0 0 38} {21 0 7 2359330} {32 0 0 42} {21 0 5 2490368} {32 0 0 46} {21 0 3 0} {32 0 0 50} {21 0 1 4097} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestRejectAssemblerWithSingleSrcDstIPV6Addr(t *testing.T) {
	cond := assembler.Condition{
		Reject: true,
		SrcIPV6List: []net.IP{
			net.ParseIP("24:22:26::1001"),
		},
		DstIPV6List: []net.IP{
			net.ParseIP("24:22:26::1001"),
		},
	}

	instrList, buildErr := assembler.BuildRawInstructions(cond)
	if buildErr != nil {
		t.Errorf("Failed to build raw instructions, %v", buildErr)
		return
	}

	correctInstrListStr := "[{40 0 0 12} {21 0 16 34525} {32 0 0 22} {21 0 6 2359330} {32 0 0 26} {21 0 4 2490368} {32 0 0 30} {21 0 2 0} {32 0 0 34} {21 9 0 4097} {32 0 0 38} {21 0 6 2359330} {32 0 0 42} {21 0 4 2490368} {32 0 0 46} {21 0 2 0} {32 0 0 50} {21 1 0 4097} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestAllowAssemblerWithMultipleSrcDstIPV6Addr(t *testing.T) {
	cond := assembler.Condition{
		Reject: false,
		SrcIPV6List: []net.IP{
			net.ParseIP("24:22:26::1001"),
			net.ParseIP("24:22:26::1002"),
		},
		DstIPV6List: []net.IP{
			net.ParseIP("24:22:26::1001"),
			net.ParseIP("24:22:26::1002"),
		},
	}

	instrList, buildErr := assembler.BuildRawInstructions(cond)
	if buildErr != nil {
		t.Errorf("Failed to build raw instructions, %v", buildErr)
		return
	}

	correctInstrListStr := "[{40 0 0 12} {21 0 33 34525} {32 0 0 22} {21 0 6 2359330} {32 0 0 26} {21 0 4 2490368} {32 0 0 30} {21 0 2 0} {32 0 0 34} {21 24 0 4097} {32 0 0 22} {21 0 6 2359330} {32 0 0 26} {21 0 4 2490368} {32 0 0 30} {21 0 2 0} {32 0 0 34} {21 16 0 4098} {32 0 0 38} {21 0 6 2359330} {32 0 0 42} {21 0 4 2490368} {32 0 0 46} {21 0 2 0} {32 0 0 50} {21 8 0 4097} {32 0 0 38} {21 0 7 2359330} {32 0 0 42} {21 0 5 2490368} {32 0 0 46} {21 0 3 0} {32 0 0 50} {21 0 1 4098} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestRejectAssemblerWithMultipleSrcDstIPV6Addr(t *testing.T) {
	cond := assembler.Condition{
		Reject: true,
		SrcIPV6List: []net.IP{
			net.ParseIP("24:22:26::1001"),
			net.ParseIP("24:22:26::1002"),
		},
		DstIPV6List: []net.IP{
			net.ParseIP("24:22:26::1001"),
			net.ParseIP("24:22:26::1002"),
		},
	}

	instrList, buildErr := assembler.BuildRawInstructions(cond)
	if buildErr != nil {
		t.Errorf("Failed to build raw instructions, %v", buildErr)
		return
	}

	correctInstrListStr := "[{40 0 0 12} {21 0 32 34525} {32 0 0 22} {21 0 6 2359330} {32 0 0 26} {21 0 4 2490368} {32 0 0 30} {21 0 2 0} {32 0 0 34} {21 25 0 4097} {32 0 0 22} {21 0 6 2359330} {32 0 0 26} {21 0 4 2490368} {32 0 0 30} {21 0 2 0} {32 0 0 34} {21 17 0 4098} {32 0 0 38} {21 0 6 2359330} {32 0 0 42} {21 0 4 2490368} {32 0 0 46} {21 0 2 0} {32 0 0 50} {21 9 0 4097} {32 0 0 38} {21 0 6 2359330} {32 0 0 42} {21 0 4 2490368} {32 0 0 46} {21 0 2 0} {32 0 0 50} {21 1 0 4098} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}
