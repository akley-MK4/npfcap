package filter_assembler

import (
	"fmt"
	"github.com/akley-MK4/npfcap/filter/assembler"
	"github.com/google/gopacket/layers"
	"net"
	"testing"
)

func TestAllowSingleSrcIPV4AddressIPProto_1(t *testing.T) {
	cond := assembler.Condition{
		Reject: false,
		SrcIPV4List: []net.IP{
			net.ParseIP("1.1.1.1"),
		},
		IPProtocolList: []layers.IPProtocol{
			layers.IPProtocolTCP,
		},
	}

	instrList, buildErr := assembler.BuildRawInstructions(cond)
	if buildErr != nil {
		t.Errorf("Failed to build raw instructions, %v", buildErr)
		return
	}

	correctInstrListStr := "[{40 0 0 12} {21 0 5 2048} {32 0 0 26} {21 0 3 16843009} {48 0 0 23} {21 0 1 6} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestAllowSingleSrcIPV4AddressMultipleIPProto_2(t *testing.T) {
	cond := assembler.Condition{
		Reject: false,
		SrcIPV4List: []net.IP{
			net.ParseIP("1.1.1.1"),
		},
		IPProtocolList: []layers.IPProtocol{
			layers.IPProtocolTCP,
			layers.IPProtocolUDP,
		},
	}

	instrList, buildErr := assembler.BuildRawInstructions(cond)
	if buildErr != nil {
		t.Errorf("Failed to build raw instructions, %v", buildErr)
		return
	}

	correctInstrListStr := "[{40 0 0 12} {21 0 6 2048} {32 0 0 26} {21 0 4 16843009} {48 0 0 23} {21 1 0 6} {21 0 1 17} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestAllowMultipleSrcIPV4AddressIPProto_3(t *testing.T) {
	cond := assembler.Condition{
		Reject: false,
		SrcIPV4List: []net.IP{
			net.ParseIP("1.1.1.1"),
			net.ParseIP("1.1.1.2"),
		},
		IPProtocolList: []layers.IPProtocol{
			layers.IPProtocolTCP,
			layers.IPProtocolUDP,
		},
	}

	instrList, buildErr := assembler.BuildRawInstructions(cond)
	if buildErr != nil {
		t.Errorf("Failed to build raw instructions, %v", buildErr)
		return
	}

	correctInstrListStr := "[{40 0 0 12} {21 0 7 2048} {32 0 0 26} {21 1 0 16843009} {21 0 4 16843010} {48 0 0 23} {21 1 0 6} {21 0 1 17} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestAllowSingleDstIPV4AddressIPProto_4(t *testing.T) {
	cond := assembler.Condition{
		Reject: false,
		DstIPV4List: []net.IP{
			net.ParseIP("1.1.1.1"),
		},
		IPProtocolList: []layers.IPProtocol{
			layers.IPProtocolTCP,
		},
	}

	instrList, buildErr := assembler.BuildRawInstructions(cond)
	if buildErr != nil {
		t.Errorf("Failed to build raw instructions, %v", buildErr)
		return
	}

	correctInstrListStr := "[{40 0 0 12} {21 0 5 2048} {32 0 0 30} {21 0 3 16843009} {48 0 0 23} {21 0 1 6} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestAllowSingleDstIPV4AddressMultipleIPProto_5(t *testing.T) {
	cond := assembler.Condition{
		Reject: false,
		DstIPV4List: []net.IP{
			net.ParseIP("1.1.1.1"),
		},
		IPProtocolList: []layers.IPProtocol{
			layers.IPProtocolTCP,
			layers.IPProtocolUDP,
		},
	}

	instrList, buildErr := assembler.BuildRawInstructions(cond)
	if buildErr != nil {
		t.Errorf("Failed to build raw instructions, %v", buildErr)
		return
	}

	correctInstrListStr := "[{40 0 0 12} {21 0 6 2048} {32 0 0 30} {21 0 4 16843009} {48 0 0 23} {21 1 0 6} {21 0 1 17} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestAllowMultipleDstIPV4AddressIPProto_6(t *testing.T) {
	cond := assembler.Condition{
		Reject: false,
		DstIPV4List: []net.IP{
			net.ParseIP("1.1.1.1"),
			net.ParseIP("1.1.1.2"),
		},
		IPProtocolList: []layers.IPProtocol{
			layers.IPProtocolTCP,
			layers.IPProtocolUDP,
		},
	}

	instrList, buildErr := assembler.BuildRawInstructions(cond)
	if buildErr != nil {
		t.Errorf("Failed to build raw instructions, %v", buildErr)
		return
	}

	correctInstrListStr := "[{40 0 0 12} {21 0 7 2048} {32 0 0 30} {21 1 0 16843009} {21 0 4 16843010} {48 0 0 23} {21 1 0 6} {21 0 1 17} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestAllowSingleSrcDstIPV4AddressIPProto_7(t *testing.T) {
	cond := assembler.Condition{
		Reject: false,
		SrcIPV4List: []net.IP{
			net.ParseIP("1.1.1.1"),
		},
		DstIPV4List: []net.IP{
			net.ParseIP("1.1.1.1"),
		},
		IPProtocolList: []layers.IPProtocol{
			layers.IPProtocolTCP,
		},
	}

	instrList, buildErr := assembler.BuildRawInstructions(cond)
	if buildErr != nil {
		t.Errorf("Failed to build raw instructions, %v", buildErr)
		return
	}

	correctInstrListStr := "[{40 0 0 12} {21 0 7 2048} {32 0 0 26} {21 2 0 16843009} {32 0 0 30} {21 0 3 16843009} {48 0 0 23} {21 0 1 6} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestAllowMultipleSrcIPV4AddrSingleDstIPV4AddrIPProto_8(t *testing.T) {
	cond := assembler.Condition{
		Reject: false,
		SrcIPV4List: []net.IP{
			net.ParseIP("1.1.1.1"),
			net.ParseIP("1.1.1.2"),
		},
		DstIPV4List: []net.IP{
			net.ParseIP("1.1.1.1"),
		},
		IPProtocolList: []layers.IPProtocol{
			layers.IPProtocolTCP,
		},
	}

	instrList, buildErr := assembler.BuildRawInstructions(cond)
	if buildErr != nil {
		t.Errorf("Failed to build raw instructions, %v", buildErr)
		return
	}

	correctInstrListStr := "[{40 0 0 12} {21 0 8 2048} {32 0 0 26} {21 3 0 16843009} {21 2 0 16843010} {32 0 0 30} {21 0 3 16843009} {48 0 0 23} {21 0 1 6} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestAllowMultipleDstIPV4AddrSingleSrcIPV4AddrIPProto_9(t *testing.T) {
	cond := assembler.Condition{
		Reject: false,
		SrcIPV4List: []net.IP{
			net.ParseIP("1.1.1.1"),
		},
		DstIPV4List: []net.IP{
			net.ParseIP("1.1.1.1"),
			net.ParseIP("1.1.1.2"),
		},
		IPProtocolList: []layers.IPProtocol{
			layers.IPProtocolTCP,
		},
	}

	instrList, buildErr := assembler.BuildRawInstructions(cond)
	if buildErr != nil {
		t.Errorf("Failed to build raw instructions, %v", buildErr)
		return
	}

	correctInstrListStr := "[{40 0 0 12} {21 0 8 2048} {32 0 0 26} {21 3 0 16843009} {32 0 0 30} {21 1 0 16843009} {21 0 3 16843010} {48 0 0 23} {21 0 1 6} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestAllowSingleSrcDstIPV4AddrMultipleIPProto_10(t *testing.T) {
	cond := assembler.Condition{
		Reject: false,
		SrcIPV4List: []net.IP{
			net.ParseIP("1.1.1.1"),
		},
		DstIPV4List: []net.IP{
			net.ParseIP("1.1.1.1"),
		},
		IPProtocolList: []layers.IPProtocol{
			layers.IPProtocolTCP,
			layers.IPProtocolUDP,
		},
	}

	instrList, buildErr := assembler.BuildRawInstructions(cond)
	if buildErr != nil {
		t.Errorf("Failed to build raw instructions, %v", buildErr)
		return
	}

	correctInstrListStr := "[{40 0 0 12} {21 0 8 2048} {32 0 0 26} {21 2 0 16843009} {32 0 0 30} {21 0 4 16843009} {48 0 0 23} {21 1 0 6} {21 0 1 17} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestAllowMultipleSrcDstIPV4AddrIPProto_11(t *testing.T) {
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
		IPProtocolList: []layers.IPProtocol{
			layers.IPProtocolTCP,
			layers.IPProtocolUDP,
		},
	}

	instrList, buildErr := assembler.BuildRawInstructions(cond)
	if buildErr != nil {
		t.Errorf("Failed to build raw instructions, %v", buildErr)
		return
	}

	correctInstrListStr := "[{40 0 0 12} {21 0 10 2048} {32 0 0 26} {21 4 0 16843009} {21 3 0 16843010} {32 0 0 30} {21 1 0 16843009} {21 0 4 16843010} {48 0 0 23} {21 1 0 6} {21 0 1 17} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}
