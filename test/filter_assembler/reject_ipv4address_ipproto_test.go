package filter_assembler

import (
	"fmt"
	"github.com/akley-MK4/npfcap/filter/assembler"
	"github.com/google/gopacket/layers"
	"net"
	"testing"
)

func TestRejectSingleSrcIPV4AddressIPProto(t *testing.T) {
	cond := assembler.Condition{
		Reject: true,
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

	correctInstrListStr := "[{40 0 0 12} {21 0 4 2048} {32 0 0 26} {21 0 2 16843009} {48 0 0 23} {21 1 0 6} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestRejectSingleSrcIPV4AddressMultipleIPProto(t *testing.T) {
	cond := assembler.Condition{
		Reject: true,
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

	correctInstrListStr := "[{40 0 0 12} {21 0 5 2048} {32 0 0 26} {21 0 3 16843009} {48 0 0 23} {21 2 0 6} {21 1 0 17} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestRejectMultipleSrcIPV4AddressIPProto(t *testing.T) {
	cond := assembler.Condition{
		Reject: true,
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

	correctInstrListStr := "[{40 0 0 12} {21 0 6 2048} {32 0 0 26} {21 1 0 16843009} {21 0 3 16843010} {48 0 0 23} {21 2 0 6} {21 1 0 17} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestRejectSingleDstIPV4AddressIPProto(t *testing.T) {
	cond := assembler.Condition{
		Reject: true,
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

	correctInstrListStr := "[{40 0 0 12} {21 0 4 2048} {32 0 0 30} {21 0 2 16843009} {48 0 0 23} {21 1 0 6} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestRejectSingleDstIPV4AddressMultipleIPProto(t *testing.T) {
	cond := assembler.Condition{
		Reject: true,
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

	correctInstrListStr := "[{40 0 0 12} {21 0 5 2048} {32 0 0 30} {21 0 3 16843009} {48 0 0 23} {21 2 0 6} {21 1 0 17} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestRejectMultipleDstIPV4AddressIPProto(t *testing.T) {
	cond := assembler.Condition{
		Reject: true,
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

	correctInstrListStr := "[{40 0 0 12} {21 0 6 2048} {32 0 0 30} {21 1 0 16843009} {21 0 3 16843010} {48 0 0 23} {21 2 0 6} {21 1 0 17} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestRejectSingleSrcDstIPV4AddressIPProto(t *testing.T) {
	cond := assembler.Condition{
		Reject: true,
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

	correctInstrListStr := "[{40 0 0 12} {21 0 6 2048} {32 0 0 26} {21 2 0 16843009} {32 0 0 30} {21 0 2 16843009} {48 0 0 23} {21 1 0 6} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestRejectMultipleSrcIPV4AddrSingleDstIPV4AddrIPProto(t *testing.T) {
	cond := assembler.Condition{
		Reject: true,
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

	correctInstrListStr := "[{40 0 0 12} {21 0 7 2048} {32 0 0 26} {21 3 0 16843009} {21 2 0 16843010} {32 0 0 30} {21 0 2 16843009} {48 0 0 23} {21 1 0 6} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestRejectMultipleDstIPV4AddrSingleSrcIPV4AddrIPProto(t *testing.T) {
	cond := assembler.Condition{
		Reject: true,
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

	correctInstrListStr := "[{40 0 0 12} {21 0 7 2048} {32 0 0 26} {21 3 0 16843009} {32 0 0 30} {21 1 0 16843009} {21 0 2 16843010} {48 0 0 23} {21 1 0 6} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestRejectSingleSrcDstIPV4AddrMultipleIPProto(t *testing.T) {
	cond := assembler.Condition{
		Reject: true,
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

	correctInstrListStr := "[{40 0 0 12} {21 0 7 2048} {32 0 0 26} {21 2 0 16843009} {32 0 0 30} {21 0 3 16843009} {48 0 0 23} {21 2 0 6} {21 1 0 17} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestRejectMultipleSrcDstIPV4AddrIPProto(t *testing.T) {
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

	correctInstrListStr := "[{40 0 0 12} {21 0 9 2048} {32 0 0 26} {21 4 0 16843009} {21 3 0 16843010} {32 0 0 30} {21 1 0 16843009} {21 0 3 16843010} {48 0 0 23} {21 2 0 6} {21 1 0 17} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}
