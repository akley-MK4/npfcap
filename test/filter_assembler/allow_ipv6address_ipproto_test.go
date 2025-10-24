package filter_assembler

import (
	"fmt"
	"github.com/akley-MK4/npfcap/filter/assembler"
	"github.com/google/gopacket/layers"
	"net"
	"testing"
)

func TestAllowSingleSrcIPV6AddressIPProto_1(t *testing.T) {
	cond := assembler.Condition{
		Reject: false,
		SrcIPV6List: []net.IP{
			net.ParseIP("24:22:26::1001"),
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

	correctInstrListStr := "[{40 0 0 12} {21 0 14 34525} {32 0 0 22} {21 0 12 2359330} {32 0 0 26} {21 0 10 2490368} {32 0 0 30} {21 0 8 0} {32 0 0 34} {21 0 6 4097} {48 0 0 20} {21 3 0 6} {21 0 3 44} {48 0 0 54} {21 0 1 6} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestAllowSingleSrcIPV6AddressMultipleIPProto_2(t *testing.T) {
	cond := assembler.Condition{
		Reject: false,
		SrcIPV6List: []net.IP{
			net.ParseIP("24:22:26::1001"),
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

	correctInstrListStr := "[{40 0 0 12} {21 0 16 34525} {32 0 0 22} {21 0 14 2359330} {32 0 0 26} {21 0 12 2490368} {32 0 0 30} {21 0 10 0} {32 0 0 34} {21 0 8 4097} {48 0 0 20} {21 5 0 6} {21 4 0 17} {21 0 4 44} {48 0 0 54} {21 1 0 6} {21 0 1 17} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestAllowMultipleSrcIPV6AddressIPProto_3(t *testing.T) {
	cond := assembler.Condition{
		Reject: false,
		SrcIPV6List: []net.IP{
			net.ParseIP("24:22:26::1001"),
			net.ParseIP("24:22:26::1002"),
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

	correctInstrListStr := "[{40 0 0 12} {21 0 24 34525} {32 0 0 22} {21 0 6 2359330} {32 0 0 26} {21 0 4 2490368} {32 0 0 30} {21 0 2 0} {32 0 0 34} {21 8 0 4097} {32 0 0 22} {21 0 14 2359330} {32 0 0 26} {21 0 12 2490368} {32 0 0 30} {21 0 10 0} {32 0 0 34} {21 0 8 4098} {48 0 0 20} {21 5 0 6} {21 4 0 17} {21 0 4 44} {48 0 0 54} {21 1 0 6} {21 0 1 17} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestAllowSingleDstIPV6AddressIPProto_4(t *testing.T) {
	cond := assembler.Condition{
		Reject: false,
		DstIPV6List: []net.IP{
			net.ParseIP("24:22:26::1001"),
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

	correctInstrListStr := "[{40 0 0 12} {21 0 14 34525} {32 0 0 38} {21 0 12 2359330} {32 0 0 42} {21 0 10 2490368} {32 0 0 46} {21 0 8 0} {32 0 0 50} {21 0 6 4097} {48 0 0 20} {21 3 0 6} {21 0 3 44} {48 0 0 54} {21 0 1 6} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestAllowSingleDstIPV6AddressMultipleIPProto_5(t *testing.T) {
	cond := assembler.Condition{
		Reject: false,
		DstIPV6List: []net.IP{
			net.ParseIP("24:22:26::1001"),
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

	correctInstrListStr := "[{40 0 0 12} {21 0 16 34525} {32 0 0 38} {21 0 14 2359330} {32 0 0 42} {21 0 12 2490368} {32 0 0 46} {21 0 10 0} {32 0 0 50} {21 0 8 4097} {48 0 0 20} {21 5 0 6} {21 4 0 17} {21 0 4 44} {48 0 0 54} {21 1 0 6} {21 0 1 17} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestAllowMultipleDstIPV6AddressIPProto_6(t *testing.T) {
	cond := assembler.Condition{
		Reject: false,
		DstIPV6List: []net.IP{
			net.ParseIP("24:22:26::1001"),
			net.ParseIP("24:22:26::1002"),
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

	correctInstrListStr := "[{40 0 0 12} {21 0 24 34525} {32 0 0 38} {21 0 6 2359330} {32 0 0 42} {21 0 4 2490368} {32 0 0 46} {21 0 2 0} {32 0 0 50} {21 8 0 4097} {32 0 0 38} {21 0 14 2359330} {32 0 0 42} {21 0 12 2490368} {32 0 0 46} {21 0 10 0} {32 0 0 50} {21 0 8 4098} {48 0 0 20} {21 5 0 6} {21 4 0 17} {21 0 4 44} {48 0 0 54} {21 1 0 6} {21 0 1 17} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestAllowSingleSrcDstIPV6AddressIPProto_7(t *testing.T) {
	cond := assembler.Condition{
		Reject: false,
		SrcIPV6List: []net.IP{
			net.ParseIP("24:22:26::1001"),
		},
		DstIPV6List: []net.IP{
			net.ParseIP("24:22:26::1001"),
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

	correctInstrListStr := "[{40 0 0 12} {21 0 22 34525} {32 0 0 22} {21 0 6 2359330} {32 0 0 26} {21 0 4 2490368} {32 0 0 30} {21 0 2 0} {32 0 0 34} {21 8 0 4097} {32 0 0 38} {21 0 12 2359330} {32 0 0 42} {21 0 10 2490368} {32 0 0 46} {21 0 8 0} {32 0 0 50} {21 0 6 4097} {48 0 0 20} {21 3 0 6} {21 0 3 44} {48 0 0 54} {21 0 1 6} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestAllowMultipleSrcIPV6AddrSingleDstIPV6AddrIPProto_8(t *testing.T) {
	cond := assembler.Condition{
		Reject: false,
		SrcIPV6List: []net.IP{
			net.ParseIP("24:22:26::1001"),
			net.ParseIP("24:22:26::1002"),
		},
		DstIPV6List: []net.IP{
			net.ParseIP("24:22:26::1001"),
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

	correctInstrListStr := "[{40 0 0 12} {21 0 30 34525} {32 0 0 22} {21 0 6 2359330} {32 0 0 26} {21 0 4 2490368} {32 0 0 30} {21 0 2 0} {32 0 0 34} {21 16 0 4097} {32 0 0 22} {21 0 6 2359330} {32 0 0 26} {21 0 4 2490368} {32 0 0 30} {21 0 2 0} {32 0 0 34} {21 8 0 4098} {32 0 0 38} {21 0 12 2359330} {32 0 0 42} {21 0 10 2490368} {32 0 0 46} {21 0 8 0} {32 0 0 50} {21 0 6 4097} {48 0 0 20} {21 3 0 6} {21 0 3 44} {48 0 0 54} {21 0 1 6} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestAllowMultipleDstIPV6AddrSingleSrcIPV6AddrIPProto_9(t *testing.T) {
	cond := assembler.Condition{
		Reject: false,
		SrcIPV6List: []net.IP{
			net.ParseIP("24:22:26::1001"),
		},
		DstIPV6List: []net.IP{
			net.ParseIP("24:22:26::1001"),
			net.ParseIP("24:22:26::1002"),
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

	correctInstrListStr := "[{40 0 0 12} {21 0 30 34525} {32 0 0 22} {21 0 6 2359330} {32 0 0 26} {21 0 4 2490368} {32 0 0 30} {21 0 2 0} {32 0 0 34} {21 16 0 4097} {32 0 0 38} {21 0 6 2359330} {32 0 0 42} {21 0 4 2490368} {32 0 0 46} {21 0 2 0} {32 0 0 50} {21 8 0 4097} {32 0 0 38} {21 0 12 2359330} {32 0 0 42} {21 0 10 2490368} {32 0 0 46} {21 0 8 0} {32 0 0 50} {21 0 6 4098} {48 0 0 20} {21 3 0 6} {21 0 3 44} {48 0 0 54} {21 0 1 6} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestAllowSingleSrcDstIPV6AddrMultipleIPProto_10(t *testing.T) {
	cond := assembler.Condition{
		Reject: false,
		SrcIPV6List: []net.IP{
			net.ParseIP("24:22:26::1001"),
		},
		DstIPV6List: []net.IP{
			net.ParseIP("24:22:26::1001"),
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

	correctInstrListStr := "[{40 0 0 12} {21 0 24 34525} {32 0 0 22} {21 0 6 2359330} {32 0 0 26} {21 0 4 2490368} {32 0 0 30} {21 0 2 0} {32 0 0 34} {21 8 0 4097} {32 0 0 38} {21 0 14 2359330} {32 0 0 42} {21 0 12 2490368} {32 0 0 46} {21 0 10 0} {32 0 0 50} {21 0 8 4097} {48 0 0 20} {21 5 0 6} {21 4 0 17} {21 0 4 44} {48 0 0 54} {21 1 0 6} {21 0 1 17} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestAllowMultipleSrcDstIPV6AddrIPProto_11(t *testing.T) {
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

	correctInstrListStr := "[{40 0 0 12} {21 0 40 34525} {32 0 0 22} {21 0 6 2359330} {32 0 0 26} {21 0 4 2490368} {32 0 0 30} {21 0 2 0} {32 0 0 34} {21 24 0 4097} {32 0 0 22} {21 0 6 2359330} {32 0 0 26} {21 0 4 2490368} {32 0 0 30} {21 0 2 0} {32 0 0 34} {21 16 0 4098} {32 0 0 38} {21 0 6 2359330} {32 0 0 42} {21 0 4 2490368} {32 0 0 46} {21 0 2 0} {32 0 0 50} {21 8 0 4097} {32 0 0 38} {21 0 14 2359330} {32 0 0 42} {21 0 12 2490368} {32 0 0 46} {21 0 10 0} {32 0 0 50} {21 0 8 4098} {48 0 0 20} {21 5 0 6} {21 4 0 17} {21 0 4 44} {48 0 0 54} {21 1 0 6} {21 0 1 17} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}
