package filter_assembler

import (
	"fmt"
	"github.com/akley-MK4/npfcap/filter/assembler"
	"github.com/google/gopacket/layers"
	"net"
	"testing"
)

func TestRejectSingleSrcIPV6AddressIPProto_1(t *testing.T) {
	cond := assembler.Condition{
		Reject: true,
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

	correctInstrListStr := "[{40 0 0 12} {21 0 13 34525} {32 0 0 22} {21 0 11 2359330} {32 0 0 26} {21 0 9 2490368} {32 0 0 30} {21 0 7 0} {32 0 0 34} {21 0 5 4097} {48 0 0 20} {21 4 0 6} {21 0 2 44} {48 0 0 54} {21 1 0 6} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestRejectSingleSrcIPV6AddressMultipleIPProto_2(t *testing.T) {
	cond := assembler.Condition{
		Reject: true,
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

	correctInstrListStr := "[{40 0 0 12} {21 0 15 34525} {32 0 0 22} {21 0 13 2359330} {32 0 0 26} {21 0 11 2490368} {32 0 0 30} {21 0 9 0} {32 0 0 34} {21 0 7 4097} {48 0 0 20} {21 6 0 6} {21 5 0 17} {21 0 3 44} {48 0 0 54} {21 2 0 6} {21 1 0 17} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestRejectMultipleSrcIPV6AddressIPProto_3(t *testing.T) {
	cond := assembler.Condition{
		Reject: true,
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

	correctInstrListStr := "[{40 0 0 12} {21 0 23 34525} {32 0 0 22} {21 0 6 2359330} {32 0 0 26} {21 0 4 2490368} {32 0 0 30} {21 0 2 0} {32 0 0 34} {21 8 0 4097} {32 0 0 22} {21 0 13 2359330} {32 0 0 26} {21 0 11 2490368} {32 0 0 30} {21 0 9 0} {32 0 0 34} {21 0 7 4098} {48 0 0 20} {21 6 0 6} {21 5 0 17} {21 0 3 44} {48 0 0 54} {21 2 0 6} {21 1 0 17} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestRejectSingleDstIPV6AddressIPProto_4(t *testing.T) {
	cond := assembler.Condition{
		Reject: true,
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

	correctInstrListStr := "[{40 0 0 12} {21 0 13 34525} {32 0 0 38} {21 0 11 2359330} {32 0 0 42} {21 0 9 2490368} {32 0 0 46} {21 0 7 0} {32 0 0 50} {21 0 5 4097} {48 0 0 20} {21 4 0 6} {21 0 2 44} {48 0 0 54} {21 1 0 6} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestRejectSingleDstIPV6AddressMultipleIPProto_5(t *testing.T) {
	cond := assembler.Condition{
		Reject: true,
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

	correctInstrListStr := "[{40 0 0 12} {21 0 15 34525} {32 0 0 38} {21 0 13 2359330} {32 0 0 42} {21 0 11 2490368} {32 0 0 46} {21 0 9 0} {32 0 0 50} {21 0 7 4097} {48 0 0 20} {21 6 0 6} {21 5 0 17} {21 0 3 44} {48 0 0 54} {21 2 0 6} {21 1 0 17} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestRejectMultipleDstIPV6AddressIPProto_6(t *testing.T) {
	cond := assembler.Condition{
		Reject: true,
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

	correctInstrListStr := "[{40 0 0 12} {21 0 23 34525} {32 0 0 38} {21 0 6 2359330} {32 0 0 42} {21 0 4 2490368} {32 0 0 46} {21 0 2 0} {32 0 0 50} {21 8 0 4097} {32 0 0 38} {21 0 13 2359330} {32 0 0 42} {21 0 11 2490368} {32 0 0 46} {21 0 9 0} {32 0 0 50} {21 0 7 4098} {48 0 0 20} {21 6 0 6} {21 5 0 17} {21 0 3 44} {48 0 0 54} {21 2 0 6} {21 1 0 17} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestRejectSingleSrcDstIPV6AddressIPProto_7(t *testing.T) {
	cond := assembler.Condition{
		Reject: true,
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

	correctInstrListStr := "[{40 0 0 12} {21 0 21 34525} {32 0 0 22} {21 0 6 2359330} {32 0 0 26} {21 0 4 2490368} {32 0 0 30} {21 0 2 0} {32 0 0 34} {21 8 0 4097} {32 0 0 38} {21 0 11 2359330} {32 0 0 42} {21 0 9 2490368} {32 0 0 46} {21 0 7 0} {32 0 0 50} {21 0 5 4097} {48 0 0 20} {21 4 0 6} {21 0 2 44} {48 0 0 54} {21 1 0 6} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestRejectMultipleSrcIPV6AddrSingleDstIPV6AddrIPProto_8(t *testing.T) {
	cond := assembler.Condition{
		Reject: true,
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

	correctInstrListStr := "[{40 0 0 12} {21 0 29 34525} {32 0 0 22} {21 0 6 2359330} {32 0 0 26} {21 0 4 2490368} {32 0 0 30} {21 0 2 0} {32 0 0 34} {21 16 0 4097} {32 0 0 22} {21 0 6 2359330} {32 0 0 26} {21 0 4 2490368} {32 0 0 30} {21 0 2 0} {32 0 0 34} {21 8 0 4098} {32 0 0 38} {21 0 11 2359330} {32 0 0 42} {21 0 9 2490368} {32 0 0 46} {21 0 7 0} {32 0 0 50} {21 0 5 4097} {48 0 0 20} {21 4 0 6} {21 0 2 44} {48 0 0 54} {21 1 0 6} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestRejectMultipleDstIPV6AddrSingleSrcIPV6AddrIPProto_9(t *testing.T) {
	cond := assembler.Condition{
		Reject: true,
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

	correctInstrListStr := "[{40 0 0 12} {21 0 29 34525} {32 0 0 22} {21 0 6 2359330} {32 0 0 26} {21 0 4 2490368} {32 0 0 30} {21 0 2 0} {32 0 0 34} {21 16 0 4097} {32 0 0 38} {21 0 6 2359330} {32 0 0 42} {21 0 4 2490368} {32 0 0 46} {21 0 2 0} {32 0 0 50} {21 8 0 4097} {32 0 0 38} {21 0 11 2359330} {32 0 0 42} {21 0 9 2490368} {32 0 0 46} {21 0 7 0} {32 0 0 50} {21 0 5 4098} {48 0 0 20} {21 4 0 6} {21 0 2 44} {48 0 0 54} {21 1 0 6} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestRejectSingleSrcDstIPV6AddrMultipleIPProto_10(t *testing.T) {
	cond := assembler.Condition{
		Reject: true,
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

	correctInstrListStr := "[{40 0 0 12} {21 0 23 34525} {32 0 0 22} {21 0 6 2359330} {32 0 0 26} {21 0 4 2490368} {32 0 0 30} {21 0 2 0} {32 0 0 34} {21 8 0 4097} {32 0 0 38} {21 0 13 2359330} {32 0 0 42} {21 0 11 2490368} {32 0 0 46} {21 0 9 0} {32 0 0 50} {21 0 7 4097} {48 0 0 20} {21 6 0 6} {21 5 0 17} {21 0 3 44} {48 0 0 54} {21 2 0 6} {21 1 0 17} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}

func TestRejectMultipleSrcDstIPV6AddrIPProto_11(t *testing.T) {
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

	correctInstrListStr := "[{40 0 0 12} {21 0 39 34525} {32 0 0 22} {21 0 6 2359330} {32 0 0 26} {21 0 4 2490368} {32 0 0 30} {21 0 2 0} {32 0 0 34} {21 24 0 4097} {32 0 0 22} {21 0 6 2359330} {32 0 0 26} {21 0 4 2490368} {32 0 0 30} {21 0 2 0} {32 0 0 34} {21 16 0 4098} {32 0 0 38} {21 0 6 2359330} {32 0 0 42} {21 0 4 2490368} {32 0 0 46} {21 0 2 0} {32 0 0 50} {21 8 0 4097} {32 0 0 38} {21 0 13 2359330} {32 0 0 42} {21 0 11 2490368} {32 0 0 46} {21 0 9 0} {32 0 0 50} {21 0 7 4098} {48 0 0 20} {21 6 0 6} {21 5 0 17} {21 0 3 44} {48 0 0 54} {21 2 0 6} {21 1 0 17} {6 0 0 262144} {6 0 0 0}]"
	generatedInstrListStr := fmt.Sprintf("%v", instrList)

	if correctInstrListStr != generatedInstrListStr {
		t.Errorf("Generated an incorrect instruction list %v\n, correct instruction list %v",
			generatedInstrListStr, correctInstrListStr)
	}
}
