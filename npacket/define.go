package npacket

const (
	EthAbsoluteOffIndex = 12
	EthTypeSize         = 2

	IPV4Size                = 4
	SrcIPV4AbsoluteOffIndex = 26
	DstIPV4AbsoluteOffIndex = SrcIPV4AbsoluteOffIndex + 4

	IPV6Size                = IPV4Size * 4
	SrcIPV6AbsoluteOffIndex = 22
	DstIPV6AbsoluteOffIndex = SrcIPV6AbsoluteOffIndex + 16

	IPV6ValuePartsNum = 4

	IPV6AddrCellInstrNum = 2

	IPProtoSize                        = 1
	IPProtocolIPV4AbsoluteOffIndex     = 23
	IPProtocolIPV6AbsoluteOffIndex     = 20
	IPProtocolIPV6FragAbsoluteOffIndex = 54
)
