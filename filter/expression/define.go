package expression

import "github.com/google/gopacket/layers"

type LogicalOperatorType uint8

const (
	LogicalOperatorAnd LogicalOperatorType = iota
	LogicalOperatorOr
	LogicalOperatorNot
)

type DirectionType uint8

const (
	DirectionTypeDi = iota
	DirectionTypeSrc
	DirectionTypeDst
)

var (
	directionTypes = []DirectionType{
		DirectionTypeDi, DirectionTypeSrc, DirectionTypeDst,
	}

	lpTypes = []LogicalOperatorType{
		LogicalOperatorAnd, LogicalOperatorOr, LogicalOperatorNot,
	}
)

var (
	dtArgsInfoMap = map[DirectionType]*DirectionArgsInfo{
		DirectionTypeDi:  {IPArg: "host", Port: "port"},
		DirectionTypeSrc: {IPArg: "src", Port: "src"},
		DirectionTypeDst: {IPArg: "dst", Port: "dst"},
	}

	ipProtoInfoMap = map[layers.IPProtocol]string{
		layers.IPProtocolTCP:  "tcp",
		layers.IPProtocolUDP:  "udp",
		layers.IPProtocolSCTP: "sctp",
	}

	logicalOperatorTypeMap = map[LogicalOperatorType]string{
		LogicalOperatorAnd: "and",
		LogicalOperatorOr:  "or",
		LogicalOperatorNot: "not",
	}
)
