package ipset

import (
	"golang.org/x/sys/unix"
)

const (
	FamilyUnspec = uint8(unix.AF_UNSPEC)
	// FamilyIPV4 represents IPv4 protocol.
	FamilyIPV4 = uint8(unix.AF_INET)
	// FamilyIPV6 represents IPv6 protocol.
	FamilyIPV6 = uint8(unix.AF_INET6)

	// ProtocolTCP represents TCP protocol.
	ProtocolTCP = uint16(unix.IPPROTO_TCP)
	// ProtocolUDP represents UDP protocol.
	ProtocolUDP = uint16(unix.IPPROTO_UDP)
	// ProtocolSCTP represents SCTP protocol.
	ProtocolSCTP = uint16(unix.IPPROTO_SCTP)
)
