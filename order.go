package ipset

import (
	"encoding/binary"

	"github.com/vishvananda/netlink/nl"
)

var (
	native       = nl.NativeEndian()
	networkOrder = binary.BigEndian
)

func htonl(val uint32) []byte {
	bytes := make([]byte, 4)
	networkOrder.PutUint32(bytes, val)
	return bytes
}

func htons(val uint16) []byte {
	bytes := make([]byte, 2)
	networkOrder.PutUint16(bytes, val)
	return bytes
}

func ntohl(buf []byte) uint32 {
	return networkOrder.Uint32(buf)
}

func ntohs(buf []byte) uint16 {
	return networkOrder.Uint16(buf)
}

func Uint8Ptr(v uint8) *uint8 {
	return &v
}

func Uint16Ptr(v uint16) *uint16 {
	return &v
}

func Uint32Ptr(v uint32) *uint32 {
	return &v
}
