package ipset

import (
	"strings"
)

const (
	TypeListSet = "list:set"

	TypeHashMac        = "hash:mac"
	TypeHashIPMac      = "hash:ip,mac"
	TypeHashNetIface   = "hash:net,iface"
	TypeHashNetPort    = "hash:net,port"
	TypeHashNetPortNet = "hash:net,port,net"
	TypeHashNetNet     = "hash:net,net"
	TypeHashNet        = "hash:net"
	TypeHashIPPortNet  = "hash:ip,port,net"
	TypeHashIPPortIP   = "hash:ip,port,ip"
	TypeHashIPMark     = "hash:ip,mark"
	TypeHashIPPort     = "hash:ip,port"
	TypeHashIP         = "hash:ip"

	TypeBitmapPort  = "bitmap:port"
	TypeBitmapIPMac = "bitmap:ip,mac"
	TypeBitmapIP    = "bitmap:ip"
)

type TypeName string

func (t TypeName) Method() string {
	idx := strings.IndexByte(string(t), ':')
	if idx > 0 {
		return string(t)[:idx]
	}
	return ""
}

// Protocol returns the ipset protocol version from the kernel
func Protocol() (uint8, uint8, error) {
	return pkgHandle.Protocol()
}

// Create creates a new ipset
func Create(setname, typename string, options CreateOptions) error {
	return pkgHandle.Create(setname, typename, options)
}

// Destroy destroys an existing ipset
func Destroy(setname string) error {
	return pkgHandle.Destroy(setname)
}

// Flush flushes an existing ipset
func Flush(setname string) error {
	return pkgHandle.Flush(setname)
}

// List dumps an specific ipset.
func List(setname string) (*Sets, error) {
	return pkgHandle.List(setname)
}

// ListAll dumps all ipsets.
func ListAll() ([]Sets, error) {
	return pkgHandle.ListAll()
}

// Add adds an entry to an existing ipset.
func Add(setname string, entry *Entry) error {
	return pkgHandle.Add(setname, entry)
}

// Del deletes an entry from an existing ipset.
func Del(setname string, entry *Entry) error {
	return pkgHandle.Del(setname, entry)
}

var typeRevisionsMap = map[string][]uint8{
	TypeListSet: {3, 2, 1, 0},

	TypeHashMac:        {0},
	TypeHashIPMac:      {0},
	TypeHashNetIface:   {6, 5, 4, 3, 2, 1, 0},
	TypeHashNetPort:    {7, 6, 5, 4, 3, 2, 1},
	TypeHashNetPortNet: {2, 1, 0},
	TypeHashNetNet:     {2, 1, 0},
	TypeHashNet:        {6, 5, 4, 3, 2, 1, 0},
	TypeHashIPPortNet:  {7, 6, 5, 4, 3, 2, 1},
	TypeHashIPPortIP:   {5, 4, 3, 2, 1},
	TypeHashIPMark:     {2, 1, 0},
	TypeHashIPPort:     {5, 4, 3, 2, 1},
	TypeHashIP:         {4, 3, 2, 1, 0},

	TypeBitmapPort:  {3, 2, 1, 0},
	TypeBitmapIPMac: {3, 2, 1, 0},
	TypeBitmapIP:    {3, 2, 1, 0},
}
