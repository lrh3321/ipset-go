package ipset

import (
	"bytes"
	"net"
)

// CreateOptions is the options struct for creating a new ipset
type CreateOptions struct {
	Family   uint8
	Protocol uint8
	Size     uint32 // size/hashsize
	MaxElem  uint32 // max elements

	Replace  bool // replace existing ipset
	Timeout  uint32
	Counters bool
	Comments bool
	Skbinfo  bool

	Revision uint8
	IPFrom   net.IP
	IPTo     net.IP
	NetMask  uint32
	PortFrom uint16
	PortTo   uint16
}

func (opt *CreateOptions) fillWithDefault(typename string) {
	revisions := typeRevisionsMap[typename]
	if len(revisions) == 1 || bytes.IndexByte(revisions, opt.Revision) < 0 {
		opt.Revision = revisions[0]
	}

	if opt.Family == FamilyUnspec {
		switch typename {
		case TypeHashMac:
		case TypeBitmapPort:
		case TypeListSet:
		default:
			opt.Family = FamilyIPV4
		}
	}

	if opt.Family == FamilyIPV4 {
		opt.IPFrom = opt.IPFrom.To4()
		opt.IPTo = opt.IPTo.To4()
	}
}

func (opts *CreateOptions) CadtFlags() uint32 {
	var cadtFlags uint32
	if opts.Comments {
		cadtFlags |= IPSET_FLAG_WITH_COMMENT
	}
	if opts.Counters {
		cadtFlags |= IPSET_FLAG_WITH_COUNTERS
	}
	if opts.Skbinfo {
		cadtFlags |= IPSET_FLAG_WITH_SKBINFO
	}
	return cadtFlags
}
