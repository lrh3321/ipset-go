package ipset

import (
	"log"
	"net"
	"os"
	"syscall"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// Entry is used for adding, updating, retreiving and deleting entries
type Entry struct {
	Name     string
	Comment  string
	MAC      net.HardwareAddr
	IP       net.IP
	CIDR     uint8
	Timeout  *uint32
	Packets  *uint64
	Bytes    *uint64
	Protocol *uint8
	Port     *uint16
	IP2      net.IP
	CIDR2    uint8
	IFace    string
	Mark     *uint32

	Replace bool // replace existing entry
}

// Sets is the result of a dump request for a set
type Sets struct {
	Nfgenmsg           *nl.Nfgenmsg
	Protocol           uint8
	ProtocolMinVersion uint8
	Revision           uint8
	Family             uint8
	Flags              uint8
	SetName            string
	TypeName           string
	Comment            string
	MarkMask           uint32

	IPFrom   net.IP
	IPTo     net.IP
	PortFrom uint16
	PortTo   uint16

	Size         uint32
	HashSize     uint32
	NumEntries   uint32
	MaxElements  uint32
	References   uint32
	SizeInMemory uint32
	CadtFlags    uint32
	Timeout      *uint32
	LineNo       uint32

	Entries []Entry
}

func (h *Handle) Protocol() (protocol uint8, minVersion uint8, err error) {
	req := h.newRequest(IPSET_CMD_PROTOCOL)
	msgs, err := req.Execute(unix.NETLINK_NETFILTER, 0)

	if err != nil {
		return 0, 0, err
	}
	response := ipsetUnserialize(msgs)
	return response.Protocol, response.ProtocolMinVersion, nil
}

func (h *Handle) Create(setname, typename string, options CreateOptions) error {
	req := h.newRequest(IPSET_CMD_CREATE)

	if !options.Replace {
		req.Flags |= unix.NLM_F_EXCL
	}

	req.AddData(nl.NewRtAttr(IPSET_ATTR_SETNAME, nl.ZeroTerminated(setname)))
	req.AddData(nl.NewRtAttr(IPSET_ATTR_TYPENAME, nl.ZeroTerminated(typename)))

	options.fillWithDefault(typename)

	req.AddData(nl.NewRtAttr(IPSET_ATTR_REVISION, nl.Uint8Attr(options.Revision)))

	data := nl.NewRtAttr(IPSET_ATTR_DATA|int(nl.NLA_F_NESTED), nil)

	if options.Family != 0xff {
		req.AddData(nl.NewRtAttr(IPSET_ATTR_FAMILY, nl.Uint8Attr(options.Family)))
	}

	if options.Size > 0 {
		switch TypeName(typename).Method() {
		case "hash":
			data.AddChild(nl.NewRtAttr(IPSET_ATTR_HASHSIZE|int(nl.NLA_F_NET_BYTEORDER), htonl(options.Size)))
		case "list":
			data.AddChild(nl.NewRtAttr(IPSET_ATTR_SIZE|int(nl.NLA_F_NET_BYTEORDER), htonl(options.Size)))
		}
	}

	if options.MaxElem > 0 {
		data.AddChild(nl.NewRtAttr(IPSET_ATTR_MAXELEM|int(nl.NLA_F_NET_BYTEORDER), htonl(options.MaxElem)))
	}

	switch typename {
	case TypeBitmapPort:
		data.AddChild(nl.NewRtAttr(IPSET_ATTR_PORT_FROM|int(nl.NLA_F_NET_BYTEORDER), htons(options.PortFrom)))
		data.AddChild(nl.NewRtAttr(IPSET_ATTR_PORT_TO|int(nl.NLA_F_NET_BYTEORDER), htons(options.PortTo)))
	case TypeBitmapIP, TypeBitmapIPMac:
		ipFrom := nl.NewRtAttr(IPSET_ATTR_IP|int(nl.NLA_F_NESTED), nil)
		ipFrom.AddChild(nl.NewRtAttr(IPSET_ATTR_IP_FROM|int(nl.NLA_F_NET_BYTEORDER), options.IPFrom))
		data.AddChild(ipFrom)

		ipTo := nl.NewRtAttr(IPSET_ATTR_IP_TO|int(nl.NLA_F_NESTED), nil)
		ipTo.AddChild(nl.NewRtAttr(IPSET_ATTR_IP_FROM|int(nl.NLA_F_NET_BYTEORDER), options.IPTo))
		data.AddChild(ipTo)
	}

	if timeout := options.Timeout; timeout > 0 {
		data.AddChild(&nl.Uint32Attribute{Type: IPSET_ATTR_TIMEOUT | nl.NLA_F_NET_BYTEORDER, Value: timeout})
	}

	if cadtFlags := options.CadtFlags(); cadtFlags > 0 {
		data.AddChild(&nl.Uint32Attribute{Type: IPSET_ATTR_CADT_FLAGS | nl.NLA_F_NET_BYTEORDER, Value: cadtFlags})
	}

	req.AddData(data)
	_, err := ipsetExecute(req)
	return err
}

func (h *Handle) Destroy(setname string) error {
	req := h.newRequest(IPSET_CMD_DESTROY)
	req.AddData(nl.NewRtAttr(IPSET_ATTR_SETNAME, nl.ZeroTerminated(setname)))
	_, err := ipsetExecute(req)
	return err
}

func (h *Handle) ForceDestroy(setname string) error {
	err := h.Destroy(setname)
	if err != nil && err != ErrSetNotExist && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (h *Handle) Flush(setname string) error {
	req := h.newRequest(IPSET_CMD_FLUSH)
	req.AddData(nl.NewRtAttr(IPSET_ATTR_SETNAME, nl.ZeroTerminated(setname)))
	_, err := ipsetExecute(req)
	return err
}

func (h *Handle) List(name string) (*Sets, error) {
	req := h.newRequest(IPSET_CMD_LIST)
	req.AddData(nl.NewRtAttr(IPSET_ATTR_SETNAME, nl.ZeroTerminated(name)))

	msgs, err := ipsetExecute(req)
	if err != nil {
		return nil, err
	}

	result := ipsetUnserialize(msgs)
	return &result, nil
}

func (h *Handle) ListAll() ([]Sets, error) {
	req := h.newRequest(IPSET_CMD_LIST)

	msgs, err := ipsetExecute(req)
	if err != nil {
		return nil, err
	}

	result := make([]Sets, len(msgs))
	for i, msg := range msgs {
		result[i].unserialize(msg)
	}

	return result, nil
}

// Add adds an entry to an existing ipset.
func (h *Handle) Add(setname string, entry *Entry) error {
	return h.addDel(IPSET_CMD_ADD, setname, entry)
}

// Del deletes an entry from an existing ipset.
func (h *Handle) Del(setname string, entry *Entry) error {
	return h.addDel(IPSET_CMD_DEL, setname, entry)
}

// Rename rename a set. Set identified by SETNAME-TO must not exist.
func (h *Handle) Rename(from string, to string) error {
	return h.renameSwap(IPSET_CMD_RENAME, from, to)
}

// Swap swap the content of two sets, or in another words, exchange the name of two sets. The referred sets must exist and compatible type of sets can be swapped only.
func (h *Handle) Swap(from string, to string) error {
	return h.renameSwap(IPSET_CMD_SWAP, from, to)
}

func (h *Handle) addDel(nlCmd int, setname string, entry *Entry) error {
	req := h.newRequest(nlCmd)
	req.AddData(nl.NewRtAttr(IPSET_ATTR_SETNAME, nl.ZeroTerminated(setname)))

	data := nl.NewRtAttr(IPSET_ATTR_DATA|int(nl.NLA_F_NESTED), nil)

	if entry.Replace {
		req.Flags |= unix.NLM_F_REPLACE
	} else {
		req.Flags |= unix.NLM_F_EXCL
	}

	if entry.Name != "" {
		data.AddChild(nl.NewRtAttr(IPSET_ATTR_NAME, nl.ZeroTerminated(entry.Name)))
	}

	if entry.Comment != "" {
		data.AddChild(nl.NewRtAttr(IPSET_ATTR_COMMENT, nl.ZeroTerminated(entry.Comment)))
	}

	if entry.Timeout != nil {
		data.AddChild(&nl.Uint32Attribute{Type: IPSET_ATTR_TIMEOUT | nl.NLA_F_NET_BYTEORDER, Value: *entry.Timeout})
	}

	family := nl.GetIPFamily(entry.IP)

	if ip := entry.IP; ip != nil {
		if family == nl.FAMILY_V4 {
			ip = ip.To4()
		}
		nestedData := nl.NewRtAttr(IPSET_ATTR_IP|int(nl.NLA_F_NET_BYTEORDER), ip)
		data.AddChild(nl.NewRtAttr(IPSET_ATTR_IP|int(nl.NLA_F_NESTED), nestedData.Serialize()))
	}

	if entry.MAC != nil {
		data.AddChild(nl.NewRtAttr(IPSET_ATTR_ETHER, entry.MAC))
	}

	if entry.CIDR != 0 {
		data.AddChild(nl.NewRtAttr(IPSET_ATTR_CIDR, nl.Uint8Attr(entry.CIDR)))
	}

	if ip := entry.IP2; ip != nil {
		if family == nl.FAMILY_V4 {
			ip = ip.To4()
		}
		nestedData := nl.NewRtAttr(IPSET_ATTR_IP|int(nl.NLA_F_NET_BYTEORDER), ip)
		data.AddChild(nl.NewRtAttr(IPSET_ATTR_IP2|int(nl.NLA_F_NESTED), nestedData.Serialize()))
	}

	if entry.CIDR2 != 0 {
		data.AddChild(nl.NewRtAttr(IPSET_ATTR_CIDR2, nl.Uint8Attr(entry.CIDR2)))
	}

	if entry.Port != nil {
		if entry.Protocol == nil {
			// use tcp protocol as default
			val := uint8(ProtocolTCP)
			entry.Protocol = &val
		}
		data.AddChild(nl.NewRtAttr(IPSET_ATTR_PROTO, nl.Uint8Attr(*entry.Protocol)))
		data.AddChild(nl.NewRtAttr(int(IPSET_ATTR_PORT|nl.NLA_F_NET_BYTEORDER), htons(*entry.Port)))
	}

	if entry.IFace != "" {
		data.AddChild(nl.NewRtAttr(IPSET_ATTR_IFACE, nl.ZeroTerminated(entry.IFace)))
	}

	if entry.Mark != nil {
		data.AddChild(&nl.Uint32Attribute{Type: IPSET_ATTR_MARK | nl.NLA_F_NET_BYTEORDER, Value: *entry.Mark})
	}

	data.AddChild(&nl.Uint32Attribute{Type: IPSET_ATTR_LINENO | nl.NLA_F_NET_BYTEORDER, Value: 0})
	req.AddData(data)

	_, err := ipsetExecute(req)
	return err
}

func (h *Handle) renameSwap(nlCmd int, from string, to string) error {
	req := h.newRequest(nlCmd)
	req.AddData(nl.NewRtAttr(IPSET_ATTR_SETNAME, nl.ZeroTerminated(from)))
	req.AddData(nl.NewRtAttr(IPSET_ATTR_SETNAME2, nl.ZeroTerminated(to)))

	_, err := ipsetExecute(req)
	return err
}

func (h *Handle) newRequest(cmd int) *nl.NetlinkRequest {
	req := h.newNetlinkRequest(cmd|(unix.NFNL_SUBSYS_IPSET<<8), GetCommandFlags(cmd))

	// Add the netfilter header
	msg := &nl.Nfgenmsg{
		NfgenFamily: uint8(unix.AF_INET),
		Version:     nl.NFNETLINK_V0,
		ResId:       0,
	}
	req.AddData(msg)
	req.AddData(nl.NewRtAttr(IPSET_ATTR_PROTOCOL, nl.Uint8Attr(IPSET_PROTOCOL)))

	return req
}

func ipsetExecute(req *nl.NetlinkRequest) (msgs [][]byte, err error) {
	msgs, err = req.Execute(unix.NETLINK_NETFILTER, 0)

	if err != nil {
		if errno := int(err.(syscall.Errno)); errno >= IPSET_ERR_PRIVATE {
			err = IPSetError(uintptr(errno))
		}
	}
	return
}

func ipsetUnserialize(msgs [][]byte) (result Sets) {
	for _, msg := range msgs {
		result.unserialize(msg)
	}
	return result
}

func (result *Sets) unserialize(msg []byte) {
	result.Nfgenmsg = nl.DeserializeNfgenmsg(msg)

	for attr := range nl.ParseAttributes(msg[4:]) {
		switch attr.Type {
		case IPSET_ATTR_PROTOCOL:
			result.Protocol = attr.Value[0]
		case IPSET_ATTR_SETNAME:
			result.SetName = nl.BytesToString(attr.Value)
		case IPSET_ATTR_COMMENT:
			result.Comment = nl.BytesToString(attr.Value)
		case IPSET_ATTR_TYPENAME:
			result.TypeName = nl.BytesToString(attr.Value)
		case IPSET_ATTR_REVISION:
			result.Revision = attr.Value[0]
		case IPSET_ATTR_FAMILY:
			result.Family = attr.Value[0]
		case IPSET_ATTR_FLAGS:
			result.Flags = attr.Value[0]
		case IPSET_ATTR_DATA | nl.NLA_F_NESTED:
			result.parseAttrData(attr.Value)
		case IPSET_ATTR_ADT | nl.NLA_F_NESTED:
			result.parseAttrADT(attr.Value)
		case IPSET_ATTR_PROTOCOL_MIN:
			result.ProtocolMinVersion = attr.Value[0]
		case IPSET_ATTR_MARKMASK:
			result.MarkMask = attr.Uint32()
		default:
			log.Printf("unknown ipset attribute from kernel: %+v %v", attr, attr.Type&nl.NLA_TYPE_MASK)
		}
	}
}

func (result *Sets) parseAttrData(data []byte) {
	for attr := range nl.ParseAttributes(data) {
		switch attr.Type {
		case IPSET_ATTR_HASHSIZE | nl.NLA_F_NET_BYTEORDER:
			result.HashSize = attr.Uint32()
		case IPSET_ATTR_MAXELEM | nl.NLA_F_NET_BYTEORDER:
			result.MaxElements = attr.Uint32()
		case IPSET_ATTR_TIMEOUT | nl.NLA_F_NET_BYTEORDER:
			val := attr.Uint32()
			result.Timeout = &val
		case IPSET_ATTR_ELEMENTS | nl.NLA_F_NET_BYTEORDER:
			result.NumEntries = attr.Uint32()
		case IPSET_ATTR_REFERENCES | nl.NLA_F_NET_BYTEORDER:
			result.References = attr.Uint32()
		case IPSET_ATTR_MEMSIZE | nl.NLA_F_NET_BYTEORDER:
			result.SizeInMemory = attr.Uint32()
		case IPSET_ATTR_CADT_FLAGS | nl.NLA_F_NET_BYTEORDER:
			result.CadtFlags = attr.Uint32()
		case IPSET_ATTR_IP | nl.NLA_F_NESTED:
			for nested := range nl.ParseAttributes(attr.Value) {
				switch nested.Type {
				case IPSET_ATTR_IP | nl.NLA_F_NET_BYTEORDER:
					result.Entries = append(result.Entries, Entry{IP: nested.Value})
				case IPSET_ATTR_IP:
					result.IPFrom = nested.Value
				default:
					log.Printf("unknown nested ipset data attribute from kernel: %+v %v", nested, nested.Type&nl.NLA_TYPE_MASK)
				}
			}
		case IPSET_ATTR_IP_TO | nl.NLA_F_NESTED:
			for nested := range nl.ParseAttributes(attr.Value) {
				switch nested.Type {
				case IPSET_ATTR_IP:
					result.IPTo = nested.Value
				default:
					log.Printf("unknown nested ipset data attribute from kernel: %+v %v", nested, nested.Type&nl.NLA_TYPE_MASK)
				}
			}
		case IPSET_ATTR_PORT_FROM | nl.NLA_F_NET_BYTEORDER:
			result.PortFrom = ntohs(attr.Value)
		case IPSET_ATTR_PORT_TO | nl.NLA_F_NET_BYTEORDER:
			result.PortTo = ntohs(attr.Value)
		case IPSET_ATTR_CADT_LINENO | nl.NLA_F_NET_BYTEORDER:
			result.LineNo = attr.Uint32()
		case IPSET_ATTR_COMMENT:
			result.Comment = nl.BytesToString(attr.Value)
		case IPSET_ATTR_SIZE | nl.NLA_F_NET_BYTEORDER:
			result.Size = attr.Uint32()
		case IPSET_ATTR_MARKMASK:
			result.MarkMask = attr.Uint32()
		default:
			log.Printf("unknown ipset data attribute from kernel: %+v %v", attr, attr.Type&nl.NLA_TYPE_MASK)
		}
	}
}

func (result *Sets) parseAttrADT(data []byte) {
	for attr := range nl.ParseAttributes(data) {
		switch attr.Type {
		case IPSET_ATTR_DATA | nl.NLA_F_NESTED:
			result.Entries = append(result.Entries, parseIPSetEntry(attr.Value))
		default:
			log.Printf("unknown ADT attribute from kernel: %+v %v", attr, attr.Type&nl.NLA_TYPE_MASK)
		}
	}
}

func parseIPSetEntry(data []byte) (entry Entry) {
	for attr := range nl.ParseAttributes(data) {
		switch attr.Type {
		case IPSET_ATTR_TIMEOUT | nl.NLA_F_NET_BYTEORDER:
			val := attr.Uint32()
			entry.Timeout = &val
		case IPSET_ATTR_BYTES | nl.NLA_F_NET_BYTEORDER:
			val := attr.Uint64()
			entry.Bytes = &val
		case IPSET_ATTR_PACKETS | nl.NLA_F_NET_BYTEORDER:
			val := attr.Uint64()
			entry.Packets = &val
		case IPSET_ATTR_ETHER:
			entry.MAC = net.HardwareAddr(attr.Value)
		case IPSET_ATTR_IP:
			entry.IP = net.IP(attr.Value)
		case IPSET_ATTR_COMMENT:
			entry.Comment = nl.BytesToString(attr.Value)
		case IPSET_ATTR_IP | nl.NLA_F_NESTED:
			for attr := range nl.ParseAttributes(attr.Value) {
				switch attr.Type {
				case IPSET_ATTR_IP:
					entry.IP = net.IP(attr.Value)
				default:
					log.Printf("unknown nested ADT attribute from kernel: %+v", attr)
				}
			}
		case IPSET_ATTR_IP2 | nl.NLA_F_NESTED:
			for attr := range nl.ParseAttributes(attr.Value) {
				switch attr.Type {
				case IPSET_ATTR_IP:
					entry.IP2 = net.IP(attr.Value)
				default:
					log.Printf("unknown nested ADT attribute from kernel: %+v", attr)
				}
			}
		case IPSET_ATTR_CIDR:
			entry.CIDR = attr.Value[0]
		case IPSET_ATTR_CIDR2:
			entry.CIDR2 = attr.Value[0]
		case IPSET_ATTR_PORT | nl.NLA_F_NET_BYTEORDER:
			val := ntohs(attr.Value)
			entry.Port = &val
		case IPSET_ATTR_PROTO:
			val := attr.Value[0]
			entry.Protocol = &val
		case IPSET_ATTR_IFACE:
			entry.IFace = nl.BytesToString(attr.Value)
		case IPSET_ATTR_NAME:
			entry.Name = nl.BytesToString(attr.Value)
		case IPSET_ATTR_MARK | nl.NLA_F_NET_BYTEORDER:
			val := attr.Uint32()
			entry.Mark = &val
		default:
			log.Printf("unknown ADT attribute from kernel: %+v", attr)
		}
	}
	return
}
