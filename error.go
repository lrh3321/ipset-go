package ipset

import "strconv"

const (
	IPSET_ERR_PRIVATE = 4096 + iota
	IPSET_ERR_PROTOCOL
	IPSET_ERR_FIND_TYPE
	IPSET_ERR_MAX_SETS
	IPSET_ERR_BUSY
	IPSET_ERR_EXIST_SETNAME2
	IPSET_ERR_TYPE_MISMATCH
	IPSET_ERR_EXIST
	IPSET_ERR_INVALID_CIDR
	IPSET_ERR_INVALID_NETMASK
	IPSET_ERR_INVALID_FAMILY
	IPSET_ERR_TIMEOUT
	IPSET_ERR_REFERENCED
	IPSET_ERR_IPADDR_IPV4
	IPSET_ERR_IPADDR_IPV6
	IPSET_ERR_COUNTER
	IPSET_ERR_COMMENT
	IPSET_ERR_INVALID_MARKMASK
	IPSET_ERR_SKBINFO

	/* Type specific error codes */
	IPSET_ERR_TYPE_SPECIFIC = 4352
)

type IPSetError uintptr

func (e IPSetError) Error() string {
	switch int(e) {
	case IPSET_ERR_PRIVATE:
		return "private"
	case IPSET_ERR_PROTOCOL:
		return "invalid protocol"
	case IPSET_ERR_FIND_TYPE:
		return "invalid type"
	case IPSET_ERR_MAX_SETS:
		return "max sets reached"
	case IPSET_ERR_BUSY:
		return "busy"
	case IPSET_ERR_EXIST_SETNAME2:
		return "exist_setname2"
	case IPSET_ERR_TYPE_MISMATCH:
		return "type mismatch"
	case IPSET_ERR_EXIST:
		return "exist"
	case IPSET_ERR_INVALID_CIDR:
		return "invalid cidr"
	case IPSET_ERR_INVALID_NETMASK:
		return "invalid netmask"
	case IPSET_ERR_INVALID_FAMILY:
		return "invalid family"
	case IPSET_ERR_TIMEOUT:
		return "timeout"
	case IPSET_ERR_REFERENCED:
		return "referenced"
	case IPSET_ERR_IPADDR_IPV4:
		return "invalid ipv4 address"
	case IPSET_ERR_IPADDR_IPV6:
		return "invalid ipv6 address"
	case IPSET_ERR_COUNTER:
		return "invalid counter"
	case IPSET_ERR_COMMENT:
		return "invalid comment"
	case IPSET_ERR_INVALID_MARKMASK:
		return "invalid markmask"
	case IPSET_ERR_SKBINFO:
		return "skbinfo"
	default:
		return "errno " + strconv.Itoa(int(e))
	}
}
