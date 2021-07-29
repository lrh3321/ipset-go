package ipset

import (
	"strconv"
	"syscall"
)

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

/* Bitmap type specific error codes */
const (
	/* The element is out of the range of the set */
	IPSET_ERR_BITMAP_RANGE = IPSET_ERR_TYPE_SPECIFIC + 1 + iota
	/* The range exceeds the size limit of the set type */
	IPSET_ERR_BITMAP_RANGE_SIZE
)

/* Hash type specific error codes */
const (
	/* Hash is full */
	IPSET_ERR_HASH_FULL = IPSET_ERR_TYPE_SPECIFIC + 1 + iota
	/* Null-valued element */
	IPSET_ERR_HASH_ELEM
	/* Invalid protocol */
	IPSET_ERR_INVALID_PROTO
	/* Protocol missing but must be specified */
	IPSET_ERR_MISSING_PROTO
	/* Range not supported */
	IPSET_ERR_HASH_RANGE_UNSUPPORTED
	/* Invalid range */
	IPSET_ERR_HASH_RANGE
)

/* List type specific error codes */
const (
	/* list:set type is not permitted to add */
	IPSET_ERR_LOOP = IPSET_ERR_TYPE_SPECIFIC + 1 + iota
	/* Missing reference set */
	IPSET_ERR_BEFORE
	/* Reference set does not exist */
	IPSET_ERR_NAMEREF
	/* Set is full */
	IPSET_ERR_LIST_FULL
	/* Reference set is not added to the set */
	IPSET_ERR_REF_EXIST
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

/* Generic error codes */
const (
	// ErrSetNotExist The set with the given name does not exist
	ErrSetNotExist = IPSetError(syscall.ENOENT)
	// ErrInvalidMessage Kernel error received: message could not be created
	ErrInvalidMessage = IPSetError(syscall.EMSGSIZE)
	// ErrInvalidProtocol Kernel error received: ipset protocol error
	ErrInvalidProtocol = IPSetError(IPSET_ERR_PROTOCOL)
)

/* Generic (CADT) error codes */
const (
	// ErrInvalidCIDR The value of the CIDR parameter of the IP address is invalid
	ErrInvalidCIDR = IPSetError(IPSET_ERR_INVALID_CIDR)
	// ErrTimeout Timeout cannot be used: set was created without timeout support
	ErrTimeout = IPSetError(IPSET_ERR_TIMEOUT)
	// ErrInvalidIPv4Address An IPv4 address is expected, but not received
	ErrInvalidIPv4Address = IPSetError(IPSET_ERR_IPADDR_IPV4)
	// ErrInvalidIPv6Address An IPv6 address is expected, but not received
	ErrInvalidIPv6Address = IPSetError(IPSET_ERR_IPADDR_IPV6)
	// ErrInvalidCounter Packet/byte counters cannot be used: set was created without counter support
	ErrInvalidCounter = IPSetError(IPSET_ERR_COUNTER)
	// ErrInvalidComment Comment cannot be used: set was created without comment support
	ErrInvalidComment = IPSetError(IPSET_ERR_COMMENT)
	// ErrSkbInfo Skbinfo mapping cannot be used: set was created without skbinfo support
	ErrSkbInfo = IPSetError(IPSET_ERR_SKBINFO)
)

/* CREATE specific error codes */
const (
	// ErrSetExist Set cannot be created: set with the same name already exists
	ErrSetExist = IPSetError(syscall.EEXIST)
	// ErrInvalidType Kernel error received: set type not supported
	ErrInvalidType = IPSetError(IPSET_ERR_FIND_TYPE)
	// ErrTypeMaxSetsReached Kernel error received: maximal number of sets reached,
	// cannot create more.
	ErrTypeMaxSetsReached = IPSetError(IPSET_ERR_MAX_SETS)
	// ErrInvalidNetmask The value of the netmask parameter is invalid
	ErrInvalidNetmask = IPSetError(IPSET_ERR_INVALID_NETMASK)
	// ErrInvalidMarkmask The value of the markmask parameter is invalid
	ErrInvalidMarkmask = IPSetError(IPSET_ERR_INVALID_MARKMASK)
	// ErrInvalidFamily Protocol family not supported by the set type
	ErrInvalidFamily = IPSetError(IPSET_ERR_INVALID_FAMILY)
)

/* DESTROY specific error codes */
const (
	// ErrBusy Set cannot be destroyed: it is in use by a kernel component
	ErrBusy = IPSetError(IPSET_ERR_BUSY)
)

/* RENAME specific error codes */
const (
	// ErrNewNameAlreadyExist Set cannot be renamed: a set with the new name already exists
	ErrNewNameAlreadyExist = IPSetError(IPSET_ERR_EXIST_SETNAME2)
	// ErrReferenced Set cannot be renamed: it is in use by another system
	ErrReferenced = IPSetError(IPSET_ERR_REFERENCED)
)

/* SWAP specific error codes */
const (
	// ErrSecondSetNotExist Sets cannot be swapped: the second set does not exist
	ErrSecondSetNotExist = IPSetError(IPSET_ERR_EXIST_SETNAME2)
	// ErrTypeMismatch The sets cannot be swapped: their type does not match
	ErrTypeMismatch = IPSetError(IPSET_ERR_TYPE_MISMATCH)
)

/* ADD specific error codes */
const (
	// ErrEntryExist Element cannot be added to the set: it's already added
	ErrEntryExist = IPSetError(IPSET_ERR_EXIST)
)

/* DEL specific error codes */
const (
	// ErrEntryNotExist Element cannot be deleted from the set: it's not added
	ErrEntryNotExist = IPSetError(IPSET_ERR_EXIST)
)
