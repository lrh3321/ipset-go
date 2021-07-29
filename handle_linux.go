package ipset

import (
	"fmt"
	"reflect"
	"time"
	"unsafe"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// Empty handle used by the netlink package methods
var pkgHandle = &Handle{}

// Handle is an handle for the netlink requests on a
// specific network namespace. All the requests on the
// same netlink family share the same netlink socket,
// which gets released when the handle is deleted.
type Handle struct {
	socket *nl.SocketHandle
}

// SetSocketTimeout configures timeout for default netlink sockets
func SetSocketTimeout(to time.Duration) error {
	if to < time.Microsecond {
		return fmt.Errorf("invalid timeout, minimul value is %s", time.Microsecond)
	}

	nl.SocketTimeoutTv = unix.NsecToTimeval(to.Nanoseconds())
	return nil
}

// GetSocketTimeout returns the timeout value used by default netlink sockets
func GetSocketTimeout() time.Duration {
	nsec := unix.TimevalToNsec(nl.SocketTimeoutTv)
	return time.Duration(nsec) * time.Nanosecond
}

// NewHandle returns a netlink handle on the current network namespace.
func NewHandle() (*Handle, error) {
	return newHandle(netns.None(), netns.None())
}

// SetSocketTimeout sets the send and receive timeout for each socket in the
// netlink handle. Although the socket timeout has granularity of one
// microsecond, the effective granularity is floored by the kernel timer tick,
// which default value is four milliseconds.
func (h *Handle) SetSocketTimeout(to time.Duration) error {
	if to < time.Microsecond {
		return fmt.Errorf("invalid timeout, minimul value is %s", time.Microsecond)
	}
	sh := h.socket
	if sh != nil {
		tv := unix.NsecToTimeval(to.Nanoseconds())
		if err := sh.Socket.SetSendTimeout(&tv); err != nil {
			return err
		}
		if err := sh.Socket.SetReceiveTimeout(&tv); err != nil {
			return err
		}
	}
	return nil
}

// SetSocketReceiveBufferSize sets the receive buffer size for each
// socket in the netlink handle. The maximum value is capped by
// /proc/sys/net/core/rmem_max.
func (h *Handle) SetSocketReceiveBufferSize(size int, force bool) error {
	opt := unix.SO_RCVBUF
	if force {
		opt = unix.SO_RCVBUFFORCE
	}
	sh := h.socket
	if sh != nil {
		fd := sh.Socket.GetFd()
		err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, opt, size)
		if err != nil {
			return err
		}
	}
	return nil
}

// GetSocketReceiveBufferSize gets the receiver buffer size for each
// socket in the netlink handle. The retrieved value should be the
// double to the one set for SetSocketReceiveBufferSize.
func (h *Handle) GetSocketReceiveBufferSize() ([]int, error) {
	sh := h.socket
	if sh == nil {
		return nil, nil
	}

	fd := sh.Socket.GetFd()
	size, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF)
	if err != nil {
		return nil, err
	}
	results := make([]int, 1)
	results[0] = size

	return results, nil
}

// NewHandleAt returns a netlink handle on the network namespace
// specified by ns. If ns=netns.None(), current network namespace
// will be assumed
func NewHandleAt(ns netns.NsHandle) (*Handle, error) {
	return newHandle(ns, netns.None())
}

// NewHandleAtFrom works as NewHandle but allows client to specify the
// new and the origin netns Handle.
func NewHandleAtFrom(newNs, curNs netns.NsHandle) (*Handle, error) {
	return newHandle(newNs, curNs)
}

func HandleFromNetlinkHandle(h *netlink.Handle) *Handle {
	val := reflect.ValueOf(h)
	sockets := val.Elem().FieldByName("sockets")

	ptr := unsafe.Pointer(sockets.UnsafeAddr())
	sockets2 := *(*map[int]*nl.SocketHandle)(ptr)
	s := sockets2[unix.NETLINK_NETFILTER]

	h2 := &Handle{socket: s}
	return h2
}

func newHandle(newNs, curNs netns.NsHandle) (*Handle, error) {
	s, err := nl.GetNetlinkSocketAt(newNs, curNs, unix.NETLINK_NETFILTER)
	if err != nil {
		return nil, err
	}
	h := &Handle{socket: &nl.SocketHandle{Socket: s}}
	return h, nil
}

// Close releases the resources allocated to this handle
func (h *Handle) Close() {
	if sh := h.socket; sh != nil {
		sh.Close()
	}
	h.socket = nil
}

// Deprecated: Use Close instead.
func (h *Handle) Delete() {
	h.Close()
}

func (h *Handle) newNetlinkRequest(proto, flags int) *nl.NetlinkRequest {
	// Do this so that package API still use nl package variable nextSeqNr
	if h.socket == nil {
		return nl.NewNetlinkRequest(proto, flags)
	}
	return &nl.NetlinkRequest{
		NlMsghdr: unix.NlMsghdr{
			Len:   uint32(unix.SizeofNlMsghdr),
			Type:  uint16(proto),
			Flags: unix.NLM_F_REQUEST | uint16(flags),
		},
		Sockets: map[int]*nl.SocketHandle{unix.NETLINK_NETFILTER: h.socket},
	}
}
