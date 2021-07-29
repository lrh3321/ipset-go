package ipset

import (
	"testing"
	"time"
	"unsafe"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestSetGetSocketTimeout(t *testing.T) {
	timeout := 10 * time.Second
	if err := netlink.SetSocketTimeout(10 * time.Second); err != nil {
		t.Fatalf("Set socket timeout for default handle failed: %v", err)
	}

	if val := netlink.GetSocketTimeout(); val != timeout {
		t.Fatalf("Unexpcted socket timeout value: got=%v, expected=%v", val, timeout)
	}
}

func TestHandleCreateDelete(t *testing.T) {
	h, err := NewHandle()
	if err != nil {
		t.Fatal(err)
	}

	sh := h.socket
	if sh == nil {
		t.Fatalf("Socket for family %d was not created", unix.NETLINK_NETFILTER)
	}

	h.Close()
	if h.socket != nil {
		t.Fatalf("Handle socket were not destroyed")
	}
}
func TestHandleTimeout(t *testing.T) {
	h, err := NewHandle()
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	sh := h.socket
	verifySockTimeVal(t, sh.Socket.GetFd(), unix.Timeval{Sec: 0, Usec: 0})

	h.SetSocketTimeout(2*time.Second + 8*time.Millisecond)

	verifySockTimeVal(t, sh.Socket.GetFd(), unix.Timeval{Sec: 2, Usec: 8000})
}

func TestHandleReceiveBuffer(t *testing.T) {
	h, err := NewHandle()
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if err := h.SetSocketReceiveBufferSize(65536, false); err != nil {
		t.Fatal(err)
	}
	sizes, err := h.GetSocketReceiveBufferSize()
	if err != nil {
		t.Fatal(err)
	}
	if len(sizes) != 1 {
		t.Fatalf("Unexpected number of socket buffer sizes: %d (expected %d)",
			len(sizes), 1)
	}
	for _, s := range sizes {
		if s < 65536 || s > 2*65536 {
			t.Fatalf("Unexpected socket receive buffer size: %d (expected around %d)",
				s, 65536)
		}
	}
}

func TestHandleFromNetlinkHandle(t *testing.T) {
	netlinkHandle, err := netlink.NewHandle()
	if err != nil {
		t.Fatal(err)
	}
	defer netlinkHandle.Delete()

	h := HandleFromNetlinkHandle(netlinkHandle)
	sizes, err := h.GetSocketReceiveBufferSize()
	if err != nil {
		t.Fatal(err)
	}
	if len(sizes) != 1 || h.socket == nil {
		t.Fatalf("Unexpected number of socket buffer sizes: %d (expected %d)",
			len(sizes), 1)
	}
}

func verifySockTimeVal(t *testing.T, fd int, tv unix.Timeval) {
	var (
		tr unix.Timeval
		v  = uint32(0x10)
	)
	_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), unix.SOL_SOCKET, unix.SO_SNDTIMEO, uintptr(unsafe.Pointer(&tr)), uintptr(unsafe.Pointer(&v)), 0)
	if errno != 0 {
		t.Fatal(errno)
	}

	if tr.Sec != tv.Sec || tr.Usec != tv.Usec {
		t.Fatalf("Unexpected timeout value read: %v. Expected: %v", tr, tv)
	}

	_, _, errno = unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), unix.SOL_SOCKET, unix.SO_RCVTIMEO, uintptr(unsafe.Pointer(&tr)), uintptr(unsafe.Pointer(&v)), 0)
	if errno != 0 {
		t.Fatal(errno)
	}

	if tr.Sec != tv.Sec || tr.Usec != tv.Usec {
		t.Fatalf("Unexpected timeout value read: %v. Expected: %v", tr, tv)
	}
}
