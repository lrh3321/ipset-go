package ipset

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

type tearDownNetlinkTest func()

func skipUnlessRoot(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges.")
	}
}

func setUpNetlinkTest(t *testing.T) tearDownNetlinkTest {
	skipUnlessRoot(t)

	// new temporary namespace so we don't pollute the host
	// lock thread since the namespace is thread local
	runtime.LockOSThread()
	var err error
	ns, err := netns.New()
	if err != nil {
		t.Fatal("Failed to create newns", ns)
	}

	return func() {
		ns.Close()
		runtime.UnlockOSThread()
	}
}

// setUpNamedNetlinkTest create a temporary named names space with a random name
func setUpNamedNetlinkTest(t *testing.T) (string, tearDownNetlinkTest) {
	skipUnlessRoot(t)

	origNS, err := netns.Get()
	if err != nil {
		t.Fatal("Failed saving orig namespace")
	}

	// create a random name
	rnd := make([]byte, 4)
	if _, err := rand.Read(rnd); err != nil {
		t.Fatal("failed creating random ns name")
	}
	name := "netlinktest-" + hex.EncodeToString(rnd)

	ns, err := netns.NewNamed(name)
	if err != nil {
		t.Fatal("Failed to create new ns", err)
	}

	runtime.LockOSThread()
	cleanup := func() {
		ns.Close()
		netns.DeleteNamed(name)
		netns.Set(origNS)
		runtime.UnlockOSThread()
	}

	if err := netns.Set(ns); err != nil {
		cleanup()
		t.Fatal("Failed entering new namespace", err)
	}

	return name, cleanup
}

func setUpNetlinkTestWithKModule(t *testing.T, name string) tearDownNetlinkTest {
	file, err := ioutil.ReadFile("/proc/modules")
	if err != nil {
		t.Fatal("Failed to open /proc/modules", err)
	}
	found := false
	for _, line := range strings.Split(string(file), "\n") {
		n := strings.Split(line, " ")[0]
		if n == name {
			found = true
			break
		}

	}
	if !found {
		t.Skipf("Test requires kmodule %q.", name)
	}
	return setUpNetlinkTest(t)
}

func minKernelRequired(t *testing.T, kernel, major int) {
	k, m, err := KernelVersion()
	if err != nil {
		t.Fatal(err)
	}
	if k < kernel || k == kernel && m < major {
		t.Skipf("Host Kernel (%d.%d) does not meet test's minimum required version: (%d.%d)",
			k, m, kernel, major)
	}
}

func KernelVersion() (kernel, major int, err error) {
	uts := unix.Utsname{}
	if err = unix.Uname(&uts); err != nil {
		return
	}

	ba := make([]byte, 0, len(uts.Release))
	for _, b := range uts.Release {
		if b == 0 {
			break
		}
		ba = append(ba, byte(b))
	}
	var rest string
	if n, _ := fmt.Sscanf(string(ba), "%d.%d%s", &kernel, &major, &rest); n < 2 {
		err = fmt.Errorf("can't parse kernel version in %q", string(ba))
	}
	return
}
