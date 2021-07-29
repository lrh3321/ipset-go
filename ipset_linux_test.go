package ipset

import (
	"bytes"
	"io/ioutil"
	"net"
	"testing"
)

func TestParseIpsetProtocolResult(t *testing.T) {
	msgBytes, err := ioutil.ReadFile("testdata/ipset_protocol_result")
	if err != nil {
		t.Fatalf("reading test fixture failed: %v", err)
	}

	msg := ipsetUnserialize([][]byte{msgBytes})
	if msg.Protocol != 6 {
		t.Errorf("expected msg.Protocol to equal 6, got %d", msg.Protocol)
	}
}

func TestParseIpsetListResult(t *testing.T) {
	msgBytes, err := ioutil.ReadFile("testdata/ipset_list_result")
	if err != nil {
		t.Fatalf("reading test fixture failed: %v", err)
	}

	msg := ipsetUnserialize([][]byte{msgBytes})
	if msg.SetName != "clients" {
		t.Errorf(`expected SetName to equal "clients", got %q`, msg.SetName)
	}
	if msg.TypeName != "hash:mac" {
		t.Errorf(`expected TypeName to equal "hash:mac", got %q`, msg.TypeName)
	}
	if msg.Protocol != 6 {
		t.Errorf("expected Protocol to equal 6, got %d", msg.Protocol)
	}
	if msg.References != 0 {
		t.Errorf("expected References to equal 0, got %d", msg.References)
	}
	if msg.NumEntries != 2 {
		t.Errorf("expected NumEntries to equal 2, got %d", msg.NumEntries)
	}
	if msg.HashSize != 1024 {
		t.Errorf("expected HashSize to equal 1024, got %d", msg.HashSize)
	}
	if *msg.Timeout != 3600 {
		t.Errorf("expected Timeout to equal 3600, got %d", *msg.Timeout)
	}
	if msg.MaxElements != 65536 {
		t.Errorf("expected MaxElements to equal 65536, got %d", msg.MaxElements)
	}
	if msg.CadtFlags != IPSET_FLAG_WITH_COMMENT|IPSET_FLAG_WITH_COUNTERS {
		t.Error("expected CadtFlags to be IPSET_FLAG_WITH_COMMENT and IPSET_FLAG_WITH_COUNTERS")
	}
	if len(msg.Entries) != 2 {
		t.Fatalf("expected 2 Entries, got %d", len(msg.Entries))
	}

	// first entry
	ent := msg.Entries[0]
	if int(*ent.Timeout) != 3577 {
		t.Errorf("expected Timeout for first entry to equal 3577, got %d", *ent.Timeout)
	}
	if int(*ent.Bytes) != 4121 {
		t.Errorf("expected Bytes for first entry to equal 4121, got %d", *ent.Bytes)
	}
	if int(*ent.Packets) != 42 {
		t.Errorf("expected Packets for first entry to equal 42, got %d", *ent.Packets)
	}
	if ent.Comment != "foo bar" {
		t.Errorf("unexpected Comment for first entry: %q", ent.Comment)
	}
	expectedMAC := net.HardwareAddr{0xde, 0xad, 0x0, 0x0, 0xbe, 0xef}
	if !bytes.Equal(ent.MAC, expectedMAC) {
		t.Errorf("expected MAC for first entry to be %s, got %s", expectedMAC.String(), ent.MAC.String())
	}

	// second entry
	ent = msg.Entries[1]
	expectedMAC = net.HardwareAddr{0x1, 0x2, 0x3, 0x0, 0x1, 0x2}
	if !bytes.Equal(ent.MAC, expectedMAC) {
		t.Errorf("expected MAC for second entry to be %s, got %s", expectedMAC.String(), ent.MAC.String())
	}
}

func TestHashMethodCreateListAddDelDestroy(t *testing.T) {
	minKernelRequired(t, 3, 11)

	timeout := uint32(3)
	protocalTCP := uint8(ProtocolTCP)
	port := uint16(80)

	testCases := []struct {
		desc     string
		setname  string
		typename string
		options  CreateOptions
		entry    *Entry
	}{
		{
			desc:     "Type-hash:ip",
			setname:  "my-test-ipset-1",
			typename: TypeHashIP,
			options: CreateOptions{
				Size:     2048,
				Replace:  true,
				Timeout:  timeout,
				Counters: true,
				Comments: true,
				Skbinfo:  false,
			},
			entry: &Entry{
				Comment: "test comment",
				IP:      net.ParseIP("10.99.99.99").To4(),
				Replace: false,
			},
		},
		{
			desc:     "Type-hash:net",
			setname:  "my-test-ipset-2",
			typename: TypeHashNet,
			options: CreateOptions{
				Replace:  true,
				Timeout:  timeout,
				Counters: false,
				Comments: true,
				Skbinfo:  true,
			},
			entry: &Entry{
				Comment: "test comment",
				IP:      net.ParseIP("10.99.99.0").To4(),
				CIDR:    24,
				Replace: false,
			},
		},
		{
			desc:     "Type-hash:net,net",
			setname:  "my-test-ipset-4",
			typename: TypeHashNetNet,
			options: CreateOptions{
				Replace:  true,
				Timeout:  timeout,
				Counters: false,
				Comments: true,
				Skbinfo:  true,
			},
			entry: &Entry{
				Comment: "test comment",
				IP:      net.ParseIP("10.99.99.0").To4(),
				CIDR:    24,
				IP2:     net.ParseIP("10.99.0.0").To4(),
				CIDR2:   24,
				Replace: false,
			},
		},
		{
			desc:     "Type-hash:ip,port,ip",
			setname:  "my-test-ipset-5",
			typename: TypeHashIPPortIP,
			options: CreateOptions{
				Replace:  true,
				Timeout:  timeout,
				Counters: false,
				Comments: true,
				Skbinfo:  true,
			},
			entry: &Entry{
				Comment: "test comment",
				IP:      net.ParseIP("10.99.99.0").To4(),
				IP2:     net.ParseIP("10.99.0.0").To4(),
				Port:    &port,
				Replace: false,
			},
		},
		{
			desc:     "Type-hash:ip,port",
			setname:  "my-test-ipset-6",
			typename: TypeHashIPPort,
			options: CreateOptions{
				Replace:  true,
				Timeout:  timeout,
				Counters: false,
				Comments: true,
				Skbinfo:  true,
			},
			entry: &Entry{
				Comment:  "test comment",
				IP:       net.ParseIP("10.99.99.1").To4(),
				Protocol: &protocalTCP,
				Port:     &port,
				Replace:  false,
			},
		},
		{
			desc:     "Type-hash:net,port,net",
			setname:  "my-test-ipset-7",
			typename: TypeHashNetPortNet,
			options: CreateOptions{
				Replace:  true,
				Timeout:  timeout,
				Counters: false,
				Comments: true,
				Skbinfo:  true,
			},
			entry: &Entry{
				Comment:  "test comment",
				IP:       net.ParseIP("10.99.99.0").To4(),
				CIDR:     24,
				IP2:      net.ParseIP("10.99.0.0").To4(),
				CIDR2:    24,
				Protocol: &protocalTCP,
				Port:     &port,
				Replace:  false,
			},
		},
		{
			desc:     "Type-hash:mac",
			setname:  "my-test-ipset-8",
			typename: TypeHashMac,
			options: CreateOptions{
				Replace:  true,
				Timeout:  timeout,
				Counters: true,
				Comments: true,
				Skbinfo:  false,
			},
			entry: &Entry{
				Comment: "test comment",
				MAC:     net.HardwareAddr{0x26, 0x6f, 0x0d, 0x5b, 0xc1, 0x9d},
				Replace: false,
			},
		},
		{
			desc:     "Type-hash:net,iface",
			setname:  "my-test-ipset-9",
			typename: TypeHashNetIface,
			options: CreateOptions{
				Replace:  true,
				Timeout:  timeout,
				Counters: true,
				Comments: true,
				Skbinfo:  false,
			},
			entry: &Entry{
				Comment: "test comment",
				IP:      net.ParseIP("10.99.99.0").To4(),
				CIDR:    24,
				IFace:   "eth0",
				Replace: false,
			},
		},
		{
			desc:     "Type-hash:ip,mark",
			setname:  "my-test-ipset-10",
			typename: TypeHashIPMark,
			options: CreateOptions{
				Replace:  true,
				Timeout:  timeout,
				Counters: true,
				Comments: true,
				Skbinfo:  false,
			},
			entry: &Entry{
				Comment: "test comment",
				IP:      net.ParseIP("10.99.99.0").To4(),
				Mark:    &timeout,
				Replace: false,
			},
		},
	}

	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			tearDown := setUpNetlinkTestWithKModule(t, "ip_set")
			defer tearDown()

			err := Create(tC.setname, tC.typename, tC.options)
			if err != nil {
				t.Fatal(err)
			}

			result, err := List(tC.setname)
			if err != nil {
				t.Fatal(err)
			}

			if result.SetName != tC.setname {
				t.Errorf("expected name to be '%s', but got '%s'", tC.setname, result.SetName)
			}

			if result.TypeName != tC.typename {
				t.Errorf("expected type to be '%s', but got '%s'", tC.typename, result.TypeName)
			}

			if *result.Timeout != timeout {
				t.Errorf("expected timeout to be %d, but got '%d'", timeout, *result.Timeout)
			}

			if tC.options.Size > 0 && result.HashSize != tC.options.Size {
				t.Errorf("expected hashsize to be %d, but got '%d'", tC.options.Size, result.HashSize)
			}

			err = Add(tC.setname, tC.entry)

			if err != nil {
				t.Error(result.Protocol, result.Family)
				t.Fatal(err)
			}

			result, err = List(tC.setname)

			if err != nil {
				t.Fatal(err)
			}

			if len(result.Entries) != 1 {
				t.Fatalf("expected 1 entry be created, got '%d'", len(result.Entries))
			}

			assertIPSetEntryEqual(t, tC.entry, &result.Entries[0])

			err = Del(tC.setname, tC.entry)
			if err != nil {
				t.Fatal(err)
			}

			result, err = List(tC.setname)
			if err != nil {
				t.Fatal(err)
			}

			if len(result.Entries) != 0 {
				t.Fatalf("expected 0 entries to exist, got %d", len(result.Entries))
			}

			err = Destroy(tC.setname)
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestBitmapMethodCreateListAddDelDestroy(t *testing.T) {
	minKernelRequired(t, 3, 11)

	timeout := uint32(3)

	testCases := []struct {
		desc     string
		setname  string
		typename string
		options  CreateOptions
		entry    *Entry
	}{
		{
			desc:     "Type-bitmap:port",
			setname:  "my-test-ipset-11",
			typename: TypeBitmapPort,
			options: CreateOptions{
				Replace:  true,
				Timeout:  timeout,
				Counters: true,
				Comments: true,
				Skbinfo:  false,
				PortFrom: 100,
				PortTo:   600,
			},
			entry: &Entry{
				Comment: "test comment",
				IP:      net.ParseIP("10.99.99.0").To4(),
				CIDR:    26,
				Mark:    &timeout,
				Replace: false,
			},
		},
		{
			desc:     "Type-bitmap:ip",
			setname:  "my-test-ipset-12",
			typename: TypeBitmapIP,
			options: CreateOptions{
				Revision: 0xff,
				Replace:  true,
				Timeout:  timeout,
				Counters: true,
				Comments: true,
				Skbinfo:  false,
				IPFrom:   net.ParseIP("10.99.99.0").To4(),
				IPTo:     net.ParseIP("10.99.99.63").To4(),
			},
			entry: &Entry{
				Comment: "test comment",
				IP:      net.ParseIP("10.99.99.0").To4(),
				CIDR:    26,
				IP2:     net.ParseIP("10.99.99.8").To4(),
				CIDR2:   26,
				Mark:    &timeout,
				Replace: false,
			},
		},
		{
			desc:     "Type-bitmap:ip,mac",
			setname:  "my-test-ipset-14",
			typename: TypeBitmapIPMac,
			options: CreateOptions{
				Replace:  true,
				Timeout:  timeout,
				Counters: true,
				Comments: true,
				Skbinfo:  false,
				IPFrom:   net.ParseIP("10.99.99.0").To4(),
				IPTo:     net.ParseIP("10.99.99.63").To4(),
			},
			entry: &Entry{
				Comment: "test comment",
				IP:      net.ParseIP("10.99.99.0").To4(),
				CIDR:    26,
				IP2:     net.ParseIP("10.99.99.8").To4(),
				CIDR2:   26,
				Mark:    &timeout,
				Replace: false,
			},
		},
	}

	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			tearDown := setUpNetlinkTest(t)
			defer tearDown()

			err := Create(tC.setname, tC.typename, tC.options)
			if err != nil {
				t.Fatal(err)
			}

			result, err := List(tC.setname)
			if err != nil {
				t.Fatal(err)
			}

			if tC.typename == TypeBitmapPort {
				if result.PortFrom != tC.options.PortFrom || result.PortTo != tC.options.PortTo {
					t.Fatalf("expected port range %d-%d, got %d-%d", tC.options.PortFrom, tC.options.PortTo, result.PortFrom, result.PortTo)
				}
			} else if tC.typename == TypeBitmapIP {
				if result.IPFrom == nil || result.IPTo == nil || !(result.IPFrom.Equal(tC.options.IPFrom) && result.IPTo.Equal(tC.options.IPTo)) {
					t.Fatalf("expected ip range %v-%v, got %v-%v", tC.options.IPFrom, tC.options.IPTo, result.IPFrom, result.IPTo)
				}
			}

		})
	}
}

func TestListMethodCreateListAddDelDestroy(t *testing.T) {
	minKernelRequired(t, 3, 11)

	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	var (
		err         error
		setname     = "list01"
		typename    = TypeListSet
		hashSetName = "hash01"
		size        = uint32(20)
		entry       = &Entry{
			Name: hashSetName,
		}
	)

	err = Create(hashSetName, TypeHashIP, CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	err = Create(setname, typename, CreateOptions{Size: uint32(size)})
	if err != nil {
		t.Fatal(err)
	}

	result, err := List(setname)
	if err != nil {
		t.Fatal(err)
	}

	if result.SetName != setname {
		t.Errorf("expected name to be '%s', but got '%s'", setname, result.SetName)
	}

	if result.TypeName != typename {
		t.Errorf("expected type to be '%s', but got '%s'", typename, result.TypeName)
	}

	if result.Size != size {
		t.Errorf("expected size to be '%d', but got '%d'", size, result.Size)
	}

	err = Add(setname, entry)
	if err != nil {
		t.Fatal(err)
	}

	result, err = List(setname)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Entries) != 1 {
		t.Fatalf("expected 1 entry be created, got '%d'", len(result.Entries))
	}

	assertIPSetEntryEqual(t, entry, &result.Entries[0])

	err = Del(setname, entry)
	if err != nil {
		t.Fatal(err)
	}

	result, err = List(setname)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Entries) != 0 {
		t.Fatalf("expected 0 entries to exist, got %d", len(result.Entries))
	}

	err = Destroy(setname)
	if err != nil {
		t.Fatal(err)
	}
}

func TestRename(t *testing.T) {
	minKernelRequired(t, 3, 11)

	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	var (
		err      error
		fromName = "set1"
		toName   = "set2"
	)

	err = Create(fromName, TypeHashIP, CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	err = Rename(fromName, toName)
	if err != nil {
		t.Fatal(err)
	}

	err = Create(fromName, TypeHashIP, CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	err = Rename(toName, fromName)
	if err != ErrNewNameAlreadyExist {
		t.Fatalf("Set should not be renamed: a set with the new name already exists, but: %v", err)
	}
}
func TestSwap(t *testing.T) {
	minKernelRequired(t, 3, 11)

	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	var (
		err       error
		fromName  = "set1"
		toName    = "set2"
		otherName = "set3"
	)

	err = Create(fromName, TypeHashIP, CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	err = Create(toName, TypeHashIP, CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	err = Create(otherName, TypeListSet, CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	err = Swap(fromName, toName)
	if err != nil {
		t.Fatal(err)
	}

	err = Swap(fromName, fromName+".new")
	if err != ErrSecondSetNotExist {
		t.Fatalf("Sets should not be swapped: the second set does not exist, but: %v", err)
	}

	err = Swap(fromName, otherName)
	if err != ErrTypeMismatch {
		t.Fatalf("The sets should not be swapped: their type does not match, but: %v", err)
	}

}

func assertIPSetEntryEqual(t *testing.T, except *Entry, actual *Entry) {
	if except.IP != nil {
		if !except.IP.Equal(actual.IP) {
			t.Fatalf("expected entry to be '%v', got '%v'", except.IP, actual.IP)
		}
	}

	if except.CIDR > 0 {
		if actual.CIDR != except.CIDR {
			t.Fatalf("expected cidr to be '%d', got '%d'", except.CIDR, actual.CIDR)
		}
	}

	if except.IP2 != nil {
		if !except.IP2.Equal(actual.IP2) {
			t.Fatalf("expected entry.ip2 to be '%v', got '%v'", except.IP2, actual.IP2)
		}
	}

	if except.CIDR2 > 0 {
		if actual.CIDR2 != except.CIDR2 {
			t.Fatalf("expected cidr2 to be '%d', got '%d'", except.CIDR2, actual.CIDR2)
		}
	}

	if except.Port != nil {
		if *actual.Protocol != *except.Protocol {
			t.Fatalf("expected protocol to be '%d', got '%d'", *except.Protocol, *actual.Protocol)
		}
		if *actual.Port != *except.Port {
			t.Fatalf("expected port to be '%d', got '%d'", *except.Port, *actual.Port)
		}
	}

	if except.MAC != nil {
		if actual.MAC.String() != except.MAC.String() {
			t.Fatalf("expected mac to be '%v', got '%v'", except.MAC, actual.MAC)
		}
	}

	if except.IFace != "" {
		if actual.IFace != except.IFace {
			t.Fatalf("expected iface to be '%v', got '%v'", except.IFace, actual.IFace)
		}
	}

	if except.Mark != nil {
		if *actual.Mark != *except.Mark {
			t.Fatalf("expected mark to be '%v', got '%v'", *except.Mark, *actual.Mark)
		}
	}

	if actual.Comment != except.Comment {
		// This is only supported in the kernel module from revision 2 or 4, so comments may be ignored.
		t.Logf("expected comment to be '%s', got '%s'", except.Comment, actual.Comment)
	}

	if actual.Name != except.Name {
		t.Fatalf("expected name to be '%s', got '%s'", except.Name, actual.Name)
	}
}
