# ipset-go - ipset library for go

[![GoDoc](https://pkg.go.dev/badge/github.com/lrh3321/ipset-go)](https://pkg.go.dev/github.com/lrh3321/ipset-go)

The ipset-go package provides a simple ipset library for go. [IP sets](https://ipset.netfilter.org/) are a framework inside the Linux kernel, which can be administered by the ipset utility. Depending on the type, an IP set may store IP addresses, networks, (TCP/UDP) port numbers, MAC addresses, interface names or combinations of them in a way, which ensures lightning speed when matching an entry against a set.This library began its life as a fork of the [vishvananda/netlink](https://github.com/vishvananda/netlink).

## Examples ##

Create a new set and add `10.0.0.1` into it:

```go
package main

import (
	"log"
	"net"

	"github.com/lrh3321/ipset-go"
)

func main() {
	var setname = "hash01"
	// Equivalent to: `ipset create hash01 hash:ip`
	err := ipset.Create(setname, ipset.TypeHashIP, ipset.CreateOptions{})
	if err != nil {
		log.Fatal(err)
	}

	// Equivalent to: `ipset add hash01 10.0.0.1`
	err = ipset.Add(setname, &ipset.Entry{IP: net.IPv4(10, 0, 0, 1).To4()})
	if err != nil {
		log.Fatal(err)
	}

	// List the set.
	set, err := ipset.List(setname)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf(`Name: %s
Type: %s
Header: family inet hashsize %d maxelem %d
Size in memory: %d
References: %d
Number of entries: %d
Members:
`,
		set.SetName,
		set.TypeName,
		set.HashSize,
		set.MaxElements,
		set.SizeInMemory,
		set.References,
		set.NumEntries,
	)

	for _, e := range set.Entries {
		fmt.Println(e.IP.String())
	}

	/*
	   Name: test_hash01
	   Type: hash:ip
	   Header: family inet hashsize 1024 maxelem 65536
	   Size in memory: 296
	   References: 0
	   Number of entries: 2
	   Members:
	   10.0.0.1
	   10.0.0.5
	*/
}

```

Destroy a set:

```go
package main

import (
	"log"
	"net"

	"github.com/lrh3321/ipset-go"
)

func main() {
	var setname = "hash01"
	// Equivalent to: `ipset destroy hash01`
	err := ipset.Destroy(setname)
	if err != nil {
		log.Fatal(err)
	}
}

```

More code:

- [ipset_linux_test.go](./ipset_linux_test.go)
- [main.go](./expample/ipset-go/main.go)
