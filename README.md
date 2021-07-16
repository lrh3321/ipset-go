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
	err := ipset.Create(setname, ipset.TypeHashIP, ipset.CreateOptions{})
	if err != nil {
		log.Fatal(err)
	}

	err = ipset.Add(setname, &ipset.Entry{IP: net.IPv4(10, 0, 0, 1).To4()})
	if err != nil {
		log.Fatal(err)
	}
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
	err := ipset.Destroy(setname)
	if err != nil {
		log.Fatal(err)
	}
}

```
