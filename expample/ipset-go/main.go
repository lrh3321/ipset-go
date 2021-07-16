package main

import (
	"log"
	"net"

	"github.com/lrh3321/ipset-go"
)

func main() {
	var setname = "test_hash01"
	err := ipset.Create(setname, ipset.TypeHashIP, ipset.CreateOptions{})
	if err != nil {
		log.Fatal(err)
	}

	err = ipset.Add(setname, &ipset.Entry{IP: net.IPv4(10, 0, 0, 1).To4()})
	if err != nil {
		log.Fatal(err)
	}

	err = ipset.Destroy(setname)
	if err != nil {
		log.Fatal(err)
	}
}
