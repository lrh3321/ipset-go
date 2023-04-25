package ipset

import (
	"fmt"
	"log"
	"net"
	"os"
)

func ExampleCreateAdd() {
	var setname = "hash01"
	err := Create(setname, TypeHashIP, CreateOptions{})
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := ForceDestroy(setname); err != nil {
			log.Fatal(err)
		}
	}()

	err = Create(setname, TypeHashIP, CreateOptions{})
	if err != nil {
		if os.IsExist(err) {
			fmt.Printf("set: %s already exist\n", setname)
		} else {
			log.Fatal(err)
		}
	}

	// replace exists one
	err = Create(setname, TypeHashIP, CreateOptions{Replace: true})
	if err != nil {
		log.Fatal(err)
	}

	err = Add(setname, &Entry{IP: net.IPv4(10, 0, 0, 1).To4()})
	if err != nil {
		log.Fatal(err)
	}

	sets, err := List(setname)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%s %v\n", sets.SetName, sets.Entries[0].IP)
	//Output:
	// set: hash01 already exist
	// hash01 10.0.0.1
}

func ExampleDestroy() {
	var setname = "hash01"
	err := Create(setname, TypeHashIP, CreateOptions{Replace: true})
	if err != nil {
		log.Fatal(err)
	}
	err = Destroy(setname)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("no such set: %s\n", setname)
		} else {
			log.Fatal(err)
		}
	}

	// destroy a  not exist one
	setname = setname + "2"
	err = Destroy(setname)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("no such set: %s\n", setname)
		} else {
			log.Fatal(err)
		}
	}
	//Output:
	// no such set: hash012
}

func ExampleForceDestroy() {
	setname := "hash03"
	if err := ForceDestroy(setname); err != nil {
		log.Fatal(err)
	}
	//Output:
}
