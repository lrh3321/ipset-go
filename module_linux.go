package ipset

import (
	"os/exec"
)

var loadKernelModule = func(name string) error {
	return exec.Command("modprobe", name).Run()
}

var ipsetTypeModules = map[string]string{
	TypeListSet: "ip_set_list_set",

	TypeHashMac:        "ip_set_hash_mac",
	TypeHashIPMac:      "ip_set_hash_ipmac",
	TypeHashNetIface:   "ip_set_hash_netiface",
	TypeHashNetPort:    "ip_set_hash_netport",
	TypeHashNetPortNet: "ip_set_hash_netportnet",
	TypeHashNetNet:     "ip_set_hash_netnet",
	TypeHashNet:        "ip_set_hash_net",
	TypeHashIPPortNet:  "ip_set_hash_ipportnet",
	TypeHashIPPortIP:   "ip_set_hash_ipportip",
	TypeHashIPMark:     "ip_set_hash_ipmark",
	TypeHashIPPort:     "ip_set_hash_ipport",
	TypeHashIP:         "ip_set_hash_ip",

	TypeBitmapPort:  "ip_set_bitmap_port",
	TypeBitmapIPMac: "ip_set_bitmap_ipmac",
	TypeBitmapIP:    "ip_set_bitmap_ip",
}

func ipsetKernelModules(typename string) []string {
	modules := []string{"ip_set"}
	if module, ok := ipsetTypeModules[typename]; ok {
		modules = append(modules, module)
	}
	return modules
}

func loadIPSetKernelModules(typename string) error {
	for _, module := range ipsetKernelModules(typename) {
		if err := loadKernelModule(module); err != nil {
			return err
		}
	}
	return nil
}
