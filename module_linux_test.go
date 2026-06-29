package ipset

import (
	"syscall"
	"testing"
)

func TestIPSetKernelModules(t *testing.T) {
	tests := []struct {
		name     string
		typename string
		want     []string
	}{
		{
			name:     "hash mac",
			typename: TypeHashMac,
			want:     []string{"ip_set", "ip_set_hash_mac"},
		},
		{
			name:     "hash ip mac",
			typename: TypeHashIPMac,
			want:     []string{"ip_set", "ip_set_hash_ipmac"},
		},
		{
			name:     "hash net iface",
			typename: TypeHashNetIface,
			want:     []string{"ip_set", "ip_set_hash_netiface"},
		},
		{
			name:     "hash net port",
			typename: TypeHashNetPort,
			want:     []string{"ip_set", "ip_set_hash_netport"},
		},
		{
			name:     "hash net",
			typename: TypeHashNet,
			want:     []string{"ip_set", "ip_set_hash_net"},
		},
		{
			name:     "hash net port net",
			typename: TypeHashNetPortNet,
			want:     []string{"ip_set", "ip_set_hash_netportnet"},
		},
		{
			name:     "hash net net",
			typename: TypeHashNetNet,
			want:     []string{"ip_set", "ip_set_hash_netnet"},
		},
		{
			name:     "hash ip port net",
			typename: TypeHashIPPortNet,
			want:     []string{"ip_set", "ip_set_hash_ipportnet"},
		},
		{
			name:     "hash ip port ip",
			typename: TypeHashIPPortIP,
			want:     []string{"ip_set", "ip_set_hash_ipportip"},
		},
		{
			name:     "hash ip mark",
			typename: TypeHashIPMark,
			want:     []string{"ip_set", "ip_set_hash_ipmark"},
		},
		{
			name:     "hash ip port",
			typename: TypeHashIPPort,
			want:     []string{"ip_set", "ip_set_hash_ipport"},
		},
		{
			name:     "hash ip",
			typename: TypeHashIP,
			want:     []string{"ip_set", "ip_set_hash_ip"},
		},
		{
			name:     "bitmap port",
			typename: TypeBitmapPort,
			want:     []string{"ip_set", "ip_set_bitmap_port"},
		},
		{
			name:     "bitmap ip mac",
			typename: TypeBitmapIPMac,
			want:     []string{"ip_set", "ip_set_bitmap_ipmac"},
		},
		{
			name:     "bitmap ip",
			typename: TypeBitmapIP,
			want:     []string{"ip_set", "ip_set_bitmap_ip"},
		},
		{
			name:     "list set",
			typename: TypeListSet,
			want:     []string{"ip_set", "ip_set_list_set"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ipsetKernelModules(tt.typename)
			if len(got) != len(tt.want) {
				t.Fatalf("expected %d modules, got %d: %v", len(tt.want), len(got), got)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Fatalf("expected module %d to be %q, got %q", i, tt.want[i], got[i])
				}
			}
		})
	}
}

func TestIPSetKernelModulesUnknownType(t *testing.T) {
	got := ipsetKernelModules("unknown:type")
	if len(got) != 1 || got[0] != "ip_set" {
		t.Fatalf("expected only base ip_set module for unknown type, got %v", got)
	}
}

func TestIsMissingIPSetModuleError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "invalid type", err: ErrInvalidType, want: true},
		{name: "netfilter family absent", err: ErrSetNotExist, want: true},
		{name: "raw enoent", err: syscall.ENOENT, want: true},
		{name: "set already exists", err: ErrSetExist, want: false},
		{name: "nil", err: nil, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isMissingIPSetModuleError(tt.err); got != tt.want {
				t.Fatalf("expected %v, got %v", tt.want, got)
			}
		})
	}
}
