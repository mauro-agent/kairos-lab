package vm

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

// MACForDisk derives the guest NIC address for a disk from its name.
//
// QEMU seeds every process with the same default address, so two VMs sharing a
// subnet collide and a DHCP lease cannot be attributed to one of them. Hashing
// the disk name gives each VM its own address while keeping it deterministic:
// the same disk must present the same MAC after a restart, or the DHCP server
// hands it a different lease and the recorded IP goes stale.
//
// The 52:54:00 prefix is the conventional QEMU/KVM one and has the bits we
// need in its first octet (RFC 7042 section 2.1): 0x52&0x01 == 0 marks the
// address unicast, and 0x52&0x02 == 0x02 marks it locally administered, so it
// can never clash with a vendor-assigned address.
func MACForDisk(diskName string) string {
	sum := sha256.Sum256([]byte(diskName))
	return fmt.Sprintf("52:54:00:%02x:%02x:%02x", sum[0], sum[1], sum[2])
}

// NormalizeMAC reduces a MAC to one comparable form: lowercase, colon
// separated, with leading zeroes stripped from each octet. It returns "" for
// anything that is not six colon-separated hex octets, which callers read as
// "no match possible".
//
// Both sides of every comparison have to go through this, because the hosts
// disagree on padding. macOS strips leading zeroes per octet -- bootplib's
// host_identifier.c formats with %x, not %02x, so 52:54:00:12:34:56 appears in
// /var/db/dhcpd_leases as 52:54:0:12:34:56, and network_cmds' arp.c prints the
// same way. Linux dnsmasq and `ip neigh` zero-pad with %.2x. Comparing the two
// raw would silently never match.
func NormalizeMAC(s string) string {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(s)), ":")
	if len(parts) != 6 {
		return ""
	}
	for i, part := range parts {
		if len(part) < 1 || len(part) > 2 {
			return ""
		}
		for _, c := range part {
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				return ""
			}
		}
		// Strip the leading zero, but keep a lone "0": "0a" -> "a", "00" -> "0".
		parts[i] = strings.TrimLeft(part, "0")
		if parts[i] == "" {
			parts[i] = "0"
		}
	}
	return strings.Join(parts, ":")
}
