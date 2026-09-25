package vm

import "path/filepath"

// The path building in this file is deliberately kept apart from the exec
// calls in network_linux.go so it can be exercised on any host, not only on
// Linux. network_linux.go carries no build tag of its own: it compiles only on
// Linux by virtue of its _linux.go filename, and a test placed beside it would
// inherit that constraint.

// nmStateDir is NetworkManager's NMSTATEDIR, the directory it keeps the
// dnsmasq lease files of shared connections in.
const nmStateDir = "/var/lib/NetworkManager"

// sharedLeaseFilePath returns the dnsmasq lease file NetworkManager writes for
// an interface running ipv4.method shared, or "" when iface is empty.
//
// NetworkManager starts the shared-mode dnsmasq with
// --dhcp-leasefile=<NMSTATEDIR>/dnsmasq-<iface>.leases, where NMSTATEDIR is
// /var/lib/NetworkManager and <iface> is nm_device_get_ip_iface() of the
// device the method was applied to.
//
// So iface is the interface that ACTUALLY RECEIVED ipv4.method shared, which
// is not the same thing as "the bridge name" even though today they are the
// same string. Move the method onto the tap and the lease file moves with it:
// a caller that recomputed this path from state.Network.BridgeName would then
// read a file nothing writes, or a stale one left by an earlier run, and no
// test here would notice. That is why PrepareLinuxShared calls this once, at
// the point it applies the method, and records the answer in
// state.Network.DHCPLeaseFile for later readers instead of letting them
// derive it again.
func sharedLeaseFilePath(iface string) string {
	if iface == "" {
		return ""
	}
	return filepath.Join(nmStateDir, "dnsmasq-"+iface+".leases")
}
