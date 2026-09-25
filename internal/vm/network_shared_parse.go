package vm

import (
	"fmt"
	"path/filepath"
	"strings"
)

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

// maxInterfaceNameLen is the longest interface name the Linux kernel accepts.
// IFNAMSIZ is 16 bytes and the last one is the terminating NUL, so 15
// characters is the real limit.
const maxInterfaceNameLen = 15

// validateStoredInterfaceName checks an interface name that came out of
// state.json, before anything is done with it. field names the setting it
// came from so the error points at the thing a user would have to edit.
//
// The names in state.json are not trustworthy input. The file lives in the
// user's config directory with mode 0644, so anything running as the user can
// put a string in it, and the Linux network paths then hand that string to
// `sudo nmcli connection delete <name>` and `sudo ip link delete <name>`
// during stale cleanup. "Wired connection 1" is a real NetworkManager profile
// on most desktops, and on distros that name profiles after the device an
// "eth0" there names the host's own NIC: either one deletes the host's
// network configuration, and the consent prompt that runs alongside names the
// uplink rather than the resource about to be deleted.
//
// The same string reaches two more places. sharedLeaseFilePath joins it into
// a path, where "../../../etc/shadow" escapes NMSTATEDIR -- filepath.Join
// cleans the result, but cleaning is what performs the escape, because the
// literal "dnsmasq-.." component is popped by the ".." that follows it. And
// it is printed into the cleanup plan, where an embedded newline plus a CSI
// sequence forges a plan row and erases the real one after it, subverting the
// confirmation prompt that immediately follows.
//
// One rule closes all three: accept exactly what the kernel accepts for an
// interface name and nothing else. That leaves no space to separate an
// argument, no dot to walk a path and no control character to reach a
// terminal.
func validateStoredInterfaceName(field, name string) error {
	switch {
	case name == "":
		return fmt.Errorf("invalid %s in stored configuration: the name is empty", field)
	case name == "." || name == "..":
		return fmt.Errorf("invalid %s %q in stored configuration: that is a directory reference, not an interface name", field, name)
	case len(name) > maxInterfaceNameLen:
		return fmt.Errorf("invalid %s %q in stored configuration: %d bytes, but an interface name is at most %d", field, name, len(name), maxInterfaceNameLen)
	case strings.HasPrefix(name, "-"):
		// Stricter than the kernel, which would accept this: a name starting
		// with a dash is read as an option by the nmcli and ip invocations it
		// is passed to, and no real interface is named that way.
		return fmt.Errorf("invalid %s %q in stored configuration: an interface name may not begin with '-'", field, name)
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
			continue
		}
		// %q and not %s: the value may carry newlines or escape sequences,
		// and an error message is printed to the same terminal the plan is.
		return fmt.Errorf("invalid %s %q in stored configuration: an interface name may contain only letters, digits, '_' and '-'", field, name)
	}
	return nil
}
