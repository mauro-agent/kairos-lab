package vm

import (
	"fmt"
	"path/filepath"
	"strings"
)

// The path building and the output parsing in this file are deliberately kept
// apart from the exec calls in network_linux.go so they can be exercised on
// any host, not only on Linux. network_linux.go carries no build tag of its own: it compiles only on
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
// This rule closes the first two of those, and only those: no space to
// separate an argument, no dot to walk a path. Both of those consumers sit
// downstream of a call to this function. The cleanup plan does not. It is
// printed before anything validates -- `reset` and `cleanup` build and print
// their plan straight from store.Load(), and only reach the check inside
// cleanupNMConnections after the user has already answered the prompt.
//
// So the third vector is closed at the print boundary instead, by a different
// mechanism than this one. internal/app runs every plan row through its
// planValue helper, which returns a value unchanged when all of its runes are
// printable and hands it to strconv.Quote when any is not -- so a row carrying
// a newline, a CSI sequence or an invalid UTF-8 byte arrives as one escaped
// line, whatever this validator would have made of it. That covers the rows
// these two names appear in and every sibling row beside them: stored paths,
// disk names and dependency names, none of which pass through here at all. The
// errors below quote with %q for the same reason, since they are printed to
// the same terminal and one of them carries the rejected value back to it.
// Two mechanisms and not one; dropping either reopens its own half.
//
// The rule is also deliberately stricter than the kernel, which is what makes
// it usable as an argv and path guard. dev_valid_name() rejects only an empty
// name, a name of IFNAMSIZ bytes or more, exactly "." or "..", and any '/',
// ':' or whitespace -- it accepts a leading '-', and it accepts a dot
// anywhere else. Neither is safe here: a leading '-' is read as an option by
// the nmcli and ip invocations, and a dot is what walks out of NMSTATEDIR.
// The known cost of the narrower rule is that a legitimate VLAN name like
// "eth0.100" is rejected. That is accepted rather than worked around: these
// two fields name the bridge and the tap kairos-lab creates for itself, both
// default to names this rule allows, and nothing in the tool puts a VLAN
// interface in either.
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

// parseBridgeSlave returns the first interface in `ip -o link show master
// <bridge>` output that is not the tap, or "" when the output names none.
// network_linux.go owns the exec that produces out; this half is the part
// worth testing, and it needs no Linux and no bridge to test.
//
// The filter is the whole point of the function. What it returns is the
// interface the teardown hands to `nmcli device connect` -- the one command in
// a teardown that puts the host's own NIC back after the bridge it was
// enslaved to is deleted. Return the tap and the teardown reconnects a device
// nobody enslaved and leaves the real NIC with no active connection; return ""
// when there was a physical slave and the host is left off the network with
// nothing said.
//
// tap is matched by name. The old filter skipped any interface whose name
// merely CONTAINED "tap", so a host NIC called "captap0" or "tap-lan" was
// silently never reconnected. DefaultTapName is skipped alongside the
// configured name so that a tap name edited in state.json after the tap was
// created cannot make the old tap look like a physical slave; for the default
// configuration the two are the same string and the behaviour is unchanged.
func parseBridgeSlave(out, tap string) string {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		// Format: "3: enp0s31f6: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 ..."
		iface := strings.TrimSuffix(fields[1], ":")
		if iface == "" || iface == tap || iface == DefaultTapName {
			continue
		}
		return iface
	}
	return ""
}
