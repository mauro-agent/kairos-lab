//go:build darwin

package vm

import "context"

// darwinLeaseFile is where Apple's DHCP server records its leases:
// bootpd.tproj/dhcpd.c defines DHCP_LEASES_FILE as exactly this path. It is
// one file for every vmnet client on the host, not one per interface, which
// is why defaultLeaseFile ignores the bridge name here.
const darwinLeaseFile = "/var/db/dhcpd_leases"

func defaultLeaseFile(_ string) string { return darwinLeaseFile }

func leaseLookup(path, mac string) string {
	return lookupLeaseFile(path, mac, parseDarwinLeases)
}

// arpLookup asks the host's ARP cache. -a lists every entry and -n keeps
// numeric addresses, so nothing here waits on a reverse DNS lookup -- which
// on a machine whose resolver is slow would otherwise cost seconds per tick.
func arpLookup(ctx context.Context, mac string) string {
	return parseDarwinARP(hostCommandOutput(ctx, "arp", "-an"), mac)
}
