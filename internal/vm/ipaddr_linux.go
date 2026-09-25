//go:build linux

package vm

import "context"

// defaultLeaseFile is only a fallback. The path that matters is the one
// PrepareLinuxShared recorded in state.Network.DHCPLeaseFile at the moment it
// applied ipv4.method shared, because the file is named after the interface
// that RECEIVED the method rather than after the bridge -- see
// sharedLeaseFilePath, which is called here rather than rebuilt so the two
// can never disagree about the spelling of that path.
func defaultLeaseFile(bridgeName string) string { return sharedLeaseFilePath(bridgeName) }

func leaseLookup(path, mac string) string {
	return lookupLeaseFile(path, mac, parseDnsmasqLeases)
}

// arpLookup asks the kernel's neighbour table. No "show" and no device
// filter: the unfiltered form is cheap, and filtering by device is precisely
// what makes iproute2 drop the "dev <ifname>" token from its output and shift
// every following field. parseLinuxNeigh keys off the lladdr keyword and so
// survives either shape, but there is no reason to hand it the harder one.
func arpLookup(ctx context.Context, mac string) string {
	return parseLinuxNeigh(hostCommandOutput(ctx, "ip", "neigh"), mac)
}
