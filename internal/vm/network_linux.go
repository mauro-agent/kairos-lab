package vm

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/kairos-io/kairos-lab/internal/state"
)

const (
	DefaultBridgeName = "kairoslab0"
	DefaultTapName    = "kairoslab-tap0"
)

// linuxNetworkPreflight performs the host-side checks PrepareLinuxBridge and
// PrepareLinuxShared both make, and resolves the bridge and tap names each of
// them goes on to build. mode is the user-facing network mode ("bridged",
// "shared"); it appears in the NetworkManager error so the message names the
// mode the caller actually asked for.
func linuxNetworkPreflight(st *state.State, runtimeDir, mode string) (bridge, tap string, err error) {
	if !networkManagerActive() {
		return "", "", fmt.Errorf("NetworkManager is required for %s networking on Linux. Please install and enable NetworkManager, or use --network user for port-forwarded access", mode)
	}
	if err := os.MkdirAll(runtimeDir, 0o755); err != nil {
		return "", "", fmt.Errorf("create runtime directory: %w", err)
	}
	bridge = st.Network.BridgeName
	if bridge == "" {
		bridge = DefaultBridgeName
	}
	tap = st.Network.TapName
	if tap == "" {
		tap = DefaultTapName
	}

	// Both names were just read out of state.json, and both are about to be
	// interpolated into root-run nmcli and ip commands, into a filesystem path
	// and into the cleanup plan the user is asked to confirm. Validate them
	// here, at the single point where both modes resolve them, rather than at
	// each of those call sites. A rejected name is an error and not a quiet
	// fall back to the default: a value someone put in state.json that
	// silently does nothing is its own surprise.
	if err := validateStoredInterfaceName("bridge name", bridge); err != nil {
		return "", "", err
	}
	if err := validateStoredInterfaceName("tap name", tap); err != nil {
		return "", "", err
	}

	// Check for stale resources from a previous run. The predicate is shared
	// with HasStaleNetworkResources so the two cannot disagree about what
	// stale means; see hasStaleBridgeResources for why every term of it
	// matters to the shared path too.
	if hasStaleBridgeResources(bridge) {
		fmt.Println("Found stale network configuration, cleaning up...")
		_ = cleanupNMConnections(bridge)
		time.Sleep(staleCleanupSettleDelay)
	}
	return bridge, tap, nil
}

// staleCleanupSettleDelay is how long the preflight waits after tearing down a
// stale bridge, giving NetworkManager time to finish releasing the interfaces
// before they are recreated. It is a var only so network_linux_test.go can
// zero it; nothing in production assigns it.
var staleCleanupSettleDelay = 2 * time.Second

// hasStaleBridgeResources reports whether a previous run left any part of this
// bridge behind: the bridge link, the bridge connection, the <bridge>-uplink
// connection or the <bridge>-tap connection.
//
// Every term matters to BOTH modes, including the -uplink one that only the
// bridged path ever creates. cleanupNMConnections downgrades a failed delete
// to a printed warning and its caller discards the result, so a teardown can
// end with the bridge connection gone and the -uplink connection still on the
// host. That orphan carries `master <bridge> slave-type bridge` and
// autoconnect, so the next `--network shared` run brings its bridge up and
// NetworkManager enslaves the host's physical NIC to a NAT bridge -- which
// destroys the "no uplink is enslaved" invariant that is the entire reason
// shared mode exists, and takes the host's connectivity with it. The bridged
// path survives the same orphan only because it recreates and re-modifies the
// -uplink connection itself.
//
// linuxNetworkPreflight and HasStaleNetworkResources both call this so the
// narrower of the two predicates cannot drift back into existence.
func hasStaleBridgeResources(bridge string) bool {
	return IsLinuxBridge(bridge) || nmConnectionExists(bridge) ||
		nmConnectionExists(bridge+"-uplink") || nmConnectionExists(bridge+"-tap")
}

func PrepareLinuxBridge(st *state.State, runtimeDir string) error {
	if runtime.GOOS != "linux" {
		return nil
	}
	bridge, tap, err := linuxNetworkPreflight(st, runtimeDir, "bridged")
	if err != nil {
		return err
	}

	uplink := st.Network.BridgeInterface
	if uplink == "" {
		// Retry a few times in case NM is still restoring the connection
		var u string
		var err error
		for i := 0; i < 5; i++ {
			u, err = detectDefaultUplink()
			if err == nil {
				break
			}
			time.Sleep(time.Second)
		}
		if err != nil {
			return err
		}
		uplink = u
	}
	if uplink == bridge {
		return fmt.Errorf("uplink interface and bridge cannot be the same: %s", uplink)
	}
	if !linkExists(uplink) {
		return fmt.Errorf("uplink interface does not exist: %s", uplink)
	}
	if IsLinuxBridge(uplink) {
		return fmt.Errorf("uplink interface must be a physical host iface, got bridge: %s", uplink)
	}
	if isVirtualInterface(uplink) {
		return fmt.Errorf("uplink interface must be a physical host iface, got virtual interface: %s (use -bridge-if to specify a physical interface like eth0, enp*, or wlan*)", uplink)
	}

	if err := prepareLinuxBridgeWithNM(bridge, tap, uplink); err != nil {
		return err
	}

	st.Network.Mode = "bridged"
	st.Network.BridgeName = bridge
	st.Network.BridgeInterface = uplink
	st.Network.TapName = tap
	// There is no NetworkManager DHCP server in bridged mode; the guest leases
	// from whatever server the physical network runs. Clear the field rather
	// than merely not writing it, for the same reason PrepareLinuxShared
	// clears BridgeInterface: `start --network shared` followed by
	// `start --network bridged` never runs cleanup in between, so an earlier
	// shared run leaves a lease path here, and the reader of this field would
	// report a previous guest's address as this one's.
	st.Network.DHCPLeaseFile = ""
	st.Network.CleanupRequired = true
	st.Network.CreatedByKairosLab = true
	st.Network.LastPreparedAt = state.NowRFC3339()
	return nil
}

func prepareLinuxBridgeWithNM(bridge, tap, uplink string) error {
	if !nmcliAvailable() {
		return fmt.Errorf("NetworkManager is active but nmcli is not installed")
	}
	bridgeConn := bridge
	uplinkConn := bridge + "-uplink"
	tapConn := bridge + "-tap"
	uid, err := tapOwnerUID()
	if err != nil {
		return err
	}

	if !nmConnectionExists(bridgeConn) {
		if err := sudo("nmcli", "connection", "add", "type", "bridge", "ifname", bridge, "con-name", bridgeConn, "autoconnect", "yes", "stp", "no"); err != nil {
			return err
		}
	}
	if err := sudo("nmcli", "connection", "modify", bridgeConn, "connection.interface-name", bridge, "ipv4.method", "auto", "ipv6.method", "auto", "bridge.stp", "no", "connection.autoconnect", "yes"); err != nil {
		return err
	}

	if !nmConnectionExists(uplinkConn) {
		if err := sudo("nmcli", "connection", "add", "type", "ethernet", "ifname", uplink, "con-name", uplinkConn, "master", bridgeConn, "slave-type", "bridge", "autoconnect", "yes"); err != nil {
			return err
		}
	}
	if err := sudo("nmcli", "connection", "modify", uplinkConn, "connection.interface-name", uplink, "master", bridgeConn, "slave-type", "bridge", "connection.autoconnect", "yes"); err != nil {
		return err
	}

	if !nmConnectionExists(tapConn) {
		if err := sudo("nmcli", "connection", "add", "type", "tun", "ifname", tap, "con-name", tapConn, "mode", "tap", "owner", uid, "master", bridgeConn, "slave-type", "bridge", "autoconnect", "yes"); err != nil {
			return err
		}
	}
	if err := sudo("nmcli", "connection", "modify", tapConn, "connection.interface-name", tap, "tun.mode", "tap", "tun.owner", uid, "master", bridgeConn, "slave-type", "bridge", "connection.autoconnect", "yes"); err != nil {
		return err
	}

	if err := sudo("nmcli", "connection", "up", bridgeConn); err != nil {
		return err
	}
	if err := sudo("nmcli", "connection", "up", uplinkConn); err != nil {
		return err
	}
	if err := sudo("nmcli", "connection", "up", tapConn); err != nil {
		return err
	}
	return nil
}

// PrepareLinuxShared builds the host side of --network shared: a bridge whose
// only port is the tap, carrying ipv4.method shared. NetworkManager then
// assigns 10.42.x.1/24 to the bridge, starts a DHCP server and DNS forwarder
// on it, and NATs the guests out of whatever the host's current default
// connection happens to be.
//
// Deliberately absent, for anyone looking for it: every uplink step
// PrepareLinuxBridge takes — detectDefaultUplink and its retry loop, the
// "must be a physical host iface" validations, the <bridge>-uplink connection.
// shared enslaves no physical interface, which is the entire point of the
// mode. A bridge with no port still activates (NetworkManager ignores carrier
// by default on controller types), so there is nothing to detect and nothing
// to validate. It is also why shared works over Wi-Fi where bridged cannot: no
// guest frame ever leaves the host with a MAC the access point did not see
// associate. And because the masquerade rule NetworkManager installs matches
// on the source subnet with no output-interface match, the host can move from
// Wi-Fi to Ethernet under a running VM without any rule churn.
func PrepareLinuxShared(st *state.State, runtimeDir string) error {
	if runtime.GOOS != "linux" {
		return nil
	}
	bridge, tap, err := linuxNetworkPreflight(st, runtimeDir, "shared")
	if err != nil {
		return err
	}

	if err := prepareLinuxSharedWithNM(bridge, tap); err != nil {
		return err
	}

	st.Network.Mode = "shared"
	st.Network.BridgeName = bridge
	// There is no uplink in shared mode. Clear the field rather than merely
	// not writing it: an earlier bridged run can have left an interface name
	// in state, and `status` would print it as this VM's uplink.
	st.Network.BridgeInterface = ""
	st.Network.TapName = tap
	// bridge, not tap: the lease file is named after the interface that
	// received ipv4.method shared. See sharedLeaseFilePath.
	st.Network.DHCPLeaseFile = sharedLeaseFilePath(bridge)
	st.Network.CleanupRequired = true
	st.Network.CreatedByKairosLab = true
	st.Network.LastPreparedAt = state.NowRFC3339()
	return nil
}

func prepareLinuxSharedWithNM(bridge, tap string) error {
	if !nmcliAvailable() {
		return fmt.Errorf("NetworkManager is active but nmcli is not installed")
	}
	bridgeConn := bridge
	tapConn := bridge + "-tap"
	uid, err := tapOwnerUID()
	if err != nil {
		return err
	}

	// autoconnect is off on both connections this path creates, where the
	// bridged path leaves it on. ipv4.method shared is not an idle setting: a
	// bridge carrying it runs a DHCP server and a DNS forwarder, and turns on
	// IPv4 forwarding and a MASQUERADE rule. NetworkManager persists these
	// connections as keyfiles, so with autoconnect on, a user who chose shared
	// mode once would get all four on every subsequent boot, with no VM
	// running and nothing asking for them. kairos-lab brings both connections
	// up explicitly on every start -- `nmcli connection up` activates a
	// connection whose autoconnect is no, since autoconnect governs only what
	// NetworkManager starts on its own -- so autoconnect buys this path
	// nothing and costs a permanent host footprint.
	if !nmConnectionExists(bridgeConn) {
		if err := sudo("nmcli", "connection", "add", "type", "bridge", "ifname", bridge, "con-name", bridgeConn, "autoconnect", "no", "stp", "no"); err != nil {
			return err
		}
	}
	// ipv4.method shared is the whole mode: it is what makes NetworkManager
	// address the bridge, run dnsmasq on it and install the NAT rule. No
	// ipv4.addresses, ipv4.dns or ipv4.dns-search go with it — the defaults
	// are what we want, and NetworkManager's verify() rejects a shared
	// connection that carries dns settings at all.
	//
	// ipv6.method is ignore here where the bridged path uses auto. Nothing
	// configures IPv6 for these guests, and a bridge with no port has nothing
	// upstream to source router advertisements, so auto would only leave the
	// bridge soliciting an address that cannot arrive. ignore says what is
	// actually true.
	if err := sudo("nmcli", "connection", "modify", bridgeConn, "connection.interface-name", bridge, "ipv4.method", "shared", "ipv6.method", "ignore", "bridge.stp", "no", "connection.autoconnect", "no"); err != nil {
		return err
	}

	// The tap is built as the bridged path builds it -- the guest end is the
	// same either way, only what sits on the other side of the bridge differs
	// -- except for autoconnect, which is off here for the reason above: a tap
	// left to come up on its own at boot brings its controller, and therefore
	// the DHCP server and the NAT rule, up with it.
	if !nmConnectionExists(tapConn) {
		if err := sudo("nmcli", "connection", "add", "type", "tun", "ifname", tap, "con-name", tapConn, "mode", "tap", "owner", uid, "master", bridgeConn, "slave-type", "bridge", "autoconnect", "no"); err != nil {
			return err
		}
	}
	if err := sudo("nmcli", "connection", "modify", tapConn, "connection.interface-name", tap, "tun.mode", "tap", "tun.owner", uid, "master", bridgeConn, "slave-type", "bridge", "connection.autoconnect", "no"); err != nil {
		return err
	}

	if err := sudo("nmcli", "connection", "up", bridgeConn); err != nil {
		return err
	}
	if err := sudo("nmcli", "connection", "up", tapConn); err != nil {
		return err
	}
	return nil
}

func CleanupLinuxBridge(st *state.State) error {
	if runtime.GOOS != "linux" {
		return nil
	}
	if !st.Network.CreatedByKairosLab {
		return nil
	}
	bridgeConn := st.Network.BridgeName
	if bridgeConn == "" {
		bridgeConn = DefaultBridgeName
	}
	if err := cleanupNMConnections(bridgeConn); err != nil {
		return err
	}
	st.Network.LastCleanupAttemptAt = state.NowRFC3339()
	st.Network = state.Network{}
	return nil
}

// HasStaleNetworkResources checks if there are kairos-lab network resources
// that exist but aren't tracked in state (e.g., from a failed setup).
func HasStaleNetworkResources(st *state.State) bool {
	if runtime.GOOS != "linux" {
		return false
	}
	if st.Network.CreatedByKairosLab {
		return false
	}
	bridge := st.Network.BridgeName
	if bridge == "" {
		bridge = DefaultBridgeName
	}
	return hasStaleBridgeResources(bridge)
}

// CleanupStaleNetworkResources removes kairos-lab network resources that aren't
// tracked in state, typically from a failed or interrupted setup.
func CleanupStaleNetworkResources(st *state.State) error {
	if runtime.GOOS != "linux" {
		return nil
	}
	bridge := st.Network.BridgeName
	if bridge == "" {
		bridge = DefaultBridgeName
	}
	return cleanupNMConnections(bridge)
}

func cleanupNMConnections(bridgeConn string) error {
	// Every destructive command below is built from this one name, which comes
	// out of state.json -- a 0644 file any process running as the user can
	// write. linuxNetworkPreflight validates it before a start, but reset and
	// cleanup reach here without passing through the preflight, so the same
	// check has to sit at the choke point too. Without it a stored name of
	// "eth0" turns into `sudo nmcli connection delete eth0` and
	// `sudo ip link delete eth0`, and the host loses its network.
	if err := validateStoredInterfaceName("bridge name", bridgeConn); err != nil {
		return fmt.Errorf("refusing to clean up network resources: %w", err)
	}
	uplinkConn := bridgeConn + "-uplink"
	tapConn := bridgeConn + "-tap"
	tap := DefaultTapName

	// Find the physical interface enslaved to the bridge before we delete anything
	var uplinkIface string
	if IsLinuxBridge(bridgeConn) {
		uplinkIface = findBridgeSlave(bridgeConn)
	}

	// Delete all NM connections - use sudo (not sudoQuiet) so user can see
	// what's happening and errors are visible
	for _, conn := range []string{tapConn, uplinkConn, bridgeConn} {
		if nmConnectionExists(conn) {
			if err := sudo("nmcli", "connection", "delete", conn); err != nil {
				fmt.Printf("warning: failed to delete connection %s: %v\n", conn, err)
			}
		}
	}

	// Now clean up any lingering interfaces that NM didn't remove
	if linkExists(tap) {
		if err := sudo("ip", "link", "delete", tap); err != nil {
			fmt.Printf("warning: failed to delete interface %s: %v\n", tap, err)
		}
	}
	if linkExists(bridgeConn) {
		if err := sudo("ip", "link", "delete", bridgeConn); err != nil {
			fmt.Printf("warning: failed to delete interface %s: %v\n", bridgeConn, err)
		}
	}

	// Reconnect the physical interface (NM connections are gone, so this
	// will use a fresh/default connection, not the bridge slave profile)
	if uplinkIface != "" {
		fmt.Printf("Reconnecting %s...\n", uplinkIface)
		if err := sudo("nmcli", "device", "connect", uplinkIface); err != nil {
			fmt.Printf("warning: failed to reconnect %s: %v\n", uplinkIface, err)
		}
	}

	return nil
}

var linkExists = func(name string) bool {
	if name == "" {
		return false
	}
	cmd := exec.Command("ip", "link", "show", name)
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}

// findBridgeSlave finds a physical interface enslaved to the given bridge
func findBridgeSlave(bridge string) string {
	// List interfaces that have this bridge as master
	out, err := exec.Command("ip", "-o", "link", "show", "master", bridge).Output()
	if err != nil {
		return ""
	}
	// Parse output to find non-tap interfaces
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		// Format: "3: enp0s31f6: <...>"
		iface := strings.TrimSuffix(fields[1], ":")
		// Skip tap interfaces
		if strings.Contains(iface, "tap") {
			continue
		}
		return iface
	}
	return ""
}

// sudo, and the host probes further down this file, are package-level vars
// rather than plain functions so network_linux_test.go can swap them for
// in-process fakes and assert the exact argv sequence these paths hand to
// root. Nothing in production assigns them; the tests restore the originals
// with t.Cleanup. The bodies are unchanged.
var sudo = func(name string, args ...string) error {
	argv := append([]string{name}, args...)
	cmd := exec.Command("sudo", argv...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("sudo command failed: sudo %s: %w", strings.Join(argv, " "), err)
	}
	return nil
}

func IsPathGone(path string) bool {
	_, err := os.Stat(path)
	return errors.Is(err, os.ErrNotExist)
}

var IsLinuxBridge = func(name string) bool {
	if runtime.GOOS != "linux" || name == "" {
		return false
	}
	_, err := os.Stat(filepath.Join("/sys/class/net", name, "bridge"))
	return err == nil
}

func detectDefaultUplink() (string, error) {
	candidates := DetectUplinkCandidates()
	if len(candidates) == 0 {
		return "", fmt.Errorf("could not determine default uplink interface (all candidates are bridges, virtual, or loopback)")
	}
	return candidates[0], nil
}

// DetectUplinkCandidates returns all valid physical interfaces from the default routes.
// The list preserves the order returned by `ip route show default` after filtering and de-duplication.
func DetectUplinkCandidates() []string {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return nil
	}
	seen := make(map[string]bool)
	var candidates []string
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		for i := 0; i < len(fields)-1; i++ {
			if fields[i] == "dev" {
				iface := fields[i+1]
				if iface != "" && iface != "lo" && !IsLinuxBridge(iface) && !isVirtualInterface(iface) && !seen[iface] {
					seen[iface] = true
					candidates = append(candidates, iface)
				}
			}
		}
	}
	return candidates
}

func isVirtualInterface(name string) bool {
	virtualPrefixes := []string{
		"docker",  // Docker default bridge
		"br-",     // Docker custom networks
		"veth",    // Virtual ethernet (container endpoints)
		"virbr",   // libvirt bridges
		"vnet",    // libvirt VM interfaces
		"lxcbr",   // LXC bridges
		"lxdbr",   // LXD bridges
		"cni",     // Kubernetes CNI
		"flannel", // Kubernetes flannel
		"calico",  // Kubernetes calico
		"weave",   // Kubernetes weave
		"tunl",    // IPIP tunnels
		"podman",  // Podman networks
	}
	for _, prefix := range virtualPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

var networkManagerActive = func() bool {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false
	}
	return exec.Command("systemctl", "is-active", "--quiet", "NetworkManager").Run() == nil
}

// nmcliAvailable reports whether the nmcli binary is on PATH. It is separate
// from nmConnectionExists so a test can drive the prepare paths on a host that
// has no NetworkManager installed at all.
var nmcliAvailable = func() bool {
	_, err := exec.LookPath("nmcli")
	return err == nil
}

var nmConnectionExists = func(name string) bool {
	if name == "" {
		return false
	}
	if _, err := exec.LookPath("nmcli"); err != nil {
		return false
	}
	return exec.Command("nmcli", "-t", "-f", "NAME", "connection", "show", name).Run() == nil
}

// tapOwnerUID resolves the uid the tap device is handed to, so QEMU can open
// it without privileges. Under sudo the invoking user is the one that matters
// and not root, which is why SUDO_USER is consulted first and why uidForUser
// exists at all.
//
// Everything else falls through to os.Getuid(), the kernel's own answer for
// who this process is: no subprocess, and nothing to validate. There is
// deliberately no $USER step. $USER is set by login shells and by little
// else, so under a systemd unit, cron, `env -i` or a minimal container shell
// it is absent -- and a chain ending in a literal "root" then handed the tap
// to uid 0 while the process ran as somebody else, leaving QEMU unable to
// open the device it had just asked to have created.
func tapOwnerUID() (string, error) {
	if user := os.Getenv("SUDO_USER"); user != "" {
		return uidForUser(user)
	}
	return strconv.Itoa(os.Getuid()), nil
}

func uidForUser(user string) (string, error) {
	out, err := exec.Command("id", "-u", user).Output()
	if err != nil {
		return "", fmt.Errorf("resolve uid for user %q: %w", user, err)
	}
	uid := strings.TrimSpace(string(out))
	if uid == "" {
		return "", fmt.Errorf("resolve uid for user %q: empty uid", user)
	}
	for _, r := range uid {
		if r < '0' || r > '9' {
			return "", fmt.Errorf("resolve uid for user %q: invalid uid %q", user, uid)
		}
	}
	return uid, nil
}
