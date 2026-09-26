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
		cleanupErr := cleanupNMConnections(bridge, tap)
		// A leftover that will not go is fatal for shared and survivable for
		// bridged. Every connection this teardown deletes is one the bridged
		// path recreates and re-modifies a few lines later, with the master,
		// the slave type and the autoconnect that run wants, so a failed
		// delete leaves it with a profile it is about to overwrite -- which
		// is why the error is dropped there. The shared path rewrites none
		// of them: its bridge carries ipv4.method shared and its only port
		// is meant to be the tap, and a surviving profile that carries
		// `master <bridge> slave-type bridge` has NetworkManager enslave a
		// host NIC to that bridge when it comes up.
		//
		// What this refusal knows, though, is only that a teardown step
		// failed -- not that such a profile survived. The step may have been
		// the `nmcli device connect` reconnect at the end, where every
		// delete succeeded and nothing is enslaved to anything. Not knowing
		// the state of the host is reason enough to stop a mode whose whole
		// promise is that no host interface is attached, so the refusal
		// stays; the message below claims no more than that. The invariant
		// itself is enforced where it is observable, by the bridge-port
		// assertion in prepareLinuxSharedWithNM, which reads the kernel's
		// port list even on a host this preflight found clean.
		//
		// This is not a refusal that comes before anything was touched,
		// either. cleanupNMConnections stops at no failure, so every later
		// step was reached -- which is not the same as every later step
		// having run: the two `ip link delete`s are skipped when linkExists
		// cannot see their interface, and the reconnect when findBridgeSlave
		// named nobody. Which of them issued anything is not knowable from
		// the joined error, so the message names the gates instead of
		// listing the steps as though they had all run.
		if cleanupErr != nil && mode == "shared" {
			return "", "", fmt.Errorf("shared networking cannot start until the leftover network configuration is gone, and removing it failed: %w. "+
				"The cleanup does not stop at its first failure, so every step after the one above was still attempted where it had anything to attempt, and the failure above names each one that failed. Several steps do nothing when there is nothing to do: the `ip link delete`s run only for an interface `ip link show` can see, and the reconnect only for an interface found on the bridge. After a reboot, where the connection keyfiles survive and the interfaces do not, the delete that failed above can be the only command this cleanup issued at all. "+
				"Where it did issue something, the host's networking has changed, and a physical interface can be left with no active connection -- `nmcli device status` shows which, and `sudo nmcli connection up <profile>` puts it back on the profile you name. Prefer that to `sudo nmcli device connect <iface>`, which activates whichever profile NetworkManager rates best for the device, routinely the bridge-slave profile after a bridged run -- one of the leftovers this cleanup was trying to remove. "+
				"The start is refused rather than attempted because shared mode enslaves no host interface: its bridge carries ipv4.method shared and its only port is meant to be the tap, and a leftover this tool could not remove may be what attaches a NIC to that bridge. "+
				"Remove the leftover the failure above names and start again, or use -network bridged, which rebuilds these connections itself",
				cleanupErr)
		}
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
// bridged path ever creates. cleanupNMConnections attempts every delete and
// returns the ones that failed joined together, so a teardown can end with
// the bridge connection gone and the -uplink connection still on the host.
// That orphan carries `master <bridge> slave-type bridge` and autoconnect, so
// a `--network shared` run that brought its bridge up over it would have
// NetworkManager enslave the host's physical NIC to a NAT bridge -- which
// destroys the "no uplink is enslaved" invariant that is the entire reason
// shared mode exists, and takes the host's connectivity with it. Widening
// this predicate is what gets that orphan DELETED on a shared run, and
// linuxNetworkPreflight refuses the start when the delete it then attempts
// fails. The bridged path carries on over the same failure, because it
// recreates and re-modifies the -uplink connection itself.
//
// Seeing it here is not what ENFORCES the invariant, and nothing in this file
// should read as if it were: every probe in the expression below answers "no"
// when it cannot get an answer, and the three connection names it knows are
// not the only ones a profile can have. What enforces it is the bridge-port
// assertion in prepareLinuxSharedWithNM, which asks the kernel which
// interfaces are actually ports of the bridge. This predicate makes the
// common case a clean start instead of a refusal.
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
	// NetworkManager starts on its own.
	//
	// It is a trade and not a free win. What autoconnect still buys is
	// re-activation on an event nothing here watches for: `systemctl restart
	// NetworkManager` under a running shared-mode guest leaves the bridge and
	// the tap down and takes the guest's network with them until the next
	// `start`, where the bridged path comes back on its own. That is the cost
	// accepted here, against a DHCP server, a DNS forwarder, IPv4 forwarding
	// and a MASQUERADE rule appearing on every boot of a host that chose
	// shared once. The recoverable failure is the better one.
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

	// The port assertion, made three times: before anything is activated,
	// once the bridge is up, and once the tap is on it. What it asks the
	// kernel is which interfaces are ports of this bridge; what it demands is
	// that none of them is one this start did not put there.
	//
	// Before either `connection up` the expected port list is EMPTY. Nothing
	// has attached the tap yet -- that is the last command in this function
	// -- so a bridge with any port at all at this point has one from
	// somewhere else. Expecting nothing is also what keeps st.Network.TapName
	// out of the predicate: an exception named by the untrusted file this
	// check exists to defend against is an exception that file can aim at the
	// host's own NIC, and validateStoredInterfaceName accepts "eth0" there.
	//
	// A bridge link that got past the preflight can already carry a host NIC:
	// linkExists answers "no" for any `ip` failure, so the `ip link delete` in
	// the teardown is skipped while isLinuxBridge, which reads /sys, still says
	// a bridge is there. The connection profile has just been re-pointed at
	// ipv4.method shared, so the first of these is the last moment before that
	// method is applied to a bridge carrying somebody's NIC.
	if err := refuseForeignBridgePort(bridge, bridgeConn, tapConn, tap, tapNotYetAttached); err != nil {
		return err
	}
	if err := sudo("nmcli", "connection", "up", bridgeConn); err != nil {
		return err
	}
	// Again now the bridge is up, which is the check that catches the hazard
	// this mode is guarded against: a profile carrying `master <bridge>
	// slave-type bridge` with autoconnect on enslaves its interface the moment
	// the controller activates, whether the preflight's connection probes
	// could see that profile or not. The tap comes up only after this passes,
	// so a refused run never puts a guest on the bridge.
	if err := refuseForeignBridgePort(bridge, bridgeConn, tapConn, tap, tapNotYetAttached); err != nil {
		return err
	}
	if err := sudo("nmcli", "connection", "up", tapConn); err != nil {
		return err
	}
	// And once more with the tap attached, where the expected port list is
	// exactly the tap. `nmcli connection up` returns when the connection has
	// activated, and an interface attached in the instant after that is not
	// seen by the check before it; this one costs one more `ip` call and
	// narrows that window to the tap's own activation. It is the only one of
	// the three that names the tap, and by the time it runs an empty port
	// list has been established twice, so a port carrying that name here is a
	// refusal whichever thing it turns out to be.
	//
	// The window is narrowed and not closed: nothing reads the port list
	// again once this function returns, and nothing watches it while the VM
	// runs.
	if err := refuseForeignBridgePort(bridge, bridgeConn, tapConn, tap, tapAttached); err != nil {
		return err
	}
	return nil
}

// tapNotYetAttached and tapAttached spell out refuseForeignBridgePort's last
// argument at the call sites, which would otherwise be a bare true or false
// on three calls that differ in nothing else.
const (
	tapNotYetAttached = false
	tapAttached       = true
)

// refuseForeignBridgePort enforces the invariant shared mode exists for: the
// only port this bridge ever has is the tap, and it has none at all until the
// tap is activated. It asks the kernel, through `ip -o link show master
// <bridge>`, rather than inferring the answer from what the teardown before
// it believed it had deleted -- those are different questions, and the second
// one has been wrong twice. A profile nmConnectionExists could not see (it
// reports "does not exist" for any nmcli exit it dislikes, a restarting
// NetworkManager included) is never deleted, so cleanup joins no errors and
// returns nil; and a profile named anything other than the three
// cleanupNMConnections knows about -- a "Wired connection 1" somebody pointed
// at this bridge -- survives a cleanup that fully succeeded. Both end with a
// preflight that saw a clean host and a NIC on a NAT bridge.
//
// It fails CLOSED, which is the whole reason bridgeSlaveLinks returns an
// error. A probe that cannot answer is not an answer, and this one gates a
// root-run network reconfiguration. `ip -o link show master` is missing from
// busybox's `ip`, which exits 2 with `either "dev" is duplicate`; from an
// iproute2 older than the filter; and from a host with no `ip` on PATH at
// all. Every one of those is a permanent property of the host rather than a
// transient failure, so reading them as "no ports" would leave the invariant
// unenforced for good on whole classes of machine -- while the port list is
// the only thing enforcing it.
//
// The one thing still read as "no ports" without asking `ip` is a bridge that
// is not there. isLinuxBridge stats /sys/class/net/<bridge>/bridge, and on a
// clean host this runs before anything has been activated, so no device of
// that name exists yet and the probe would fail saying exactly that. A stat
// that answers "no" for some other reason -- a host with no readable /sys --
// takes a start past this check, and that is the last fail-open here. It is a
// narrower one than the probe's: it needs the bridge's own sysfs entry to be
// unreadable, not merely `ip` to be unusable.
//
// Both refusals hand the host back the way they found it, as far as they can;
// see revertSharedSetup. The profile that did the attaching is left alone: it
// may be one this tool never created, and deleting a user's network
// configuration on their behalf is the failure mode this whole path exists to
// avoid.
func refuseForeignBridgePort(bridge, bridgeConn, tapConn, tap string, tapIsAttached bool) error {
	if !isLinuxBridge(bridge) {
		return nil
	}
	out, err := bridgeSlaveLinks(bridge)
	if err != nil {
		return fmt.Errorf("shared networking will not start over bridge %s, because the check that nothing is attached to it could not be run: `ip -o link show master %s` failed: %w. "+
			"The bridge exists on this host, so the question is a real one and this start could not answer it. Shared mode's promise is that no host interface is a port of its bridge -- that is what the consent prompt says, and ipv4.method shared is what makes getting it wrong expensive -- so a port list that cannot be read is a refusal and not a pass. "+
			"`ip` may not be on PATH at all; it may be busybox's `ip`, which has no `show master` filter; or it may be an iproute2 older than that filter. `ip -V` says which. "+
			"The same list is in `ls /sys/class/net/%s/brif`, which needs none of them: if it names an interface of yours, something is attaching that interface to this bridge; if it is empty, `sudo ip link delete %s` removes the leftover bridge and the next start builds its own. "+
			"%s. "+
			"Or use -network bridged, which attaches an interface to a bridge on purpose, or -network user, which builds no bridge at all",
			bridge, bridge, err, bridge, bridge, revertSharedSetup(bridgeConn, tapConn))
	}
	var expected []string
	if tapIsAttached {
		expected = []string{tap}
	}
	unexpected := unexpectedBridgePorts(parseBridgePorts(out), expected)
	if len(unexpected) == 0 {
		return nil
	}
	// The message names every unexpected port and not the first one: a host
	// with two NICs on this bridge used to be told about one of them, and the
	// user who cleared that one was refused again on the next start naming
	// the second, with no hint there had been more. It also says what it
	// observed and no more than that -- a port list read out of the kernel --
	// because it observed no profile and used to claim one.
	expectation := fmt.Sprintf("this bridge is meant to have no ports at all at this point, since the tap %s is attached by a later step of this same start", tap)
	if tapIsAttached {
		expectation = fmt.Sprintf("the only port this bridge is meant to have is the tap %s", tap)
	}
	return fmt.Errorf("shared networking will not run over bridge %s: `ip -o link show master %s` reports %s on it, and %s. "+
		"That port list is all this start observed. It is the kernel's own answer about what is attached to the bridge; which profile attached it, or whether any profile did, was not looked at and is not claimed here. "+
		"The likely cause is a NetworkManager profile carrying `master %s slave-type bridge`: `nmcli -f NAME,DEVICE,TYPE connection show --active` lists the active ones, `nmcli -f connection.master connection show <name>` confirms which bridge one attaches to, and deleting or re-pointing it is the fix. "+
		"There may be no such profile to find. A bridge left behind by an earlier run keeps whatever is on it across a NetworkManager restart with nothing live holding it there, and then `sudo ip link delete %s` -- which removes the bridge and releases every port on it -- or `sudo ip link set dev <iface> nomaster` for one of them is what clears it. "+
		"Put an interface back with `sudo nmcli connection up <profile>` naming the profile you want, and only once the offending one is gone or re-pointed: `nmcli device connect <iface>` activates whichever profile NetworkManager rates best for that device, and after a bridged run that is routinely the bridge-slave profile it left behind, which attaches the interface to a bridge again. "+
		"%s. "+
		"Then start again, or use -network bridged, which attaches an interface to its bridge on purpose",
		bridge, bridge, quoteNames(unexpected), expectation, bridge, bridge, revertSharedSetup(bridgeConn, tapConn))
}

// revertSharedSetup undoes what prepareLinuxSharedWithNM has already done to
// this host, and returns a sentence saying what it attempted and what of that
// failed. Both refusals above call it before returning their error.
//
// Deactivating is not reverting. By the time any of those checks runs,
// `nmcli connection modify <bridge> ... ipv4.method shared` has returned and
// NetworkManager has written that to a keyfile, so a refusal that only took
// the connection down would walk away leaving a persisted NAT-bridge profile
// behind -- and a refusal fires precisely when something else is attaching an
// interface to that bridge, ordinarily a profile with autoconnect on. The
// next time that interface comes up, NetworkManager activates its controller,
// and the interface lands on a bridge running a DHCP server, IPv4 forwarding
// and a MASQUERADE rule, with no VM anywhere near it. A refusal has to leave
// the host no more dangerous than it found it.
//
// The down comes first, even though deleting a connection deactivates it too,
// because it is the step that releases the interface and it is worth having
// happened even when the delete after it fails.
//
// The deletes are unconditional rather than gated on nmConnectionExists.
// Both connections were modified successfully a few lines above, which is how
// this knows they are there -- a better answer than a probe that reports
// "does not exist" for any nmcli exit it dislikes. Deleting is more than
// restoring, for a bridge connection that predates this start: what its
// settings were is recorded nowhere, and what this start overwrote cannot be
// put back. What goes is a profile named after the bridge in state.json,
// which is the same profile every teardown in this file deletes.
func revertSharedSetup(bridgeConn, tapConn string) string {
	notes := make([]string, 0, 4)
	if err := sudo("nmcli", "connection", "down", bridgeConn); err != nil {
		notes = append(notes, fmt.Sprintf("taking connection %s down failed (%v), which is what a bridge this start never activated does; if it was up, it may be up still", bridgeConn, err))
	} else {
		notes = append(notes, fmt.Sprintf("connection %s was taken down, which should release what it had attached", bridgeConn))
	}
	var deleted, failed []string
	bridgeDeleted := false
	for _, conn := range []string{tapConn, bridgeConn} {
		if err := sudo("nmcli", "connection", "delete", conn); err != nil {
			failed = append(failed, fmt.Sprintf("%s (%v)", conn, err))
			continue
		}
		deleted = append(deleted, conn)
		if conn == bridgeConn {
			bridgeDeleted = true
		}
	}
	if len(deleted) > 0 {
		notes = append(notes, fmt.Sprintf("the connections this start had written were deleted (%s)", strings.Join(deleted, ", ")))
	}
	if len(failed) > 0 {
		notes = append(notes, fmt.Sprintf("deleting %s failed", strings.Join(failed, ", ")))
	}
	if bridgeDeleted {
		notes = append(notes, fmt.Sprintf("so the ipv4.method shared this start had written to %s is off this host again", bridgeConn))
	} else {
		notes = append(notes, fmt.Sprintf("so the ipv4.method shared this start had written to %s is still on this host, and `sudo nmcli connection delete %s` is what removes it", bridgeConn, bridgeConn))
	}
	return strings.Join(notes, "; ")
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
	if err := cleanupNMConnections(bridgeConn, st.Network.TapName); err != nil {
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
	return cleanupNMConnections(bridge, st.Network.TapName)
}

// cleanupNMConnections tears down the bridge, the tap and the NetworkManager
// connections that go with them, and returns every step that failed, joined.
//
// It used to print each failure with fmt.Printf and return nil. That made a
// PARTIAL teardown indistinguishable from a complete one to every caller: the
// only non-nil return was the refusal below, so `reset` printed "reset
// complete" over a host that still had the bridge, the tap and their
// connections on it. The printing was the second half of the same problem --
// fmt.Printf writes to process stdout, past the io.Writer the app layer
// threads through reset and cleanup, so those warnings were invisible to the
// app layer and to every test at that level.
//
// Collecting does not mean stopping. Every step below is REACHED whatever the
// ones before it did: one connection that will not delete must not strand the
// tap, the bridge and the reconnect behind it. Reached is not the same as
// issued, and no caller may say it is: the two `ip link delete`s run only for
// an interface linkExists can see, and the reconnect only for an interface
// findBridgeSlave found on the bridge, so a teardown can reach every step and
// issue one command.
func cleanupNMConnections(bridgeConn, tapName string) error {
	// Every destructive command below is built from these two names, which
	// come out of state.json -- a 0644 file any process running as the user
	// can write. linuxNetworkPreflight validates them before a start, but
	// reset and cleanup reach here without passing through the preflight, so
	// the same check has to sit at the choke point too. Without it a stored
	// name of "eth0" turns into `sudo nmcli connection delete eth0` and
	// `sudo ip link delete eth0`, and the host loses its network. The tap name
	// is checked for exactly the same reason as the bridge name: it is the
	// argument of an `ip link delete` below.
	if err := validateStoredInterfaceName("bridge name", bridgeConn); err != nil {
		return fmt.Errorf("refusing to clean up network resources: %w", err)
	}
	tap := tapName
	if tap == "" {
		tap = DefaultTapName
	}
	if err := validateStoredInterfaceName("tap name", tap); err != nil {
		return fmt.Errorf("refusing to clean up network resources: %w", err)
	}
	uplinkConn := bridgeConn + "-uplink"
	tapConn := bridgeConn + "-tap"

	// Find the physical interface enslaved to the bridge before we delete
	// anything. The tap is a port of this bridge too and must not be mistaken
	// for it, which is why the name is passed down; see parseBridgeSlave.
	var uplinkIface string
	if IsLinuxBridge(bridgeConn) {
		uplinkIface = findBridgeSlave(bridgeConn, tap)
	}

	var failures []error

	// Delete all NM connections - use sudo (not sudoQuiet) so user can see
	// what's happening and errors are visible
	for _, conn := range []string{tapConn, uplinkConn, bridgeConn} {
		if nmConnectionExists(conn) {
			if err := sudo("nmcli", "connection", "delete", conn); err != nil {
				failures = append(failures, fmt.Errorf("delete connection %s: %w", conn, err))
			}
		}
	}

	// Now clean up any lingering interfaces that NM didn't remove
	if linkExists(tap) {
		if err := sudo("ip", "link", "delete", tap); err != nil {
			failures = append(failures, fmt.Errorf("delete interface %s: %w", tap, err))
		}
	}
	if linkExists(bridgeConn) {
		if err := sudo("ip", "link", "delete", bridgeConn); err != nil {
			failures = append(failures, fmt.Errorf("delete interface %s: %w", bridgeConn, err))
		}
	}

	// Reconnect the physical interface (NM connections are gone, so this
	// will use a fresh/default connection, not the bridge slave profile)
	if uplinkIface != "" {
		fmt.Printf("Reconnecting %s...\n", uplinkIface)
		if err := sudo("nmcli", "device", "connect", uplinkIface); err != nil {
			failures = append(failures, fmt.Errorf("reconnect %s: %w", uplinkIface, err))
		}
	}

	// nil when failures is empty, which is the whole point: a teardown that
	// did everything asked of it still reports success.
	return errors.Join(failures...)
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

// bridgeSlaveLinks returns the output of `ip -o link show master <bridge>`,
// one line per interface attached to that bridge, and whatever the command
// failed with.
//
// The error IS the signature's point. This used to answer "" for any failure,
// which made "the bridge has no ports" and "this host cannot answer the
// question" the same value -- and to refuseForeignBridgePort the first of
// those means PROCEED. The second one is permanent on a host whose `ip` is
// busybox's, which has no `show master` filter and exits 2 with `either "dev"
// is duplicate, or "br0" is garbage`; on an iproute2 older than the filter;
// and on a host with no `ip` on PATH. So that shape left the invariant
// unenforced for good on every such machine, while the port list was the only
// thing left enforcing it. Each caller now decides for itself: the assertion
// refuses on the error, the teardown carries on past it.
//
// This is the swappable seam, and it sits one level BELOW findBridgeSlave,
// which used to be the var itself. Replacing the whole function also replaced
// the part that decides WHICH interface gets reconnected, so the filter in it
// was never executed by a test: deleting that filter left the entire suite
// green. With only the exec replaced, every test that reaches a teardown runs
// the real parse and the real filter over output the fake supplies.
var bridgeSlaveLinks = func(bridge string) (string, error) {
	out, err := exec.Command("ip", "-o", "link", "show", "master", bridge).Output()
	if err != nil {
		// What `ip` printed is what tells "no such device" from "unknown
		// option" from "operation not permitted", and the refusal built on
		// this error asks the user to tell exactly those apart. %q because
		// these are another program's bytes on their way to a terminal.
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
			return "", fmt.Errorf("%w: %q", err, firstLine(string(exitErr.Stderr), maxProbeStderrLen))
		}
		return "", err
	}
	return string(out), nil
}

// maxProbeStderrLen caps how much of a failing probe's stderr is quoted into
// an error. One line of `ip` diagnostics is what is wanted out of it; the
// rest of the message has to stay readable beside it.
const maxProbeStderrLen = 200

// findBridgeSlave finds the physical interface enslaved to the given bridge,
// or "" when it has none. tap is the tap device in play; it is a port of this
// same bridge and is never the answer. The choosing is parseBridgeSlave's, in
// network_shared_parse.go, where it can be tested on any host.
//
// A probe that failed answers "" here, and that tolerance is deliberate:
// cleanupNMConnections is this function's only caller, and what it wants is a
// reconnect hint, not a security control. The cost of a wrong "" there is one
// `nmcli device connect` not issued at the end of a teardown that has already
// deleted the connections and the links, where a teardown that refused to run
// because `ip` could not answer would instead leave the bridge, the tap and
// their profiles standing. The check that must not fail open calls
// bridgeSlaveLinks itself and refuses on the error; see
// refuseForeignBridgePort.
func findBridgeSlave(bridge, tap string) string {
	out, err := bridgeSlaveLinks(bridge)
	if err != nil {
		return ""
	}
	return parseBridgeSlave(out, tap)
}

// sudo, bridgeSlaveLinks above it and the host probes further down this file
// are package-level vars rather than plain functions so network_linux_test.go
// can swap them for in-process fakes and assert the exact argv sequence these
// paths hand to root. Each is one exec call, its result and, in
// bridgeSlaveLinks, the wording of the error that call failed with -- no
// branch any caller depends on. So what a fake replaces is the subprocess and
// never a decision: findBridgeSlave, which decides which interface a teardown
// reconnects, is a plain function for that reason, and so is
// refuseForeignBridgePort, which decides what the port list means. Nothing in
// production assigns these; the tests restore the originals with t.Cleanup.
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

// IsLinuxBridge is a function and not a var so that it is the same kind of
// identifier as the !linux IsLinuxBridge in network_stub.go. When this was an
// exported var, `vm.IsLinuxBridge = f` compiled on Linux and failed to compile
// on darwin, which is a GOOS-specific break waiting for the first caller
// outside this package to write it. The swappable seam the tests need stays,
// one level down and unexported.
func IsLinuxBridge(name string) bool {
	return isLinuxBridge(name)
}

var isLinuxBridge = func(name string) bool {
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
