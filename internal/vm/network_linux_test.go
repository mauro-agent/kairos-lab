// Tests for the host-networking paths in network_linux.go.
//
// There is deliberately no build tag here. network_linux.go carries none
// either: it compiles only on Linux by virtue of its _linux.go filename, and
// this file's name gives it the identical constraint. So these tests run on
// the ubuntu CI leg and are absent from the macOS one, which is what we want
// -- every symbol they touch exists only on Linux, and the darwin build of
// the package would not compile them.
//
// Almost nothing here goes near the host. sudo, findBridgeSlave and the host
// probes beside them are package-level vars (see the comment above sudo);
// newFakeHost swaps them for an in-process fake that records the argv of
// every command the code would have handed to root, and restores the
// originals with t.Cleanup so no test can leak its fake into another.
//
// "Almost", because one test is a deliberate exception:
// TestTapOwnerUIDHonoursSudoUserFirst runs a real
// `id -u kairoslab-no-such-user` through uidForUser. Faking the resolver
// there would gut the test, whose entire claim is that an unresolvable
// SUDO_USER is an error and not a silent fall back to the current uid, which
// under sudo is root's -- only the real resolver can establish that. The
// subprocess is read-only, changes nothing on the host, and fails the same
// way everywhere, since the account it asks about is one no host has. No
// other test in this file starts a process.
package vm

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/kairos-io/kairos-lab/internal/state"
)

// fakeHost is a host with no NetworkManager, no interfaces and no root. It
// answers the probes from its own maps and applies each recorded command back
// onto them, so a probe made after a command sees what that command did
// rather than a frozen snapshot.
type fakeHost struct {
	conns   map[string]bool
	links   map[string]bool
	bridges map[string]bool
	// slaves is what findBridgeSlave reports for a bridge: the first physical
	// interface enslaved to it, or "" when there is none. A missing key is
	// the shared-mode shape -- that bridge's only port is the tap, and
	// findBridgeSlave skips tap interfaces, so it answers "" for it.
	slaves   map[string]string
	commands [][]string
}

func newFakeHost(t *testing.T) *fakeHost {
	t.Helper()
	h := &fakeHost{
		conns:   map[string]bool{},
		links:   map[string]bool{},
		bridges: map[string]bool{},
		slaves:  map[string]string{},
	}

	origSudo := sudo
	origNMActive := networkManagerActive
	origNmcli := nmcliAvailable
	origConnExists := nmConnectionExists
	origIsBridge := isLinuxBridge
	origLinkExists := linkExists
	origFindSlave := findBridgeSlave
	origDelay := staleCleanupSettleDelay
	t.Cleanup(func() {
		sudo = origSudo
		networkManagerActive = origNMActive
		nmcliAvailable = origNmcli
		nmConnectionExists = origConnExists
		isLinuxBridge = origIsBridge
		linkExists = origLinkExists
		findBridgeSlave = origFindSlave
		staleCleanupSettleDelay = origDelay
	})

	sudo = h.run
	networkManagerActive = func() bool { return true }
	nmcliAvailable = func() bool { return true }
	nmConnectionExists = func(name string) bool { return name != "" && h.conns[name] }
	isLinuxBridge = func(name string) bool { return name != "" && h.bridges[name] }
	linkExists = func(name string) bool { return name != "" && (h.links[name] || h.bridges[name]) }
	findBridgeSlave = func(bridge string) string { return h.slaves[bridge] }
	staleCleanupSettleDelay = 0

	// Both variables empty keeps tapOwnerUID on its os.Getuid() branch, so the
	// uid in the expected argv is known and no subprocess runs.
	t.Setenv("SUDO_USER", "")
	t.Setenv("USER", "")
	return h
}

func (h *fakeHost) run(name string, args ...string) error {
	argv := append([]string{name}, args...)
	h.commands = append(h.commands, argv)
	h.apply(argv)
	return nil
}

func (h *fakeHost) apply(argv []string) {
	if len(argv) < 4 {
		return
	}
	switch {
	case argv[0] == "nmcli" && argv[1] == "connection" && argv[2] == "delete":
		delete(h.conns, argv[3])
	case argv[0] == "ip" && argv[1] == "link" && argv[2] == "delete":
		delete(h.links, argv[3])
		delete(h.bridges, argv[3])
	case argv[0] == "nmcli" && argv[1] == "connection" && argv[2] == "add":
		if conn := valueAfter(argv, "con-name"); conn != "" {
			h.conns[conn] = true
		}
		if ifname := valueAfter(argv, "ifname"); ifname != "" {
			h.links[ifname] = true
			if valueAfter(argv, "type") == "bridge" {
				h.bridges[ifname] = true
			}
		}
	}
}

// lines renders the recorded commands one per line, in order, so a whole
// sequence can be pinned as data instead of as a chain of assertions.
func (h *fakeHost) lines() []string {
	out := make([]string, 0, len(h.commands))
	for _, argv := range h.commands {
		out = append(out, strings.Join(argv, " "))
	}
	return out
}

func valueAfter(argv []string, key string) string {
	for i, a := range argv {
		if a == key && i+1 < len(argv) {
			return argv[i+1]
		}
	}
	return ""
}

func assertSequence(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("issued %d commands, want %d:\n got:\n  %s\nwant:\n  %s",
			len(got), len(want), strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("command %d differs:\n got: %s\nwant: %s", i, got[i], want[i])
		}
	}
}

func testUID(t *testing.T) string {
	t.Helper()
	return strconv.Itoa(os.Getuid())
}

// sharedSequence is the argv sequence --network shared produces on a host
// with nothing of ours on it. It is spelled out rather than generated: the
// point of pinning it is that a change to the real sequence has to be
// retyped here by whoever makes it.
func sharedSequence(uid string) []string {
	return []string{
		"nmcli connection add type bridge ifname kairoslab0 con-name kairoslab0 autoconnect no stp no",
		"nmcli connection modify kairoslab0 connection.interface-name kairoslab0 ipv4.method shared ipv6.method ignore bridge.stp no connection.autoconnect no",
		"nmcli connection add type tun ifname kairoslab-tap0 con-name kairoslab0-tap mode tap owner " + uid + " master kairoslab0 slave-type bridge autoconnect no",
		"nmcli connection modify kairoslab0-tap connection.interface-name kairoslab-tap0 tun.mode tap tun.owner " + uid + " master kairoslab0 slave-type bridge connection.autoconnect no",
		"nmcli connection up kairoslab0",
		"nmcli connection up kairoslab0-tap",
	}
}

// bridgedSequence is the same for --network bridged over eth0. It is pinned
// so the shared work cannot quietly alter shipped behaviour: every line here
// predates it.
func bridgedSequence(uid string) []string {
	return []string{
		"nmcli connection add type bridge ifname kairoslab0 con-name kairoslab0 autoconnect yes stp no",
		"nmcli connection modify kairoslab0 connection.interface-name kairoslab0 ipv4.method auto ipv6.method auto bridge.stp no connection.autoconnect yes",
		"nmcli connection add type ethernet ifname eth0 con-name kairoslab0-uplink master kairoslab0 slave-type bridge autoconnect yes",
		"nmcli connection modify kairoslab0-uplink connection.interface-name eth0 master kairoslab0 slave-type bridge connection.autoconnect yes",
		"nmcli connection add type tun ifname kairoslab-tap0 con-name kairoslab0-tap mode tap owner " + uid + " master kairoslab0 slave-type bridge autoconnect yes",
		"nmcli connection modify kairoslab0-tap connection.interface-name kairoslab-tap0 tun.mode tap tun.owner " + uid + " master kairoslab0 slave-type bridge connection.autoconnect yes",
		"nmcli connection up kairoslab0",
		"nmcli connection up kairoslab0-uplink",
		"nmcli connection up kairoslab0-tap",
	}
}

func TestPrepareLinuxSharedCleanHostSequence(t *testing.T) {
	h := newFakeHost(t)
	st := &state.State{}

	if err := PrepareLinuxShared(st, t.TempDir()); err != nil {
		t.Fatalf("PrepareLinuxShared: %v", err)
	}

	assertSequence(t, h.lines(), sharedSequence(testUID(t)))

	// The mode's defining property, asserted separately from the sequence so
	// it survives a rewrite of the expected lines: nothing in shared mode
	// ever names an uplink connection, because nothing enslaves a host NIC.
	for _, line := range h.lines() {
		if strings.Contains(line, "-uplink") {
			t.Errorf("shared path names an uplink connection: %s", line)
		}
	}
}

// Regression test for the orphaned <bridge>-uplink connection.
//
// cleanupNMConnections prints a warning and carries on when a delete fails,
// and its caller discards the result, so a host can be left with the bridge
// connection gone and <bridge>-uplink still present. The preflight used to
// ask only about the bridge link and the bridge connection, so it saw that
// host as clean -- and the orphan, which carries master/slave-type bridge and
// autoconnect, would have enslaved the physical NIC to the NAT bridge the
// shared path then brought up.
func TestPrepareLinuxSharedDeletesOrphanedUplinkConnection(t *testing.T) {
	h := newFakeHost(t)
	h.conns[DefaultBridgeName+"-uplink"] = true
	st := &state.State{}

	if err := PrepareLinuxShared(st, t.TempDir()); err != nil {
		t.Fatalf("PrepareLinuxShared: %v", err)
	}

	want := append([]string{"nmcli connection delete kairoslab0-uplink"}, sharedSequence(testUID(t))...)
	assertSequence(t, h.lines(), want)

	if h.conns[DefaultBridgeName+"-uplink"] {
		t.Errorf("the orphaned uplink connection is still on the host after PrepareLinuxShared")
	}
}

func TestPrepareLinuxSharedRecordsState(t *testing.T) {
	newFakeHost(t)
	st := &state.State{}
	// An earlier bridged run left an uplink in state; shared has none.
	st.Network.BridgeInterface = "eth0"

	if err := PrepareLinuxShared(st, t.TempDir()); err != nil {
		t.Fatalf("PrepareLinuxShared: %v", err)
	}

	if st.Network.Mode != "shared" {
		t.Errorf("Mode = %q, want %q", st.Network.Mode, "shared")
	}
	if st.Network.BridgeInterface != "" {
		t.Errorf("BridgeInterface = %q, want it cleared: shared enslaves no uplink", st.Network.BridgeInterface)
	}
	want := sharedLeaseFilePath(DefaultBridgeName)
	if st.Network.DHCPLeaseFile != want {
		t.Errorf("DHCPLeaseFile = %q, want %q", st.Network.DHCPLeaseFile, want)
	}
	if !strings.Contains(st.Network.DHCPLeaseFile, DefaultBridgeName) {
		t.Errorf("DHCPLeaseFile %q does not name the bridge that carries ipv4.method shared", st.Network.DHCPLeaseFile)
	}
	if st.Network.BridgeName != DefaultBridgeName || st.Network.TapName != DefaultTapName {
		t.Errorf("BridgeName/TapName = %q/%q, want %q/%q",
			st.Network.BridgeName, st.Network.TapName, DefaultBridgeName, DefaultTapName)
	}
	if !st.Network.CleanupRequired || !st.Network.CreatedByKairosLab {
		t.Errorf("CleanupRequired=%v CreatedByKairosLab=%v, want both true",
			st.Network.CleanupRequired, st.Network.CreatedByKairosLab)
	}
}

func TestPrepareLinuxBridgeSequence(t *testing.T) {
	h := newFakeHost(t)
	h.links["eth0"] = true
	st := &state.State{}
	st.Network.BridgeInterface = "eth0" // skips detectDefaultUplink, which shells out

	if err := PrepareLinuxBridge(st, t.TempDir()); err != nil {
		t.Fatalf("PrepareLinuxBridge: %v", err)
	}

	assertSequence(t, h.lines(), bridgedSequence(testUID(t)))

	if st.Network.Mode != "bridged" {
		t.Errorf("Mode = %q, want %q", st.Network.Mode, "bridged")
	}
	if st.Network.BridgeInterface != "eth0" {
		t.Errorf("BridgeInterface = %q, want %q", st.Network.BridgeInterface, "eth0")
	}
}

// Regression test for a shared-mode lease path surviving into bridged state.
//
// `start --network shared` then `start --network bridged` runs no cleanup in
// between, so PrepareLinuxBridge inherits whatever the shared run wrote. The
// only writer of DHCPLeaseFile is the shared path, so a bridged run that
// merely does not write the field leaves the previous run's value in place,
// and the reader of that field reports a previous guest's address.
func TestPrepareLinuxBridgeClearsDHCPLeaseFile(t *testing.T) {
	h := newFakeHost(t)
	h.links["eth0"] = true
	st := &state.State{}
	st.Network.BridgeInterface = "eth0"
	st.Network.Mode = "shared"
	st.Network.DHCPLeaseFile = sharedLeaseFilePath(DefaultBridgeName)
	if st.Network.DHCPLeaseFile == "" {
		t.Fatal("fixture is empty, the test would pass for the wrong reason")
	}

	if err := PrepareLinuxBridge(st, t.TempDir()); err != nil {
		t.Fatalf("PrepareLinuxBridge: %v", err)
	}

	if st.Network.DHCPLeaseFile != "" {
		t.Errorf("DHCPLeaseFile = %q after a bridged run, want it cleared: there is no NetworkManager DHCP server in bridged mode",
			st.Network.DHCPLeaseFile)
	}
}

// Regression test for an unvalidated interface name from state.json reaching
// a root-run command.
//
// The half that matters is that NOTHING is issued. The stale-cleanup block in
// the preflight hands the stored name straight to `nmcli connection delete`
// and `ip link delete`, so a name that gets as far as that block is already a
// deleted host network -- which is why the validator is placed ahead of it
// rather than anywhere else in the preflight. Each case seeds the fake host
// with the malformed name PRESENT as a connection and a link, so a validator
// that were removed, or moved back below the stale block, would leave the
// preflight finding it "stale" and deleting it.
func TestPrepareLinuxSharedRejectsStoredNamesBeforeIssuingAnything(t *testing.T) {
	tests := []struct {
		name   string
		bridge string
		tap    string
	}{
		{"bridge name is a NetworkManager profile", attackNMProfileName, ""},
		{"bridge name walks out of NMSTATEDIR", attackPathTraversal, ""},
		{"bridge name forges a plan row", attackPlanRowInjection, ""},
		{"tap name is a NetworkManager profile", "", attackNMProfileName},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newFakeHost(t)
			st := &state.State{}
			st.Network.BridgeName = tt.bridge
			st.Network.TapName = tt.tap
			for _, name := range []string{tt.bridge, tt.tap} {
				if name == "" {
					continue
				}
				h.conns[name] = true
				h.links[name] = true
				h.bridges[name] = true
			}

			err := PrepareLinuxShared(st, t.TempDir())
			if err == nil {
				t.Fatalf("PrepareLinuxShared accepted a malformed stored name")
			}
			if len(h.commands) != 0 {
				t.Errorf("rejected input still reached root:\n  %s", strings.Join(h.lines(), "\n  "))
			}
			if !strings.Contains(err.Error(), "stored configuration") {
				t.Errorf("error %q does not say where the value came from", err)
			}
			if st.Network.Mode != "" || st.Network.DHCPLeaseFile != "" {
				t.Errorf("state was written despite the error: Mode=%q DHCPLeaseFile=%q",
					st.Network.Mode, st.Network.DHCPLeaseFile)
			}
		})
	}
}

// Shared mode's connections must not come up on their own. A bridge carrying
// ipv4.method shared runs a DHCP server and a DNS forwarder and installs a
// MASQUERADE rule, and NetworkManager persists these connections as keyfiles:
// with autoconnect on, one `--network shared` run would put all of that on
// every subsequent boot. kairos-lab activates both explicitly on each start,
// so a start still works; what is given up is re-activation after a
// NetworkManager restart, which leaves a running guest's network down until
// the next start. See prepareLinuxSharedWithNM for the trade in full.
// Bridged is shipped behaviour and keeps autoconnect yes.
func TestSharedDisablesAutoconnectAndBridgedKeepsIt(t *testing.T) {
	t.Run("shared", func(t *testing.T) {
		h := newFakeHost(t)
		if err := PrepareLinuxShared(&state.State{}, t.TempDir()); err != nil {
			t.Fatalf("PrepareLinuxShared: %v", err)
		}
		assertAutoconnect(t, h, "no")
	})
	t.Run("bridged", func(t *testing.T) {
		h := newFakeHost(t)
		h.links["eth0"] = true
		st := &state.State{}
		st.Network.BridgeInterface = "eth0"
		if err := PrepareLinuxBridge(st, t.TempDir()); err != nil {
			t.Fatalf("PrepareLinuxBridge: %v", err)
		}
		assertAutoconnect(t, h, "yes")
	})
}

// assertAutoconnect checks that every connection built in the recorded
// sequence sets autoconnect to want, on both the add and the modify.
func assertAutoconnect(t *testing.T, h *fakeHost, want string) {
	t.Helper()
	seen := 0
	for _, argv := range h.commands {
		for _, key := range []string{"autoconnect", "connection.autoconnect"} {
			v := valueAfter(argv, key)
			if v == "" {
				continue
			}
			seen++
			if v != want {
				t.Errorf("%s = %q, want %q in: %s", key, v, want, strings.Join(argv, " "))
			}
		}
	}
	if seen < 4 {
		t.Errorf("found %d autoconnect settings, want at least 4 (an add and a modify, for the bridge and for the tap)", seen)
	}
}

// The preflight and HasStaleNetworkResources must agree about what stale
// means: the preflight seeing less than the reporter is how a resource gets
// left on the host by a run that said it cleaned up.
func TestStalenessPredicateCoversEveryResource(t *testing.T) {
	tests := []struct {
		name string
		seed func(*fakeHost)
	}{
		{"bridge link", func(h *fakeHost) { h.bridges[DefaultBridgeName] = true }},
		{"bridge connection", func(h *fakeHost) { h.conns[DefaultBridgeName] = true }},
		{"uplink connection", func(h *fakeHost) { h.conns[DefaultBridgeName+"-uplink"] = true }},
		{"tap connection", func(h *fakeHost) { h.conns[DefaultBridgeName+"-tap"] = true }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newFakeHost(t)
			tt.seed(h)
			if !hasStaleBridgeResources(DefaultBridgeName) {
				t.Errorf("hasStaleBridgeResources missed a leftover %s", tt.name)
			}
			st := &state.State{}
			if !HasStaleNetworkResources(st) {
				t.Errorf("HasStaleNetworkResources missed a leftover %s", tt.name)
			}
		})
	}

	t.Run("clean host", func(t *testing.T) {
		newFakeHost(t)
		if hasStaleBridgeResources(DefaultBridgeName) {
			t.Error("hasStaleBridgeResources reports a clean host as stale")
		}
	})
}

// tapOwnerUID hands the tap to the user who will run QEMU. SUDO_USER is the
// reason the environment is consulted at all and stays first; everything else
// is os.Getuid(), because a guess is worse than the kernel's own answer -- the
// old chain fell through $USER to a literal "root" and handed the tap to uid 0
// under a systemd unit, cron or `env -i`, where neither variable is set.
func TestTapOwnerUIDFallsBackToTheRealUID(t *testing.T) {
	tests := []struct {
		name      string
		sudoUser  string
		user      string
		wantOwnUI bool
	}{
		{"neither variable set", "", "", true},
		{"only USER set, and it is someone else", "", "nobody", true},
		{"only USER set, and it is root", "", "root", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("SUDO_USER", tt.sudoUser)
			t.Setenv("USER", tt.user)
			got, err := tapOwnerUID()
			if err != nil {
				t.Fatalf("tapOwnerUID: %v", err)
			}
			if want := strconv.Itoa(os.Getuid()); got != want {
				t.Errorf("tapOwnerUID() = %q, want %q (the uid this process actually runs as)", got, want)
			}
		})
	}
}

// SUDO_USER still wins when it is set: an unresolvable one is an error, not a
// silent fall through to the current uid, which under sudo would be root.
func TestTapOwnerUIDHonoursSudoUserFirst(t *testing.T) {
	t.Setenv("SUDO_USER", "kairoslab-no-such-user")
	t.Setenv("USER", "")
	if got, err := tapOwnerUID(); err == nil {
		t.Errorf("tapOwnerUID() = %q, nil; want an error for an unresolvable SUDO_USER", got)
	}
}

// reset and cleanup reach cleanupNMConnections without passing through
// linuxNetworkPreflight, so the validator there does not protect them. The
// stored name lands in `sudo nmcli connection delete <name>` and
// `sudo ip link delete <name>`, which for a stored name of "eth0" on a distro
// that names profiles after devices takes out the host's own network. The
// guard has to sit at the choke point as well as at the entry point.
func TestCleanupNMConnectionsRefusesAMalformedStoredName(t *testing.T) {
	for _, bridge := range []string{
		attackNMProfileName,
		attackPathTraversal,
		attackPlanRowInjection,
		"",
	} {
		t.Run(fmt.Sprintf("%q", bridge), func(t *testing.T) {
			h := newFakeHost(t)
			// Make every resource look present, so the only thing standing
			// between the name and root is the validator.
			h.conns[bridge] = true
			h.conns[bridge+"-tap"] = true
			h.conns[bridge+"-uplink"] = true
			h.links[bridge] = true
			h.bridges[bridge] = true

			err := cleanupNMConnections(bridge)
			if err == nil {
				t.Fatalf("cleanupNMConnections accepted a malformed stored name")
			}
			if len(h.commands) != 0 {
				t.Errorf("rejected input still reached root:\n  %s", strings.Join(h.lines(), "\n  "))
			}
			if !strings.Contains(err.Error(), "refusing to clean up") {
				t.Errorf("error %q does not say it declined to act", err)
			}
		})
	}
}

// The guard must not block the ordinary case it sits in front of.
func TestCleanupNMConnectionsStillRemovesAValidBridge(t *testing.T) {
	h := newFakeHost(t)
	h.conns[DefaultBridgeName] = true
	h.conns[DefaultBridgeName+"-tap"] = true
	h.bridges[DefaultBridgeName] = true

	if err := cleanupNMConnections(DefaultBridgeName); err != nil {
		t.Fatalf("cleanupNMConnections(%q) = %v, want nil", DefaultBridgeName, err)
	}
	joined := strings.Join(h.lines(), "\n")
	for _, want := range []string{
		"nmcli connection delete " + DefaultBridgeName + "-tap",
		"nmcli connection delete " + DefaultBridgeName,
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in:\n%s", want, joined)
		}
	}
}

// The reconnect is the last thing a teardown does and the only command in it
// that puts the host back the way it was: deleting the bridge leaves whatever
// was enslaved to it with no active connection, and `nmcli device connect
// <iface>` is what gives that interface one again. Nothing covered it until
// findBridgeSlave became swappable, because reaching the branch at all meant
// running a real `ip -o link show master` against the test host.
//
// It must also not fire when there is nothing to put back. A shared-mode
// bridge has no physical slave -- its only port is the tap, which
// findBridgeSlave skips -- and reconnecting a device that was never enslaved
// is an unrequested change to the host's networking.
func TestCleanupNMConnectionsReconnectsAnEnslavedHostNIC(t *testing.T) {
	t.Run("bridge with a physical slave", func(t *testing.T) {
		h := newFakeHost(t)
		h.conns[DefaultBridgeName] = true
		h.conns[DefaultBridgeName+"-uplink"] = true
		h.bridges[DefaultBridgeName] = true
		h.slaves[DefaultBridgeName] = "eth0"

		if err := cleanupNMConnections(DefaultBridgeName); err != nil {
			t.Fatalf("cleanupNMConnections(%q) = %v, want nil", DefaultBridgeName, err)
		}
		assertSequence(t, h.lines(), []string{
			"nmcli connection delete kairoslab0-uplink",
			"nmcli connection delete kairoslab0",
			"ip link delete kairoslab0",
			// After the deletes, never before: the point of reconnecting is to
			// replace the slave profile that has just been removed.
			"nmcli device connect eth0",
		})
	})

	t.Run("bridge whose only slave is the tap", func(t *testing.T) {
		h := newFakeHost(t)
		h.conns[DefaultBridgeName] = true
		h.conns[DefaultBridgeName+"-tap"] = true
		h.bridges[DefaultBridgeName] = true
		h.links[DefaultTapName] = true
		// No h.slaves entry: findBridgeSlave skips tap interfaces, so a bridge
		// with only a tap on it reports no slave.

		if err := cleanupNMConnections(DefaultBridgeName); err != nil {
			t.Fatalf("cleanupNMConnections(%q) = %v, want nil", DefaultBridgeName, err)
		}
		assertSequence(t, h.lines(), []string{
			"nmcli connection delete kairoslab0-tap",
			"nmcli connection delete kairoslab0",
			"ip link delete kairoslab-tap0",
			"ip link delete kairoslab0",
		})
		for _, line := range h.lines() {
			if strings.Contains(line, "device connect") {
				t.Errorf("reconnected a device that was never enslaved: %s", line)
			}
		}
	})
}
