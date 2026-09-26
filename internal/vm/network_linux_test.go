// Tests for the host-networking paths in network_linux.go.
//
// There is deliberately no build tag here. network_linux.go carries none
// either: it compiles only on Linux by virtue of its _linux.go filename, and
// this file's name gives it the identical constraint. So these tests run on
// the ubuntu CI leg and are absent from the macOS one, which is what we want
// -- every symbol they touch exists only on Linux, and the darwin build of
// the package would not compile them.
//
// Almost nothing here goes near the host. sudo, bridgeSlaveLinks and the host
// probes beside them are package-level vars (see the comment above sudo);
// newFakeHost swaps them for an in-process fake that records the argv of
// every command the code would have handed to root, and restores the
// originals with t.Cleanup so no test can leak its fake into another. What
// the fake replaces is only ever a subprocess: findBridgeSlave, which decides
// which interface a teardown reconnects, is a plain function and runs for
// real in every test that reaches it.
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
	// slaves lists the interfaces enslaved to a bridge, tap included. A
	// missing key is a bridge with no ports at all; the shared-mode shape is
	// the tap on its own, which findBridgeSlave must report as no slave.
	//
	// The list is in the order `ip -o link show master <bridge>` would print
	// it, and the fake renders real-looking output from it, so the parse and
	// the tap filter in findBridgeSlave run for real. Seeding the tap in the
	// list is the point: a bridge always has its tap on it, and a filter that
	// stopped working would return the tap here.
	slaves map[string][]string
	// failCmd, when set, decides which recorded commands fail. A failing
	// command is still recorded but is not applied to the host state, which
	// is how a partial teardown really behaves.
	failCmd  func(argv []string) error
	commands [][]string
}

func newFakeHost(t *testing.T) *fakeHost {
	t.Helper()
	h := &fakeHost{
		conns:   map[string]bool{},
		links:   map[string]bool{},
		bridges: map[string]bool{},
		slaves:  map[string][]string{},
	}

	origSudo := sudo
	origNMActive := networkManagerActive
	origNmcli := nmcliAvailable
	origConnExists := nmConnectionExists
	origIsBridge := isLinuxBridge
	origLinkExists := linkExists
	origSlaveLinks := bridgeSlaveLinks
	origDelay := staleCleanupSettleDelay
	t.Cleanup(func() {
		sudo = origSudo
		networkManagerActive = origNMActive
		nmcliAvailable = origNmcli
		nmConnectionExists = origConnExists
		isLinuxBridge = origIsBridge
		linkExists = origLinkExists
		bridgeSlaveLinks = origSlaveLinks
		staleCleanupSettleDelay = origDelay
	})

	sudo = h.run
	networkManagerActive = func() bool { return true }
	nmcliAvailable = func() bool { return true }
	nmConnectionExists = func(name string) bool { return name != "" && h.conns[name] }
	isLinuxBridge = func(name string) bool { return name != "" && h.bridges[name] }
	linkExists = func(name string) bool { return name != "" && (h.links[name] || h.bridges[name]) }
	bridgeSlaveLinks = h.slaveLinks
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
	if h.failCmd != nil {
		if err := h.failCmd(argv); err != nil {
			// Not applied: a command that failed changed nothing.
			return err
		}
	}
	h.apply(argv)
	return nil
}

// slaveLinks renders `ip -o link show master <bridge>` from the fake's own
// slave list, one line per enslaved interface, in the kernel's format.
func (h *fakeHost) slaveLinks(bridge string) string {
	var b strings.Builder
	for i, iface := range h.slaves[bridge] {
		b.WriteString(ipLinkLine(i+3, iface, bridge))
		b.WriteString("\n")
	}
	return b.String()
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
// cleanupNMConnections attempts every delete and reports the ones that failed
// rather than stopping at the first, so a host can be left with the bridge
// connection gone and <bridge>-uplink still present. The preflight used to
// ask only about the bridge link and the bridge connection, so it saw that
// host as clean -- and the orphan, which carries master/slave-type bridge and
// autoconnect, would have enslaved the physical NIC to the NAT bridge the
// shared path then brought up. Seeing it is half the fix; what happens when
// the delete that follows FAILS is the other half, one test below.
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

// The same orphan, this time one that will not go.
//
// Seeing a stale <bridge>-uplink connection and failing to delete it used to
// end the same way as seeing nothing at all: the preflight discarded the
// cleanup error, prepareLinuxSharedWithNM built the NAT bridge over the top
// and brought it up, and NetworkManager enslaved the host's physical NIC to a
// bridge carrying ipv4.method shared -- because that is what the orphan says
// to do. The run succeeded, the consent prompt above it had promised "no
// uplink interface is used", and the host lost its connectivity.
//
// So the delete failing is fatal for shared. Nothing may be issued after it,
// and the error has to name the leftover and a way out, since the user is the
// only one who can clear it.
func TestPrepareLinuxSharedRefusesWhenAStaleUplinkWillNotGo(t *testing.T) {
	h := newFakeHost(t)
	h.conns[DefaultBridgeName+"-uplink"] = true
	h.failCmd = func(argv []string) error {
		if strings.Join(argv, " ") == "nmcli connection delete kairoslab0-uplink" {
			return fmt.Errorf("exit status 1")
		}
		return nil
	}
	st := &state.State{}

	err := PrepareLinuxShared(st, t.TempDir())
	if err == nil {
		t.Fatal("PrepareLinuxShared built a NAT bridge over an uplink connection it could not delete")
	}

	// The refusal is the whole of the run: the failed delete is the last
	// thing issued, so no bridge was created, modified or brought up.
	assertSequence(t, h.lines(), []string{"nmcli connection delete kairoslab0-uplink"})
	if h.bridges[DefaultBridgeName] || h.links[DefaultTapName] {
		t.Errorf("the host was changed by a refused run: bridge=%v tap=%v",
			h.bridges[DefaultBridgeName], h.links[DefaultTapName])
	}

	// What is still on the host, and what to do about it. The wrapped error
	// from cleanupNMConnections names the step that failed; the rest is the
	// way out, which the user cannot work out from "exit status 1".
	for _, want := range []string{
		"delete connection kairoslab0-uplink",
		"nmcli connection delete kairoslab0-uplink",
		"-network bridged",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q:\n%v", want, err)
		}
	}

	if st.Network.Mode != "" || st.Network.BridgeName != "" || st.Network.CreatedByKairosLab {
		t.Errorf("state was written for a run that prepared nothing: %+v", st.Network)
	}
}

// The other half of that decision: bridged carries on over exactly the same
// failure, and must keep doing so.
//
// The orphan is a connection the bridged path creates itself, and it recreates
// and re-modifies it a few commands later -- so a delete that failed leaves it
// with a connection it is about to overwrite with the settings it wants,
// rather than with a NIC enslaved to a NAT bridge. Refusing here would turn a
// survivable leftover into a start the user cannot make without hand-editing
// NetworkManager.
func TestPrepareLinuxBridgeSurvivesAStaleUplinkThatWillNotGo(t *testing.T) {
	h := newFakeHost(t)
	h.links["eth0"] = true
	h.conns[DefaultBridgeName+"-uplink"] = true
	h.failCmd = func(argv []string) error {
		if strings.Join(argv, " ") == "nmcli connection delete kairoslab0-uplink" {
			return fmt.Errorf("exit status 1")
		}
		return nil
	}
	st := &state.State{}
	st.Network.BridgeInterface = "eth0"

	if err := PrepareLinuxBridge(st, t.TempDir()); err != nil {
		t.Fatalf("PrepareLinuxBridge refused a leftover it rebuilds itself: %v", err)
	}

	uid := testUID(t)
	// The bridged sequence, minus the `add` for the uplink connection: the
	// delete failed, so the connection is still there and only the modify
	// runs. That modify is the reason this is survivable -- it sets the
	// master, the slave type and the autoconnect this run wants.
	want := []string{
		"nmcli connection delete kairoslab0-uplink",
		"nmcli connection add type bridge ifname kairoslab0 con-name kairoslab0 autoconnect yes stp no",
		"nmcli connection modify kairoslab0 connection.interface-name kairoslab0 ipv4.method auto ipv6.method auto bridge.stp no connection.autoconnect yes",
		"nmcli connection modify kairoslab0-uplink connection.interface-name eth0 master kairoslab0 slave-type bridge connection.autoconnect yes",
		"nmcli connection add type tun ifname kairoslab-tap0 con-name kairoslab0-tap mode tap owner " + uid + " master kairoslab0 slave-type bridge autoconnect yes",
		"nmcli connection modify kairoslab0-tap connection.interface-name kairoslab-tap0 tun.mode tap tun.owner " + uid + " master kairoslab0 slave-type bridge connection.autoconnect yes",
		"nmcli connection up kairoslab0",
		"nmcli connection up kairoslab0-uplink",
		"nmcli connection up kairoslab0-tap",
	}
	assertSequence(t, h.lines(), want)
	if st.Network.Mode != "bridged" {
		t.Errorf("Mode = %q, want %q", st.Network.Mode, "bridged")
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

			err := cleanupNMConnections(bridge, DefaultTapName)
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

	if err := cleanupNMConnections(DefaultBridgeName, DefaultTapName); err != nil {
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
// <iface>` is what gives that interface one again.
//
// The tap is seeded as a slave in every case here, because it always is one:
// the fake renders real `ip -o link show master` output and findBridgeSlave
// parses it for real, so whether the tap or the host NIC comes back is
// decided by the filter under test and not by the fake.
//
// The reconnect must also not fire when there is nothing to put back. A
// shared-mode bridge has no physical slave -- its only port is the tap -- and
// reconnecting a device that was never enslaved is an unrequested change to
// the host's networking.
func TestCleanupNMConnectionsReconnectsAnEnslavedHostNIC(t *testing.T) {
	t.Run("bridge with a physical slave", func(t *testing.T) {
		h := newFakeHost(t)
		h.conns[DefaultBridgeName] = true
		h.conns[DefaultBridgeName+"-uplink"] = true
		h.bridges[DefaultBridgeName] = true
		// The tap is listed first, as the kernel would list it, so returning
		// the first line instead of the first non-tap line is visible here.
		h.slaves[DefaultBridgeName] = []string{DefaultTapName, "eth0"}

		if err := cleanupNMConnections(DefaultBridgeName, DefaultTapName); err != nil {
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
		h.slaves[DefaultBridgeName] = []string{DefaultTapName}

		if err := cleanupNMConnections(DefaultBridgeName, DefaultTapName); err != nil {
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

	// The substring filter this replaced skipped any interface whose name
	// merely contained "tap", so a host NIC called "captap0" was left with no
	// active connection after a teardown and nothing said so.
	t.Run("host NIC whose name contains tap", func(t *testing.T) {
		h := newFakeHost(t)
		h.conns[DefaultBridgeName] = true
		h.bridges[DefaultBridgeName] = true
		h.slaves[DefaultBridgeName] = []string{DefaultTapName, "captap0"}

		if err := cleanupNMConnections(DefaultBridgeName, DefaultTapName); err != nil {
			t.Fatalf("cleanupNMConnections(%q) = %v, want nil", DefaultBridgeName, err)
		}
		assertSequence(t, h.lines(), []string{
			"nmcli connection delete kairoslab0",
			"ip link delete kairoslab0",
			"nmcli device connect captap0",
		})
	})
}

// A teardown that could not finish must say so. cleanupNMConnections used to
// print each failure with fmt.Printf and return nil, so the only non-nil
// return was the refusal above: `reset` printed "reset complete" over a host
// that still had every one of these resources on it, and the warnings went to
// process stdout where the app layer's own writer could not see them.
func TestCleanupNMConnectionsReportsEveryFailure(t *testing.T) {
	t.Run("every step fails", func(t *testing.T) {
		h := newFakeHost(t)
		h.conns[DefaultBridgeName] = true
		h.conns[DefaultBridgeName+"-tap"] = true
		h.conns[DefaultBridgeName+"-uplink"] = true
		h.bridges[DefaultBridgeName] = true
		h.links[DefaultTapName] = true
		h.slaves[DefaultBridgeName] = []string{DefaultTapName, "eth0"}
		h.failCmd = func([]string) error { return fmt.Errorf("exit status 1") }

		err := cleanupNMConnections(DefaultBridgeName, DefaultTapName)
		if err == nil {
			t.Fatal("cleanupNMConnections reported success after every step failed")
		}

		// Collecting is not stopping: one resource that will not go must not
		// strand the ones behind it.
		assertSequence(t, h.lines(), []string{
			"nmcli connection delete kairoslab0-tap",
			"nmcli connection delete kairoslab0-uplink",
			"nmcli connection delete kairoslab0",
			"ip link delete kairoslab-tap0",
			"ip link delete kairoslab0",
			"nmcli device connect eth0",
		})

		// And every failure is named, since this error is what the app layer
		// prints in place of "reset complete".
		for _, want := range []string{
			"delete connection kairoslab0-tap",
			"delete connection kairoslab0-uplink",
			"delete connection kairoslab0",
			"delete interface kairoslab-tap0",
			"delete interface kairoslab0",
			"reconnect eth0",
		} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error does not mention %q:\n%v", want, err)
			}
		}
	})

	t.Run("one step fails", func(t *testing.T) {
		h := newFakeHost(t)
		h.conns[DefaultBridgeName] = true
		h.conns[DefaultBridgeName+"-tap"] = true
		h.bridges[DefaultBridgeName] = true
		h.links[DefaultTapName] = true
		h.failCmd = func(argv []string) error {
			if strings.Join(argv, " ") == "nmcli connection delete kairoslab0-tap" {
				return fmt.Errorf("exit status 1")
			}
			return nil
		}

		err := cleanupNMConnections(DefaultBridgeName, DefaultTapName)
		if err == nil {
			t.Fatal("a partial teardown reported success")
		}
		if !strings.Contains(err.Error(), "delete connection kairoslab0-tap") {
			t.Errorf("error does not name the step that failed:\n%v", err)
		}
		if strings.Contains(err.Error(), "delete interface kairoslab0") {
			t.Errorf("error names a step that succeeded:\n%v", err)
		}
		assertSequence(t, h.lines(), []string{
			"nmcli connection delete kairoslab0-tap",
			"nmcli connection delete kairoslab0",
			"ip link delete kairoslab-tap0",
			"ip link delete kairoslab0",
		})
	})

	t.Run("nothing fails", func(t *testing.T) {
		h := newFakeHost(t)
		h.conns[DefaultBridgeName] = true
		h.bridges[DefaultBridgeName] = true

		if err := cleanupNMConnections(DefaultBridgeName, DefaultTapName); err != nil {
			t.Fatalf("a teardown that did everything asked of it returned %v, want nil", err)
		}
	})
}

// The tap name reaches `sudo ip link delete <name>` exactly as the bridge
// name does, so it is checked at the same choke point and for the same
// reason. Before it was threaded through, this path deleted the constant
// DefaultTapName whatever state.json said -- which left a configured tap on
// the host and needed no validation because no stored value was used.
func TestCleanupNMConnectionsRefusesAMalformedStoredTapName(t *testing.T) {
	for _, tap := range []string{attackNMProfileName, attackPathTraversal, attackPlanRowInjection} {
		t.Run(fmt.Sprintf("%q", tap), func(t *testing.T) {
			h := newFakeHost(t)
			h.conns[DefaultBridgeName] = true
			h.links[tap] = true

			err := cleanupNMConnections(DefaultBridgeName, tap)
			if err == nil {
				t.Fatal("cleanupNMConnections accepted a malformed stored tap name")
			}
			if len(h.commands) != 0 {
				t.Errorf("rejected input still reached root:\n  %s", strings.Join(h.lines(), "\n  "))
			}
			if !strings.Contains(err.Error(), "tap name") {
				t.Errorf("error %q does not name the field it came from", err)
			}
		})
	}

	// An empty tap name is not malformed: it is a state file written before
	// the tap was ever created, and it means the default.
	t.Run("empty means the default", func(t *testing.T) {
		h := newFakeHost(t)
		h.conns[DefaultBridgeName] = true
		h.links[DefaultTapName] = true

		if err := cleanupNMConnections(DefaultBridgeName, ""); err != nil {
			t.Fatalf("cleanupNMConnections with no stored tap name = %v, want nil", err)
		}
		assertSequence(t, h.lines(), []string{
			"nmcli connection delete kairoslab0",
			"ip link delete kairoslab-tap0",
		})
	})

	// And a configured one is the tap that gets deleted, which is the point of
	// threading it in at all.
	t.Run("a configured tap is the one deleted", func(t *testing.T) {
		h := newFakeHost(t)
		h.conns[DefaultBridgeName] = true
		h.links["kltap0"] = true

		if err := cleanupNMConnections(DefaultBridgeName, "kltap0"); err != nil {
			t.Fatalf("cleanupNMConnections = %v, want nil", err)
		}
		assertSequence(t, h.lines(), []string{
			"nmcli connection delete kairoslab0",
			"ip link delete kltap0",
		})
	})
}
