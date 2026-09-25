// Tests for the discovery sources in ipaddr.go: the order Resolve asks them
// in, the loop and cancellation behaviour of Poll, and the guest-agent
// exchange.
//
// There is no build tag here either. ipaddr.go is untagged, so everything it
// contains runs on both CI legs; what differs per platform is only WHICH
// parser leaseLookup and arpLookup reach for, and the helpers below render
// their fixtures in the format of the host the test is running on. The two
// exec/socket seams -- hostCommandOutput and qgaDial -- are swapped for
// in-process fakes, so no test here runs a subprocess, opens a real socket or
// reads a file outside its own t.TempDir.
package vm

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// testMAC is the canonical padded spelling, as it would be handed to QEMU.
// The fixtures below write it out in the form the platform's own tooling
// would use, which on macOS is the stripped one.
const (
	testMAC  = "52:54:00:12:34:56"
	leaseIP  = "192.168.64.12"
	arpIP    = "192.168.64.13"
	agentIP  = "192.168.64.14"
	otherMAC = "52:54:00:ab:cd:ef"
)

// hostSourcesAvailable reports whether this platform has a lease file and an
// ARP command this package knows how to read. Both CI legs do; the skips
// below exist so that a build for some third GOOS -- where ipaddr_other.go
// answers "" for both -- reports honestly rather than failing.
func hostSourcesAvailable() bool {
	return runtime.GOOS == "darwin" || runtime.GOOS == "linux"
}

// platformLeaseContent renders a lease for mac in the format THIS platform's
// leaseLookup parses. macOS strips the leading zeroes of each octet, as
// bootpd does, so the fixture exercises the normalisation rather than
// sidestepping it.
func platformLeaseContent(mac, ip string) string {
	switch runtime.GOOS {
	case "darwin":
		stripped := strings.ReplaceAll(mac, ":0", ":")
		return "{\n\tname=kairos\n\tip_address=" + ip + "\n\thw_address=1," + stripped + "\n}\n"
	case "linux":
		return "1716915600 " + mac + " " + ip + " kairos *\n"
	}
	return ""
}

// platformARPOutput renders one neighbour entry in the format this platform's
// arpLookup parses.
func platformARPOutput(mac, ip string) string {
	switch runtime.GOOS {
	case "darwin":
		return "? (" + ip + ") at " + strings.ReplaceAll(mac, ":0", ":") + " on bridge100 ifscope [ethernet]\n"
	case "linux":
		return ip + " dev kairoslab0 lladdr " + mac + " REACHABLE\n"
	}
	return ""
}

// wantARPArgv is the command this platform's ARP source must run. Asserting
// it is what keeps a "harmless" edit from turning `ip neigh` into
// `ip neigh show dev <x>`, which drops the dev token from the output and
// moves every field the parser reads.
func wantARPArgv() string {
	switch runtime.GOOS {
	case "darwin":
		return "arp -an"
	case "linux":
		return "ip neigh"
	}
	return ""
}

func qgaReplyFor(mac, ip string) string {
	return `{"return":[` +
		`{"name":"lo","hardware-address":"00:00:00:00:00:00","ip-addresses":[{"ip-address":"127.0.0.1","ip-address-type":"ipv4","prefix":8}]},` +
		`{"name":"eth0","hardware-address":"` + mac + `","ip-addresses":[` +
		`{"ip-address":"fe80::5054:ff:fe12:3456","ip-address-type":"ipv6","prefix":64},` +
		`{"ip-address":"` + ip + `","ip-address-type":"ipv4","prefix":24}]}]}`
}

// fakeSources stands in for the two seams of ipaddr.go: the ARP subprocess
// and the guest-agent socket. It records that each was consulted, which is
// what the source-order tests assert -- "the lease file answered" is only
// half the claim, the other half is that nothing else was asked.
type fakeSources struct {
	mu       sync.Mutex
	arpCalls []string
	arpOut   string
	qgaDials int
	qgaReply string
	qgaErr   error

	stop chan struct{}
}

func newFakeSources(t *testing.T) *fakeSources {
	t.Helper()
	f := &fakeSources{stop: make(chan struct{})}

	origHost, origDial, origTimeout := hostCommandOutput, qgaDial, qgaReadTimeout
	t.Cleanup(func() {
		close(f.stop)
		hostCommandOutput, qgaDial, qgaReadTimeout = origHost, origDial, origTimeout
	})

	hostCommandOutput = func(_ context.Context, name string, args ...string) string {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.arpCalls = append(f.arpCalls, strings.Join(append([]string{name}, args...), " "))
		return f.arpOut
	}

	qgaDial = func(_ context.Context, _ string) (net.Conn, error) {
		f.mu.Lock()
		f.qgaDials++
		reply, err := f.qgaReply, f.qgaErr
		f.mu.Unlock()
		if err != nil {
			return nil, err
		}
		client, server := net.Pipe()
		go f.serve(server, reply)
		go func() {
			<-f.stop
			_ = server.Close()
		}()
		return client, nil
	}
	return f
}

// serve is QEMU's side of the chardev. With reply set it answers one
// LF-terminated line; with reply empty it reads the request and then NEVER
// answers, which is precisely what a "wait=off" chardev does when the guest
// ships no qemu-guest-agent -- the write is accepted into a virtio-serial
// port that nothing on the other side is reading.
func (f *fakeSources) serve(server net.Conn, reply string) {
	defer server.Close()
	buf := make([]byte, 4096)
	if _, err := server.Read(buf); err != nil {
		return
	}
	if reply == "" {
		<-f.stop
		return
	}
	_, _ = server.Write([]byte(reply + "\n"))
}

func (f *fakeSources) setARP(out string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.arpOut = out
}

func (f *fakeSources) setQGA(reply string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.qgaReply = reply
}

func (f *fakeSources) setQGADialError(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.qgaErr = err
}

func (f *fakeSources) snapshot() ([]string, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.arpCalls...), f.qgaDials
}

// writeLease puts a lease file for mac in a temp dir and returns its path.
func writeLease(t *testing.T, mac, ip string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dhcp.leases")
	if err := os.WriteFile(path, []byte(platformLeaseContent(mac, ip)), 0o644); err != nil {
		t.Fatalf("write lease file: %v", err)
	}
	return path
}

// missingLease is a path in a fresh temp dir that deliberately does not
// exist: the ordinary state of a lease file before the first client has
// leased anything.
func missingLease(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "nothing-here.leases")
}

func TestResolvePrefersTheLeaseFile(t *testing.T) {
	if !hostSourcesAvailable() {
		t.Skipf("no lease file source on %s", runtime.GOOS)
	}
	f := newFakeSources(t)
	// Both later sources are armed with DIFFERENT addresses, so the test
	// fails loudly rather than coincidentally if the order is ever inverted.
	f.setARP(platformARPOutput(testMAC, arpIP))
	f.setQGA(qgaReplyFor(testMAC, agentIP))

	l := IPLookup{MAC: testMAC, Mode: "shared", LeaseFile: writeLease(t, testMAC, leaseIP), QGASocketPath: "/fake/qga.sock"}
	res, ok := l.Resolve(context.Background())
	if !ok || res.IP != leaseIP || res.Source != IPSourceDHCPLease {
		t.Fatalf("Resolve = %+v, %v; want %s from %s", res, ok, leaseIP, IPSourceDHCPLease)
	}
	arp, qga := f.snapshot()
	if len(arp) != 0 {
		t.Errorf("ARP was consulted despite a lease file answer: %v", arp)
	}
	if qga != 0 {
		t.Errorf("the guest agent was dialled %d times despite a lease file answer", qga)
	}
}

func TestResolveFallsBackToARP(t *testing.T) {
	if !hostSourcesAvailable() {
		t.Skipf("no ARP source on %s", runtime.GOOS)
	}
	f := newFakeSources(t)
	f.setARP(platformARPOutput(testMAC, arpIP))
	f.setQGA(qgaReplyFor(testMAC, agentIP))

	l := IPLookup{MAC: testMAC, Mode: "shared", LeaseFile: missingLease(t), QGASocketPath: "/fake/qga.sock"}
	res, ok := l.Resolve(context.Background())
	if !ok || res.IP != arpIP || res.Source != IPSourceARP {
		t.Fatalf("Resolve = %+v, %v; want %s from %s", res, ok, arpIP, IPSourceARP)
	}
	arp, qga := f.snapshot()
	if len(arp) != 1 || arp[0] != wantARPArgv() {
		t.Errorf("ARP commands = %v, want exactly [%q]", arp, wantARPArgv())
	}
	if qga != 0 {
		t.Errorf("the guest agent was dialled %d times despite an ARP answer", qga)
	}
}

func TestResolveFallsBackToTheGuestAgentLast(t *testing.T) {
	f := newFakeSources(t)
	f.setARP("")
	f.setQGA(qgaReplyFor(testMAC, agentIP))

	l := IPLookup{MAC: testMAC, Mode: "shared", LeaseFile: missingLease(t), QGASocketPath: "/fake/qga.sock"}
	res, ok := l.Resolve(context.Background())
	if !ok || res.IP != agentIP || res.Source != IPSourceGuestAgent {
		t.Fatalf("Resolve = %+v, %v; want %s from %s", res, ok, agentIP, IPSourceGuestAgent)
	}
	arp, qga := f.snapshot()
	if hostSourcesAvailable() && len(arp) != 1 {
		t.Errorf("ARP commands = %v, want the one probe that came up empty", arp)
	}
	if qga != 1 {
		t.Errorf("the guest agent was dialled %d times, want 1", qga)
	}
}

func TestResolveReturnsFalseWhenNothingAnswers(t *testing.T) {
	f := newFakeSources(t)
	f.setARP("")
	f.setQGA(`{"return":[]}`)

	l := IPLookup{MAC: testMAC, Mode: "shared", LeaseFile: missingLease(t), QGASocketPath: "/fake/qga.sock"}
	if res, ok := l.Resolve(context.Background()); ok {
		t.Fatalf("Resolve = %+v, true; want no answer", res)
	}
}

// A lease for a DIFFERENT VM in the same file must not be mistaken for ours;
// this is the case the per-disk MAC exists to make decidable.
func TestResolveIgnoresAnotherVMsLease(t *testing.T) {
	if !hostSourcesAvailable() {
		t.Skipf("no lease file source on %s", runtime.GOOS)
	}
	f := newFakeSources(t)
	f.setARP("")
	f.setQGA(`{"return":[]}`)

	l := IPLookup{MAC: testMAC, Mode: "shared", LeaseFile: writeLease(t, otherMAC, leaseIP), QGASocketPath: "/fake/qga.sock"}
	if res, ok := l.Resolve(context.Background()); ok {
		t.Fatalf("Resolve = %+v, true; want no answer for a lease belonging to %s", res, otherMAC)
	}
}

func TestResolveRejectsAnUnusableMAC(t *testing.T) {
	for _, mac := range []string{"", "not-a-mac", "52:54:00:12:34", "52:54:00:12:34:56:78"} {
		t.Run("mac="+mac, func(t *testing.T) {
			f := newFakeSources(t)
			f.setARP(platformARPOutput(testMAC, arpIP))
			f.setQGA(qgaReplyFor(testMAC, agentIP))

			l := IPLookup{MAC: mac, Mode: "shared", LeaseFile: writeLease(t, testMAC, leaseIP), QGASocketPath: "/fake/qga.sock"}
			if res, ok := l.Resolve(context.Background()); ok {
				t.Fatalf("Resolve with MAC %q = %+v, true; want no answer", mac, res)
			}
			// The point is not only the answer but the cost: with no usable
			// MAC there is nothing any source could be matched against, so
			// none of them may be probed at all.
			arp, qga := f.snapshot()
			if len(arp) != 0 || qga != 0 {
				t.Errorf("probed the host with an unusable MAC: arp=%v qga dials=%d", arp, qga)
			}
		})
	}
}

// user mode is QEMU's own SLIRP stack: its DHCP server is inside the QEMU
// process and no guest frame reaches the host, so neither host source can
// ever answer and neither should be run. The guest agent still is, because it
// reports what the guest itself sees.
func TestResolveSkipsHostSourcesInUserMode(t *testing.T) {
	if !hostSourcesAvailable() {
		t.Skipf("no host sources on %s", runtime.GOOS)
	}
	f := newFakeSources(t)
	f.setARP(platformARPOutput(testMAC, arpIP))
	f.setQGA(qgaReplyFor(testMAC, agentIP))

	l := IPLookup{MAC: testMAC, Mode: "user", LeaseFile: writeLease(t, testMAC, leaseIP), QGASocketPath: "/fake/qga.sock"}
	res, ok := l.Resolve(context.Background())
	if !ok || res.IP != agentIP || res.Source != IPSourceGuestAgent {
		t.Fatalf("Resolve in user mode = %+v, %v; want %s from %s", res, ok, agentIP, IPSourceGuestAgent)
	}
	if arp, _ := f.snapshot(); len(arp) != 0 {
		t.Errorf("ARP was consulted in user mode: %v", arp)
	}
}

func TestResolveStopsOnAnAlreadyCancelledContext(t *testing.T) {
	if !hostSourcesAvailable() {
		t.Skipf("no host sources on %s", runtime.GOOS)
	}
	f := newFakeSources(t)
	f.setARP(platformARPOutput(testMAC, arpIP))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	l := IPLookup{MAC: testMAC, Mode: "shared", LeaseFile: writeLease(t, testMAC, leaseIP), QGASocketPath: "/fake/qga.sock"}
	if res, ok := l.Resolve(ctx); ok {
		t.Fatalf("Resolve on a cancelled context = %+v, true; want no answer", res)
	}
	if arp, qga := f.snapshot(); len(arp) != 0 || qga != 0 {
		t.Errorf("probed the host on a cancelled context: arp=%v qga dials=%d", arp, qga)
	}
}

func TestDefaultLeaseFile(t *testing.T) {
	got := defaultLeaseFile(DefaultBridgeName)
	var want string
	switch runtime.GOOS {
	case "darwin":
		// bootpd.tproj/dhcpd.c: DHCP_LEASES_FILE. One file for every vmnet
		// client, so the bridge name has no part in it.
		want = "/var/db/dhcpd_leases"
		if other := defaultLeaseFile("something-else"); other != want {
			t.Errorf("defaultLeaseFile(%q) = %q, want the same %q", "something-else", other, want)
		}
	case "linux":
		want = "/var/lib/NetworkManager/dnsmasq-" + DefaultBridgeName + ".leases"
		if empty := defaultLeaseFile(""); empty != "" {
			t.Errorf("defaultLeaseFile(\"\") = %q, want empty", empty)
		}
	}
	if got != want {
		t.Errorf("defaultLeaseFile(%q) on %s = %q, want %q", DefaultBridgeName, runtime.GOOS, got, want)
	}
}

// Every way a lease file read can fail is the same silent "": there is
// nothing here a user did wrong and nothing to report, only a next source to
// try.
func TestLeaseLookupToleratesAnUnreadableFile(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name string
		path string
	}{
		{"file that does not exist yet", filepath.Join(dir, "nothing-here.leases")},
		{"empty path", ""},
		{"a directory in place of the file", dir},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := leaseLookup(tc.path, testMAC); got != "" {
				t.Errorf("leaseLookup(%q) = %q, want empty", tc.path, got)
			}
		})
	}
}

func TestParseQGAInterfaces(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload string
		mac     string
		want    string
	}{
		{
			"ordinary response",
			qgaReplyFor(testMAC, agentIP),
			testMAC,
			agentIP,
		},
		{
			"interface with no hardware-address at all",
			`{"return":[{"name":"eth0","ip-addresses":[{"ip-address":"192.168.64.99","ip-address-type":"ipv4","prefix":24}]}]}`,
			testMAC,
			"",
		},
		{
			"interface with no ip-addresses yet",
			`{"return":[{"name":"eth0","hardware-address":"52:54:00:12:34:56"}]}`,
			testMAC,
			"",
		},
		{
			"interface with only an ipv6 address",
			`{"return":[{"name":"eth0","hardware-address":"52:54:00:12:34:56","ip-addresses":[{"ip-address":"fe80::5054:ff:fe12:3456","ip-address-type":"ipv6","prefix":64}]}]}`,
			testMAC,
			"",
		},
		{
			"loopback address on the matching interface is skipped",
			`{"return":[{"name":"eth0","hardware-address":"52:54:00:12:34:56","ip-addresses":[{"ip-address":"127.0.0.1","ip-address-type":"ipv4","prefix":8},{"ip-address":"192.168.64.14","ip-address-type":"ipv4","prefix":24}]}]}`,
			testMAC,
			agentIP,
		},
		{
			"the unconfigured 0.0.0.0 of a guest still waiting for a lease",
			`{"return":[{"name":"eth0","hardware-address":"52:54:00:12:34:56","ip-addresses":[{"ip-address":"0.0.0.0","ip-address-type":"ipv4","prefix":0}]}]}`,
			testMAC,
			"",
		},
		{
			"the second interface is the match",
			`{"return":[{"name":"eth0","hardware-address":"52:54:00:ab:cd:ef","ip-addresses":[{"ip-address":"10.0.0.9","ip-address-type":"ipv4","prefix":24}]},{"name":"eth1","hardware-address":"52:54:00:12:34:56","ip-addresses":[{"ip-address":"192.168.64.14","ip-address-type":"ipv4","prefix":24}]}]}`,
			testMAC,
			agentIP,
		},
		{
			"a guest that reports its address with stripped octets",
			`{"return":[{"name":"eth0","hardware-address":"52:54:0:12:34:56","ip-addresses":[{"ip-address":"192.168.64.14","ip-address-type":"ipv4","prefix":24}]}]}`,
			testMAC,
			agentIP,
		},
		{
			"an ipv4 address mislabelled ipv6 is not taken",
			`{"return":[{"name":"eth0","hardware-address":"52:54:00:12:34:56","ip-addresses":[{"ip-address":"192.168.64.14","ip-address-type":"ipv6","prefix":24}]}]}`,
			testMAC,
			"",
		},
		{"command not found error envelope", `{"error":{"class":"CommandNotFound","desc":"the command guest-network-get-interfaces has not been found"}}`, testMAC, ""},
		{"empty return", `{"return":[]}`, testMAC, ""},
		{"malformed json", `{"return":[{"name":`, testMAC, ""},
		{"empty payload", "", testMAC, ""},
		{"empty needle", qgaReplyFor(testMAC, agentIP), "", ""},
		{"garbage needle", qgaReplyFor(testMAC, agentIP), "not-a-mac", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseQGAInterfaces(tc.payload, tc.mac); got != tc.want {
				t.Errorf("parseQGAInterfaces(..., %q) = %q, want %q", tc.mac, got, tc.want)
			}
		})
	}
}

func TestGuestAgentIPReadsOneLine(t *testing.T) {
	f := newFakeSources(t)
	f.setQGA(qgaReplyFor(testMAC, agentIP))
	l := IPLookup{MAC: testMAC, QGASocketPath: "/fake/qga.sock"}
	if got := l.guestAgentIP(context.Background()); got != agentIP {
		t.Fatalf("guestAgentIP = %q, want %q", got, agentIP)
	}
}

func TestGuestAgentIPWithoutASocketPath(t *testing.T) {
	f := newFakeSources(t)
	f.setQGA(qgaReplyFor(testMAC, agentIP))
	l := IPLookup{MAC: testMAC}
	if got := l.guestAgentIP(context.Background()); got != "" {
		t.Fatalf("guestAgentIP with no socket path = %q, want empty", got)
	}
	if _, qga := f.snapshot(); qga != 0 {
		t.Errorf("dialled %d times with no socket path, want 0", qga)
	}
}

// A root-owned socket on a macOS host where QEMU runs under sudo: the dial
// fails with EACCES and the source is simply silent.
func TestGuestAgentIPToleratesADialError(t *testing.T) {
	f := newFakeSources(t)
	f.setQGADialError(errors.New("dial unix /fake/qga.sock: connect: permission denied"))
	l := IPLookup{MAC: testMAC, QGASocketPath: "/fake/qga.sock"}
	if got := l.guestAgentIP(context.Background()); got != "" {
		t.Fatalf("guestAgentIP with a refused dial = %q, want empty", got)
	}
}

// The wait=off case, and the reason qgaReadTimeout exists. QEMU accepts the
// connection and the write even when the guest ships no agent, so nothing
// ever answers and no error is ever reported. The context here has no
// deadline and is never cancelled, which leaves the source's OWN deadline as
// the only thing that can end the read.
func TestGuestAgentIPHonoursItsOwnDeadline(t *testing.T) {
	f := newFakeSources(t)
	f.setQGA("")
	qgaReadTimeout = 100 * time.Millisecond

	l := IPLookup{MAC: testMAC, QGASocketPath: "/fake/qga.sock"}
	done := make(chan string, 1)
	go func() { done <- l.guestAgentIP(context.Background()) }()
	select {
	case got := <-done:
		if got != "" {
			t.Fatalf("guestAgentIP = %q, want empty", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("guestAgentIP never returned: a wait=off chardev with no agent behind it answers nothing, so without its own read deadline this source blocks for the life of the VM")
	}
}

func TestGuestAgentIPReturnsOnContextCancellation(t *testing.T) {
	f := newFakeSources(t)
	f.setQGA("")
	// Long enough that only the cancellation can end the read.
	qgaReadTimeout = 5 * time.Minute

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l := IPLookup{MAC: testMAC, QGASocketPath: "/fake/qga.sock"}
	done := make(chan string, 1)
	go func() { done <- l.guestAgentIP(ctx) }()
	time.AfterFunc(50*time.Millisecond, cancel)
	select {
	case got := <-done:
		if got != "" {
			t.Fatalf("guestAgentIP = %q, want empty", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("guestAgentIP ignored its cancelled context")
	}
}

func TestPollReturnsAsSoonAsASourceAnswers(t *testing.T) {
	if !hostSourcesAvailable() {
		t.Skipf("no lease file source on %s", runtime.GOOS)
	}
	newFakeSources(t)
	l := IPLookup{MAC: testMAC, Mode: "shared", LeaseFile: writeLease(t, testMAC, leaseIP)}

	start := time.Now()
	// The interval is deliberately far longer than the margin: an answer that
	// is already there must not cost a tick.
	res, ok := l.Poll(context.Background(), 30*time.Second, 10*time.Second)
	elapsed := time.Since(start)
	if !ok || res.IP != leaseIP || res.Source != IPSourceDHCPLease {
		t.Fatalf("Poll = %+v, %v; want %s from %s", res, ok, leaseIP, IPSourceDHCPLease)
	}
	if elapsed > 2*time.Second {
		t.Errorf("Poll took %s to return an answer that was already available", elapsed)
	}
}

func TestPollGivesUpAtItsTimeout(t *testing.T) {
	newFakeSources(t)
	// No QGA socket path, so the last source costs nothing and the loop is
	// purely about the timeout.
	l := IPLookup{MAC: testMAC, Mode: "shared", LeaseFile: missingLease(t)}

	start := time.Now()
	res, ok := l.Poll(context.Background(), 150*time.Millisecond, 20*time.Millisecond)
	elapsed := time.Since(start)
	if ok {
		t.Fatalf("Poll = %+v, true; want no answer", res)
	}
	if elapsed < 100*time.Millisecond {
		t.Errorf("Poll gave up after %s, well before its 150ms timeout", elapsed)
	}
	if elapsed > 5*time.Second {
		t.Errorf("Poll took %s to honour a 150ms timeout", elapsed)
	}
}

// M5 cancels this the moment QEMU exits. A poller that finished its interval
// first would still be resolving, and still writing into state, after the VM
// it describes had gone.
func TestPollReturnsPromptlyOnCancellation(t *testing.T) {
	newFakeSources(t)
	l := IPLookup{MAC: testMAC, Mode: "shared", LeaseFile: missingLease(t)}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	time.AfterFunc(50*time.Millisecond, cancel)

	start := time.Now()
	res, ok := l.Poll(ctx, 60*time.Second, 5*time.Second)
	elapsed := time.Since(start)
	if ok {
		t.Fatalf("Poll = %+v, true; want no answer", res)
	}
	// Generous against the 5s interval and the 60s timeout it was given:
	// anything near either of those means the cancellation was not noticed.
	if elapsed > 2*time.Second {
		t.Errorf("Poll returned %s after its context was cancelled, with a 5s interval and a 60s timeout", elapsed)
	}
}

func TestPollRejectsAnUnusableMAC(t *testing.T) {
	f := newFakeSources(t)
	f.setARP(platformARPOutput(testMAC, arpIP))
	l := IPLookup{MAC: "", Mode: "shared", LeaseFile: missingLease(t), QGASocketPath: "/fake/qga.sock"}

	start := time.Now()
	if res, ok := l.Poll(context.Background(), 30*time.Second, time.Second); ok {
		t.Fatalf("Poll with no MAC = %+v, true; want no answer", res)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("Poll with no MAC took %s; it has nothing to match and must say so at once", elapsed)
	}
	if arp, qga := f.snapshot(); len(arp) != 0 || qga != 0 {
		t.Errorf("polled the host with no MAC: arp=%v qga dials=%d", arp, qga)
	}
}
