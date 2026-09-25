package vm

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Finding the address of a running guest. The guest is on a bridge we built,
// it took a lease from a DHCP server we started (shared mode) or from the
// LAN's (bridged mode), and nothing told us what it got -- so the address has
// to be recovered from the host, keyed on the one thing we chose ourselves:
// the NIC address MACForDisk derived for this disk.
//
// Three sources answer that question, and they are tried in a fixed order
// that is about trustworthiness, not convenience:
//
//  1. the DHCP lease file -- the server's own record of what it handed out,
//     so it is authoritative and it is a plain file read;
//  2. the ARP/neighbour cache -- evidence the host has actually exchanged
//     frames with that MAC, which is one subprocess and needs no agent in the
//     guest, but ages out and can hold a stale entry from a previous boot;
//  3. the QEMU guest agent -- the guest's own answer, correct when it comes
//     but present only if the image ships qemu-guest-agent, and on macOS
//     usually unreachable (see guestAgentIP).
//
// Every source is best effort. A missing file, a denied read, a missing
// binary, a guest with no agent: each falls through to the next in silence,
// because none of them is an error the user did anything about. Resolve
// returning false means "not yet", and Poll exists because "not yet" is the
// normal answer for the first several seconds of a boot.

// IP source names, as recorded in IPResult.Source. They are the strings the
// caller prints and stores, so they are spelled once here.
const (
	IPSourceDHCPLease  = "dhcp-lease"
	IPSourceARP        = "arp"
	IPSourceGuestAgent = "qemu-guest-agent"
)

// Poll defaults. 45 seconds is the budget the PRD sets: long enough for a
// Kairos live ISO to boot and request a lease, short enough that a user
// staring at a VM with no address learns so while they still care. Waiting
// longer does not help -- past that point the answer is a diagnostic, not
// more patience.
//
// A one-second tick costs less than it looks: the lease file is the first
// source and needs no subprocess at all, so ARP only runs on the ticks where
// no lease has appeared yet.
const (
	DefaultIPPollInterval = 1 * time.Second
	DefaultIPPollTimeout  = 45 * time.Second
)

// IPLookup is everything the three sources need to know about one VM.
type IPLookup struct {
	// MAC is the VM's NIC address exactly as it was passed to QEMU. It is the
	// key every source is matched on; with no usable MAC there is nothing to
	// look up, and Resolve says so immediately.
	MAC string
	// Mode is the user-facing network mode: shared, bridged or user.
	Mode string
	// LeaseFile is state.Network.DHCPLeaseFile, the path PrepareLinuxShared
	// recorded at the moment it applied ipv4.method shared. Empty means "use
	// the platform default", which is right on macOS and a fallback on Linux
	// -- see sharedLeaseFilePath for why the recorded path is the better one.
	LeaseFile string
	// BridgeName derives the default lease path on Linux and is unused on
	// macOS, where bootpd keeps one file for every vmnet client.
	BridgeName string
	// QGASocketPath is the unix socket QEMU was given as the guest-agent
	// chardev backend.
	QGASocketPath string
}

// IPResult is an answer and where it came from. Source is one of the
// IPSource* constants; the caller prints it, because "192.168.64.12 (from the
// ARP cache)" and "192.168.64.12 (from the DHCP lease)" deserve different
// amounts of trust from a human reading them.
type IPResult struct {
	IP     string
	Source string
}

// Resolve asks the three sources in order and returns the first answer.
//
// It returns ok == false when none of them answered, which during a boot is
// the ordinary case rather than a failure: the guest has not requested a
// lease yet. No error is returned for the same reason -- there is no failure
// here a caller could act on, and an error per source per tick would be noise
// over the whole poll window.
func (l IPLookup) Resolve(ctx context.Context) (IPResult, bool) {
	// The MAC guard comes first and covers all three sources at once. An
	// unset MAC -- legitimate for a disk recorded before state.Disk.MAC
	// existed -- or a malformed one cannot be matched against anything, so
	// the correct answer is an immediate false rather than three fruitless
	// probes per tick. CanonicalMAC rather than NormalizeMAC only because
	// this is the validity question and not a comparison; the two accept
	// exactly the same inputs.
	if _, ok := CanonicalMAC(l.MAC); !ok {
		return IPResult{}, false
	}
	if ctx.Err() != nil {
		return IPResult{}, false
	}

	// user mode is QEMU's own SLIRP stack: the DHCP server lives inside the
	// QEMU process, so no lease is ever written to a host file, and no frame
	// from the guest reaches the host's neighbour table, so no ARP entry ever
	// exists either. Neither host source can answer, and skipping them saves
	// a subprocess on every tick of a poll that only the guest agent can end.
	// The agent is still asked, because it reports the address the guest
	// itself sees (10.0.2.15 behind SLIRP) -- true of the guest, even though
	// the way in from the host is the forwarded ports on localhost.
	if l.Mode != "user" {
		if ip := l.leaseIP(); ip != "" {
			return IPResult{IP: ip, Source: IPSourceDHCPLease}, true
		}
		if ip := arpLookup(ctx, l.MAC); ip != "" {
			return IPResult{IP: ip, Source: IPSourceARP}, true
		}
	}
	if ip := l.guestAgentIP(ctx); ip != "" {
		return IPResult{IP: ip, Source: IPSourceGuestAgent}, true
	}
	return IPResult{}, false
}

// Poll calls Resolve every interval until it answers, until timeout elapses,
// or until ctx is cancelled -- whichever happens first.
//
// The first attempt is made immediately and not after the first tick: an
// address that is already in the lease file must not cost an interval.
//
// Cancellation is the important half. The caller cancels this the moment
// QEMU exits, and ctx is threaded into every source -- exec.CommandContext
// kills a running `arp`/`ip` child, and the guest-agent read takes its
// deadline from the same ctx -- so the loop returns at once instead of
// finishing the tick it was in. A poller that ignored that would still be
// running, and still writing its answer into state, after the VM it describes
// had gone.
//
// A timeout of zero or less means "no timeout of my own": the poll then ends
// only when a source answers or ctx says stop.
func (l IPLookup) Poll(ctx context.Context, timeout, interval time.Duration) (IPResult, bool) {
	if _, ok := CanonicalMAC(l.MAC); !ok {
		return IPResult{}, false
	}
	if interval <= 0 {
		interval = DefaultIPPollInterval
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if res, ok := l.Resolve(ctx); ok {
			return res, true
		}
		select {
		case <-ctx.Done():
			return IPResult{}, false
		case <-ticker.C:
		}
	}
}

// leaseIP reads the DHCP lease file this VM's server writes and returns the
// address recorded for its MAC, or "".
//
// The recorded path wins over the computed one. PrepareLinuxShared stores the
// lease path at the point it applies ipv4.method shared, because the file is
// named after the interface that received the method and not after "the
// bridge" -- recomputing it here from BridgeName would read a file nothing
// writes the day those two names differ. The default is the fallback for a
// state file written before that field existed, and on macOS it is simply the
// one path bootpd uses.
func (l IPLookup) leaseIP() string {
	path := l.LeaseFile
	if path == "" {
		path = defaultLeaseFile(l.BridgeName)
	}
	if path == "" {
		return ""
	}
	return leaseLookup(path, l.MAC)
}

// lookupLeaseFile is the half of leaseLookup that is identical on every
// platform: read the file, hand the bytes to the platform's parser. The
// platform file supplies only the parser, so the two cannot drift apart about
// what "best effort" means.
func lookupLeaseFile(path, mac string, parse func(content, mac string) string) string {
	content := leaseFileContent(path)
	if content == "" {
		return ""
	}
	return parse(content, mac)
}

// leaseFileContent returns the contents of a DHCP lease file, or "" for every
// way reading it can fail. Two of those ways are entirely expected and
// neither is worth a word to the user:
//
//   - os.ErrNotExist, before any client has taken a lease. dnsmasq creates
//     the file when it writes the first one, so it is genuinely absent for
//     the first seconds of every shared-mode run.
//   - os.ErrPermission. Not on Linux, where dnsmasq deliberately sets
//     umask(022) so that its lease and pid files are world-readable, but a
//     host that tightened /var/lib/NetworkManager would land here, and so
//     would a macOS host with a locked-down /var/db.
//
// Anything else -- a directory in place of the file, an I/O error -- is
// treated the same way, because the caller's next move is identical in every
// case: try the next source.
func leaseFileContent(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

// hostCommandOutput runs a read-only host probe and returns its stdout, or ""
// when the command fails -- a binary that is not installed, a non-zero exit,
// or a context cancelled while it ran.
//
// It is a package-level var for the same reason sudo and bridgeSlaveLinks are
// in network_linux.go: ipaddr_test.go swaps it for an in-process fake, so the
// ARP source can be driven on a host with no VM and no neighbours, and the
// exact argv can be asserted. What the fake replaces is a subprocess and
// never a decision -- the parsers in ipaddr_parse.go run for real over
// whatever output the fake supplies. Nothing in production assigns it; the
// tests restore it with t.Cleanup.
//
// exec.CommandContext and not exec.Command, here and nowhere else in this
// package: Poll is cancelled the moment QEMU exits, and a probe still running
// after that is a child process nobody is waiting for.
var hostCommandOutput = func(ctx context.Context, name string, args ...string) string {
	out, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil {
		return ""
	}
	return string(out)
}

// The QEMU guest agent source.
//
// One exchange over the guest-agent unix socket: connect, write
// guest-network-get-interfaces, read one line, close. A unix socket and a
// line of JSON behave identically on both platforms, so this half needs no
// per-platform file.

// qgaGetInterfaces is the only command this package sends. qga/main.c's
// send_response writes a compact single-line JSON object terminated with LF
// (not CRLF, and with no QMP-style greeting banner first), so the whole
// protocol here is: one line out, one line back.
const qgaGetInterfaces = `{"execute":"guest-network-get-interfaces"}`

// qgaMaxResponse caps how much is read while looking for that LF. A guest
// with a dozen interfaces answers in a few kilobytes; the cap exists so that
// something which is not qemu-ga on the other end of the socket cannot make
// this grow without bound.
const qgaMaxResponse = 1 << 20

// qgaReadTimeout bounds one exchange with the agent, and it is the single
// most important line in this file.
//
// QEMU is started with "-chardev socket,...,server=on,wait=off". wait=off
// means QEMU itself listens and accepts, so the connect succeeds and the
// write succeeds EVEN WHEN THE GUEST SHIPS NO qemu-guest-agent AT ALL -- the
// bytes are simply queued into a virtio-serial port nothing is reading. There
// is no error to notice and nothing ever arrives back. Without a deadline of
// its own, this source does not fail: it blocks, for as long as the VM is
// running, and it takes the whole poll with it.
//
// It is a var only so ipaddr_test.go can shorten it; nothing in production
// assigns it.
var qgaReadTimeout = 2 * time.Second

// qgaDial is the exec-equivalent seam for the socket, swapped by
// ipaddr_test.go for an in-process net.Pipe. Nothing in production assigns it.
var qgaDial = func(ctx context.Context, path string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", path)
}

// guestAgentIP asks the guest for its own interface list and returns the
// first usable IPv4 address on the NIC whose hardware address is this VM's,
// or "".
//
// This is the last source on both platforms, and on macOS it is barely a
// source at all. There -- and only there -- QEMU is launched under sudo for
// vmnet, so it creates this socket as root; connecting to a unix socket
// requires write permission on it, so a resolver running as the user gets
// EACCES and never sees a byte. That is by design and is not worked around:
// the two sources ahead of it need no agent in the guest and no privilege on
// the host, and an agent that answers is a bonus rather than a dependency.
func (l IPLookup) guestAgentIP(ctx context.Context) string {
	if l.QGASocketPath == "" {
		return ""
	}
	conn, err := qgaDial(ctx, l.QGASocketPath)
	if err != nil {
		// Expected until QEMU has created the socket, and expected forever on
		// a macOS host where QEMU runs as root. Neither is worth saying.
		return ""
	}
	defer conn.Close()

	// The deadline is the smaller of "one exchange" and whatever the caller's
	// context already allows, so a cancelled poll cannot be extended by this
	// source and a long-running poll cannot be stalled by it either.
	deadline := time.Now().Add(qgaReadTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return ""
	}

	// A context can also be cancelled outright -- QEMU exited -- which no
	// deadline computed above would notice. Moving the deadline into the past
	// unblocks a read that is already waiting; net.Conn deadlines are safe to
	// set from another goroutine, and doing it this way avoids racing the
	// deferred Close. The watcher always ends, because done is closed on
	// every return path.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.SetDeadline(time.Now())
		case <-done:
		}
	}()

	// No guest-sync first, deliberately. guest-sync exists to discard replies
	// left over from an earlier, abandoned exchange on a REUSED connection;
	// every call here dials its own socket and closes it on return, so there
	// is no stale state on it to flush and the extra round trip would only be
	// one more thing to time out.
	if _, err := conn.Write([]byte(qgaGetInterfaces + "\n")); err != nil {
		return ""
	}
	return parseQGAInterfaces(readQGALine(conn), l.MAC)
}

// readQGALine reads up to the first LF and returns the bytes before it, or ""
// when nothing arrives. The deadline set by the caller is what ends this on a
// guest with no agent listening.
func readQGALine(conn net.Conn) string {
	var line []byte
	chunk := make([]byte, 4096)
	for {
		n, err := conn.Read(chunk)
		for i := 0; i < n; i++ {
			if chunk[i] == '\n' {
				return string(append(line, chunk[:i]...))
			}
		}
		line = append(line, chunk[:n]...)
		if err != nil {
			// qemu-ga always terminates its response with LF, so an error
			// before one means the connection went away mid-answer or the
			// deadline fired. Whatever arrived is handed on regardless:
			// truncated JSON simply fails to unmarshal, and the empty case
			// costs nothing.
			return string(line)
		}
		if len(line) >= qgaMaxResponse {
			return ""
		}
	}
}

// qgaResponse is the envelope qemu-ga returns. A command it does not
// recognise comes back as {"error":{...}} with no "return" member at all,
// which needs no special case: Return is then nil and there is nothing to
// walk.
type qgaResponse struct {
	Return []qgaInterface `json:"return"`
}

// qgaInterface mirrors GuestNetworkInterface from qga/qapi-schema.json. Both
// optional members of that schema are modelled so that ABSENT is
// distinguishable and is handled:
//
//   - hardware-address is a pointer, because an interface without one cannot
//     be matched to a MAC and must be skipped rather than compared as "".
//     Skipping matters: NormalizeMAC("") is ("", false), and an absent
//     address must not be allowed to look like any other unparseable value.
//   - ip-addresses is a slice, nil when absent, which is exactly an interface
//     that has not been configured yet -- the normal state of the guest's NIC
//     in the seconds before its DHCP exchange completes.
type qgaInterface struct {
	Name            string         `json:"name"`
	HardwareAddress *string        `json:"hardware-address"`
	IPAddresses     []qgaIPAddress `json:"ip-addresses"`
}

// qgaIPAddress mirrors GuestIpAddress. Type is "ipv4" or "ipv6"; it is
// checked in addition to usableIPv4 and not instead of it, because the field
// is the guest's claim about the address and usableIPv4 is the truth about
// it.
type qgaIPAddress struct {
	Address string `json:"ip-address"`
	Type    string `json:"ip-address-type"`
	Prefix  int    `json:"prefix"`
}

// parseQGAInterfaces finds the first usable IPv4 address the agent reports
// for mac, or "". Malformed JSON, an error envelope and an empty list are all
// the same "" -- this is the last source, and there is nothing after it to
// report to.
func parseQGAInterfaces(payload, mac string) string {
	needle, ok := NormalizeMAC(mac)
	if !ok {
		return ""
	}
	var resp qgaResponse
	if err := json.Unmarshal([]byte(payload), &resp); err != nil {
		return ""
	}
	for _, iface := range resp.Return {
		if iface.HardwareAddress == nil || !sameMAC(needle, *iface.HardwareAddress) {
			continue
		}
		for _, addr := range iface.IPAddresses {
			if strings.ToLower(addr.Type) == "ipv6" {
				continue
			}
			if got := usableIPv4(addr.Address); got != "" {
				return got
			}
		}
	}
	return ""
}
