package vm

import (
	"net"
	"strings"
)

// The parsing in this file is deliberately kept apart from the exec calls and
// the file reads in ipaddr.go and its platform files, exactly as
// network_darwin_parse.go is kept apart from network_darwin.go. Every
// function here takes a string and returns a string, so the whole address
// discovery surface is exercised on any host and on BOTH CI legs: the macOS
// formats are parsed under test on Linux and the Linux formats under test on
// macOS. Nothing here opens a file, runs a command or looks at runtime.GOOS.
//
// All four parsers obey the same three rules, and each of the three is a bug
// that was available to write:
//
//   - The needle MAC goes through NormalizeMAC ONCE, up front, and a !ok
//     needle returns "" before a single candidate is examined. NormalizeMAC
//     answers ("", false) for the empty string and for garbage alike, so
//     comparing normalised values without consulting the bool makes an unset
//     MAC equal to every unparseable candidate -- and a VM recorded before
//     the MAC field existed would then adopt the address of the first
//     malformed line in the file.
//   - Every candidate goes through NormalizeMAC too, because the two hosts
//     disagree about padding. macOS strips leading zeroes per octet
//     (bootplib/host_identifier.c and network_cmds/arp.c both format with %x),
//     so the NIC we hand QEMU as 52:54:00:12:34:56 comes back as
//     52:54:0:12:34:56; dnsmasq and `ip neigh` zero-pad with %.2x. A raw
//     comparison silently never matches on one of the two platforms.
//   - Every address goes through usableIPv4. All four sources carry IPv6 as
//     well, and an IPv6 address returned as "the VM's IP" is not a near miss:
//     it is recorded in state.json and printed as the address to ssh to.
//
// None of them may panic on ragged input. A lease file is read while its
// writer is appending to it, and an ARP table is whatever the host prints.

// usableIPv4 returns the dotted-quad form of s when s is an IPv4 address a
// guest could actually be reached at, and "" for everything else.
//
// It is the single place the address rule lives, so the four parsers and the
// guest-agent source cannot drift apart about what counts as an answer.
//
// The To4 call is the IPv4 rule itself: net.ParseIP happily accepts
// "fd00::5", and every one of these sources carries IPv6 alongside IPv4. It
// also folds an IPv4-mapped form like "::ffff:192.168.64.12" down to the
// dotted quad a user can type.
//
// The unicast rule is the second half. IsGlobalUnicast rejects 0.0.0.0,
// 127.0.0.0/8, the 224.0.0.0/4 multicast range and 255.255.255.255 in one
// call, and all four are things these sources really do carry: an ARP table
// holds an entry for 224.0.0.251 (mDNS) on any mac, with a real link-layer
// address beside it. Link-local unicast is let through despite not being
// global, because a 169.254 address is what a guest that failed to get a
// lease genuinely has, and reporting it is more use than reporting nothing.
func usableIPv4(s string) string {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return ""
	}
	v4 := ip.To4()
	if v4 == nil {
		return ""
	}
	if !v4.IsGlobalUnicast() && !v4.IsLinkLocalUnicast() {
		return ""
	}
	return v4.String()
}

// sameMAC reports whether candidate names the same NIC as needle, where
// needle has ALREADY been through NormalizeMAC and is known good. A candidate
// NormalizeMAC rejects is never a match -- that is the guard that keeps
// "(incomplete)", a DHCPv6 DUID and a torn line from matching anything.
func sameMAC(needle, candidate string) bool {
	got, ok := NormalizeMAC(candidate)
	return ok && got == needle
}

// ethernetHWAddress returns the address half of a bootpd hw_address value
// when the record describes an Ethernet client, and "" otherwise.
//
// The value is "<arp-hardware-type>,<address>": 1 is Ethernet (ARPHRD_ETHER),
// and ff is the marker bootpd writes for a DHCPv6 DUID, which is not a
// hardware address at all but an opaque client identifier that is merely
// spelled like one, colon-separated hex.
//
// The type prefix is the ONLY thing that says which of the two a value is.
// The server stores whatever bytes the client sent and does not validate
// their length, so a DUID of six octets -- which no well-formed DUID is, but
// any client on the segment can send -- is indistinguishable from a MAC once
// the prefix has been trimmed away, and a parser that blind-trimmed would
// hand a v6 record's address to whichever VM those six bytes happened to
// spell. Matching the type instead of stripping it is the whole point.
func ethernetHWAddress(value string) string {
	hwType, addr, found := strings.Cut(value, ",")
	if !found || strings.TrimSpace(hwType) != "1" {
		return ""
	}
	return strings.TrimSpace(addr)
}

// parseDarwinLeases finds the IPv4 address leased to mac in the contents of
// Apple's /var/db/dhcpd_leases, or "" when the file names no such client.
//
// The format is bootplib/NICache.c's PLCache_write: a "{" line, then
// tab-indented "<key>=<value>" lines, then a "}" line, one group per client.
// Three properties of that file decide the shape of this function:
//
//   - name= is OPTIONAL. bootpd's dhcpd.c writes it only "if (hostname_opt)",
//     so a guest that sends no hostname -- which is most of them during an
//     installer boot -- gets a record with no name line. Requiring one would
//     skip exactly the VMs we most want to find.
//   - identifier= is a separate line that is USUALLY but not always the same
//     as hw_address, so the match is made on hw_address alone. See
//     ethernetHWAddress for the DHCPv6 record where believing identifier is
//     actively wrong.
//   - The last record may have no closing brace, because this file is read
//     while bootpd is writing it. A record cut off that way still counts if
//     both fields we need arrived, which is why the match is attempted once
//     more after the loop rather than only on "}".
func parseDarwinLeases(content, mac string) string {
	needle, ok := NormalizeMAC(mac)
	if !ok {
		return ""
	}
	var ip, hw string
	match := func() string {
		// sameMAC is the only guard needed: it rejects "" -- a record with no
		// hw_address line, or one whose type was not Ethernet -- exactly as
		// it rejects any other value NormalizeMAC will not take.
		if !sameMAC(needle, hw) {
			return ""
		}
		return usableIPv4(ip)
	}
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		switch line {
		case "{":
			ip, hw = "", ""
			continue
		case "}":
			if got := match(); got != "" {
				return got
			}
			ip, hw = "", ""
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		switch strings.TrimSpace(key) {
		case "ip_address":
			ip = strings.TrimSpace(value)
		case "hw_address":
			// "" for a DHCPv6 DUID record, which then matches nothing.
			hw = ethernetHWAddress(strings.TrimSpace(value))
		}
	}
	return match()
}

// parseDnsmasqLeases finds the IPv4 address leased to mac in the contents of
// the dnsmasq lease file NetworkManager writes for a shared connection
// (/var/lib/NetworkManager/dnsmasq-<iface>.leases), or "".
//
// The format is dnsmasq's lease_update_file: one space-separated line per
// lease, "<expiry> <mac> <ip> <hostname-or-*> <client-id-or-*>", with the MAC
// zero-padded. Two other line shapes live in the same file and neither is a
// v4 lease:
//
//   - a bare "duid <hex>" line, which carries the server's own DHCPv6 DUID
//     and has only two fields;
//   - IPv6 leases, "<expiry> <iaid> <v6addr> <hostname> <clid>", where the
//     second field is a numeric IAID rather than a MAC and the third is a v6
//     address. Those have the full five fields, so no field count
//     distinguishes them -- only the MAC and IPv4 checks do, which is why
//     both are applied to every line rather than only to lines that look
//     interesting.
//
// The length guard is therefore about indexing and nothing else: three is the
// number of fields this function READS, and it keeps the duid line from
// panicking a parser that reaches for fields[2].
func parseDnsmasqLeases(content, mac string) string {
	needle, ok := NormalizeMAC(mac)
	if !ok {
		return ""
	}
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		if !sameMAC(needle, fields[1]) {
			continue
		}
		if got := usableIPv4(fields[2]); got != "" {
			return got
		}
	}
	return ""
}

// parseDarwinARP finds the IPv4 address `arp -an` reports for mac, or "".
//
// The layout is network_cmds' arp.c print_entry:
//
//	<host-or-?> (<ipv4>) at <mac|(incomplete)> [on <ifname>] [ifscope] [permanent] [published] [[ethernet]]
//
// Everything after the link-layer address is optional and varies by entry, so
// the parse keys off the literal " at " separator and takes the next
// whitespace token rather than counting fields from either end. An entry with
// no resolved address prints "(incomplete)" in that position; it needs no
// special case, because NormalizeMAC rejects it like any other non-MAC.
//
// The address is the last token before " at ", parenthesised by arp itself.
// Leading zeroes are stripped here too -- print_lladdr formats with %x -- so
// the same normalisation that covers the lease file covers this.
func parseDarwinARP(out, mac string) string {
	needle, ok := NormalizeMAC(mac)
	if !ok {
		return ""
	}
	for _, line := range strings.Split(out, "\n") {
		head, tail, found := strings.Cut(line, " at ")
		if !found {
			continue
		}
		lladdr := strings.Fields(tail)
		if len(lladdr) == 0 || !sameMAC(needle, lladdr[0]) {
			continue
		}
		addr := strings.Fields(head)
		if len(addr) == 0 {
			continue
		}
		if got := usableIPv4(strings.Trim(addr[len(addr)-1], "()")); got != "" {
			return got
		}
	}
	return ""
}

// parseLinuxNeigh finds the IPv4 address `ip neigh` reports for mac, or "".
//
// The layout is iproute2's ipneigh.c print_neigh:
//
//	<dst> [dev <ifname>] [lladdr <mac>] [router] [proxy] ... <NUD_STATE> [proto <p>]
//
// Two of those brackets are why this keys off the lladdr KEYWORD instead of a
// field index. "dev <ifname>" is omitted whenever the command filtered by
// device, which shifts every later field left by two -- so an index that is
// right for `ip neigh` is wrong for `ip neigh show dev br0`, and a caller
// that adds a filter later would silently start reading the NUD state as a
// MAC. And FAILED and INCOMPLETE entries carry no lladdr at all, so there is
// no position to read in the first place.
//
// The address is always field 0, and it is genuinely an IPv6 address for
// every v6 neighbour on the bridge -- including one whose link-layer address
// is the very MAC being searched for, since a guest's fe80:: address is
// derived from that MAC. usableIPv4 is what keeps such an entry from being
// returned as the VM's address.
func parseLinuxNeigh(out, mac string) string {
	needle, ok := NormalizeMAC(mac)
	if !ok {
		return ""
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		for i := 1; i < len(fields)-1; i++ {
			if fields[i] != "lladdr" {
				continue
			}
			if sameMAC(needle, fields[i+1]) {
				if got := usableIPv4(fields[0]); got != "" {
					return got
				}
			}
			// One lladdr per entry: whether it matched or not, this line is
			// finished.
			break
		}
	}
	return ""
}
