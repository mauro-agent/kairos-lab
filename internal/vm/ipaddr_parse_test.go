// Tests for the four lease and ARP parsers in ipaddr_parse.go.
//
// There is deliberately no build tag here and none on the file under test:
// every function they cover takes a string and returns a string, so the macOS
// formats are parsed under test on the ubuntu CI leg and the Linux formats on
// the macOS one. That is the point of splitting the package this way -- the
// bugs in these formats are format bugs, and none of them needs the host that
// produces them in order to be caught.
package vm

import "testing"

// Sample output, in the exact shapes the producing code writes.
//
// The macOS lease file is built from explicit \n and \t escapes rather than a
// raw string literal because the tabs are load-bearing in the format
// (bootplib/NICache.c indents every key line with one) and an indentation
// character that cannot be seen in a diff is not something to leave to a
// reviewer's eye.
const (
	// Four records from /var/db/dhcpd_leases, in bootplib PLCache_write form:
	// one ordinary client, one with no name= line, one DHCPv6 record whose
	// identifier= is a genuine MAC, and one whose identifier= disagrees with
	// its hw_address.
	darwinLeasesOut = "{\n" +
		"\tname=kairos-node\n" +
		"\tip_address=192.168.64.12\n" +
		"\thw_address=1,52:54:0:12:34:56\n" +
		"\tidentifier=1,52:54:0:12:34:56\n" +
		"\tlease=0x664f1234\n" +
		"}\n" +
		"{\n" +
		"\tip_address=192.168.64.13\n" +
		"\thw_address=1,52:54:0:ab:cd:ef\n" +
		"\tidentifier=1,52:54:0:ab:cd:ef\n" +
		"\tlease=0x664f1235\n" +
		"}\n" +
		"{\n" +
		"\tname=v6-client\n" +
		"\tip_address=192.168.64.14\n" +
		"\thw_address=ff,0:1:0:1:2d:9e:3f:aa:52:54:0:99:88:77\n" +
		"\tidentifier=1,52:54:0:99:88:77\n" +
		"\tlease=0x664f1236\n" +
		"}\n" +
		"{\n" +
		"\tname=renamed\n" +
		"\tip_address=192.168.64.15\n" +
		"\thw_address=1,52:54:0:aa:bb:cc\n" +
		"\tidentifier=1,52:54:0:dd:ee:ff\n" +
		"\tlease=0x664f1237\n" +
		"}\n"

	// A DHCPv6 record whose DUID is exactly six octets. No well-formed DUID
	// is that short, but the server stores the bytes the client sent without
	// checking, so this is what a client on the same segment can put in the
	// file: a value spelled exactly like a MAC, distinguishable from one only
	// by its ff type prefix.
	darwinLeasesShortDUID = "{\n" +
		"\tname=v6-enterprise\n" +
		"\tip_address=192.168.64.16\n" +
		"\thw_address=ff,0:2:0:0:ab:cd\n" +
		"\tidentifier=ff,0:2:0:0:ab:cd\n" +
		"\tlease=0x664f1238\n" +
		"}\n"

	// The tail of the file as it looks while bootpd is still writing it: the
	// closing brace has not been flushed yet.
	darwinLeasesTruncated = "{\n" +
		"\tname=partial\n" +
		"\tip_address=192.168.64.20\n" +
		"\thw_address=1,52:54:0:11:22:33\n"

	// Records whose hw_address is not a usable address at all: an Ethernet
	// type with nothing after the comma, an empty value, and a value that is
	// not hex.
	darwinLeasesMalformed = "{\n" +
		"\tip_address=192.168.64.30\n" +
		"\thw_address=1,\n" +
		"}\n" +
		"{\n" +
		"\tip_address=192.168.64.31\n" +
		"\thw_address=\n" +
		"}\n" +
		"{\n" +
		"\tip_address=192.168.64.32\n" +
		"\thw_address=1,not-a-mac\n" +
		"}\n"

	// Defensive: bootpd is a v4 server and would not write this, but nothing
	// downstream may return an IPv6 address as the VM's IP whatever a file
	// says.
	darwinLeasesV6Address = "{\n" +
		"\tip_address=fd00:1::5\n" +
		"\thw_address=1,52:54:0:be:ef:01\n" +
		"}\n"
)

// dnsmasq lease file as lease_update_file writes it: the server's own DUID on
// a bare two-field line, two IPv4 leases (the second with no hostname and no
// client id), one IPv6 lease whose second field is an IAID rather than a MAC,
// and a line torn by a write in progress.
const dnsmasqLeasesOut = `duid 00:01:00:01:2d:9e:3f:aa:52:54:00:99:88:77
1716915600 52:54:00:12:34:56 192.168.64.12 kairos-node 01:52:54:00:12:34:56
1716915601 52:54:00:ab:cd:ef 192.168.64.13 * *
1716915602 86400 fd00:1::5 v6-host 00:01:00:01:2d:9e:3f:aa
1716915603 52:54:00:99:88:77
`

// Defensive, in the same spirit as darwinLeasesV6Address: dnsmasq keys its
// IPv6 leases on an IAID and never writes this shape, and it still must not
// yield an IPv6 address.
const dnsmasqLeaseV6WithMAC = "1716915604 52:54:00:be:ef:01 fd00:1::7 v6only *\n"

// `arp -an` as network_cmds' print_entry writes it: an entry with the ifscope
// and [ethernet] suffixes, one that is permanent and published, one with no
// link-layer address yet, one with no "on <ifname>" at all, and the mDNS
// multicast entry every mac has.
const arpDarwinOut = `? (192.168.64.12) at 52:54:0:12:34:56 on bridge100 ifscope [ethernet]
kairos.local (192.168.64.13) at 52:54:0:ab:cd:ef on bridge100 permanent published [ethernet]
? (192.168.64.14) at (incomplete) on bridge100 [ethernet]
? (192.168.64.15) at 52:54:0:aa:bb:cc
? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
`

// `ip neigh` as iproute2's print_neigh writes it: an entry with the dev
// token, one without it (the shape a device-filtered command prints), a
// FAILED entry with no lladdr at all, an IPv6 neighbour whose lladdr is the
// same NIC as the IPv4 entry below it, and one with a proto suffix.
const ipNeighOut = `192.168.64.12 dev kairoslab0 lladdr 52:54:00:12:34:56 REACHABLE
192.168.64.13 lladdr 52:54:00:ab:cd:ef STALE
192.168.64.14 dev kairoslab0 FAILED
fe80::5054:ff:fe99:8877 dev kairoslab0 lladdr 52:54:00:99:88:77 router STALE
192.168.64.15 dev kairoslab0 lladdr 52:54:00:99:88:77 REACHABLE
192.168.64.16 dev kairoslab0 lladdr 52:54:00:de:ad:01 REACHABLE proto kernel
`

func TestParseDarwinLeases(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		mac     string
		want    string
	}{
		{"file strips leading zeroes, needle is padded", darwinLeasesOut, "52:54:00:12:34:56", "192.168.64.12"},
		{"needle stripped the same way the file is", darwinLeasesOut, "52:54:0:12:34:56", "192.168.64.12"},
		{"needle in upper case", darwinLeasesOut, "52:54:00:AB:CD:EF", "192.168.64.13"},
		{"record with no name line", darwinLeasesOut, "52:54:00:ab:cd:ef", "192.168.64.13"},
		{"dhcpv6 record is skipped even though its identifier is a real mac", darwinLeasesOut, "52:54:00:99:88:77", ""},
		{"match is on hw_address", darwinLeasesOut, "52:54:00:aa:bb:cc", "192.168.64.15"},
		{"a differing identifier is never the match", darwinLeasesOut, "52:54:00:dd:ee:ff", ""},
		{"a six-octet dhcpv6 duid is still not an ethernet address", darwinLeasesShortDUID, "00:02:00:00:ab:cd", ""},
		{"empty content", "", "52:54:00:12:34:56", ""},
		{"no record for this mac", darwinLeasesOut, "52:54:00:00:00:01", ""},
		{"record cut off mid-write still counts", darwinLeasesTruncated, "52:54:00:11:22:33", "192.168.64.20"},
		{"empty needle against malformed hw_address records", darwinLeasesMalformed, "", ""},
		{"empty needle against well formed records", darwinLeasesOut, "", ""},
		{"garbage needle", darwinLeasesOut, "not-a-mac", ""},
		{"an ipv6 address is not an answer", darwinLeasesV6Address, "52:54:00:be:ef:01", ""},
		{"ragged input does not panic", "{\n}\n}\n=\n\t=\nhw_address\n{", "52:54:00:12:34:56", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseDarwinLeases(tc.content, tc.mac); got != tc.want {
				t.Errorf("parseDarwinLeases(..., %q) = %q, want %q", tc.mac, got, tc.want)
			}
		})
	}
}

func TestParseDnsmasqLeases(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		mac     string
		want    string
	}{
		{"ordinary lease", dnsmasqLeasesOut, "52:54:00:12:34:56", "192.168.64.12"},
		{"lease with no hostname and no client id", dnsmasqLeasesOut, "52:54:00:ab:cd:ef", "192.168.64.13"},
		{"file is padded, needle is stripped", dnsmasqLeasesOut, "52:54:0:ab:cd:ef", "192.168.64.13"},
		{"the bare duid line is not a lease", dnsmasqLeasesOut, "00:01:00:01:2d:9e", ""},
		{"a duid-shaped needle is not a mac", dnsmasqLeasesOut, "00:01:00:01:2d:9e:3f:aa", ""},
		{"the ipv6 lease names an iaid, not a nic", dnsmasqLeasesOut, "00:00:00:01:51:80", ""},
		{"a line torn mid-write has no address to give", dnsmasqLeasesOut, "52:54:00:99:88:77", ""},
		{"an ipv6 address is not an answer", dnsmasqLeaseV6WithMAC, "52:54:00:be:ef:01", ""},
		{"empty content", "", "52:54:00:12:34:56", ""},
		{"no lease for this mac", dnsmasqLeasesOut, "52:54:00:00:00:01", ""},
		{"empty needle", dnsmasqLeasesOut, "", ""},
		{"garbage needle", dnsmasqLeasesOut, "not-a-mac", ""},
		{"ragged input does not panic", "\n \n1716915600\nduid\n", "52:54:00:12:34:56", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseDnsmasqLeases(tc.content, tc.mac); got != tc.want {
				t.Errorf("parseDnsmasqLeases(..., %q) = %q, want %q", tc.mac, got, tc.want)
			}
		})
	}
}

func TestParseDarwinARP(t *testing.T) {
	const incompleteOnly = "? (192.168.64.14) at (incomplete) on bridge100 [ethernet]\n"
	for _, tc := range []struct {
		name string
		out  string
		mac  string
		want string
	}{
		{"entry with ifscope and ethernet suffixes", arpDarwinOut, "52:54:00:12:34:56", "192.168.64.12"},
		{"entry that is permanent and published", arpDarwinOut, "52:54:00:ab:cd:ef", "192.168.64.13"},
		{"entry with no on <ifname>", arpDarwinOut, "52:54:00:aa:bb:cc", "192.168.64.15"},
		{"arp strips leading zeroes too", arpDarwinOut, "52:54:0:12:34:56", "192.168.64.12"},
		{"an incomplete entry has no address to match", incompleteOnly, "52:54:00:12:34:56", ""},
		{"an empty needle must not match an incomplete entry", incompleteOnly, "", ""},
		{"a multicast entry is not a guest", arpDarwinOut, "01:00:5e:00:00:fb", ""},
		{"empty output", "", "52:54:00:12:34:56", ""},
		{"no entry for this mac", arpDarwinOut, "52:54:00:00:00:01", ""},
		{"garbage needle", arpDarwinOut, "not-a-mac", ""},
		{"ragged input does not panic", " at \n? () at \nat\n? (x) at y\n", "52:54:00:12:34:56", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseDarwinARP(tc.out, tc.mac); got != tc.want {
				t.Errorf("parseDarwinARP(..., %q) = %q, want %q", tc.mac, got, tc.want)
			}
		})
	}
}

func TestParseLinuxNeigh(t *testing.T) {
	const failedOnly = "192.168.64.14 dev kairoslab0 FAILED\n"
	for _, tc := range []struct {
		name string
		out  string
		mac  string
		want string
	}{
		{"entry with the dev token", ipNeighOut, "52:54:00:12:34:56", "192.168.64.12"},
		{"entry without the dev token", ipNeighOut, "52:54:00:ab:cd:ef", "192.168.64.13"},
		{"the ipv6 neighbour for the same nic is skipped", ipNeighOut, "52:54:00:99:88:77", "192.168.64.15"},
		{"entry with a proto suffix", ipNeighOut, "52:54:00:de:ad:01", "192.168.64.16"},
		{"neigh pads, needle is stripped", ipNeighOut, "52:54:0:12:34:56", "192.168.64.12"},
		{"a FAILED entry carries no lladdr", failedOnly, "52:54:00:12:34:56", ""},
		{"an empty needle must not match a FAILED entry", failedOnly, "", ""},
		{"empty output", "", "52:54:00:12:34:56", ""},
		{"no entry for this mac", ipNeighOut, "52:54:00:00:00:01", ""},
		{"garbage needle", ipNeighOut, "not-a-mac", ""},
		{"ragged input does not panic", "192.168.64.1\nlladdr\n192.168.64.2 lladdr\n\n", "52:54:00:12:34:56", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseLinuxNeigh(tc.out, tc.mac); got != tc.want {
				t.Errorf("parseLinuxNeigh(..., %q) = %q, want %q", tc.mac, got, tc.want)
			}
		})
	}
}

// TestUsableIPv4 pins the address rule the four parsers share. Every rejected
// value below is one a real source carries: an ARP table holds multicast and
// broadcast entries, a neighbour table is mostly IPv6, and a guest that never
// got a lease reports 0.0.0.0 through the guest agent.
func TestUsableIPv4(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		{"192.168.64.12", "192.168.64.12"},
		{"  192.168.64.12  ", "192.168.64.12"},
		{"169.254.10.4", "169.254.10.4"},
		{"::ffff:192.168.64.12", "192.168.64.12"},
		{"fd00:1::5", ""},
		{"fe80::5054:ff:fe99:8877", ""},
		{"127.0.0.1", ""},
		{"0.0.0.0", ""},
		{"224.0.0.251", ""},
		{"255.255.255.255", ""},
		{"", ""},
		{"not-an-address", ""},
		{"192.168.64.12/24", ""},
	} {
		if got := usableIPv4(tc.in); got != tc.want {
			t.Errorf("usableIPv4(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
