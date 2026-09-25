package vm

import (
	"strconv"
	"strings"
	"testing"
)

func TestMACForDiskShape(t *testing.T) {
	mac := MACForDisk("kairos-core-20250101-120000")
	if !strings.HasPrefix(mac, "52:54:00:") {
		t.Fatalf("MAC %q should carry the 52:54:00 QEMU prefix", mac)
	}
	octets := strings.Split(mac, ":")
	if len(octets) != 6 {
		t.Fatalf("MAC %q should have 6 octets, got %d", mac, len(octets))
	}
	for _, octet := range octets {
		if len(octet) != 2 {
			t.Errorf("octet %q of %q should be zero-padded to 2 digits", octet, mac)
		}
		if _, err := strconv.ParseUint(octet, 16, 8); err != nil {
			t.Errorf("octet %q of %q is not hex: %v", octet, mac, err)
		}
	}
}

func TestMACForDiskFirstOctetBits(t *testing.T) {
	// The bits are the property that matters, not the literal prefix: bit 0
	// clear means unicast, bit 1 set means locally administered (RFC 7042
	// section 2.1), which is what keeps the address off any vendor's range.
	first := strings.Split(MACForDisk("kairos-core-20250101-120000"), ":")[0]
	b, err := strconv.ParseUint(first, 16, 8)
	if err != nil {
		t.Fatalf("first octet %q is not hex: %v", first, err)
	}
	if b&0x01 != 0 {
		t.Errorf("first octet %#x has the multicast bit set, want unicast", b)
	}
	if b&0x02 != 0x02 {
		t.Errorf("first octet %#x is not locally administered", b)
	}
}

func TestMACForDiskIsStable(t *testing.T) {
	// The guest must present the same address after a restart or it loses its
	// DHCP lease.
	const disk = "kairos-core-20250101-120000"
	if first, second := MACForDisk(disk), MACForDisk(disk); first != second {
		t.Fatalf("MAC for %q changed between calls: %q then %q", disk, first, second)
	}
}

func TestMACForDiskIsDistinctPerDisk(t *testing.T) {
	a := MACForDisk("kairos-core-20250101-120000")
	b := MACForDisk("kairos-core-20250101-120001")
	if a == b {
		t.Fatalf("different disks share the MAC %q", a)
	}
}

func TestNormalizeMAC(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{"linux zero-padded form", "52:54:00:12:34:56", "52:54:0:12:34:56"},
		{"macos stripped form", "52:54:0:12:34:56", "52:54:0:12:34:56"},
		{"all-zero octet keeps one digit", "0:0:0:0:0:0", "0:0:0:0:0:0"},
		{"padded all-zero octet", "00:00:00:00:00:00", "0:0:0:0:0:0"},
		{"leading zero stripped", "52:54:00:0a:04:0f", "52:54:0:a:4:f"},
		{"uppercase lowercased", "52:54:00:AB:CD:EF", "52:54:0:ab:cd:ef"},
		{"surrounding whitespace trimmed", "  52:54:00:12:34:56\n", "52:54:0:12:34:56"},
		{"empty string", "", ""},
		{"not a mac", "not-a-mac", ""},
		{"five octets", "52:54:00:12:34", ""},
		{"seven octets", "52:54:00:12:34:56:78", ""},
		{"three-digit octet", "52:54:000:12:34:56", ""},
		{"empty octet", "52:54::12:34:56", ""},
		{"non-hex octet", "52:54:00:12:34:zz", ""},
		{"dash separated", "52-54-00-12-34-56", ""},
	} {
		if got := NormalizeMAC(tc.in); got != tc.want {
			t.Errorf("%s: NormalizeMAC(%q) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
	}
}

func TestNormalizeMACPaddedAndStrippedAgree(t *testing.T) {
	// The whole point of the normaliser: a lease file written by macOS and a
	// MAC written by us must compare equal.
	padded := NormalizeMAC("52:54:00:12:34:56")
	stripped := NormalizeMAC("52:54:0:12:34:56")
	if padded == "" {
		t.Fatal("padded form should normalise to a non-empty value")
	}
	if padded != stripped {
		t.Fatalf("padded %q and stripped %q should normalise alike", padded, stripped)
	}
}

func TestNormalizeMACRoundTripsGeneratedMAC(t *testing.T) {
	mac := MACForDisk("kairos-core-20250101-120000")
	if got := NormalizeMAC(mac); got == "" {
		t.Fatalf("generated MAC %q should normalise", mac)
	}
}
