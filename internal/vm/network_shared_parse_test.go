package vm

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestSharedLeaseFilePath(t *testing.T) {
	tests := []struct {
		name  string
		iface string
		want  string
	}{
		{
			name:  "bridge carrying the shared method",
			iface: "kairoslab0",
			want:  "/var/lib/NetworkManager/dnsmasq-kairoslab0.leases",
		},
		{
			// An empty interface means nothing received the method yet, so
			// there is no lease file to name. Returning the directory with a
			// bare "dnsmasq-.leases" in it would give a reader a path that
			// looks real and never exists.
			name:  "empty iface",
			iface: "",
			want:  "",
		},
		{
			// Hyphens are ordinary characters in the template; the default tap
			// name has one, and it is the interface the method would land on
			// if the shared method ever moved off the bridge.
			name:  "hyphenated interface name",
			iface: "kairoslab-tap0",
			want:  "/var/lib/NetworkManager/dnsmasq-kairoslab-tap0.leases",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sharedLeaseFilePath(tt.iface); got != tt.want {
				t.Errorf("sharedLeaseFilePath(%q) = %q, want %q", tt.iface, got, tt.want)
			}
		})
	}
}

// The lease file is per interface, so the path is only right for the interface
// that actually received ipv4.method shared. A resolver handed the wrong one
// reads the wrong file rather than failing, which is why PrepareLinuxShared
// stores the path it computed instead of letting readers rebuild it.
func TestSharedLeaseFilePathIsPerInterface(t *testing.T) {
	bridge := sharedLeaseFilePath(DefaultBridgeName)
	tap := sharedLeaseFilePath(DefaultTapName)
	if bridge == tap {
		t.Errorf("lease path for %q and %q are both %q, want distinct files",
			DefaultBridgeName, DefaultTapName, bridge)
	}
}

// The three strings below are the ones that were demonstrated to reach a
// root-run command, a path join outside NMSTATEDIR, and the terminal a
// consent prompt is printed to. They are spelled out here rather than
// described so a future relaxation of the rule has to delete a named attack.
const (
	// A real NetworkManager profile name on most desktops. As a stored bridge
	// name it becomes `sudo nmcli connection delete Wired connection 1` and
	// `sudo ip link delete Wired connection 1`.
	attackNMProfileName = "Wired connection 1"
	// sharedLeaseFilePath would join this to /var/lib/NetworkManager and
	// clean it down to /var/lib/etc/shadow.leases, outside NMSTATEDIR.
	attackPathTraversal = "../../../etc/shadow"
	// A forged cleanup-plan row followed by CSI 2K CR, which erases the real
	// row printed after it. Written with Go escapes: no raw control byte ever
	// appears in this source file.
	attackPlanRowInjection = "kairoslab0\n  - eth0 (will be KEPT)\x1b[2K\r"
)

func TestValidateStoredInterfaceNameAccepts(t *testing.T) {
	names := []string{
		DefaultBridgeName,
		DefaultTapName,
		"eth0",
		"enp0s31f6",
		"br-0_1",
		"a",
		"012345678901234", // exactly IFNAMSIZ-1 bytes
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			if err := validateStoredInterfaceName("bridge name", name); err != nil {
				t.Errorf("validateStoredInterfaceName(%q) = %v, want nil", name, err)
			}
		})
	}
}

func TestValidateStoredInterfaceNameRejects(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"empty", ""},
		{"dot", "."},
		{"dot dot", ".."},
		{"too long by one", "0123456789012345"},
		{"embedded space splits an argv", attackNMProfileName},
		{"path traversal escapes NMSTATEDIR", attackPathTraversal},
		{"newline and CSI forge a plan row", attackPlanRowInjection},
		{"shell metacharacters", "eth0;reboot"},
		{"slash", "net/eth0"},
		{"leading dash looks like a flag", "--help"},
		{"non-ascii rune", "eth\u00f80"},
		{"nul-ish control byte", "eth0\x00"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateStoredInterfaceName("bridge name", tt.value)
			if err == nil {
				t.Fatalf("validateStoredInterfaceName(%q) = nil, want an error", tt.value)
			}
			msg := err.Error()
			if !strings.Contains(msg, "bridge name") {
				t.Errorf("error does not name the field it came from: %q", msg)
			}
			if !strings.Contains(msg, "stored configuration") {
				t.Errorf("error does not say the value came from stored configuration: %q", msg)
			}
			// The rejected value is quoted with %q, so reporting it cannot
			// itself deliver the escape sequence that got it rejected.
			for _, r := range msg {
				if r < 0x20 || r == 0x7f {
					t.Errorf("error message carries raw control byte %#x: %q", r, msg)
				}
			}
		})
	}
}

// "--help" is rejected above for its leading dash, so the reader does not have
// to reason about whether nmcli would treat a stored name as a flag. This
// pins that the value is still reported, since an error that hides what it
// rejected sends the user looking in the wrong file.
func TestValidateStoredInterfaceNameReportsTheValue(t *testing.T) {
	err := validateStoredInterfaceName("tap name", attackNMProfileName)
	if err == nil {
		t.Fatal("want an error")
	}
	if !strings.Contains(err.Error(), attackNMProfileName) {
		t.Errorf("error %q does not contain the rejected value %q", err, attackNMProfileName)
	}
	if !strings.Contains(err.Error(), "tap name") {
		t.Errorf("error %q does not name the tap name field", err)
	}
}

// The traversal case is the reason the validator runs before
// sharedLeaseFilePath rather than after it: the join cannot be made safe on
// its own, because cleaning the result is exactly what performs the escape.
func TestSharedLeaseFilePathEscapesWithoutValidation(t *testing.T) {
	got := sharedLeaseFilePath(attackPathTraversal)
	if strings.HasPrefix(got, nmStateDir+"/") {
		t.Fatalf("sharedLeaseFilePath(%q) = %q, expected it to escape %q -- if this now stays inside the directory, the validator is no longer the only thing keeping it there",
			attackPathTraversal, got, nmStateDir)
	}
	if got != "/var/lib/etc/shadow.leases" {
		t.Errorf("sharedLeaseFilePath(%q) = %q, want %q", attackPathTraversal, got, "/var/lib/etc/shadow.leases")
	}
	// Every name the validator does accept stays inside NMSTATEDIR.
	for _, name := range []string{DefaultBridgeName, DefaultTapName, "eth0"} {
		if err := validateStoredInterfaceName("bridge name", name); err != nil {
			t.Fatalf("fixture %q is not accepted: %v", name, err)
		}
		p := sharedLeaseFilePath(name)
		if filepath.Dir(p) != nmStateDir {
			t.Errorf("sharedLeaseFilePath(%q) = %q, outside %q", name, p, nmStateDir)
		}
	}
}
