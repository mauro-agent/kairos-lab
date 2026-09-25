package vm

import "testing"

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
