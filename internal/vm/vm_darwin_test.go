//go:build darwin

package vm

import (
	"runtime"
	"strings"
	"testing"
)

func macOSBridgeConfig(iface string) StartConfig {
	return StartConfig{
		DiskPath:      "/tmp/kairos.qcow2",
		QGASocketPath: "/tmp/kairos.sock",
		CPUs:          2,
		MemoryMB:      4096,
		NetworkMode:   "bridged",
		MacOSBiosPath: "/opt/homebrew/share/qemu/edk2-aarch64-code.fd",
		BridgeIface:   iface,
	}
}

// The old code silently substituted en0 here, which is how a VM ended up
// bridged onto an unplugged port (kairos-io/kairos#4431).
func TestBuildMacOSRejectsUnresolvedBridgeIface(t *testing.T) {
	if runtime.GOARCH != "arm64" {
		t.Skip("macOS support is Apple Silicon only")
	}
	_, args, err := buildMacOS(macOSBridgeConfig(""))
	if err == nil {
		t.Fatalf("expected an error for an unresolved bridge interface, got args: %v", args)
	}
	if !strings.Contains(err.Error(), "bridge interface") {
		t.Errorf("error %q should name the missing bridge interface", err)
	}
}

func TestBuildMacOSUsesResolvedBridgeIface(t *testing.T) {
	if runtime.GOARCH != "arm64" {
		t.Skip("macOS support is Apple Silicon only")
	}
	_, args, err := buildMacOS(macOSBridgeConfig("en1"))
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "vmnet-bridged,id=net0,ifname=en1") {
		t.Fatalf("expected the resolved interface in args: %s", joined)
	}
	if strings.Contains(joined, "ifname=en0") {
		t.Fatalf("en0 should no longer be substituted: %s", joined)
	}
}

// User mode needs no interface at all, so it must not be caught by the check.
func TestBuildMacOSUserModeNeedsNoBridgeIface(t *testing.T) {
	if runtime.GOARCH != "arm64" {
		t.Skip("macOS support is Apple Silicon only")
	}
	cfg := macOSBridgeConfig("")
	cfg.NetworkMode = "user"
	_, args, err := buildMacOS(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(args, " "), "hostfwd=tcp::2222-:22") {
		t.Fatalf("expected the user-mode port forwards: %v", args)
	}
}

func TestBuildMacOSSharedModeUsesVmnetShared(t *testing.T) {
	if runtime.GOARCH != "arm64" {
		t.Skip("macOS support is Apple Silicon only")
	}
	cfg := macOSBridgeConfig("")
	cfg.NetworkMode = "shared"
	cfg.MACAddress = testMACAddress
	_, args, err := buildMacOS(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got := argAfter(t, args, "-netdev"); got != "vmnet-shared,id=net0" {
		t.Errorf("-netdev = %q, want vmnet-shared,id=net0", got)
	}
	wantDevice := "virtio-net-pci,netdev=net0,mac=" + testMACAddress
	if got := nicDeviceArg(t, args); got != wantDevice {
		t.Errorf("NIC device = %q, want %q", got, wantDevice)
	}
}

// vmnet-shared attaches to no host interface: NetdevVmnetSharedOptions has no
// ifname member, and QEMU's opts visitor rejects a leftover key with "Invalid
// parameter", so an ifname here aborts the VM at startup rather than being
// ignored. The assertion is deliberately over the whole command line.
func TestBuildMacOSSharedModePassesNoIfname(t *testing.T) {
	if runtime.GOARCH != "arm64" {
		t.Skip("macOS support is Apple Silicon only")
	}
	cfg := macOSBridgeConfig("en1")
	cfg.NetworkMode = "shared"
	_, args, err := buildMacOS(cfg)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "ifname=") {
		t.Fatalf("shared mode must pass no ifname: QEMU has no ifname option for "+
			"vmnet-shared and aborts at startup on the unknown key, args: %s", joined)
	}
}

// The bridged-only guard must not catch the modes that need no interface.
func TestBuildMacOSSharedAndUserNeedNoBridgeIface(t *testing.T) {
	if runtime.GOARCH != "arm64" {
		t.Skip("macOS support is Apple Silicon only")
	}
	for _, mode := range []string{"shared", "user"} {
		cfg := macOSBridgeConfig("")
		cfg.NetworkMode = mode
		if _, _, err := buildMacOS(cfg); err != nil {
			t.Errorf("%s mode should not need a bridge interface: %v", mode, err)
		}
	}
}

func TestBuildMacOSBridgedCarriesMAC(t *testing.T) {
	if runtime.GOARCH != "arm64" {
		t.Skip("macOS support is Apple Silicon only")
	}
	cfg := macOSBridgeConfig("en1")
	cfg.MACAddress = testMACAddress
	_, args, err := buildMacOS(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got := argAfter(t, args, "-netdev"); got != "vmnet-bridged,id=net0,ifname=en1" {
		t.Errorf("-netdev = %q, want vmnet-bridged,id=net0,ifname=en1", got)
	}
	wantDevice := "virtio-net-pci,netdev=net0,mac=" + testMACAddress
	if got := nicDeviceArg(t, args); got != wantDevice {
		t.Errorf("NIC device = %q, want %q", got, wantDevice)
	}
}

// Without the guest-agent socket the IP resolver loses its QGA source on
// macOS entirely, so this has to match what buildLinux emits.
func TestBuildMacOSIncludesGuestAgent(t *testing.T) {
	if runtime.GOARCH != "arm64" {
		t.Skip("macOS support is Apple Silicon only")
	}
	_, args, err := buildMacOS(macOSBridgeConfig("en1"))
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"socket,path=/tmp/kairos.sock,server=on,wait=off,id=qga0",
		"virtio-serial",
		"virtserialport,chardev=qga0,name=org.qemu.guest_agent.0",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("expected %q in args: %s", want, joined)
		}
	}
}
