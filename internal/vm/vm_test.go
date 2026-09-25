package vm

import (
	"runtime"
	"strings"
	"testing"
)

func TestBuildLinuxCommandIncludesTapInBridgeMode(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only test")
	}
	_, args, err := buildLinux(StartConfig{
		ISOPath:       "/tmp/kairos.iso",
		DiskPath:      "/tmp/kairos.qcow2",
		QGASocketPath: "/tmp/kairos.sock",
		CPUs:          2,
		MemoryMB:      4096,
		NetworkMode:   "bridged",
		LinuxTapName:  "kairoslab-tap0",
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "ifname=kairoslab-tap0") {
		t.Fatalf("expected tap interface in args: %s", joined)
	}
}

func TestBuildLinuxCommandFailsWithoutTapInBridgeMode(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only test")
	}
	_, _, err := buildLinux(StartConfig{NetworkMode: "bridged"})
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestBuildLinuxCommandSerialDisplayUsesNographic(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only test")
	}
	_, args, err := buildLinux(StartConfig{
		ISOPath:       "/tmp/kairos.iso",
		DiskPath:      "/tmp/kairos.qcow2",
		QGASocketPath: "/tmp/kairos.sock",
		CPUs:          2,
		MemoryMB:      4096,
		NetworkMode:   "user",
		DisplayMode:   "serial",
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "-nographic") {
		t.Fatalf("expected -nographic for serial display mode: %s", joined)
	}
}

func TestBuildLinuxCommandWindowDisplayOmitsNographic(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only test")
	}
	_, args, err := buildLinux(StartConfig{
		ISOPath:       "/tmp/kairos.iso",
		DiskPath:      "/tmp/kairos.qcow2",
		QGASocketPath: "/tmp/kairos.sock",
		CPUs:          2,
		MemoryMB:      4096,
		NetworkMode:   "user",
		DisplayMode:   "window",
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "-nographic") {
		t.Fatalf("did not expect -nographic for window display mode: %s", joined)
	}
	if !strings.Contains(joined, "-display default") {
		t.Fatalf("expected explicit display backend for window display mode: %s", joined)
	}
	if runtime.GOARCH == "arm64" && !strings.Contains(joined, "virtio-gpu-pci") {
		t.Fatalf("expected virtio-gpu-pci for arm64 window display mode: %s", joined)
	}
}

// testMACAddress is a fixed literal rather than a MACForDisk call: these tests
// pin how a MAC reaches the command line, not how one is derived.
const testMACAddress = "52:54:00:aa:bb:cc"

// argAfter returns the single value following flag in args.
func argAfter(t *testing.T, args []string, flag string) string {
	t.Helper()
	for i, a := range args {
		if a == flag {
			if i+1 >= len(args) {
				t.Fatalf("%s is the last argument, it has no value: %v", flag, args)
			}
			return args[i+1]
		}
	}
	t.Fatalf("%s missing from args: %v", flag, args)
	return ""
}

// nicDeviceArg returns the -device value that configures the guest NIC. There
// are several -device arguments, so it matches on the device model.
func nicDeviceArg(t *testing.T, args []string) string {
	t.Helper()
	for _, a := range args {
		if strings.HasPrefix(a, "virtio-net-pci") {
			return a
		}
	}
	t.Fatalf("no virtio-net-pci device in args: %v", args)
	return ""
}

func TestBuildLinuxNetdevPerNetworkMode(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only test")
	}
	// shared and bridged are the same command line on Linux: both hand the
	// guest a tap on a NetworkManager bridge, and only the bridge's own IPv4
	// method differs, which is not configured here.
	const tapNetdev = "tap,id=net0,ifname=kairoslab-tap0,script=no,downscript=no"
	for _, tc := range []struct {
		mode       string
		wantNetdev string
	}{
		{"shared", tapNetdev},
		{"bridged", tapNetdev},
		{"user", "user,id=net0,hostfwd=tcp::2222-:22,hostfwd=tcp::8080-:8080"},
	} {
		_, args, err := buildLinux(StartConfig{
			ISOPath:       "/tmp/kairos.iso",
			DiskPath:      "/tmp/kairos.qcow2",
			QGASocketPath: "/tmp/kairos.sock",
			CPUs:          2,
			MemoryMB:      4096,
			NetworkMode:   tc.mode,
			LinuxTapName:  "kairoslab-tap0",
			MACAddress:    testMACAddress,
		})
		if err != nil {
			t.Errorf("%s mode: %v", tc.mode, err)
			continue
		}
		if got := argAfter(t, args, "-netdev"); got != tc.wantNetdev {
			t.Errorf("%s mode: -netdev = %q, want %q", tc.mode, got, tc.wantNetdev)
		}
		wantDevice := "virtio-net-pci,netdev=net0,mac=" + testMACAddress
		if got := nicDeviceArg(t, args); got != wantDevice {
			t.Errorf("%s mode: NIC device = %q, want %q", tc.mode, got, wantDevice)
		}
		joined := strings.Join(args, " ")
		if !strings.Contains(joined, "mac="+testMACAddress) {
			t.Errorf("%s mode: expected the configured MAC in args: %s", tc.mode, joined)
		}
	}
}

func TestBuildLinuxSharedModeRequiresTapAndNamesItself(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only test")
	}
	_, _, err := buildLinux(StartConfig{NetworkMode: "shared"})
	if err == nil {
		t.Fatal("expected an error for shared mode with no tap name")
	}
	// The error used to hardcode "bridged", which sends someone starting a
	// shared VM looking at bridged configuration they never touched.
	if !strings.Contains(err.Error(), "shared") {
		t.Errorf("error %q should name the shared mode", err)
	}
	if strings.Contains(err.Error(), "bridged") {
		t.Errorf("error %q should not name bridged for a shared start", err)
	}
}

func TestBuildLinuxEmptyMACOmitsMACEntirely(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only test")
	}
	// A caller that never sets MACAddress must degrade to QEMU's own default
	// address, not emit a dangling "mac=" that QEMU refuses to parse.
	_, args, err := buildLinux(StartConfig{
		DiskPath:      "/tmp/kairos.qcow2",
		QGASocketPath: "/tmp/kairos.sock",
		CPUs:          2,
		MemoryMB:      4096,
		NetworkMode:   "shared",
		LinuxTapName:  "kairoslab-tap0",
	})
	if err != nil {
		t.Fatal(err)
	}
	device := nicDeviceArg(t, args)
	if device != "virtio-net-pci,netdev=net0" {
		t.Errorf("NIC device = %q, want the bare device with no MAC suffix", device)
	}
	if strings.Contains(strings.Join(args, " "), "mac=") {
		t.Errorf("an empty MACAddress must not put mac= on the command line: %v", args)
	}
}
