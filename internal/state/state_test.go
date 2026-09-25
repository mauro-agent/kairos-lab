package state

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadMissingReturnsDefault(t *testing.T) {
	t.Setenv("KAIROS_LAB_CONFIG_DIR", t.TempDir())
	t.Setenv("KAIROS_LAB_CACHE_DIR", t.TempDir())
	store, err := DefaultStore()
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if st.Version != SchemaVersion {
		t.Fatalf("unexpected version: %d", st.Version)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	t.Setenv("KAIROS_LAB_CONFIG_DIR", t.TempDir())
	t.Setenv("KAIROS_LAB_CACHE_DIR", t.TempDir())
	store, err := DefaultStore()
	if err != nil {
		t.Fatal(err)
	}
	st := NewState(store)
	st.Platform.OS = "linux"
	st.Setup.InstalledByKairosLab = []string{"qemu"}
	stateFile := filepath.Join(store.ConfigDir, "state.json")
	if err := store.Save(st); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stateFile); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Platform.OS != "linux" {
		t.Fatalf("platform mismatch: %s", loaded.Platform.OS)
	}
	if len(loaded.Setup.InstalledByKairosLab) != 1 || loaded.Setup.InstalledByKairosLab[0] != "qemu" {
		t.Fatalf("dependencies mismatch: %#v", loaded.Setup.InstalledByKairosLab)
	}
}

func TestSaveLoadRoundTripKeepsMACAndIP(t *testing.T) {
	t.Setenv("KAIROS_LAB_CONFIG_DIR", t.TempDir())
	t.Setenv("KAIROS_LAB_CACHE_DIR", t.TempDir())
	store, err := DefaultStore()
	if err != nil {
		t.Fatal(err)
	}
	st := NewState(store)
	AddDisk(st, Disk{
		Name:      "kairos-core-20250101-120000",
		Path:      "/tmp/kairos.qcow2",
		CreatedAt: "2025-01-01T12:00:00Z",
		Size:      "60G",
		MAC:       "52:54:00:ab:cd:ef",
	})
	st.VM.IPAddress = "192.168.64.7"
	if err := store.Save(st); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	disk := FindDiskByName(loaded, "kairos-core-20250101-120000")
	if disk == nil {
		t.Fatal("disk missing after reload")
	}
	if disk.MAC != "52:54:00:ab:cd:ef" {
		t.Errorf("disk MAC = %q, want 52:54:00:ab:cd:ef", disk.MAC)
	}
	if loaded.VM.IPAddress != "192.168.64.7" {
		t.Errorf("vm IP address = %q, want 192.168.64.7", loaded.VM.IPAddress)
	}
}

func TestLoadStateWrittenBeforeMACField(t *testing.T) {
	// A disk recorded before the mac field existed has no such key at all. It
	// must load without error and simply arrive with an empty MAC, which a
	// later start fills in; there is no migration and no schema bump.
	t.Setenv("KAIROS_LAB_CONFIG_DIR", t.TempDir())
	t.Setenv("KAIROS_LAB_CACHE_DIR", t.TempDir())
	store, err := DefaultStore()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(store.ConfigDir, 0o755); err != nil {
		t.Fatal(err)
	}
	legacy := `{"version":1,"disks":[{"name":"old","path":"/tmp/old.qcow2","created_at":"2025-01-01T00:00:00Z","size":"60G"}]}`
	if err := os.WriteFile(filepath.Join(store.ConfigDir, "state.json"), []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := store.Load()
	if err != nil {
		t.Fatalf("loading a pre-MAC state file should succeed: %v", err)
	}
	disk := FindDiskByName(st, "old")
	if disk == nil {
		t.Fatal("disk \"old\" missing from the loaded state")
	}
	if disk.MAC != "" {
		t.Errorf("disk MAC = %q, want empty for a pre-MAC state file", disk.MAC)
	}
	if st.VM.IPAddress != "" {
		t.Errorf("vm IP address = %q, want empty for a pre-MAC state file", st.VM.IPAddress)
	}
}
