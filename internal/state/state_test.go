package state

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	// must load without error and simply arrive with an empty MAC, which the
	// start path will fill in once it is wired up to do so; there is no
	// migration and no schema bump.
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

// TestStateJSONKeysForMACAndIP pins the on-disk JSON contract for the two
// fields added with the per-VM MAC work: the key names themselves, and the
// omitempty that keeps them out of a file where they carry no value. Renaming
// either key, or dropping omitempty from either, leaves every round-trip test
// green because those only ever go through this package's own structs -- so
// this test reads the raw bytes instead.
func TestStateJSONKeysForMACAndIP(t *testing.T) {
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
	})
	if err := store.Save(st); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(store.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"mac"`, `"ip_address"`} {
		if strings.Contains(string(raw), key) {
			t.Errorf("state.json should omit %s when the value is empty, got:\n%s", key, raw)
		}
	}

	st.Disks[0].MAC = "52:54:00:ab:cd:ef"
	st.VM.IPAddress = "192.168.64.7"
	if err := store.Save(st); err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile(store.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"mac"`, `"ip_address"`} {
		if !strings.Contains(string(raw), key) {
			t.Errorf("state.json should carry the %s key once it has a value, got:\n%s", key, raw)
		}
	}
}

// blockedStore returns a store that shares cfg's directories but whose state
// path is an existing directory. os.Rename can never take over a directory
// name, so a Save through the returned store is guaranteed to fail at exactly
// the point this package cares about -- after the temporary file exists --
// without mocking the filesystem out from under it.
func blockedStore(t *testing.T, cfg *Store) *Store {
	t.Helper()
	blocked := filepath.Join(cfg.ConfigDir, "blocked-state.json")
	if err := os.MkdirAll(blocked, 0o755); err != nil {
		t.Fatal(err)
	}
	return &Store{ConfigDir: cfg.ConfigDir, CacheDir: cfg.CacheDir, StatePath: blocked}
}

// TestSaveFailureLeavesPreviousStateIntact is the whole point of writing
// through a rename: a save that cannot complete must leave the file that was
// already on disk byte-for-byte as it was, still parseable by the next reader,
// rather than the truncated stump a failed in-place write would leave behind.
func TestSaveFailureLeavesPreviousStateIntact(t *testing.T) {
	t.Setenv("KAIROS_LAB_CONFIG_DIR", t.TempDir())
	t.Setenv("KAIROS_LAB_CACHE_DIR", t.TempDir())
	store, err := DefaultStore()
	if err != nil {
		t.Fatal(err)
	}
	st := NewState(store)
	st.Platform.OS = "linux"
	st.VM.IPAddress = "192.168.64.7"
	if err := store.Save(st); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(store.StatePath)
	if err != nil {
		t.Fatal(err)
	}

	doomed := blockedStore(t, store)
	st.Platform.OS = "darwin"
	if err := doomed.Save(st); err == nil {
		t.Fatal("saving onto a directory should fail")
	}

	after, err := os.ReadFile(store.StatePath)
	if err != nil {
		t.Fatalf("the previous state file should still be readable: %v", err)
	}
	if string(after) != string(before) {
		t.Errorf("a failed save rewrote the previous state file:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("the previous state file should still parse: %v", err)
	}
	if loaded.Platform.OS != "linux" || loaded.VM.IPAddress != "192.168.64.7" {
		t.Errorf("previous state changed: os = %q, ip = %q", loaded.Platform.OS, loaded.VM.IPAddress)
	}
}

// TestSaveFailureLeavesNoTemporaryFile pins the cleanup half of the rename
// dance. The temporary file is created in the config dir, so forgetting to
// remove it on failure would slowly fill a directory the user actually looks
// at with state.json.tmp-* debris.
func TestSaveFailureLeavesNoTemporaryFile(t *testing.T) {
	t.Setenv("KAIROS_LAB_CONFIG_DIR", t.TempDir())
	t.Setenv("KAIROS_LAB_CACHE_DIR", t.TempDir())
	store, err := DefaultStore()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(NewState(store)); err != nil {
		t.Fatal(err)
	}

	doomed := blockedStore(t, store)
	for i := 0; i < 3; i++ {
		if err := doomed.Save(NewState(store)); err == nil {
			t.Fatal("saving onto a directory should fail")
		}
	}

	entries, err := os.ReadDir(store.ConfigDir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	want := []string{"blocked-state.json", "state.json"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Errorf("config dir contents = %v, want %v", names, want)
	}
}

// TestSaveLoadRoundTripKeepsFileMode guards the mode the rename path has to
// restore by hand: os.CreateTemp makes a 0600 file, while state.json has
// always been 0644.
func TestSaveLoadRoundTripKeepsFileMode(t *testing.T) {
	t.Setenv("KAIROS_LAB_CONFIG_DIR", t.TempDir())
	t.Setenv("KAIROS_LAB_CACHE_DIR", t.TempDir())
	store, err := DefaultStore()
	if err != nil {
		t.Fatal(err)
	}
	st := NewState(store)
	st.Platform.Arch = "arm64"
	if err := store.Save(st); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Platform.Arch != "arm64" {
		t.Errorf("arch = %q, want arm64", loaded.Platform.Arch)
	}
	info, err := os.Stat(store.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o644 {
		t.Errorf("state file mode = %04o, want 0644", perm)
	}
	// A second save renames a fresh temporary file over the first one, so the
	// mode has to survive the replacement too, not just the initial create.
	if err := store.Save(st); err != nil {
		t.Fatal(err)
	}
	info, err = os.Stat(store.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o644 {
		t.Errorf("state file mode after re-save = %04o, want 0644", perm)
	}
}

// TestConcurrentSaveAndLoad reproduces the situation the rename exists for: a
// reader (`kairos-lab status` in another terminal) hitting state.json while a
// writer is replacing it. Every Load must return a fully parsed state -- never
// a parse error from a truncated file. The saved payload changes length from
// iteration to iteration so that a partially written file would be visibly
// malformed rather than accidentally valid JSON.
func TestConcurrentSaveAndLoad(t *testing.T) {
	t.Setenv("KAIROS_LAB_CONFIG_DIR", t.TempDir())
	t.Setenv("KAIROS_LAB_CACHE_DIR", t.TempDir())
	store, err := DefaultStore()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(NewState(store)); err != nil {
		t.Fatal(err)
	}

	const saves = 50
	const loads = 200
	saveErrs := make(chan error, saves)
	loadErrs := make(chan error, loads)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < saves; i++ {
			st := NewState(store)
			st.VM.LastError = strings.Repeat("x", i*8)
			if err := store.Save(st); err != nil {
				saveErrs <- err
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < loads; i++ {
			if _, err := store.Load(); err != nil {
				loadErrs <- err
				return
			}
		}
	}()
	wg.Wait()
	close(saveErrs)
	close(loadErrs)

	for err := range saveErrs {
		t.Errorf("concurrent save failed: %v", err)
	}
	for err := range loadErrs {
		t.Errorf("concurrent load could not read the state file: %v", err)
	}
}
