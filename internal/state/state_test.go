package state

import (
	"fmt"
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
	MutableVM(st).IPAddress = "192.168.64.7"
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
	if VMOrZero(loaded).IPAddress != "192.168.64.7" {
		t.Errorf("vm IP address = %q, want 192.168.64.7", VMOrZero(loaded).IPAddress)
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
	if VMOrZero(st).IPAddress != "" {
		t.Errorf("vm IP address = %q, want empty for a pre-MAC state file", VMOrZero(st).IPAddress)
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
	MutableVM(st).IPAddress = "192.168.64.7"
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

// sealDir makes dir unwritable for the rest of the test, so that anything
// trying to create a new entry in it -- the temporary file Save opens, in
// particular -- fails with EACCES before it has touched a single existing
// file. The restore exists because t.TempDir's own cleanup cannot remove a
// tree it is not allowed to write to and would fail the test on the way out.
// Registering it before the chmod rather than after is defensive habit and not
// the thing that makes that work: t.Cleanup runs its functions last registered
// first, and t.TempDir registered its teardown back when it created the
// directory, so a restore registered on either side of the chmod still runs
// before that teardown either way.
func sealDir(t *testing.T, dir string) {
	t.Helper()
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
}

// TestSaveFailureLeavesPreviousStateIntact is the whole point of writing
// through a rename: a save that cannot complete must leave the file that was
// already on disk byte-for-byte as it was, still parseable by the next reader,
// rather than the truncated stump a failed in-place write would leave behind.
//
// The failure is induced by sealing the directory the state file lives in,
// which is what makes this test discriminate rather than decorate. An in-place
// os.WriteFile does not need write permission on the directory to reopen a
// file that already exists and is writable by its owner -- it would truncate
// the live state.json and then succeed -- whereas creating the temporary file
// has to add an entry to the directory and fails before writing anything.
// Pointing the failure at some other path than the one the assertions read
// would let the old implementation pass this test unchanged.
func TestSaveFailureLeavesPreviousStateIntact(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory write permission, so the save under test would succeed")
	}
	t.Setenv("KAIROS_LAB_CONFIG_DIR", t.TempDir())
	t.Setenv("KAIROS_LAB_CACHE_DIR", t.TempDir())
	store, err := DefaultStore()
	if err != nil {
		t.Fatal(err)
	}
	st := NewState(store)
	st.Platform.OS = "linux"
	MutableVM(st).IPAddress = "192.168.64.7"
	if err := store.Save(st); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(store.StatePath)
	if err != nil {
		t.Fatal(err)
	}

	sealDir(t, filepath.Dir(store.StatePath))
	st.Platform.OS = "darwin"
	MutableVM(st).IPAddress = "10.0.0.1"
	if err := store.Save(st); err == nil {
		t.Fatal("saving into a directory that cannot be written should fail")
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
	if loaded.Platform.OS != "linux" || VMOrZero(loaded).IPAddress != "192.168.64.7" {
		t.Errorf("previous state changed: os = %q, ip = %q", loaded.Platform.OS, VMOrZero(loaded).IPAddress)
	}
}

// TestSaveFailureLeavesNoTemporaryFile pins the cleanup half of the rename
// dance. The temporary file is created beside the state file -- the config dir,
// for the store this test builds -- so forgetting to remove it on failure would
// slowly fill a directory the user actually looks at with state.json.tmp-*
// debris. Three failing saves rather than one, so a leak shows up as debris
// accumulating rather than a single file that could be mistaken for the real
// one.
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

// TestSaveUsesTheStatePathDirectoryForItsTemporaryFile pins which directory the
// temporary file is created in, for a Store whose StatePath is not inside its
// ConfigDir. Store is exported with exported fields and nothing makes those two
// agree, and only the directory StatePath lives in is guaranteed to be on the
// same filesystem as the rename's destination -- across two filesystems rename
// fails outright with EXDEV rather than copying.
//
// Every other test in this package builds its store through DefaultStore, which
// always puts state.json inside ConfigDir, so all of them stay green if the
// create is pointed back at ConfigDir. This one is the discriminator, and it
// discriminates twice over so that it does so as any user:
//
//   - ConfigDir is sealed, so a create attempted there fails with EACCES and
//     takes the whole save down with it. Root ignores directory permissions, so
//     that half only runs when the tests are not root.
//   - ConfigDir's modification time is compared across the save. A directory's
//     mtime moves when an entry is added to it, and moves again when one is
//     removed, so a temporary file created there and renamed away leaves the
//     evidence behind even though the file itself is gone. Nothing in a correct
//     save touches that directory at all: MkdirAll finds it already there and
//     returns without writing.
func TestSaveUsesTheStatePathDirectoryForItsTemporaryFile(t *testing.T) {
	configDir := t.TempDir()
	stateDir := t.TempDir()
	store := &Store{
		ConfigDir: configDir,
		CacheDir:  t.TempDir(),
		StatePath: filepath.Join(stateDir, "state.json"),
	}
	if os.Geteuid() != 0 {
		sealDir(t, configDir)
	}
	before, err := os.Stat(configDir)
	if err != nil {
		t.Fatal(err)
	}

	st := NewState(store)
	st.Platform.Arch = "arm64"
	if err := store.Save(st); err != nil {
		t.Fatalf("a state path outside ConfigDir should still save: %v", err)
	}

	if _, err := os.Stat(store.StatePath); err != nil {
		t.Fatalf("the state file should exist at StatePath: %v", err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("the saved state file should parse: %v", err)
	}
	if loaded.Platform.Arch != "arm64" {
		t.Errorf("arch = %q, want arm64", loaded.Platform.Arch)
	}

	entries, err := os.ReadDir(configDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("ConfigDir contents after the save = %v, want nothing: the state file and its temporary belong beside StatePath", names)
	}
	after, err := os.Stat(configDir)
	if err != nil {
		t.Fatal(err)
	}
	if !after.ModTime().Equal(before.ModTime()) {
		t.Errorf("ConfigDir was modified by a save that should not have touched it (mtime %v -> %v): the temporary file was created there instead of beside StatePath",
			before.ModTime(), after.ModTime())
	}
}

// TestSavePreservesExistingStateFileMode is the mode half of writing through a
// rename. An in-place write left the mode of an existing file untouched --
// O_CREATE|O_TRUNC ignores its mode argument once the file exists -- so a user
// who tightened state.json by hand kept it tightened across every later save.
// A rename publishes the temporary file's own mode instead, which would undo
// that silently on the next save, so Save has to copy the old mode onto the
// replacement. The 0644 case is here because carrying the mode across has to
// mean carrying it, not clamping it: a state.json that is already group- and
// world-readable stays exactly that.
func TestSavePreservesExistingStateFileMode(t *testing.T) {
	for _, mode := range []os.FileMode{0o600, 0o640, 0o644} {
		t.Run(fmt.Sprintf("%04o", mode), func(t *testing.T) {
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
			// chmod rather than a mode argument, because os.WriteFile and friends
			// run their mode through the umask and would not reliably produce the
			// mode this case is about.
			if err := os.Chmod(store.StatePath, mode); err != nil {
				t.Fatal(err)
			}

			MutableVM(st).IPAddress = "192.168.64.7"
			if err := store.Save(st); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(store.StatePath)
			if err != nil {
				t.Fatal(err)
			}
			if perm := info.Mode().Perm(); perm != mode {
				t.Errorf("state file mode after a save = %04o, want %04o", perm, mode)
			}
			loaded, err := store.Load()
			if err != nil {
				t.Fatal(err)
			}
			if VMOrZero(loaded).IPAddress != "192.168.64.7" {
				t.Errorf("vm IP address = %q, want 192.168.64.7", VMOrZero(loaded).IPAddress)
			}
		})
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
	// One slot each: both goroutines return after their first send, so a
	// capacity matching the loop count would only ever hold one value anyway.
	saveErrs := make(chan error, 1)
	loadErrs := make(chan error, 1)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < saves; i++ {
			st := NewState(store)
			MutableVM(st).LastError = strings.Repeat("x", i*8)
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

// --- SchemaVersion 2: the VM list, its migration and its helpers ----------

// TestLoadMigratesLegacyVMIntoVMs is the ordinary case the migration exists
// for: a v1 file with a populated "vm" object, written by any build before
// this one, has to keep meaning what it meant -- exactly one VM, the one
// named by disk_name -- once read by a build that understands "vms" instead.
func TestLoadMigratesLegacyVMIntoVMs(t *testing.T) {
	t.Setenv("KAIROS_LAB_CONFIG_DIR", t.TempDir())
	t.Setenv("KAIROS_LAB_CACHE_DIR", t.TempDir())
	store, err := DefaultStore()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(store.ConfigDir, 0o755); err != nil {
		t.Fatal(err)
	}
	legacy := `{"version":1,"network":{"mode":"shared","tap_name":"kairoslab-tap0"},"vm":{"disk_name":"kairos-disk0","pid":1234,"ip_address":"192.168.64.7"}}`
	if err := os.WriteFile(store.StatePath, []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}

	st, err := store.Load()
	if err != nil {
		t.Fatalf("loading a v1 file with a populated vm object should succeed: %v", err)
	}
	if len(st.VMs) != 1 {
		t.Fatalf("VMs after migration = %+v, want exactly one entry", st.VMs)
	}
	got := st.VMs[0]
	if got.Name != "kairos-disk0" {
		t.Errorf("migrated VM Name = %q, want %q (the old disk_name)", got.Name, "kairos-disk0")
	}
	if got.Slot != 0 {
		t.Errorf("migrated VM Slot = %d, want 0", got.Slot)
	}
	if got.TapName != "kairoslab-tap0" {
		t.Errorf("migrated VM TapName = %q, want %q, taken from the Network block", got.TapName, "kairoslab-tap0")
	}
	if got.NetworkMode != "shared" {
		t.Errorf("migrated VM NetworkMode = %q, want %q, taken from the Network block", got.NetworkMode, "shared")
	}
	if got.PID != 1234 || got.IPAddress != "192.168.64.7" {
		t.Errorf("migrated VM did not carry over its other fields untouched: %+v", got)
	}
	if st.LegacyVM != nil {
		t.Errorf("LegacyVM should be nil once Load returns, got %+v", st.LegacyVM)
	}

	if err := store.Save(st); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(store.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"vm"`) {
		t.Errorf("a save after migrating should carry no \"vm\" key, got:\n%s", raw)
	}
	if !strings.Contains(string(raw), `"vms"`) {
		t.Errorf("a save after migrating should carry the \"vms\" key, got:\n%s", raw)
	}
	// The version guard exists to stop an old binary from misreading a file a
	// new one wrote; that only works if a migrated v1 file is actually
	// relabelled v2 once it is saved again. It carried "version":1 next to a
	// "vms" list before this was fixed, which is indistinguishable, to a v1
	// Load, from a file that never had a VM at all -- v1's Load has no
	// version check and no "vms" field to decode, so it silently reports
	// nothing running for a VM the file says is at a live PID.
	if !strings.Contains(string(raw), `"version": 2`) {
		t.Errorf("a save after migrating a v1 file should carry \"version\": 2, got:\n%s", raw)
	}
}

// TestLoadMigratesAlpha1ShapedLegacyVM pins the migration against the exact
// shape the v0.0.0-alpha1 tag wrote, not just the shape the current build
// happens to produce. disk_name did not exist on VM until commit 006089f,
// which `git merge-base --is-ancestor v0.0.0-alpha1 006089f` confirms comes
// after alpha1, so an alpha1 state.json with a live VM has a "vm" object
// carrying pid and disk_path but no disk_name key at all. Gating the
// migration on DiskName alone -- the defect this test is written against --
// silently dropped that entire record: demonstrated against both binaries
// with this exact shape and a live PID, the pre-milestone build correctly
// refused start and reset ("a vm is already running", "a VM is still
// running"), and the regressed build refused neither.
func TestLoadMigratesAlpha1ShapedLegacyVM(t *testing.T) {
	t.Setenv("KAIROS_LAB_CONFIG_DIR", t.TempDir())
	t.Setenv("KAIROS_LAB_CACHE_DIR", t.TempDir())
	store, err := DefaultStore()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(store.ConfigDir, 0o755); err != nil {
		t.Fatal(err)
	}
	legacy := `{"version":1,"vm":{"pid":1234,"disk_path":"/home/user/.cache/kairos-lab/vm/kairos-disk0.qcow2","log_path":"/home/user/.cache/kairos-lab/vm/kairos-disk0.log","qga_socket_path":"/home/user/.cache/kairos-lab/vm/kairos-disk0.qga.sock","started_at":"2026-03-18T00:00:00Z"}}`
	if err := os.WriteFile(store.StatePath, []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}

	st, err := store.Load()
	if err != nil {
		t.Fatalf("loading an alpha1-shaped v1 file should succeed: %v", err)
	}
	if len(st.VMs) != 1 {
		t.Fatalf("VMs after migrating an alpha1-shaped record = %+v, want exactly one entry", st.VMs)
	}
	got := st.VMs[0]
	if got.Name == "" {
		t.Error("migrated VM Name is empty; a record with no disk_name still needs a usable Name")
	}
	if got.Name != "kairos-disk0" {
		t.Errorf("migrated VM Name = %q, want %q, derived from disk_path's basename", got.Name, "kairos-disk0")
	}
	if got.PID != 1234 {
		t.Errorf("migrated VM PID = %d, want 1234", got.PID)
	}
	if got.LogPath == "" || got.QGASockPath == "" {
		t.Errorf("migrated VM lost LogPath or QGASockPath: %+v", got)
	}
}

// TestLoadMigratesALegacyVMWithNeitherDiskNameNorDiskPath pins the last-resort
// fallback in legacyVMName: a record that carries a live PID but not even a
// disk_path (imaginable from a build older still, or a file trimmed by hand)
// must still survive migration with a stable synthetic name rather than
// being silently dropped or given an empty Name that collides with any other
// unnamed entry.
func TestLoadMigratesALegacyVMWithNeitherDiskNameNorDiskPath(t *testing.T) {
	t.Setenv("KAIROS_LAB_CONFIG_DIR", t.TempDir())
	t.Setenv("KAIROS_LAB_CACHE_DIR", t.TempDir())
	store, err := DefaultStore()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(store.ConfigDir, 0o755); err != nil {
		t.Fatal(err)
	}
	legacy := `{"version":1,"vm":{"pid":4321}}`
	if err := os.WriteFile(store.StatePath, []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}

	st, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(st.VMs) != 1 {
		t.Fatalf("VMs = %+v, want exactly one entry", st.VMs)
	}
	if st.VMs[0].Name != "vm0" {
		t.Errorf("migrated VM Name = %q, want the synthetic %q", st.VMs[0].Name, "vm0")
	}
	if st.VMs[0].PID != 4321 {
		t.Errorf("migrated VM PID = %d, want 4321", st.VMs[0].PID)
	}
}

// TestValidVMName pins the rule legacyVMName runs every candidate through:
// reject empty, ".", "..", any path separator, and any non-printable rune --
// the same rule validDiskName (internal/app/app.go) applies to a disk name
// typed at the prompt, duplicated here rather than shared (see validVMName's
// own comment for why).
func TestValidVMName(t *testing.T) {
	valid := []string{"kairos-disk0", "vm0", "a", "disk.qcow2", "my_vm-1"}
	for _, name := range valid {
		if err := validVMName(name); err != nil {
			t.Errorf("validVMName(%q) = %v, want nil", name, err)
		}
	}
	invalid := []string{
		"",
		".",
		"..",
		"/",
		"a/b",
		`a\b`,
		"../../etc/passwd",
		"\x1b[2K\rowned",
	}
	for _, name := range invalid {
		if err := validVMName(name); err == nil {
			t.Errorf("validVMName(%q) = nil, want an error", name)
		}
	}
}

// TestLegacyVMNameRejectsAnUnsafeDerivedName pins the fix for legacyVMName
// synthesising a name the repo's own validator rejects. Every case here was
// measured against the pre-fix function: filepath.Base plus a trimmed
// .qcow2 suffix, with no validation of the result at all, before
// legacyVMName ran every candidate through validVMName and fell back to
// syntheticVMName when a candidate failed.
func TestLegacyVMNameRejectsAnUnsafeDerivedName(t *testing.T) {
	cases := []struct {
		name     string
		diskPath string
		want     string
	}{
		// filepath.Base keeps only the final path component, so this one
		// happens to come out harmless -- included to show the fix does not
		// change a case that was already safe.
		{"escapes a directory but the basename is plain", "../../etc/passwd", "passwd"},
		{"root", "/", "vm0"},
		{"dot-dot", "..", "vm0"},
		{"control characters", "/tmp/\x1b[2K\rowned.qcow2", "vm0"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st := &State{}
			got := legacyVMName(st, &VM{DiskPath: c.diskPath})
			if got != c.want {
				t.Errorf("legacyVMName with disk_path %q = %q, want %q", c.diskPath, got, c.want)
			}
			if err := validVMName(got); err != nil {
				t.Errorf("legacyVMName with disk_path %q returned %q, which validVMName itself rejects: %v", c.diskPath, got, err)
			}
		})
	}
}

// TestLegacyVMNameFallsBackWhenDiskNameItselfIsUnsafe pins that an unsafe
// disk_name -- not just an unsafe disk_path -- is also rejected rather than
// used as-is: a hand-edited legacy file can set disk_name directly.
func TestLegacyVMNameFallsBackWhenDiskNameItselfIsUnsafe(t *testing.T) {
	st := &State{}
	got := legacyVMName(st, &VM{DiskName: "..", DiskPath: "/home/user/disk0.qcow2"})
	if got != "disk0" {
		t.Errorf("legacyVMName with an unsafe disk_name = %q, want the disk_path-derived %q", got, "disk0")
	}
}

// TestSyntheticVMNameAvoidsCollidingWithADiskOrAVM pins the fix for
// VM.Name's former claim that a migrated record's name "is already unique
// among disks": the fixed "vm0" fallback used to be returned unconditionally,
// which collides head-on with a real disk already named vm0. syntheticVMName
// must instead pick the first name in vm0, vm1, ... that is free on both
// st.Disks and st.VMs.
func TestSyntheticVMNameAvoidsCollidingWithADiskOrAVM(t *testing.T) {
	st := &State{
		Disks: []Disk{{Name: "vm0"}, {Name: "vm2"}},
		VMs:   []VM{{Name: "vm1"}},
	}
	got := syntheticVMName(st)
	if got != "vm3" {
		t.Errorf("syntheticVMName = %q, want %q (vm0..vm2 all taken)", got, "vm3")
	}
}

// TestLoadMigratesALegacyVMWithADiskPathThatCollidesWithAnExistingDisk pins
// the same fix end to end through Load: a legacy record with no disk_name
// and a disk_path of ".." must not migrate to a Name that collides with a
// disk already recorded under the synthetic fallback's own first choice.
func TestLoadMigratesALegacyVMWithADiskPathThatCollidesWithAnExistingDisk(t *testing.T) {
	t.Setenv("KAIROS_LAB_CONFIG_DIR", t.TempDir())
	t.Setenv("KAIROS_LAB_CACHE_DIR", t.TempDir())
	store, err := DefaultStore()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(store.ConfigDir, 0o755); err != nil {
		t.Fatal(err)
	}
	legacy := `{"version":1,"disks":[{"name":"vm0","path":"/whatever/vm0.qcow2"}],"vm":{"pid":4321,"disk_path":".."}}`
	if err := os.WriteFile(store.StatePath, []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}

	st, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(st.VMs) != 1 {
		t.Fatalf("VMs = %+v, want exactly one entry", st.VMs)
	}
	if st.VMs[0].Name == "vm0" {
		t.Errorf("migrated VM Name = %q, collides with the disk already named vm0", st.VMs[0].Name)
	}
	if st.VMs[0].Name != "vm1" {
		t.Errorf("migrated VM Name = %q, want %q (vm0 taken by the disk)", st.VMs[0].Name, "vm1")
	}
}

// TestLoadSetupOnlyLegacyFileDropsTheDeadVMKey covers the file shape every
// setup-only run before this milestone actually wrote: the old VM field had
// no omitempty, so state.json always carried a "vm" key even when no VM had
// ever started, decoding as an empty VM{}. That empty record is not a VM that
// ran and must not become a migrated entry -- but the dead key still has to
// stop being written once the file is saved again.
func TestLoadSetupOnlyLegacyFileDropsTheDeadVMKey(t *testing.T) {
	t.Setenv("KAIROS_LAB_CONFIG_DIR", t.TempDir())
	t.Setenv("KAIROS_LAB_CACHE_DIR", t.TempDir())
	store, err := DefaultStore()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(store.ConfigDir, 0o755); err != nil {
		t.Fatal(err)
	}
	legacy := `{"version":1,"setup":{"completed_at":"2025-01-01T00:00:00Z","dependency_check_passed":true},"vm":{}}`
	if err := os.WriteFile(store.StatePath, []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}

	st, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(st.VMs) != 0 {
		t.Errorf("VMs after loading a setup-only legacy file = %+v, want none", st.VMs)
	}

	if err := store.Save(st); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(store.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"vm"`) {
		t.Errorf("a save should carry no dead \"vm\": {} key, got:\n%s", raw)
	}
}

// TestLoadDoesNotMigrateWhenVMsAlreadyPresent pins that the migration is keyed
// on len(st.VMs) == 0 and not on the mere presence of a "vm" key: a file that
// already carries "vms" -- which is every file this build itself writes -- is
// left exactly as it was.
func TestLoadDoesNotMigrateWhenVMsAlreadyPresent(t *testing.T) {
	t.Setenv("KAIROS_LAB_CONFIG_DIR", t.TempDir())
	t.Setenv("KAIROS_LAB_CACHE_DIR", t.TempDir())
	store, err := DefaultStore()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(store.ConfigDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// The stray "vm" object beside "vms" is not a realistic file -- nothing
	// this codebase writes produces both -- but it is exactly what makes this
	// a test of the len(VMs) == 0 rule rather than of some other one, such as
	// "migrate whenever vm is present".
	legacy := `{"version":2,"vm":{"disk_name":"should-not-appear"},"vms":[{"name":"kairos-disk0","slot":0,"pid":42}]}`
	if err := os.WriteFile(store.StatePath, []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}

	st, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(st.VMs) != 1 || st.VMs[0].Name != "kairos-disk0" {
		t.Fatalf("VMs = %+v, want exactly the one entry already on file, unmigrated", st.VMs)
	}
	if st.VMs[0].PID != 42 {
		t.Errorf("VMs[0].PID = %d, want 42, unchanged from what was on file", st.VMs[0].PID)
	}
}

// TestLoadRefusesANewerSchemaVersion pins the guard against a file THIS
// build cannot understand: a version above SchemaVersion means some future
// release wrote it in a shape this one has never seen. It is not a downgrade
// defence -- an older binary reading a file a newer one wrote runs its own
// Load, which this check cannot reach into and never will, so it changes
// nothing about what that binary does. What it changes is what THIS binary
// does when handed a file from later than itself: refuse with a message
// naming both versions and the file to look at, instead of silently
// misreading a shape it does not have fields for.
func TestLoadRefusesANewerSchemaVersion(t *testing.T) {
	t.Setenv("KAIROS_LAB_CONFIG_DIR", t.TempDir())
	t.Setenv("KAIROS_LAB_CACHE_DIR", t.TempDir())
	store, err := DefaultStore()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(store.ConfigDir, 0o755); err != nil {
		t.Fatal(err)
	}
	future := fmt.Sprintf(`{"version":%d}`, SchemaVersion+1)
	if err := os.WriteFile(store.StatePath, []byte(future), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := store.Load(); err == nil {
		t.Fatal("loading a state file from a newer schema version should be refused, not silently accepted")
	} else {
		for _, want := range []string{store.StatePath, fmt.Sprintf("%d", SchemaVersion+1), fmt.Sprintf("%d", SchemaVersion)} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not mention %q", err, want)
			}
		}
	}
}

// TestLoadRefusesTooManyVMs pins the cap on len(st.VMs): the slot domain is
// 0..MaxSlot, so a file with more VMs than that has more entries than this
// build can ever address, and is corrupt or hand-edited rather than merely
// large. The refusal is deliberate even though it costs every later command
// that calls Load -- status, start, reset and cleanup alike -- and the file
// the error names has to be corrected by hand; there is no in-band recovery.
func TestLoadRefusesTooManyVMs(t *testing.T) {
	t.Setenv("KAIROS_LAB_CONFIG_DIR", t.TempDir())
	t.Setenv("KAIROS_LAB_CACHE_DIR", t.TempDir())
	store, err := DefaultStore()
	if err != nil {
		t.Fatal(err)
	}
	st := NewState(store)
	for i := 0; i <= MaxSlot+1; i++ { // MaxSlot+2 entries, one past the MaxSlot+1 that fits
		st.VMs = append(st.VMs, VM{Name: fmt.Sprintf("vm%d", i)})
	}
	if err := store.Save(st); err != nil {
		t.Fatal(err)
	}

	_, err = store.Load()
	if err == nil {
		t.Fatal("loading a state file with more VMs than slots exist should be refused, not silently accepted")
	}
	if !strings.Contains(err.Error(), fmt.Sprintf("%d", MaxSlot+2)) {
		t.Errorf("error %q does not name the VM count %d", err, MaxSlot+2)
	}
}

// TestAllocateVMSlot covers AllocateVMSlot's four documented behaviours: the
// lowest slot wins, an already-used slot is skipped, a slot free rejects is
// skipped, and exhausting 0..MaxSlot is an error rather than an out-of-range
// slot.
func TestAllocateVMSlot(t *testing.T) {
	t.Run("empty state returns the lowest slot", func(t *testing.T) {
		st := &State{}
		slot, err := AllocateVMSlot(st, nil)
		if err != nil || slot != 0 {
			t.Fatalf("AllocateVMSlot(empty) = (%d, %v), want (0, nil)", slot, err)
		}
	})

	t.Run("skips slots already used by existing entries", func(t *testing.T) {
		st := &State{VMs: []VM{{Name: "a", Slot: 0}, {Name: "b", Slot: 1}}}
		slot, err := AllocateVMSlot(st, nil)
		if err != nil || slot != 2 {
			t.Fatalf("AllocateVMSlot = (%d, %v), want (2, nil)", slot, err)
		}
	})

	t.Run("skips slots free rejects", func(t *testing.T) {
		st := &State{}
		slot, err := AllocateVMSlot(st, func(s int) bool { return s != 0 && s != 1 })
		if err != nil || slot != 2 {
			t.Fatalf("AllocateVMSlot = (%d, %v), want (2, nil)", slot, err)
		}
	})

	t.Run("errors once 0..MaxSlot is exhausted", func(t *testing.T) {
		vms := make([]VM, 0, MaxSlot+1)
		for i := 0; i <= MaxSlot; i++ {
			vms = append(vms, VM{Name: fmt.Sprintf("vm%d", i), Slot: i})
		}
		st := &State{VMs: vms}
		slot, err := AllocateVMSlot(st, nil)
		if err == nil {
			t.Fatal("AllocateVMSlot with every slot in 0..MaxSlot used should return an error")
		}
		// -1, not 0: 0 is itself a valid slot, so a caller that writes
		// slot, _ := AllocateVMSlot(...) and drops the error must not get back
		// something that looks like a real allocation of the first slot.
		if slot != -1 {
			t.Errorf("AllocateVMSlot error return = %d, want -1 so an ignored error still fails ValidateSlot", slot)
		}
	})

	t.Run("ignores a stored slot outside 0..MaxSlot when building the used set", func(t *testing.T) {
		// This pins the contract, not a behavioural difference this specific
		// case can show: mutation testing this exact scenario (a single
		// wildly out-of-range Slot) against a build that skips the
		// ValidateSlot check found no observable difference, because the
		// search loop below only ever queries keys 0..MaxSlot and an
		// out-of-range key can never collide with one of those queries. The
		// skip is still correct -- it is what keeps a corrupt or hand-edited
		// slot from being recorded in `used` at all, which matters once
		// anything downstream (a future widening of the search range, a
		// second reader of `used`) stops guaranteeing that same non-collision
		// -- so this stays as a regression pin on the stated contract.
		st := &State{VMs: []VM{{Name: "corrupt", Slot: 1000000}}}
		slot, err := AllocateVMSlot(st, nil)
		if err != nil || slot != 0 {
			t.Fatalf("AllocateVMSlot with only an out-of-range stored slot = (%d, %v), want (0, nil)", slot, err)
		}
	})
}

// TestValidateSlot pins the boundary: 0 and MaxSlot are accepted, one step
// past either side is refused.
func TestValidateSlot(t *testing.T) {
	if err := ValidateSlot(-1); err == nil {
		t.Error("ValidateSlot(-1) = nil, want an error")
	}
	if err := ValidateSlot(MaxSlot + 1); err == nil {
		t.Errorf("ValidateSlot(%d) = nil, want an error", MaxSlot+1)
	}
	if err := ValidateSlot(0); err != nil {
		t.Errorf("ValidateSlot(0) = %v, want nil", err)
	}
	if err := ValidateSlot(MaxSlot); err != nil {
		t.Errorf("ValidateSlot(%d) = %v, want nil", MaxSlot, err)
	}
}

// TestFindUpsertRemoveVM covers the three name-keyed helpers together: Upsert
// appends when the name is new and replaces in place when it is not, Find
// returns a pointer into the live slice (so a write through it is a write to
// the state), and Remove deletes by name and leaves the rest untouched.
func TestFindUpsertRemoveVM(t *testing.T) {
	st := &State{}
	UpsertVM(st, VM{Name: "kairos-disk0", PID: 111})
	UpsertVM(st, VM{Name: "kairos-disk1", PID: 222})
	if len(st.VMs) != 2 {
		t.Fatalf("VMs after two inserting upserts = %+v, want 2 entries", st.VMs)
	}

	UpsertVM(st, VM{Name: "kairos-disk0", PID: 999})
	if len(st.VMs) != 2 {
		t.Fatalf("VMs after a replacing upsert = %+v, want still 2 entries", st.VMs)
	}
	if got := FindVM(st, "kairos-disk0"); got == nil || got.PID != 999 {
		t.Errorf("FindVM(kairos-disk0) = %+v, want PID 999", got)
	}

	if got := FindVM(st, "kairos-disk0"); got != nil {
		got.IPAddress = "192.168.64.9"
	}
	if st.VMs[0].IPAddress != "192.168.64.9" {
		t.Errorf("writing through FindVM's pointer did not reach st.VMs: %+v", st.VMs)
	}

	RemoveVM(st, "kairos-disk1")
	if len(st.VMs) != 1 || FindVM(st, "kairos-disk1") != nil {
		t.Errorf("VMs after removing kairos-disk1 = %+v, want it gone", st.VMs)
	}
	if FindVM(st, "kairos-disk0") == nil {
		t.Error("removing kairos-disk1 should not touch kairos-disk0")
	}
}

// TestSaveLoadRoundTripsNewVMFields is the schema-2 sibling of
// TestSaveLoadRoundTripKeepsMACAndIP: every field VM gained in this milestone
// survives a save and a reload, not just the pre-existing ones.
func TestSaveLoadRoundTripsNewVMFields(t *testing.T) {
	t.Setenv("KAIROS_LAB_CONFIG_DIR", t.TempDir())
	t.Setenv("KAIROS_LAB_CACHE_DIR", t.TempDir())
	store, err := DefaultStore()
	if err != nil {
		t.Fatal(err)
	}
	st := NewState(store)
	UpsertVM(st, VM{
		Name:        "kairos-disk0",
		Slot:        3,
		NetworkMode: "bridged",
		TapName:     "kairoslab-tap-3",
		SSHPort:     2203,
		WebPort:     8103,
		PID:         4321,
	})
	if err := store.Save(st); err != nil {
		t.Fatal(err)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	got := FindVM(loaded, "kairos-disk0")
	if got == nil {
		t.Fatal("VM missing after reload")
	}
	if got.Slot != 3 {
		t.Errorf("Slot = %d, want 3", got.Slot)
	}
	if got.NetworkMode != "bridged" {
		t.Errorf("NetworkMode = %q, want %q", got.NetworkMode, "bridged")
	}
	if got.TapName != "kairoslab-tap-3" {
		t.Errorf("TapName = %q, want %q", got.TapName, "kairoslab-tap-3")
	}
	if got.SSHPort != 2203 {
		t.Errorf("SSHPort = %d, want 2203", got.SSHPort)
	}
	if got.WebPort != 8103 {
		t.Errorf("WebPort = %d, want 8103", got.WebPort)
	}
	if got.PID != 4321 {
		t.Errorf("PID = %d, want 4321", got.PID)
	}
}
