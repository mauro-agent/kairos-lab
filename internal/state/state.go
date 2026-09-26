package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const SchemaVersion = 1

type Platform struct {
	OS             string `json:"os"`
	Arch           string `json:"arch"`
	PackageManager string `json:"package_manager"`
}

type Setup struct {
	CompletedAt           string   `json:"completed_at,omitempty"`
	PreExistingDeps       []string `json:"pre_existing_deps,omitempty"`
	InstalledByKairosLab  []string `json:"installed_by_kairos_lab,omitempty"`
	DependencyCheckPassed bool     `json:"dependency_check_passed"`
}

type Network struct {
	Mode                 string   `json:"mode,omitempty"`
	BridgeInterface      string   `json:"bridge_interface,omitempty"`
	BridgeName           string   `json:"bridge_name,omitempty"`
	TapName              string   `json:"tap_name,omitempty"`
	DHCPPIDFile          string   `json:"dhcp_pid_file,omitempty"`
	DHCPLeaseFile        string   `json:"dhcp_lease_file,omitempty"`
	CreatedByKairosLab   bool     `json:"created_by_kairos_lab"`
	CreatedResources     []string `json:"created_resources,omitempty"`
	CleanupRequired      bool     `json:"cleanup_required"`
	LastPreparedAt       string   `json:"last_prepared_at,omitempty"`
	LastCleanupAttemptAt string   `json:"last_cleanup_attempt_at,omitempty"`
}

type Disk struct {
	Name      string `json:"name"`
	Path      string `json:"path"`
	ISOName   string `json:"iso_name,omitempty"`
	CreatedAt string `json:"created_at"`
	Size      string `json:"size"`
	MemoryGB  int    `json:"memory_gb,omitempty"`
	CPUs      int    `json:"cpus,omitempty"`
	// MAC is the per-disk QEMU NIC address. It is additive and omitempty, so a
	// disk recorded before this field existed loads with an empty MAC; the
	// start path will fill one in once it is wired up to do so. No state
	// migration is needed either way.
	MAC string `json:"mac,omitempty"`
}

type VM struct {
	ISOSource   string   `json:"iso_source,omitempty"`
	ISOInput    string   `json:"iso_input,omitempty"`
	ISOLocal    string   `json:"iso_local_path,omitempty"`
	DiskPath    string   `json:"disk_path,omitempty"`
	DiskName    string   `json:"disk_name,omitempty"`
	LogPath     string   `json:"log_path,omitempty"`
	QemuBinary  string   `json:"qemu_binary,omitempty"`
	QemuArgs    []string `json:"qemu_args,omitempty"`
	PID         int      `json:"pid,omitempty"`
	StartedAt   string   `json:"started_at,omitempty"`
	StoppedAt   string   `json:"stopped_at,omitempty"`
	LastError   string   `json:"last_error,omitempty"`
	RuntimeDir  string   `json:"runtime_dir,omitempty"`
	QGASockPath string   `json:"qga_socket_path,omitempty"`
	IPAddress   string   `json:"ip_address,omitempty"`
}

type State struct {
	Version      int      `json:"version"`
	Platform     Platform `json:"platform"`
	Setup        Setup    `json:"setup"`
	Network      Network  `json:"network"`
	VM           VM       `json:"vm"`
	Disks        []Disk   `json:"disks,omitempty"`
	ManagedDirs  []string `json:"managed_dirs,omitempty"`
	ManagedFiles []string `json:"managed_files,omitempty"`
}

type Store struct {
	ConfigDir string
	CacheDir  string
	StatePath string
}

func DefaultStore() (*Store, error) {
	cfgRoot := os.Getenv("KAIROS_LAB_CONFIG_DIR")
	if cfgRoot == "" {
		d, err := os.UserConfigDir()
		if err != nil {
			return nil, fmt.Errorf("get user config dir: %w", err)
		}
		cfgRoot = d
	}
	cacheRoot := os.Getenv("KAIROS_LAB_CACHE_DIR")
	if cacheRoot == "" {
		d, err := os.UserCacheDir()
		if err != nil {
			return nil, fmt.Errorf("get user cache dir: %w", err)
		}
		cacheRoot = d
	}
	cfgDir := filepath.Join(cfgRoot, "kairos-lab")
	cacheDir := filepath.Join(cacheRoot, "kairos-lab")
	return &Store{
		ConfigDir: cfgDir,
		CacheDir:  cacheDir,
		StatePath: filepath.Join(cfgDir, "state.json"),
	}, nil
}

func NewState(s *Store) *State {
	st := &State{Version: SchemaVersion}
	st.ManagedDirs = uniqueSorted([]string{s.ConfigDir, s.CacheDir})
	return st
}

func (s *Store) Load() (*State, error) {
	b, err := os.ReadFile(s.StatePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return NewState(s), nil
		}
		return nil, fmt.Errorf("read state file: %w", err)
	}
	var st State
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, fmt.Errorf("parse state file: %w", err)
	}
	if st.Version == 0 {
		st.Version = SchemaVersion
	}
	st.ManagedDirs = uniqueSorted(append(st.ManagedDirs, s.ConfigDir, s.CacheDir))
	st.ManagedFiles = uniqueSorted(st.ManagedFiles)
	return &st, nil
}

func (s *Store) Save(st *State) error {
	if err := os.MkdirAll(s.ConfigDir, 0o755); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	if err := os.MkdirAll(s.CacheDir, 0o755); err != nil {
		return fmt.Errorf("create cache directory: %w", err)
	}
	st.ManagedDirs = uniqueSorted(append(st.ManagedDirs, s.ConfigDir, s.CacheDir))
	st.ManagedFiles = uniqueSorted(st.ManagedFiles)
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("serialize state: %w", err)
	}
	// The state file is published by renaming a complete temporary file over
	// it, not by writing into it in place. Writing in place truncates first, so
	// another process reading state.json at that moment -- a `kairos-lab
	// status` in a second terminal, say, while a running VM's IP address is
	// being recorded -- sees an empty or half-written file and fails to parse
	// it. A rename swaps the name onto already-complete contents in one step,
	// so every reader sees either the whole old file or the whole new one and
	// never something in between. That is also why the temporary file is
	// created in ConfigDir rather than the system temp dir: rename is only
	// atomic within a single filesystem, and /tmp is routinely a different one.
	tmp, err := os.CreateTemp(s.ConfigDir, "state.json.tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary state file: %w", err)
	}
	tmpPath := tmp.Name()
	closed := false
	renamed := false
	// Any failure below must leave no trace: the previous state.json is still
	// the live one, and a half-written temporary file next to it would be
	// nothing but litter in the user's config dir.
	defer func() {
		if !closed {
			_ = tmp.Close()
		}
		if !renamed {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("write state file: %w", err)
	}
	// Flush before the rename, so the name can never be published pointing at
	// contents the kernel has not yet put on disk.
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync state file: %w", err)
	}
	// os.CreateTemp makes the file 0600, but state.json has always been 0644
	// and is read by the user outside this tool; the mode is part of the
	// existing behaviour, so restore it rather than quietly tightening it.
	if err := tmp.Chmod(0o644); err != nil {
		return fmt.Errorf("set state file mode: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close state file: %w", err)
	}
	closed = true
	if err := os.Rename(tmpPath, s.StatePath); err != nil {
		return fmt.Errorf("replace state file: %w", err)
	}
	renamed = true
	return nil
}

func (s *Store) RemoveStateFile() error {
	err := os.Remove(s.StatePath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove state file: %w", err)
	}
	return nil
}

func AddManagedFile(st *State, path string) {
	st.ManagedFiles = uniqueSorted(append(st.ManagedFiles, path))
}

func AddManagedDir(st *State, path string) {
	st.ManagedDirs = uniqueSorted(append(st.ManagedDirs, path))
}

func RemoveManagedFile(st *State, path string) {
	out := make([]string, 0, len(st.ManagedFiles))
	for _, p := range st.ManagedFiles {
		if p != path {
			out = append(out, p)
		}
	}
	st.ManagedFiles = out
}

func NowRFC3339() string {
	return time.Now().UTC().Format(time.RFC3339)
}

func NowTimestamp() string {
	return time.Now().Format("20060102-150405")
}

func AddDisk(st *State, disk Disk) {
	st.Disks = append(st.Disks, disk)
}

func FindDiskByName(st *State, name string) *Disk {
	for i := range st.Disks {
		if st.Disks[i].Name == name {
			return &st.Disks[i]
		}
	}
	return nil
}

func RemoveDisk(st *State, name string) {
	out := make([]Disk, 0, len(st.Disks))
	for _, d := range st.Disks {
		if d.Name != name {
			out = append(out, d)
		}
	}
	st.Disks = out
}

func IsSetupComplete(st *State) bool {
	return st.Setup.CompletedAt != "" && st.Setup.DependencyCheckPassed
}

func uniqueSorted(values []string) []string {
	set := map[string]struct{}{}
	for _, v := range values {
		if v == "" {
			continue
		}
		set[v] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
