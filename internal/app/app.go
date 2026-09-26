package app

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/kairos-io/kairos-lab/internal/cleanup"
	"github.com/kairos-io/kairos-lab/internal/deps"
	"github.com/kairos-io/kairos-lab/internal/iso"
	"github.com/kairos-io/kairos-lab/internal/platform"
	"github.com/kairos-io/kairos-lab/internal/state"
	"github.com/kairos-io/kairos-lab/internal/vm"
)

func Run(args []string, stdin io.Reader, stdout, stderr io.Writer, version string) error {
	if len(args) == 0 {
		printUsage(stdout)
		return nil
	}
	store, err := state.DefaultStore()
	if err != nil {
		return err
	}
	switch args[0] {
	case "setup":
		return runSetup(args[1:], stdin, stdout, stderr, store)
	case "download":
		return runDownload(args[1:], stdin, stdout, store)
	case "start":
		return runStart(args[1:], stdin, stdout, stderr, store)
	case "status":
		// status builds no flag set, so it has no NArg to check; it used to
		// ignore anything after the verb outright. See rejectPositionalArgs.
		if len(args) > 1 {
			return fmt.Errorf("unexpected argument %q: status takes no arguments", args[1])
		}
		return runStatus(stdout, store)
	case "reset":
		return runReset(args[1:], stdin, stdout, store)
	case "cleanup":
		return runCleanup(args[1:], stdin, stdout, store)
	case "version", "-v", "--version":
		writeLine(stdout, version)
		return nil
	case "help", "-h", "--help":
		printUsage(stdout)
		return nil
	default:
		printUsage(stderr)
		return fmt.Errorf("unknown command: %s", args[0])
	}
}

// rejectPositionalArgs fails a subcommand that was handed a positional
// argument. Every kairos-lab option is a flag, so a leftover argument is
// always a mistake, and it used to be a silent one: `kairos-lab start
// /path/to.iso` parsed the path into the flag set's remaining args and dropped
// it, so -iso stayed empty and iso.ResolveForStart auto-selected whatever was
// in the download cache. The VM booted from an image the user never named and
// nothing said so (kairos-io/kairos#4432).
//
// hint names the flag that carries the value the user probably meant, so the
// error points at the interface instead of only rejecting the input.
func rejectPositionalArgs(fs *flag.FlagSet, hint string) error {
	if fs.NArg() == 0 {
		return nil
	}
	if hint != "" {
		return fmt.Errorf("unexpected argument %q: %s", fs.Arg(0), hint)
	}
	return fmt.Errorf("unexpected argument %q: %s takes flags only", fs.Arg(0), fs.Name())
}

func runSetup(args []string, stdin io.Reader, stdout, _ io.Writer, store *state.Store) error {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	autoYes := fs.Bool("yes", false, "auto-confirm installs and sudo operations")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := rejectPositionalArgs(fs, ""); err != nil {
		return err
	}

	writeLine(stdout, "[1/4] Detecting platform and package manager")
	st, err := store.Load()
	if err != nil {
		return err
	}
	p := platform.Detect()
	st.Platform = state.Platform{OS: p.OS, Arch: p.Arch, PackageManager: p.PackageManager}

	writeLine(stdout, "[2/4] Checking required dependencies")
	required := deps.Required(p)
	present := deps.PresentNames(required)
	missing := deps.Missing(required)
	st.Setup.PreExistingDeps = mergeUnique(st.Setup.PreExistingDeps, present)

	if len(missing) > 0 {
		if p.PackageManager == "" {
			return fmt.Errorf("missing dependencies and no package manager detected")
		}
		missingNames := depNames(missing)
		writef(stdout, "missing dependencies: %s\n", strings.Join(missingNames, ", "))
		ok, err := confirm(stdin, stdout, *autoYes, "install missing dependencies now")
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("dependency installation declined")
		}
		pkgs, err := deps.InstallablePackages(p.PackageManager, missing)
		if err != nil {
			return err
		}
		useSudo := p.OS == "linux"
		if useSudo {
			ok, err = confirm(stdin, stdout, *autoYes, "this step needs sudo to install packages")
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("sudo permission denied")
			}
		}
		writeLine(stdout, "[3/4] Installing missing dependencies")
		if err := deps.Install(p.PackageManager, pkgs, useSudo); err != nil {
			return err
		}
		st.Setup.InstalledByKairosLab = mergeUnique(st.Setup.InstalledByKairosLab, missingNames)
	} else {
		writeLine(stdout, "[3/4] All dependencies already present")
	}

	writeLine(stdout, "[4/4] Writing state")
	st.Setup.DependencyCheckPassed = true
	st.Setup.CompletedAt = state.NowRFC3339()
	if err := store.Save(st); err != nil {
		return err
	}
	writef(stdout, "setup complete (%s/%s, pkg manager: %s)\n", p.OS, p.Arch, p.PackageManager)
	return nil
}

func runDownload(args []string, stdin io.Reader, stdout io.Writer, store *state.Store) error {
	if len(args) > 0 {
		return fmt.Errorf("download does not accept arguments")
	}

	st, err := store.Load()
	if err != nil {
		return err
	}
	if err := requireSetup(st); err != nil {
		return err
	}

	downloadsDir := filepath.Join(store.CacheDir, "downloads")
	localPath, err := iso.Download(iso.DownloadConfig{
		DownloadsDir: downloadsDir,
		Stdin:        stdin,
		Stdout:       stdout,
	})
	if err != nil {
		return err
	}

	state.AddManagedDir(st, downloadsDir)
	state.AddManagedFile(st, localPath)

	if err := store.Save(st); err != nil {
		return err
	}
	return nil
}

// validDiskName returns an error if name contains path separators or other
// characters that would allow it to escape the vm directory when used as a filename.
func validDiskName(name string) error {
	if name == "" {
		return fmt.Errorf("disk name must not be empty")
	}
	if strings.ContainsAny(name, "/\\") {
		return fmt.Errorf("disk name must not contain path separators")
	}
	if name == "." || name == ".." {
		return fmt.Errorf("disk name %q is not allowed", name)
	}
	return nil
}

// promptDiskName asks the user to confirm or replace suggestedName, re-prompting
// if the chosen name is already in takenNames or contains unsafe characters.
func promptDiskName(suggestedName string, takenNames map[string]struct{}, stdin io.Reader, stdout io.Writer) (string, error) {
	writeLine(stdout, "")
	writef(stdout, "Suggested disk name: %s\n", suggestedName)

	reader := bufio.NewReader(stdin)
	for {
		writef(stdout, "Press Enter to accept, or type a new name: ")
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("cancelled")
		}
		name := strings.TrimSpace(line)
		if name == "" {
			name = suggestedName
		}
		if err := validDiskName(name); err != nil {
			writef(stdout, "Invalid name: %v\n", err)
			continue
		}
		if _, taken := takenNames[name]; taken {
			writef(stdout, "A disk named %q already exists, choose a different name.\n", name)
			continue
		}
		return name, nil
	}
}

// selectOrCreateDisk prompts the user to pick an existing disk or configure a new one.
// For new disks it returns a pending Disk struct (isNew=true) without creating any file.
func selectOrCreateDisk(st *state.State, vmDir, downloadsDir, diskSize string, stdin io.Reader, stdout io.Writer) (disk *state.Disk, isoLocal string, isNew bool, err error) {
	if len(st.Disks) == 0 {
		return nil, "", false, fmt.Errorf("no disks found")
	}

	writeLine(stdout, "Existing disks:")
	for i, d := range st.Disks {
		isoInfo := ""
		if d.ISOName != "" {
			isoInfo = fmt.Sprintf(" (from %s)", d.ISOName)
		}
		createdAt := d.CreatedAt
		if t, err := time.Parse(time.RFC3339, d.CreatedAt); err == nil {
			createdAt = t.Local().Format("2006-01-02 15:04")
		}
		writef(stdout, "  [%d] %s - created %s%s\n", i+1, d.Name, createdAt, isoInfo)
	}
	writef(stdout, "  [n] Create new disk\n")
	writeLine(stdout, "")
	writef(stdout, "Choice [1-%d or n]: ", len(st.Disks))

	reader := bufio.NewReader(stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, "", false, fmt.Errorf("cancelled")
	}

	choice := strings.TrimSpace(strings.ToLower(line))

	if choice == "n" || choice == "new" {
		writeLine(stdout, "")
		res, err := iso.ResolveForStart("", downloadsDir, stdin, stdout)
		if err != nil {
			return nil, "", false, err
		}
		isoPath := res.LocalPath
		isoBaseName := strings.TrimSuffix(filepath.Base(isoPath), ".iso")
		suggestedName := fmt.Sprintf("%s-%s", isoBaseName, state.NowTimestamp())
		diskName, err := promptDiskName(suggestedName, diskNameSet(st), stdin, stdout)
		if err != nil {
			return nil, "", false, err
		}
		pending := &state.Disk{
			Name: diskName,
			Path: filepath.Join(vmDir, diskName+".qcow2"),
			Size: diskSize,
		}
		return pending, isoPath, true, nil
	}

	idx, err := strconv.Atoi(choice)
	if err != nil || idx < 1 || idx > len(st.Disks) {
		return nil, "", false, fmt.Errorf("invalid choice: %s", choice)
	}

	return &st.Disks[idx-1], "", false, nil
}

// requireNetworkPrivilege is vm.RequireNetworkPrivilege behind a package-level
// var so that a test can put its own function in its place. It is the seam
// idiom this repo already uses for host-touching calls (see the note on
// IsLinuxBridge in internal/vm/network_stub.go), and it is needed here for a
// specific reason: the real function is a no-op everywhere except darwin, so
// on the Linux CI leg a direct call would return nil whether the wiring below
// existed or not. Every assertion about where the pre-flight sits -- that the
// mode it is asked about is the one the config review settled on, and that a
// refusal stops the run before a disk image is created -- would pass on a
// tree that had never called it at all.
var requireNetworkPrivilege = vm.RequireNetworkPrivilege

// prepareLinuxBridge is vm.PrepareLinuxBridge behind the same kind of seam,
// and for a reason of its own: runStart reads st.Network.BridgeInterface back
// after this call, because the prepare decides which interface is enslaved and
// can detect one itself. Nothing in a test can otherwise reach that read. The
// real function needs an active NetworkManager and issues sudo nmcli
// commands, so a test driving it for real would either fail on the CI host or
// reconfigure it, and stubbing vm.PrepareLinuxBridge is the only way to
// observe what runStart does with the answer it gives back.
var prepareLinuxBridge = vm.PrepareLinuxBridge

func runStart(args []string, stdin io.Reader, stdout, stderr io.Writer, store *state.Store) error {
	fs := flag.NewFlagSet("start", flag.ContinueOnError)
	isoPath := fs.String("iso", "", "path to ISO file")
	diskName := fs.String("name", "", "disk name (creates new if doesn't exist)")
	diskSize := fs.String("disk-size", "60G", "disk image size for new disks")
	newDisk := fs.Bool("new", false, "create a new disk (even if others exist)")
	noISO := fs.Bool("no-iso", false, "boot without ISO (for installed systems)")
	memory := fs.Int("memory", defaultMemoryMB()/1024, "memory in GB")
	cpus := fs.Int("cpus", 2, "number of vCPUs")
	network := fs.String("network", defaultNetworkMode, "network mode: shared|bridged|user")
	display := fs.String("display", "window", "display mode: window|serial")
	bridgeIface := fs.String("bridge-if", defaultBridgeIface(), "bridge interface (macOS vmnet or Linux uplink iface)")
	autoYes := fs.Bool("yes", false, "auto-confirm sudo operations")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := rejectPositionalArgs(fs, "pass the ISO with -iso"); err != nil {
		return err
	}
	if !networkModeValid(*network) {
		return fmt.Errorf("invalid network mode: %s", *network)
	}
	if *display != "serial" && *display != "window" {
		return fmt.Errorf("invalid display mode: %s", *display)
	}

	st, err := store.Load()
	if err != nil {
		return err
	}
	if err := requireSetup(st); err != nil {
		return err
	}
	running, _ := vm.IsRunning(st.VM.PID)
	if running {
		return fmt.Errorf("a vm is already running with pid %d", st.VM.PID)
	}

	vmDir := filepath.Join(store.CacheDir, "vm")
	runtimeDir := filepath.Join(store.CacheDir, "runtime")
	downloadsDir := filepath.Join(store.CacheDir, "downloads")
	if err := os.MkdirAll(vmDir, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(runtimeDir, 0o755); err != nil {
		return err
	}
	state.AddManagedDir(st, vmDir)
	state.AddManagedDir(st, runtimeDir)
	state.AddManagedDir(st, downloadsDir)

	// Resolve disk and ISO
	// New disks are not created yet — a pending Disk struct is built and the file
	// is only written to disk after the user confirms the full configuration.
	var disk *state.Disk
	var isoLocal string
	var isNewDisk bool

	// Handle explicit -iso flag
	if *isoPath != "" {
		res, err := iso.ResolveForStart(*isoPath, downloadsDir, stdin, stdout)
		if err != nil {
			return err
		}
		isoLocal = res.LocalPath
	}

	if *diskName != "" {
		disk = state.FindDiskByName(st, *diskName)
		if disk == nil {
			// Named disk doesn't exist yet — build a pending struct
			if isoLocal == "" {
				res, err := iso.ResolveForStart("", downloadsDir, stdin, stdout)
				if err != nil {
					return err
				}
				isoLocal = res.LocalPath
			}
			pending := state.Disk{
				Name: *diskName,
				Path: filepath.Join(vmDir, *diskName+".qcow2"),
				Size: *diskSize,
			}
			disk = &pending
			isNewDisk = true
		}
	} else if *newDisk || len(st.Disks) == 0 {
		// New disk (forced or no disks exist) — build a pending struct
		if isoLocal == "" {
			res, err := iso.ResolveForStart("", downloadsDir, stdin, stdout)
			if err != nil {
				return err
			}
			isoLocal = res.LocalPath
		}
		isoBaseName := strings.TrimSuffix(filepath.Base(isoLocal), ".iso")
		suggestedName := fmt.Sprintf("%s-%s", isoBaseName, state.NowTimestamp())
		finalName := suggestedName
		if !*autoYes {
			var err error
			finalName, err = promptDiskName(suggestedName, diskNameSet(st), stdin, stdout)
			if err != nil {
				return err
			}
		}
		pending := state.Disk{
			Name: finalName,
			Path: filepath.Join(vmDir, finalName+".qcow2"),
			Size: *diskSize,
		}
		disk = &pending
		isNewDisk = true
	} else {
		// Existing disks available — ask what to do
		var err error
		disk, isoLocal, isNewDisk, err = selectOrCreateDisk(st, vmDir, downloadsDir, *diskSize, stdin, stdout)
		if err != nil {
			return err
		}
	}

	// Apply -no-iso flag (user explicitly doesn't want ISO even for new disk)
	if *noISO {
		isoLocal = ""
	}

	// Determine network interface for bridged mode. This is the first of two
	// resolutions: the flag's mode is not the final one, so the review below
	// resolves again for a run that arrives in another mode and leaves as
	// bridged. See resolveBridgeUplink.
	networkIface, err := resolveBridgeUplink(*network, *bridgeIface)
	if err != nil {
		return err
	}

	// For existing disks, seed memory/CPU from the disk's saved settings so
	// that the user's previous choices persist across restarts — but only when
	// the user did not explicitly pass -memory/-cpus on this invocation.
	if !isNewDisk {
		explicitFlags := map[string]bool{}
		fs.Visit(func(f *flag.Flag) { explicitFlags[f.Name] = true })
		if disk.MemoryGB > 0 && !explicitFlags["memory"] {
			*memory = disk.MemoryGB
		}
		if disk.CPUs > 0 && !explicitFlags["cpus"] {
			*cpus = disk.CPUs
		}
	}

	// Build VM configuration
	vmConfig := &vmStartConfig{
		DiskName:     disk.Name,
		DiskPath:     disk.Path,
		DiskSize:     disk.Size,
		ISOPath:      isoLocal,
		MemoryGB:     *memory,
		CPUs:         *cpus,
		NetworkMode:  *network,
		NetworkIface: networkIface,
		Display:      *display,
		DownloadsDir: downloadsDir,
		IsNewDisk:    isNewDisk,
		TakenNames:   diskNameSet(st),
	}

	// Show configuration and allow editing runtime settings
	if !*autoYes {
		var err error
		vmConfig, err = reviewVMConfig(vmConfig, stdin, stdout)
		if err != nil {
			return err
		}
		*memory = vmConfig.MemoryGB
		*cpus = vmConfig.CPUs
		*network = vmConfig.NetworkMode
		networkIface = vmConfig.NetworkIface
		*display = vmConfig.Display
		isoLocal = vmConfig.ISOPath

		// The review is the last writer of the mode, so the uplink is
		// resolved once more against what it settled on. A run that arrives
		// in any other mode -- which is every run that passes no -network at
		// all, since the flag defaults to shared -- skipped the resolution
		// above, and prompt 7 can still turn it into a bridged one. Without
		// this the interface stays empty: the sudo prompt a few steps down
		// would name nothing while vm.PrepareLinuxBridge went and detected an
		// uplink of its own, so the user would consent to enslaving an
		// interface nobody named.
		//
		// It is a second call and not a move, because a run that came in as
		// bridged has to see its interface on row 8 of the review it is being
		// shown. When that call already answered, this one returns the same
		// value without asking the host again.
		networkIface, err = resolveBridgeUplink(*network, networkIface)
		if err != nil {
			return err
		}
	}

	// Refuse a mode this host cannot give the privilege for, here and nowhere
	// else. Here, because the review above is the last writer of the mode --
	// a user who passed -network user and then answered "shared" at prompt 7
	// has to be told about shared -- and because nothing has been built yet:
	// no disk image, no bridge, no tap. Later would mean saying the run
	// cannot work after a 60 GB image exists, and the failure would arrive as
	// an opaque sudo password prompt followed by a vmnet error out of QEMU.
	// Nowhere else, because a second call at flag-parse time would print the
	// same refusal twice.
	if err := requireNetworkPrivilege(*network); err != nil {
		return err
	}

	// Materialize disk — done after review so the config is final.
	if isNewDisk {
		// Validate the final disk path stays within vmDir before touching the filesystem.
		absVMDir, err := filepath.Abs(vmDir)
		if err != nil {
			return fmt.Errorf("resolve vm directory: %w", err)
		}
		absDiskPath, err := filepath.Abs(vmConfig.DiskPath)
		if err != nil {
			return fmt.Errorf("resolve disk path: %w", err)
		}
		rel, err := filepath.Rel(absVMDir, absDiskPath)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			return fmt.Errorf("disk path %q must be within vm directory %q", vmConfig.DiskPath, vmDir)
		}

		writef(stdout, "Creating disk: %s (%s)\n", vmConfig.DiskName, vmConfig.DiskSize)
		// Remove any stale file from a previous abandoned attempt so that the
		// user-chosen size is always honoured (EnsureDisk is a no-op when the
		// file already exists).
		if err := os.Remove(absDiskPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove stale disk image: %w", err)
		}
		if err := vm.EnsureDisk(absDiskPath, vmConfig.DiskSize); err != nil {
			return err
		}
		isoName := ""
		if isoLocal != "" {
			isoName = filepath.Base(isoLocal)
		}
		newDisk := state.Disk{
			Name:      vmConfig.DiskName,
			Path:      absDiskPath,
			CreatedAt: state.NowRFC3339(),
			Size:      vmConfig.DiskSize,
			ISOName:   isoName,
		}
		state.AddDisk(st, newDisk)
		state.AddManagedFile(st, vmConfig.DiskPath)
		disk = state.FindDiskByName(st, vmConfig.DiskName)
		if disk == nil {
			return fmt.Errorf("internal error: disk not found after creation")
		}
	} else if vmConfig.DiskSize != disk.Size {
		// Existing disk: size was changed (gate already confirmed during review)
		writef(stdout, "Recreating disk at new size %s...\n", vmConfig.DiskSize)
		if err := os.Remove(disk.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove old disk image: %w", err)
		}
		if err := vm.EnsureDisk(disk.Path, vmConfig.DiskSize); err != nil {
			return err
		}
		if stateDisk := state.FindDiskByName(st, disk.Name); stateDisk != nil {
			stateDisk.Size = vmConfig.DiskSize
		}
		disk.Size = vmConfig.DiskSize
	}

	writeLine(stdout, "")
	writeLine(stdout, "A VM will start and attach to this terminal.")
	writeLine(stdout, "To exit the VM, press: Ctrl-a x")
	writeLine(stdout, "")
	if !*autoYes {
		writef(stdout, "Press Enter to start (or Ctrl-c to cancel): ")
		var buf [1]byte
		if _, err := stdin.Read(buf[:]); err != nil {
			return fmt.Errorf("cancelled")
		}
		if buf[0] != '\n' && buf[0] != '\r' {
			return fmt.Errorf("cancelled")
		}
		writeLine(stdout, "")
	}

	writeLine(stdout, "[1/3] Preparing networking")
	if *network == "bridged" && runtime.GOOS == "darwin" {
		// vmnet happily builds a bridge onto an interface with no link. The
		// VM then boots, looks healthy, and never gets a lease, so refuse
		// here instead (kairos-io/kairos#4431).
		if err := vm.ValidateBridgeIface(networkIface); err != nil {
			return err
		}
		if vm.IsWiFiIface(networkIface) {
			writeLine(stdout, vm.WiFiBridgeWarning(networkIface))
		}
	}
	if *network == "shared" && runtime.GOOS == "linux" {
		// No uplink is named in this prompt and none is recorded on the
		// state, because shared enslaves no physical interface: the bridge
		// vm.PrepareLinuxShared builds carries ipv4.method shared and has the
		// tap as its only port, and that call clears
		// st.Network.BridgeInterface for the same reason. A prompt naming an
		// interface would be asking the user to consent to something this
		// mode never does, and `status` would then report a stale uplink as
		// this VM's.
		//
		// The parenthesis is a promise about what the next step does, and
		// vm.PrepareLinuxShared is what keeps it: it reads the bridge's port
		// list out of the kernel three times -- before anything is
		// activated, once the bridge is up, and once the tap is on it -- and
		// refuses the run if the list holds anything it did not expect,
		// taking the bridge back down and deleting the connections it had
		// just written rather than leaving a host NIC on a NAT bridge. Until
		// the tap is activated it expects NO ports at all, so no name out of
		// state.json is exempt from the check.
		//
		// Stated no wider than that code states it. What is covered: any
		// port the kernel reports, whatever profile attached it and whether
		// the pre-flight's connection probes could see that profile at all;
		// and a port list that could not be read, which is a refusal there
		// and not a pass. What is not: an interface attached in the instant
		// after the last of the three checks returns, and any attached later,
		// since nothing reads the list again once the VM is running. One
		// probe there is still trusted to say no -- the /sys stat that asks
		// whether the bridge exists in the first place, which a host with no
		// readable /sys answers the same way as a host with no bridge.
		ok, err := confirm(stdin, stdout, *autoYes, "shared networking needs sudo to prepare a NAT bridge/tap (no uplink interface is used)")
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("sudo permission denied")
		}
		if err := vm.PrepareLinuxShared(st, runtimeDir); err != nil {
			return err
		}
	}
	if *network == "bridged" && runtime.GOOS == "linux" {
		// networkIface is resolved by now: resolveBridgeUplink ran against
		// the mode this run settled on, and returned an error rather than an
		// empty string if the host offered no candidate. So this prompt names
		// the interface that is about to be enslaved, which is the only form
		// of it worth asking -- "(uplink: )" asks the user to agree to
		// whatever vm.PrepareLinuxBridge goes on to detect for itself.
		st.Network.BridgeInterface = networkIface
		ok, err := confirm(stdin, stdout, *autoYes, fmt.Sprintf("bridged networking needs sudo to prepare bridge/tap (uplink: %s)", st.Network.BridgeInterface))
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("sudo permission denied")
		}
		if err := prepareLinuxBridge(st, runtimeDir); err != nil {
			return err
		}
		// Read back what the prepare enslaved instead of trusting what it
		// was asked for. From this caller that is a no-op today, and the
		// comment used to claim otherwise: the guarantee at the top of this
		// branch is that networkIface is non-empty here, and
		// vm.PrepareLinuxBridge runs a detection path of its own only when
		// the field arrives EMPTY -- so the name it writes back is the name
		// it was handed. The empty case is not live from here, and saying it
		// was made two comments eight lines apart contradict each other.
		//
		// The line stays as defence in depth, because what it keeps true is
		// a three-way agreement -- the prompt above, the recorded state and
		// the command line all naming one interface -- and it is the prepare
		// that decides which interface was enslaved, not this function.
		// Relax the guarantee above, or give the prepare any other reason to
		// use a different interface, and this readback is what stops the
		// three drifting apart without anyone noticing.
		networkIface = st.Network.BridgeInterface
	}

	// The guest NIC address is per-disk and sticky. A disk that already
	// carries one keeps it; one recorded before the field existed -- or one
	// created a moment ago -- gets a derived address filled in here and
	// persisted below. vm.MACForDisk hashes the disk name, so the address is
	// the same on every restart, which is what keeps a DHCP lease
	// attributable to this VM rather than to whichever guest last took
	// QEMU's single default address.
	//
	// A stored value is deliberately not validated here. netDeviceArg rejects
	// a corrupt one by name, which is an error the user can act on; quietly
	// replacing it with a derived address would start the VM on an address
	// state.json does not record.
	//
	// "Blank" has to mean the same thing here as it does there, which is why
	// this trims. netDeviceArg treats a whitespace-only value as unset and
	// emits a bare device, so a stored "   " that got past an untrimmed check
	// here handed the guest QEMU's single default address -- the collision
	// the derived one exists to avoid -- and then persisted the whitespace
	// below, so the next start did it again.
	//
	// disk.Name and not vmConfig.DiskName: the disk was re-fetched from state
	// after the review, so this is the name the image was created under. The
	// two differ whenever the review renamed a new disk, and deriving from
	// the pre-rename name would give the VM an address that no longer belongs
	// to the disk it boots.
	macAddress := disk.MAC
	if strings.TrimSpace(macAddress) == "" {
		macAddress = vm.MACForDisk(disk.Name)
	}

	biosPath := ""
	if runtime.GOOS == "darwin" {
		biosPath, err = macOSFirmwarePath()
		if err != nil {
			return err
		}
	}
	// Use short names for socket (Unix socket path limit is ~108 chars)
	qgaSock := filepath.Join(runtimeDir, "qemu.sock")
	logPath := filepath.Join(runtimeDir, "qemu.log")
	binary, qemuArgs, err := vm.BuildQEMUCommand(vm.StartConfig{
		ISOPath:       isoLocal,
		DiskPath:      disk.Path,
		QGASocketPath: qgaSock,
		CPUs:          *cpus,
		MemoryMB:      *memory * 1024,
		NetworkMode:   *network,
		DisplayMode:   *display,
		BridgeIface:   bridgeInterfaceForMode(*network, networkIface),
		LinuxTapName:  st.Network.TapName,
		MACAddress:    macAddress,
		MacOSBiosPath: biosPath,
	})
	if err != nil {
		return err
	}

	cmdName := binary
	cmdArgs := qemuArgs
	if vmnetNeedsSudo(runtime.GOOS, *network) {
		ok, err := confirm(stdin, stdout, *autoYes, vmnetSudoPrompt(*network))
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("sudo permission denied")
		}
		cmdName = "sudo"
		cmdArgs = append([]string{binary}, qemuArgs...)
	}

	writeLine(stdout, "[2/3] Recording VM state")
	// Persist the chosen memory and CPU settings on the disk so they become
	// the default next time this disk is started. Guard against zero/negative
	// values that could arrive via explicit flags (e.g. -memory 0) without
	// going through the interactive reviewer.
	if stateDisk := state.FindDiskByName(st, disk.Name); stateDisk != nil {
		if vmConfig.MemoryGB > 0 {
			stateDisk.MemoryGB = vmConfig.MemoryGB
		}
		if vmConfig.CPUs > 0 {
			stateDisk.CPUs = vmConfig.CPUs
		}
		stateDisk.MAC = macAddress
	}
	st.Network.Mode = *network
	st.Network.BridgeInterface = bridgeInterfaceForMode(*network, networkIface)
	st.VM.ISOLocal = isoLocal
	st.VM.DiskPath = disk.Path
	st.VM.DiskName = disk.Name
	st.VM.LogPath = logPath
	st.VM.QemuBinary = cmdName
	st.VM.QemuArgs = cmdArgs
	st.VM.StartedAt = state.NowRFC3339()
	st.VM.StoppedAt = ""
	st.VM.RuntimeDir = runtimeDir
	st.VM.QGASockPath = qgaSock
	st.VM.LastError = ""
	state.AddManagedFile(st, logPath)
	state.AddManagedFile(st, qgaSock)
	if err := store.Save(st); err != nil {
		return err
	}

	writeLine(stdout, "[3/3] Starting VM")
	writef(stdout, "Running: %s\n", renderCommand(cmdName, cmdArgs))
	if *network == "user" {
		writeLine(stdout, "user mode forwards: ssh localhost:2222, http localhost:8080")
	}

	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open log file: %w", err)
	}
	defer func() {
		_ = logFile.Close()
	}()

	command := exec.Command(cmdName, cmdArgs...)
	if sf, ok := stdin.(*os.File); ok {
		command.Stdin = sf
	} else {
		command.Stdin = os.Stdin
	}
	if cmdName == "sudo" {
		// sudo on macOS may fail with "unable to allocate pty" when stdio is
		// proxied through pipes. Keep stdio attached directly to the terminal.
		command.Stdout = stdout
		command.Stderr = stderr
	} else {
		command.Stdout = io.MultiWriter(stdout, logFile)
		command.Stderr = io.MultiWriter(stderr, logFile)
	}
	if err := command.Start(); err != nil {
		st.VM.LastError = err.Error()
		_ = store.Save(st)
		return fmt.Errorf("start qemu: %w", err)
	}
	st.VM.PID = command.Process.Pid
	if err := store.Save(st); err != nil {
		_ = command.Process.Kill()
		return err
	}

	waitErr := command.Wait()
	st.VM.PID = 0
	st.VM.StoppedAt = state.NowRFC3339()
	if waitErr != nil {
		st.VM.LastError = waitErr.Error()
		_ = store.Save(st)
		return fmt.Errorf("vm exited with error: %w (log: %s)", waitErr, logPath)
	}
	st.VM.LastError = ""
	if err := store.Save(st); err != nil {
		return err
	}
	writeLine(stdout, "vm exited")
	return nil
}

func runStatus(stdout io.Writer, store *state.Store) error {
	st, err := store.Load()
	if err != nil {
		return err
	}
	if err := requireSetup(st); err != nil {
		return err
	}
	p := platform.Detect()
	req := deps.Required(p)
	present := deps.PresentNames(req)
	running, _ := vm.IsRunning(st.VM.PID)

	platformLabel := st.Platform.OS + "/" + st.Platform.Arch
	if st.Platform.OS == "" {
		platformLabel = p.OS + "/" + p.Arch + " (detected)"
	}
	pm := st.Platform.PackageManager
	if pm == "" {
		pm = p.PackageManager + " (detected)"
	}

	writef(stdout, "platform: %s\n", platformLabel)
	writef(stdout, "package manager: %s\n", pm)
	writef(stdout, "dependencies present now: %s\n", joinOrNone(present))
	writef(stdout, "dependencies pre-existing: %s\n", joinOrNone(st.Setup.PreExistingDeps))
	writef(stdout, "dependencies installed by kairos-lab: %s\n", joinOrNone(st.Setup.InstalledByKairosLab))
	writef(stdout, "managed dirs: %s\n", joinOrNone(st.ManagedDirs))
	writef(stdout, "managed files: %s\n", joinOrNone(st.ManagedFiles))
	writef(stdout, "iso source: %s\n", emptyAsNone(st.VM.ISOSource))
	writef(stdout, "iso path: %s\n", emptyAsNone(st.VM.ISOLocal))
	writef(stdout, "disk path: %s\n", emptyAsNone(st.VM.DiskPath))
	writef(stdout, "network mode: %s\n", emptyAsNone(st.Network.Mode))
	if st.Network.Mode == "bridged" {
		writef(stdout, "bridge iface: %s%s\n", emptyAsNone(st.Network.BridgeInterface), bridgeIfaceLinkNote(st.Network.BridgeInterface))
		writef(stdout, "bridge resources: bridge=%s tap=%s\n", emptyAsNone(st.Network.BridgeName), emptyAsNone(st.Network.TapName))
	}
	writef(stdout, "vm running: %t\n", running)
	if running {
		writef(stdout, "vm pid: %d\n", st.VM.PID)
	}
	if st.VM.LastError != "" {
		writef(stdout, "last vm error: %s\n", st.VM.LastError)
	}
	return nil
}

func runReset(args []string, stdin io.Reader, stdout io.Writer, store *state.Store) error {
	fs := flag.NewFlagSet("reset", flag.ContinueOnError)
	dryRun := fs.Bool("dry-run", false, "show what would be removed")
	autoYes := fs.Bool("yes", false, "auto-confirm destructive operations")
	diskToRemove := fs.String("disk", "", "remove specific disk by name (default: all)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := rejectPositionalArgs(fs, "remove a single disk with -disk"); err != nil {
		return err
	}

	st, err := store.Load()
	if err != nil {
		return err
	}
	if err := requireSetup(st); err != nil {
		return err
	}

	running, _ := vm.IsRunning(st.VM.PID)
	if running {
		return fmt.Errorf("a VM is still running (PID %d). Exit the VM first (Ctrl-a x in serial console)", st.VM.PID)
	}

	// Collect paths to remove
	var paths []string
	var disksToRemove []state.Disk

	if *diskToRemove != "" {
		// Remove specific disk
		disk := state.FindDiskByName(st, *diskToRemove)
		if disk == nil {
			return fmt.Errorf("disk not found: %s", *diskToRemove)
		}
		disksToRemove = append(disksToRemove, *disk)
		paths = append(paths, disk.Path)
	} else {
		// Remove all disks
		for _, d := range st.Disks {
			disksToRemove = append(disksToRemove, d)
			paths = append(paths, d.Path)
		}
	}

	// Add runtime files
	paths = append(paths, st.VM.LogPath, st.VM.QGASockPath)

	toRemove, toSkip := splitRemovalPaths(paths, st)

	writeLine(stdout, "reset plan:")
	if len(disksToRemove) > 0 {
		writeLine(stdout, "Will remove disks:")
		for _, d := range disksToRemove {
			writef(stdout, "  - %s\n", planValue(d.Name))
		}
	}
	printRemovalPlan(stdout, "reset", toRemove, toSkip)
	hasStaleNetwork := vm.HasStaleNetworkResources(st)
	if runtime.GOOS == "linux" && st.Network.CreatedByKairosLab {
		// Both names come out of state.json, which anything running as the
		// user can write, and these rows reach the terminal just above the
		// confirmation prompt -- a stored newline plus a CSI sequence would
		// forge a plan row and erase the real one, so the user would consent
		// to a plan they were never shown. The validator in internal/vm only
		// fires later, inside the cleanup itself. Nothing is escaped here:
		// printList runs every row through planValue, which quotes a row only
		// when it carries something a terminal would act on, so an ordinary
		// run still reads "bridge: kairoslab0". Escaping at this call site
		// would protect these two rows and no others -- which is exactly the
		// hole this replaced.
		printList(stdout, "Will clean up network resources", []string{
			"bridge: " + nonEmpty(st.Network.BridgeName, vm.DefaultBridgeName),
			"tap: " + nonEmpty(st.Network.TapName, vm.DefaultTapName),
		})
	} else if hasStaleNetwork {
		printList(stdout, "Will clean up stale network resources (from failed/interrupted setup)", []string{
			"bridge: " + vm.DefaultBridgeName,
			"connections: " + vm.DefaultBridgeName + ", " + vm.DefaultBridgeName + "-uplink, " + vm.DefaultBridgeName + "-tap",
		})
	}

	if *dryRun {
		writeLine(stdout, "dry-run only, no changes made")
		return nil
	}

	ok, err := confirm(stdin, stdout, *autoYes, "proceed with reset")
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("reset cancelled")
	}

	for _, p := range toRemove {
		// planValue on both halves: the echo and the error that may follow it
		// carry the same stored path, and the error is the one that can
		// rewrite the echo above it -- the only record of what was deleted.
		writef(stdout, "Removing: %s\n", planValue(p))
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove %s: %w", planValue(p), bareFileError(err))
		}
		state.RemoveManagedFile(st, p)
	}

	// Remove disks from state
	for _, d := range disksToRemove {
		state.RemoveDisk(st, d.Name)
	}

	// The error itself is kept, not a bool: it is the only thing that knows
	// WHICH part of the teardown failed. A refusal means nothing was touched
	// and a stored name has to be corrected; a partial failure means some
	// connections and links went and others did not, with the stored names
	// perfectly fine. The outcome reported at the end says which of those
	// happened by carrying this error into it.
	var networkCleanupErr error
	if runtime.GOOS == "linux" && st.Network.CreatedByKairosLab {
		writeLine(stdout, "Cleaning up the network kairos-lab created...")
		if err := vm.CleanupLinuxBridge(st); err != nil {
			writef(stdout, "warning: bridge cleanup failed: %v\n", err)
			networkCleanupErr = err
		}
	} else if hasStaleNetwork {
		writeLine(stdout, "Cleaning up stale network resources...")
		if err := vm.CleanupStaleNetworkResources(st); err != nil {
			writef(stdout, "warning: stale network cleanup failed: %v\n", err)
			networkCleanupErr = err
		}
	}

	st.VM = state.VM{}
	if err := store.Save(st); err != nil {
		return err
	}
	// The disks and files are gone either way, which is why the failure above
	// is a warning and not an abort. But "reset complete" after a teardown
	// that did not finish is a lie the user has no way to see through, and the
	// next reset would print the same warning forever.
	//
	// What did not happen is not guessed at: the network layer returns the
	// failures it collected, and this message carries them instead of
	// asserting that every resource is still on the host and that a stored
	// name is at fault. A refusal means exactly that; a partial teardown
	// means some resources went and the names were never the problem.
	if networkCleanupErr != nil {
		return fmt.Errorf("reset incomplete: disks and files were removed, but the network cleanup did not finish: %w. What it names is still on the host; if the failure is about a stored bridge or tap name, correct it in stored configuration (%s), then run reset again", networkCleanupErr, store.StatePath)
	}
	writeLine(stdout, "reset complete")
	return nil
}

func runCleanup(args []string, stdin io.Reader, stdout io.Writer, store *state.Store) error {
	fs := flag.NewFlagSet("cleanup", flag.ContinueOnError)
	autoYes := fs.Bool("yes", false, "auto-confirm destructive operations")
	dryRun := fs.Bool("dry-run", false, "show what would be removed")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := rejectPositionalArgs(fs, ""); err != nil {
		return err
	}

	st, err := store.Load()
	if err != nil {
		return err
	}
	if err := requireSetup(st); err != nil {
		return err
	}

	pm := st.Platform.PackageManager
	pinfo := platform.Detect()
	if pm == "" {
		pm = pinfo.PackageManager
	}
	removeDeps := cleanup.DependenciesToRemove(st.Setup.PreExistingDeps, st.Setup.InstalledByKairosLab)
	required := deps.Required(pinfo)
	pkgRemovals := []string{}
	if len(removeDeps) > 0 && pm != "" {
		pkgRemovals, err = deps.UninstallablePackages(pm, removeDeps, required)
		if err != nil {
			return err
		}
	}

	filesToRemove, filesToSkip := splitRemovalPaths(st.ManagedFiles, st)
	dirsToRemove, dirsToSkip := splitRemovalPaths(st.ManagedDirs, st)

	writeLine(stdout, "cleanup plan:")
	printList(stdout, "Will remove files", filesToRemove)
	printListWithReasons(stdout, "Will skip files", filesToSkip)
	printList(stdout, "Will remove directories", dirsToRemove)
	printListWithReasons(stdout, "Will skip directories", dirsToSkip)
	printList(stdout, "Will uninstall dependencies", pkgRemovals)
	printList(stdout, "Will keep dependencies (pre-existing)", st.Setup.PreExistingDeps)

	hasStaleNetwork := vm.HasStaleNetworkResources(st)
	if runtime.GOOS == "linux" && st.Network.CreatedByKairosLab {
		// Both names come out of state.json, which anything running as the
		// user can write, and these rows reach the terminal just above the
		// confirmation prompt -- a stored newline plus a CSI sequence would
		// forge a plan row and erase the real one, so the user would consent
		// to a plan they were never shown. The validator in internal/vm only
		// fires later, inside the cleanup itself. Nothing is escaped here:
		// printList runs every row through planValue, which quotes a row only
		// when it carries something a terminal would act on, so an ordinary
		// run still reads "bridge: kairoslab0". Escaping at this call site
		// would protect these two rows and no others -- which is exactly the
		// hole this replaced.
		printList(stdout, "Will clean up network resources", []string{
			"bridge: " + nonEmpty(st.Network.BridgeName, vm.DefaultBridgeName),
			"tap: " + nonEmpty(st.Network.TapName, vm.DefaultTapName),
		})
	} else if hasStaleNetwork {
		printList(stdout, "Will clean up stale network resources (from failed/interrupted setup)", []string{
			"bridge: " + vm.DefaultBridgeName,
			"connections: " + vm.DefaultBridgeName + ", " + vm.DefaultBridgeName + "-uplink, " + vm.DefaultBridgeName + "-tap",
		})
	}

	if *dryRun {
		writeLine(stdout, "dry-run only, no changes made")
		return nil
	}

	ok, err := confirm(stdin, stdout, *autoYes, "cleanup removes all kairos-lab artifacts and tool-installed dependencies")
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("cleanup cancelled")
	}

	running, _ := vm.IsRunning(st.VM.PID)
	if running {
		return fmt.Errorf("a VM is still running (PID %d). Exit the VM first (Ctrl-a x in serial console)", st.VM.PID)
	}

	// The error itself is kept, not a bool: it is the only thing that knows
	// WHICH part of the teardown failed. A refusal means nothing was touched
	// and a stored name has to be corrected; a partial failure means some
	// connections and links went and others did not, with the stored names
	// perfectly fine. The outcome reported at the end says which of those
	// happened by carrying this error into it.
	var networkCleanupErr error
	if runtime.GOOS == "linux" && st.Network.CreatedByKairosLab {
		writeLine(stdout, "Cleaning up the network kairos-lab created...")
		if err := vm.CleanupLinuxBridge(st); err != nil {
			writef(stdout, "warning: bridge cleanup failed: %v\n", err)
			networkCleanupErr = err
		}
	} else if hasStaleNetwork {
		writeLine(stdout, "Cleaning up stale network resources...")
		if err := vm.CleanupStaleNetworkResources(st); err != nil {
			writef(stdout, "warning: stale network cleanup failed: %v\n", err)
			networkCleanupErr = err
		}
	}

	if len(pkgRemovals) > 0 && pm != "" {
		useSudo := runtime.GOOS == "linux"
		if useSudo {
			ok, err := confirm(stdin, stdout, *autoYes, "remove kairos-lab-installed dependencies with sudo")
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("cleanup cancelled")
			}
		}
		if err := deps.Uninstall(pm, pkgRemovals, useSudo); err != nil {
			return err
		}
	}

	for _, p := range filesToRemove {
		writef(stdout, "Removing file: %s\n", planValue(p))
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove file %s: %w", planValue(p), bareFileError(err))
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(dirsToRemove)))
	for _, d := range dirsToRemove {
		writef(stdout, "Removing directory: %s\n", planValue(d))
		if err := os.RemoveAll(d); err != nil {
			return fmt.Errorf("remove directory %s: %w", planValue(d), bareFileError(err))
		}
	}
	if err := store.RemoveStateFile(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// Same reasoning as reset, minus the way out: the state file has just been
	// removed, so there is no stored name left to correct and no command left
	// to re-run. Whatever the teardown could not remove has to be removed by
	// hand, and saying "cleanup complete" here would be how the user never
	// learns that.
	if networkCleanupErr != nil {
		return fmt.Errorf("cleanup incomplete: files and dependencies were removed, but the network cleanup did not finish: %w. What it names is still on the host, and stored configuration is gone, so remove those connections and links with nmcli by hand", networkCleanupErr)
	}
	writeLine(stdout, "cleanup complete")
	return nil
}

func printUsage(w io.Writer) {
	writeLine(w, "kairos-lab: local Kairos workshop CLI")
	writeLine(w, "")
	writeLine(w, "Quick start:")
	writeLine(w, "  kairos-lab download             Download a Kairos ISO")
	writeLine(w, "  kairos-lab start                Create disk and boot ISO")
	writeLine(w, "  kairos-lab start                Boot existing disk (after install)")
	writeLine(w, "")
	writeLine(w, "Commands:")
	writeLine(w, "  setup                Detect/install dependencies")
	writeLine(w, "  download             Download a Kairos ISO (interactive selection)")
	writeLine(w, "  start [flags]        Boot VM (select/create disk, optionally attach ISO)")
	writeLine(w, "  status               Show state and runtime information")
	writeLine(w, "  reset [--disk name]  Remove disks and network (keep setup/ISOs)")
	writeLine(w, "  cleanup              Remove everything created by tool")
	writeLine(w, "  version              Print CLI version")
	writeLine(w, "")
	writeLine(w, "Start flags:")
	writeLine(w, "  -name <name>         Use/create disk with this name")
	writeLine(w, "  -new                 Create new disk (even if others exist)")
	writeLine(w, "  -no-iso              Boot without ISO (installed system)")
	writeLine(w, "  -iso <path>          Use specific ISO file")
	writeLine(w, "")
	writeLine(w, "Exit VM with Ctrl-a x (QEMU serial console quit)")
}

func writeLine(w io.Writer, a ...any) {
	_, _ = fmt.Fprintln(w, a...)
}

func writef(w io.Writer, format string, a ...any) {
	_, _ = fmt.Fprintf(w, format, a...)
}

func confirm(stdin io.Reader, stdout io.Writer, autoYes bool, msg string) (bool, error) {
	if autoYes {
		return true, nil
	}
	writef(stdout, "%s [y/N]: ", msg)
	var answer string
	if _, err := fmt.Fscanln(stdin, &answer); err != nil {
		if errors.Is(err, io.EOF) {
			return false, nil
		}
		return false, err
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "y" || answer == "yes", nil
}

func prompt(stdin io.Reader, stdout io.Writer, msg string) (string, error) {
	writef(stdout, "%s: ", msg)
	reader := bufio.NewReader(stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		if errors.Is(err, io.EOF) && line == "" {
			return "", fmt.Errorf("no input")
		} else if !errors.Is(err, io.EOF) {
			return "", err
		}
	}
	return strings.TrimSpace(line), nil
}

type vmStartConfig struct {
	DiskName     string
	DiskPath     string
	DiskSize     string
	ISOPath      string
	MemoryGB     int
	CPUs         int
	NetworkMode  string
	NetworkIface string
	Display      string
	DownloadsDir string
	IsNewDisk    bool
	TakenNames   map[string]struct{}
}

func reviewVMConfig(cfg *vmStartConfig, stdin io.Reader, stdout io.Writer) (*vmStartConfig, error) {
	// systemRAMGB never changes during a session — compute once outside the loop.
	ramGB := systemRAMGB()
	ramHint := ""
	if ramGB > 0 {
		ramHint = fmt.Sprintf("  (%d GB available)", ramGB)
	}

	for {
		writeLine(stdout, "")
		diskFreeGB := freeSpaceGB(filepath.Dir(cfg.DiskPath))
		diskHint := ""
		if diskFreeGB > 0 {
			diskHint = fmt.Sprintf("  (%d GB free)", diskFreeGB)
		}
		writeLine(stdout, "VM Configuration:")
		writef(stdout, "  1) Disk name:    %s\n", cfg.DiskName)
		writef(stdout, "  2) Disk path:    %s\n", cfg.DiskPath)
		writef(stdout, "  3) Disk size:    %d GB%s\n", parseSizeGB(cfg.DiskSize), diskHint)
		if cfg.ISOPath != "" {
			writef(stdout, "  4) ISO:          %s\n", filepath.Base(cfg.ISOPath))
		} else {
			writeLine(stdout, "  4) ISO:          (none - booting from disk)")
		}
		writef(stdout, "  5) Memory:       %d GB%s\n", cfg.MemoryGB, ramHint)
		writef(stdout, "  6) CPUs:         %d  (%d logical CPUs on host)\n", cfg.CPUs, runtime.NumCPU())
		writef(stdout, "  7) Network:      %s\n", cfg.NetworkMode)
		if bridgedIfaceSelectable(cfg.NetworkMode) {
			writef(stdout, "  8) Net interface: %s\n", cfg.NetworkIface)
		} else {
			writeLine(stdout, "  8) Net interface: (n/a)")
		}
		writef(stdout, "  9) Display:      %s\n", cfg.Display)
		writeLine(stdout, "")
		writef(stdout, "Press Enter to continue, or enter a number to edit: ")

		reader := bufio.NewReader(stdin)
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("cancelled")
		}
		line = strings.TrimSpace(line)

		if line == "" {
			return cfg, nil
		}

		choice := 0
		if _, err := fmt.Sscanf(line, "%d", &choice); err != nil {
			writeLine(stdout, "Invalid input, please enter a number or press Enter to continue")
			continue
		}

		switch choice {
		case 1:
			if !cfg.IsNewDisk {
				writeLine(stdout, "(disk name cannot be changed for an existing disk)")
				break
			}
			val, err := prompt(stdin, stdout, "Enter disk name")
			if err != nil {
				return nil, err
			}
			if val != "" {
				if err := validDiskName(val); err != nil {
					writef(stdout, "Invalid name: %v\n", err)
					break
				}
				if _, taken := cfg.TakenNames[val]; taken {
					writef(stdout, "A disk named %q already exists, choose a different name.\n", val)
					break
				}
				cfg.DiskName = val
				cfg.DiskPath = filepath.Join(filepath.Dir(cfg.DiskPath), val+".qcow2")
			}
		case 2:
			if !cfg.IsNewDisk {
				writeLine(stdout, "(disk path cannot be changed for an existing disk)")
				break
			}
			writeLine(stdout, "(disk path is derived from the disk name — change the name to update the path)")
		case 3:
			if cfg.IsNewDisk {
				val, err := prompt(stdin, stdout, "Enter disk size in GB (e.g., 20, 60)")
				if err != nil {
					return nil, err
				}
				if val != "" {
					gb, err := strconv.Atoi(strings.TrimSpace(val))
					if err != nil || gb <= 0 {
						writeLine(stdout, "Invalid disk size, enter a number in GB (e.g., 20, 60)")
					} else {
						cfg.DiskSize = fmt.Sprintf("%dG", gb)
					}
				}
			} else {
				writeLine(stdout, "Warning: changing disk size will delete and recreate the disk image.")
				writeLine(stdout, "Any existing data on the disk will be lost.")
				ok, err := confirm(stdin, stdout, false, "I understand and want to change the disk size")
				if err != nil {
					return nil, err
				}
				if !ok {
					writeLine(stdout, "Cancelled.")
					break
				}
				val, err := prompt(stdin, stdout, "Enter new disk size in GB (e.g., 20, 60)")
				if err != nil {
					return nil, err
				}
				if val != "" {
					gb, err := strconv.Atoi(strings.TrimSpace(val))
					if err != nil || gb <= 0 {
						writeLine(stdout, "Invalid disk size, enter a number in GB (e.g., 20, 60)")
					} else {
						cfg.DiskSize = fmt.Sprintf("%dG", gb)
					}
				}
			}
		case 4:
			writeLine(stdout, "")
			selectedISO, err := iso.SelectOrDownloadISO(cfg.DownloadsDir, stdin, stdout)
			if err != nil {
				writef(stdout, "ISO selection failed: %v\n", err)
			} else {
				cfg.ISOPath = selectedISO
			}
		case 5:
			val, err := prompt(stdin, stdout, "Enter memory in GB (e.g., 4, 8)")
			if err != nil {
				return nil, err
			}
			if val != "" {
				gb, err := strconv.Atoi(strings.TrimSpace(val))
				if err != nil || gb <= 0 {
					writeLine(stdout, "Invalid memory value, enter a number in GB (e.g., 4, 8)")
				} else {
					cfg.MemoryGB = gb
				}
			}
		case 6:
			val, err := prompt(stdin, stdout, "Enter number of CPUs (e.g., 2, 4)")
			if err != nil {
				return nil, err
			}
			if val != "" {
				var cpus int
				if _, err := fmt.Sscanf(val, "%d", &cpus); err == nil && cpus > 0 {
					cfg.CPUs = cpus
				} else {
					writeLine(stdout, "Invalid CPU value")
				}
			}
		case 7:
			val, err := prompt(stdin, stdout, "Enter network mode (shared, bridged or user)")
			if err != nil {
				return nil, err
			}
			// An empty answer is "leave it alone" and stays silent: Enter
			// is the way out of this sub-prompt, not a mistake. Anything
			// else that is not a mode prints the rejection and falls
			// through to the menu, so the user answers again inside the
			// review instead of losing the rest of the configuration they
			// just edited to a hard error.
			switch {
			case networkModeValid(val):
				cfg.NetworkMode = val
				// A mode chosen here is a mode the run did not arrive in,
				// so entry 8 can have nothing to show: a start that came
				// in as shared or user never resolved an interface. Fill
				// one in now, so the row above reads as the interface the
				// run is going to enslave rather than as a blank the user
				// has to know to go and set.
				//
				// A host that offers none is not an error here. runStart
				// resolves again after the review and reports it there;
				// refusing inside the menu would throw away every other
				// edit made in it, and the row simply stays empty until
				// then.
				if iface, err := resolveBridgeUplink(cfg.NetworkMode, cfg.NetworkIface); err == nil {
					cfg.NetworkIface = iface
				}
			case val != "":
				writeLine(stdout, "Invalid network mode, use 'shared', 'bridged' or 'user'")
			}
		case 8:
			if bridgedIfaceSelectable(cfg.NetworkMode) {
				candidates := bridgeIfaceCandidates()
				if len(candidates) > 1 {
					writeLine(stdout, "Available interfaces:")
					for i, iface := range candidates {
						writef(stdout, "  %d) %s\n", i+1, iface)
					}
					val, err := prompt(stdin, stdout, fmt.Sprintf("Select interface [1-%d]", len(candidates)))
					if err != nil {
						return nil, err
					}
					var idx int
					if _, err := fmt.Sscanf(val, "%d", &idx); err == nil && idx >= 1 && idx <= len(candidates) {
						cfg.NetworkIface = candidates[idx-1]
					} else {
						writeLine(stdout, "Invalid selection")
					}
				} else {
					val, err := prompt(stdin, stdout, "Enter interface name")
					if err != nil {
						return nil, err
					}
					if val != "" {
						cfg.NetworkIface = val
					}
				}
			} else {
				writeLine(stdout, "Invalid option (a network interface applies to bridged mode only, on Linux and macOS; shared mode attaches to no host interface)")
			}
		case 9:
			val, err := prompt(stdin, stdout, "Enter display mode (window or serial)")
			if err != nil {
				return nil, err
			}
			if val == "window" || val == "serial" {
				cfg.Display = val
			} else if val != "" {
				writeLine(stdout, "Invalid display mode, use 'window' or 'serial'")
			}
		default:
			writeLine(stdout, "Invalid option")
		}
	}
}

func depNames(ds []deps.Dependency) []string {
	out := make([]string, 0, len(ds))
	for _, d := range ds {
		out = append(out, d.Name)
	}
	sort.Strings(out)
	return out
}

func mergeUnique(a, b []string) []string {
	set := map[string]struct{}{}
	for _, v := range a {
		if v != "" {
			set[v] = struct{}{}
		}
	}
	for _, v := range b {
		if v != "" {
			set[v] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func defaultMemoryMB() int {
	if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" {
		return 8192
	}
	return 4096
}

// systemRAMGB returns the host's total physical RAM in GB, or 0 if undetectable.
func systemRAMGB() int {
	switch runtime.GOOS {
	case "darwin":
		out, err := exec.Command("sysctl", "-n", "hw.memsize").Output()
		if err != nil {
			return 0
		}
		b, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
		if err != nil {
			return 0
		}
		return int(b / (1024 * 1024 * 1024))
	case "linux":
		data, err := os.ReadFile("/proc/meminfo")
		if err != nil {
			return 0
		}
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "MemTotal:") {
				fields := strings.Fields(line)
				if len(fields) < 2 {
					return 0
				}
				kb, err := strconv.ParseInt(fields[1], 10, 64)
				if err != nil {
					return 0
				}
				return int(kb / (1024 * 1024))
			}
		}
	}
	return 0
}

// freeSpaceGB returns the free disk space in GB at the given path, or 0 if undetectable.
func freeSpaceGB(path string) int {
	out, err := exec.Command("df", "-k", path).Output()
	if err != nil {
		return 0
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 2 {
		return 0
	}
	fields := strings.Fields(lines[len(lines)-1])
	if len(fields) < 4 {
		return 0
	}
	kb, err := strconv.ParseInt(fields[3], 10, 64)
	if err != nil {
		return 0
	}
	return int(kb / (1024 * 1024))
}

// parseSizeGB parses a size string like "60G" or "60" into an integer GB value.
func parseSizeGB(s string) int {
	s = strings.TrimSuffix(strings.TrimSpace(strings.ToUpper(s)), "G")
	n, _ := strconv.Atoi(s)
	return n
}

// bridgeIfaceLinkNote annotates the bridge interface in `status` output with
// its link state, so a bridge onto a dead port is visible without the user
// having to reach for ifconfig (kairos-io/kairos#4431). It is empty on
// platforms that do not report one.
func bridgeIfaceLinkNote(iface string) string {
	if iface == "" {
		return ""
	}
	switch status := vm.BridgeIfaceStatus(iface); status {
	case "":
		return ""
	case "active":
		return " (link active)"
	default:
		return fmt.Sprintf(" (link %s - the VM will not get an address over this interface)", status)
	}
}

// bridgeIfaceCandidates lists the host interfaces bridged networking can use,
// most likely first. Linux bridges through a NetworkManager uplink, macOS
// through vmnet, so the two enumerate different things.
//
// It is a var rather than a func so a test can answer for the host. Both
// implementations shell out -- `ip route show default` on Linux, the vmnet
// interface list on macOS -- and the answer is whatever the machine running
// the suite happens to be plugged into: a container whose only default route
// is a filtered virtual device, or a macOS runner with no active link, both
// answer "nothing". Every assertion about which interface a bridged run names
// and records needs a known answer, and asking the host for one is how a test
// comes to pass on a laptop and fail on a CI leg.
var bridgeIfaceCandidates = func() []string {
	switch runtime.GOOS {
	case "linux":
		return vm.DetectUplinkCandidates()
	case "darwin":
		return vm.DetectBridgeIfaceCandidates()
	}
	return nil
}

// resolveBridgeUplink answers which host interface a bridged run attaches to,
// filling in a candidate from the host when the user named none.
//
// It is called twice by runStart, before and after the config review, and
// that is the point of it being a function: the mode is not final until the
// review returns, so a gate on the flag's mode and a gate on the reviewed one
// are two different gates. They used to be exactly that -- detection keyed on
// the flag, the sudo consent prompt keyed on the reviewed mode -- which
// agreed only for as long as the flag defaulted to bridged. Once the default
// moved to shared, a user who chose bridged at prompt 7 got a consent prompt
// naming no interface at all, and vm.PrepareLinuxBridge then picked one and
// enslaved it.
//
// Calling it a second time costs nothing when the first already answered: a
// non-empty interface is returned unchanged, and the host is asked only when
// there is nothing to return.
//
// The gate is bridgedIfaceSelectable, the same predicate the review's entry 8
// uses to decide whether an interface is the user's to choose. shared and
// user attach to no interface, so for them the flag's value is passed through
// untouched and dropped later by bridgeInterfaceForMode.
func resolveBridgeUplink(mode, iface string) (string, error) {
	if !bridgedIfaceSelectable(mode) || iface != "" {
		return iface, nil
	}
	candidates := bridgeIfaceCandidates()
	if len(candidates) == 0 {
		return "", noBridgeUplinkError(runtime.GOOS)
	}
	// With several candidates the first one wins and the config review lets
	// the user change it at entry 8.
	return candidates[0], nil
}

// noBridgeUplinkError is what a bridged run is told when the host offers no
// interface to attach to. The two platforms fail differently enough to be
// worth different sentences: on Linux there is no default route through
// anything physical, on macOS no interface reports an active link, and vmnet
// would happily bridge onto the dead one (kairos-io/kairos#4431).
//
// goos is a parameter rather than runtime.GOOS so that both messages are
// reachable from either CI leg. A GOOS-gated string is a string only one leg
// can pin, and this one tells the user their two ways out of the failure.
func noBridgeUplinkError(goos string) error {
	if goos == "darwin" {
		return fmt.Errorf("no host interface has a link, so bridged networking would leave the VM without an address (use -bridge-if to specify one, or -network user for port-forwarded access)")
	}
	return fmt.Errorf("no suitable uplink interface found for bridged networking (use -bridge-if to specify one, or -network user for port-forwarded access)")
}

// vmnetNeedsSudo reports whether QEMU itself has to be launched as root.
//
// Both vmnet modes, not just bridged: shared is -netdev vmnet-shared and
// needs root exactly as vmnet-bridged does (vm.RequireNetworkPrivilege's
// darwinRootModes is the same pair). Launched unprivileged, QEMU exits
// non-zero with a vmnet error and no VM. On Linux nothing here runs as root:
// the bridge and the tap are prepared beforehand by NetworkManager, and QEMU
// opens a tap that already belongs to the user.
//
// goos is a parameter and not runtime.GOOS because the decision is otherwise
// pinnable on one CI leg only -- narrowing it back to bridged alone, which is
// what it said before shared was wired up, survived the entire suite.
func vmnetNeedsSudo(goos, mode string) bool {
	return goos == "darwin" && (mode == "bridged" || mode == "shared")
}

// vmnetSudoPrompt is what that consent asks. It names the mode the user
// actually chose, so consent is asked for the run they asked for, and it is
// built here rather than inline for the same reason as above: the branch it
// is printed from runs on darwin only, so this is the only place a test on
// either leg can read it.
func vmnetSudoPrompt(mode string) string {
	return fmt.Sprintf("%s vmnet mode runs qemu with sudo", mode)
}

// networkModes is the whole set of modes the CLI accepts, and it lives here,
// alone, because the set used to be spelled out inline at each of the two
// places a mode string is checked -- once in runStart against the -network
// flag, and once in reviewVMConfig against what the user types at prompt 7 --
// and those two drifted the moment a mode was added. Adding a mode to the flag
// and forgetting the reviewer leaves the CLI in the state where a run can be
// started in the new mode but the config review cannot select it back, and
// rejects the very value the flag just handed it, which is invisible to anyone
// who passes -yes and unavoidable for everyone who does not.
//
// So a fourth mode is one entry in the slice below and nothing else: the
// flag's validation, the reviewer's prompt and both rejection messages then
// agree by construction.
//
// Every mode in this slice is runnable on both supported platforms. There
// used to be a second question here -- whether a mode the CLI accepts could
// actually be run on this host -- because nothing prepared the host side of
// shared on Linux; it was answered by a temporary networkModeUnavailable that
// refused shared at both places a mode is chosen. runStart now calls
// vm.PrepareLinuxShared, so the mode has a host side on Linux as well as on
// macOS and there is no such question left to ask. Which of these the
// -network flag defaults to is a separate decision, and it is
// defaultNetworkMode below.
//
// Matching is deliberately exact. "Shared", "SHARED" and " shared" are all
// rejected rather than folded, both because every other enumerated value in
// this CLI (the display mode validated right after the network one in
// runStart, the subcommand names in Run) is matched exactly too, and because
// a tolerated near-miss would be written to state.json and handed to
// internal/vm, where BuildQEMUCommand compares the mode exactly and quietly
// falls back to user networking for anything it does not recognise -- a VM
// that boots, looks healthy, and is on the wrong network.
var networkModes = []string{"shared", "bridged", "user"}

// defaultNetworkMode is what the -network flag falls back to, and it is
// shared because that is the mode that works on the most hosts with the
// fewest surprises: it needs no uplink interface, so it runs on a Wi-Fi-only
// laptop where bridged cannot (no guest frame leaves the host with a MAC the
// access point never saw associate), and unlike user mode it gives each guest
// a real address on a NAT subnet, so several VMs can see each other and form
// a cluster. bridged is still one flag away for anyone who needs the VM on
// the LAN itself.
const defaultNetworkMode = "shared"

// networkModeValid reports whether mode is one the CLI accepts. The empty
// string is not one of them, which the reviewer relies on: an empty answer at
// prompt 7 means "leave it alone", so it must fail this check and then be
// filtered out ahead of the rejection message rather than being accepted here.
func networkModeValid(mode string) bool {
	return slices.Contains(networkModes, mode)
}

// bridgeInterfaceForMode answers what host interface this run attaches to, and
// it exists because the answer has to be the same in the two places runStart
// records it: on st.Network, which is what `status` prints and what the
// teardown reads, and on vm.StartConfig.BridgeIface, whose own doc says the
// field "is meaningful only for bridged mode".
//
// Only bridged attaches to an interface. shared builds a NAT bridge with no
// port but the tap -- vm.PrepareLinuxShared clears st.Network.BridgeInterface
// on purpose, and macOS vmnet-shared takes no ifname at all -- and user mode
// needs none. So the flag's value is dropped for both rather than carried:
// `start -network shared -bridge-if eth0` otherwise records an uplink the run
// never used, which is a lie state.json keeps until the next bridged start.
//
// What it answers for bridged is only as good as what it is handed, and the
// caller is careful about that. On Linux, iface is what vm.PrepareLinuxBridge
// reported having enslaved, not what it was asked for: re-deriving the
// recorded value from the flag instead is how a run that auto-detected and
// enslaved a real NIC came to record an empty interface. On macOS nothing
// prepares a bridge -- vmnet does that inside QEMU -- so there iface is the
// interface the run resolved, which is the only answer there is.
func bridgeInterfaceForMode(mode, iface string) string {
	if mode == "bridged" {
		return iface
	}
	return ""
}

// bridgedIfaceSelectable reports whether the network interface is the user's
// to choose in this configuration.
func bridgedIfaceSelectable(networkMode string) bool {
	return networkMode == "bridged" && (runtime.GOOS == "linux" || runtime.GOOS == "darwin")
}

// defaultBridgeIface leaves the bridge interface unset on every platform. It
// used to answer "en0" on macOS, which bridged the VM onto the built-in
// Ethernet port even when that port had no cable in it (kairos-io/kairos#4431).
// The interface is resolved from the host's default route in runStart instead,
// where it can also be validated.
func defaultBridgeIface() string {
	return ""
}

func macOSFirmwarePath() (string, error) {
	if runtime.GOOS != "darwin" {
		return "", nil
	}
	cmd := exec.Command("brew", "--prefix", "qemu")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("discover qemu brew prefix: %w", err)
	}
	prefix := strings.TrimSpace(string(out))
	path := filepath.Join(prefix, "share", "qemu", "edk2-aarch64-code.fd")
	if _, err := os.Stat(path); err != nil {
		return "", fmt.Errorf("firmware not found at %s", path)
	}
	return path, nil
}

// renderCommand renders the command line a start is about to run, for the
// "Running:" line printed just above the launch.
//
// Its words are not all the tool's own. The disk path, the ISO path and the
// tap name come out of state.json, a 0644 file any process running as the
// user can write, so this line carries untrusted text to a terminal exactly
// as the reset and cleanup plans do -- and on macOS it is the line recording
// a command about to run as root. It used to quote on " \t\n\"" alone, which
// let an ESC or a CR through raw: a stored path of "/tmp/k.qcow2<CSI>2K<CR>"
// printed a line that erased and rewrote itself.
//
// So every word goes through planValue, the same boundary the plans use. It
// costs ordinary output nothing: planValue returns an all-printable value
// unchanged, and a qemu command line is paths, numbers and comma-separated
// option lists.
//
// The space rule is renderCommand's own and stays on top of that, because
// planValue does not quote a space and this line is a command: a word with a
// space in it has to look like one word. \t and \n are no longer named here
// only because planValue already quotes them.
func renderCommand(name string, args []string) string {
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, renderCommandWord(name))
	for _, a := range args {
		parts = append(parts, renderCommandWord(a))
	}
	return strings.Join(parts, " ")
}

func renderCommandWord(word string) string {
	if rendered := planValue(word); rendered != word {
		return rendered
	}
	if strings.ContainsAny(word, " \"") {
		return strconv.Quote(word)
	}
	return word
}

func splitRemovalPaths(paths []string, st *state.State) ([]string, map[string]string) {
	remove := make([]string, 0, len(paths))
	skip := map[string]string{}
	seen := map[string]struct{}{}
	for _, p := range paths {
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		if !cleanup.IsPathSafe(p, st.ManagedDirs) {
			skip[p] = "outside managed directories"
			continue
		}
		if _, err := os.Stat(p); errors.Is(err, os.ErrNotExist) {
			skip[p] = "not found"
			continue
		}
		remove = append(remove, p)
	}
	sort.Strings(remove)
	return remove, skip
}

func printRemovalPlan(stdout io.Writer, label string, remove []string, skip map[string]string) {
	writef(stdout, "%s plan:\n", label)
	printList(stdout, "Will remove", remove)
	printListWithReasons(stdout, "Will skip", skip)
}

// planValue renders a value bound for a plan the user is about to consent to.
//
// reset and cleanup build their plan straight from state.json -- a 0644 file
// any process running as the user can write -- and print it directly above the
// confirmation prompt. Every value in it is therefore untrusted text about to
// be written to a terminal: a stored newline forges a plan row, and a CSI
// sequence after it erases the real row that follows, so the user answers "y"
// to a plan they were never shown. Nothing upstream can prevent this for the
// plan, because the plan is printed before anything validates -- the interface
// validator in internal/vm only fires later, inside the cleanup itself, and
// paths, disk names and dependency names have no validator at all.
//
// So the guard lives here, at the point a value becomes a terminal line, and
// not at the call sites: a call site has to remember, and the previous fix
// escaped two rows while the identical attack walked through their siblings in
// the same plan.
//
// A value whose runes are all printable is returned unchanged, so an ordinary
// plan still reads "bridge: kairoslab0" and "- /home/u/.cache/kairos-lab/vm"
// rather than being uniformly quoted into noise. Anything else is handed to
// strconv.Quote.
//
// strconv.Quote, and not a hand-rolled escaper, because it is already exactly
// this function: it escapes every rune unicode.IsPrint rejects, and IsPrint is
// false for the whole of Cc, Cf, Co, Zl and Zp. That covers C0, DEL, the C1
// block including 8-bit CSI U+009B and NEL U+0085, LS/PS U+2028/U+2029, the
// bidi overrides such as RLO U+202E, the zero-width formatters, private-use
// runes, and OSC-8 hyperlinks (which need an ESC or a C1 OSC to begin). It
// also escapes bytes that are not valid UTF-8 at all, including encoded
// surrogates, as \x escapes.
// bareFileError strips the path an *os.PathError carries, leaving the reason.
// The caller already prints that path once, through planValue; the copy inside
// the error is redundant, and because %w renders it verbatim it is the one
// that carries a stored newline or escape sequence to the terminal. Unwrapping
// to the syscall errno keeps errors.Is working -- os.ErrPermission and friends
// match the errno, not the wrapper.
func bareFileError(err error) error {
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		return pathErr.Err
	}
	return err
}

func planValue(s string) string {
	// The range loop below decodes an invalid byte as utf8.RuneError, and
	// U+FFFD is printable -- so a raw 0x9b (8-bit CSI, invalid on its own in
	// UTF-8) would pass the loop untouched. Reject invalid encoding first;
	// strconv.Quote renders those bytes as \x escapes.
	if !utf8.ValidString(s) {
		return strconv.Quote(s)
	}
	for _, r := range s {
		// The three whitespace controls are spelled out even though
		// unicode.IsPrint already rejects all three. They are the runes that
		// do the damage -- a newline is what makes a forged row a row -- and a
		// reader should not have to know the Cc table to see that they are
		// caught here.
		if !unicode.IsPrint(r) || r == '\n' || r == '\r' || r == '\t' {
			return strconv.Quote(s)
		}
	}
	return s
}

func printList(w io.Writer, title string, values []string) {
	writef(w, "- %s:\n", title)
	if len(values) == 0 {
		writeLine(w, "  - none")
		return
	}
	for _, v := range values {
		writef(w, "  - %s\n", planValue(v))
	}
}

func printListWithReasons(w io.Writer, title string, values map[string]string) {
	writef(w, "- %s:\n", title)
	if len(values) == 0 {
		writeLine(w, "  - none")
		return
	}
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		// The reason is a constant from splitRemovalPaths today, but it goes
		// through planValue too: this is the primitive, and the next reason
		// added here should not have to be audited.
		writef(w, "  - %s (%s)\n", planValue(k), planValue(values[k]))
	}
}

func joinOrNone(values []string) string {
	if len(values) == 0 {
		return "none"
	}
	return strings.Join(values, ", ")
}

func emptyAsNone(v string) string {
	if v == "" {
		return "none"
	}
	return v
}

func nonEmpty(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

func diskNameSet(st *state.State) map[string]struct{} {
	m := make(map[string]struct{}, len(st.Disks))
	for _, d := range st.Disks {
		m[d.Name] = struct{}{}
	}
	return m
}

var errSetupRequired = errors.New("setup has not been completed. Please run 'kairos-lab setup' first")

func requireSetup(st *state.State) error {
	if !state.IsSetupComplete(st) {
		return errSetupRequired
	}
	return nil
}
