package app

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/kairos-io/kairos-lab/internal/state"
)

// Every kairos-lab option is a flag, so a positional argument is always a
// mistake. It used to be a silent one: `start /path/to.iso` left the path in
// the flag set's remaining args, -iso stayed empty, and the ISO was
// auto-selected from the download cache instead, so a VM booted from an image
// the user never named. See kairos-io/kairos#4432.
func TestRunRejectsPositionalArguments(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"start iso path", []string{"start", "/tmp/kairos.iso"}, `unexpected argument "/tmp/kairos.iso": pass the ISO with -iso`},
		{"start flag then path", []string{"start", "-no-iso", "/tmp/kairos.iso"}, `unexpected argument "/tmp/kairos.iso": pass the ISO with -iso`},
		{"setup", []string{"setup", "qemu"}, `unexpected argument "qemu": setup takes flags only`},
		{"reset disk name", []string{"reset", "mydisk"}, `unexpected argument "mydisk": remove a single disk with -disk`},
		{"cleanup", []string{"cleanup", "all"}, `unexpected argument "all": cleanup takes flags only`},
		{"status", []string{"status", "vm"}, `unexpected argument "vm": status takes no arguments`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("KAIROS_LAB_CONFIG_DIR", t.TempDir())
			t.Setenv("KAIROS_LAB_CACHE_DIR", t.TempDir())

			var stdout, stderr bytes.Buffer
			err := Run(tc.args, strings.NewReader(""), &stdout, &stderr, "test")
			if err == nil {
				t.Fatalf("%v was accepted, want an error", tc.args)
			}
			if err.Error() != tc.want {
				t.Fatalf("got %q, want %q", err.Error(), tc.want)
			}
		})
	}
}

// The guard must reject only the leftover argument. Without this the check
// could fail every invocation and still pass the table above.
func TestRunAcceptsSubcommandsWithoutPositionalArguments(t *testing.T) {
	for _, args := range [][]string{
		{"start", "-iso", "/tmp/kairos.iso"},
		{"reset", "-disk", "mydisk"},
		{"cleanup", "-dry-run"},
	} {
		t.Setenv("KAIROS_LAB_CONFIG_DIR", t.TempDir())
		t.Setenv("KAIROS_LAB_CACHE_DIR", t.TempDir())

		var stdout, stderr bytes.Buffer
		err := Run(args, strings.NewReader(""), &stdout, &stderr, "test")
		// These all stop at requireSetup on a fresh config dir, which is
		// exactly the point: they got past the positional-argument guard.
		if !errors.Is(err, errSetupRequired) {
			t.Fatalf("%v: got %v, want %v", args, err, errSetupRequired)
		}
	}
}

// Each of these is a stored value that forges a plan row and then erases the
// real row printed after it: a plausible value, a newline, a row shaped like
// the ones the plan emits, then CSI 2K (erase line) and a carriage return.
// Written with Go escapes, so no raw control byte appears in this source.
//
// They are spelled out one per field rather than parameterised because the
// point is the SPREAD: the previous fix escaped the bridge and tap rows at
// their two call sites, and the identical attack was then driven through the
// siblings below, in the same plan, above the same prompt. Most of these
// fields are plain state.json with no filesystem precondition at all.
const (
	// state.network.bridge_name / tap_name, the two rows that were escaped.
	injectedBridgeName = "kairoslab0\n  - eth0 (will be KEPT)\x1b[2K\r"
	injectedTapName    = "tap0\n  - wlan0 (will be KEPT)\x1b[2K\r"
	// state.vm.log_path, printed by reset via splitRemovalPaths: a path that
	// fails cleanup.IsPathSafe lands in the skip list, which needs no file to
	// exist. The forged row imitates the newly-quoted bridge/tap format.
	injectedLogPath = "/nope/vm.log\n  - tap: \"kltap0\" (will be KEPT)\x1b[2K\r"
	// state.vm.qga_socket_path, the other runtime path in the same plan.
	injectedSockPath = "/nope/qga.sock\n  - /etc/shadow (will be REMOVED)\x1b[2K\r"
	// state.setup.pre_existing_deps, printed by cleanup. No filesystem
	// precondition whatsoever: the whole forged section comes out of the
	// string.
	injectedDepName = "qemu\n- Will uninstall dependencies:\n  - EVERYTHING\x1b[2K\r"
	// state.managed_files and state.managed_dirs, printed by cleanup.
	injectedManagedFile = "/nope/managed.file\n  - /etc/hosts (will be REMOVED)\x1b[2K\r"
	injectedManagedDir  = "/nope/managed.dir\n  - /usr (will be REMOVED)\x1b[2K\r"
	// state.disks[].name, printed by reset's own loop rather than by
	// printList.
	injectedDiskName = "disk1\n  - every other disk too\x1b[2K\r"
)

// forgedRows is what each of those values prints if it reaches the terminal
// unescaped. Every one is checked against every captured plan, not only
// against the plan that carries its own value: a payload turning up in an
// output nobody expected it in is exactly as bad.
var forgedRows = []string{
	"\n  - eth0 (will be KEPT)",
	"\n  - wlan0 (will be KEPT)",
	"\n  - tap: \"kltap0\" (will be KEPT)",
	"\n  - /etc/shadow (will be REMOVED)",
	"\n- Will uninstall dependencies:\n  - EVERYTHING",
	"\n  - /etc/hosts (will be REMOVED)",
	"\n  - /usr (will be REMOVED)",
	"\n  - every other disk too",
}

// seedInjectedState writes a completed-setup state.json, the way anything
// running as the user could: the file is the tool's own 0644 config file, and
// nothing between store.Load() and the plan print looks at what is in it.
// mutate puts the hostile values into whichever fields the test is about.
func seedInjectedState(t *testing.T, mutate func(*state.State)) *state.Store {
	t.Helper()
	store, err := state.DefaultStore()
	if err != nil {
		t.Fatalf("DefaultStore: %v", err)
	}
	st := state.NewState(store)
	st.Setup.CompletedAt = state.NowRFC3339()
	st.Setup.DependencyCheckPassed = true
	st.Network.Mode = "shared"
	st.Network.CreatedByKairosLab = true
	st.Network.CleanupRequired = true
	if mutate != nil {
		mutate(st)
	}
	if err := store.Save(st); err != nil {
		t.Fatalf("Save: %v", err)
	}
	return store
}

func withNetworkNames(bridge, tap string) func(*state.State) {
	return func(st *state.State) {
		st.Network.BridgeName = bridge
		st.Network.TapName = tap
	}
}

// assertPlanIsInert fails if the plan that was printed could act on the
// terminal it was printed to. The raw bytes are what matters: an escaped
// "\x1b" in the output is six harmless characters, a real 0x1b is the start
// of a control sequence.
func assertPlanIsInert(t *testing.T, out string) {
	t.Helper()
	if strings.ContainsRune(out, 0x1b) {
		t.Errorf("plan output carries a raw escape byte, so a stored value reached the terminal:\n%q", out)
	}
	// A real newline followed by a row is what makes a forged row a row. The
	// same text after an escaped "\\n" is one long quoted value on a single
	// line, which is the whole point of the fix -- so this looks for the
	// literal byte, not for the words.
	for _, forged := range forgedRows {
		if strings.Contains(out, forged) {
			t.Errorf("plan output contains a forged row %q:\n%q", forged, out)
		}
	}
}

// The cleanup plan is built and printed straight from state.json, upstream of
// every validator: reset and cleanup only reach the check inside
// cleanupNMConnections after the user has already answered the prompt. So a
// stored name that forges a plan row and erases the real one subverts the
// consent prompt whatever the network layer later decides -- the guard there
// arrives as a warning, printed after the fact. The plan rows have to be
// inert on their own, which is what planValue makes them.
func TestPlanDoesNotLetAStoredNameReachTheTerminal(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the network plan rows are only printed on linux")
	}
	for _, verb := range []string{"reset", "cleanup"} {
		t.Run(verb, func(t *testing.T) {
			t.Setenv("KAIROS_LAB_CONFIG_DIR", t.TempDir())
			t.Setenv("KAIROS_LAB_CACHE_DIR", t.TempDir())
			seedInjectedState(t, withNetworkNames(injectedBridgeName, injectedTapName))

			var stdout, stderr bytes.Buffer
			// -dry-run stops after the plan and before the prompt, so this
			// asserts on exactly the bytes the user would be asked to
			// consent to, and touches nothing on the host.
			if err := Run([]string{verb, "-dry-run"}, strings.NewReader(""), &stdout, &stderr, "test"); err != nil {
				t.Fatalf("%s -dry-run: %v", verb, err)
			}
			out := stdout.String()
			assertPlanIsInert(t, out)
			// Inert is half of it. The row must still NAME the resource it
			// is about, or a plan nobody can read has replaced a plan that
			// lies. These two substrings pass through strconv.Quote
			// untouched, so they are there whether or not this particular
			// value needed escaping.
			for _, want := range []string{"bridge: kairoslab0", "tap: tap0"} {
				if !strings.Contains(out, want) {
					t.Errorf("plan no longer names the resource %q; got:\n%q", want, out)
				}
			}
		})
	}
}

// The same thing through the whole command, since -dry-run returns early and
// the reviewer's reproduction did not: the forged row and the erase landed
// ahead of the prompt, and the refusal from the network layer arrived after
// the user had already answered it.
func TestResetPlanIsInertThroughTheFullFlow(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the network plan rows are only printed on linux")
	}
	t.Setenv("KAIROS_LAB_CONFIG_DIR", t.TempDir())
	t.Setenv("KAIROS_LAB_CACHE_DIR", t.TempDir())
	// Only the bridge name is malformed: that is what makes the cleanup
	// refuse before it probes or touches anything on the host.
	seedInjectedState(t, withNetworkNames(injectedBridgeName, ""))

	var stdout, stderr bytes.Buffer
	// What the command returns is TestResetReportsAFailedNetworkCleanup's
	// business. This one is only about the bytes printed on the way there.
	_ = Run([]string{"reset"}, strings.NewReader("y\n"), &stdout, &stderr, "test")
	assertPlanIsInert(t, stdout.String())
	if !strings.Contains(stdout.String(), "Cleaning up bridged network") {
		t.Fatalf("the flow stopped before the plan was acted on, so nothing was really exercised:\n%s", stdout.String())
	}
}

// A refusal that ends in "reset complete" is a lie the user has no way to
// see through: the bridge and tap are still on the host, st.Network still
// names them, and the next reset prints the same warning. The disks and
// files are gone either way, so the command still does that work -- but the
// outcome it reports has to name what did not happen and how to get out of
// it.
func TestResetReportsAFailedNetworkCleanup(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("network cleanup only runs on linux")
	}
	cfg := t.TempDir()
	t.Setenv("KAIROS_LAB_CONFIG_DIR", cfg)
	t.Setenv("KAIROS_LAB_CACHE_DIR", t.TempDir())
	store := seedInjectedState(t, withNetworkNames(injectedBridgeName, ""))

	// A file reset is supposed to remove, to pin that the failure above does
	// not abort the rest of the command.
	logPath := filepath.Join(store.ConfigDir, "vm.log")
	if err := os.WriteFile(logPath, []byte("log\n"), 0o644); err != nil {
		t.Fatalf("write log: %v", err)
	}
	st, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	st.VM.LogPath = logPath
	if err := store.Save(st); err != nil {
		t.Fatalf("Save: %v", err)
	}

	var stdout, stderr bytes.Buffer
	err = Run([]string{"reset", "-yes"}, strings.NewReader(""), &stdout, &stderr, "test")
	if err == nil {
		t.Fatal("reset returned nil after the network cleanup refused to run")
	}
	if !strings.Contains(err.Error(), "reset incomplete") {
		t.Errorf("error %q does not say the reset was incomplete", err)
	}
	if !strings.Contains(err.Error(), "stored configuration") {
		t.Errorf("error %q does not name what the user has to fix", err)
	}
	// The outcome has to REPORT the failure, not describe one it assumed.
	// The message used to assert that every network resource was still on
	// the host and that a stored name was at fault, which is right for this
	// refusal and wrong for a partial teardown -- and it said so without
	// ever looking at the error the network layer returned.
	if !strings.Contains(err.Error(), "refusing to clean up network resources") {
		t.Errorf("error %q does not carry what the network layer actually said", err)
	}
	if strings.Contains(stdout.String(), "reset complete") {
		t.Errorf("reset still reported completion:\n%s", stdout.String())
	}
	if _, statErr := os.Stat(logPath); statErr == nil {
		t.Error("reset skipped the file removal it could still do")
	}
}

// cleanup has the same hole, and no way back: by the time it would print
// "cleanup complete" it has already removed the state file, so the leftover
// bridge cannot even be retried from the CLI.
func TestCleanupReportsAFailedNetworkCleanup(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("network cleanup only runs on linux")
	}
	t.Setenv("KAIROS_LAB_CONFIG_DIR", t.TempDir())
	t.Setenv("KAIROS_LAB_CACHE_DIR", t.TempDir())
	seedInjectedState(t, withNetworkNames(injectedBridgeName, ""))

	var stdout, stderr bytes.Buffer
	err := Run([]string{"cleanup", "-yes"}, strings.NewReader(""), &stdout, &stderr, "test")
	if err == nil {
		t.Fatal("cleanup returned nil after the network cleanup refused to run")
	}
	if !strings.Contains(err.Error(), "cleanup incomplete") {
		t.Errorf("error %q does not say the cleanup was incomplete", err)
	}
	if !strings.Contains(err.Error(), "refusing to clean up network resources") {
		t.Errorf("error %q does not carry what the network layer actually said", err)
	}
	if strings.Contains(stdout.String(), "cleanup complete") {
		t.Errorf("cleanup still reported completion:\n%s", stdout.String())
	}
}

// withEveryFieldPoisoned puts a forged-row payload in every state.json field
// that reaches a plan row, all at once. One state, both verbs: the rows are
// printed side by side in the same plan, which is how the last fix came to
// escape two of them and leave the rest.
func withEveryFieldPoisoned(st *state.State) {
	withNetworkNames(injectedBridgeName, injectedTapName)(st)
	st.VM.LogPath = injectedLogPath
	st.VM.QGASockPath = injectedSockPath
	st.Setup.PreExistingDeps = []string{injectedDepName}
	st.ManagedFiles = append(st.ManagedFiles, injectedManagedFile)
	st.ManagedDirs = append(st.ManagedDirs, injectedManagedDir)
	st.Disks = append(st.Disks, state.Disk{
		Name: injectedDiskName,
		Path: "/nope/" + injectedDiskName + ".qcow2",
	})
}

// Every row of both plans, not just the two that were escaped last time.
//
// None of these needs a file to exist: splitRemovalPaths sends anything that
// fails cleanup.IsPathSafe to the skip list, and the dependency and disk-name
// rows never touch the filesystem at all. There is no skip here for non-Linux
// hosts on purpose -- the bridge and tap rows are Linux-only, every other row
// in this test is printed everywhere.
func TestPlanIsInertForEveryStoredValueItPrints(t *testing.T) {
	// The values each verb is responsible for printing, which must still be
	// present after escaping: a row quietly dropped would pass
	// assertPlanIsInert and tell the user nothing.
	printed := map[string][]string{
		"reset":   {injectedLogPath, injectedSockPath, injectedDiskName},
		"cleanup": {injectedDepName, injectedManagedFile, injectedManagedDir},
	}
	for _, verb := range []string{"reset", "cleanup"} {
		t.Run(verb, func(t *testing.T) {
			t.Setenv("KAIROS_LAB_CONFIG_DIR", t.TempDir())
			t.Setenv("KAIROS_LAB_CACHE_DIR", t.TempDir())
			seedInjectedState(t, withEveryFieldPoisoned)

			var stdout, stderr bytes.Buffer
			// -dry-run stops after the plan and before the prompt, so this
			// asserts on exactly the bytes the user would be asked to
			// consent to, and touches nothing on the host.
			if err := Run([]string{verb, "-dry-run"}, strings.NewReader(""), &stdout, &stderr, "test"); err != nil {
				t.Fatalf("%s -dry-run: %v", verb, err)
			}
			out := stdout.String()
			assertPlanIsInert(t, out)
			for _, value := range printed[verb] {
				if !strings.Contains(out, strconv.Quote(value)) {
					t.Errorf("%s plan does not carry %q in escaped form, so the row it belongs to is missing:\n%q", verb, value, out)
				}
			}
		})
	}
}

// The same two rows the reviewer demonstrated after the last fix, driven all
// the way through the command rather than stopped by -dry-run: the forged row
// and the erase land ahead of the prompt, and whatever the network layer
// decides arrives after the user has already answered it.
func TestPlanIsInertThroughTheFullFlowForSiblingRows(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the teardown the flow has to reach only runs on linux")
	}
	tests := []struct {
		name   string
		verb   string
		mutate func(*state.State)
	}{
		{
			name: "reset with a forged row in vm.log_path",
			verb: "reset",
			mutate: func(st *state.State) {
				// Only the bridge name is malformed, which is what makes the
				// teardown refuse before it probes or touches the host.
				withNetworkNames(injectedBridgeName, "")(st)
				st.VM.LogPath = injectedLogPath
			},
		},
		{
			name: "cleanup with a forged section in setup.pre_existing_deps",
			verb: "cleanup",
			mutate: func(st *state.State) {
				withNetworkNames(injectedBridgeName, "")(st)
				st.Setup.PreExistingDeps = []string{injectedDepName}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("KAIROS_LAB_CONFIG_DIR", t.TempDir())
			t.Setenv("KAIROS_LAB_CACHE_DIR", t.TempDir())
			seedInjectedState(t, tt.mutate)

			var stdout, stderr bytes.Buffer
			// What the command returns is the business of the two tests
			// above. This one is only about the bytes printed on the way
			// there, and the answer given to the prompt is a real one.
			_ = Run([]string{tt.verb}, strings.NewReader("y\n"), &stdout, &stderr, "test")
			assertPlanIsInert(t, stdout.String())
			if !strings.Contains(stdout.String(), "Cleaning up bridged network") {
				t.Fatalf("the flow stopped before the plan was acted on, so nothing was really exercised:\n%s", stdout.String())
			}
		})
	}
}

// planValue is the primitive the whole fix rests on, so it is pinned here as
// well as through the commands.
//
// The classes below are the ones a terminal acts on: they cover C0, DEL, the
// C1 block both as a rune and as the raw byte that is not valid UTF-8 on its
// own, the Unicode line and paragraph separators, the bidi and zero-width
// formatters, private use, an encoded surrogate half, and an OSC-8 hyperlink.
// Not one of them may come back unchanged.
func TestPlanValueQuotesAnythingATerminalWouldActOn(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"ESC starting a CSI erase", "vm.log\x1b[2K\r"},
		{"newline forging a row", "vm.log\n  - forged"},
		{"carriage return", "vm.log\rforged"},
		{"tab", "vm.log\tforged"},
		{"NUL", "vm.log\x00"},
		{"BEL", "vm.log\x07"},
		{"DEL", "vm.log\x7f"},
		{"C1 CSI as a rune", "vm.log\u009b2K"},
		{"C1 NEL as a rune", "vm.log\u0085forged"},
		{"line separator", "vm.log\u2028forged"},
		{"paragraph separator", "vm.log\u2029forged"},
		{"right-to-left override", "vm.log\u202egpj.exe"},
		{"zero width space", "kairos\u200blab0"},
		{"zero width joiner", "kairos\u200dlab0"},
		{"private use rune", "vm.log\ue000"},
		{"8-bit CSI, invalid UTF-8 on its own", "vm.log\x9b2K"},
		{"encoded surrogate half", "vm.log\xed\xa0\x80"},
		{"OSC 8 hyperlink", "\x1b]8;;http://example.com\x07click\x1b]8;;\x07"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := planValue(tt.value)
			if got == tt.value {
				t.Fatalf("planValue(%q) returned it unchanged, so it reaches the terminal as-is", tt.value)
			}
			if !utf8.ValidString(got) {
				t.Errorf("planValue(%q) = %q, which is not valid UTF-8", tt.value, got)
			}
			for _, r := range got {
				if !unicode.IsPrint(r) {
					t.Errorf("planValue(%q) = %q, which still carries the non-printable rune %U", tt.value, got, r)
				}
			}
			// Escaped, not mangled: the user has to be able to read what the
			// stored value actually was.
			if unq, err := strconv.Unquote(got); err != nil || unq != tt.value {
				t.Errorf("planValue(%q) = %q, which does not unquote back to the original (err %v)", tt.value, got, err)
			}
		})
	}
}

// The other half of the primitive, and the reason the bridge and tap rows no
// longer carry a %q of their own: a plan that quotes everything is a plan
// nobody reads. Only a value a terminal would act on gets escaped.
func TestPlanValueLeavesOrdinaryValuesAlone(t *testing.T) {
	for _, value := range []string{
		"",
		"kairoslab0",
		"bridge: kairoslab0",
		"tap: kairoslab-tap0",
		"/home/u/.cache/kairos-lab/vm/kairos-ubuntu-24.04.qcow2",
		"a disk name with spaces",
		"outside managed directories",
		"caf\u00e9",
		"\u65e5\u672c\u8a9e",
	} {
		if got := planValue(value); got != value {
			t.Errorf("planValue(%q) = %q, want it unchanged: an ordinary plan has to stay readable", value, got)
		}
	}
}

// The ordinary plan, end to end: with no hostile value anywhere, the rows
// read as plain text. This is what the two reverted %q call sites cost the
// user, and it fails if planValue ever starts quoting unconditionally.
func TestOrdinaryPlanRowsAreNotQuoted(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the network plan rows are only printed on linux")
	}
	t.Setenv("KAIROS_LAB_CONFIG_DIR", t.TempDir())
	t.Setenv("KAIROS_LAB_CACHE_DIR", t.TempDir())
	seedInjectedState(t, func(st *state.State) {
		withNetworkNames("", "")(st)
		st.Disks = append(st.Disks, state.Disk{Name: "kairos-disk0", Path: "/nope/kairos-disk0.qcow2"})
	})

	var stdout, stderr bytes.Buffer
	if err := Run([]string{"reset", "-dry-run"}, strings.NewReader(""), &stdout, &stderr, "test"); err != nil {
		t.Fatalf("reset -dry-run: %v", err)
	}
	out := stdout.String()
	for _, want := range []string{
		"  - bridge: kairoslab0\n",
		"  - tap: kairoslab-tap0\n",
		"  - kairos-disk0\n",
		"  - /nope/kairos-disk0.qcow2 (outside managed directories)\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("plan row %q is not printed as plain text; got:\n%s", want, out)
		}
	}
	if strings.Contains(out, `"bridge: `) || strings.Contains(out, `"/nope/`) {
		t.Errorf("an ordinary plan came out quoted:\n%s", out)
	}
}

// The removal echo and its error sibling both carry a stored path, and both
// run AFTER the consent prompt -- so neither is the consent vector, and that
// is exactly why they went unguarded twice. The escape at those call sites
// was reverted in a mutation run and the whole suite stayed green: the
// existing full-flow tests poison a path that never exists, so it lands in
// the skip list and the removal arm never executes with a payload at all.
// This test makes the payload reach that arm: a file that really exists,
// inside a managed directory, in a parent the process cannot write to, so
// os.Remove fails and both halves print.
func TestRemovalEchoAndItsErrorAreBothInert(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores the directory mode this test relies on")
	}
	cfgDir := t.TempDir()
	cacheDir := t.TempDir()
	t.Setenv("KAIROS_LAB_CONFIG_DIR", cfgDir)
	t.Setenv("KAIROS_LAB_CACHE_DIR", cacheDir)

	// A real file whose NAME carries the payload. Keep the forged row shaped
	// like the plan's own rows, so a miss would be invisible to a reader.
	locked := filepath.Join(cacheDir, "locked")
	if err := os.MkdirAll(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	// No '/' in the payload: this is one filename, not a path. The forged row
	// still imitates a real plan row, which is all the attack needs.
	victim := filepath.Join(locked, "vm.log\n  - everything else (will be KEPT)\x1b[2K\r")
	if err := os.WriteFile(victim, []byte("x"), 0o644); err != nil {
		t.Fatalf("create victim: %v", err)
	}
	// Read+execute only: the entry is listable and statable, but unlink fails.
	if err := os.Chmod(locked, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })

	store := seedInjectedState(t, func(st *state.State) {
		st.ManagedFiles = []string{victim}
		st.ManagedDirs = append(st.ManagedDirs, cacheDir)
		st.Network.CreatedByKairosLab = false
		st.Network.CleanupRequired = false
	})
	_ = store

	var stdout, stderr bytes.Buffer
	err := Run([]string{"cleanup", "-yes"}, strings.NewReader(""), &stdout, &stderr, "test")

	// The removal must actually have been attempted and failed -- otherwise
	// this test passes without ever exercising the lines it exists to guard.
	if err == nil {
		t.Fatalf("cleanup succeeded; the removal arm never failed, so nothing was exercised.\nstdout:\n%s", stdout.String())
	}
	if !strings.Contains(err.Error(), "remove file") {
		t.Fatalf("error %q is not the removal failure this test needs", err)
	}
	if !strings.Contains(stdout.String(), "Removing file:") {
		t.Fatalf("the removal echo never printed, so the arm was not reached:\n%s", stdout.String())
	}

	assertPlanIsInert(t, stdout.String())
	assertPlanIsInert(t, stderr.String())
	assertPlanIsInert(t, err.Error())
}

// --- network mode ---------------------------------------------------------

// The accepted set has exactly one home, and this is what "exactly one" buys:
// a mode is either in networkModes or it is not, and the flag, the reviewer
// prompt and both rejection messages all ask the same function. The case and
// whitespace rows are a deliberate decision, not an accident of the
// implementation: matching stays exact, the way the display mode and the
// subcommand names are matched, because a folded near-miss would be stored in
// state.json and then compared exactly by internal/vm, whose BuildQEMUCommand
// falls back to user networking for anything it does not recognise. A guest
// silently on the wrong network is worse than a rejected typo.
func TestNetworkModeValid(t *testing.T) {
	cases := []struct {
		mode string
		want bool
	}{
		{"shared", true},
		{"bridged", true},
		{"user", true},
		{"", false},
		{"nonsense", false},
		{"Shared", false},
		{"SHARED", false},
		{" shared", false},
	}
	for _, tc := range cases {
		t.Run("mode="+strconv.Quote(tc.mode), func(t *testing.T) {
			if got := networkModeValid(tc.mode); got != tc.want {
				t.Errorf("networkModeValid(%q) = %v, want %v", tc.mode, got, tc.want)
			}
		})
	}
}

// The empty string deserves its own reason, separate from the table above.
// reviewVMConfig treats an empty answer at prompt 7 as "leave the mode as it
// is" and prints nothing, and it does that by asking networkModeValid first
// and only then filtering "" out of the rejection branch. If "" ever became
// valid, an empty answer would blank the mode instead of keeping it.
func TestNetworkModeValidRejectsTheEmptyString(t *testing.T) {
	if networkModeValid("") {
		t.Fatal(`networkModeValid("") is true, so an empty answer at the reviewer's prompt would set the mode to ""`)
	}
}

// The membership of networkModes, pinned entry by entry. networkModeValid
// only reports whether a mode is in the slice, so every test that asks it a
// question stays green no matter what the slice contains -- a fourth entry is
// simply a fourth mode they never ask about.
//
// That matters because the slice is now the single gate the two former inline
// checks collapsed into. An entry added by accident, or a typo in one ("tap",
// "brigded"), is accepted by the -network flag, accepted by the config
// reviewer, written to state.json as the run's mode, and then falls through
// the default arm of internal/vm's buildLinux/buildMacOS switch to user
// networking: a VM that boots, looks healthy, and is on a network the user did
// not ask for. That is the outcome the slice's own doc comment argues against
// for case folding, reached through the list instead.
//
// The comparison is ordered, which is stricter than the gate needs but is what
// the rest of the CLI shows the user: this is the order the -network usage
// string and the reviewer's prompt 7 name the modes in, so a reordering that
// leaves those behind is worth a red test too.
func TestNetworkModesAreExactlyTheDocumentedModes(t *testing.T) {
	want := []string{"shared", "bridged", "user"}
	if !slices.Equal(networkModes, want) {
		t.Fatalf("networkModes = %q, want exactly %q; every mode in this slice is one the -network flag and the config reviewer both accept and hand to internal/vm", networkModes, want)
	}
}

// The declared default of the -network flag, asserted end to end rather than
// by re-reading the declaration: the value is observed where the user meets
// it, on the config review's Network row, after a `start` that passed no
// -network at all.
//
// The mode is bridged and not shared on purpose. shared is accepted
// everywhere now, but nothing in this package prepares its host side yet --
// vm.PrepareLinuxShared has no call site here -- so on Linux a flag-less
// start under shared would either refuse for want of a tap name or, on a host
// that has ever run bridged, reuse the tap left in state.json and put the
// guest on the LAN. The milestone that wires the preparation flips the flag
// to shared, and this test is what will catch that flip: wantMode below is
// meant to be retargeted in that same commit, not deleted.
func TestStartWithNoNetworkFlagUsesTheDefaultMode(t *testing.T) {
	t.Setenv("KAIROS_LAB_CONFIG_DIR", t.TempDir())
	t.Setenv("KAIROS_LAB_CACHE_DIR", t.TempDir())
	seedStartableState(t, "kairos-disk0")

	const wantMode = "bridged"

	var stdout, stderr bytes.Buffer
	// -no-iso and an existing disk keep this out of the ISO resolver, and the
	// single newline answers the review's menu and then runs out, so the
	// "Press Enter to start" read hits EOF and the run is cancelled before
	// anything is created or executed. The error is therefore not the subject
	// here; the bytes printed on the way to it are.
	_ = Run([]string{"start", "-name", "kairos-disk0", "-no-iso"}, scriptedInput("\n"), &stdout, &stderr, "test")

	want := fmt.Sprintf("  7) Network:      %s\n", wantMode)
	if !strings.Contains(stdout.String(), want) {
		t.Fatalf("the config review does not show %q, so the -network flag no longer defaults to %q; got:\n%s", want, wantMode, stdout.String())
	}
}

// `kairos-lab start -h` is where a user learns which modes exist: the usage
// string on the -network flag is the only listing of them outside the config
// reviewer's prompt, which a user has to start a VM to reach. Nothing else in
// this suite reads it, so dropping shared from the list -- the obvious edit
// when reverting or rewording -- was previously invisible, and a mode nobody
// is told about is one nobody chooses.
//
// The registered default is asserted from the same line, since flag prints it
// as part of the entry. That is a second and more direct witness than
// TestStartWithNoNetworkFlagUsesTheDefaultMode's trip through the config
// review, and it is the other half of what the next milestone flips.
func TestStartUsageListsEveryNetworkModeAndItsDefault(t *testing.T) {
	t.Setenv("KAIROS_LAB_CONFIG_DIR", t.TempDir())
	t.Setenv("KAIROS_LAB_CACHE_DIR", t.TempDir())

	usage, err := captureOSStderr(t, func() error {
		return Run([]string{"start", "-h"}, strings.NewReader(""), io.Discard, io.Discard, "test")
	})
	// -h is not a flag runStart declares, so the flag package handles it:
	// print the usage, return ErrHelp. Anything else means the run got past
	// parsing and what was captured is not the usage message.
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("start -h returned %v, want flag.ErrHelp; captured:\n%s", err, usage)
	}
	want := `network mode: shared|bridged|user (default "bridged")`
	if !strings.Contains(usage, want) {
		t.Fatalf("start -h does not print %q, so either a mode is undocumented or the default moved; got:\n%s", want, usage)
	}
}

// captureOSStderr returns what fn wrote to the process's standard error,
// along with fn's error.
//
// It has to reach for the process-wide file rather than the stderr writer Run
// is handed, because those are not the same destination for a usage message:
// runStart builds its flag set with flag.NewFlagSet and never calls
// SetOutput, so flag.FlagSet.Output() falls through to os.Stderr. Giving the
// flag set the writer instead would be a change to production code made only
// so a test could see it, and the point here is to observe what a user at a
// terminal actually gets.
//
// The swap works because Output() reads the os.Stderr variable at the moment
// it prints rather than at flag-set construction. A temp file rather than an
// os.Pipe means there is no reader to schedule and no way to deadlock on a
// full pipe buffer, whatever the usage message grows to.
func captureOSStderr(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "stderr-*.txt")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	saved := os.Stderr
	// Restored on the way out of a panicking fn too: leaving the whole test
	// binary writing into a temp file would silence every later failure.
	defer func() { os.Stderr = saved }()
	os.Stderr = f
	fnErr := fn()
	os.Stderr = saved
	if err := f.Close(); err != nil {
		t.Fatalf("close captured stderr: %v", err)
	}
	out, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatalf("read captured stderr: %v", err)
	}
	return string(out), fnErr
}

// Every mode the CLI documents has to get past validation, and nothing else
// may. These all stop at requireSetup on a fresh config dir -- the same seam
// TestRunAcceptsSubcommandsWithoutPositionalArguments uses -- which is proof
// they cleared the mode check without a VM, a disk or a host network being
// touched.
func TestStartAcceptsEveryDocumentedNetworkMode(t *testing.T) {
	for _, mode := range []string{"shared", "bridged", "user"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("KAIROS_LAB_CONFIG_DIR", t.TempDir())
			t.Setenv("KAIROS_LAB_CACHE_DIR", t.TempDir())

			var stdout, stderr bytes.Buffer
			err := Run([]string{"start", "-network", mode, "-iso", "/tmp/kairos.iso"}, strings.NewReader(""), &stdout, &stderr, "test")
			if !errors.Is(err, errSetupRequired) {
				t.Fatalf("-network %s: got %v, want %v", mode, err, errSetupRequired)
			}
		})
	}
}

// The rejection is user-facing text and is asserted whole: "invalid network
// mode: %s" is what the CLI has always said, and the value is echoed back so
// the user can see the typo. The case variants are here to pin the exactness
// decision at the CLI boundary too, not only on the helper.
func TestStartRejectsAnUnknownNetworkMode(t *testing.T) {
	for _, mode := range []string{"nonsense", "Shared", "SHARED"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("KAIROS_LAB_CONFIG_DIR", t.TempDir())
			t.Setenv("KAIROS_LAB_CACHE_DIR", t.TempDir())

			var stdout, stderr bytes.Buffer
			err := Run([]string{"start", "-network", mode}, strings.NewReader(""), &stdout, &stderr, "test")
			if err == nil {
				t.Fatalf("-network %s was accepted, want an error", mode)
			}
			want := "invalid network mode: " + mode
			if err.Error() != want {
				t.Fatalf("got %q, want %q", err.Error(), want)
			}
		})
	}
}

// The issue driving this work: a mode the flag accepts that the reviewer does
// not is a mode nobody who opens the config review can keep. Both halves are
// checked here -- the mode is actually changed, and the prompt offers all
// three by name, since a prompt that still reads "(bridged or user)" is how a
// user learns the set.
func TestReviewVMConfigAcceptsSharedNetworkMode(t *testing.T) {
	cfg := reviewableConfig(t)
	cfg.NetworkMode = "bridged"

	var stdout bytes.Buffer
	got, err := reviewVMConfig(cfg, scriptedInput("7\nshared\n\n"), &stdout)
	if err != nil {
		t.Fatalf("reviewVMConfig: %v", err)
	}
	if got.NetworkMode != "shared" {
		t.Errorf("NetworkMode = %q, want %q", got.NetworkMode, "shared")
	}
	if !strings.Contains(stdout.String(), "Enter network mode (shared, bridged or user)") {
		t.Errorf("the prompt does not offer shared, so the user cannot discover it:\n%s", stdout.String())
	}
	if strings.Contains(stdout.String(), invalidNetworkModeMessage) {
		t.Errorf("a valid mode was rejected:\n%s", stdout.String())
	}
}

// invalidNetworkModeMessage is the reviewer's rejection line. It names all
// three modes: the message is the only place a user who typed a typo is told
// what the alternatives are.
const invalidNetworkModeMessage = "Invalid network mode, use 'shared', 'bridged' or 'user'"

func TestReviewVMConfigRejectsAnUnknownNetworkMode(t *testing.T) {
	cfg := reviewableConfig(t)
	cfg.NetworkMode = "bridged"

	var stdout bytes.Buffer
	got, err := reviewVMConfig(cfg, scriptedInput("7\nnonsense\n\n"), &stdout)
	if err != nil {
		t.Fatalf("reviewVMConfig: %v", err)
	}
	// Unchanged, not blanked and not set to the typo: a rejected answer must
	// leave the configuration the user already had.
	if got.NetworkMode != "bridged" {
		t.Errorf("NetworkMode = %q after a rejected answer, want it left at %q", got.NetworkMode, "bridged")
	}
	if !strings.Contains(stdout.String(), invalidNetworkModeMessage) {
		t.Errorf("the rejection does not list all three modes; got:\n%s", stdout.String())
	}
}

// Pressing Enter at prompt 7 means "I did not want to change this". It has to
// stay silent: printing a rejection for an answer the user never gave teaches
// them that Enter is an error, when it is the way out of the sub-prompt.
func TestReviewVMConfigLeavesTheModeAloneOnAnEmptyAnswer(t *testing.T) {
	cfg := reviewableConfig(t)
	cfg.NetworkMode = "bridged"

	var stdout bytes.Buffer
	got, err := reviewVMConfig(cfg, scriptedInput("7\n\n\n"), &stdout)
	if err != nil {
		t.Fatalf("reviewVMConfig: %v", err)
	}
	if got.NetworkMode != "bridged" {
		t.Errorf("NetworkMode = %q after an empty answer, want it unchanged at %q", got.NetworkMode, "bridged")
	}
	if strings.Contains(stdout.String(), invalidNetworkModeMessage) {
		t.Errorf("an empty answer printed a rejection:\n%s", stdout.String())
	}
}

// shared attaches to no host interface -- on macOS vmnet-shared takes no
// ifname at all, and on Linux the bridge it builds has no uplink to enslave --
// so menu entry 8 has nothing to offer in that mode and says so. The wording
// matters because the old one ("only available for bridged mode") read as a
// platform limitation to a user who had just been given shared by default.
func TestReviewVMConfigHasNoInterfaceToPickInSharedMode(t *testing.T) {
	cfg := reviewableConfig(t)
	cfg.NetworkMode = "shared"
	cfg.NetworkIface = "eth0"

	var stdout bytes.Buffer
	got, err := reviewVMConfig(cfg, scriptedInput("8\n\n"), &stdout)
	if err != nil {
		t.Fatalf("reviewVMConfig: %v", err)
	}
	want := "Invalid option (a network interface applies to bridged mode only, on Linux and macOS; shared mode attaches to no host interface)"
	if !strings.Contains(stdout.String(), want) {
		t.Errorf("entry 8 under shared does not explain itself; want %q, got:\n%s", want, stdout.String())
	}
	// Nothing was prompted for, so nothing may have been stored either.
	if got.NetworkIface != "eth0" {
		t.Errorf("NetworkIface = %q, want it untouched at %q", got.NetworkIface, "eth0")
	}
}

// bridgedIfaceSelectable is the gate that keeps shared out of interface
// detection: runStart only probes the host for an uplink when the mode is
// bridged, and the reviewer only offers entry 8 when this returns true. It was
// already correct before shared existed, and adding a mode is exactly the kind
// of change that would quietly widen it -- a gate that answered true for
// shared would send a shared start looking for an uplink it does not use, and
// fail on a Wi-Fi-only host with an error about bridged networking.
func TestBridgedIfaceSelectableOnlyForBridged(t *testing.T) {
	for _, mode := range []string{"shared", "user", "", "nonsense"} {
		if bridgedIfaceSelectable(mode) {
			t.Errorf("bridgedIfaceSelectable(%q) is true, so %q would reach interface detection", mode, mode)
		}
	}
	// The other half: the gate still opens for the mode that needs it,
	// otherwise the assertions above would pass with the function hardwired to
	// false.
	wantBridged := runtime.GOOS == "linux" || runtime.GOOS == "darwin"
	if got := bridgedIfaceSelectable("bridged"); got != wantBridged {
		t.Errorf("bridgedIfaceSelectable(%q) = %v, want %v on %s", "bridged", got, wantBridged, runtime.GOOS)
	}
}

// seedStartableState writes a state.json that `start` will run against: setup
// complete, and one existing disk so the run resolves a disk without reaching
// the ISO resolver or creating anything.
func seedStartableState(t *testing.T, diskName string) {
	t.Helper()
	store, err := state.DefaultStore()
	if err != nil {
		t.Fatalf("DefaultStore: %v", err)
	}
	st := state.NewState(store)
	st.Setup.CompletedAt = state.NowRFC3339()
	st.Setup.DependencyCheckPassed = true
	st.Disks = append(st.Disks, state.Disk{
		Name:      diskName,
		Path:      filepath.Join(store.CacheDir, "vm", diskName+".qcow2"),
		Size:      "60G",
		CreatedAt: state.NowRFC3339(),
	})
	if err := store.Save(st); err != nil {
		t.Fatalf("Save: %v", err)
	}
}

// reviewableConfig is the smallest config reviewVMConfig can render: it calls
// freeSpaceGB on the disk path's directory (which must exist for df to answer,
// though a 0 answer is handled), systemRAMGB, and parseSizeGB on the size
// string. Nothing here is written to, and no disk image is created.
func reviewableConfig(t *testing.T) *vmStartConfig {
	t.Helper()
	return &vmStartConfig{
		DiskName:     "kairos-disk0",
		DiskPath:     filepath.Join(t.TempDir(), "kairos-disk0.qcow2"),
		DiskSize:     "60G",
		MemoryGB:     4,
		CPUs:         2,
		NetworkMode:  "bridged",
		Display:      "window",
		DownloadsDir: t.TempDir(),
		TakenNames:   map[string]struct{}{},
	}
}

// scriptedInput hands back one line per Read, the way a terminal in canonical
// mode does.
//
// A plain strings.Reader cannot drive reviewVMConfig: the function builds a
// fresh bufio.Reader for the menu on every iteration and prompt() builds
// another for every sub-prompt, and each of those fills its 4 KiB buffer from
// the first Read. A strings.Reader answers that with the WHOLE script, so the
// first bufio.Reader swallows every remaining line and then goes out of scope
// with them still in its buffer; the next prompt sees EOF and the reviewer
// returns "no input" instead of processing line two. Reading a line at a time
// is both what a tty actually does and the only way these tests exercise the
// menu rather than the cancel path.
func scriptedInput(script string) io.Reader {
	lines := strings.SplitAfter(script, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		if line != "" {
			out = append(out, line)
		}
	}
	return &lineReader{lines: out}
}

type lineReader struct{ lines []string }

func (r *lineReader) Read(p []byte) (int, error) {
	if len(r.lines) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.lines[0])
	if n < len(r.lines[0]) {
		r.lines[0] = r.lines[0][n:]
		return n, nil
	}
	r.lines = r.lines[1:]
	return n, nil
}
