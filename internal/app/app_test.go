package app

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
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
