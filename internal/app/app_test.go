package app

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

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

// injectedBridgeName is a stored bridge name that forges a cleanup-plan row
// and then erases the real row printed after it: a newline, a row shaped like
// the ones printList emits, then CSI 2K (erase line) and a carriage return.
// Written with Go escapes, so no raw control byte appears in this source.
const injectedBridgeName = "kairoslab0\n  - eth0 (will be KEPT)\x1b[2K\r"

// injectedTapName does the same from the tap row, which is the other
// state-derived value in the same plan.
const injectedTapName = "tap0\n  - wlan0 (will be KEPT)\x1b[2K\r"

// seedInjectedState writes a completed-setup state.json carrying the given
// network names, the way anything running as the user could: the file is the
// tool's own 0644 config file, and nothing between store.Load() and the plan
// print looks at what is in it.
func seedInjectedState(t *testing.T, bridge, tap string) *state.Store {
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
	st.Network.BridgeName = bridge
	st.Network.TapName = tap
	if err := store.Save(st); err != nil {
		t.Fatalf("Save: %v", err)
	}
	return store
}

// assertPlanIsInert fails if the plan that was printed could act on the
// terminal it was printed to. The raw bytes are what matters: an escaped
// "\x1b" in the output is six harmless characters, a real 0x1b is the start
// of a control sequence.
func assertPlanIsInert(t *testing.T, out string) {
	t.Helper()
	if strings.ContainsRune(out, 0x1b) {
		t.Errorf("plan output carries a raw escape byte, so a stored name reached the terminal:\n%q", out)
	}
	// A real newline followed by a row is what makes a forged row a row. The
	// same text after an escaped "\\n" is one long quoted value on a single
	// line, which is the whole point of the fix -- so this looks for the
	// literal byte, not for the words.
	for _, forged := range []string{"\n  - eth0 (will be KEPT)", "\n  - wlan0 (will be KEPT)"} {
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
// inert on their own, which is what %q makes them.
func TestPlanDoesNotLetAStoredNameReachTheTerminal(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the network plan rows are only printed on linux")
	}
	for _, verb := range []string{"reset", "cleanup"} {
		t.Run(verb, func(t *testing.T) {
			t.Setenv("KAIROS_LAB_CONFIG_DIR", t.TempDir())
			t.Setenv("KAIROS_LAB_CACHE_DIR", t.TempDir())
			seedInjectedState(t, injectedBridgeName, injectedTapName)

			var stdout, stderr bytes.Buffer
			// -dry-run stops after the plan and before the prompt, so this
			// asserts on exactly the bytes the user would be asked to
			// consent to, and touches nothing on the host.
			if err := Run([]string{verb, "-dry-run"}, strings.NewReader(""), &stdout, &stderr, "test"); err != nil {
				t.Fatalf("%s -dry-run: %v", verb, err)
			}
			out := stdout.String()
			assertPlanIsInert(t, out)
			for _, want := range []string{
				fmt.Sprintf("  - bridge: %q\n", injectedBridgeName),
				fmt.Sprintf("  - tap: %q\n", injectedTapName),
			} {
				if !strings.Contains(out, want) {
					t.Errorf("plan is missing the escaped row %q; got:\n%q", want, out)
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
	seedInjectedState(t, injectedBridgeName, "")

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
	store := seedInjectedState(t, injectedBridgeName, "")

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
	seedInjectedState(t, injectedBridgeName, "")

	var stdout, stderr bytes.Buffer
	err := Run([]string{"cleanup", "-yes"}, strings.NewReader(""), &stdout, &stderr, "test")
	if err == nil {
		t.Fatal("cleanup returned nil after the network cleanup refused to run")
	}
	if !strings.Contains(err.Error(), "cleanup incomplete") {
		t.Errorf("error %q does not say the cleanup was incomplete", err)
	}
	if strings.Contains(stdout.String(), "cleanup complete") {
		t.Errorf("cleanup still reported completion:\n%s", stdout.String())
	}
}
