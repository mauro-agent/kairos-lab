//go:build unix

package state

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// TestUpdateSerialisesConcurrentMutators is the test the whole lock exists to
// satisfy: two goroutines calling Update on the same store at the same time
// must both survive, rather than one silently overwriting the other's write.
//
// Without mutual exclusion, the race goes like this: both goroutines Load the
// same starting file (no VMs yet), each appends its own VM to its own
// in-memory copy, and both call Save -- whichever Rename lands second
// publishes a file with only its own VM, discarding the other's entirely. To
// give that race the best chance of actually happening rather than merely
// being possible, both goroutines are released from a closed channel at
// once -- so their first filesystem call, the Load, is what races -- and the
// whole thing is repeated across several attempts against a freshly reset
// state file, since a single attempt can get lucky even when unsynchronised.
//
// This test was confirmed to redden the way the plan asked: with the
// syscall.Flock call in acquireLock commented out, this test failed on
// multiple attempts (one of the two VMs from a given attempt missing), every
// run tried; restoring the Flock call brought it back to a clean pass every
// time. That confirms the assertions below are actually exercising the lock
// and not just decorating a test that would pass unconditionally.
func TestUpdateSerialisesConcurrentMutators(t *testing.T) {
	t.Setenv("KAIROS_LAB_CONFIG_DIR", t.TempDir())
	t.Setenv("KAIROS_LAB_CACHE_DIR", t.TempDir())
	store, err := DefaultStore()
	if err != nil {
		t.Fatal(err)
	}

	const attempts = 20
	for attempt := 0; attempt < attempts; attempt++ {
		if err := store.Save(NewState(store)); err != nil {
			t.Fatal(err)
		}

		start := make(chan struct{})
		var wg sync.WaitGroup
		errs := make(chan error, 2)
		for _, name := range []string{"vm-a", "vm-b"} {
			name := name
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				if _, err := store.Update(func(st *State) error {
					UpsertVM(st, VM{Name: name})
					return nil
				}); err != nil {
					errs <- err
				}
			}()
		}
		close(start)
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatalf("attempt %d: Update failed: %v", attempt, err)
		}

		final, err := store.Load()
		if err != nil {
			t.Fatal(err)
		}
		if FindVM(final, "vm-a") == nil || FindVM(final, "vm-b") == nil {
			t.Fatalf("attempt %d: both concurrent Updates should survive, got VMs %+v -- one Update overwrote the other, so the lock did not serialise them", attempt, final.VMs)
		}
	}
}

// TestUpdateRefusesAFIFOAtTheLockPath pins the O_RDWR half of acquireLock's
// open call. mkfifo needs no privilege beyond write access to the config
// directory, which the user running kairos-lab already has, so this is a
// realistic obstacle and not a contrived one. An O_WRONLY open of a FIFO
// blocks until a reader opens the other end, which nothing here ever does; if
// acquireLock regressed to O_WRONLY this test would hang rather than fail,
// which is why it is bounded by a timeout instead of relying on the test
// process's own default deadline.
func TestUpdateRefusesAFIFOAtTheLockPath(t *testing.T) {
	t.Setenv("KAIROS_LAB_CONFIG_DIR", t.TempDir())
	t.Setenv("KAIROS_LAB_CACHE_DIR", t.TempDir())
	store, err := DefaultStore()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(store.ConfigDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(store.LockPath, 0o644); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := store.Update(func(*State) error { return nil })
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Update against a FIFO lock path should fail, not lock and use it")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Update blocked on a FIFO at the lock path instead of refusing it -- an O_WRONLY open would hang here forever")
	}
}

// TestUpdateRefusesASymlinkAtTheLockPath pins the O_NOFOLLOW half of
// acquireLock's open call: a symlink planted at the lock path must be
// refused, not followed and locked (or worse, created) at whatever it points
// to.
//
// The load-bearing case is the symlink pointing at an EXISTING regular file,
// not a dangling one. A dangling target used to be all this test planted,
// and the two-phase open defused it without O_NOFOLLOW's help: the first
// open carries O_EXCL, which fails EEXIST on a symlink all by itself
// (dangling or not), and the reopen has no O_CREATE, which fails ENOENT on a
// dangling target all by itself -- so both halves of the open pass for
// reasons that have nothing to do with O_NOFOLLOW. Demonstrated: with
// syscall.O_NOFOLLOW removed from both opens in acquireLock, the dangling
// case still passed. Pointing the symlink at a file that already exists
// removes that confound: O_EXCL still fails EEXIST on the symlink name
// itself, but the reopen would then FOLLOW the link to a real, existing
// file and succeed, and Update would go on to lock and use it -- unless
// O_NOFOLLOW is what stops the reopen from following it in the first place.
func TestUpdateRefusesASymlinkAtTheLockPath(t *testing.T) {
	t.Run("target exists", func(t *testing.T) {
		t.Setenv("KAIROS_LAB_CONFIG_DIR", t.TempDir())
		t.Setenv("KAIROS_LAB_CACHE_DIR", t.TempDir())
		store, err := DefaultStore()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(store.ConfigDir, 0o755); err != nil {
			t.Fatal(err)
		}
		// The symlink's target directory is its own t.TempDir() and not
		// store.ConfigDir, so the assertion below -- that the target's contents
		// are untouched -- cannot be confused by anything Update itself is
		// entitled to create (ConfigDir, via MkdirAll).
		target := filepath.Join(t.TempDir(), "attacker-target")
		if err := os.WriteFile(target, []byte("attacker file\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, store.LockPath); err != nil {
			t.Fatal(err)
		}

		if _, err := store.Update(func(*State) error { return nil }); err == nil {
			t.Fatal("Update against a symlinked lock path should fail, not follow the link and lock its target")
		} else if !strings.Contains(err.Error(), "symbolic link") {
			t.Errorf("error %q does not name the symlink refusal O_NOFOLLOW produces (ELOOP, \"too many levels of symbolic links\")", err)
		}
		body, err := os.ReadFile(target)
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != "attacker file\n" {
			t.Errorf("the symlink target's contents changed: %q", body)
		}
	})

	// Kept alongside the load-bearing case above: a dangling target is a
	// realistic shape too (a symlink whose target was removed, or one aimed at
	// a path that was never created), and it should still be refused even
	// though, as the doc comment above explains, this particular case does not
	// by itself pin O_NOFOLLOW.
	t.Run("target does not exist", func(t *testing.T) {
		t.Setenv("KAIROS_LAB_CONFIG_DIR", t.TempDir())
		t.Setenv("KAIROS_LAB_CACHE_DIR", t.TempDir())
		store, err := DefaultStore()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(store.ConfigDir, 0o755); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(t.TempDir(), "attacker-target")
		if err := os.Symlink(target, store.LockPath); err != nil {
			t.Fatal(err)
		}

		if _, err := store.Update(func(*State) error { return nil }); err == nil {
			t.Fatal("Update against a symlinked lock path should fail, not follow the link")
		}
		if _, err := os.Lstat(target); !os.IsNotExist(err) {
			t.Errorf("the symlink target should not exist, lstat returned: %v", err)
		}
	})
}

// TestUpdateRefusesAHardLinkAtTheLockPath pins the Nlink defence against a
// hard link at the lock path, which O_NOFOLLOW does nothing about: O_NOFOLLOW
// stops a SYMLINK from being followed, but a hard link is a second name for
// the very same inode, and the open just opens that inode directly, no
// following involved. IsRegular is true for it, exactly as it is for a
// legitimate lock file, which is what made the pre-fix code chown it at euid
// 0 without ever noticing it was not the file this call created (see
// acquireLock's own comment for the root-privileged half of this attack,
// which needs euid 0 to observe and so cannot be driven through this
// unprivileged test). What this test pins is available at any privilege
// level: a lock file with more than one link is refused outright, and the
// other name's contents are left untouched.
func TestUpdateRefusesAHardLinkAtTheLockPath(t *testing.T) {
	t.Setenv("KAIROS_LAB_CONFIG_DIR", t.TempDir())
	t.Setenv("KAIROS_LAB_CACHE_DIR", t.TempDir())
	store, err := DefaultStore()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(store.ConfigDir, 0o755); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(store.ConfigDir, "victim")
	if err := os.WriteFile(victim, []byte("victim\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(victim, store.LockPath); err != nil {
		t.Fatal(err)
	}

	if _, err := store.Update(func(*State) error { return nil }); err == nil {
		t.Fatal("Update against a hard-linked lock path should fail, not lock the victim's inode")
	}

	body, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "victim\n" {
		t.Errorf("the hard link's target was modified: contents = %q", body)
	}
}

// TestUpdateTimesOutRatherThanHangingOnAHeldLock pins the fix for a bare
// LOCK_EX with no deadline: any same-uid process that already holds this
// lock used to wedge every later Update indefinitely, with no message at
// all -- the same shape of failure the FIFO paragraph in acquireLock's
// comment already names, arrived at one syscall later. lockAcquireTimeout is
// shortened here only, the same idiom internal/vm/network_linux.go uses for
// staleCleanupSettleDelay, so this test proves the bound is enforced without
// itself waiting out the production timeout.
func TestUpdateTimesOutRatherThanHangingOnAHeldLock(t *testing.T) {
	t.Setenv("KAIROS_LAB_CONFIG_DIR", t.TempDir())
	t.Setenv("KAIROS_LAB_CACHE_DIR", t.TempDir())
	store, err := DefaultStore()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(store.ConfigDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Stand in for another kairos-lab process mid-Update: open and flock the
	// lock path directly, and hold it for the rest of the test.
	held, err := os.OpenFile(store.LockPath, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if err := syscall.Flock(int(held.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}

	original := lockAcquireTimeout
	lockAcquireTimeout = 200 * time.Millisecond
	t.Cleanup(func() { lockAcquireTimeout = original })

	done := make(chan error, 1)
	go func() {
		_, err := store.Update(func(*State) error { return nil })
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Update against an already-held lock should time out, not succeed")
		}
		if !strings.Contains(err.Error(), store.LockPath) {
			t.Errorf("error %q does not name the lock path", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Update did not return within 5s of a 200ms lockAcquireTimeout -- it is hanging rather than timing out")
	}
}

// TestAcquireLockRestartsAfterThePathIsReplacedBetweenOpenAndFlock pins the
// post-flock path/inode check (case 3 in lockOpenAttempts's own comment): a
// concurrent replace of the lock file that lands after this call's own open
// and fstat/Nlink check (which see the original file, correctly, since
// nothing has touched it yet) but before its flock succeeds must not be
// allowed to stand -- the descriptor would otherwise be left holding a lock
// on an inode that path no longer names, which guards nothing against
// anyone else who opens path fresh.
//
// The timing is made deterministic with real concurrency rather than a
// microsecond race: a competing flock is held on the original file first, so
// the goroutine under test is guaranteed to have already opened the file and
// taken its fstat/Nlink snapshot (Nlink == 1, correctly, since the swap
// below has not happened yet) before it ever reaches its own (blocked)
// flock attempt. The swap -- remove the original name, create a fresh file
// at the same name -- then happens at leisure, and only once it is
// complete is the held lock released, which is what lets the goroutine's
// blocked flock() finally succeed, on the now-orphaned original inode.
//
// What proves the fix actually ran, rather than merely that acquireLock
// returned no error, is the contention check at the end: flock is a
// per-INODE exclusion between any two independently opened descriptors on
// it (measured: two separate os.OpenFile calls on the same path conflict
// with each other, even within one process), so a LOCK_EX|LOCK_NB attempt
// through this test's own separate descriptor on the REPLACEMENT file
// succeeds if and only if acquireLock is not currently holding a lock on
// that same inode. Before this fix, acquireLock returned success right
// after the flock on the orphaned original succeeded, with nothing checking
// that path had moved on -- which this assertion would have caught, since
// nothing would then be holding the replacement's lock at all.
func TestAcquireLockRestartsAfterThePathIsReplacedBetweenOpenAndFlock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.lock")

	original, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	if err := syscall.Flock(int(original.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}

	type result struct {
		unlock func()
		err    error
	}
	resultCh := make(chan result, 1)
	go func() {
		u, err := acquireLock(path)
		resultCh <- result{u, err}
	}()

	// Give the goroutine time to open the file, take its fstat/Nlink
	// snapshot, and hit its own first (necessarily blocked, since original
	// still holds the lock) flock attempt -- all a handful of syscalls,
	// several orders of magnitude faster than this margin, and none of it
	// depends on anything this goroutine (the test) does next.
	time.Sleep(50 * time.Millisecond)

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	replacement, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()

	if err := syscall.Flock(int(original.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}

	var res result
	select {
	case res = <-resultCh:
	case <-time.After(5 * time.Second):
		t.Fatal("acquireLock did not return within 5s")
	}
	if res.err != nil {
		t.Fatalf("acquireLock returned an error, want success once the churn stops: %v", res.err)
	}
	defer res.unlock()

	flockErr := syscall.Flock(int(replacement.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if flockErr == nil {
		_ = syscall.Flock(int(replacement.Fd()), syscall.LOCK_UN)
		t.Fatal("acquireLock is not holding a lock on the replacement file -- it must have locked the orphaned original instead and never noticed path had moved on")
	}
	if !errors.Is(flockErr, syscall.EWOULDBLOCK) {
		t.Fatalf("unexpected error locking the replacement file from a second descriptor: %v", flockErr)
	}
}

// TestAcquireLockGivesUpWhenThePathNeverStopsBeingReplaced pins the restart
// bound: lockOpenAttempts caps the number of times acquireLock restarts the
// whole open/validate/lock sequence, so a path that keeps getting replaced
// on every single attempt must end in the timeout-shaped give-up error
// rather than spinning forever. openLockFile is faked to replace whatever it
// just successfully opened, on every call -- which drives the Nlink == 0
// retry (case 2) on every attempt, the same restart counter the post-flock
// check (case 3) shares, per lockOpenAttempts's own comment -- so this
// equally pins that the two share one bound rather than each getting its
// own.
func TestAcquireLockGivesUpWhenThePathNeverStopsBeingReplaced(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.lock")

	original := openLockFile
	calls := 0
	openLockFile = func(name string, flag int, perm os.FileMode) (*os.File, error) {
		f, err := original(name, flag, perm)
		if err != nil {
			return f, err
		}
		calls++
		if rerr := os.Remove(name); rerr != nil {
			t.Fatalf("remove during simulated churn: %v", rerr)
		}
		repl, cerr := original(name, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o644)
		if cerr != nil {
			t.Fatalf("recreate during simulated churn: %v", cerr)
		}
		_ = repl.Close()
		return f, nil
	}
	t.Cleanup(func() { openLockFile = original })

	_, err := acquireLock(path)
	if err == nil {
		t.Fatal("acquireLock should give up rather than succeed against a path that never stops being replaced")
	}
	if !strings.Contains(err.Error(), "kept being replaced or removed") {
		t.Errorf("error %q does not describe giving up on a churning path", err)
	}
	if calls != lockOpenAttempts {
		t.Errorf("openLockFile was called %d times, want exactly lockOpenAttempts (%d): the restart bound did not stop the loop where expected", calls, lockOpenAttempts)
	}
}

// TestAcquireLockOnceRetriesWhenLockFileDeletedAfterOpen pins the Nlink == 0
// branch (case 2 in lockOpenAttempts's comment): a lock file deleted in the
// window between this call's own open and the fstat immediately following
// it is "the file was deleted under us", not "the file aliases another
// path" -- it gets retry == true and a message that says so, distinct from
// the Nlink > 1 hard-link refusal pinned separately below.
func TestAcquireLockOnceRetriesWhenLockFileDeletedAfterOpen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.lock")

	original := openLockFile
	openLockFile = func(name string, flag int, perm os.FileMode) (*os.File, error) {
		f, err := original(name, flag, perm)
		if err != nil {
			return f, err
		}
		if rerr := os.Remove(name); rerr != nil {
			t.Fatalf("remove: %v", rerr)
		}
		return f, nil
	}
	t.Cleanup(func() { openLockFile = original })

	unlock, retry, err := acquireLockOnce(path, time.Now().Add(time.Second))
	if err == nil {
		if unlock != nil {
			unlock()
		}
		t.Fatal("acquireLockOnce should fail when its own descriptor's file was deleted before the Nlink check, not succeed")
	}
	if !retry {
		t.Errorf("a deleted-under-us lock file should be retryable, got retry = false, err = %v", err)
	}
	if !strings.Contains(err.Error(), "deleted") {
		t.Errorf("error %q does not describe the file as having been deleted", err)
	}
}

// TestAcquireLockOnceRefusesAHardLinkedFile pins the Nlink > 1 branch as the
// other half of the same fstat check TestAcquireLockOnceRetriesWhen
// LockFileDeletedAfterOpen pins: unlike a deleted file, a hard-linked one is
// a real, persistent problem with whatever is at path, so it is refused
// with retry == false and a distinct message, not folded into the same
// retryable bucket as Nlink == 0. TestUpdateRefusesAHardLinkAtTheLockPath
// above already pins this end-to-end through Update; this is the same
// check, exercised directly and paired with its Nlink == 0 sibling so the
// two distinct messages are asserted side by side.
func TestAcquireLockOnceRefusesAHardLinkedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.lock")
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("victim\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(victim, path); err != nil {
		t.Fatal(err)
	}

	unlock, retry, err := acquireLockOnce(path, time.Now().Add(time.Second))
	if err == nil {
		if unlock != nil {
			unlock()
		}
		t.Fatal("acquireLockOnce should refuse a hard-linked lock file, not succeed")
	}
	if retry {
		t.Errorf("a hard-linked file is a persistent problem, not a transient one -- got retry = true, err = %v", err)
	}
	if !strings.Contains(err.Error(), "hard links") {
		t.Errorf("error %q does not name the hard-link refusal", err)
	}
}

// TestAcquireLockOnceRejectsUnparsableSudoIDsAsRoot pins the euid-0
// chown-precondition's parse-failure branch. geteuid is faked to 0 rather
// than run as real root -- see openLockFile/geteuid's own comment for why
// that is enough to drive this branch without the test process needing
// root -- and confirms the lock file is removed rather than left behind
// root-"owned" (in the sense this run believed itself to be root) with an
// unresolved identity to hand it to.
func TestAcquireLockOnceRejectsUnparsableSudoIDsAsRoot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.lock")

	t.Setenv("SUDO_UID", "not-a-number")
	t.Setenv("SUDO_GID", "0")
	originalEuid := geteuid
	geteuid = func() int { return 0 }
	t.Cleanup(func() { geteuid = originalEuid })

	unlock, retry, err := acquireLockOnce(path, time.Now().Add(time.Second))
	if err == nil {
		if unlock != nil {
			unlock()
		}
		t.Fatal("acquireLockOnce should fail when SUDO_UID cannot be parsed as an integer under a faked euid 0, not succeed")
	}
	if retry {
		t.Errorf("an unparsable SUDO_UID/SUDO_GID is a real, non-transient problem -- got retry = true, err = %v", err)
	}
	if !strings.Contains(err.Error(), "could not be parsed") {
		t.Errorf("error %q does not name the parse failure", err)
	}
	if _, serr := os.Stat(path); !os.IsNotExist(serr) {
		t.Errorf("the lock file should have been removed rather than left behind, stat returned: %v", serr)
	}
}

// TestAcquireLockOnceRejectsAChownFailureAsRoot pins the euid-0
// chown-precondition's chown-failure branch. geteuid is faked to 0, but the
// chown syscall itself is not faked -- it runs for real, under this test
// process's real, unprivileged credentials, against a target uid that is
// neither that identity nor root, which is what makes the real fchown fail
// with EPERM deterministically without the test needing actual root.
func TestAcquireLockOnceRejectsAChownFailureAsRoot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.lock")

	targetUID := os.Geteuid() + 1
	t.Setenv("SUDO_UID", strconv.Itoa(targetUID))
	t.Setenv("SUDO_GID", strconv.Itoa(os.Getegid()))
	originalEuid := geteuid
	geteuid = func() int { return 0 }
	t.Cleanup(func() { geteuid = originalEuid })

	unlock, retry, err := acquireLockOnce(path, time.Now().Add(time.Second))
	if err == nil {
		if unlock != nil {
			unlock()
		}
		t.Fatal("acquireLockOnce should fail when the chown fails under a faked euid 0, not succeed")
	}
	if retry {
		t.Errorf("a chown failure is a real, non-transient problem -- got retry = true, err = %v", err)
	}
	if !strings.Contains(err.Error(), "could not be chowned") {
		t.Errorf("error %q does not name the chown failure", err)
	}
	if _, serr := os.Stat(path); !os.IsNotExist(serr) {
		t.Errorf("the lock file should have been removed rather than left root-owned, stat returned: %v", serr)
	}
}
