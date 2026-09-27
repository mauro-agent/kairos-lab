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
// The timing is made deterministic with a real handshake through the
// statLockFile seam, not an unsynchronised sleep: a previous version of this
// test used time.Sleep(50 * time.Millisecond) here on the theory that the
// goroutine's own open, fstat and first flock attempt -- a handful of
// syscalls -- would always finish well within that margin. They usually do,
// but "usually" is not "guaranteed": under scheduling pressure a
// late-scheduled goroutine could still be sitting at its very first
// instruction when the sleep elapses, so the swap below would land BEFORE
// the goroutine ever opens path, not after -- meaning its first (and only)
// attempt opens the REPLACEMENT directly, flocks it unopposed, matches its
// own Lstat trivially, and returns success on attempt 0, having never
// reached the restart path this test exists to pin. Every assertion below
// still passes in that scenario, because the lock it ends up holding
// genuinely is the replacement's -- which is what makes it a silent,
// load-dependent false pass rather than a loud failure.
//
// A first attempt at fixing that synchronised on openLockFile instead --
// signalling the moment the reopen of path (the only call in acquireLockOnce
// that touches path itself once a pre-existing file, "original" below, is
// already there) was issued -- is not quite enough either. That does prove
// the open targeted "original" rather than a later replacement, but the
// fstat/Nlink snapshot acquireLockOnce takes right after that open is a
// separate call, on a separate line, and nothing pins it to have already run
// by the time a test synchronised only on the open goes on to swap path.
// Measured: with the post-flock check deleted (the mutation this test exists
// to catch) and only that open-based signal gating the swap, this test still
// PASSED in roughly 1 run out of 5 under an injected 120ms scheduling delay
// -- the swap's unlink of path occasionally landed in the gap between the
// open returning and the fstat running, which drops this attempt's Nlink to
// 0 and routes it through the Nlink == 0 restart (case 2) instead of the
// post-flock check (case 3) this test means to pin; case 2 does not depend
// on the deleted check at all, so the mutant passed by accident, through the
// wrong door.
//
// statLockFile closes that gap: it is invoked exactly where the fstat/Nlink
// snapshot is taken, so gating the swap on it having already RETURNED (not
// merely on the earlier open having been issued) proves that snapshot is
// already in hand -- reading the original file's Nlink == 1, correctly,
// since nothing has touched it yet -- before the swap can begin. flock's own
// exclusivity does the rest of the ordering work from there: a competing
// LOCK_EX is already held on original before the goroutine is even spawned,
// so its own LOCK_EX|LOCK_NB attempt gets EWOULDBLOCK and the retry loop
// sleeps lockRetryInterval before trying again, which is what leaves it
// still holding that snapshot, blocked, once the swap below completes and
// releases the lock it is waiting on.
//
// What proves the fix actually ran, rather than merely that acquireLock
// returned no error, is two things, not one: the openLockFile call count
// asserted after the fact must be at least 2 -- proving a restart actually
// happened, rather than the single successful-on-attempt-0 path the
// unsynchronised version could silently take -- and the contention check at
// the end: flock is a per-INODE exclusion between any two independently
// opened descriptors on it (measured: two separate os.OpenFile calls on the
// same path conflict with each other, even within one process), so a
// LOCK_EX|LOCK_NB attempt through this test's own separate descriptor on the
// REPLACEMENT file succeeds if and only if acquireLock is not currently
// holding a lock on that same inode. Before the post-flock check existed,
// acquireLock returned success right after the flock on the orphaned
// original succeeded, with nothing checking that path had moved on -- which
// this assertion would have caught, since nothing would then be holding the
// replacement's lock at all.
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

	realOpenLockFile := openLockFile
	openCalls := 0
	openLockFile = func(name string, flag int, perm os.FileMode) (*os.File, error) {
		f, err := realOpenLockFile(name, flag, perm)
		openCalls++
		return f, err
	}
	t.Cleanup(func() { openLockFile = realOpenLockFile })

	realStatLockFile := statLockFile
	statted := make(chan struct{})
	var signaled bool
	statLockFile = func(f *os.File) (os.FileInfo, error) {
		fi, err := realStatLockFile(f)
		if !signaled {
			signaled = true
			close(statted)
		}
		return fi, err
	}
	t.Cleanup(func() { statLockFile = realStatLockFile })

	type result struct {
		unlock func()
		err    error
	}
	resultCh := make(chan result, 1)
	go func() {
		u, err := acquireLock(path)
		resultCh <- result{u, err}
	}()

	select {
	case <-statted:
	case <-time.After(5 * time.Second):
		t.Fatal("acquireLock did not reach its fstat/Nlink snapshot of path within 5s")
	}

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

	if openCalls < 2 {
		t.Errorf("openLockFile was called %d time(s), want at least 2: acquireLock must not have restarted, so this test never exercised the post-flock identity check it exists to pin", openCalls)
	}

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
// bound's existence: lockOpenAttempts caps the number of times acquireLock
// restarts the whole open/validate/lock sequence, so a path that keeps
// getting replaced on every single attempt must end in the give-up error
// rather than spinning forever -- removing lockOpenAttempts's cap (letting
// acquireLock restart unboundedly) reddens this test.
//
// linkLockFile is faked to remove path immediately after every successful
// link -- which drives the Nlink == 0 retry (case 2 in lockOpenAttempts's
// comment) on every attempt. This does NOT also exercise case 3 (the
// post-flock path/inode mismatch): every attempt here is caught by the
// Nlink == 0 check before ever reaching the flock, since removing path drops
// this call's own link count to 0 well before that point (instrumented: the
// post-flock check was reached 0 times over 5 runs of this test). So this
// pins only that the bound exists, not that case 2 and case 3 share it --
// TestAcquireLockRestartsAfterThePathIsReplacedBetweenOpenAndFlock is what
// exercises case 3, separately, and nothing here pins that the two count
// against the same counter rather than each having its own.
//
// The error assertion checks for "restart bound (lockOpenAttempts) was
// spent" specifically, not the more general "kept being replaced or
// removed" both give-up messages share: acquireLock returns two distinct
// give-up errors, one when lockOpenAttempts is spent (this test's own
// scenario) and a separate one when lockAcquireTimeout elapses instead, and
// a substring present in both pins neither -- it would still pass against a
// mutant that made this test hit the wrong one of the two. Only the
// restart-bound phrasing is unique to the message this scenario actually
// produces.
func TestAcquireLockGivesUpWhenThePathNeverStopsBeingReplaced(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.lock")

	original := linkLockFile
	calls := 0
	linkLockFile = func(oldname, newname string) error {
		if err := original(oldname, newname); err != nil {
			return err
		}
		calls++
		if rerr := os.Remove(newname); rerr != nil {
			t.Fatalf("remove during simulated churn: %v", rerr)
		}
		return nil
	}
	t.Cleanup(func() { linkLockFile = original })

	_, err := acquireLock(path)
	if err == nil {
		t.Fatal("acquireLock should give up rather than succeed against a path that never stops being replaced")
	}
	if !strings.Contains(err.Error(), "restart bound (lockOpenAttempts) was spent") {
		t.Errorf("error %q does not describe the restart bound being spent -- it should not be the deadline (lockAcquireTimeout) give-up message instead", err)
	}
	if calls != lockOpenAttempts {
		t.Errorf("linkLockFile succeeded %d time(s), want exactly lockOpenAttempts (%d): the restart bound did not stop the loop where expected", calls, lockOpenAttempts)
	}
}

// TestAcquireLockOnceRetriesWhenLockFileDeletedAfterOpen pins the Nlink == 0
// branch (case 2 in lockOpenAttempts's comment): a lock file deleted in the
// window between this call's own link() into place and the fstat that
// follows it is "the file was deleted under us", not "the file aliases
// another path" -- it gets retry == true and a message that says so,
// distinct from the Nlink > 1 hard-link refusal pinned separately below.
//
// linkLockFile, not openLockFile, is the seam to fake for this: creation no
// longer opens path directly (see acquireLockOnce's own doc comment), so the
// window this test targets sits between linkLockFile succeeding and
// acquireLockOnce's own subsequent removal of its temporary name -- a
// concurrent unlink of path landing there leaves only the temporary name,
// and this call's own cleanup of THAT name is what actually drops the link
// count to 0, one line later.
func TestAcquireLockOnceRetriesWhenLockFileDeletedAfterOpen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.lock")

	original := linkLockFile
	linkLockFile = func(oldname, newname string) error {
		if err := original(oldname, newname); err != nil {
			return err
		}
		if rerr := os.Remove(newname); rerr != nil {
			t.Fatalf("remove: %v", rerr)
		}
		return nil
	}
	t.Cleanup(func() { linkLockFile = original })

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

// TestAcquireLockOnceRetriesAPreExistingHardLinkedFile pins the Nlink > 1
// branch this scenario reaches: path is already a hard link to victim before
// this call ever runs, so linkLockFile's own link(2) fails EEXIST and this
// call takes the reopen branch -- the same branch case 4 in
// lockOpenAttempts's own comment describes another kairos-lab process's own
// mid-publish as reaching. A single attempt cannot tell the two apart (chown
// never runs on this branch either way, which is exactly why it is the
// persistent case's only remaining target), so it is retry == true here,
// same as that transient case -- not retry == false, which used to be this
// test's own assertion (and this test's own name) until the design changed
// to fix spurious non-retryable refusals during an ordinary concurrent
// publish. The persistent case this test actually sets up is still refused
// in the end: TestUpdateRefusesAHardLinkAtTheLockPath pins that end-to-end
// through Update, where acquireLock's restart bound converts a hard link
// that never resolves into its own give-up error once the bound is spent,
// rather than acquireLockOnce ever calling it non-retryable on the first
// attempt.
func TestAcquireLockOnceRetriesAPreExistingHardLinkedFile(t *testing.T) {
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
	if !retry {
		t.Errorf("a single attempt reaching a hard link via the reopen branch cannot yet tell it apart from another kairos-lab process mid-publish -- got retry = false, err = %v", err)
	}
	if !strings.Contains(err.Error(), "hard links") {
		t.Errorf("error %q does not name the hard-link refusal", err)
	}

	body, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "victim\n" {
		t.Errorf("the hard link's target was modified: contents = %q", body)
	}
}

// TestAcquireLockOnceRejectsUnparsableSudoIDsAsRoot pins the euid-0
// chown-precondition's parse-failure branch. geteuid is faked to 0 rather
// than run as real root -- see openLockFile/geteuid's own comment for why
// that is enough to drive this branch without the test process needing
// root -- and confirms the temporary file is removed rather than left
// behind root-"owned" (in the sense this run believed itself to be root)
// with an unresolved identity to hand it to.
//
// The directory, not path itself, is what this asserts against: this
// branch fires before linkLockFile ever runs, so path is never created in
// the first place, and an os.Stat(path) NotExist assertion used to hold
// unconditionally -- true whether or not cleanupTmp ran at all.
// Demonstrated: removing the cleanupTmp() call from this branch in
// production code left a state.lock.tmp-* behind and this test still
// passed, because it was asserting something about path that this branch
// never touches. A ReadDir of the directory is what actually depends on the
// temporary file's removal.
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
	entries, derr := os.ReadDir(dir)
	if derr != nil {
		t.Fatalf("read dir: %v", derr)
	}
	if len(entries) != 0 {
		t.Errorf("the temporary file should have been removed rather than left behind, directory contains: %v", entries)
	}
}

// TestAcquireLockOnceRejectsAChownFailureAsRoot pins the euid-0
// chown-precondition's chown-failure branch. geteuid is faked to 0, but the
// chown syscall itself is not faked -- it runs for real, under this test
// process's real, unprivileged credentials, against a target uid that is
// neither that identity nor root, which is what makes the real fchown fail
// with EPERM deterministically without the test needing actual root. If the
// suite is ever run as real root, targetUID's real fchown would succeed
// instead of failing -- the same reason state_test.go's
// TestSaveFailureLeavesPreviousStateIntact guards itself the same way.
//
// The directory, not path itself, is what this asserts against -- see
// TestAcquireLockOnceRejectsUnparsableSudoIDsAsRoot's own comment for why an
// os.Stat(path) assertion here was a tautology (path is never created
// before this branch fires) rather than a pin on cleanupTmp actually
// running.
func TestAcquireLockOnceRejectsAChownFailureAsRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can chown to any uid, so the chown under test would succeed")
	}
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
	entries, derr := os.ReadDir(dir)
	if derr != nil {
		t.Fatalf("read dir: %v", derr)
	}
	if len(entries) != 0 {
		t.Errorf("the temporary file should have been removed rather than left root-owned, directory contains: %v", entries)
	}
}

// TestAcquireLockOnceRefusesASecondLinkOnItsOwnPublishedFile pins the
// !reopened arm of the Nlink > 1 check -- reachable only through this call's
// own successful link (or its own successful link(2)-unsupported fallback
// create), which is why a second name appearing on that same inode before
// the fstat runs is refused outright (retry == false), not treated as the
// transient, other-process-mid-publish case the reopen branch handles.
// Mutating `reopened := false` to `reopened := true` unconditionally --
// which makes this arm unreachable -- reddens this test: with that mutation
// this scenario returns retry == true instead of false.
//
// statLockFile is the seam used to plant the second link, rather than racing
// a real goroutine: it runs exactly once, right after this call's own
// successful link and its own cleanup of its temporary name (f is already
// tmpFile, path already names the published file) and right before the
// fstat/Nlink snapshot the check under test reads -- see statLockFile's own
// comment for why that is a reliable, synchronous point to intervene rather
// than a timing window measured in microseconds.
func TestAcquireLockOnceRefusesASecondLinkOnItsOwnPublishedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.lock")
	second := filepath.Join(dir, "second-name")

	realStatLockFile := statLockFile
	statLockFile = func(f *os.File) (os.FileInfo, error) {
		if err := os.Link(path, second); err != nil {
			t.Fatalf("plant a second link at %s: %v", second, err)
		}
		return realStatLockFile(f)
	}
	t.Cleanup(func() { statLockFile = realStatLockFile })

	unlock, retry, err := acquireLockOnce(path, time.Now().Add(time.Second))
	if err == nil {
		if unlock != nil {
			unlock()
		}
		t.Fatal("acquireLockOnce should refuse when its own just-published file gains a second link before the fstat, not succeed")
	}
	if retry {
		t.Errorf("this call is the only one that has ever named this inode by path on the non-reopen branch, so a second name on it now is a real, persistent problem, not a transient one -- got retry = true, err = %v", err)
	}
	if !strings.Contains(err.Error(), "hard links") {
		t.Errorf("error %q does not name the hard-link refusal", err)
	}
}

// TestAcquireLockOnceRefusalQuotesAnAttackerControlledTempSibling pins two
// things at once, both at 0% coverage before this test: that the outright
// -refusal branch's own lockTempSibling hint actually fires when a real
// leftover sibling is there (exercising lockTempSibling's own
// `return matches[0]`, and this call site's own `if sib != ""` body), and
// that the sibling's name -- read from filepath.Glob over ConfigDir, which
// this file's own comments already treat as attacker-writable -- reaches the
// error message quoted (%q) rather than raw. cmd/kairos-lab/main.go prints
// errors with a bare fmt.Fprintln(os.Stderr, "error:", err), no filtering, so
// an unquoted control byte in a filename would reach a real terminal.
func TestAcquireLockOnceRefusalQuotesAnAttackerControlledTempSibling(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.lock")
	second := filepath.Join(dir, "second-name")
	sibling := path + ".tmp-esc\x1bcr\rlf\n"
	if err := os.WriteFile(sibling, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	realStatLockFile := statLockFile
	statLockFile = func(f *os.File) (os.FileInfo, error) {
		if err := os.Link(path, second); err != nil {
			t.Fatalf("plant a second link at %s: %v", second, err)
		}
		return realStatLockFile(f)
	}
	t.Cleanup(func() { statLockFile = realStatLockFile })

	_, _, err := acquireLockOnce(path, time.Now().Add(time.Second))
	if err == nil {
		t.Fatal("acquireLockOnce should refuse when its own just-published file gains a second link before the fstat, not succeed")
	}
	msg := err.Error()
	// On the sibling's quoted NAME rather than on the prose around it: the
	// name is what the hint exists to deliver and what the quoting has to
	// cover, and an assertion on the wording breaks whenever the wording is
	// corrected without the behaviour changing -- which is how this line was
	// found.
	if !strings.Contains(msg, strconv.Quote(sibling)) {
		t.Errorf("error %q does not name the leftover temporary sibling %q", msg, sibling)
	}
	if strings.ContainsAny(msg, "\x1b\r\n") {
		t.Errorf("error message contains raw control bytes from the attacker-named sibling, want them quoted: %q", msg)
	}
	if !strings.Contains(msg, `\x1b`) || !strings.Contains(msg, `\r`) || !strings.Contains(msg, `\n`) {
		t.Errorf("error message does not contain the quoted escapes for the sibling's control bytes: %q", msg)
	}
}

// TestAcquireLockGiveUpQuotesAnAttackerControlledTempSibling pins the same
// two things as TestAcquireLockOnceRefusalQuotesAnAttackerControlledTempSibling
// above, but at acquireLock's own give-up call site, and specifically at the
// churn branch of it. The hard-link branch has a sibling hint of its own and
// it is quoted the same way; what pins that one is
// TestAcquireLockGiveUpNamesASiblingThatIsTheSecondLink below, which plants
// the fixture where the sibling is not merely present but is the second link.
func TestAcquireLockGiveUpQuotesAnAttackerControlledTempSibling(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.lock")
	sibling := path + ".tmp-esc\x1bcr\rlf\n"
	if err := os.WriteFile(sibling, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	original := linkLockFile
	linkLockFile = func(oldname, newname string) error {
		if err := original(oldname, newname); err != nil {
			return err
		}
		if rerr := os.Remove(newname); rerr != nil {
			t.Fatalf("remove during simulated churn: %v", rerr)
		}
		return nil
	}
	t.Cleanup(func() { linkLockFile = original })

	_, err := acquireLock(path)
	if err == nil {
		t.Fatal("acquireLock should give up against a path that never stops being replaced")
	}
	msg := err.Error()
	// On the sibling's quoted NAME rather than on the prose around it: the
	// name is what the hint exists to deliver and what the quoting has to
	// cover, and an assertion on the wording breaks whenever the wording is
	// corrected without the behaviour changing -- which is how this line was
	// found.
	if !strings.Contains(msg, strconv.Quote(sibling)) {
		t.Errorf("error %q does not name the leftover temporary sibling %q", msg, sibling)
	}
	if strings.ContainsAny(msg, "\x1b\r\n") {
		t.Errorf("error message contains raw control bytes from the attacker-named sibling, want them quoted: %q", msg)
	}
	if !strings.Contains(msg, `\x1b`) || !strings.Contains(msg, `\r`) || !strings.Contains(msg, `\n`) {
		t.Errorf("error message does not contain the quoted escapes for the sibling's control bytes: %q", msg)
	}
}

// TestAcquireLockOnceFallsBackWhenLinkIsUnsupported pins the
// isLinkUnsupported fallback, at 0% coverage before this test -- the whole
// fallback block was never reached by any test. linkLockFile is faked to
// return EOPNOTSUPP -- one of the four errno shapes isLinkUnsupported
// recognises -- on every call, which routes this call through the
// O_CREATE|O_EXCL-at-path branch rather than the ordinary
// temp-file-and-link one. SUDO_UID/SUDO_GID are set to this process's own
// real uid/gid, and geteuid is faked to 0, so the fallback's chown runs and
// succeeds without real root by asking for the ownership the file already
// has. That makes this the SUCCESS shape of the branch; what it can and
// cannot assert about the chown is spelled out at the assertion itself.
func TestAcquireLockOnceFallsBackWhenLinkIsUnsupported(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.lock")

	realLinkLockFile := linkLockFile
	linkLockFile = func(oldname, newname string) error { return syscall.EOPNOTSUPP }
	t.Cleanup(func() { linkLockFile = realLinkLockFile })

	t.Setenv("SUDO_UID", strconv.Itoa(os.Geteuid()))
	t.Setenv("SUDO_GID", strconv.Itoa(os.Getegid()))
	originalEuid := geteuid
	geteuid = func() int { return 0 }
	t.Cleanup(func() { geteuid = originalEuid })

	unlock, retry, err := acquireLockOnce(path, time.Now().Add(time.Second))
	if err != nil {
		t.Fatalf("acquireLockOnce should fall back to creating directly at path when link(2) is unsupported, not fail: retry=%v, err=%v", retry, err)
	}
	defer unlock()

	// Creates AT the final name, with no leftover temporary file: unlike the
	// ordinary route, this branch never has a separate temporary name to
	// clean up (see the fallback's own comment).
	entries, derr := os.ReadDir(dir)
	if derr != nil {
		t.Fatal(derr)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(path) {
		t.Fatalf("directory contains %v, want exactly the lock file itself with no leftover temporary name", entries)
	}

	var st syscall.Stat_t
	if serr := syscall.Stat(path, &st); serr != nil {
		t.Fatal(serr)
	}
	// Deliberately NOT asserted here: that the fallback's own chown ran.
	// SUDO_UID/SUDO_GID above are this process's own ids, so the fchown is a
	// no-op and the resulting ownership is identical whether
	// chownToInvokingUser was called or skipped -- deleting that call from the
	// fallback entirely reddens nothing here. An assertion that cannot fail is
	// worse than no assertion, because it reads like a guarantee.
	//
	// Nor is it pinned anywhere else, and that is a property of the code
	// rather than a gap in the tests: chownToInvokingUser has already run once
	// in this same call, against the temporary file, with identical
	// preconditions -- same euid, same SUDO_UID, same SUDO_GID -- and a
	// failure there returns before the link is ever attempted. So any
	// configuration that would make the fallback's chown fail has already made
	// the earlier one fail, and the fallback's failure branch (with the
	// os.Remove(path) that is this function's one exception to leaving the
	// lock path alone) is unreachable by construction. It is kept as defence
	// in depth against a future edit that reorders or removes the earlier
	// call; an attempt to test it here observed only the earlier chown
	// failing, which is the tautology this comment exists to stop someone
	// rediscovering.
	_ = st
	// Still checks Nlink: an ordinary, single-link file is what the Nlink
	// check is required to accept, and did -- acquireLockOnce returned
	// success rather than refusing or retrying.
	if st.Nlink != 1 {
		t.Errorf("fallback-created lock file has %d hard links, want 1", st.Nlink)
	}
	// Still runs the post-flock identity check: unlock succeeding (deferred
	// above) with no error already proves this call reached and passed it.
}

// TestAcquireLockGiveUpNamesASiblingThatIsTheSecondLink pins the sibling hint
// on the HARD-LINK give-up, which is a different branch from the churn
// give-up the sibling test above covers.
//
// It exists because an earlier version of this code looked for a sibling only
// on the churn branch, reasoning that this call's own temporary name is always
// gone by the time a reopen observes a hard link -- true -- and generalising
// from that to every sibling, which is false. The fixture below is the
// counterexample: a publish killed between its own link(tmp, path) and its own
// os.Remove(tmpPath) leaves the temporary name pointing at the very inode now
// at path, so the sibling IS the second link. Nlink stays at 2 for good, every
// attempt is spent, and removing that file by hand is precisely what clears
// it -- so the message has to name it.
func TestAcquireLockGiveUpNamesASiblingThatIsTheSecondLink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.lock")
	// The state an interrupted publish leaves: the temporary name and the
	// lock path are two names for one inode.
	sibling := path + ".tmp-0123456789abcdef"
	if err := os.WriteFile(sibling, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(sibling, path); err != nil {
		t.Fatal(err)
	}

	original := lockAcquireTimeout
	lockAcquireTimeout = 2 * time.Second
	t.Cleanup(func() { lockAcquireTimeout = original })

	_, err := acquireLock(path)
	if err == nil {
		t.Fatal("acquireLock should give up against a permanently hard-linked lock path, not acquire it")
	}
	msg := err.Error()
	// This exact phrase is emitted only by the hard-link give-up branch, so it
	// is what distinguishes the two branches. Asserting merely on "hard link"
	// would not: the churn give-up wraps lastErr too, and lastErr's own text
	// already contains those words, so collapsing both branches onto the churn
	// narrative would leave a looser assertion green.
	if !strings.Contains(msg, "still found more than one hard link") {
		t.Errorf("give-up message is not the hard-link one, so the branch selection fell through to the churn narrative: %q", msg)
	}
	if !strings.Contains(msg, strconv.Quote(sibling)) {
		t.Errorf("give-up message does not name the leftover sibling %q, which is the second link and whose removal is the remedy: %q", sibling, msg)
	}
	// Not "every attempt": nothing records what the earlier attempts saw.
	if strings.Contains(msg, "every attempt") {
		t.Errorf("give-up message claims something about every attempt when only the last one's error is carried: %q", msg)
	}
}

// TestAcquireLockOnceDoesNotFallBackOnAnUnrelatedLinkError pins
// isLinkUnsupported's own narrowness end to end: a link(2) failure for a
// reason that has nothing to do with hardlink support at all (EACCES, a
// permissions problem) must surface as the ordinary, non-retryable "create
// lock file" error, not be swallowed into the fallback -- which would give up
// the fallback's own (already-reduced) protections for no reason, and
// silently mask a real permissions problem as if it were a filesystem
// limitation.
func TestAcquireLockOnceDoesNotFallBackOnAnUnrelatedLinkError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.lock")

	original := linkLockFile
	linkLockFile = func(oldname, newname string) error { return syscall.EACCES }
	t.Cleanup(func() { linkLockFile = original })

	unlock, retry, err := acquireLockOnce(path, time.Now().Add(time.Second))
	if err == nil {
		if unlock != nil {
			unlock()
		}
		t.Fatal("acquireLockOnce should surface an unrelated link(2) failure (EACCES) as an ordinary error, not fall back to creating directly at path")
	}
	if retry {
		t.Errorf("EACCES is not one of the four races lockOpenAttempts's comment describes -- got retry = true, err = %v", err)
	}
	if _, statErr := os.Lstat(path); !os.IsNotExist(statErr) {
		t.Errorf("path should not have been created at all when link(2) fails for an unrelated reason, lstat returned: %v", statErr)
	}
}

// TestIsLinkUnsupportedClassifiesErrnosNarrowly pins isLinkUnsupported's own
// narrow boundary directly, at 0.0% coverage before this test: only the four
// errnos its own comment names, not a blanket "anything that is not
// ErrExist".
func TestIsLinkUnsupportedClassifiesErrnosNarrowly(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"EPERM", syscall.EPERM, true},
		{"EOPNOTSUPP", syscall.EOPNOTSUPP, true},
		{"ENOSYS", syscall.ENOSYS, true},
		{"EXDEV", syscall.EXDEV, true},
		{"EACCES", syscall.EACCES, false},
		{"ErrExist", os.ErrExist, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isLinkUnsupported(tc.err); got != tc.want {
				t.Errorf("isLinkUnsupported(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
