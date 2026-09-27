//go:build unix

// This file has no !unix companion on purpose. .goreleaser.yaml builds only
// linux and darwin, and CI runs ubuntu-latest and macos-latest -- both unix
// -- so a !unix fallback would compile on no platform this repo ships or
// tests, and would exist only to bit-rot unnoticed.
package state

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

// Update runs mutate against the state Load returns, saves the result, and
// returns it -- with an exclusive cross-process lock held for the whole
// Load/mutate/Save cycle, so two processes calling Update at the same time
// cannot each load the same starting state and each save a version that
// undoes the other's change.
//
// The lock is advisory: it only ever excludes another call to Update. A
// process that calls Load and Save directly -- which every call site still
// does in this milestone, since converting them is the next one -- is
// unaffected and can still race. Nothing here can change that; flock only
// binds callers who ask for it.
//
// Update must never be called from inside a mutate callback. acquireLock
// opens a fresh file descriptor on every call, and flock's exclusivity is
// per OPEN FILE DESCRIPTION, not per process or per path -- so a nested call
// would try to lock the same file a second time from the same process with a
// second descriptor, which blocks against the first exactly as it would
// against a different process. That is not a deadlock, though: the bounded
// retry loop below (see lockAcquireTimeout) means the nested call cannot
// succeed -- it burns the whole lockAcquireTimeout and then fails with a
// timeout error naming the lock path -- which makes the outer call fail too,
// since mutate's own error return propagates straight out of Update.
// Demonstrated with lockAcquireTimeout shortened to 300ms: an inner Update
// nested inside an outer one's mutate callback returned the timeout error,
// the outer Update then returned that same error, and a later, unnested
// Update acquired the lock in 6ms -- nothing was left wedged. This is not
// theoretical for this codebase specifically: milestone 3 gives runStart's
// IP-poller a reason to write state from a goroutine that runs concurrently
// with the main path holding this lock mid-cycle -- a separate goroutine
// calling Update, not a nested call from inside mutate. Two goroutines
// contending for this lock do not deadlock either; they serialise behind
// whichever one gets it first, or the loser times out under contention.
//
// On a mutate error, the lock is released and the error is returned as-is,
// without saving: whatever mutate half-built on the in-memory State is
// discarded along with it. That is only true of the State value, though --
// not of every side effect of the attempt. os.MkdirAll below and the lock
// file's create-if-absent open have already happened by the time mutate
// runs, so a failed Update can still leave a freshly created config
// directory or lock file behind; "as if Update had never been called" used
// to be the claim here, and it overstated what actually unwinds.
func (s *Store) Update(mutate func(*State) error) (*State, error) {
	if err := os.MkdirAll(s.ConfigDir, 0o755); err != nil {
		return nil, fmt.Errorf("create config directory: %w", err)
	}

	lockPath := s.LockPath
	if lockPath == "" {
		lockPath = filepath.Join(s.ConfigDir, "state.lock")
	}

	unlock, err := acquireLock(lockPath)
	if err != nil {
		return nil, err
	}
	defer unlock()

	st, err := s.Load()
	if err != nil {
		return nil, err
	}
	if err := mutate(st); err != nil {
		return nil, err
	}
	// The lock path is deliberately NOT added to st.ManagedFiles. It used to
	// be, on the theory that `cleanup` should remove it along with everything
	// else this tool leaves behind -- but cleanup's removal loop is
	// os.Remove, and unlinking the lock path while another process holds it
	// open is exactly the swap the separate-lock-file design exists to avoid
	// (see acquireLockOnce's own doc comment): the name stops pointing at the
	// locked inode, and the next Update's O_CREATE makes a fresh inode at
	// that name and locks THAT one instead, immediately, with zero mutual
	// exclusion from whoever still holds the old one. Demonstrated: process A
	// holding LOCK_EX, the path unlinked out from under it, and process B's
	// O_CREATE|LOCK_EX|LOCK_NB succeeding at once -- two writers inside the
	// critical section simultaneously. Nothing is lost by leaving it
	// untracked: cleanup already removes ConfigDir wholesale (it is in
	// ManagedDirs), which takes the lock file with it regardless of whether
	// it also appears in ManagedFiles.
	if err := s.Save(st); err != nil {
		return nil, err
	}
	return st, nil
}

// lockRetryInterval is how long acquireLock sleeps between LOCK_EX|LOCK_NB
// attempts while another process holds the lock, before checking the overall
// deadline again.
const lockRetryInterval = 100 * time.Millisecond

// lockAcquireTimeout bounds how long acquireLock will keep retrying an
// already-held lock before giving up, rather than blocking forever the way a
// bare LOCK_EX does. A plain LOCK_EX wedges every later Update -- including
// the `reset` that would otherwise let a user clean up the mess -- against
// any same-uid process that still holds the lock, with no message saying
// why; that is the exact FIFO-shaped failure this file's other comments
// already warn about, reached one syscall later than the FIFO gets to it.
// Demonstrated: a held lock blocked a second acquireLock for at least 15
// seconds with no output before the attempt was given up on.
//
// It is a var, not a const, only so a test can shorten it -- the same idiom
// internal/vm/network_linux.go uses for staleCleanupSettleDelay: nothing in
// production ever assigns it.
var lockAcquireTimeout = 5 * time.Second

// lockOpenAttempts bounds how many times acquireLock restarts the whole
// open/validate/lock sequence from the top, across three distinct races that
// all have the same shape: something removed or replaced whatever path names
// while this call was partway through locking it, leaving this call holding
// (or about to hold) a lock on an inode nobody can reach by path any more --
// which guards nothing, since every other process still finds path, opens
// whatever inode is there now, and locks THAT one, with zero mutual
// exclusion from this one.
//
//  1. The create/reopen race, documented at the point it is detected below: a
//     concurrent unlink of the lock path between the O_EXCL attempt failing
//     and the reopen succeeding fails the reopen with ENOENT.
//  2. A concurrent unlink that instead lands strictly between an open
//     (either branch) and the fstat that follows it: the descriptor is still
//     open on an inode whose Nlink has already dropped to 0, meaning every
//     name that inode had -- including this one -- is already gone. Also
//     documented at the point it is detected below.
//  3. A concurrent replace -- an unlink followed by a fresh create at the
//     same name -- that lands AFTER this call's own flock succeeds: caught
//     by comparing a stat of the descriptor (taken before the flock) against
//     a stat of the PATH (taken after), since flock's exclusivity binds the
//     inode this descriptor points at and says nothing about what the name
//     currently resolves to. This is what makes the os.Remove calls in the
//     euid-0 chown-failure branch below safe: that unlink can hand a
//     concurrent waiter a lock on an inode this same restart will notice is
//     no longer the one at path, and send back through this loop instead of
//     letting it proceed as if it had exclusive access.
//
// The fix in every case is the same: close the stale descriptor and start
// over from the open, on the theory that a path this volatile will
// eventually hold still for one full attempt. 2, not unbounded: one retry
// was already enough for case 1 alone (a single concurrent unlinker,
// measured), and cases 2 and 3 are instances of the identical race rather
// than a reason to add headroom per case -- a real deployment is not
// expected to hit more than one of the three in a row. Anything that keeps
// failing past this bound is a path that will not stop changing, which is a
// real error to surface (see the timeout-shaped error acquireLock returns
// when this bound or the overall lockAcquireTimeout deadline is reached)
// rather than a reason to keep spinning.
const lockOpenAttempts = 2

// openLockFile is os.OpenFile, and geteuid is os.Geteuid, each a var only so
// a test can substitute it -- the same idiom lockAcquireTimeout already uses
// in this file ("a var only so a test can shorten it; nothing in production
// assigns it").
//
// openLockFile lets a test intervene between this call's own open and its
// flock -- swapping the file at path out from under it -- to drive the
// post-flock inode check (case 3 in lockOpenAttempts's comment) on demand,
// deterministically, rather than racing a real concurrent goroutine against
// a timing window measured in microseconds.
//
// geteuid lets a test simulate running as euid 0 -- which the chown branch
// below is gated on -- without the test process actually needing to run as
// root. The chown syscall itself is not faked: fchown still runs for real
// against the test's real (non-root) privileges, which is what lets a test
// drive a genuine chown failure deterministically (chown to a uid that is
// not the test's own euid fails with EPERM when not actually privileged)
// without a third seam.
var (
	openLockFile = os.OpenFile
	geteuid      = os.Geteuid
)

// acquireLock opens (creating if needed) the file at path, locks it
// exclusively with flock, and returns a function that unlocks and closes it.
// The caller is expected to defer the returned function immediately.
//
// This is a thin restart wrapper around acquireLockOnce, which is where
// every actual open/validate/lock decision (and the reasoning behind each
// one) lives; see its own doc comment for that. What lives here is only the
// bound on how many times, and for how long, this will restart the whole
// sequence when acquireLockOnce reports the path was replaced or removed out
// from under a single attempt (see lockOpenAttempts's own comment for the
// three specific races that can trigger a restart).
func acquireLock(path string) (unlock func(), err error) {
	// One deadline, computed once here and threaded through every attempt
	// below (both the flock-wait loop inside acquireLockOnce and the
	// restart bound in this loop): lockAcquireTimeout is documented as the
	// OVERALL limit on how long acquireLock keeps trying, and computing a
	// fresh deadline per attempt would let a path that keeps getting
	// replaced (lockOpenAttempts's cases 2 and 3) rearm a full fresh
	// lockAcquireTimeout of flock-wait budget on every restart, silently
	// turning a bounded wait into an unbounded one.
	deadline := time.Now().Add(lockAcquireTimeout)
	var lastErr error
	for attempt := 0; ; attempt++ {
		unlockFn, retry, aerr := acquireLockOnce(path, deadline)
		if aerr == nil {
			return unlockFn, nil
		}
		if !retry {
			return nil, aerr
		}
		lastErr = aerr
		// Give up with a timeout-shaped error, rather than restart again,
		// once EITHER bound is spent: lockOpenAttempts (a path that keeps
		// getting replaced faster than the deadline arrives, which would
		// otherwise spin very fast for the whole lockAcquireTimeout) or the
		// deadline itself (a path that stops changing only after
		// lockAcquireTimeout has already elapsed). lastErr is wrapped in
		// rather than discarded, so the specific race that was hit --
		// ENOENT on the reopen, Nlink == 0, or the post-flock path/inode
		// mismatch -- is still visible to whoever reads the error.
		if attempt >= lockOpenAttempts-1 || !time.Now().Before(deadline) {
			return nil, fmt.Errorf("timed out after %d attempt(s) trying to get a stable lock on %s: the file kept being replaced or removed out from under this process -- if this persists, another process may be repeatedly recreating it; try again (%w)", attempt+1, path, lastErr)
		}
	}
}

// acquireLockOnce is the single-attempt body acquireLock's restart loop
// calls: it opens (creating if needed) the file at path, validates it, locks
// it exclusively with flock (waiting, bounded by deadline, if someone else
// already holds it), and returns a function that unlocks and closes it.
//
// The retry return distinguishes two kinds of failure. false means the
// failure is a real, non-transient problem (a FIFO or socket at path, a
// symlink, a hard link, an unparseable SUDO_UID/SUDO_GID, a chown failure,
// or the lock genuinely still held past deadline) and acquireLock should
// return it as-is. true means path was observed to have been replaced or
// removed out from under this attempt -- see lockOpenAttempts's own comment
// for the three specific races this covers -- and acquireLock should close
// this attempt's descriptor (already done here before returning) and start
// over from the open, on the theory that a path this volatile will
// eventually hold still for one full attempt.
//
// A separate file, and not state.json itself: Save (state.go) publishes
// state.json by os.Rename-ing a temporary file over the name, so the inode a
// lock was taken on stops being the inode at that path the moment any writer
// saves. A second process that then locked "state.json" would lock the NEW
// inode left by that rename and get zero mutual exclusion from a process
// still holding a lock on the old one. A lock file that nothing ever renames
// over is the only way flock's guarantee -- which is about an inode, not a
// path -- holds across saves.
//
// Every choice below closes a specific hole that was demonstrated against
// this repo, not a theoretical one, and each is commented at the line it
// governs.
func acquireLockOnce(path string, deadline time.Time) (unlock func(), retry bool, err error) {
	// O_NOFOLLOW: this file lives in the user's config directory, which
	// kairos-lab's own privilege model treats as attacker-writable input in
	// several other places already (see the comments on Store.Save and
	// validateStoredInterfaceName) -- and running the whole tool under sudo
	// is blessed on macOS, where the stock sudoers keeps HOME, so this open
	// can happen as root against a path inside a directory the invoking user
	// controls. It is what stops a symlink planted at path from being
	// followed: measured against a plain os.OpenFile(path, os.O_CREATE|
	// os.O_RDWR, ...) with a symlink already at path, the open followed the
	// link and created the attacker's chosen target -- as root, if the
	// process was. With O_NOFOLLOW the same open instead fails immediately
	// with "too many levels of symbolic links".
	//
	// O_RDWR and not O_WRONLY: a FIFO planted at path (mkfifo needs no
	// privilege beyond write access to the directory, which the user already
	// has) makes an O_WRONLY|O_CREATE open BLOCK until a reader opens the
	// other end -- which nothing here ever will, so every later invocation of
	// this tool, including the `reset` that would otherwise let a user clean
	// up the mess, hangs forever on this open. Measured: O_WRONLY blocked
	// indefinitely against a FIFO at path; O_RDWR on the same FIFO returned
	// immediately, because a reader/writer open on a FIFO does not wait for a
	// peer the way a read-only or write-only one does.
	//
	// os.OpenFile and not a raw syscall.Open: os.OpenFile always adds
	// O_CLOEXEC under the hood, and that is load-bearing here rather than
	// hygiene. `kairos-lab start` execs QEMU as a child process; a lock fd
	// that leaked across that exec would still be held open (and still
	// flocked) by the QEMU process for the VM's entire lifetime, so a second
	// `kairos-lab start` run against the same config dir would block on this
	// same flock until that VM exited -- silently, with no message pointing
	// at why. Do not swap this for syscall.Open even for a seemingly
	// equivalent flag set; it does not set O_CLOEXEC and a later refactor
	// that made that swap would reintroduce exactly this.
	//
	// 0o644 and not 0o600: what actually saves a user from being locked out
	// of their own file after a root-privileged run (sudo on macOS) is the
	// chown below, made a hard precondition rather than best-effort -- NOT
	// the mode. A previous version of this comment claimed "at 0o644 the user
	// can still open it read-write", which is false: the mode's `other` class
	// is what a non-owning user gets, and 0644's other class is r--, while
	// this open is O_RDWR; measured directly, O_RDWR on a real root-owned
	// 0644 file this process did not own returned "permission denied", and
	// O_RDONLY on the same file succeeded. A second version of this same
	// comment then claimed a process with the same uid the file already has
	// "can still open it read-write regardless of mode", which is also
	// false: measured as the owning uid against its own file, O_RDWR
	// succeeded at 0644 but 0444, 0400 and 0000 all failed with permission
	// denied -- the owner-class bits bind the owner exactly as they read.
	// Root is the only thing exempt from a file's mode altogether, and that
	// is what a root-privileged run's own opens rely on regardless of what
	// this mode is set to. What 0644 actually buys the one case that
	// matters, correctly stated: nothing a tighter mode would not also buy
	// -- the chown below is what changes the owner away from root, and the
	// owning uid it hands the file to gets read-write from 0644's owner
	// class either way, the same as it would from 0600's.
	//
	// The open itself is two-phase, not one os.OpenFile call, and that is the
	// fix for a hard-link attack fchown lands on: `ln /etc/sudoers
	// ~/.config/kairos-lab/state.lock` plants a hard link whose inode is a
	// file the attacker does not own but the lock code would previously have
	// chowned anyway, because O_NOFOLLOW stops a SYMLINK and does nothing at
	// all about a hard link -- IsRegular() is true for one, and f.Chown is
	// fchown(2), which lands on the inode the fd points at regardless of how
	// many names lead to it. Demonstrated: with a hard link planted at the
	// lock path, the O_NOFOLLOW open succeeded, IsRegular was true, the fd's
	// inode equalled the victim's, and the victim's ownership changed.
	// Linux's fs.protected_hardlinks=1 confines the ordinary version of this
	// to files the attacker already owns, but macOS -- precisely where this
	// tool blesses running under sudo with HOME preserved -- has no
	// equivalent control at all.
	//
	// So: try O_CREATE|O_EXCL first. Success means this call is the one that
	// created the file, which is the only case chown below ever runs in --
	// a hard link or any other pre-existing name at path fails O_EXCL with
	// os.ErrExist and falls through to a plain reopen that never chowns
	// anything. The Nlink check just below is the second, independent half of
	// the same fix: even on the created branch, this refuses to lock (and
	// therefore never chowns) a file that already has more than one link,
	// which a file this call only just created cannot legitimately have.
	//
	// The reopen carries no O_CREATE -- it must not create a file the O_EXCL
	// attempt just proved already exists, or it would stop being the "only
	// case chown runs in is the one that created the file" guarantee above
	// depends on -- but that leaves a real window open: this process's own
	// `cleanup` (or another one running concurrently) can unlink path between
	// the two opens, and a lock path this steady-state, no-contention run IS
	// going to take -- the O_EXCL attempt failing EEXIST because a previous
	// run's lock file is still there is the ordinary case, not the rare one
	// -- would then fail the reopen with ENOENT. That is case 1 of the three
	// races lockOpenAttempts's own comment describes: retry is returned true
	// rather than failing this attempt's caller outright, for a path that
	// is, an instant later, perfectly creatable again.
	created := true
	f, err := openLockFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR|syscall.O_NOFOLLOW, 0o644)
	if err != nil {
		if !errors.Is(err, os.ErrExist) {
			return nil, false, fmt.Errorf("open lock file %s: %w", path, err)
		}
		created = false
		f, err = openLockFile(path, os.O_RDWR|syscall.O_NOFOLLOW, 0o644)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil, true, fmt.Errorf("open lock file %s: %w", path, err)
			}
			return nil, false, fmt.Errorf("open lock file %s: %w", path, err)
		}
	}
	closed := false
	cleanup := func() {
		if !closed {
			_ = f.Close()
		}
	}
	defer func() {
		if err != nil {
			cleanup()
		}
	}()

	// fstat the DESCRIPTOR, not the path: a path-based stat could observe a
	// perfectly ordinary regular file and then race a swap before the flock
	// below is taken. Stat-ing the fd instead answers the only question that
	// matters -- what did this open actually hand back -- and cannot be
	// raced out from under it. A FIFO, socket or device sitting at this path
	// is not a lock file anyone legitimately created; it is refused rather
	// than locked.
	fi, err := f.Stat()
	if err != nil {
		return nil, false, fmt.Errorf("stat lock file %s: %w", path, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, false, fmt.Errorf("lock file %s is not a regular file (mode %s): refusing to lock it", path, fi.Mode())
	}
	// The Nlink field this checks below distinguishes three states, not two:
	//
	//   Nlink == 1: an ordinary lock file with exactly the one name this
	//   call opened it by. Proceed.
	//
	//   Nlink == 0: this descriptor's inode has already been unlinked from
	//   every name it had, including path -- case 2 of the three races
	//   lockOpenAttempts's own comment describes. This is "the file was
	//   deleted under us", not "the file aliases another path", and it gets
	//   retry == true and a message that says so, exactly like case 1 above:
	//   there is nothing wrong with the file this call is holding open other
	//   than that path no longer names it, which the next attempt's open
	//   trivially fixes.
	//
	//   Nlink > 1: a second name for this inode that this function did not
	//   itself create -- this function never names a file more than once --
	//   so it is refused outright with retry == false, on both branches
	//   above. On the reopen branch this is the only defence against the
	//   hard-link attack described above (chown never runs there at all); on
	//   the created branch it is a second, independent one, in case anything
	//   ever links to the file in the window between this open and this
	//   stat. Unlike Nlink == 0, a hard link is a real, persistent problem
	//   with whatever is at path, not a transient one an instant will fix --
	//   it does not belong in the same retryable bucket.
	//
	// The type assertion failing is treated as a refusal too, not as "the
	// check does not apply here": failing open is what a defence is supposed
	// to do when it cannot tell whether the thing it defends against is
	// present, and the alternative -- ok == false silently skipping the only
	// guard the reopen branch has -- is a fail-OPEN shape that would lock a
	// hard-linked file the moment this assertion ever stopped holding. It is
	// unreachable on every GOOS this //go:build unix file compiles for today
	// (fi.Sys() is always *syscall.Stat_t on linux and darwin alike), which is
	// exactly why it must fail closed rather than silently trust that fact
	// forever.
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, false, fmt.Errorf("lock file %s: could not determine its hard link count (fi.Sys() did not return *syscall.Stat_t): refusing to lock it", path)
	}
	if st.Nlink == 0 {
		// No manual close here: err is set on the way out, so the deferred
		// cleanup above closes f. Nothing has been locked yet at this point,
		// so a plain close is all this branch ever needs.
		return nil, true, fmt.Errorf("lock file %s was deleted while this process was opening it (0 hard links)", path)
	}
	if st.Nlink > 1 {
		return nil, false, fmt.Errorf("lock file %s has %d hard links, want exactly 1: refusing to lock a file that may alias another path", path, st.Nlink)
	}

	// The chown is a hard precondition when it applies, not a best-effort
	// nicety: it is the only thing that stops a root-privileged run (sudo on
	// macOS) from leaving a root-owned file inside a directory the invoking
	// user owns and expects to fully control -- see the mode comment above
	// for why 0o644 does not do this on its own. It applies only when this
	// call created the file (created, above): a file that already existed
	// was not created by this euid-0 run, and chowning it would be changing
	// the ownership of someone else's file rather than fixing this run's
	// own. SUDO_UID/SUDO_GID are what sudo itself sets to the invoking user's
	// identity, so chowning to them undoes exactly the ownership sudo
	// introduced -- nothing more. When they are absent (running as real root,
	// not via sudo) there is no invoking user to hand the file back to, so
	// nothing here is attempted or required.
	//
	// Both failure branches below unlink path before returning: created is
	// true here, so this call is the one that just put a root-owned file at
	// path, and leaving it there hands the very next unprivileged run (this
	// tool never suggests running as root except for this one euid-0 path) a
	// bare "permission denied" on that file with no remedy at all -- exactly
	// the lockout the chown exists to prevent, self-inflicted by the attempt
	// to prevent it. Unlinking it here is what closes the loop the previous
	// version of this error asked the user to close by hand ("remove the
	// file and try again"); this does that removal itself instead of asking.
	//
	// Unlinking path here by name, rather than the inode this descriptor
	// holds, is exactly the shape of change that used to break mutual
	// exclusion for a concurrent waiter: a second process's reopen can have
	// already succeeded against this same inode, in the window between this
	// call's O_EXCL and this point, and go on to flock it and proceed as
	// though it had exclusive access to whatever is at path -- which, after
	// this unlink, it no longer does. That is what the post-flock
	// path/inode check below (case 3 in lockOpenAttempts's comment) exists
	// to catch, in that OTHER call, not this one: this call itself never
	// reaches the flock below on either failure branch here, so what makes
	// this unlink safe is not anything added in this call's own path, but
	// every caller of acquireLockOnce validating what it locked, after it
	// locked it, against what the name currently resolves to.
	if created && geteuid() == 0 {
		uidStr, gidStr := os.Getenv("SUDO_UID"), os.Getenv("SUDO_GID")
		if uidStr != "" && gidStr != "" {
			uid, uerr := strconv.Atoi(uidStr)
			gid, gerr := strconv.Atoi(gidStr)
			// Absent SUDO_UID/SUDO_GID is fine (real root, not via sudo --
			// nothing to hand the file back to, above). Present but
			// unparsable is a different case entirely: sudo did set them, so
			// there IS an invoking user this file should belong to, and
			// silently skipping the chown here used to take the lock anyway
			// and leave exactly the root-owned file the chown exists to
			// prevent -- with nothing in the error path ever telling anyone
			// that happened, because there was no error path; this branch did
			// not return one.
			if uerr != nil || gerr != nil {
				_ = os.Remove(path)
				return nil, false, fmt.Errorf("lock file %s was created owned by root, but SUDO_UID=%q / SUDO_GID=%q could not be parsed as integers (%v / %v): the file has been removed rather than left root-owned -- try again", path, uidStr, gidStr, uerr, gerr)
			}
			if cerr := f.Chown(uid, gid); cerr != nil {
				_ = os.Remove(path)
				return nil, false, fmt.Errorf("lock file %s was created owned by root and could not be chowned to the invoking user (uid %d, gid %d): %w -- the file has been removed rather than left root-owned; try again", path, uid, gid, cerr)
			}
		}
	}

	// LOCK_EX|LOCK_NB in a bounded retry loop, not a bare blocking LOCK_EX:
	// see lockAcquireTimeout's own comment for why a plain LOCK_EX is a
	// silent, indefinite hang the moment any same-uid process already holds
	// this lock. deadline is the caller's, not a fresh one computed here --
	// see acquireLock's own comment for why it must not be recomputed per
	// attempt.
	for {
		flockErr := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if flockErr == nil {
			break
		}
		if !errors.Is(flockErr, syscall.EWOULDBLOCK) {
			return nil, false, fmt.Errorf("lock file %s: %w", path, flockErr)
		}
		if !time.Now().Before(deadline) {
			return nil, false, fmt.Errorf("timed out after %s waiting for the lock on %s: another kairos-lab process, or another part of this one, is holding it -- wait for it to finish and try again", lockAcquireTimeout, path)
		}
		time.Sleep(lockRetryInterval)
	}

	// The standard lockfile-validation check, and the reason every one of
	// this function's callers -- not just this one -- has to run it: flock's
	// exclusivity is a property of the INODE this descriptor points at, not
	// of path, and path is the name every OTHER process still finds this
	// lock by. The two can come apart -- a concurrent unlink-then-recreate
	// at path, landing anywhere from just after this call's own open to
	// just after this very flock succeeded -- and when they do, this
	// descriptor is holding a lock on an orphaned inode that guards nothing:
	// every other process opens the name, gets the NEW inode now sitting at
	// path, and locks that one immediately, with zero mutual exclusion from
	// this call. Comparing a stat of path against a stat of the descriptor
	// is what tells the two apart: st (from the fstat above, unaffected by
	// the chown, which changes ownership, not device or inode) is this
	// descriptor's identity; pathStat is a fresh Lstat of the name, not a
	// Stat, on the same not-attacker-controlled-input reasoning as the
	// O_NOFOLLOW open above -- a symlink now sitting at path should not be
	// followed even just to compare, since its own device+inode will simply
	// (and correctly) fail to match this descriptor's either way. A path
	// that no longer exists at all (ENOENT) is folded into the same
	// mismatch, for the same reason as Nlink == 0 above: this descriptor's
	// lock does not guard whatever is or is not at path any more, and that
	// is the whole of what this check exists to catch.
	//
	// This also makes a user's manual `rm` of the lock file safe -- which
	// matters because the timed-out error above used to recommend exactly
	// that ("remove the file and try again", in an earlier version of this
	// comment) -- rather than a second, silent way to end up with two
	// processes each believing they hold exclusive access.
	//
	// On mismatch this is folded into the same retry as cases 1 and 2 above
	// (see lockOpenAttempts's comment): the lock this attempt holds is
	// unlocked and closed, and the caller starts over from the open.
	var pathStat syscall.Stat_t
	if serr := syscall.Lstat(path, &pathStat); serr != nil || pathStat.Dev != st.Dev || pathStat.Ino != st.Ino {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		cleanup()
		closed = true
		return nil, true, fmt.Errorf("lock file %s was replaced or removed while this process held its lock (path now resolves to a different inode, or none)", path)
	}

	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		closed = true
		_ = f.Close()
	}, false, nil
}
