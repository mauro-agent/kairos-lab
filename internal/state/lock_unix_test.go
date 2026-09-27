//go:build unix

package state

import (
	"os"
	"path/filepath"
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
