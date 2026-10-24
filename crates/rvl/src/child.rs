//! The one way `rvl` runs a child it waits on: a retriever helper or the
//! user's coding agent.
//!
//! `Command::output()` has no timeout, so a helper that hangs hangs the scan,
//! and a CI job with it. The budgets above it (`run_with_budget`) could only
//! stop WAITING: the worker thread was abandoned and the child kept running.
//! [`run`] owns both halves instead:
//!
//! * The child starts in its OWN process group (unix), so a timeout kills
//!   everything it started, not just the process rvl knows the pid of: a
//!   `node`/`java`/`python3` helper and whatever it forked share the group.
//! * At the deadline the whole group gets `SIGKILL` and the child is reaped,
//!   so no orphan and no zombie survives the call.
//! * The group is killed after a NORMAL exit too: a straggler that outlives
//!   its leader would otherwise hold the output pipes open and wedge the read.
//! * A process group no longer receives the terminal's Ctrl-C, so while a
//!   group is live rvl forwards `SIGINT`/`SIGTERM`/`SIGHUP` to it as a kill
//!   before dying of the signal itself. Without that, interrupting a scan
//!   would leave its helpers running.

use std::io::Read;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

/// How a bounded child ended.
#[derive(Debug)]
pub enum Ran {
    /// It exited on its own; its full output.
    Exited(Output),
    /// The deadline passed first. Its process group was killed and reaped.
    TimedOut,
}

/// Run `cmd` to completion, or until `deadline`. stdin is closed; stdout and
/// stderr are captured, the same as `Command::output()`. `None` waits forever,
/// still in its own process group.
pub fn run(cmd: &mut Command, deadline: Option<Instant>) -> std::io::Result<Ran> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
        signals::install();
    }
    let mut child = cmd.spawn()?;
    #[cfg(unix)]
    let _live = signals::Live::register(child.id());
    let (tx, rx) = std::sync::mpsc::channel();
    drain(child.stdout.take(), 0, tx.clone());
    drain(child.stderr.take(), 1, tx);
    let mut pause = Duration::from_millis(1);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break Some(status);
        }
        let now = Instant::now();
        if deadline.is_some_and(|d| now >= d) {
            break None;
        }
        let left = deadline.map_or(pause, |d| d - now);
        std::thread::sleep(pause.min(left));
        pause = (pause * 2).min(Duration::from_millis(50));
    };
    // After a normal exit this reaches whatever the leader left in its group.
    // The group id cannot have been reused while any member is alive, and
    // with none alive there is nothing to hit but a pid the kernel would have
    // to recycle as a new group leader within microseconds.
    kill_group(&mut child);
    let Some(status) = status else {
        child.wait()?;
        // The readers end on their own once the group's pipes close; nobody
        // needs what they hold.
        return Ok(Ran::TimedOut);
    };
    let mut streams = [Vec::new(), Vec::new()];
    for _ in 0..streams.len() {
        let got = match deadline {
            Some(d) => rx.recv_timeout(d.saturating_duration_since(Instant::now())),
            None => rx
                .recv()
                .map_err(|_| std::sync::mpsc::RecvTimeoutError::Disconnected),
        };
        match got {
            Ok((i, bytes)) => streams[i] = bytes,
            // A descendant that left the group still holds a pipe open: the
            // deadline bounds the read as it bounds the run.
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => return Ok(Ran::TimedOut),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    let [stdout, stderr] = streams;
    Ok(Ran::Exited(Output {
        status,
        stdout,
        stderr,
    }))
}

/// Read one pipe to its end on a thread, sending the bytes tagged with `slot`.
fn drain<R: Read + Send + 'static>(
    pipe: Option<R>,
    slot: usize,
    tx: std::sync::mpsc::Sender<(usize, Vec<u8>)>,
) {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut p) = pipe {
            let _ = p.read_to_end(&mut buf);
        }
        let _ = tx.send((slot, buf));
    });
}

#[cfg(unix)]
fn kill_group(child: &mut std::process::Child) {
    // SAFETY: plain syscall. The group id is the child's pid.
    unsafe {
        libc::killpg(child.id() as libc::pid_t, libc::SIGKILL);
    }
}

#[cfg(not(unix))]
fn kill_group(child: &mut std::process::Child) {
    let _ = child.kill();
}

/// Killing live groups when rvl itself is interrupted.
#[cfg(unix)]
mod signals {
    use std::sync::atomic::{AtomicI32, Ordering};

    /// Live process groups. Fixed slots rather than a locked collection: the
    /// handler reads them, and a handler may not take a lock. Helpers run one
    /// at a time, so a handful of slots is plenty; a group that finds no free
    /// slot simply is not forwarded the signal.
    static LIVE: [AtomicI32; 16] = [const { AtomicI32::new(0) }; 16];

    const FORWARDED: [libc::c_int; 3] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP];

    /// Install the handler once, for each signal that still has its default
    /// action. A signal the caller set to ignore (`nohup`) stays ignored.
    pub fn install() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            for sig in FORWARDED {
                // SAFETY: `on_signal` is async-signal-safe: atomics and
                // syscalls only.
                unsafe {
                    let previous = libc::signal(
                        sig,
                        on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t,
                    );
                    if previous != libc::SIG_DFL {
                        libc::signal(sig, previous);
                    }
                }
            }
        });
    }

    extern "C" fn on_signal(sig: libc::c_int) {
        for slot in &LIVE {
            let pgid = slot.load(Ordering::SeqCst);
            if pgid > 0 {
                // SAFETY: async-signal-safe syscalls.
                unsafe {
                    libc::killpg(pgid, libc::SIGKILL);
                }
            }
        }
        // Then die of the signal as rvl would have without the handler.
        unsafe {
            libc::signal(sig, libc::SIG_DFL);
            libc::raise(sig);
        }
    }

    /// A registered live group, released on drop.
    pub struct Live(Option<usize>);

    impl Live {
        pub fn register(pid: u32) -> Live {
            let pgid = pid as i32;
            Live(LIVE.iter().position(|s| {
                s.compare_exchange(0, pgid, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
            }))
        }
    }

    impl Drop for Live {
        fn drop(&mut self) {
            if let Some(i) = self.0 {
                LIVE[i].store(0, Ordering::SeqCst);
            }
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn sh(script: &str) -> Command {
        let mut c = Command::new("sh");
        c.arg("-c").arg(script);
        c
    }

    /// Is `pid` gone? A killed orphan is a zombie until its new parent reaps
    /// it, and a zombie runs nothing, so it counts as gone. Polled briefly:
    /// the reparent and reap are not instant.
    fn gone(pid: i32) -> bool {
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            let ps = Command::new("ps")
                .args(["-o", "stat=", "-p", &pid.to_string()])
                .output()
                .unwrap();
            let stat = String::from_utf8_lossy(&ps.stdout).trim().to_string();
            if stat.is_empty() || stat.starts_with('Z') {
                return true;
            }
            if Instant::now() > until {
                return false;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    #[test]
    fn a_child_that_exits_returns_its_output() {
        let got = run(&mut sh("echo out; echo err >&2; exit 3"), None).unwrap();
        let Ran::Exited(o) = got else {
            panic!("must exit: {got:?}")
        };
        assert_eq!(o.status.code(), Some(3));
        assert_eq!(String::from_utf8_lossy(&o.stdout), "out\n");
        assert_eq!(String::from_utf8_lossy(&o.stderr), "err\n");
    }

    #[test]
    fn a_child_past_its_deadline_is_killed_with_everything_it_started() {
        let dir = tempfile::tempdir().unwrap();
        let pidfile = dir.path().join("pid");
        // The grandchild writes its pid, then both sleep far past the deadline.
        let script = format!("sleep 60 & echo $! > {}; wait", pidfile.display());
        let start = Instant::now();
        let got = run(
            &mut sh(&script),
            Some(Instant::now() + Duration::from_millis(300)),
        )
        .unwrap();
        assert!(matches!(got, Ran::TimedOut), "{got:?}");
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "{:?}",
            start.elapsed()
        );
        let grandchild: i32 = std::fs::read_to_string(&pidfile)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(
            gone(grandchild),
            "the grandchild {grandchild} outlived the kill"
        );
    }

    #[test]
    fn a_straggler_does_not_outlive_a_leader_that_exited() {
        let dir = tempfile::tempdir().unwrap();
        let pidfile = dir.path().join("pid");
        let script = format!(
            "sleep 60 >/dev/null 2>&1 & echo $! > {}; echo done",
            pidfile.display()
        );
        let got = run(
            &mut sh(&script),
            Some(Instant::now() + Duration::from_secs(30)),
        )
        .unwrap();
        assert!(matches!(got, Ran::Exited(_)), "{got:?}");
        let straggler: i32 = std::fs::read_to_string(&pidfile)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(
            gone(straggler),
            "the straggler {straggler} outlived its leader"
        );
    }
}
