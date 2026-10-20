//! `write_executable` must produce a file that runs at once while other
//! threads of the same process fork. A plain `std::fs::write` here fails with
//! "Text file busy" whenever a fork lands while the write descriptor is open.

#![cfg(unix)]

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};

/// A fresh directory for one test, under cargo's scratch space for tests.
fn scratch(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("write_executable-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn a_written_executable_runs_at_once_while_other_threads_fork() {
    const WRITERS: usize = 4;
    const ROUNDS_PER_WRITER: usize = 50;
    const FORKERS: usize = 8;

    let dir = scratch("forking");
    let done = AtomicBool::new(false);
    std::thread::scope(|s| {
        for _ in 0..FORKERS {
            s.spawn(|| {
                while !done.load(Ordering::Relaxed) {
                    Command::new("/bin/sh").args(["-c", ":"]).status().unwrap();
                }
            });
        }
        let writers: Vec<_> = (0..WRITERS)
            .map(|w| {
                let dir = &dir;
                s.spawn(move || {
                    for round in 0..ROUNDS_PER_WRITER {
                        let exe = dir.join(format!("stub-{w}-{round}"));
                        rvl_testgate::write_executable(&exe, "#!/bin/sh\necho ran\n");
                        let out = Command::new(&exe)
                            .output()
                            .unwrap_or_else(|e| panic!("round {round}: {e}"));
                        assert_eq!(out.stdout, b"ran\n", "round {round}");
                    }
                })
            })
            .collect();
        let results: Vec<_> = writers.into_iter().map(|h| h.join()).collect();
        done.store(true, Ordering::Relaxed);
        for r in results {
            if let Err(panic) = r {
                std::panic::resume_unwind(panic);
            }
        }
    });
}

#[test]
fn the_written_file_holds_the_body_and_no_partial_is_left() {
    let dir = scratch("body");
    let exe = dir.join("stub");
    let body = "#!/bin/sh\nprintf '%s\\n' \"it's $1\"\n";
    rvl_testgate::write_executable(&exe, body);
    assert_eq!(std::fs::read_to_string(&exe).unwrap(), body);
    let names: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(names, ["stub"], "the temporary name must be renamed away");
    let out = Command::new(&exe).arg("x").output().unwrap();
    assert_eq!(out.stdout, b"it's x\n");
}
