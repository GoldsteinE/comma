#![allow(unused_unsafe)]

mod syscall;
use syscall::Syscall;

use std::{
    collections::HashMap,
    convert::{TryFrom as _, TryInto as _},
    io,
    os::unix::process::CommandExt as _,
    process::{Command, Stdio},
};

use color_eyre::eyre::{self, bail, WrapErr as _};
use nix::{
    errno::Errno,
    libc::{PTRACE_EVENT_CLONE, PTRACE_EVENT_FORK, PTRACE_EVENT_VFORK},
    sys::{
        ptrace,
        signal::Signal,
        wait::{waitpid, WaitPidFlag, WaitStatus},
    },
    unistd::Pid,
};

fn ptrace_options() -> ptrace::Options {
    use ptrace::Options;

    Options::PTRACE_O_TRACEFORK
        | Options::PTRACE_O_TRACEVFORK
        | Options::PTRACE_O_TRACECLONE
        | Options::PTRACE_O_TRACESYSGOOD
}

fn main() -> eyre::Result<()> {
    color_eyre::install()?;
    tracing_subscriber::fmt::init();

    let mut cmd = Command::new("cmake");
    unsafe {
        cmd.pre_exec(|| ptrace::traceme().map_err(|err| io::Error::from_raw_os_error(err as i32)));
    }
    cmd.stdin(Stdio::null());
    cmd.current_dir("/home/goldstein/pets/comma/foobar/build");
    cmd.arg("--debug-output").arg("--trace").arg("..");
    let child = cmd.spawn()?;
    let pid = Pid::from_raw(
        child
            .id()
            .try_into()
            .wrap_err("failed to convert PID to i32")?,
    );

    let wait_res = waitpid(pid, None)?;
    if !matches!(wait_res, WaitStatus::Stopped(_, Signal::SIGTRAP)) {
        bail!("unexpected wait_pid result: {:?}", wait_res);
    }

    ptrace::setoptions(pid, ptrace_options())?;

    tracing::info!("Tracking pid {}", pid);
    let mut syscall_start_map = HashMap::new();
    syscall_start_map.insert(pid, true);

    match ptrace::syscall(pid, None) {
        Ok(_) | Err(Errno::ESRCH) => {}
        Err(err) => return Err(err.into()),
    }

    let exit_code = loop {
        let status = waitpid(None, Some(WaitPidFlag::__WALL))?;
        let current_pid = status.pid();

        match status {
            WaitStatus::Exited(exited_pid, code) => {
                tracing::info!("{} exited with code {}", exited_pid, code);
                if pid == exited_pid {
                    break code;
                }
            }
            WaitStatus::Signaled(signaled_pid, sig, _) => {
                tracing::info!("{} received signal {}", signaled_pid, sig);
                if pid == signaled_pid {
                    break -(sig as i32);
                }
            }
            WaitStatus::PtraceEvent(parent_pid, _, ev) => match ev {
                PTRACE_EVENT_VFORK | PTRACE_EVENT_FORK | PTRACE_EVENT_CLONE => {
                    let child_pid = Pid::from_raw(
                        i32::try_from(ptrace::getevent(parent_pid)?)
                            .wrap_err("child pid is too big")?,
                    );

                    tracing::info!(
                        "process {} spawned child with pid {}",
                        parent_pid,
                        child_pid
                    );
                }
                other => {
                    tracing::info!("Unexpected event: {}", other);
                }
            },
            WaitStatus::PtraceSyscall(syscall_pid) => {
                let syscall_start = syscall_start_map.get(&syscall_pid).copied().unwrap_or(true);
                let regs = ptrace::getregs(syscall_pid)?;
                if syscall_start {
                    let syscall = Syscall::from_regs(syscall_pid, regs);
                    tracing::info!("[{}] syscall: {:?}", syscall_pid, syscall);
                } else {
                    tracing::info!("[{}] syscall result: {}", syscall_pid, regs.rax as i64);
                }

                syscall_start_map.insert(syscall_pid, !syscall_start);
            }
            WaitStatus::Stopped(pid, _) => {
                tracing::info!("{} stopped", pid);
                ptrace::syscall(pid, None)?;
            }
            WaitStatus::Continued(pid) => {
                tracing::info!("{} continued", pid);
            }
            WaitStatus::StillAlive => {
                tracing::info!("{} is still alive", pid);
            }
        }

        if let Some(pid) = current_pid {
            tracing::info!("Advancing {} (of {:?})", pid, syscall_start_map.keys());
            match ptrace::syscall(pid, None) {
                Ok(_) | Err(Errno::ESRCH) => {}
                Err(err) => return Err(err.into()),
            }
        }
    };

    tracing::info!("Exit code: {}", exit_code);

    Ok(())
}
