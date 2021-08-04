#![allow(unused_unsafe)]

mod syscall;
use syscall::Syscall;

use std::{convert::{TryInto as _, TryFrom as _},io, os::unix::process::CommandExt as _, process::Command};

use color_eyre::eyre::{self, bail, WrapErr as _};
use nix::{libc::{PTRACE_EVENT_CLONE, PTRACE_EVENT_FORK, PTRACE_EVENT_VFORK}, sys::{ptrace, signal::Signal, wait::{WaitPidFlag, WaitStatus, waitpid}}, unistd::Pid};

fn main() -> eyre::Result<()> {
    color_eyre::install()?;
    tracing_subscriber::fmt::init();

    let mut cmd = Command::new("/home/goldstein/pets/comma/simple");
    unsafe {
        cmd.pre_exec(|| ptrace::traceme().map_err(|err| io::Error::from_raw_os_error(err as i32)));
    }
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

    ptrace::setoptions(pid, {
        use ptrace::Options;

        Options::PTRACE_O_TRACEFORK
            | Options::PTRACE_O_TRACEVFORK
            | Options::PTRACE_O_TRACECLONE
            | Options::PTRACE_O_TRACESYSGOOD
    })?;

    let mut syscall_start = true;
    let exit_code = loop {
        ptrace::syscall(pid, None)?;
        match waitpid(pid, Some(WaitPidFlag::WNOHANG))? {
            WaitStatus::Exited(_, code) => break code,
            WaitStatus::Signaled(_, sig, _) => break -(sig as i32),
            WaitStatus::PtraceEvent(_, _, ev) => match ev {
                PTRACE_EVENT_VFORK | PTRACE_EVENT_FORK | PTRACE_EVENT_CLONE => {
                    let child_pid = Pid::from_raw(
                        i32::try_from(ptrace::getevent(pid)?).wrap_err("child pid is too big")?,
                    );
                    if child_pid == pid {
                        tracing::info!("thread spawned");
                    } else {
                        tracing::info!("process spawned with pid {}", pid);
                    }
                }
                other => {
                    tracing::info!("Unexpected event: {}", other);
                }
            },
            WaitStatus::PtraceSyscall(_) => {
                let regs = ptrace::getregs(pid)?;
                if syscall_start {
                    tracing::info!("Syscall: {:?}", Syscall::from_regs(pid, regs));
                }
                syscall_start ^= true;
            }
            WaitStatus::Stopped(_, _) => {}
            WaitStatus::Continued(_) => {}
            WaitStatus::StillAlive => {}
        }
    };

    tracing::info!("Exit code: {}", exit_code);

    Ok(())
}
