#![allow(unused_unsafe)]

mod syscall;
use syscall::Syscall;

use std::{
    collections::HashMap,
    convert::{TryFrom as _, TryInto as _},
    io,
    os::unix::process::CommandExt as _,
    process::Command,
};

use color_eyre::eyre::{self, bail, WrapErr as _};
use nix::{
    errno::Errno,
    libc::{PTRACE_EVENT_CLONE, PTRACE_EVENT_FORK, PTRACE_EVENT_VFORK},
    sys::{
        ptrace,
        signal::Signal,
        wait::{waitpid, WaitStatus},
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

    ptrace::setoptions(pid, ptrace_options())?;

    tracing::info!("Tracking pid {}", pid);
    let mut syscall_start_map = HashMap::new();
    syscall_start_map.insert(pid, true);
    let exit_code = loop {
        for curr_pid in syscall_start_map.keys() {
            match ptrace::syscall(*curr_pid, None) {
                Ok(_) => {}
                Err(Errno::ESRCH) => {}
                Err(err) => return Err(err.into()),
            }
        }

        match waitpid(None, None)? {
            WaitStatus::Exited(exited_pid, code) => {
                if pid == exited_pid {
                    break code;
                }
            }
            WaitStatus::Signaled(signaled_pid, sig, _) => {
                if pid == signaled_pid {
                    break -(sig as i32);
                }
            }
            WaitStatus::PtraceEvent(_, _, ev) => match ev {
                PTRACE_EVENT_VFORK | PTRACE_EVENT_FORK | PTRACE_EVENT_CLONE => {
                    let child_pid = Pid::from_raw(
                        i32::try_from(ptrace::getevent(pid)?).wrap_err("child pid is too big")?,
                    );
                    if child_pid == pid {
                        tracing::info!("thread spawned");
                    } else {
                        tracing::info!("process spawned with pid {}", child_pid);
                        syscall_start_map.insert(child_pid, true);
                        // ptrace::attach(child_pid)?;
                    }
                }
                other => {
                    tracing::info!("Unexpected event: {}", other);
                }
            },
            WaitStatus::PtraceSyscall(syscall_pid) => {
                let syscall_start = syscall_start_map.get(&syscall_pid).copied().unwrap_or(true);

                let regs = ptrace::getregs(syscall_pid)?;
                if syscall_start {
                    tracing::info!(
                        "[{}] Syscall: {:?}",
                        syscall_pid,
                        Syscall::from_regs(syscall_pid, regs)
                    );
                }

                syscall_start_map.insert(syscall_pid, !syscall_start);
            }
            WaitStatus::Stopped(_, _) => {}
            WaitStatus::Continued(_) => {}
            WaitStatus::StillAlive => {}
        }
    };

    tracing::info!("Exit code: {}", exit_code);

    Ok(())
}
