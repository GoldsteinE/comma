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

    let mut cmd = Command::new("/home/goldstein/pets/comma/threads");
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
    let mut must_poll: Option<Pid> = None;
    syscall_start_map.insert(pid, true);
    let exit_code = loop {
        if let Some(must_poll_pid) = must_poll {
            tracing::info!("Advancing only {} because of must_poll", must_poll_pid);
            match ptrace::syscall(must_poll_pid, None) {
                Ok(_) => {}
                Err(Errno::ESRCH) => {}
                Err(err) => return Err(err.into()),
            }
        } else {
            for curr_pid in syscall_start_map.keys() {
                tracing::info!("Advancing {} (of {:?})", curr_pid, syscall_start_map);
                match ptrace::syscall(*curr_pid, None) {
                    Ok(_) => {}
                    Err(Errno::ESRCH) => {}
                    Err(err) => return Err(err.into()),
                }
            }
        }

        let wait = must_poll.take();
        match waitpid(wait, Some(WaitPidFlag::__WALL))? {
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
            WaitStatus::PtraceEvent(parent_pid, _, ev) => match ev {
                PTRACE_EVENT_VFORK | PTRACE_EVENT_FORK | PTRACE_EVENT_CLONE => {
                    let child_pid = Pid::from_raw(
                        i32::try_from(ptrace::getevent(pid)?).wrap_err("child pid is too big")?,
                    );
                    tracing::info!(
                        "process {} spawned child with pid {}",
                        parent_pid,
                        child_pid
                    );
                    syscall_start_map.insert(child_pid, true);
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

                    if syscall.spawns_new_thread() {
                        must_poll = Some(syscall_pid);
                    }
                } else {
                    tracing::info!("[{}] syscall result: {}", syscall_pid, regs.rax);
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
