use std::{
    convert::TryFrom as _,
    ffi::{c_void, OsString},
    fs,
    os::unix::ffi::OsStringExt as _,
    path::PathBuf,
};

use color_eyre::eyre::{Result, WrapErr as _};
use nix::{errno::Errno, libc::{FD_SETSIZE, c_int, c_long, c_uint, c_ulong, pid_t, user_regs_struct}, sys::{ptrace, select::FdSet}, unistd::Pid};

#[allow(non_camel_case_types)]
pub type c_umode_t = u16;

// Assumed in the rest of the file
const _ASSERT_C_LONG_IS_I64: [(); std::mem::size_of::<c_long>()] = [(); std::mem::size_of::<u64>()];
const _ASSERT_USIZE_IS_U64: [(); std::mem::size_of::<usize>()] = [(); std::mem::size_of::<u64>()];
// DEBUG
const _ASSERT_FD_SET_CONSISTS_OF_LONGS: [(); std::mem::size_of::<FdSet>()] =
    [(); FD_SETSIZE / std::mem::size_of::<c_long>()];

#[derive(Debug, Clone, Copy)]
pub struct OpenHow {
    pub flags: u64,
    pub mode: u64,
    pub resolve: u64,
}

impl OpenHow {
    fn read_from_process(pid: Pid, addr: u64) -> Result<Self, Errno> {
        let addr = addr as usize;

        let flags = ptrace::read(pid, addr as *mut c_void)? as u64;
        let mode = ptrace::read(pid, (addr + 8) as *mut c_void)? as u64;
        let resolve = ptrace::read(pid, (addr + 16) as *mut c_void)? as u64;

        Ok(Self {
            flags,
            mode,
            resolve,
        })
    }
}

fn read_string_from_process(pid: Pid, addr: u64) -> Result<Vec<u8>, Errno> {
    let mut result = Vec::new();
    let mut addr = addr as usize;
    loop {
        let data: c_long = ptrace::read(pid, addr as *mut c_void)?;
        let bytes = data.to_ne_bytes();
        for byte in bytes {
            if byte == 0 {
                return Ok(result);
            }

            result.push(byte)
        }

        addr += 8;
    }
}

#[derive(Clone)]
#[repr(transparent)]
pub struct DebuggableFdSet(FdSet);

impl std::fmt::Debug for DebuggableFdSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_list();
        for fd in self.0.clone().fds(None) {
            d.entry(&fd);
        }
        d.finish()
    }
}

// DEBUG
pub fn read_fd_set_from_process(pid: Pid, addr: u64) -> Result<Option<DebuggableFdSet>, Errno> {
    if addr == 0 {
        return Ok(None);
    }

    let mut addr = addr as *const c_long;
    let n: c_long = ptrace::read(pid, addr as _)?;
    let mut buf = [c_long::default(); 1024 / 8 / core::mem::size_of::<c_long>()];
    for i in 0..buf.len() {
        let b = ptrace::read(pid, addr as _)? as u64;
        buf[i] = b as i64;
        addr = unsafe { addr.offset(1) };
    }
    unsafe { Ok(Some(std::mem::transmute(buf))) }
}

fn pathbuf_from_reg(pid: Pid, ptr: u64) -> Result<PathBuf> {
    read_string_from_process(pid, ptr)
        .map(OsString::from_vec)
        .map(PathBuf::from)
        .wrap_err("failed to read filename from process")
}

fn pathbuf_from_fd(pid: Pid, fd: u64) -> Result<PathBuf> {
    let fd = fd as i32;

    // TODO: more efficient method?
    let mut pid_path = PathBuf::new();
    pid_path.push("/proc");
    pid_path.push(pid.to_string());

    if fd == nix::libc::AT_FDCWD {
        pid_path.push("cwd")
    } else {
        pid_path.push("fd");
        pid_path.push(fd.to_string());
    }

    // TODO: allocation
    fs::read_link(pid_path).wrap_err_with(|| format!("failed to resolve fd {}", fd))
}

fn maybe_cwd(pid: Pid, return_cwd: bool) -> Result<Option<PathBuf>> {
    if return_cwd {
        let mut cwd_path = PathBuf::new();
        cwd_path.push("/proc");
        cwd_path.push(pid.to_string());
        cwd_path.push("cwd");
        fs::read_link(cwd_path)
            .wrap_err("failed to resolve cwd")
            .map(Some)
    } else {
        Ok(None)
    }
}

#[derive(Debug, Clone)]
pub enum Syscall {
    Open {
        dir: Option<PathBuf>,
        filename: PathBuf,
        flags: c_int,
        mode: c_umode_t,
    },
    OpenAt {
        dir: PathBuf,
        filename: PathBuf,
        flags: c_int,
        mode: c_umode_t,
    },
    OpenAt2 {
        dir: PathBuf,
        filename: PathBuf,
        how: OpenHow,
        size: isize,
    },
    Truncate {
        dir: Option<PathBuf>,
        filename: PathBuf,
        length: c_long,
    },
    Ftruncate {
        filename: PathBuf,
        length: c_long,
    },
    Rename {
        dir: Option<PathBuf>,
        old: PathBuf,
        new: PathBuf,
    },
    RenameAt {
        old_dir: PathBuf,
        old: PathBuf,
        new_dir: PathBuf,
        new: PathBuf,
    },
    RenameAt2 {
        old_dir: PathBuf,
        old: PathBuf,
        new_dir: PathBuf,
        new: PathBuf,
        flags: c_uint,
    },
    Mkdir {
        parent: Option<PathBuf>,
        path: PathBuf,
        mode: c_umode_t,
    },
    MkdirAt {
        parent: PathBuf,
        path: PathBuf,
        mode: c_umode_t,
    },
    Rmdir {
        parent: Option<PathBuf>,
        path: PathBuf,
    },
    Creat {
        dir: Option<PathBuf>,
        path: PathBuf,
        mode: c_umode_t,
    },
    Link {
        dir: Option<PathBuf>,
        old: PathBuf,
        new: PathBuf,
    },
    LinkAt {
        old_dir: PathBuf,
        old: PathBuf,
        new_dir: PathBuf,
        new: PathBuf,
        flags: c_int,
    },
    Unlink {
        dir: Option<PathBuf>,
        path: PathBuf,
    },
    UnlinkAt {
        dir: PathBuf,
        path: PathBuf,
        flag: c_int,
    },
    Symlink {
        cwd: Option<PathBuf>,
        old: PathBuf,
        new: PathBuf,
    },
    SymlinkAt {
        cwd: Option<PathBuf>,
        old: PathBuf,
        new_dir: PathBuf,
        new: PathBuf,
    },
    Mknod {
        dir: Option<PathBuf>,
        path: PathBuf,
        mode: c_umode_t,
        dev: c_uint,
    },
    MknodAt {
        dir: PathBuf,
        path: PathBuf,
        mode: c_umode_t,
        dev: c_uint,
    },
    Other(SyscallNr),
    Unknown(u64),
    // DEBUG
    Wait4 {
        pid: pid_t,
        wstatus: usize,
        options: c_int,
        rusage: usize,
    },
    Select {
        nfds: c_int,
        readfds: Option<DebuggableFdSet>,
        writefds: Option<DebuggableFdSet>,
        exceptfds: Option<DebuggableFdSet>,
        timeout: usize,
    },
    Clone {
        clone_flags: c_ulong,
        newsp: c_ulong,
        parent_tidptr: usize,
        child_tidptr: usize,
        tls_val: c_int,
    },
    Read {
        fd: c_uint,
        buf: usize,
        count: usize,
    },
}

impl Syscall {
    pub fn from_regs(pid: Pid, regs: user_regs_struct) -> Self {
        match Self::try_from_regs(pid, regs) {
            Ok(this) => this,
            Err(err) => {
                tracing::warn!("failed to parse syscall args: {}", err);
                // TODO: unneeded match
                match SyscallNr::try_from(regs.orig_rax) {
                    Ok(nr) => Syscall::Other(nr),
                    Err(_) => Syscall::Unknown(regs.orig_rax),
                }
            }
        }
    }

    pub fn try_from_regs(pid: Pid, regs: user_regs_struct) -> Result<Self> {
        Ok(match SyscallNr::try_from(regs.orig_rax) {
            Ok(SyscallNr::open) => {
                let filename = pathbuf_from_reg(pid, regs.rdi)?;
                Self::Open {
                    dir: maybe_cwd(pid, filename.is_relative())?,
                    filename,
                    flags: regs.rsi as c_int,
                    mode: regs.rdx as c_umode_t,
                }
            }
            Ok(SyscallNr::openat) => Self::OpenAt {
                dir: pathbuf_from_fd(pid, regs.rdi)?,
                filename: pathbuf_from_reg(pid, regs.rsi)?,
                flags: regs.rdx as c_int,
                mode: regs.r10 as c_umode_t,
            },
            Ok(SyscallNr::openat2) => Self::OpenAt2 {
                dir: pathbuf_from_fd(pid, regs.rdi)?,
                filename: pathbuf_from_reg(pid, regs.rsi)?,
                how: OpenHow::read_from_process(pid, regs.rdx)?,
                size: regs.r10 as isize,
            },
            Ok(SyscallNr::truncate) => {
                let filename = pathbuf_from_reg(pid, regs.rdi)?;
                Self::Truncate {
                    dir: maybe_cwd(pid, filename.is_relative())?,
                    filename,
                    length: regs.rsi as c_long,
                }
            }
            Ok(SyscallNr::ftruncate) => Self::Ftruncate {
                filename: pathbuf_from_fd(pid, regs.rdi)?,
                length: regs.rsi as c_long,
            },
            Ok(SyscallNr::rename) => {
                let old = pathbuf_from_reg(pid, regs.rdi)?;
                let new = pathbuf_from_reg(pid, regs.rsi)?;
                let dir = maybe_cwd(pid, old.is_relative() || new.is_relative())?;
                Self::Rename { old, new, dir }
            }
            Ok(SyscallNr::renameat) => Self::RenameAt {
                old_dir: pathbuf_from_fd(pid, regs.rdi)?,
                old: pathbuf_from_reg(pid, regs.rsi)?,
                new_dir: pathbuf_from_fd(pid, regs.rdx)?,
                new: pathbuf_from_reg(pid, regs.r10)?,
            },
            Ok(SyscallNr::renameat2) => Self::RenameAt2 {
                old_dir: pathbuf_from_fd(pid, regs.rdi)?,
                old: pathbuf_from_reg(pid, regs.rsi)?,
                new_dir: pathbuf_from_fd(pid, regs.rdx)?,
                new: pathbuf_from_reg(pid, regs.r10)?,
                flags: regs.r8 as c_uint,
            },
            Ok(SyscallNr::mkdir) => {
                let path = pathbuf_from_reg(pid, regs.rdi)?;
                Self::Mkdir {
                    parent: maybe_cwd(pid, path.is_relative())?,
                    path,
                    mode: regs.rsi as c_umode_t,
                }
            }
            Ok(SyscallNr::mkdirat) => Self::MkdirAt {
                parent: pathbuf_from_fd(pid, regs.rdi)?,
                path: pathbuf_from_reg(pid, regs.rsi)?,
                mode: regs.rdx as c_umode_t,
            },
            Ok(SyscallNr::rmdir) => {
                let path = pathbuf_from_reg(pid, regs.rdi)?;
                Self::Rmdir {
                    parent: maybe_cwd(pid, path.is_relative())?,
                    path,
                }
            }
            Ok(SyscallNr::creat) => {
                let path = pathbuf_from_reg(pid, regs.rdi)?;
                Self::Creat {
                    dir: maybe_cwd(pid, path.is_relative())?,
                    path,
                    mode: regs.rsi as c_umode_t,
                }
            }
            Ok(SyscallNr::link) => {
                let old = pathbuf_from_reg(pid, regs.rdi)?;
                let new = pathbuf_from_reg(pid, regs.rsi)?;
                let dir = maybe_cwd(pid, old.is_relative() || new.is_relative())?;
                Self::Link { old, new, dir }
            }
            Ok(SyscallNr::linkat) => Self::LinkAt {
                old_dir: pathbuf_from_fd(pid, regs.rdi)?,
                old: pathbuf_from_reg(pid, regs.rsi)?,
                new_dir: pathbuf_from_fd(pid, regs.rdx)?,
                new: pathbuf_from_reg(pid, regs.r10)?,
                flags: regs.r8 as c_int,
            },
            Ok(SyscallNr::unlink) => {
                let path = pathbuf_from_reg(pid, regs.rdi)?;
                Self::Unlink {
                    dir: maybe_cwd(pid, path.is_relative())?,
                    path,
                }
            }
            Ok(SyscallNr::unlinkat) => Self::UnlinkAt {
                dir: pathbuf_from_fd(pid, regs.rdi)?,
                path: pathbuf_from_reg(pid, regs.rsi)?,
                flag: regs.rdx as c_int,
            },
            Ok(SyscallNr::symlink) => {
                let old = pathbuf_from_reg(pid, regs.rdi)?;
                let new = pathbuf_from_reg(pid, regs.rsi)?;
                let dir = maybe_cwd(pid, old.is_relative() || new.is_relative())?;
                Self::Symlink { old, new, cwd: dir }
            }
            Ok(SyscallNr::symlinkat) => {
                let old = pathbuf_from_reg(pid, regs.rdi)?;
                Self::SymlinkAt {
                    cwd: maybe_cwd(pid, old.is_relative())?,
                    old,
                    new_dir: pathbuf_from_fd(pid, regs.rsi)?,
                    new: pathbuf_from_reg(pid, regs.rdx)?,
                }
            }
            Ok(SyscallNr::mknod) => {
                let path = pathbuf_from_reg(pid, regs.rdi)?;
                let dir = maybe_cwd(pid, path.is_relative())?;
                Self::Mknod {
                    dir,
                    path,
                    mode: regs.rsi as c_umode_t,
                    dev: regs.rdx as c_uint,
                }
            }
            Ok(SyscallNr::mknodat) => Self::MknodAt {
                dir: pathbuf_from_fd(pid, regs.rdi)?,
                path: pathbuf_from_reg(pid, regs.rsi)?,
                mode: regs.rdx as c_umode_t,
                dev: regs.r10 as c_uint,
            },

            // DEBUG
            Ok(SyscallNr::wait4) => Self::Wait4 {
                pid: regs.rdi as pid_t,
                wstatus: regs.rsi as usize,
                options: regs.rdx as c_int,
                rusage: regs.r10 as usize,
            },
            Ok(SyscallNr::select) => Self::Select {
                nfds: regs.rdi as c_int,
                readfds: read_fd_set_from_process(pid, regs.rsi)?,
                writefds: read_fd_set_from_process(pid, regs.rdx)?,
                exceptfds: read_fd_set_from_process(pid, regs.r10)?,
                timeout: regs.r8 as usize,
            },
            Ok(SyscallNr::clone) => Self::Clone {
                clone_flags: regs.rdi as c_ulong,
                newsp: regs.rsi as c_ulong,
                parent_tidptr: regs.rdx as usize,
                child_tidptr: regs.r10 as usize,
                tls_val: regs.r8 as c_int,
            },
            Ok(SyscallNr::read) => Self::Read {
                fd: regs.rdi as c_uint,
                buf: regs.rsi as usize,
                count: regs.rdx as usize,
            },

            Ok(nr) => Self::Other(nr),
            Err(_) => Self::Unknown(regs.orig_rax),
        })
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, num_enum::IntoPrimitive, num_enum::TryFromPrimitive)]
#[repr(u64)]
pub enum SyscallNr {
    read = 0,
    write = 1,
    open = 2,
    close = 3,
    stat = 4,
    fstat = 5,
    lstat = 6,
    poll = 7,
    lseek = 8,
    mmap = 9,
    mprotect = 10,
    munmap = 11,
    brk = 12,
    rt_sigaction = 13,
    rt_sigprocmask = 14,
    rt_sigreturn = 15,
    ioctl = 16,
    pread64 = 17,
    pwrite64 = 18,
    readv = 19,
    writev = 20,
    access = 21,
    pipe = 22,
    select = 23,
    sched_yield = 24,
    mremap = 25,
    msync = 26,
    mincore = 27,
    madvise = 28,
    shmget = 29,
    shmat = 30,
    shmctl = 31,
    dup = 32,
    dup2 = 33,
    pause = 34,
    nanosleep = 35,
    getitimer = 36,
    alarm = 37,
    setitimer = 38,
    getpid = 39,
    sendfile = 40,
    socket = 41,
    connect = 42,
    accept = 43,
    sendto = 44,
    recvfrom = 45,
    sendmsg = 46,
    recvmsg = 47,
    shutdown = 48,
    bind = 49,
    listen = 50,
    getsockname = 51,
    getpeername = 52,
    socketpair = 53,
    setsockopt = 54,
    getsockopt = 55,
    clone = 56,
    fork = 57,
    vfork = 58,
    execve = 59,
    exit = 60,
    wait4 = 61,
    kill = 62,
    uname = 63,
    semget = 64,
    semop = 65,
    semctl = 66,
    shmdt = 67,
    msgget = 68,
    msgsnd = 69,
    msgrcv = 70,
    msgctl = 71,
    fcntl = 72,
    flock = 73,
    fsync = 74,
    fdatasync = 75,
    truncate = 76,
    ftruncate = 77,
    getdents = 78,
    getcwd = 79,
    chdir = 80,
    fchdir = 81,
    rename = 82,
    mkdir = 83,
    rmdir = 84,
    creat = 85,
    link = 86,
    unlink = 87,
    symlink = 88,
    readlink = 89,
    chmod = 90,
    fchmod = 91,
    chown = 92,
    fchown = 93,
    lchown = 94,
    umask = 95,
    gettimeofday = 96,
    getrlimit = 97,
    getrusage = 98,
    sysinfo = 99,
    times = 100,
    ptrace = 101,
    getuid = 102,
    syslog = 103,
    getgid = 104,
    setuid = 105,
    setgid = 106,
    geteuid = 107,
    getegid = 108,
    setpgid = 109,
    getppid = 110,
    getpgrp = 111,
    setsid = 112,
    setreuid = 113,
    setregid = 114,
    getgroups = 115,
    setgroups = 116,
    setresuid = 117,
    getresuid = 118,
    setresgid = 119,
    getresgid = 120,
    getpgid = 121,
    setfsuid = 122,
    setfsgid = 123,
    getsid = 124,
    capget = 125,
    capset = 126,
    rt_sigpending = 127,
    rt_sigtimedwait = 128,
    rt_sigqueueinfo = 129,
    rt_sigsuspend = 130,
    sigaltstack = 131,
    utime = 132,
    mknod = 133,
    uselib = 134,
    personality = 135,
    ustat = 136,
    statfs = 137,
    fstatfs = 138,
    sysfs = 139,
    getpriority = 140,
    setpriority = 141,
    sched_setparam = 142,
    sched_getparam = 143,
    sched_setscheduler = 144,
    sched_getscheduler = 145,
    sched_get_priority_max = 146,
    sched_get_priority_min = 147,
    sched_rr_get_interval = 148,
    mlock = 149,
    munlock = 150,
    mlockall = 151,
    munlockall = 152,
    vhangup = 153,
    modify_ldt = 154,
    pivot_root = 155,
    _sysctl = 156,
    prctl = 157,
    arch_prctl = 158,
    adjtimex = 159,
    setrlimit = 160,
    chroot = 161,
    sync = 162,
    acct = 163,
    settimeofday = 164,
    mount = 165,
    umount2 = 166,
    swapon = 167,
    swapoff = 168,
    reboot = 169,
    sethostname = 170,
    setdomainname = 171,
    iopl = 172,
    ioperm = 173,
    create_module = 174,
    init_module = 175,
    delete_module = 176,
    get_kernel_syms = 177,
    query_module = 178,
    quotactl = 179,
    nfsservctl = 180,
    getpmsg = 181,
    putpmsg = 182,
    afs_syscall = 183,
    tuxcall = 184,
    security = 185,
    gettid = 186,
    readahead = 187,
    setxattr = 188,
    lsetxattr = 189,
    fsetxattr = 190,
    getxattr = 191,
    lgetxattr = 192,
    fgetxattr = 193,
    listxattr = 194,
    llistxattr = 195,
    flistxattr = 196,
    removexattr = 197,
    lremovexattr = 198,
    fremovexattr = 199,
    tkill = 200,
    time = 201,
    futex = 202,
    sched_setaffinity = 203,
    sched_getaffinity = 204,
    set_thread_area = 205,
    io_setup = 206,
    io_destroy = 207,
    io_getevents = 208,
    io_submit = 209,
    io_cancel = 210,
    get_thread_area = 211,
    lookup_dcookie = 212,
    epoll_create = 213,
    epoll_ctl_old = 214,
    epoll_wait_old = 215,
    remap_file_pages = 216,
    getdents64 = 217,
    set_tid_address = 218,
    restart_syscall = 219,
    semtimedop = 220,
    fadvise64 = 221,
    timer_create = 222,
    timer_settime = 223,
    timer_gettime = 224,
    timer_getoverrun = 225,
    timer_delete = 226,
    clock_settime = 227,
    clock_gettime = 228,
    clock_getres = 229,
    clock_nanosleep = 230,
    exit_group = 231,
    epoll_wait = 232,
    epoll_ctl = 233,
    tgkill = 234,
    utimes = 235,
    vserver = 236,
    mbind = 237,
    set_mempolicy = 238,
    get_mempolicy = 239,
    mq_open = 240,
    mq_unlink = 241,
    mq_timedsend = 242,
    mq_timedreceive = 243,
    mq_notify = 244,
    mq_getsetattr = 245,
    kexec_load = 246,
    waitid = 247,
    add_key = 248,
    request_key = 249,
    keyctl = 250,
    ioprio_set = 251,
    ioprio_get = 252,
    inotify_init = 253,
    inotify_add_watch = 254,
    inotify_rm_watch = 255,
    migrate_pages = 256,
    openat = 257,
    mkdirat = 258,
    mknodat = 259,
    fchownat = 260,
    futimesat = 261,
    newfstatat = 262,
    unlinkat = 263,
    renameat = 264,
    linkat = 265,
    symlinkat = 266,
    readlinkat = 267,
    fchmodat = 268,
    faccessat = 269,
    pselect6 = 270,
    ppoll = 271,
    unshare = 272,
    set_robust_list = 273,
    get_robust_list = 274,
    splice = 275,
    tee = 276,
    sync_file_range = 277,
    vmsplice = 278,
    move_pages = 279,
    utimensat = 280,
    epoll_pwait = 281,
    signalfd = 282,
    timerfd_create = 283,
    eventfd = 284,
    fallocate = 285,
    timerfd_settime = 286,
    timerfd_gettime = 287,
    accept4 = 288,
    signalfd4 = 289,
    eventfd2 = 290,
    epoll_create1 = 291,
    dup3 = 292,
    pipe2 = 293,
    inotify_init1 = 294,
    preadv = 295,
    pwritev = 296,
    rt_tgsigqueueinfo = 297,
    perf_event_open = 298,
    recvmmsg = 299,
    fanotify_init = 300,
    fanotify_mark = 301,
    prlimit64 = 302,
    name_to_handle_at = 303,
    open_by_handle_at = 304,
    clock_adjtime = 305,
    syncfs = 306,
    sendmmsg = 307,
    setns = 308,
    getcpu = 309,
    process_vm_readv = 310,
    process_vm_writev = 311,
    kcmp = 312,
    finit_module = 313,
    sched_setattr = 314,
    sched_getattr = 315,
    renameat2 = 316,
    seccomp = 317,
    getrandom = 318,
    memfd_create = 319,
    kexec_file_load = 320,
    bpf = 321,
    execveat = 322,
    userfaultfd = 323,
    membarrier = 324,
    mlock2 = 325,
    copy_file_range = 326,
    preadv2 = 327,
    pwritev2 = 328,
    pkey_mprotect = 329,
    pkey_alloc = 330,
    pkey_free = 331,
    statx = 332,
    io_pgetevents = 333,
    rseq = 334,
    pidfd_send_signal = 424,
    io_uring_setup = 425,
    io_uring_enter = 426,
    io_uring_register = 427,
    open_tree = 428,
    move_mount = 429,
    fsopen = 430,
    fsconfig = 431,
    fsmount = 432,
    fspick = 433,
    pidfd_open = 434,
    clone3 = 435,
    close_range = 436,
    openat2 = 437,
    pidfd_getfd = 438,
    faccessat2 = 439,
    process_madvise = 440,
    epoll_pwait2 = 441,
    mount_setattr = 442,
}
