use alloc_counter::{no_alloc, AllocCounterSystem};
use std::ffi::{c_char, c_int, c_void};

pub mod id_map;

/// In test builds, use alloc_counter to verify at runtime that the functions which must be
/// async-signal-safe do not allocate.
#[cfg_attr(debug_assertions, global_allocator)]
static ALLOC: AllocCounterSystem = AllocCounterSystem;

#[derive(Debug)]
pub struct Error {
    errno: c_int,
    why: Option<&'static str>,
}

impl Error {
    /// Create an error from the last OS error.
    fn last_os_error() -> Error {
        Error {
            errno: unsafe { *libc::__errno_location() },
            why: None,
        }
    }

    /// Replace the context of an error.
    fn context(self, msg: &'static str) -> Error {
        Error {
            errno: self.errno,
            why: Some(msg),
        }
    }

    /// Create from a [`std::io::Error`].
    fn from_io_error(e: std::io::Error) -> Error {
        Error {
            errno: e.raw_os_error().unwrap_or(0),
            why: None,
        }
    }
}

// Define a macro, bail!, which returns an error with no errno and a custom message.
macro_rules! bail {
    ($msg:expr) => {
        return Err(Error {
            errno: 0,
            why: Some($msg),
        })
    };
}

// Define a macro, bail_errno!, which returns an error with the last OS error:
//
// - `bail_errno!()` returns an error with the last OS error.
// - `bail_errno!(msg)` returns an error with the last OS error and a context message.
macro_rules! bail_errno {
    () => {
        return Err(Error::last_os_error());
    };
    ($msg:expr) => {
        return Err(Error::last_os_error().context($msg));
    };
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        // Get the error message from errno.
        let error_msg = unsafe { libc::strerror(self.errno) };
        let error_msg_len = unsafe { libc::strlen(error_msg) };
        let error_msg_str: &str = unsafe {
            std::str::from_utf8_unchecked(std::slice::from_raw_parts(
                error_msg as *const u8,
                error_msg_len,
            ))
        };

        if let Some(why) = self.why {
            write!(f, "{}: {} (errno {})", why, error_msg_str, self.errno)
        } else {
            write!(f, "{} (errno {})", error_msg_str, self.errno)
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Command to execute inside the sandbox.
#[derive(Clone, Debug)]
pub struct Command {
    /// Command to execute.
    pub command: *const c_char,

    /// Null-terminated argument list.
    pub args: Vec<*const c_char>,

    /// Null-terminated environment list.
    pub envp: Vec<*const c_char>,

    /// File descriptor to use as stdin. If None, stdin is inherited from the parent.
    pub stdin_fd: Option<c_int>,

    /// File descriptor to use as stdout. If None, stdout is inherited from the parent.
    pub stdout_fd: Option<c_int>,

    /// File descriptor to use as stderr. If None, stderr is inherited from the parent.
    pub stderr_fd: Option<c_int>,

    /// Run the command in a user namespace?
    pub enter_user_namespace: bool,

    /// Contents of the `/proc/PID/uid_map` file.
    pub uid_map: Option<id_map::IdMap>,

    /// Contents of the `/proc/PID/gid_map` file.
    pub gid_map: Option<id_map::IdMap>,

    /// User ID to use for the child process.
    pub uid: Option<u32>,

    /// Group ID to use for the child process.
    pub gid: Option<u32>,
}

/// Handle representing an isolated child process.
pub struct Child {
    pid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitStatus {
    Code(c_int),
    Signal(c_int),
}

impl ExitStatus {
    pub fn from_wait_status(wait_status: c_int) -> Result<ExitStatus> {
        if libc::WIFEXITED(wait_status) {
            return Ok(ExitStatus::Code(libc::WEXITSTATUS(wait_status)));
        }
        if libc::WIFSIGNALED(wait_status) {
            return Ok(ExitStatus::Signal(libc::WTERMSIG(wait_status)));
        }

        bail!("invalid wait status")
    }

    pub fn success(&self) -> bool {
        matches!(self, ExitStatus::Code(0))
    }
}
/// Spawn a child process, returning a [`Child`].
/// For safety, this function __cannot__ return until the child has been executed. This is
/// because the child entrypoints may borrow memory from the parent.
///
/// # Safety
///
/// The pointers in `cmd` must be valid until this function returns.
pub unsafe fn spawn(cmd: Command) -> Result<Child> {
    let pid = libc::getpid();
    eprintln!("spawn: spawning: pid={pid}");

    // Create the child in a new user namespace.
    let mut clone_flags = 0;

    // NOTE: You MUST set `SIGCHLD` in order for `clone()` to work properly.
    clone_flags |= libc::SIGCHLD;

    // If configured, enter a new user namespace here.
    if cmd.enter_user_namespace {
        clone_flags |= libc::CLONE_NEWUSER;
    }

    // Allocate a child stack.
    let mut child_stack = vec![0; 8192];

    // Get the top address of the stack, aligned, as a *mut c_void.
    let child_stack_ptr = get_topmost_stack_pointer(child_stack.as_mut());

    // Create a socket pair, so we can signal the child to continue once we write the uid map,
    // disable setgroups, and write the gid map.
    let mut socket_fds = [0; 2];
    let 0.. = libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, socket_fds.as_mut_ptr()) else {
        bail_errno!("socketpair failed while setting up uid/gidmap sync socket");
    };
    let [idmap_sync_tx_fd, idmap_sync_rx_fd] = socket_fds;

    let outer_child_arg = OuterChildArg {
        cmd: cmd.clone(),
        idmap_sync_rx_fd,
    };

    let child_pid @ 0.. = libc::clone(
        outer_child_extern,
        child_stack_ptr,
        clone_flags,
        &outer_child_arg as *const OuterChildArg as *mut c_void,
    ) else {
        bail_errno!("clone(2) failed");
    };

    eprintln!("spawn: child_pid={child_pid}");

    // Write the UID map.
    if let Some(uid_map) = cmd.uid_map {
        eprintln!("spawn: writing uid_map");
        std::fs::write(
            format!("/proc/{child_pid}/uid_map"),
            uid_map.into_idmap_file_contents(),
        )
        .map_err(Error::from_io_error)
        .map_err(|e| e.context("Failed to write UID map"))?;
    }

    // Disable setgroups and set the GID map.
    if let Some(gid_map) = cmd.gid_map {
        std::fs::write(format!("/proc/{child_pid}/setgroups"), "deny\n")
            .map_err(Error::from_io_error)
            .map_err(|e| e.context("Failed to disable setgroups"))?;
        std::fs::write(
            format!("/proc/{child_pid}/gid_map"),
            gid_map.into_idmap_file_contents(),
        )
        .map_err(Error::from_io_error)
        .map_err(|e| e.context("Failed to write UID map"))?;
    }

    // Send a byte to the child, to signal that we've written the uid/gid maps.
    let mut buf = [0];
    let 1 = libc::write(idmap_sync_tx_fd, buf.as_mut_ptr().cast(), 1) else {
        bail_errno!("failed to write to idmap_sync_tx_fd");
    };
    eprintln!("spawn: sent to idmap_sync_tx_fd");

    Ok(Child {
        pid: child_pid.try_into().expect("pid out of range"),
    })
}

impl Child {
    /// Wait for the child to exit, returning the exit status.
    pub fn wait(&self) -> Result<ExitStatus> {
        let mut status: c_int = 0;
        let 0.. =
            (unsafe { libc::waitpid(self.pid.try_into().unwrap(), &mut status as *mut c_int, 0) })
        else {
            bail_errno!("waitpid failed");
        };

        ExitStatus::from_wait_status(status)
    }
}

struct OuterChildArg {
    cmd: Command,
    idmap_sync_rx_fd: c_int,
}

#[cfg_attr(debug_assertions, no_alloc)]
extern "C" fn outer_child_extern(arg: *mut c_void) -> c_int {
    let arg: &OuterChildArg = unsafe { &*(arg as *mut OuterChildArg) };

    // Catch any panics.
    let result = match std::panic::catch_unwind(|| unsafe {
        outer_child_entrypoint(&arg.cmd, arg.idmap_sync_rx_fd)
    }) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("outer: caught panic: {e:?}");
            return 126;
        }
    };

    // Match the result.
    match result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {}", e);
            42
        }
    }
}

/// Handler for the outer clone.
/// - Runs inside userns.
// #[cfg_attr(debug_assertions, no_alloc)]
unsafe fn outer_child_entrypoint(cmd: &Command, idmap_sync_rx_fd: c_int) -> Result<()> {
    let pid = libc::getpid();
    let uid = libc::getuid();
    let euid = libc::geteuid();
    let gid = libc::getgid();
    let egid = libc::getegid();

    eprintln!("outer: pid={pid}");
    eprintln!("outer: uid={uid} euid={euid}");
    eprintln!("outer: gid={gid} egid={egid}");

    // Receive a byte from the sync socket to wait for uid_map, setgroups, and gid_map to be
    // written.
    let mut buf = [99];
    let 1 = libc::read(idmap_sync_rx_fd, buf.as_mut_ptr().cast(), 1) else {
        bail_errno!("failed to read from idmap_sync_rx_fd");
    };
    assert_eq!(buf[0], 0);

    // Configure stdin, stdout, and stderr.
    if let Some(stdin_fd) = cmd.stdin_fd {
        eprintln!("outer: set stdin_fd={stdin_fd}");
        let 0.. = libc::dup2(stdin_fd, libc::STDIN_FILENO) else {
            bail_errno!("dup2(stdin_fd) failed");
        };
    }
    if let Some(stdout_fd) = cmd.stdout_fd {
        eprintln!("outer: set stdout_fd={stdout_fd}");
        let 0.. = libc::dup2(stdout_fd, libc::STDOUT_FILENO) else {
            bail_errno!("dup2(stdout_fd) failed");
        };
    }
    if let Some(stderr_fd) = cmd.stderr_fd {
        eprintln!("outer: set stderr_fd={stderr_fd}");
        let 0.. = libc::dup2(stderr_fd, libc::STDERR_FILENO) else {
            bail_errno!("dup2(stderr_fd) failed");
        };
    }

    // For now, simply call the inner child entrypoint, without entering additional
    // namespaces. This will exit with the error status of the child process.
    inner_child_entrypoint(cmd)
}

/// Handler for the inner clone, if necessary, or simply called by the outer entrypoint.
/// - Runs inside all namespaces.
#[cfg_attr(debug_assertions, no_alloc)]
unsafe fn inner_child_entrypoint(cmd: &Command) -> Result<()> {
    let pid = libc::getpid();
    let (uid, euid) = (libc::getuid(), libc::geteuid());
    let (gid, egid) = (libc::getgid(), libc::getegid());
    eprintln!("inner: pid={pid}");
    eprintln!("inner: uid={uid} euid={euid} gid={gid} egid={egid}");

    // Set UID and GID
    if let Some(uid) = cmd.uid {
        let 0 = libc::setuid(uid) else {
            bail_errno!("setuid failed");
        };
    }
    if let Some(gid) = cmd.gid {
        let 0 = libc::setgid(gid) else {
            bail_errno!("setgid failed");
        };
    }

    let (uid, euid) = (libc::getuid(), libc::geteuid());
    let (gid, egid) = (libc::getgid(), libc::getegid());
    eprintln!("inner: after setuid/setgid: uid={uid} euid={euid} gid={gid} egid={egid}");

    // For now, simply exec the command.
    let 0 = libc::execve(cmd.command, cmd.args.as_ptr(), cmd.envp.as_ptr()) else {
        bail_errno!("exec_command failed");
    };

    unreachable!("execve(2) returned without error---this should never happen");
}

/// Get the topmost valid stack pointer inside a segment of stack memory.
unsafe fn get_topmost_stack_pointer(stack: &mut [u8]) -> *mut c_void {
    let top_addr = stack.as_mut_ptr().add(stack.len()) as *mut c_void;

    // Align downwards, multiple of 16.
    let top_addr = top_addr as usize & !0xf;

    top_addr as *mut c_void
}

#[allow(unused)]
fn write_str(path: *const c_char, contents: *const c_char, flags: c_int) -> Result<()> {
    let fd @ 0.. = (unsafe { libc::open(path, flags) }) else {
        bail_errno!("failed to open file for writing");
    };

    // TODO: Can we avoid `strlen()` here?
    let len = unsafe { libc::strlen(contents) };

    let mut bytes_written = 0;
    while bytes_written < len {
        let bytes =
            unsafe { libc::write(fd, contents.add(bytes_written).cast(), len - bytes_written) };
        if bytes < 0 {
            bail_errno!("failed to write to file");
        }
        bytes_written += bytes as usize;
    }

    let 0.. = (unsafe { libc::close(fd) }) else {
        bail_errno!("failed to close file after writing");
    };

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::ptr;

    #[test]
    fn false_exits_1() {
        let cmd_path = CString::new("/usr/bin/false").unwrap();
        let null_fd = unsafe { libc::open("/dev/null\0".as_ptr().cast(), libc::O_RDONLY) };

        let cmd = Command {
            enter_user_namespace: false,
            command: cmd_path.as_ptr(),
            args: vec![cmd_path.as_ptr(), ptr::null()],
            envp: vec![ptr::null()],
            stdin_fd: Some(null_fd),
            stdout_fd: Some(null_fd),
            stderr_fd: Some(null_fd),
            uid_map: None,
            gid_map: None,
            uid: None,
            gid: None,
        };

        let child = unsafe { spawn(cmd) }.unwrap();

        // Wait a bit so the logs can sort themselves out
        std::thread::sleep(std::time::Duration::from_millis(100));

        assert_eq!(child.wait().unwrap(), ExitStatus::Code(1));
    }

    #[test]
    fn userns_id_exits_0() {
        let cmd_path = CString::new("/usr/bin/id").unwrap();
        let _null_fd = unsafe { libc::open("/dev/null\0".as_ptr().cast(), libc::O_RDONLY) };

        let mut uid_map = id_map::IdMap::new();
        uid_map.map_one(unsafe { libc::getuid() }, 0);

        let cmd = Command {
            enter_user_namespace: true,
            command: cmd_path.as_ptr(),
            args: vec![cmd_path.as_ptr(), ptr::null()],
            envp: vec![ptr::null()],
            stdin_fd: None,
            stdout_fd: None,
            stderr_fd: None,
            uid_map: Some(uid_map),
            gid_map: None,
            uid: Some(0),
            gid: None,
        };

        let child = unsafe { spawn(cmd) }.unwrap();

        // Wait a bit so the logs can sort themselves out
        std::thread::sleep(std::time::Duration::from_millis(100));

        assert!(child.wait().unwrap().success());
    }
}
