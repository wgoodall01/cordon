use alloc_counter::{no_alloc, AllocCounterSystem};
use std::ffi::{c_char, c_int, c_void};
use std::mem;
use std::ptr;

pub mod id_map;
pub mod mount_table;

/// In test builds, use alloc_counter to verify at runtime that the functions which must be
/// async-signal-safe do not allocate.
#[cfg_attr(debug_assertions, global_allocator)]
static ALLOC: AllocCounterSystem = AllocCounterSystem;

/// Size of the stack for cloned children.
const STACK_SIZE: usize = 8 * 1024 * 1024; // 8 MB

#[derive(Debug)]
pub struct Error {
    errno: c_int,
    cause: Option<&'static str>,
    context: Option<&'static str>,
}

impl Error {
    /// Create an empty error.
    fn new() -> Error {
        Error {
            errno: 0,
            cause: None,
            context: None,
        }
    }

    /// Create an error from the last OS error.
    fn last_os_error() -> Error {
        Error {
            errno: unsafe { *libc::__errno_location() },
            cause: None,
            context: None,
        }
    }

    /// Replace the cause of an error.
    fn cause(self, msg: &'static str) -> Error {
        Error {
            errno: self.errno,
            cause: Some(msg),
            context: self.context,
        }
    }

    /// Replace the context of an error.
    fn context(self, msg: &'static str) -> Error {
        Error {
            errno: self.errno,
            cause: self.cause,
            context: Some(msg),
        }
    }

    /// Create from a [`std::io::Error`].
    fn from_io_error(e: std::io::Error) -> Error {
        Error {
            errno: e.raw_os_error().unwrap_or(0),
            cause: None,
            context: None,
        }
    }
}

// Define a macro, bail!, which returns an error with no errno and a custom message.
macro_rules! bail {
    ($msg:expr) => {
        return Err(Error {
            errno: 0,
            cause: Some($msg),
            context: None,
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
        return Err(Error::last_os_error().cause($msg));
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

        match (self.context, self.cause) {
            (Some(context), None) => {
                write!(f, "{}: {} (errno {})", context, error_msg_str, self.errno)
            }
            (None, Some(cause)) => write!(f, "{}: {} (errno {})", cause, error_msg_str, self.errno),
            (Some(context), Some(cause)) => write!(
                f,
                "{}: {}: {} (errno {})",
                context, cause, error_msg_str, self.errno
            ),
            (None, None) => write!(f, "{} (errno {})", error_msg_str, self.errno),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Command to execute inside the sandbox.
#[derive(Debug)]
pub struct Command {
    /// Command to execute.
    pub command: *const c_char,

    /// Null-element-terminated argument list.
    pub args: Vec<*const c_char>,

    /// Null-element-terminated environment list.
    pub envp: Vec<*const c_char>,

    /// File descriptor to use as stdin. If None, stdin is inherited from the parent.
    pub stdin_fd: Option<c_int>,

    /// File descriptor to use as stdout. If None, stdout is inherited from the parent.
    pub stdout_fd: Option<c_int>,

    /// File descriptor to use as stderr. If None, stderr is inherited from the parent.
    pub stderr_fd: Option<c_int>,

    /// The set of namespaces which should be created and entered by the child process.
    pub namespaces: NamespaceSet,

    /// Contents of the `/proc/PID/uid_map` file.
    pub uid_map: Option<id_map::IdMap>,

    /// Contents of the `/proc/PID/gid_map` file.
    pub gid_map: Option<id_map::IdMap>,

    /// Set a custom user ID for the child process.
    pub set_uid: Option<u32>,

    /// Set a custom group ID for the child process.
    pub set_gid: Option<u32>,

    /// If set, pivot root to this directory before executing the command.
    pub pivot_root_to: Option<*const c_char>,

    /// If set, change directory to this path (relative to the child's root) before
    /// execiting the command.
    pub set_working_dir: Option<*const c_char>,

    /// Mount these filesystems in the container after any mount namespace has been set up.
    pub mounts: mount_table::MountTable,
}

/// Bitset of namespaces to enter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NamespaceSet {
    pub cgroup: bool,
    pub ipc: bool,
    pub network: bool,
    pub mount: bool,
    pub pid: bool,
    // pub time: bool, // This isn't important to support.
    pub user: bool,
    pub uts: bool,
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

    // Create the IdMap sync socket.
    // We send one byte from the parent to the child once the uid_map and gid_map have been
    // written. The child waits for this byte before doing any operation which requires users and
    // groups to be mapped (e.g. setuid, setgid).
    let (idmap_sync_tx_fd, idmap_sync_rx_fd) = socket_pair()
        .map_err(|e| e.context("Failed to create socketpair for uid/gidmap sync socket"))?;

    // Create the pid return socket.
    // We send the pid of the innermost child process to the parent once it has been spawned. The
    // parent will then wait directly on the innermost child's PID, while any outer children
    // exit.
    let (pid_return_tx_fd, pid_return_rx_fd) = socket_pair()
        .map_err(|e| e.context("Failed to create socketpair for pid return socket"))?;

    // Create the child in a new user namespace.
    let mut clone_flags = 0;

    // NOTE: You MUST set `SIGCHLD` in order for `waitpid()` after `clone()` to work properly.
    clone_flags |= libc::SIGCHLD;

    // If configured, enter a new user namespace here.
    if cmd.namespaces.user {
        clone_flags |= libc::CLONE_NEWUSER;
    }

    // Allocate the stack for the inner child, so we can pass it through the outer child.
    let inner_child_stack = vec![0; STACK_SIZE];

    // Allocate the stack for the outer child, and get its topmost address.
    let mut outer_child_stack = vec![0; STACK_SIZE];
    let outer_child_stack_ptr = get_topmost_stack_pointer(outer_child_stack.as_mut());

    // Construct the argument to the child entrypoint.
    let mut outer_child_arg = OuterChildArg {
        cmd: &cmd,
        idmap_sync_rx_fd,
        pid_return_tx_fd,
        inner_child_stack,
    };

    let outer_child_pid @ 0.. = libc::clone(
        outer_child_extern,
        outer_child_stack_ptr,
        clone_flags,
        &mut outer_child_arg as *const OuterChildArg as *mut c_void,
    ) else {
        bail_errno!("clone(2) failed");
    };

    eprintln!("spawn: outer_child_pid={outer_child_pid}");

    // Write the UID map.
    if let Some(uid_map) = cmd.uid_map {
        eprintln!("spawn: writing uid_map");
        std::fs::write(
            format!("/proc/{outer_child_pid}/uid_map"),
            uid_map.into_idmap_file_contents(),
        )
        .map_err(Error::from_io_error)
        .map_err(|e| e.context("Failed to write UID map"))?;
    }

    // Disable setgroups and set the GID map.
    if let Some(gid_map) = cmd.gid_map {
        std::fs::write(format!("/proc/{outer_child_pid}/setgroups"), "deny\n")
            .map_err(Error::from_io_error)
            .map_err(|e| e.context("Failed to disable setgroups"))?;
        std::fs::write(
            format!("/proc/{outer_child_pid}/gid_map"),
            gid_map.into_idmap_file_contents(),
        )
        .map_err(Error::from_io_error)
        .map_err(|e| e.context("Failed to write UID map"))?;
    }

    // Send a byte to the child, to signal that we've written the uid/gid maps.
    socket_send::<u8>(idmap_sync_tx_fd, 0)
        .map_err(|e| e.context("Failed to send to uid/gidmap sync socket"))?;
    eprintln!("spawn: sent to idmap_sync_tx_fd");

    // Wait for the outer child to send us the PID of the inner child.
    let inner_child_pid: c_int = socket_recv::<c_int>(pid_return_rx_fd)
        .map_err(|e| e.context("Failed to receive from pid return socket"))?;
    eprintln!("spawn: got inner_child_pid={inner_child_pid}");

    // Wait for the outer child to exit.
    let outer_child_exit =
        waitpid(outer_child_pid).map_err(|e| e.context("failed to wait for outer child exit"))?;
    eprintln!("spawn: got outer_child_exit={outer_child_exit:?}");

    // Return the pid of the inner child, which eventually becomes the target subprocess.
    // We can do this because it is spawned by the outer child with CLONE_PARENT, so it will always
    // be our child in the process tree.
    Ok(Child {
        pid: inner_child_pid.try_into().expect("pid out of range"),
    })
}

impl Child {
    /// Wait for the child to exit, returning the exit status.
    pub fn wait(&self) -> Result<ExitStatus> {
        unsafe { waitpid(self.pid.try_into().unwrap()) }
    }
}

struct OuterChildArg {
    cmd: *const Command,
    idmap_sync_rx_fd: c_int,
    pid_return_tx_fd: c_int,
    inner_child_stack: Vec<u8>,
}

#[cfg_attr(debug_assertions, no_alloc)]
extern "C" fn outer_child_extern(arg: *mut c_void) -> c_int {
    let arg: &mut OuterChildArg = unsafe { &mut *(arg as *mut OuterChildArg) };

    // Catch any panics.
    let result = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        outer_child_entrypoint(arg)
    })) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("outer: caught panic: {e:?}");
            return 126;
        }
    };

    // Match the result.
    result
        .map(|()| 0)
        .map_err(|e| eprintln!("inner: error: {}", e))
        .unwrap_or(42)
}

/// Handler for the outer clone.
/// - Runs inside userns.
#[cfg_attr(debug_assertions, no_alloc)]
unsafe fn outer_child_entrypoint(arg: &mut OuterChildArg) -> Result<()> {
    let cmd: &Command = &*arg.cmd;

    let pid = libc::getpid();
    let uid = libc::getuid();
    let euid = libc::geteuid();
    let gid = libc::getgid();
    let egid = libc::getegid();

    eprintln!("outer: pid={pid}");
    eprintln!("outer: uid={uid} euid={euid}");
    eprintln!("outer: gid={gid} egid={egid}");

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

    // Calculate the clone flags for the child.
    let mut clone_flags = 0;

    // NOTE: You MUST set `SIGCHLD` in order for `waitpid()` after `clone()` to work properly.
    clone_flags |= libc::SIGCHLD;

    // When the inner child is created, create it as a sibling process to this process in the
    // process tree. This allows our parent process to wait for its termination using `waitpid(2)`.
    clone_flags |= libc::CLONE_PARENT;

    // If configured, enter a new mount namespace here.
    // TODO: For about an 0.1ms latency bump, we can avoid a double-fork by entering the mount
    // namespace using `unshare(2)` instead of `clone(2)`, IFF we do not need to enter a PID
    // namespace (which requires another fork, even when `unshare(2)` is used).
    if cmd.namespaces.mount {
        clone_flags |= libc::CLONE_NEWNS;
    }

    // If configured, enter a new PID namespace here.
    if cmd.namespaces.pid {
        clone_flags |= libc::CLONE_NEWPID;
    }

    // If configured, enter a new UTS namespace here.
    if cmd.namespaces.uts {
        clone_flags |= libc::CLONE_NEWUTS;
    }

    // If configured, enter a new SysV IPC namespace here.
    if cmd.namespaces.ipc {
        clone_flags |= libc::CLONE_NEWIPC;
    }

    // If configured, enter a new network namespace here.
    if cmd.namespaces.network {
        clone_flags |= libc::CLONE_NEWNET;
    }

    // If configured, enter a new cgroup namespace here.
    if cmd.namespaces.cgroup {
        clone_flags |= libc::CLONE_NEWCGROUP;
    }

    // Get the stack pointer for the child.
    let inner_child_stack_ptr = get_topmost_stack_pointer(arg.inner_child_stack.as_mut());

    // Construct the argument to the child entrypoint.
    let mut inner_child_arg = InnerChildArg {
        cmd: arg.cmd,
        idmap_sync_rx_fd: arg.idmap_sync_rx_fd,
    };

    // Create the inner child.
    let inner_child_pid @ 0.. = libc::clone(
        inner_child_extern,
        inner_child_stack_ptr,
        clone_flags,
        &mut inner_child_arg as *mut InnerChildArg as *mut c_void,
    ) else {
        bail_errno!("clone(2) failed");
    };
    eprintln!("outer: inner_child_pid={inner_child_pid}");

    // Send the PID of the inner child to the parent.
    socket_send(arg.pid_return_tx_fd, inner_child_pid)
        .map_err(|e| e.context("Failed to send to pid return socket"))?;
    eprintln!("outer: sent to pid_return_fd: {inner_child_pid}");

    // Exit cleanly.
    Ok(())
}

struct InnerChildArg {
    cmd: *const Command,
    idmap_sync_rx_fd: c_int,
}

#[cfg_attr(debug_assertions, no_alloc)]
extern "C" fn inner_child_extern(arg: *mut c_void) -> c_int {
    let arg: &mut InnerChildArg = unsafe { &mut *(arg as *mut InnerChildArg) };

    // Catch any panics.
    // SAFETY: We do not use the argument after it's moved into this function.
    let result = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        inner_child_entrypoint(arg)
    })) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("inner: caught panic: {e:?}");
            return 126;
        }
    };

    result
        .map(|()| 0)
        .map_err(|e| eprintln!("inner: error: {}", e))
        .unwrap_or(42)
}

/// Handler for the inner clone, if necessary, or simply called by the outer entrypoint.
/// - Runs inside all namespaces.
#[cfg_attr(debug_assertions, no_alloc)]
unsafe fn inner_child_entrypoint(arg: &mut InnerChildArg) -> Result<()> {
    let cmd: &Command = &*arg.cmd;

    let pid = libc::getpid();
    let (uid, euid) = (libc::getuid(), libc::geteuid());
    let (gid, egid) = (libc::getgid(), libc::getegid());
    eprintln!("inner: pid={pid}");
    eprintln!("inner: uid={uid} euid={euid} gid={gid} egid={egid}");

    // If we're in a mount namespace, remount the root as slave recursive.
    if cmd.namespaces.mount {
        let 0 = libc::mount(
            ptr::null(),
            b"/\0".as_ptr().cast(),
            ptr::null(),
            // MS_SLAVE: Mount events from the host should propagate in, but mount events
            // in the guest should not propagate out.
            libc::MS_SLAVE | libc::MS_REC,
            ptr::null(),
        ) else {
            bail_errno!("remounting root as slave recursive failed");
        };
    }
    eprintln!("inner: remounted root as recursive slave");

    // Mount the user-supplied mount table.
    for mount in &cmd.mounts.mounts {
        // NOTE: There is a TOCTOU race condition between reading the filetype of the source, and creating the right kind of mountpoint. Normally this is not an issue, but it will cause a failure if the source filetype changes from file to directory.
        if let Some(mut mountpoint_type) = mount.create_mountpoint {
            eprintln!(
                "inner: creating mountpoint for {:?} on {:?}",
                mount.source, mount.target
            );

            // If the mountpoint type is DetermineFromSource, `stat()` the source.
            if mountpoint_type == mount_table::MountpointType::DetermineFromSource {
                // Is the source a file or a directory?
                let source_stat = stat(mount.source.as_ptr()).map_err(|e| {
                    e.context("failed to stat() mount source while creating mountpoint")
                })?;

                if source_stat.st_mode & libc::S_IFMT == libc::S_IFDIR {
                    mountpoint_type = mount_table::MountpointType::Dir;
                } else {
                    mountpoint_type = mount_table::MountpointType::File;
                }
            }

            match mountpoint_type {
                mount_table::MountpointType::Dir => {
                    let target_ptr: *const c_char = mount.target.as_ptr().cast();
                    mkdirp(target_ptr)
                        .map_err(|e| e.context("failed to mkdir() directory mountpoint"))?;
                }
                mount_table::MountpointType::File => {
                    let 0 = libc::creat(mount.target.as_ptr(), 0o644) else {
                        bail_errno!("failed to creat() file mountpoint");
                    };
                }
                mount_table::MountpointType::DetermineFromSource => {
                    unreachable!("type should have been resolved earlier in the function")
                }
            }
        }

        eprintln!(
            "inner: mounting {:?} on {:?} type {:?}",
            mount.source, mount.target, mount.fstype
        );
        let 0 = libc::mount(
            mount.source.as_ptr(),
            mount.target.as_ptr(),
            mount.fstype.as_ptr(),
            mount.flags,
            match &mount.data {
                Some(data) => data.as_ptr().cast(),
                None => ptr::null(),
            },
        ) else {
            bail_errno!("user mount failed");
        };
    }

    // Pivot to the new root, if necessary, using the `pivot_root(.,.)` shortcut.
    if let Some(new_root) = cmd.pivot_root_to {
        // Bind-mount the new root to itself (because the new root must be a mount point).
        let 0 = libc::mount(
            new_root,
            new_root,
            ptr::null(),
            // Note: We need MS_REC here so that bind mounts inside the new root are propagated.
            libc::MS_BIND | libc::MS_REC,
            ptr::null(),
        ) else {
            bail_errno!("re-bind-mounting pivot_root location failed");
        };

        // CD into the new root.
        let 0 = libc::chdir(new_root) else {
            bail_errno!("chdir to pivot_root location failed");
        };

        // Pivot root into the new root.
        let dot = ".\0".as_ptr();
        let 0 = libc::syscall(libc::SYS_pivot_root, dot, dot) else {
            bail_errno!("pivot_root failed");
        };

        // Unmount the old root, and remove the mount point.
        let 0 = libc::umount2(dot, libc::MNT_DETACH) else {
            bail_errno!("failed to detact old root mount point");
        };

        // Set the working directory to "/" within the new root.
        let 0 = libc::chdir(b"/\0".as_ptr()) else {
            bail_errno!("chdir to / after pivot_root failed");
        };
    }

    // Set the working directory.
    if let Some(working_dir) = cmd.set_working_dir {
        let 0 = libc::chdir(working_dir) else {
            bail_errno!("chdir to set_working_dir failed");
        };
    }

    // Receive a byte from the sync socket to wait for uid_map, setgroups, and gid_map to be
    // written.
    socket_recv::<u8>(arg.idmap_sync_rx_fd)
        .map_err(|e| e.context("Failed to read from uid/gidmap sync socket"))?;

    // Set our UID and GID
    if let Some(uid) = cmd.set_uid {
        let 0 = libc::setuid(uid) else {
            bail_errno!("setuid failed");
        };
    }
    if let Some(gid) = cmd.set_gid {
        let 0 = libc::setgid(gid) else {
            bail_errno!("setgid failed");
        };
    }

    let (uid, euid) = (libc::getuid(), libc::geteuid());
    let (gid, egid) = (libc::getgid(), libc::getegid());
    eprintln!("inner: after setuid/setgid: uid={uid} euid={euid} gid={gid} egid={egid}");

    // Execute the child command.
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

/// Create a Unix stream socket pair.
fn socket_pair() -> Result<(c_int, c_int)> {
    // Create a socket pair, so we can signal the child to continue once we write the uid map,
    // disable setgroups, and write the gid map.
    let mut socket_fds = [0; 2];
    let 0.. =
        (unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, socket_fds.as_mut_ptr()) })
    else {
        bail_errno!("failed to create socketpair");
    };
    let [a, b] = socket_fds;
    Ok((a, b))
}

/// Send a value, interpretable as bytes, to a socket's file descriptor.
unsafe fn socket_send<T: Copy>(sock_fd: c_int, value: T) -> Result<()> {
    let size = mem::size_of::<T>();

    // Send the PID of the inner child to the parent.
    let result = libc::write(sock_fd, (&value) as *const T as *const c_void, size);

    if result == -1 {
        return Err(Error::last_os_error().cause("failed to send to socket"));
    }

    if (result as usize) != size {
        return Err(Error::new().cause("failed to send socket message in single write call"));
    }

    Ok(())
}

/// Receive a value, interpretable as bytes, from a socket's file descriptor.
unsafe fn socket_recv<T: Copy>(sock_fd: c_int) -> Result<T> {
    let size = mem::size_of::<T>();
    // assert!(size > 0, "cannot receive zero-sized type");

    let mut output_slot = mem::MaybeUninit::<T>::uninit();
    let result = libc::read(
        sock_fd,
        output_slot.as_mut_ptr().cast(),
        mem::size_of::<T>(),
    );

    if result == -1 {
        return Err(Error::last_os_error().cause("failed to receive from socket"));
    };

    if result == 0 {
        return Err(Error::new().cause("reached EOF while receiving from socket"));
    }

    if (result as usize) != size {
        return Err(Error::new().cause("failed to receive socket message in single read call"));
    }

    Ok(output_slot.assume_init())
}

unsafe fn waitpid(pid: c_int) -> Result<ExitStatus> {
    let mut status: c_int = 0;
    let 0.. = (unsafe { libc::waitpid(pid, &mut status as *mut c_int, 0) }) else {
        bail_errno!("waitpid failed");
    };
    ExitStatus::from_wait_status(status)
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

fn stat(path: *const c_char) -> Result<libc::stat> {
    let mut stat_buf = mem::MaybeUninit::<libc::stat>::uninit();
    let 0.. = (unsafe { libc::stat(path, stat_buf.as_mut_ptr()) }) else {
        bail_errno!("failed to stat file");
    };
    Ok(unsafe { stat_buf.assume_init() })
}

/// Create a directory for all non-existent path components of `path`.
fn mkdirp(path: *const c_char) -> Result<()> {
    let mkdir_ignoring_eexist = |path: *const c_char| -> Result<()> {
        let mkdir_result = unsafe { libc::mkdir(path, 0o755) };
        if mkdir_result == -1 {
            let err = Error::last_os_error();
            if err.errno != libc::EEXIST {
                return Err(err.cause("failed to create directory"));
            }
        };
        Ok(())
    };

    // Error if the path is longer than PATH_MAX.
    let path_len = unsafe { libc::strlen(path) };
    if path_len > libc::PATH_MAX as usize {
        bail!("mkdirp() path is longer than PATH_MAX");
    }
    // Copy the path to a local buffer.
    let mut buf = [b'\0'; libc::PATH_MAX as usize + 1];
    buf[..path_len + 1].copy_from_slice(unsafe { std::slice::from_raw_parts(path, path_len + 1) });

    // Loop through indices of `/` characters in the buffer to create ancestors.
    for i in 1..buf.len() {
        if buf[i] == b'\0' {
            break;
        }
        if buf[i] != b'/' {
            continue;
        }

        // Replace the `/` with a null byte.
        buf[i] = b'\0';

        // Create the directory, ignoring EEXIST.
        mkdir_ignoring_eexist(buf.as_ptr())?;

        // Put the `/` back.
        buf[i] = b'/';
    }

    // Create the final directory.
    mkdir_ignoring_eexist(buf.as_ptr().cast())?;

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
            command: cmd_path.as_ptr(),
            args: vec![cmd_path.as_ptr(), ptr::null()],
            envp: vec![ptr::null()],
            stdin_fd: Some(null_fd),
            stdout_fd: Some(null_fd),
            stderr_fd: Some(null_fd),
            namespaces: NamespaceSet::default(),
            uid_map: None,
            gid_map: None,
            set_uid: None,
            set_gid: None,
            pivot_root_to: None,
            set_working_dir: None,
            mounts: mount_table::MountTable::new(),
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
            command: cmd_path.as_ptr(),
            args: vec![cmd_path.as_ptr(), ptr::null()],
            envp: vec![ptr::null()],
            stdin_fd: None,
            stdout_fd: None,
            stderr_fd: None,
            namespaces: NamespaceSet {
                user: true,
                mount: true,
                ..NamespaceSet::default()
            },
            uid_map: Some(uid_map),
            gid_map: None,
            set_uid: Some(0),
            set_gid: None,
            pivot_root_to: None,
            set_working_dir: None,
            mounts: mount_table::MountTable::new(),
        };

        let child = unsafe { spawn(cmd) }.unwrap();

        // Wait a bit so the logs can sort themselves out
        std::thread::sleep(std::time::Duration::from_millis(100));

        assert!(child.wait().unwrap().success());
    }
}
