use alloc_counter::no_alloc;
use std::ffi::{c_char, c_int, c_void};
use std::io::{BufRead, Write};
use std::os::fd::FromRawFd;
use std::ptr;

use tracing::{debug, span, Level};

use crate::error::{bail_errno, Error, Result};
use crate::libc_util::*;
use crate::{id_map, mount_table, systemd};

/// Size of the stack for cloned children.
const STACK_SIZE: usize = 8 * 1024 * 1024; // 8 MB

/// Log a message (given in format_args! style) by writing it to a file descriptor.
///
/// This cannot allocate---buffer messages to a fixed-length, stack-allocated 2048-byte buffer.
///
/// ```
/// log_fd!(fd, "msg {param}", param = 42)
/// ```
macro_rules! log_fd {
    ($fd:expr, $fmt:expr) => {
        {
            let mut buffer = [0u8; 2048];
            let mut cursor = std::io::Cursor::new(&mut buffer[..]);
            let _ = writeln!(cursor, $fmt);
            let _ = unsafe {libc::write($fd, cursor.get_ref().as_ptr() as *const c_void, cursor.position() as usize)};
        }
    };
    ($fd:expr, $fmt:expr, $($arg:tt)*) => {
        {
            let mut buffer = [0u8; 2048];
            let mut cursor = std::io::Cursor::new(&mut buffer[..]);
            let _ = writeln!(cursor, $fmt, $($arg)*);
            let _ = unsafe {libc::write($fd, cursor.get_ref().as_ptr() as *const c_void, cursor.position() as usize)};
        }
    };
}
/// Context for sandbox execution.
#[derive(Debug)]
pub struct Context {
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

    /// Configure a cgroup through a transient systemd scope for the child process.
    pub scope: Option<systemd::ScopeParameters>,
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

    // Optionally, return a handle to the systemd unit we're supervising.
    scope: Option<systemd::ScopeHandle>,
}

/// Spawn a child process, returning a [`Child`].
/// For safety, this function __cannot__ return until the child has been executed. This is
/// because the child entrypoints may borrow memory from the parent.
///
/// # Safety
///
/// The pointers in `ctx` must be valid until this function returns.
pub unsafe fn spawn(ctx: Context) -> Result<Child> {
    let span = span!(Level::DEBUG, "spawn");
    let _span_guard = span.enter();

    // Create the outer child's log stream.
    let (log_outer_tx_fd, log_outer_rx_fd) = socket_pair()
        .map_err(|e| e.context("Failed to create log stream for outer child socket"))?;
    let log_outer_span = span!(Level::DEBUG, "outer");
    let _log_outer_follower_handle = spawn_log_forwarder(log_outer_span.clone(), log_outer_rx_fd);

    // Create the inner child's log stream.
    let (log_inner_tx_fd, log_inner_rx_fd) = socket_pair()
        .map_err(|e| e.context("Failed to create log stream for inner child socket"))?;
    let log_inner_span = span!(parent: log_outer_span, Level::DEBUG, "inner");
    let _log_inner_follower_handle = spawn_log_forwarder(log_inner_span, log_inner_rx_fd);

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

    // Create a socket to wait for cgroup creation.
    // This prevents the outer process from exiting before a cgroup has been arranged for it and
    // its children.
    let (cgroup_sync_tx_fd, cgroup_sync_rx_fd) = socket_pair()
        .map_err(|e| e.context("Failed to create socketpair for cgroup sync socket"))?;

    // Create the child in a new user namespace.
    let mut clone_flags = 0;

    // NOTE: You MUST set `SIGCHLD` in order for `waitpid()` after `clone()` to work properly.
    clone_flags |= libc::SIGCHLD;

    // If configured, enter a new user namespace here.
    if ctx.namespaces.user {
        clone_flags |= libc::CLONE_NEWUSER;
    }

    // Allocate the stack for the inner child, so we can pass it through the outer child.
    let inner_child_stack = vec![0; STACK_SIZE];

    // Allocate the stack for the outer child, and get its topmost address.
    let mut outer_child_stack = vec![0; STACK_SIZE];
    let outer_child_stack_ptr = get_topmost_stack_pointer(outer_child_stack.as_mut());

    // Construct the argument to the child entrypoint.
    let mut outer_child_arg = OuterChildArg {
        ctx: &ctx,
        idmap_sync_rx_fd,
        log_outer_tx_fd,
        cgroup_sync_rx_fd,
        log_inner_tx_fd,
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

    // After we've cloned the first child, close our copies of the send end of the logging file
    // descriptors.
    let _ = libc::close(log_outer_tx_fd);
    let _ = libc::close(log_inner_tx_fd);

    debug!(%outer_child_pid);

    // Arrange for a systemd scope to contain the child process.
    let maybe_scope_handle = match ctx.scope {
        Some(scope_config) => {
            let scope_handle =
                systemd::start_transient_unit(outer_child_pid.try_into().unwrap(), scope_config)
                    .map_err(|e| {
                        debug!(err=%e, "failed to start systemd unit");
                        Error::new().cause("Failed to start transient systemd unit")
                    })?;
            Some(scope_handle)
        }
        None => None,
    };

    // If using a cgroup: signal that we're done waiting for the cgroup.
    // If not using a cgroup: signal anyways.
    socket_send::<u8>(cgroup_sync_tx_fd, 0)
        .map_err(|e| e.context("Failed to send to cgroup sync socket"))?;

    // Write the UID map.
    if let Some(uid_map) = ctx.uid_map {
        debug!("writing uid_map");
        std::fs::write(
            format!("/proc/{outer_child_pid}/uid_map"),
            uid_map.into_idmap_file_contents(),
        )
        .map_err(Error::from)
        .map_err(|e| e.context("Failed to write UID map"))?;
    }

    // Disable setgroups and set the GID map.
    if let Some(gid_map) = ctx.gid_map {
        std::fs::write(format!("/proc/{outer_child_pid}/setgroups"), "deny\n")
            .map_err(Error::from)
            .map_err(|e| e.context("Failed to disable setgroups"))?;
        std::fs::write(
            format!("/proc/{outer_child_pid}/gid_map"),
            gid_map.into_idmap_file_contents(),
        )
        .map_err(Error::from)
        .map_err(|e| e.context("Failed to write UID map"))?;
    }

    // Send a byte to the child, to signal that we've written the uid/gid maps.
    socket_send::<u8>(idmap_sync_tx_fd, 0)
        .map_err(|e| e.context("Failed to send to uid/gidmap sync socket"))?;
    debug!("sent to idmap_sync_tx_fd");

    // Wait for the outer child to send us the PID of the inner child.
    let inner_child_pid: c_int = socket_recv::<c_int>(pid_return_rx_fd)
        .map_err(|e| e.context("Failed to receive from pid return socket"))?;
    debug!(inner_child_pid=?inner_child_pid, "got inner_child_pid");

    // Wait for the outer child to exit.
    let outer_child_exit =
        waitpid(outer_child_pid).map_err(|e| e.context("failed to wait for outer child exit"))?;
    debug!(outer_child_exit=?outer_child_exit, "got outer_child_exit");

    // Return the pid of the inner child, which eventually becomes the target subprocess.
    // We can do this because it is spawned by the outer child with CLONE_PARENT, so it will always
    // be our child in the process tree.
    Ok(Child {
        pid: inner_child_pid.try_into().expect("pid out of range"),
        scope: maybe_scope_handle,
    })
}

impl Child {
    /// Wait for the child to exit, returning the exit status.
    pub fn wait(&self) -> Result<ExitStatus> {
        unsafe { waitpid(self.pid.try_into().unwrap()) }
    }

    /// Get the scope handle, if we have a scope.
    pub fn scope(&self) -> Option<&systemd::ScopeHandle> {
        self.scope.as_ref()
    }
}

struct OuterChildArg {
    ctx: *const Context,
    idmap_sync_rx_fd: c_int,
    cgroup_sync_rx_fd: c_int,
    pid_return_tx_fd: c_int,
    log_outer_tx_fd: c_int,
    log_inner_tx_fd: c_int,
    inner_child_stack: Vec<u8>,
}

#[cfg_attr(debug_assertions, no_alloc)]
extern "C" fn outer_child_extern(arg: *mut c_void) -> c_int {
    let arg: &mut OuterChildArg = unsafe { &mut *(arg as *mut OuterChildArg) };
    let lfd = arg.log_outer_tx_fd;

    // Catch any panics.
    let result = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        outer_child_entrypoint(arg)
    })) {
        Ok(r) => r,
        Err(e) => {
            log_fd!(lfd, "caught panic: {e:?}");
            return 126;
        }
    };

    // Match the result.
    result
        .map(|()| 0)
        .map_err(|e| log_fd!(lfd, "error: {}", e))
        .unwrap_or(42)
}

/// Handler for the outer clone.
/// - Runs inside userns.
#[cfg_attr(debug_assertions, no_alloc)]
unsafe fn outer_child_entrypoint(arg: &mut OuterChildArg) -> Result<()> {
    let lfd: c_int = arg.log_outer_tx_fd;
    let ctx: &Context = &*arg.ctx;

    let pid = libc::getpid();
    let uid = libc::getuid();
    let euid = libc::geteuid();
    let gid = libc::getgid();
    let egid = libc::getegid();

    log_fd!(lfd, "pid={pid} uid={uid} euid={euid} gid={gid} egid={egid}");

    // Configure stdin, stdout, and stderr.
    if let Some(stdin_fd) = ctx.stdin_fd {
        log_fd!(lfd, "set stdin_fd={stdin_fd}");
        let 0.. = libc::dup2(stdin_fd, libc::STDIN_FILENO) else {
            bail_errno!("dup2(stdin_fd) failed");
        };
    }
    if let Some(stdout_fd) = ctx.stdout_fd {
        log_fd!(lfd, "set stdout_fd={stdout_fd}");
        let 0.. = libc::dup2(stdout_fd, libc::STDOUT_FILENO) else {
            bail_errno!("dup2(stdout_fd) failed");
        };
    }
    if let Some(stderr_fd) = ctx.stderr_fd {
        log_fd!(lfd, "set stderr_fd={stderr_fd}");
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
    if ctx.namespaces.mount {
        clone_flags |= libc::CLONE_NEWNS;
    }

    // If configured, enter a new PID namespace here.
    if ctx.namespaces.pid {
        clone_flags |= libc::CLONE_NEWPID;
    }

    // If configured, enter a new UTS namespace here.
    if ctx.namespaces.uts {
        clone_flags |= libc::CLONE_NEWUTS;
    }

    // If configured, enter a new SysV IPC namespace here.
    if ctx.namespaces.ipc {
        clone_flags |= libc::CLONE_NEWIPC;
    }

    // If configured, enter a new network namespace here.
    if ctx.namespaces.network {
        clone_flags |= libc::CLONE_NEWNET;
    }

    // If configured, enter a new cgroup namespace here.
    if ctx.namespaces.cgroup {
        clone_flags |= libc::CLONE_NEWCGROUP;
    }

    // Get the stack pointer for the child.
    let inner_child_stack_ptr = get_topmost_stack_pointer(arg.inner_child_stack.as_mut());

    // Construct the argument to the child entrypoint.
    let mut inner_child_arg = InnerChildArg {
        ctx: arg.ctx,
        idmap_sync_rx_fd: arg.idmap_sync_rx_fd,
        log_inner_tx_fd: arg.log_inner_tx_fd,
    };

    // Wait for our cgroup to be created before we clone.
    socket_recv::<u8>(arg.cgroup_sync_rx_fd)
        .map_err(|e| e.context("Failed to read from cgroup sync socket"))?;

    // Create the inner child.
    let inner_child_pid @ 0.. = libc::clone(
        inner_child_extern,
        inner_child_stack_ptr,
        clone_flags,
        &mut inner_child_arg as *mut InnerChildArg as *mut c_void,
    ) else {
        bail_errno!("clone(2) failed");
    };
    log_fd!(lfd, "inner_child_pid={inner_child_pid}");

    // Send the PID of the inner child to the parent.
    socket_send(arg.pid_return_tx_fd, inner_child_pid)
        .map_err(|e| e.context("Failed to send to pid return socket"))?;
    log_fd!(lfd, "sent to pid_return_fd: {inner_child_pid}");

    // Exit cleanly.
    Ok(())
}

struct InnerChildArg {
    ctx: *const Context,
    idmap_sync_rx_fd: c_int,
    log_inner_tx_fd: c_int,
}

#[cfg_attr(debug_assertions, no_alloc)]
extern "C" fn inner_child_extern(arg: *mut c_void) -> c_int {
    let arg: &mut InnerChildArg = unsafe { &mut *(arg as *mut InnerChildArg) };
    let lfd = arg.log_inner_tx_fd;

    // Catch any panics.
    // SAFETY: We do not use the argument after it's moved into this function.
    let result = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        inner_child_entrypoint(arg)
    })) {
        Ok(r) => r,
        Err(e) => {
            log_fd!(lfd, "caught panic: {e:?}");
            return 126;
        }
    };

    result
        .map(|()| 0)
        .map_err(|e| log_fd!(lfd, "error: {}", e))
        .unwrap_or(42)
}

/// Handler for the inner clone, if necessary, or simply called by the outer entrypoint.
/// - Runs inside all namespaces.
#[cfg_attr(debug_assertions, no_alloc)]
unsafe fn inner_child_entrypoint(arg: &mut InnerChildArg) -> Result<()> {
    let ctx: &Context = &*arg.ctx;
    let lfd = arg.log_inner_tx_fd;

    let pid = libc::getpid();
    let (uid, euid) = (libc::getuid(), libc::geteuid());
    let (gid, egid) = (libc::getgid(), libc::getegid());
    log_fd!(lfd, "pid={pid} uid={uid} euid={euid} gid={gid} egid={egid}");

    // If we're in a mount namespace, remount the root as slave recursive.
    if ctx.namespaces.mount {
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
        log_fd!(lfd, "remounted root as recursive slave");
    }

    // Mount the user-supplied mount table.
    for mount in &ctx.mounts.mounts {
        // NOTE: There is a TOCTOU race condition between reading the filetype of the source, and creating the right kind of mountpoint. Normally this is not an issue, but it will cause a failure if the source filetype changes from file to directory.
        if let Some(mut mountpoint_type) = mount.create_mountpoint {
            log_fd!(
                lfd,
                "creating mountpoint for {:?} on {:?}",
                mount.source,
                mount.target
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

        log_fd!(
            lfd,
            "mounting {:?} on {:?} type {:?}",
            mount.source,
            mount.target,
            mount.fstype
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
    if let Some(new_root) = ctx.pivot_root_to {
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
    if let Some(working_dir) = ctx.set_working_dir {
        let 0 = libc::chdir(working_dir) else {
            bail_errno!("chdir to set_working_dir failed");
        };
    }

    // Receive a byte from the sync socket to wait for uid_map, setgroups, and gid_map to be
    // written.
    socket_recv::<u8>(arg.idmap_sync_rx_fd)
        .map_err(|e| e.context("Failed to read from uid/gidmap sync socket"))?;

    // Set our UID and GID
    if let Some(uid) = ctx.set_uid {
        let 0 = libc::setuid(uid) else {
            bail_errno!("setuid failed");
        };
    }
    if let Some(gid) = ctx.set_gid {
        let 0 = libc::setgid(gid) else {
            bail_errno!("setgid failed");
        };
    }

    if ctx.set_uid.is_some() || ctx.set_gid.is_some() {
        let (uid, euid) = (libc::getuid(), libc::geteuid());
        let (gid, egid) = (libc::getgid(), libc::getegid());
        log_fd!(
            lfd,
            "after setuid/setgid: uid={uid} euid={euid} gid={gid} egid={egid}"
        );
    }

    // Execute the child command.
    let 0 = libc::execve(ctx.command, ctx.args.as_ptr(), ctx.envp.as_ptr()) else {
        bail_errno!("exec_command failed");
    };

    unreachable!("execve(2) returned without error---this should never happen");
}

/// Start a thread to forward logs written to a socket to a particular span in the host's tracing
/// log.
fn spawn_log_forwarder(span: tracing::Span, log_rx_fd: libc::c_int) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        // Create a UnixStream from the FD
        let log_outer_rx = unsafe { std::os::unix::net::UnixStream::from_raw_fd(log_rx_fd) };

        // Loop over lines
        for line in std::io::BufReader::new(log_outer_rx).lines().flatten() {
            debug!(parent: &span, "{}", line);
        }
    })
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

        let ctx = Context {
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
            scope: None,
        };

        let child = unsafe { spawn(ctx) }.unwrap();

        // Wait a bit so the logs can sort themselves out
        std::thread::sleep(std::time::Duration::from_millis(100));

        assert_eq!(child.wait().unwrap(), ExitStatus::Code(1));
    }

    #[test]
    fn userns_id_exits_0() {
        let cmd_path = CString::new("/usr/bin/id").unwrap();
        let null_fd = unsafe { libc::open("/dev/null\0".as_ptr().cast(), libc::O_RDONLY) };

        let mut uid_map = id_map::IdMap::new();
        uid_map.map_one(unsafe { libc::getuid() }, 0);

        let cmd = Context {
            command: cmd_path.as_ptr(),
            args: vec![cmd_path.as_ptr(), ptr::null()],
            envp: vec![ptr::null()],
            stdin_fd: None,
            stdout_fd: None,
            stderr_fd: Some(null_fd),
            namespaces: NamespaceSet {
                user: true,
                ..NamespaceSet::default()
            },
            uid_map: Some(uid_map),
            gid_map: None,
            set_uid: Some(0),
            set_gid: None,
            pivot_root_to: None,
            set_working_dir: None,
            mounts: mount_table::MountTable::new(),
            scope: None,
        };

        let child = unsafe { spawn(cmd) }.unwrap();

        // Wait a bit so the logs can sort themselves out
        std::thread::sleep(std::time::Duration::from_millis(100));

        assert!(child.wait().unwrap().success());
    }
}
