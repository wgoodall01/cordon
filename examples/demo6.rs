//! # Demo: Systemd integration and cgroups
//!
//! This demo asks systemd to place our child process into its own ephemeral unit (a scope), and
//! with it, place the child into its own cgroup.
//!
//! This also allows you to monitor the child process like you would any other systemd unit.
//!
//! - Running `cat /proc/$$/cgroup` will show the host's session slice.
//! - On the host:
//!     - Running `systemctl --user status $unit_name` will show the status of the container.
//!     - Running `systemctl freeze $unit_name` on the host will suspend execution of the child with
//!       the cgroup freezer.
//! - Running a fork bomb `x(){ x|x& };x` inside the guest will not affect the host (TasksMax is
//!   set). You'll see a `can't fork` error as the guest hits the task limit.

use c_str_macro::c_str;
use cordon::{IdMap, MountTable, NamespaceSet};
use std::ptr;
use tracing::info;
mod common;

pub fn main() -> eyre::Result<()> {
    common::configure_logging();

    // Configure the mount table of the child process.
    // The "target prefix" will be prepended to all mount destinations.
    let executable_path = c_str!("/bin/sh");

    // A `Context` describes the behavior of Cordon's sandboxing.
    let ctx = cordon::Context {
        // The binary to run, arguments, and environment.
        command: executable_path.as_ptr(),
        args: vec![executable_path.as_ptr(), ptr::null()],
        envp: vec![c_str!("ENVVAR=test").as_ptr(), ptr::null()],
        // Note: We must allocate memory up-front, because we cannot allocate in the children.

        // Standard IO.
        stdin_fd: None,
        stdout_fd: None,
        stderr_fd: None,

        // Namespace configuration.
        namespaces: NamespaceSet {
            user: true,  // Unshared at the first fork.
            mount: true, // Unshared at the second fork, because we need root privileges to do so.
            pid: true,   // Unshared at the second fork, making the inner child PID 1.
            ..Default::default()
        },

        // User and group IDs and mappings.
        set_uid: None,
        set_gid: None,
        uid_map: Some(IdMap::self_to_inner_uid(0)),
        gid_map: Some(IdMap::self_to_inner_gid(0)),

        // Mounts and chroot.
        // The `./_root` dir contains a small busybox-based root filesystem.
        pivot_root_to: Some(c_str!("./_root").as_ptr()),
        set_working_dir: None,
        mounts: {
            let mut mt = MountTable::with_target_prefix(c_str!("./_root"));

            mt.add_temp(c_str!("/tmp")); // Mount tmpfs on `/tmp`
            mt.add_proc(); // Mount procfs on `/proc`
            mt.add_sys(); // Bind-mount the host's `/sys` on `/sys`

            // Pass throuch the host's desktop folder to the guest.
            mt.add_bind(c_str!("/home/wgoodall01/Desktop"), c_str!("/host_desktop"));

            mt
        },

        // Systemd integration and cgroup parameters.
        scope: Some(cordon::systemd::ScopeParameters {
            description: Some("Cordon demo number six!".into()),
            tasks_max: Some(8),
            memory_max: Some(1024 * 1024 * 1024),
            ..cordon::systemd::ScopeParameters::with_unique_name()
        }),

        forward_spawn_logs: true,
    };

    // Spawn the child process.
    let child = unsafe { cordon::spawn(ctx) }?;

    // Log the name of the scope the child is running in.
    info!(unit = ?child.scope().unwrap());

    // Wait for the child to exit.
    let exit = child.wait()?;
    info!(?exit);
    Ok(())
}
