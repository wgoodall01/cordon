//! # Demo: Mount manipulation
//!
//! This demo runs the child in a mount namespace, and mounts /tmp, /proc, and /sys into that
//! namespace.
//!
//! We'll also mount the host desktop folder into the child's `/host-desktop` directory as an
//! example of a bind mount.
//!
//! - Running `ls /proc` will only show PIDs inside the namespace (so will `ps aux`).
//! - Running `cat /proc/$$/cgroup` will show the host's session slice.
//! - Running `ls /host_desktop` will list the host's desktop folder.
//! - Touching a file in `/host_desktop` will create it in the host's desktop folder.

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
        scope: None,
    };

    // Spawn the child process.
    let child = unsafe { cordon::spawn(ctx) }?;

    // Wait for the child to exit.
    let exit = child.wait()?;
    info!(?exit);
    Ok(())
}
