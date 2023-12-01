//! # Demo: PID namespace
//!
//! This demo runs the child in a PID namespace---isolating its process tree from the host.
//!
//! - Running `echo $$` will show that the shell is running as PID 1.

use c_str_macro::c_str;
use cordon::{IdMap, MountTable};
use std::ptr;
use tracing::info;
mod common;

pub fn main() -> eyre::Result<()> {
    common::configure_logging();

    let executable_path = c_str!("/bin/sh");

    // A `Context` describes the behavior of Cordon's sandboxing.
    let ctx = cordon::spawn::Context {
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
        namespaces: cordon::spawn::NamespaceSet {
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
        mounts: MountTable::default(),

        // Systemd integration and cgroup parameters.
        scope: None,

        forward_spawn_logs: true,
    };

    // Spawn the child process.
    let child = unsafe { cordon::spawn::spawn(ctx) }?;

    // Wait for the child to exit.
    let exit = child.wait()?;
    info!(?exit);
    Ok(())
}
