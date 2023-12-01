//! # Demo: User mapping
//!
//! This demo maps the current user on the host to the root user within the user namespace.
//!
//! - Looking at the logs will show `uid=0 gid=0` after the first fork.
//! - Running `id` will show `root`.
//! - Running `ls / /home` will show the host filesystem.
//! - Running `cat /proc/$$/cgroup` will show a cgroup in the host user's session.
//! - Touching a file as root will show as root in the namespace, and as the current user on the host.

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
            user: true,
            ..Default::default()
        },

        // User and group IDs and mappings.
        set_uid: None,
        set_gid: None,
        uid_map: Some(IdMap::self_to_inner_uid(0)),
        gid_map: Some(IdMap::self_to_inner_gid(0)),

        // Mounts and chroot.
        pivot_root_to: None,
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
