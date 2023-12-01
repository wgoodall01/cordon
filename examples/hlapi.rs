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

    let mut cmd = cordon::Command::new("/bin/sh");
    cmd.verbose(true);
    cmd.env("ENVVAR", "test");
    cmd.unshare(cordon::Namespace::User);
    cmd.unshare(cordon::Namespace::Mount);
    cmd.unshare(cordon::Namespace::Pid);
    cmd.uid_map(IdMap::self_to_inner_uid(0));
    cmd.gid_map(IdMap::self_to_inner_gid(0));
    cmd.pivot_root_to("./_root");
    cmd.mount_table({
        let mut mt = MountTable::with_target_prefix(c_str!("./_root"));

        mt.add_temp(c_str!("/tmp")); // Mount tmpfs on `/tmp`
        mt.add_proc(); // Mount procfs on `/proc`
        mt.add_sys(); // Bind-mount the host's `/sys` on `/sys`

        // Pass throuch the host's desktop folder to the guest.
        mt.add_bind(c_str!("/home/wgoodall01/Desktop"), c_str!("/host_desktop"));

        mt
    });
    cmd.scope(cordon::systemd::ScopeParameters {
        description: Some("Cordon demo number six!".into()),
        tasks_max: Some(8),
        memory_max: Some(1024 * 1024 * 1024),
        ..cordon::systemd::ScopeParameters::with_unique_name()
    });

    // Spawn the child process.
    let child = cmd.spawn()?;

    // Wait for the child to exit.
    let exit = child.wait()?;
    info!(?exit);
    Ok(())
}
