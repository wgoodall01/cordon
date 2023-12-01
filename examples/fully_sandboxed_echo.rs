use c_str_macro::c_str;
use cordon::{IdMap, MountTable};
use tracing::info;
mod common;

pub fn main() -> eyre::Result<()> {
    // common::configure_logging();

    let mut cmd = cordon::Command::new("/bin/sh");
    // cmd.verbose(true);
    cmd.env("ENVVAR", "test");
    cmd.args(&["-c", "echo 'Hello, World!'"]);
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
