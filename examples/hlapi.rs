use c_str_macro::c_str;
use cordon::{IdMap, MountTable};
use tracing::info;
mod common;

pub fn main() -> eyre::Result<()> {
    common::configure_logging();

    cordon::Command::new("/bin/sh")
        .env("ENVVAR", "Test env var")
        .arg("-c")
        .arg(r#"echo "Var is equal to $ENVVAR""#)
        .spawn()?
        .wait()?;

    cordon::Command::new("/bin/sh")
        .verbose(true)
        .env("ENVVAR", "test")
        .unshare(cordon::Namespace::User)
        .unshare(cordon::Namespace::Mount)
        .unshare(cordon::Namespace::Pid)
        .uid_map(IdMap::self_to_inner_uid(0))
        .gid_map(IdMap::self_to_inner_gid(0))
        .pivot_root_to("./local_chroot_jail")
        .mount_table({
            let mut mt = MountTable::with_target_prefix(c_str!("./local_chroot_jail"));
            mt.add_temp(c_str!("/tmp")); // Mount tmpfs on `/tmp`
            mt.add_proc(); // Mount procfs on `/proc`
            mt.add_sys(); // Bind-mount the host's `/sys` on `/sys`
            mt
        })
        .scope(cordon::systemd::ScopeParameters {
            description: Some("Isolated shell".into()),
            tasks_max: Some(8),
            memory_max: Some(1024 * 1024 * 1024),
            ..cordon::systemd::ScopeParameters::with_unique_name()
        })
        .spawn()?
        .wait()?;

    // Spawn the child process.
    let child = cmd.spawn()?;

    // Wait for the child to exit.
    let exit = child.wait()?;
    info!(?exit);
    Ok(())
}
