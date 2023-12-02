use c_str_macro::c_str;
use cordon::{IdMap, MountTable};
use tracing::info;
mod common;

pub fn main() -> eyre::Result<()> {
    // common::configure_logging();

    let mut cmd = cordon::Command::new("/usr/bin/busybox");
    cmd.verbose(true);
    cmd.argv0("sh");
    cmd.args(&["-c", "echo 'Hello, World!'"]);

    // Spawn the child process.
    let child = cmd.spawn()?;

    // Wait for the child to exit.
    let exit = child.wait()?;
    info!(?exit);
    Ok(())
}
