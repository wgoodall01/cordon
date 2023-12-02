mod common;

pub fn main() -> eyre::Result<()> {
    // common::configure_logging();

    let mut cmd = std::process::Command::new("/usr/bin/busybox");
    cmd.args(&["sh", "-c", "echo 'Hello, World!'"]);

    // Spawn the child process.
    let mut child = cmd.spawn()?;

    // Wait for the child to exit.
    let _exit = child.wait()?;

    Ok(())
}
