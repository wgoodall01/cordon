use cordon::id_map::IdMap;
use std::ffi::CString;

use std::ptr;

pub fn main() {
    let cmd_path = CString::new("/usr/bin/sh").unwrap();

    let _null_fd = unsafe { libc::open("/dev/null\0".as_ptr().cast(), libc::O_RDWR) };

    let target_uid = 0;
    let target_gid = 4242;

    let cmd = cordon::Command {
        enter_user_namespace: true,
        enter_mount_namespace: true,
        command: cmd_path.as_ptr(),
        args: vec![cmd_path.as_ptr(), ptr::null()],
        envp: vec![ptr::null()],
        stdin_fd: None,
        stdout_fd: None,
        stderr_fd: None,
        set_uid: None,
        set_gid: None,
        uid_map: Some(IdMap::self_to_inner_uid(target_uid)),
        gid_map: Some(IdMap::self_to_inner_gid(target_gid)),
    };

    let child = unsafe { cordon::spawn(cmd) }.unwrap();

    // Wait a bit so the logs can sort themselves out
    std::thread::sleep(std::time::Duration::from_millis(100));

    let exit = child.wait().unwrap();
    eprintln!("exit={exit:?}");
    assert!(exit.success());
}
