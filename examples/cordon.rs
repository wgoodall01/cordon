use std::ffi::CString;

use std::ptr;

pub fn main() {
    let cmd_path = CString::new("/usr/bin/sh").unwrap();

    let _null_fd = unsafe { libc::open("/dev/null\0".as_ptr().cast(), libc::O_RDWR) };

    let target_uid = 0;
    let target_gid = 0;

    // Map current user/group to root.
    let uid = unsafe { libc::getuid() };
    let mut uid_map = cordon::id_map::IdMap::new();
    uid_map.map_one(uid, target_uid);

    // Map current user/group to root.
    let gid = unsafe { libc::getgid() };
    let mut gid_map = cordon::id_map::IdMap::new();
    gid_map.map_one(gid, target_gid);

    let cmd = cordon::Command {
        enter_user_namespace: true,
        command: cmd_path.as_ptr(),
        args: vec![cmd_path.as_ptr(), ptr::null()],
        envp: vec![ptr::null()],
        stdin_fd: None,
        stdout_fd: None,
        stderr_fd: None,
        uid_map: Some(uid_map),
        gid_map: Some(gid_map),
        uid: Some(target_uid),
        gid: Some(target_gid),
    };

    let child = unsafe { cordon::spawn(cmd) }.unwrap();

    // Wait a bit so the logs can sort themselves out
    std::thread::sleep(std::time::Duration::from_millis(100));

    let exit = child.wait().unwrap();
    eprintln!("exit={exit:?}");
    assert!(exit.success());
}
