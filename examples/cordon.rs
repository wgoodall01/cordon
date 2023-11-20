use c_str_macro::c_str;
use cordon::id_map::IdMap;
use cordon::mount_table::MountTable;
use std::ffi::CString;

use std::ptr;

pub fn main() {
    let _null_fd = unsafe { libc::open("/dev/null\0".as_ptr().cast(), libc::O_RDWR) };

    let target_uid = 0;
    let target_gid = 0;

    // Create the staging dir in some tmpfs on the host. We need an actual directory
    // somewhere, so that we can mount something (perhaps tmpfs) over it, create the rest of the mounts in that mount, and then pivot_root into it.
    std::fs::create_dir("/dev/shm/cordon_root")
        .or_else(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                Ok(())
            } else {
                Err(e)
            }
        })
        .unwrap();

    // Create a tmpfs on `/__cordon_root/`
    let mut mount_table = MountTable::with_target_prefix(c_str!("/dev/shm/cordon_root"));

    // Prevent any mountpoints from being created in /dev/shm/cordon_root.
    mount_table.add_temp(c_str!("/"));

    // Mount in _root
    mount_table.add_bind(
        CString::new(format!("{}/_root", env!("CARGO_MANIFEST_DIR"))).unwrap(),
        c_str!("/"),
    );

    // Mount /proc and /sys
    mount_table.add_proc();
    mount_table.add_sys();
    mount_table.add_sys_cgroup();

    let cmd_path = CString::new("/bin/sh").unwrap();

    let cmd = cordon::Command {
        command: cmd_path.as_ptr(),
        args: vec![cmd_path.as_ptr(), ptr::null()],
        envp: vec![b"ENVVAR=test\0".as_ptr(), ptr::null()],
        stdin_fd: None,
        stdout_fd: None,
        stderr_fd: None,
        namespaces: cordon::NamespaceSet {
            mount: true,
            pid: true,
            user: true,
            network: false,
            cgroup: true,
            ..Default::default()
        },
        set_uid: None,
        set_gid: None,
        uid_map: Some(IdMap::self_to_inner_uid(target_uid)),
        gid_map: Some(IdMap::self_to_inner_gid(target_gid)),
        pivot_root_to: Some(b"/dev/shm/cordon_root\0".as_ptr()),
        set_working_dir: None,
        mounts: mount_table,
        scope: Some(cordon::systemd::ScopeParameters {
            description: Some("Cordon example scope".to_string()),
            ..cordon::systemd::ScopeParameters::with_unique_name()
        }),
    };

    let child = unsafe { cordon::spawn(cmd) }.unwrap();

    let exit = child.wait().unwrap();
    eprintln!("exit={exit:?}");
    assert!(exit.success());
}
