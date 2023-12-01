use c_str_macro::c_str;
use std::ffi::{CStr, CString};

/// A list of mounts to be carried out inside the child process.
#[derive(Debug, Clone)]
pub struct MountTable {
    /// The list of mounts.
    pub(crate) mounts: Vec<Mount>,

    /// The target prefix to prepend to each mount's target. By default, the empty string.
    target_prefix: Option<CString>,
}

/// Mount is a struct that represents a mount entry in the mount table.
#[derive(Debug, Clone)]
pub struct Mount {
    pub(crate) source: CString,
    pub(crate) target: CString,
    pub(crate) fstype: CString,
    pub(crate) flags: u64,
    pub(crate) data: Option<CString>,

    /// Before this mount is created, should we create a mountpoint for it?
    pub(crate) create_mountpoint: Option<MountpointType>,
}

/// The type of mountpoint to create.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountpointType {
    Dir,
    File,

    /// `stat()` the source of the mount, and use that type. Useful for bind mounts.
    DetermineFromSource,
}

impl Mount {
    /// Set whether we should create a mountpoint before mounting this mount.
    pub fn create_mountpoint(&mut self, mountpoint_type: MountpointType) -> &mut Self {
        self.create_mountpoint = Some(mountpoint_type);
        self
    }
}

impl Default for MountTable {
    fn default() -> Self {
        Self::new()
    }
}

impl MountTable {
    /// Creates an empty mount table.
    pub fn new() -> MountTable {
        MountTable {
            mounts: vec![],
            target_prefix: None,
        }
    }

    /// Creates a mount table with a target prefix.
    ///
    /// A target prefix will be automatically prepended to the `target` of each mount in the
    /// `MountTable`. This is useful if, for instance, the container will immediately chroot into this prefix.
    pub fn with_target_prefix(prefix: impl Into<CString>) -> MountTable {
        MountTable {
            mounts: vec![],
            target_prefix: Some(prefix.into()),
        }
    }

    /// Get the current target prefix.
    pub fn target_prefix(&self) -> Option<&CStr> {
        self.target_prefix.as_deref()
    }

    /// Adds a mount to the mount table.
    pub fn add_mount(
        &mut self,
        source: impl Into<CString>,
        target: impl Into<CString>,
        fstype: impl Into<CString>,
        flags: u64,
        data: Option<impl Into<CString>>,
    ) -> &mut Mount {
        // Concatenate target_prefix with target
        let prefixed_target: CString = match &self.target_prefix {
            Some(prefix) => {
                let mut new_target = prefix.clone().into_bytes();
                new_target.push(b'/');
                new_target.extend(target.into().as_bytes());
                CString::new(new_target)
                    .expect("impossible for target_prefix or target to contain a NUL")
            }
            None => target.into(),
        };

        let mount = Mount {
            source: source.into(),
            target: prefixed_target,
            fstype: fstype.into(),
            flags,
            data: data.map(|d| d.into()),
            create_mountpoint: None,
        };
        self.mounts.push(mount);
        self.mounts.last_mut().unwrap()
    }

    /// Adds a bind mount to the mount table.
    pub fn add_bind(
        &mut self,
        source: impl Into<CString>,
        target: impl Into<CString>,
    ) -> &mut Mount {
        self.add_mount(
            source,
            target,
            CString::new("<bind>").unwrap(),
            libc::MS_BIND | libc::MS_REC, // Always use a recursive bind mount.
            None::<CString>,
        )
        .create_mountpoint(MountpointType::DetermineFromSource)
    }

    /// Adds a tmpfs mount to the mount table.
    pub fn add_temp(&mut self, target: impl Into<CString>) {
        self.add_mount(
            CString::new("<dummy>").unwrap(),
            target,
            CString::new("tmpfs").unwrap(),
            0,
            None::<CString>,
        )
        .create_mountpoint(MountpointType::Dir);
    }

    /// Adds a procfs mount at `/proc`.
    pub fn add_proc(&mut self) {
        self.add_mount(
            CString::new("proc").unwrap(),
            CString::new("proc").unwrap(),
            CString::new("proc").unwrap(),
            0,
            None::<CString>,
        )
        .create_mountpoint(MountpointType::Dir);
    }

    /// Bind-mounts the host's `/sys` at `/sys`
    pub fn add_sys(&mut self) {
        self.add_bind(c_str!("/sys"), c_str!("/sys"))
            .create_mountpoint(MountpointType::Dir);
    }

    /// Remounts the root of the cgroup namespace at `/sys/fs/cgroup`
    pub fn add_sys_cgroup(&mut self) {
        self.add_temp(c_str!("/sys/fs/cgroup"));
        self.add_mount(
            CString::new("cgroup").unwrap(),
            CString::new("/sys/fs/cgroup").unwrap(),
            CString::new("cgroup2").unwrap(), // We use cgroups v2
            0,
            None::<CString>,
        );
    }
}
