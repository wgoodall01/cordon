use std::collections::BTreeMap;
use std::ffi::{c_char, CString};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::ptr;

use crate::error::{bail, Error, Result};
use crate::{libc_util, spawn, systemd};
use crate::{IdMap, MountTable, NamespaceSet};

/// A command to be launched within the cordon.
pub struct Command {
    // Exec information
    command: String,
    args: Vec<String>,
    env: BTreeMap<String, Option<String>>,
    inherit_parent_env: bool,

    // Stdio redirection.
    stdin: Option<OwnedFd>,
    stdout: Option<OwnedFd>,
    stderr: Option<OwnedFd>,

    // Namespace information.
    namespaces: NamespaceSet,

    // User and group information.
    uid_map: Option<IdMap>,
    gid_map: Option<IdMap>,
    set_uid: Option<u32>,
    set_gid: Option<u32>,

    // Roots, mounts, working directory.
    pivot_root_to: Option<String>,
    set_working_dir: Option<PathBuf>,
    mounts: MountTable,

    // Systemd integratieo, if configured.
    scope: Option<systemd::ScopeParameters>,

    forward_spawn_logs: bool,
}

/// A handle to a cordoned child process.
pub struct Child(spawn::Child);

/// The exit status of a child process.
#[derive(Debug, Clone, Copy)]
pub struct ExitStatus(libc_util::ExitStatus);

#[derive(Debug, Clone, Copy)]
pub enum Namespace {
    Cgroup,
    Ipc,
    Network,
    Mount,
    Pid,
    User,
    Uts,
}

impl Command {
    /// Create a new command.
    pub fn new(program: impl AsRef<str>) -> Command {
        Command {
            command: program.as_ref().to_owned(),
            args: vec![program.as_ref().to_owned()],
            env: BTreeMap::new(),
            inherit_parent_env: false,
            stdin: None,
            stdout: None,
            stderr: None,
            namespaces: NamespaceSet::default(),
            uid_map: None,
            gid_map: None,
            set_uid: None,
            set_gid: None,
            pivot_root_to: None,
            set_working_dir: None,
            mounts: MountTable::default(),
            scope: None,
            forward_spawn_logs: false,
        }
    }

    /// Enable verbose logging to `tracing`.
    pub fn verbose(&mut self, enabled: bool) -> &mut Command {
        self.forward_spawn_logs = enabled;
        self
    }

    /// Set the contents of `argv[0]`.
    pub fn argv0(&mut self, argv0: impl AsRef<str>) -> &mut Command {
        self.args[0] = argv0.as_ref().to_owned();
        self
    }

    /// Append an argument.
    pub fn arg(&mut self, arg: impl AsRef<str>) -> &mut Command {
        self.args.push(arg.as_ref().to_owned());
        self
    }

    /// Append several arguments.
    pub fn args(&mut self, args: impl IntoIterator<Item = impl AsRef<str>>) -> &mut Command {
        self.args
            .extend(args.into_iter().map(|e| e.as_ref().to_owned()));
        self
    }

    /// Override the working directory of the process.
    pub fn current_dir(&mut self, path: impl AsRef<Path>) -> &mut Command {
        self.set_working_dir = Some(path.as_ref().into());
        self
    }

    /// Set the value of an environment variable in the child.
    pub fn env(&mut self, key: impl AsRef<str>, value: impl AsRef<str>) -> &mut Command {
        let key = key.as_ref().to_owned();
        let value = value.as_ref().to_owned();
        self.env.insert(key, Some(value));
        self
    }

    /// Clear all environment variables, and prevent the child from inheriting the
    /// parent's environment.
    pub fn env_clear(&mut self) -> &mut Command {
        self.inherit_parent_env = false;
        self.env = BTreeMap::new();
        self
    }

    /// Explicitly removes an environment variable, preventing it from being inherited
    /// from the parent's environment.
    pub fn env_remove(&mut self, key: impl AsRef<str>) -> &mut Command {
        self.env.insert(key.as_ref().to_owned(), None);
        self
    }

    /// Sets several environment variables.
    pub fn envs(
        &mut self,
        envs: impl IntoIterator<Item = (impl AsRef<str>, impl AsRef<str>)>,
    ) -> &mut Command {
        let envs_iter = envs
            .into_iter()
            .map(|(k, v)| (k.as_ref().to_owned(), Some(v.as_ref().to_owned())));
        self.env.extend(envs_iter);
        self
    }

    /// Configures the child's stdout stream.
    pub fn stdout(&mut self, stream: impl Into<OwnedFd>) -> &mut Command {
        self.stdout = Some(stream.into());
        self
    }

    /// Configures the child's stderr stream.
    pub fn stderr(&mut self, stream: impl Into<OwnedFd>) -> &mut Command {
        self.stderr = Some(stream.into());
        self
    }

    /// Configures the child's stdin stream.
    pub fn stdin(&mut self, stream: impl Into<OwnedFd>) -> &mut Command {
        self.stdin = Some(stream.into());
        self
    }

    /// Unshares a namespace in the child process.
    pub fn unshare(&mut self, namespace: Namespace) -> &mut Command {
        match namespace {
            Namespace::Cgroup => self.namespaces.cgroup = true,
            Namespace::Ipc => self.namespaces.ipc = true,
            Namespace::Network => self.namespaces.network = true,
            Namespace::Mount => self.namespaces.mount = true,
            Namespace::Pid => self.namespaces.pid = true,
            Namespace::User => self.namespaces.user = true,
            Namespace::Uts => self.namespaces.uts = true,
        };
        self
    }

    /// Sets the user ID mapping and enables writing the `uid_map`.
    pub fn uid_map(&mut self, map: IdMap) -> &mut Command {
        self.uid_map = Some(map);
        self
    }

    /// Sets the group ID mapping and enables writing the `gid_map`.
    pub fn gid_map(&mut self, map: IdMap) -> &mut Command {
        self.gid_map = Some(map);
        self
    }

    /// Sets the user ID of the child process, and enables setting `uid`.
    pub fn uid(&mut self, uid: u32) -> &mut Command {
        self.set_uid = Some(uid);
        self
    }

    /// Sets the group ID of the child process, and enables setting `gid`.
    pub fn gid(&mut self, gid: u32) -> &mut Command {
        self.set_gid = Some(gid);
        self
    }

    /// Sets the root directory of the child process, and enables pivoting root.
    pub fn pivot_root_to(&mut self, path: impl AsRef<str>) -> &mut Command {
        self.pivot_root_to = Some(path.as_ref().to_owned());
        self
    }

    /// Sets the working directory of the child process, and enables changing the working
    /// directory.
    pub fn working_dir(&mut self, path: impl AsRef<Path>) -> &mut Command {
        self.set_working_dir = Some(path.as_ref().into());
        self
    }

    /// Sets the mount table used by the child process.
    pub fn mount_table(&mut self, mounts: MountTable) -> &mut Command {
        self.mounts = mounts;
        self
    }

    /// Configures a systemd scope for the child process.
    pub fn scope(&mut self, params: systemd::ScopeParameters) -> &mut Command {
        self.scope = Some(params);
        self
    }

    /// Returns an iterator over the arguments passed to the program.
    pub fn get_args(&self) -> impl Iterator<Item = &str> {
        self.args.iter().map(|e| e.as_str())
    }

    /// Returns the working directory set for the child process. Returns None if the
    /// working directory will not be changed.
    pub fn get_current_dir(&self) -> Option<&Path> {
        self.set_working_dir.as_ref().map(|e| e.as_path())
    }

    /// Returns the environment variables being passed to the child program.
    pub fn get_envs(&self) -> impl Iterator<Item = (&str, Option<&str>)> {
        self.env
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_ref().map(|e| e.as_str())))
    }

    /// Gets the executable name.
    pub fn get_program(&self) -> &str {
        self.command.as_str()
    }

    /// Executes a command as a child process, waiting for it to finish and collecting
    /// its status.
    pub fn status(self) -> Result<ExitStatus> {
        let child = self.spawn()?;
        Ok(child.wait()?)
    }

    /// Spawn the subprocess, and return a handle to it.
    pub fn spawn(self) -> Result<Child> {
        // Null-terminate the command.
        let Ok(command) = CString::new(self.command) else {
            bail!("command contains an interior NUL");
        };

        // Collect the arguments.
        let args_buf = self
            .args
            .into_iter()
            .map(|e| {
                CString::new(e).map_err(|_| Error::new().cause("argument contains internal NUL"))
            })
            .collect::<Result<Vec<_>>>()?;
        let mut args: Vec<*const c_char> = args_buf.iter().map(|a| a.as_ptr()).collect();
        args.push(ptr::null());

        // Collect the environment variables.
        let mut env_map: BTreeMap<CString, CString> = std::env::vars_os()
            .into_iter()
            .map(|(k, v)| -> Result<_> {
                let k = CString::new(k.into_vec())
                    .map_err(|_| Error::new().cause("existing env contains internal NUL"))?;
                let v = CString::new(v.into_vec())
                    .map_err(|_| Error::new().cause("existing env contains internal NUL"))?;
                Ok((k, v))
            })
            .collect::<Result<_>>()?;
        for var in self.env {
            match var {
                (k, Some(v)) => {
                    let k = CString::new(k)
                        .map_err(|_| Error::new().cause("env key contains internal NUL"))?;
                    let v = CString::new(v)
                        .map_err(|_| Error::new().cause("env key contains internal NUL"))?;
                    env_map.insert(k, v);
                }
                (k, None) => {
                    let k = CString::new(k)
                        .map_err(|_| Error::new().cause("env key contains internal NUL"))?;
                    env_map.remove(&k);
                }
            };
        }
        let envp_buf = env_map
            .into_iter()
            .map(|(k, v)| {
                let mut kv = vec![];
                kv.extend(k.into_bytes());
                kv.push('=' as u8);
                kv.extend(v.into_bytes());
                CString::new(kv).unwrap()
            })
            .collect::<Vec<_>>();
        let mut envp = envp_buf.iter().map(|e| e.as_ptr()).collect::<Vec<_>>();
        envp.push(ptr::null());

        let pivot_root_buf = self.pivot_root_to.map(|e| CString::new(e).unwrap());
        let pivot_root_to = pivot_root_buf.as_ref().map(|e| e.as_ptr());

        // convert pathbuf to *const c_char
        let set_working_dir_buf = self
            .set_working_dir
            .map(|e| CString::new(e.into_os_string().into_vec()).unwrap());
        let set_working_dir = set_working_dir_buf.as_ref().map(|e| e.as_ptr());

        // Set up the context.
        let ctx = spawn::Context {
            command: command.as_ptr(),
            args,
            envp,
            stdin_fd: self.stdin.map(|fd| fd.as_raw_fd()),
            stdout_fd: self.stdout.map(|fd| fd.as_raw_fd()),
            stderr_fd: self.stderr.map(|fd| fd.as_raw_fd()),
            namespaces: self.namespaces,
            uid_map: self.uid_map,
            gid_map: self.gid_map,
            set_uid: self.set_uid,
            set_gid: self.set_gid,
            pivot_root_to,
            set_working_dir,
            mounts: self.mounts,
            scope: self.scope,
            forward_spawn_logs: self.forward_spawn_logs,
        };

        // Spawn the child.
        let child = unsafe { spawn::spawn(ctx)? };

        Ok(Child(child))
    }
}

impl Child {
    pub fn wait(self) -> Result<ExitStatus> {
        Ok(ExitStatus(self.0.wait()?))
    }
}
