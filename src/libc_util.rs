use alloc_counter::no_alloc;
use std::ffi::{c_char, c_int, c_void};
use std::mem;

use crate::error::{bail, bail_errno, Error, Result};

/// Get the topmost valid stack pointer inside a segment of stack memory.
#[cfg_attr(debug_assertions, no_alloc)]
pub unsafe fn get_topmost_stack_pointer(stack: &mut [u8]) -> *mut c_void {
    let top_addr = stack.as_mut_ptr().add(stack.len()) as *mut c_void;

    // Align downwards, multiple of 16.
    let top_addr = top_addr as usize & !0xf;

    top_addr as *mut c_void
}

/// Create a Unix stream socket pair.
#[cfg_attr(debug_assertions, no_alloc)]
pub fn socket_pair() -> Result<(c_int, c_int)> {
    // Create a socket pair, so we can signal the child to continue once we write the uid map,
    // disable setgroups, and write the gid map.
    let mut socket_fds = [0; 2];
    let 0.. =
        (unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, socket_fds.as_mut_ptr()) })
    else {
        bail_errno!("failed to create socketpair");
    };
    let [a, b] = socket_fds;
    Ok((a, b))
}

/// Send a value, interpretable as bytes, to a socket's file descriptor.
#[cfg_attr(debug_assertions, no_alloc)]
pub unsafe fn socket_send<T: Copy>(sock_fd: c_int, value: T) -> Result<()> {
    let size = mem::size_of::<T>();

    // Send the PID of the inner child to the parent.
    let result = libc::write(sock_fd, (&value) as *const T as *const c_void, size);

    if result == -1 {
        return Err(Error::last_os_error().cause("failed to send to socket"));
    }

    if (result as usize) != size {
        return Err(Error::new().cause("failed to send socket message in single write call"));
    }

    Ok(())
}

/// Receive a value, interpretable as bytes, from a socket's file descriptor.
#[cfg_attr(debug_assertions, no_alloc)]
pub unsafe fn socket_recv<T: Copy>(sock_fd: c_int) -> Result<T> {
    let size = mem::size_of::<T>();
    // assert!(size > 0, "cannot receive zero-sized type");

    let mut output_slot = mem::MaybeUninit::<T>::uninit();
    let result = libc::read(
        sock_fd,
        output_slot.as_mut_ptr().cast(),
        mem::size_of::<T>(),
    );

    if result == -1 {
        return Err(Error::last_os_error().cause("failed to receive from socket"));
    };

    if result == 0 {
        return Err(Error::new().cause("reached EOF while receiving from socket"));
    }

    if (result as usize) != size {
        return Err(Error::new().cause("failed to receive socket message in single read call"));
    }

    Ok(output_slot.assume_init())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitStatus {
    Code(c_int),
    Signal(c_int),
}

impl ExitStatus {
    pub fn from_wait_status(wait_status: c_int) -> Result<ExitStatus> {
        if libc::WIFEXITED(wait_status) {
            return Ok(ExitStatus::Code(libc::WEXITSTATUS(wait_status)));
        }
        if libc::WIFSIGNALED(wait_status) {
            return Ok(ExitStatus::Signal(libc::WTERMSIG(wait_status)));
        }

        bail!("invalid wait status")
    }

    pub fn success(&self) -> bool {
        matches!(self, ExitStatus::Code(0))
    }
}

#[cfg_attr(debug_assertions, no_alloc)]
pub unsafe fn waitpid(pid: c_int) -> Result<ExitStatus> {
    let mut status: c_int = 0;
    let 0.. = (unsafe { libc::waitpid(pid, &mut status as *mut c_int, 0) }) else {
        bail_errno!("waitpid failed");
    };
    ExitStatus::from_wait_status(status)
}

#[cfg_attr(debug_assertions, no_alloc)]
pub fn write_str(path: *const c_char, contents: *const c_char, flags: c_int) -> Result<()> {
    let fd @ 0.. = (unsafe { libc::open(path, flags) }) else {
        bail_errno!("failed to open file for writing");
    };

    // TODO: Can we avoid `strlen()` here?
    let len = unsafe { libc::strlen(contents) };

    let mut bytes_written = 0;
    while bytes_written < len {
        let bytes =
            unsafe { libc::write(fd, contents.add(bytes_written).cast(), len - bytes_written) };
        if bytes < 0 {
            bail_errno!("failed to write to file");
        }
        bytes_written += bytes as usize;
    }

    let 0.. = (unsafe { libc::close(fd) }) else {
        bail_errno!("failed to close file after writing");
    };

    Ok(())
}

#[cfg_attr(debug_assertions, no_alloc)]
pub fn stat(path: *const c_char) -> Result<libc::stat> {
    let mut stat_buf = mem::MaybeUninit::<libc::stat>::uninit();
    let 0.. = (unsafe { libc::stat(path, stat_buf.as_mut_ptr()) }) else {
        bail_errno!("failed to stat file");
    };
    Ok(unsafe { stat_buf.assume_init() })
}

/// Create a directory for all non-existent path components of `path`.
#[cfg_attr(debug_assertions, no_alloc)]
pub fn mkdirp(path: *const c_char) -> Result<()> {
    let mkdir_ignoring_eexist = |path: *const c_char| -> Result<()> {
        let mkdir_result = unsafe { libc::mkdir(path, 0o755) };
        if mkdir_result == -1 {
            let err = Error::last_os_error();
            if err.errno != libc::EEXIST {
                return Err(err.cause("failed to create directory"));
            }
        };
        Ok(())
    };

    // Error if the path is longer than PATH_MAX.
    let path_len = unsafe { libc::strlen(path) };
    if path_len > libc::PATH_MAX as usize {
        bail!("mkdirp() path is longer than PATH_MAX");
    }
    // Copy the path to a local buffer.
    let mut buf = [b'\0'; libc::PATH_MAX as usize + 1];
    buf[..path_len + 1].copy_from_slice(unsafe { std::slice::from_raw_parts(path, path_len + 1) });

    // Loop through indices of `/` characters in the buffer to create ancestors.
    for i in 1..buf.len() {
        if buf[i] == b'\0' {
            break;
        }
        if buf[i] != b'/' {
            continue;
        }

        // Replace the `/` with a null byte.
        buf[i] = b'\0';

        // Create the directory, ignoring EEXIST.
        mkdir_ignoring_eexist(buf.as_ptr())?;

        // Put the `/` back.
        buf[i] = b'/';
    }

    // Create the final directory.
    mkdir_ignoring_eexist(buf.as_ptr().cast())?;

    Ok(())
}
