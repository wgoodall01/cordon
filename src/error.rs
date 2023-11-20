use alloc_counter::no_alloc;
use std::ffi::c_int;

/// Result type for our error type.
pub type Result<T> = std::result::Result<T, Error>;

/// An error type which can track cause (reason the error happened) and context (what we were
/// doing when the error happened) without allocating.
#[derive(Debug, Clone, Copy)]
pub struct Error {
    pub errno: c_int,
    pub cause: Option<&'static str>,
    pub context: Option<&'static str>,
}

impl Error {
    /// Create an empty error.
    #[cfg_attr(debug_assertions, no_alloc)]
    pub fn new() -> Error {
        Error {
            errno: 0,
            cause: None,
            context: None,
        }
    }

    /// Create an error from the last OS error.
    #[cfg_attr(debug_assertions, no_alloc)]
    pub fn last_os_error() -> Error {
        Error {
            errno: unsafe { *libc::__errno_location() },
            cause: None,
            context: None,
        }
    }

    /// Replace the cause of an error.
    #[cfg_attr(debug_assertions, no_alloc)]
    pub fn cause(self, msg: &'static str) -> Error {
        Error {
            errno: self.errno,
            cause: Some(msg),
            context: self.context,
        }
    }

    /// Replace the context of an error.
    #[cfg_attr(debug_assertions, no_alloc)]
    pub fn context(self, msg: &'static str) -> Error {
        Error {
            errno: self.errno,
            cause: self.cause,
            context: Some(msg),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        Error {
            errno: e.raw_os_error().unwrap_or(0),
            cause: None,
            context: None,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        // Get the error message from errno.
        let error_msg = unsafe { libc::strerror(self.errno) };
        let error_msg_len = unsafe { libc::strlen(error_msg) };
        let error_msg_str: &str = unsafe {
            std::str::from_utf8_unchecked(std::slice::from_raw_parts(
                error_msg as *const u8,
                error_msg_len,
            ))
        };

        match (self.context, self.cause) {
            (Some(context), None) => {
                write!(f, "{}: {} (errno {})", context, error_msg_str, self.errno)
            }
            (None, Some(cause)) => write!(f, "{}: {} (errno {})", cause, error_msg_str, self.errno),
            (Some(context), Some(cause)) => write!(
                f,
                "{}: {}: {} (errno {})",
                context, cause, error_msg_str, self.errno
            ),
            (None, None) => write!(f, "{} (errno {})", error_msg_str, self.errno),
        }
    }
}

// Define a macro, bail!, which returns an error with no errno and a custom message.
macro_rules! bail {
    ($msg:expr) => {
        return Err(Error {
            errno: 0,
            cause: Some($msg),
            context: None,
        })
    };
}
pub(crate) use bail;

// Define a macro, bail_errno!, which returns an error with the last OS error:
//
// - `bail_errno!()` returns an error with the last OS error.
// - `bail_errno!(msg)` returns an error with the last OS error and a context message.
macro_rules! bail_errno {
    () => {
        return Err(Error::last_os_error());
    };
    ($msg:expr) => {
        return Err(Error::last_os_error().cause($msg));
    };
}
pub(crate) use bail_errno;
