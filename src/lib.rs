mod libc_util;

mod error;
mod id_map;
mod mount_table;
mod spawn;
pub mod systemd;

mod command;

pub use id_map::IdMap;
pub use mount_table::MountTable;
pub use spawn::{spawn, Context, NamespaceSet};

pub use command::{Child, Command, Namespace, ExitStatus};

/// In test builds, use alloc_counter to verify at runtime that the functions which must be
/// async-signal-safe do not allocate.
#[cfg(debug_assertions)]
#[global_allocator]
static ALLOC: alloc_counter::AllocCounterSystem = alloc_counter::AllocCounterSystem;
