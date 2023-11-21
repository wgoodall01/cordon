use alloc_counter::AllocCounterSystem;

mod libc_util;

pub mod error;
pub mod id_map;
pub mod mount_table;
pub mod spawn;
pub mod systemd;

pub use id_map::IdMap;
pub use mount_table::MountTable;
pub use spawn::{spawn, Context, NamespaceSet, Child};

/// In test builds, use alloc_counter to verify at runtime that the functions which must be
/// async-signal-safe do not allocate.
#[cfg_attr(debug_assertions, global_allocator)]
static ALLOC: AllocCounterSystem = AllocCounterSystem;
