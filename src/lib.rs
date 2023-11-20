use alloc_counter::AllocCounterSystem;

pub mod error;
pub mod id_map;
mod libc_util;
pub mod mount_table;
pub mod spawn;
pub mod systemd;

/// In test builds, use alloc_counter to verify at runtime that the functions which must be
/// async-signal-safe do not allocate.
#[cfg_attr(debug_assertions, global_allocator)]
static ALLOC: AllocCounterSystem = AllocCounterSystem;
