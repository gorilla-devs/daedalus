//! Common utilities shared across loader implementations
//!
//! This module contains shared functionality used by multiple loader implementations
//! (Forge, NeoForge, etc.) to avoid code duplication.

pub mod cas;
pub mod change_detection;
pub mod manifest_merge;

// Re-export commonly used items for convenience
pub use cas::{build_cas_url, extract_hash_from_cas_url};
pub use change_detection::{detect_version_change, ChangeResult};
pub use manifest_merge::{
    merge_loader_versions, sort_by_minecraft_order, sort_loaders_by_metadata,
};
