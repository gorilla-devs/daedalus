//! Helper functions for Minecraft version processing
//!
//! This module contains utility functions used during version processing
//! to check library and version properties.

use daedalus::minecraft::Library;

/// Check if a library uses split natives
///
/// Whether `lib` is a split-natives library — one whose identifier starts with
/// `natives-` (e.g. `natives-linux`, `natives-windows`, `natives-osx`).
pub fn lib_is_split_natives(lib: &Library) -> bool {
    lib.name
        .identifier
        .as_ref()
        .is_some_and(|data| data.starts_with("natives-"))
}
