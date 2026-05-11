//! Helper functions for Minecraft version processing
//!
//! This module contains utility functions used during version processing
//! to check library and version properties.

use daedalus::minecraft::{Library, VersionInfo};

/// Check if a library uses split natives
///
/// Split natives are identified by an identifier starting with "natives-"
/// (e.g., "natives-linux", "natives-windows", "natives-osx")
///
/// # Arguments
/// - `lib`: The library to check
///
/// # Returns
/// `true` if the library has a split natives identifier, `false` otherwise
pub fn lib_is_split_natives(lib: &Library) -> bool {
    lib.name
        .identifier
        .as_ref()
        .is_some_and(|data| data.starts_with("natives-"))
}

/// Check if a Minecraft version has any libraries with split natives
///
/// # Arguments
/// - `ver`: The version info to check
///
/// # Returns
/// `true` if any library in the version has split natives, `false` otherwise
pub fn version_has_split_natives(ver: &VersionInfo) -> bool {
    ver.libraries.iter().any(lib_is_split_natives)
}

