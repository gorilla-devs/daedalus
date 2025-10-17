//! Helper functions for Minecraft version processing
//!
//! This module contains utility functions used during version processing
//! to check library and version properties.

use daedalus::minecraft::{Library, Os, Rule, RuleAction, VersionInfo};

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

/// Check if a library's rules indicate it is macOS-only
///
/// A library is considered macOS-only if:
/// - It has rules that allow macOS (Os::Osx)
/// - It does NOT have rules that allow all platforms
///
/// # Arguments
/// - `rules`: The optional rules to check
///
/// # Returns
/// `true` if the rules indicate macOS-only, `false` otherwise
pub fn is_macos_only(rules: &Option<Vec<Rule>>) -> bool {
    let mut allows_osx = false;
    let mut allows_all = false;
    if let Some(rules) = rules {
        for rule in rules {
            if rule.action == RuleAction::Allow
                && rule.os.is_some()
                && rule
                    .os
                    .clone()
                    .expect("Unwrap to be safe with boolean short circuit")
                    .name
                    .is_some_and(|os| os == Os::Osx)
            {
                allows_osx = true;
            }
            if rule.action == RuleAction::Allow && rule.os.is_none() {
                allows_all = false;
            }
        }

        allows_osx && !allows_all
    } else {
        false
    }
}
