//! Type definitions for NeoForge loader processing

// NeoForge uses the same installer profile format as Forge V2+
// Re-export from forge module to avoid duplication
pub use crate::forge::types::ForgeInstallerProfileV2 as NeoForgeInstallerProfile;
