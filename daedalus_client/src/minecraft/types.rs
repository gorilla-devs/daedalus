//! Type definitions for Minecraft version processing

use daedalus::minecraft::{Library, PartialLibrary};
use serde::Deserialize;

/// A library patch configuration for modifying or replacing libraries
#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LibraryPatch {
    #[serde(rename = "_comment")]
    pub _comment: String,
    #[serde(rename = "match")]
    pub match_: Vec<String>,
    pub additional_libraries: Option<Vec<Library>>,
    #[serde(rename = "override")]
    pub override_: Option<PartialLibrary>,
    pub patch_additional_libraries: Option<bool>,
}

/// Marker for LWJGL variant acceptance/rejection configuration
#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LWJGLVariantMarker {
    #[serde(rename = "match")]
    pub match_: String,
    #[serde(rename = "_comment")]
    pub _comment: String,
    pub reason: Option<String>,
}

/// Configuration for LWJGL variant filtering
#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LWJGLVariantConfig {
    pub accept: Vec<LWJGLVariantMarker>,
    pub reject: Vec<LWJGLVariantMarker>,
}
