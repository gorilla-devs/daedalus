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
