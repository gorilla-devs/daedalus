//! Library patching system for Minecraft version processing
//!
//! This module handles loading and applying patches to library definitions,
//! allowing for overrides and additional libraries to be injected.

use crate::minecraft::types::LibraryPatch;
use daedalus::minecraft::{Library, LibraryDownloads, merge_partial_library};
use std::collections::HashMap;
use tracing::info;

/// A patch list pre-indexed by the library coordinates each patch matches.
///
/// Patches list maven coordinates in their `match` field. Looking patches up by
/// coord directly avoids scanning the whole patch list for every library.
pub struct LibraryPatchIndex {
    by_match: HashMap<String, Vec<usize>>,
    patches: Vec<LibraryPatch>,
    /// Indices of patches that matched at least one library since this index
    /// was built. Patch anchors are exact coordinate strings, so an upstream
    /// rename or reclassifier (e.g. a core jar gaining an `:unsafe`
    /// classifier) silently kills them — `never_matched` exposes the dead
    /// ones after a full reprocess.
    matched: dashmap::DashSet<usize>,
}

impl LibraryPatchIndex {
    pub fn new(patches: Vec<LibraryPatch>) -> Self {
        let mut by_match: HashMap<String, Vec<usize>> = HashMap::new();
        for (idx, patch) in patches.iter().enumerate() {
            for matched_coord in &patch.match_ {
                by_match.entry(matched_coord.clone()).or_default().push(idx);
            }
        }
        Self {
            by_match,
            patches,
            matched: dashmap::DashSet::new(),
        }
    }

    fn patches_for(&self, coord: &str) -> Vec<&LibraryPatch> {
        self.by_match
            .get(coord)
            .map(|indices| {
                indices
                    .iter()
                    .map(|&i| {
                        self.matched.insert(i);
                        &self.patches[i]
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Patches whose anchors matched no library so far. Only meaningful after
    /// a FULL reprocess of every version — on incremental cycles most patches
    /// legitimately go unexercised because their versions were skip-reused.
    pub fn never_matched(&self) -> Vec<&LibraryPatch> {
        self.patches
            .iter()
            .enumerate()
            .filter(|(i, _)| !self.matched.contains(i))
            .map(|(_, p)| p)
            .collect()
    }
}

/// Apply library patches recursively
///
/// Patches can:
/// - Override library properties
/// - Add additional libraries
/// - Recursively patch the additional libraries
pub fn patch_library(
    patches: &LibraryPatchIndex,
    mut library: Library,
) -> Vec<Library> {
    let mut val = Vec::new();

    let actual_patches = patches.patches_for(&library.name.to_string());

    if !actual_patches.is_empty() {
        for patch in actual_patches {
            info!(
                "patching {} with library patch {}",
                library.name, patch._comment
            );

            if let Some(override_) = &patch.override_ {
                library = merge_partial_library(override_.clone(), library);
            }

            if let Some(additional_libraries) = &patch.additional_libraries {
                for additional_library in additional_libraries {
                    if patch.patch_additional_libraries.unwrap_or(false) {
                        // Recursive patching
                        let mut libs =
                            patch_library(patches, additional_library.clone());
                        val.append(&mut libs)
                    } else {
                        let mut new_lib = additional_library.clone();
                        new_lib.patched = true;
                        val.push(new_lib);
                    }
                }
            }
        }

        val.push(library);
    } else {
        val.push(library);
    }

    val
}

/// Fetch library patches from embedded JSON file
pub async fn get_library_patches()
-> Result<LibraryPatchIndex, crate::infrastructure::error::Error> {
    let patches = include_bytes!("../../patched-library-patches.json");
    let unprocessed_patches: Vec<LibraryPatch> =
        serde_json::from_slice(patches)?;
    let processed: Vec<LibraryPatch> =
        unprocessed_patches.iter().map(pre_process_patch).collect();
    Ok(LibraryPatchIndex::new(processed))
}

/// Expand the `${BASE_URL}` placeholder in a patch URL.
///
/// The mirrored maven artifacts are published under the CAS-versioned prefix, so
/// the placeholder expands to the versioned base for those URLs. Expanding it
/// here rather than writing the version into the patch file keeps the committed
/// JSON correct across a CAS_VERSION bump, and leaves URLs that merely contain
/// the word "maven" — upstream repo1.maven.org entries — untouched.
fn expand_base_url(url: &str) -> String {
    let base = crate::common::BASE_URL.as_str();
    url.replace(
        "${BASE_URL}/maven/",
        &format!("{base}/v{}/maven/", crate::services::cas::CAS_VERSION),
    )
    .replace("${BASE_URL}", base)
}

/// Pre-process a patch by replacing ${BASE_URL} placeholders
fn pre_process_patch(patch: &LibraryPatch) -> LibraryPatch {
    fn patch_url(url: &mut String) {
        *url = expand_base_url(url);
    }

    fn patch_downloads(downloads: &mut LibraryDownloads) {
        if let Some(artifact) = downloads.artifact.as_mut() {
            if let Some(url) = artifact.url.as_mut() {
                patch_url(url);
            }
        }
        if let Some(classifiers) = downloads.classifiers.as_mut() {
            for (_, artifact) in classifiers.iter_mut() {
                if let Some(url) = artifact.url.as_mut() {
                    patch_url(url);
                }
            }
        }
    }

    let mut patch_copy: LibraryPatch = patch.clone();
    if let Some(libraries) = patch_copy.additional_libraries.as_mut() {
        for lib in libraries.iter_mut() {
            if let Some(downloads) = lib.downloads.as_mut() {
                patch_downloads(downloads);
            }
        }
    }
    if let Some(override_) = patch_copy.override_.as_mut() {
        if let Some(url) = override_.url.as_mut() {
            patch_url(url);
        }
        if let Some(downloads) = override_.downloads.as_mut() {
            patch_downloads(downloads);
        }
    }
    patch_copy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mirrored_maven_url_gets_the_cas_versioned_prefix() {
        // The mirror is uploaded under v{CAS_VERSION}/maven/, so a patch URL
        // that resolves to it has to carry the same prefix or 404.
        let base = crate::common::BASE_URL.as_str();
        let version = crate::services::cas::CAS_VERSION;

        assert_eq!(
            expand_base_url(
                "${BASE_URL}/maven/org/lwjgl/lwjgl/3.3.3/lwjgl-3.3.3.jar"
            ),
            format!(
                "{base}/v{version}/maven/org/lwjgl/lwjgl/3.3.3/lwjgl-3.3.3.jar"
            )
        );
    }

    #[test]
    fn a_placeholder_outside_the_mirror_expands_to_the_bare_base() {
        let base = crate::common::BASE_URL.as_str();

        assert_eq!(
            expand_base_url("${BASE_URL}/something-else.json"),
            format!("{base}/something-else.json")
        );
    }

    #[test]
    fn an_upstream_maven_url_is_left_alone() {
        // Contains "maven" but no placeholder: rewriting it would point a
        // patched library at our CDN for an artifact we never mirrored.
        let upstream = "https://repo1.maven.org/maven2/org/x/1.0/x-1.0.jar";

        assert_eq!(expand_base_url(upstream), upstream);
    }
}
