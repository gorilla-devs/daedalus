//! Library patching system for Minecraft version processing
//!
//! This module handles loading and applying patches to library definitions,
//! allowing for overrides and additional libraries to be injected.

use crate::minecraft::types::LibraryPatch;
use daedalus::minecraft::{merge_partial_library, Library, LibraryDownloads};
use tracing::info;

/// Apply library patches recursively
///
/// Patches can:
/// - Override library properties
/// - Add additional libraries
/// - Recursively patch the additional libraries
pub fn patch_library(patches: &[LibraryPatch], mut library: Library) -> Vec<Library> {
    let mut val = Vec::new();

    let actual_patches = patches
        .iter()
        .filter(|x| x.match_.contains(&library.name.to_string()))
        .collect::<Vec<_>>();

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
                        let mut libs = patch_library(patches, additional_library.clone());
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
pub async fn get_library_patches(
) -> Result<Vec<LibraryPatch>, crate::infrastructure::error::Error> {
    let patches = include_bytes!("../../patched-library-patches.json");
    let unprocessed_patches: Vec<LibraryPatch> = serde_json::from_slice(patches)?;
    Ok(unprocessed_patches.iter().map(pre_process_patch).collect())
}

/// Pre-process a patch by replacing ${BASE_URL} placeholders
fn pre_process_patch(patch: &LibraryPatch) -> LibraryPatch {
    fn patch_url(url: &mut String) {
        *url = url.replace(
            "${BASE_URL}",
            &dotenvy::var("BASE_URL").expect("BASE_URL must be set"),
        );
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
