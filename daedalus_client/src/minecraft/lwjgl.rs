//! LWJGL variant processing and validation system
//!
//! This module handles:
//! - Processing LWJGL variant libraries
//! - Validating native classifiers for different operating systems
//! - Managing LWJGL version variants across Minecraft versions
//! - Filtering and identifying compatible LWJGL configurations

use crate::minecraft::library_patches::patch_library;
use crate::minecraft::types::{LibraryPatch, LWJGLVariantConfig};
use daedalus::minecraft::{Dependency, LWJGLEntry, LibraryGroup, Os};
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

/// Process a single LWJGL variant and validate its structure
///
/// This function:
/// 1. Applies library patches to the variant
/// 2. Sets up LWJGL 2 vs LWJGL 3 configuration with conflicts
/// 3. Filters out unneeded libraries (jutils, jinput for LWJGL 3)
/// 4. Validates native classifiers for all platforms (Linux, Windows, macOS)
///
/// # Arguments
/// - `variant`: The LWJGL library group to process
/// - `patches`: Library patches to apply
///
/// # Returns
/// - `Ok(Some((path, library_group)))` if the variant is valid and should be uploaded
/// - `Ok(None)` if the variant is invalid (missing classifiers or downloads)
/// - `Err` if an unknown LWJGL version is encountered
pub fn process_single_lwjgl_variant(
    variant: &LibraryGroup,
    patches: &Vec<LibraryPatch>,
) -> Result<Option<(String, LibraryGroup)>, crate::infrastructure::error::Error> {
    let lwjgl_version = variant.version.clone();

    info!("Processing LWJGL variant {}", lwjgl_version);

    let mut lwjgl = variant.clone();

    let mut new_libraries = Vec::new();

    for library in lwjgl.libraries.clone() {
        let mut libs = patch_library(patches, library);
        new_libraries.append(&mut libs);
    }
    lwjgl.libraries = new_libraries;

    let version_path = if lwjgl_version.starts_with("2") {
        lwjgl.id = "LWJGL 2".to_string();
        lwjgl.uid = "org.lwjgl2".to_string();
        lwjgl.conflicts = Some(vec![Dependency {
            name: "lwjgl".to_string(),
            uid: "org.lwjgl3".to_string(),
            rule: None,
        }]);

        format!(
            "minecraft/v{}/libraries/org.lwjgl2/{}.json",
            daedalus::minecraft::CURRENT_FORMAT_VERSION,
            lwjgl_version
        )
    } else if lwjgl_version.starts_with('3') {
        lwjgl.id = "LWJGL 3".to_string();
        lwjgl.uid = "org.lwjgl3".to_string();
        lwjgl.conflicts = Some(vec![Dependency {
            name: "lwjgl".to_string(),
            uid: "org.lwjgl2".to_string(),
            rule: None,
        }]);

        let unneeded: HashSet<&str> = vec!["jutils", "jinput"].into_iter().collect();
        let filtered_libs = lwjgl
            .libraries
            .into_iter()
            .filter(|lib| !unneeded.contains(lib.name.artifact.as_str()))
            .collect::<Vec<_>>();
        lwjgl.libraries = filtered_libs;

        format!(
            "minecraft/v{}/libraries/org.lwjgl3/{}.json",
            daedalus::minecraft::CURRENT_FORMAT_VERSION,
            lwjgl_version
        )
    } else {
        return Err(crate::infrastructure::error::invalid_input(format!(
            "Unknown LWJGL version {}",
            lwjgl_version
        )));
    };

    let mut good = true;
    for lib in &lwjgl.libraries {
        if lib.patched {
            continue;
        }
        if let Some(natives) = &lib.natives {
            let checked: HashSet<&Os> = vec![&Os::Linux, &Os::Windows, &Os::Osx]
                .into_iter()
                .collect();
            if !checked.is_subset(&natives.clone().keys().collect()) {
                warn!(
                    "LWJGL variant library missing system classifier: {} {} {:?}",
                    lwjgl.version,
                    lib.name,
                    natives.keys()
                );
                good = false;
                break;
            }
            if lib.downloads.is_some() {
                if let Some(classifiers) = &lib
                    .downloads
                    .clone()
                    .expect("Unwrap to be safe inside is_some")
                    .classifiers
                {
                    for entry in checked {
                        let baked_entry = natives.get(entry);
                        if let Some(baked_entry) = baked_entry {
                            if !classifiers.contains_key(baked_entry) {
                                warn!(
                                    "LWJGL variant library missing download for classifier: {} {} {:?} {:?}",
                                    lwjgl.version,
                                    lib.name,
                                    baked_entry,
                                    classifiers.keys().collect::<Vec<_>>()
                                );
                                good = false;
                                break;
                            }
                        }
                    }
                } else {
                    warn!(
                        "LWJGL variant library missing downloads classifiers: {} {}",
                        lwjgl.version, lib.name
                    );
                    good = false;
                    break;
                }
            }
        }
    }
    if good {
        Ok(Some((version_path, lwjgl)))
    } else {
        Ok(None)
    }
}

/// Add an LWJGL version to the variants collection
///
/// This function tracks different LWJGL variants (with the same version but different
/// library configurations) and updates release times as newer variants are discovered.
///
/// # Arguments
/// - `variants_mutex`: Shared map of LWJGL version to variant entries
/// - `lwjgl`: The library group to add as a variant
pub async fn add_lwjgl_version(
    variants_mutex: Arc<Mutex<BTreeMap<String, Vec<LWJGLEntry>>>>,
    lwjgl: &LibraryGroup,
) {
    let mut lwjgl_copy = lwjgl.clone();
    lwjgl_copy.libraries.sort_by(|x, y| x.name.cmp(&y.name));

    let entry = LWJGLEntry::from_group(lwjgl_copy);
    let current_sha1 = entry.sha1.clone();
    let version = entry.group.version.clone();
    let mut found = false;

    let mut version_variants = variants_mutex.lock().await;

    let variants = version_variants
        .entry(version.clone())
        .or_insert_with(Vec::new);
    for variant in variants.iter_mut() {
        if entry.sha1 == variant.sha1 {
            found = true;
            if entry.group.release_time > variant.group.release_time {
                variant.group.release_time = entry.group.release_time;
            }
            break;
        }
    }

    if !found {
        info!(
            "!! New variant for LWJGL version {:?} : {}",
            version, current_sha1
        );
        debug!("New LWLGL variant {:?}", &lwjgl);
        variants.push(entry);
    }
}

/// Fetch LWJGL variant configuration from embedded JSON file
///
/// The configuration contains lists of accepted and rejected LWJGL variant SHA1 hashes,
/// used to filter out known bad variants and only accept validated ones.
///
/// # Returns
/// The LWJGL variant configuration with accept/reject lists
pub async fn get_lwjgl_config(
) -> Result<LWJGLVariantConfig, crate::infrastructure::error::Error> {
    let config = include_bytes!("../../lwjgl-config.json");
    Ok(serde_json::from_slice(config)?)
}
