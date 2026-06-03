//! Computes LWJGL variant hashes for Minecraft versions.
//! Usage: cargo run --example lwjgl_hash -- <minecraft_version_id> [minecraft_version_id...]
//! Example: cargo run --example lwjgl_hash -- 26.1

use chrono::DateTime;
use daedalus::minecraft::*;
use sha1::Sha1;
use std::collections::HashMap;

fn lib_is_split_natives(lib: &Library) -> bool {
    lib.name
        .identifier
        .as_ref()
        .is_some_and(|data| data.starts_with("natives-"))
}

fn version_has_split_natives(ver: &VersionInfo) -> bool {
    ver.libraries.iter().any(|lib| lib_is_split_natives(lib))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    daedalus::Branding::set_branding(daedalus::Branding::new(
        "daedalus-hash-tool".to_string(),
        "noreply@example.com".to_string(),
    ))
    .unwrap();

    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!(
            "Usage: cargo run --example lwjgl_hash -- <version_id> [version_id...]"
        );
        eprintln!("Example: cargo run --example lwjgl_hash -- 26.1 1.21.4");
        std::process::exit(1);
    }

    eprintln!("Fetching version manifest...");
    let manifest = fetch_version_manifest(None).await?;

    for version_id in &args {
        let version = manifest
            .versions
            .iter()
            .find(|v| v.id == *version_id)
            .ok_or_else(|| {
                format!("Version {} not found in manifest", version_id)
            })?;

        eprintln!("Fetching version info for {}...", version_id);
        let mut version_info = fetch_version_info(version).await?;

        let has_split_natives = version_has_split_natives(&version_info);
        let mut _is_lwjgl_3 = false;
        let mut lwjgl_buckets: HashMap<Option<Vec<Rule>>, LibraryGroup> =
            HashMap::new();

        for library in version_info.libraries.iter_mut() {
            // Merge split native identifiers into artifact name (same as daedalus_client)
            if lib_is_split_natives(library) {
                if let Some(identifier) = &library.name.identifier {
                    library.name.artifact =
                        format!("{}-{}", library.name.artifact, identifier);
                    library.name.identifier = None;
                }
            }

            let spec = &mut library.name;
            if !spec.is_lwjgl() {
                continue;
            }

            let mut rules = None;
            let set_version: Option<String> = if has_split_natives {
                _is_lwjgl_3 = true;
                Some(spec.version.clone())
            } else {
                rules = library.rules.clone();
                library.rules = None;
                if spec.package == "org.lwjgl.lwjgl" && spec.artifact == "lwjgl"
                {
                    Some(spec.version.clone())
                } else if spec.package == "org.lwjgl"
                    && spec.artifact == "lwjgl"
                {
                    _is_lwjgl_3 = true;
                    Some(spec.version.clone())
                } else {
                    None
                }
            };

            let bucket =
                lwjgl_buckets.entry(rules.clone()).or_insert_with(|| {
                    LibraryGroup {
                        id: "LWJGL".to_string(),
                        version: "undetermined".to_string(),
                        uid: "org.lwjgl".to_string(),
                        release_time: version_info.release_time,
                        libraries: Vec::new(),
                        requires: None,
                        conflicts: None,
                        type_: VersionType::Release,
                        has_split_natives: Some(has_split_natives),
                    }
                });
            bucket.has_split_natives = Some(has_split_natives);

            if let Some(version) = set_version {
                bucket.version = version;
            }
            bucket.libraries.push(library.clone());
        }

        // Process buckets same as daedalus_client
        if lwjgl_buckets.len() == 1 {
            for (_key, lwjgl) in lwjgl_buckets.iter_mut() {
                lwjgl.libraries.sort_by_key(|lib| lib.name.clone());
                print_hash(version_id, lwjgl);
            }
        } else {
            let common_bucket = lwjgl_buckets.get(&None).cloned();
            for (key, lwjgl) in lwjgl_buckets.iter_mut() {
                if key.is_none() {
                    continue;
                }
                if let Some(mut common_bucket) = common_bucket.clone() {
                    lwjgl.libraries.append(&mut common_bucket.libraries);
                }
                lwjgl.libraries.sort_by_key(|lib| lib.name.clone());
                print_hash(version_id, lwjgl);
            }
        }
    }

    Ok(())
}

fn print_hash(version_id: &str, group: &LibraryGroup) {
    let mut group_copy = group.clone();
    group_copy.release_time = DateTime::default();
    let mut hasher = Sha1::new();
    hasher.update(
        &serde_json::to_vec(&group_copy).expect("library group to serialize"),
    );
    let hash = hasher.hexdigest();

    let natives: Vec<Vec<String>> = group
        .libraries
        .iter()
        .filter_map(|lib| {
            lib.natives
                .as_ref()
                .map(|n| n.keys().map(|k| format!("{:?}", k)).collect())
        })
        .collect();

    println!(
        "Version: {} | LWJGL: {} | Hash: {} | Split: {} | Natives: {:?} | Release: {}",
        version_id,
        group.version,
        hash,
        group.has_split_natives.unwrap_or(false),
        natives,
        group.release_time,
    );
}
