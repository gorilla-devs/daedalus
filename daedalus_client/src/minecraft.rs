use crate::download_file;
use crate::{format_url, upload_file_to_bucket};
use anyhow::bail;
use daedalus::minecraft::{
    merge_partial_library, Dependency, DependencyRule, JavaVersion, LWJGLEntry,
    Library, LibraryDownload, LibraryDownloads, LibraryGroup,
    ListMergeStrategy, MinecraftJavaProfile, Os, PartialLibrary, Rule,
    RuleAction, VersionInfo, VersionManifest, VersionType,
};
use daedalus::{get_hash, GradleSpecifier};
use log::{debug, error, info, warn};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::convert::TryFrom;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{Mutex, Semaphore};

fn patch_library(
    patches: &Vec<LibraryPatch>,
    mut library: Library,
) -> Vec<Library> {
    let mut val = Vec::new();

    let actual_patches = patches
        .iter()
        .filter(|x| x.match_.contains(&library.name.to_string()))
        .collect::<Vec<_>>();

    if !actual_patches.is_empty() {
        for patch in actual_patches {
            info!(
                "processing {} with library patch {}",
                library.name, patch._comment
            );

            if let Some(override_) = &patch.override_ {
                library = merge_partial_library(
                    override_.clone(),
                    library,
                    &patch.list_merge_strategy,
                );
            }

            if let Some(additional_libraries) = &patch.additional_libraries {
                for additional_library in additional_libraries {
                    if patch.patch_additional_libraries.unwrap_or(false) {
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

fn process_single_lwjgl_variant(
    variant: &LibraryGroup,
    patches: &Vec<LibraryPatch>,
) -> Result<Option<(String, LibraryGroup)>, anyhow::Error> {
    let lwjgl_version = variant.version.clone();
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

        // remove jutils and jinput from LWJGL 3
        // this is a dependency that Mojang kept in, but doesn't belong there anymore
        let unneeded: HashSet<&str> =
            vec!["jutils", "jinput"].into_iter().collect();
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
        bail!("Unknown LWJGL version {}", lwjgl_version);
    };

    let mut good = true;
    for lib in &lwjgl.libraries {
        if lib.patched {
            continue;
        }
        if let Some(natives) = &lib.natives {
            let checked: HashSet<&Os> =
                vec![&Os::Linux, &Os::Windows, &Os::Osx]
                    .into_iter()
                    .collect();
            if !checked.is_subset(&natives.clone().keys().collect()) {
                warn!("LWJGL variant library missing system classifier: {} {} {:?}", lwjgl.version, lib.name, natives.keys());
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
                                warn!("LWJGL variant library missing download for classifier: {} {} {:?} {:?}", lwjgl.version, lib.name, baked_entry, classifiers.keys().collect::<Vec<_>>());
                                good = false;
                                break;
                            }
                        }
                    }
                } else {
                    warn!("LWJGL variant library missing downloads classifiers: {} {}", lwjgl.version, lib.name);
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

/// Patch CVE-2021-44228, CVE-2021-44832, CVE-2021-45046
fn map_log4j_artifact(
    version: &str,
) -> Result<Option<(String, String)>, anyhow::Error> {
    debug!("log4j version: {}", version);
    let x = lenient_semver::parse(version);
    if x <= lenient_semver::parse("2.0") {
        // all versions below 2.0 (including beta9 and rc2) use a patch from cdn
        debug!("log4j use beta9 patch");
        return Ok(Some(("2.0-beta9-fixed".to_string(), format_url("maven/"))));
    }
    if x <= lenient_semver::parse("2.17.1") {
        // CVE-2021-44832 fixed in 2.17.1
        debug!("bump log4j to 2.17.1");
        return Ok(Some((
            "2.17.1".to_string(),
            "https://repo1.maven.org/maven2/".to_string(),
        )));
    }
    debug!("no log4j match!");
    Ok(None)
}

pub async fn retrieve_data(
    uploaded_files: &mut Vec<String>,
    semaphore: Arc<Semaphore>,
) -> Result<VersionManifest, anyhow::Error> {
    log::info!("Retrieving Minecraft data ...");

    let old_manifest = daedalus::minecraft::fetch_version_manifest(Some(
        &format_url(&format!(
            "minecraft/v{}/manifest.json",
            daedalus::minecraft::CURRENT_FORMAT_VERSION
        )),
    ))
    .await
    .ok();

    let mut manifest =
        daedalus::minecraft::fetch_version_manifest(None).await?;

    let cloned_manifest = Arc::new(Mutex::new(manifest.clone()));

    let patches = get_library_patches().await?;
    let cloned_patches = Arc::new(&patches);

    let lwjgl_config = get_lwjgl_config().await?;

    let visited_assets_mutex = Arc::new(Mutex::new(Vec::new()));
    let uploaded_files_mutex = Arc::new(Mutex::new(Vec::new()));

    // collections of seen lwjgl versions

    let lwjgl_version_variants_mutex: Arc<
        Mutex<BTreeMap<String, Vec<LWJGLEntry>>>,
    > = Arc::new(Mutex::new(BTreeMap::new()));
    let lwjgl_reject_reasons: HashMap<String, Option<String>> = lwjgl_config
        .reject
        .clone()
        .into_iter()
        .map(|mark| (mark.match_, mark.reason))
        .collect();
    let reject_lwjgl_variants: HashSet<String> = lwjgl_config
        .reject
        .into_iter()
        .map(|mark| mark.match_)
        .collect();
    let accept_lwjgl_variants: HashSet<String> = lwjgl_config
        .accept
        .into_iter()
        .map(|mark| mark.match_)
        .collect();

    async fn add_lwjgl_version(
        variants_mutex: Arc<Mutex<BTreeMap<String, Vec<LWJGLEntry>>>>,
        lwjgl: &LibraryGroup,
    ) {
        let mut lwjgl_copy = lwjgl.clone();
        lwjgl_copy.libraries.sort_by_key(|lib| lib.name.clone());

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

    let now = Instant::now();

    let mut version_futures = Vec::new();

    for version in manifest.versions.iter_mut() {
        version_futures.push(async {
            let old_version = if let Some(old_manifest) = &old_manifest {
                old_manifest.versions.iter().find(|x| x.id == version.id)
            } else {
                None
            };

            if let Some(old_version) = old_version {
                if old_version.sha1 == version.sha1 {
                    return Ok(());
                }
            }

            let visited_assets_mutex = Arc::clone(&visited_assets_mutex);
            let cloned_manifest_mutex = Arc::clone(&cloned_manifest);
            let uploaded_files_mutex = Arc::clone(&uploaded_files_mutex);
            let semaphore = Arc::clone(&semaphore);
            let patches = Arc::clone(&cloned_patches);

            let lwjgl_version_variants_mutex = Arc::clone(&lwjgl_version_variants_mutex);

            let assets_hash =
                old_version.and_then(|x| x.assets_index_sha1.clone());

            async move {
                let mut upload_futures = Vec::new();

                let mut version_info =
                    daedalus::minecraft::fetch_version_info(version).await?;

                fn lib_is_split_natives(lib: &Library) -> bool {
                    lib.name.identifier.clone().is_some_and(|data| data.starts_with("natives-"))
                }

                fn version_has_split_natives(ver: &VersionInfo) -> bool {
                    ver.libraries.iter().any(|lib| lib_is_split_natives(lib))
                }

                fn is_macos_only(rules: &Option<Vec<Rule>>) -> bool {
                    let mut allows_osx = false;
                    let mut allows_all  = false;
                    if let Some(rules) = rules {
                        for rule in rules {
                            if rule.action == RuleAction::Allow && rule.os.is_some() && rule.os.clone().expect("Unwrap to be safe with boolean short circuit").name.is_some_and(|os| os == Os::Osx) {
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

                let has_split_natives = version_has_split_natives(&version_info);
                let mut is_lwjgl_3 = false;
                let mut lwjgl_buckets: HashMap<Option<Vec<Rule>>, LibraryGroup> = HashMap::new();


                let mut new_libraries = Vec::new();
                info!("Processing libraries for version {}", version_info.id);
                for mut library in version_info.libraries.clone() {
                    let spec = &mut library.name;
                    if spec.is_lwjgl() {

                        let mut rules = None;
                        let set_version: Option<String> = if has_split_natives { // implies lwjgl3
                            is_lwjgl_3 = true;
                            debug!("lwlgl library {} has split natives, version {}", spec, spec.version);

                            Some(spec.version.clone())
                        } else {
                            debug!("lwlgl library {} is not split, package: {} artifact:{} version: {}", spec, spec.package, spec.artifact, spec.version);
                            rules = library.rules.clone();
                            if is_macos_only(&rules) {
                                info!("Candidate library {} is only for macOS and is therefore ignored", spec);
                                continue;
                            }
                            // NOTE: Prism does macos only lib exclusion here
                            if spec.package == "org.lwjgl.lwjgl" && spec.artifact == "lwjgl" {
                                Some(spec.version.clone())
                            } else if spec.package == "org.lwjgl" && spec.artifact == "lwjgl" {
                                is_lwjgl_3 = true;
                                Some(spec.version.clone())
                            } else {
                                None
                            }
                        };
                        debug!("lwjgl library {} is setting version {:?}", spec, set_version);

                        let bucket = lwjgl_buckets.entry(rules.clone()).or_insert_with(|| {
                            debug!("Creating lwjgl bucket {:?} for {}", &rules, version_info.id);
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
                            debug!("Setting bucket version {} for {}", version, version_info.id);
                            bucket.version = version;
                        }
                        bucket.libraries.push(library);
                        if version_info.release_time > bucket.release_time {
                            bucket.release_time = version_info.release_time;
                        }

                    } else if spec.is_log4j() {
                        if let Some((version_override, maven_override)) = map_log4j_artifact(&spec.version)? {
                            let replacement_name = GradleSpecifier {
                                package: "org.apache.logging.log4j".to_string(),
                                artifact: spec.artifact.clone(),
                                identifier: None,
                                version: version_override.clone(),
                                extension: "jar".to_string()
                            };
                            let (sha1, size) = match version_override.as_str() {
                                "2.0-beta9-fixed" => {
                                    match spec.artifact.as_str() {
                                        "log4j-api" => {
                                            Ok(("b61eaf2e64d8b0277e188262a8b771bbfa1502b3", 107347))
                                        }
                                        "log4j-core" => {
                                            Ok(("677991ea2d7426f76309a73739cecf609679492c", 677588))
                                        }
                                        _ => {
                                            Err(anyhow::anyhow!("Unhandled log4j artifact {} for overridden version {}", spec.artifact, version_override))
                                        }
                                    }
                                }
                                "2.17.1" => {
                                    match spec.artifact.as_str() {
                                        "log4j-api" => {
                                            Ok(("d771af8e336e372fb5399c99edabe0919aeaf5b2", 301872))
                                        },
                                        "log4j-core" => {
                                            Ok(("779f60f3844dadc3ef597976fcb1e5127b1f343d", 1790452))
                                        },
                                        "log4j-slf4j18-impl" => {
                                            Ok(("ca499d751f4ddd8afb016ef698c30be0da1d09f7", 21268))
                                        }
                                        _ => {
                                            Err(anyhow::anyhow!("Unhandled log4j artifact {} for overridden version {}", spec.artifact, version_override))
                                        }
                                    }
                                }
                                _ => {
                                    Err(anyhow::anyhow!("Unhandled log4j version {}", version_override))
                                }
                            }?;
                            let artifact = LibraryDownload {
                                path: replacement_name.path(),
                                sha1: sha1.to_string(),
                                size,
                                url: Some(format!("{}{}", maven_override, replacement_name.path())),

                            };
                            new_libraries.push(
                                Library {
                                    name: replacement_name,
                                    downloads: Some(LibraryDownloads { artifact: Some(artifact), classifiers: None }),
                                    extract: None,
                                    url: None,
                                    natives: None,
                                    rules: None,
                                    checksums: None,
                                    include_in_classpath: library.include_in_classpath,
                                    patched: true,
                                }
                            );
                        } else {
                            new_libraries.push(library)
                        }
                    } else {
                        let mut libs =
                            patch_library(&patches, library);
                        new_libraries.append(&mut libs)
                    }
                }

                if lwjgl_buckets.len() == 1 {
                    for (key, lwjgl) in lwjgl_buckets.iter_mut() {
                        lwjgl.libraries.sort_by_key(|lib| lib.name.clone() );
                        add_lwjgl_version(lwjgl_version_variants_mutex.clone(), lwjgl).await;
                        info!("Found only candidate LWJGL {:?} {:?}", lwjgl.version, key);
                    }
                } else {
                    let common_bucket = lwjgl_buckets.get(&None).cloned();
                    for (key, lwjgl) in lwjgl_buckets.iter_mut() {
                        if key.is_none() {
                            continue
                        }
                        if let Some(mut common_bucket) = common_bucket.clone() {
                            lwjgl.libraries.append(&mut common_bucket.libraries);
                        }
                        lwjgl.libraries.sort_by_key(|lib| lib.name.clone() );
                        add_lwjgl_version(lwjgl_version_variants_mutex.clone(), lwjgl).await;
                        info!("Found candidate LWJGL {:?} {:?}", lwjgl.version, key);
                    }
                    // remove the common bucket
                    lwjgl_buckets.remove(&None);
                }

                version_info.libraries = new_libraries;

                let suggested_lwjgl_version = if lwjgl_buckets.len() == 1 {
                    if is_lwjgl_3 {
                        Ok(lwjgl_buckets.values().next().expect("Safe to unwrap because there is one item present").version.clone())
                    } else {
                        Ok("2.9.4-nightly-20150209".to_string())
                    }
                } else {
                    let bad_versions: HashSet<&str> = vec!["3.1.6", "3.2.1"].into_iter().collect();
                    let our_versions: HashSet<&str> = lwjgl_buckets.values().into_iter().map(|lwjgl| lwjgl.version.as_str()).collect();

                    if our_versions == bad_versions {
                        info!("Found broken 3.1.6/3.2.1 LWJGL combo in version {} , forcing LWJGL. 3.2.1", &version_info.id);
                        Ok("3.2.1".to_string())
                    } else {
                        Err(anyhow::anyhow!("Can not determine a single suggested LWJGL version in version {} from among {:?}", &version_info.id, our_versions))
                    }

                }?;

                let lwjgl_dependency = if is_lwjgl_3 {
                    Dependency {
                        name: "lwjgl".to_string(),
                        uid: "org.lwjgl3".to_string(),
                        rule: Some(DependencyRule::Suggests(suggested_lwjgl_version)),
                    }
                } else {
                    Dependency {
                        name: "lwjgl".to_string(),
                        uid: "org.lwjgl2".to_string(),
                        rule: Some(DependencyRule::Suggests(suggested_lwjgl_version)),
                    }
                };

                if version_info.requires.is_none() {
                    version_info.requires = Some(Vec::new());
                }
                version_info.requires.as_mut().expect("Safe to unwrap because we just ensured it's creation").push(lwjgl_dependency);

                // Patch java version
                version_info.java_version = {
                    if let Some(java_version) = &version_info.java_version {
                        match MinecraftJavaProfile::try_from(
                            &*java_version.component,
                        ) {
                            Ok(java_version) => Some(JavaVersion {
                                component: java_version.as_str().to_string(),
                                major_version: 0,
                            }),
                            Err(err) => {
                                println!(
                                    "Unknown java version \"{}\": {}",
                                    java_version.component, err
                                );
                                None
                            }
                        }
                    } else {
                        Some(JavaVersion {
                            component: MinecraftJavaProfile::JreLegacy
                                .as_str()
                                .to_string(),
                            major_version: 0,
                        })
                    }
                };

                let version_info_hash = get_hash(bytes::Bytes::from(
                    serde_json::to_vec(&version_info)?,
                ))
                .await?;

                let version_path = format!(
                    "minecraft/v{}/versions/{}.json",
                    daedalus::minecraft::CURRENT_FORMAT_VERSION,
                    version.id
                );
                let assets_path = format!(
                    "minecraft/v{}/assets/{}.json",
                    daedalus::minecraft::CURRENT_FORMAT_VERSION,
                    version_info.asset_index.id
                );
                let assets_index_url = version_info.asset_index.url.clone();

                {
                    let mut cloned_manifest =
                        cloned_manifest_mutex.lock().await;

                    if let Some(position) = cloned_manifest
                        .versions
                        .iter()
                        .position(|x| version.id == x.id)
                    {
                        cloned_manifest.versions[position].url =
                            format_url(&version_path);
                        cloned_manifest.versions[position].assets_index_sha1 =
                            Some(version_info.asset_index.sha1.clone());
                        cloned_manifest.versions[position].assets_index_url =
                            Some(format_url(&assets_path));
                        cloned_manifest.versions[position].java_profile =
                            version_info.java_version.as_ref().map(|x| {
                                MinecraftJavaProfile::try_from(&*x.component)
                                    .expect("Safe to unwrap since we ensure it's valid in version_json already")
                            });
                        cloned_manifest.versions[position].sha1 =
                            version_info_hash;
                    } else {
                        cloned_manifest.versions.insert(
                            0,
                            daedalus::minecraft::Version {
                                id: version_info.id.clone(),
                                type_: version_info.type_.clone(),
                                url: format_url(&version_path),
                                time: version_info.time,
                                release_time: version_info.release_time,
                                sha1: version_info_hash,
                                java_profile: version_info.java_version.as_ref().map(|x| {
                                    MinecraftJavaProfile::try_from(&*x.component)
                                        .expect("Safe to unwrap since we ensure it's valid in version_json already")
                                }),
                                compliance_level: 1,
                                assets_index_url: Some(
                                    version_info.asset_index.sha1.clone(),
                                ),
                                assets_index_sha1: Some(
                                    version_info.asset_index.sha1.clone(),
                                ),
                            },
                        )
                    }
                }

                let mut download_assets = false;

                {
                    let mut visited_assets = visited_assets_mutex.lock().await;

                    if !visited_assets.contains(&version_info.asset_index.id) {
                        if let Some(assets_hash) = assets_hash {
                            if version_info.asset_index.sha1 != assets_hash {
                                download_assets = true;
                            }
                        } else {
                            download_assets = true;
                        }
                    }

                    if download_assets {
                        visited_assets
                            .push(version_info.asset_index.id.clone());
                    }
                }

                if download_assets {
                    let assets_index = download_file(
                        &assets_index_url,
                        Some(&version_info.asset_index.sha1),
                        semaphore.clone(),
                    )
                    .await?;

                    {
                        upload_futures.push(upload_file_to_bucket(
                            assets_path,
                            assets_index.to_vec(),
                            Some("application/json".to_string()),
                            uploaded_files_mutex.as_ref(),
                            semaphore.clone(),
                        ));
                    }
                }

                {
                    upload_futures.push(upload_file_to_bucket(
                        version_path,
                        serde_json::to_vec(&version_info)?,
                        Some("application/json".to_string()),
                        uploaded_files_mutex.as_ref(),
                        semaphore.clone(),
                    ));
                }

                futures::future::try_join_all(upload_futures).await?;

                Ok::<(), anyhow::Error>(())
            }
            .await?;

            Ok::<(), anyhow::Error>(())
        })
    }

    {
        let mut versions = version_futures.into_iter().peekable();
        let mut chunk_index = 0;
        while versions.peek().is_some() {
            let now = Instant::now();

            let chunk: Vec<_> = versions.by_ref().take(100).collect();
            futures::future::try_join_all(chunk).await?;

            chunk_index += 1;

            let elapsed = now.elapsed();
            info!("Chunk {} Elapsed: {:.2?}", chunk_index, elapsed);
        }
    }
    //futures::future::try_join_all(version_futures).await?;

    {
        debug!("waiting for lock on lwjgl version mutex");
        let lwjgl_version_variants = lwjgl_version_variants_mutex.lock().await;

        info!("Processing LWJGL variants");
        for (lwjgl_version_variant, lwjgl_variant_entries) in
            lwjgl_version_variants.iter()
        {
            info!(
                "{} variant(s) for LWJGL {}",
                lwjgl_variant_entries.len(),
                lwjgl_version_variant
            );

            let mut decided_variant = None;
            let mut accepted_variants = 0;
            let mut unknown_variants = 0;

            for variant in lwjgl_variant_entries {
                if reject_lwjgl_variants.contains(&variant.sha1) {
                    let reason = lwjgl_reject_reasons
                    .get(&variant.sha1)
                    .expect(
                        "Unwrap to be safe because sha was present in config",
                    )
                    .clone()
                    .unwrap_or("unspecified".to_string());
                    info!("LWJGL Variant {} for version {} ignored because it was marked as bad. Reason: {}", variant.sha1, lwjgl_version_variant, &reason);
                    continue;
                }
                if accept_lwjgl_variants.contains(&variant.sha1) {
                    info!(
                        "LWJGL Variant {} for version {} accepted",
                        variant.sha1, lwjgl_version_variant
                    );
                    decided_variant = Some(variant);
                    accepted_variants += 1;
                    continue;
                }

                // print natives data to decide which  variant to use
                let natives = variant
                    .group
                    .libraries
                    .iter()
                    .filter_map(|lib| {
                        lib.natives.as_ref().map(|natives| {
                            natives.keys().cloned().collect::<Vec<_>>()
                        })
                    })
                    .collect::<Vec<_>>();

                #[cfg(feature = "sentry")]
                sentry::capture_message(
                    &format!(
                        "Unmarked LWJGL variant {}, #{} ({}) natives: {:?} Split: {}",
                        variant.sha1,
                        lwjgl_version_variant,
                        variant.group.release_time,
                        natives,
                        variant
                            .group
                            .has_split_natives
                            .map_or("unknown".to_string(), |b| b.to_string()),
                    ),
                    sentry::Level::Warning,
                );

                warn!(
                    "Unmarked LWJGL variant {}, #{} ({}) natives: {:?} Split: {}",
                    variant.sha1,
                    lwjgl_version_variant,
                    variant.group.release_time,
                    natives,
                    variant
                        .group
                        .has_split_natives
                        .map_or("unknown".to_string(), |b| b.to_string()),
                );
                unknown_variants += 1;
            }

            let uploaded_files_mutex = Arc::clone(&uploaded_files_mutex);
            let semaphore = Arc::clone(&semaphore);
            let patches = Arc::clone(&cloned_patches);

            async move {

                if decided_variant.is_some()
                    && accepted_variants == 1
                    && unknown_variants == 0
                {
                    if let Some((lwjgl_path, lwjgl)) = process_single_lwjgl_variant(&decided_variant.expect("Unwrap to be safe inside is_some").group, &patches)? {
                        {
                            debug!("Uploading {}", lwjgl_path);
                            upload_file_to_bucket(
                                lwjgl_path,
                                serde_json::to_vec(&lwjgl)?,
                                Some("application/json".to_string()),
                                uploaded_files_mutex.as_ref(),
                                semaphore.clone(),
                            ).await?;
                        }

                    } else {
                        info!("Skipped LWJGL {}", &decided_variant.expect("Unwrap to be safe inside is_some").group.version);
                    }
                } else {
                    #[cfg(feature = "sentry")]
                    sentry::capture_message(
                        &format!(
                            "No variant decided for version {} of out {} possible and {} unknown",
                            lwjgl_version_variant, accepted_variants, unknown_variants
                        ),
                        sentry::Level::Warning,
                    );
                    error!("No variant decided for version {} of out {} possible and {} unknown", lwjgl_version_variant, accepted_variants, unknown_variants);
                }

                Ok::<(), anyhow::Error>(())
            }
            .await?
        }
    }

    upload_file_to_bucket(
        format!(
            "minecraft/v{}/manifest.json",
            daedalus::minecraft::CURRENT_FORMAT_VERSION
        ),
        serde_json::to_vec(&*cloned_manifest.lock().await)?,
        Some("application/json".to_string()),
        uploaded_files_mutex.as_ref(),
        semaphore,
    )
    .await?;

    if let Ok(uploaded_files_mutex) = Arc::try_unwrap(uploaded_files_mutex) {
        uploaded_files.extend(uploaded_files_mutex.into_inner());
    }

    let elapsed = now.elapsed();
    info!("Elapsed: {:.2?}", elapsed);

    Ok(Arc::try_unwrap(cloned_manifest)
        .map_err(|err| {
            anyhow::anyhow!(
                "Failed to unwrap Arc<Mutex<VersionManifest>>: {:?}",
                err
            )
        })?
        .into_inner())
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
/// A version of the fabric loader
struct LibraryPatch {
    #[serde(rename = "_comment")]
    pub _comment: String,
    #[serde(rename = "match")]
    pub match_: Vec<String>,
    pub additional_libraries: Option<Vec<Library>>,
    #[serde(rename = "override")]
    pub override_: Option<PartialLibrary>,
    pub patch_additional_libraries: Option<bool>,
    #[serde(default)]
    pub list_merge_strategy: ListMergeStrategy,
}

/// Fetches the list of library patches
async fn get_library_patches() -> Result<Vec<LibraryPatch>, anyhow::Error> {
    let patches = include_bytes!("../library-patches.json");
    let unprocessed_patches: Vec<LibraryPatch> =
        serde_json::from_slice(patches)?;
    Ok(unprocessed_patches.iter().map(pre_process_patch).collect())
}

fn pre_process_patch(patch: &LibraryPatch) -> LibraryPatch {
    fn patch_url(url: &mut String) {
        *url = url.replace("${BASE_URL}", &*dotenvy::var("BASE_URL").unwrap());
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

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LWJGLVariantMarker {
    #[serde(rename = "match")]
    pub match_: String,
    #[serde(rename = "_comment")]
    pub _comment: String,
    pub reason: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LWJGLVariantConfig {
    pub accept: Vec<LWJGLVariantMarker>,
    pub reject: Vec<LWJGLVariantMarker>,
}

/// Fetches
async fn get_lwjgl_config() -> Result<LWJGLVariantConfig, anyhow::Error> {
    let config = include_bytes!("../lwjgl-config.json");
    Ok(serde_json::from_slice(config)?)
}
