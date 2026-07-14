use crate::{Error, download_file};

use crate::minecraft::{
    Argument, ArgumentType, Library, LoggingConfig, LoggingConfigName,
    VersionInfo, VersionType,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeMap;

/// A data variable entry that depends on the side of the installation
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SidedDataEntry {
    /// The value on the client
    pub client: String,
    /// The value on the server
    pub server: String,
}

fn deserialize_date<'de, D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;

    // Try parsing with timezone first (standard ISO 8601)
    serde_json::from_str::<DateTime<Utc>>(&format!("\"{s}\""))
        // Fallback: parse as naive datetime (no timezone) and assume UTC
        // Uses %.f to accept any number of fractional seconds (not just 9)
        .or_else(|_| {
            chrono::NaiveDateTime::parse_from_str(&s, "%Y-%m-%dT%H:%M:%S%.f")
                .map(|dt| dt.and_utc())
        })
        // Fallback: try without fractional seconds
        .or_else(|_| {
            chrono::NaiveDateTime::parse_from_str(&s, "%Y-%m-%dT%H:%M:%S")
                .map(|dt| dt.and_utc())
        })
        .map_err(serde::de::Error::custom)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
/// A partial version returned by fabric meta
pub struct PartialVersionInfo {
    /// The version ID of the version
    pub id: String,
    /// The version ID this partial version inherits from
    pub inherits_from: String,
    /// The time that the version was released
    #[serde(deserialize_with = "deserialize_date")]
    pub release_time: DateTime<Utc>,
    /// The latest time a file in this version was updated
    #[serde(deserialize_with = "deserialize_date")]
    pub time: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The classpath to the main class to launch the game
    pub main_class: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// (Legacy) Arguments passed to the game
    pub minecraft_arguments: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Arguments passed to the game or JVM
    pub arguments: Option<BTreeMap<ArgumentType, Vec<Argument>>>,
    /// Libraries that the version depends on
    pub libraries: Vec<Library>,
    #[serde(rename = "type")]
    /// The type of version
    pub type_: VersionType,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Logging configuration
    pub logging: Option<BTreeMap<LoggingConfigName, LoggingConfig>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// (Forge-only)
    pub data: Option<BTreeMap<String, SidedDataEntry>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// (Forge-only) The list of processors to run after downloading the files
    pub processors: Option<Vec<Processor>>,
}

/// A processor to be ran after downloading the files
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Processor {
    /// Maven coordinates for the JAR library of this processor.
    pub jar: String,
    /// Maven coordinates for all the libraries that must be included in classpath when running this processor.
    pub classpath: Vec<String>,
    /// Arguments for this processor.
    pub args: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Represents a map of outputs. Keys and values can be data values
    pub outputs: Option<BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Which sides this processor shall be ran on.
    /// Valid values: client, server, extract
    pub sides: Option<Vec<String>>,
}

/// Fetches the version manifest of a game version's URL
pub async fn fetch_partial_version(
    url: &str,
) -> Result<PartialVersionInfo, Error> {
    Ok(serde_json::from_slice(&download_file(url, None).await?)?)
}

/// Merges a partial version into a complete one
pub fn merge_partial_version(
    partial: PartialVersionInfo,
    merge: VersionInfo,
) -> VersionInfo {
    let merge_id = merge.id.clone();
    // The placeholder is a compile-time constant shared by generator and
    // consumers, so substitution works regardless of branding configuration.
    let dummy_replace_string = crate::DUMMY_REPLACE_STRING;

    // A loader library on the classpath shadows the vanilla library with the
    // same package:artifact:classifier coordinates (legacy Forge ships its own
    // log4j, jopt-simple, guava, ...): the vanilla copy is dropped so the
    // merged version carries exactly one copy of each such library. Split
    // natives use distinct classifiers, so they are only shadowed when the
    // loader ships the same classifier itself.
    let loader_classpath_coords = partial
        .libraries
        .iter()
        .filter(|lib| lib.include_in_classpath)
        .map(|lib| lib.name.get_computed_name())
        .collect::<std::collections::HashSet<_>>();
    let merge_libraries = merge
        .libraries
        .into_iter()
        .filter(|lib| {
            !loader_classpath_coords.contains(&lib.name.get_computed_name())
        })
        .collect::<Vec<_>>();

    VersionInfo {
        arguments: if let Some(partial_args) = partial.arguments {
            if let Some(merge_args) = merge.arguments {
                let mut new_map = BTreeMap::new();

                fn add_keys(
                    new_map: &mut BTreeMap<ArgumentType, Vec<Argument>>,
                    args: BTreeMap<ArgumentType, Vec<Argument>>,
                ) {
                    for (type_, arguments) in args {
                        new_map.entry(type_).or_default().extend(arguments);
                    }
                }

                add_keys(&mut new_map, merge_args);
                add_keys(&mut new_map, partial_args);

                Some(new_map)
            } else {
                Some(partial_args)
            }
        } else {
            merge.arguments
        },
        asset_index: merge.asset_index,
        assets: merge.assets,
        downloads: merge.downloads,
        id: partial.id.replace(dummy_replace_string, &merge_id),
        inherits_from: Some(merge_id.clone()),
        java_version: merge.java_version,
        libraries: partial
            .libraries
            .into_iter()
            .chain(merge_libraries)
            .map(|x| Library {
                downloads: x.downloads,
                extract: x.extract,
                name: x
                    .name
                    .to_string()
                    .replace(dummy_replace_string, &merge_id)
                    .parse()
                    .expect(
                        "Gradle specifier to still be valid after branding",
                    ),
                url: x.url,
                sha1: x.sha1,
                size: x.size,
                natives: x.natives,
                rules: x.rules,
                checksums: x.checksums,
                include_in_classpath: x.include_in_classpath,
                version_hashes: x.version_hashes,
                patched: false,
            })
            .collect::<Vec<_>>(),
        requires: merge.requires,
        main_class: if let Some(main_class) = partial.main_class {
            main_class
        } else {
            merge.main_class
        },
        minecraft_arguments: partial.minecraft_arguments,
        minimum_launcher_version: merge.minimum_launcher_version,
        release_time: partial.release_time,
        time: partial.time,
        type_: partial.type_,
        logging: if let Some(cfg) = partial.logging {
            Some(cfg)
        } else {
            merge.logging
        },
        data: partial.data,
        processors: partial.processors,
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
/// A manifest containing information about a mod loader's versions
pub struct Manifest {
    /// The game versions the mod loader supports
    pub game_versions: Vec<Version>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
///  A game version of Minecraft
pub struct Version {
    /// The minecraft version ID
    pub id: String,
    /// Whether the release is stable or not
    pub stable: bool,
    /// A map that contains loader versions for the game version
    pub loaders: Vec<LoaderVersion>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
/// A version of a Minecraft mod loader
pub struct LoaderVersion {
    /// The version ID of the loader
    pub id: String,
    /// The URL of the version's manifest
    pub url: String,
    /// Whether the loader is stable or not
    pub stable: bool,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    /// (GDLauncher Provided) The upstream SHA-1 of the loader's installer jar
    /// (from the maven `.sha1` sidecar), preserved across runs so a cheap
    /// sidecar check can detect an upstream re-publish without re-downloading
    /// the installer. `None` for loaders that have no installer (fabric/quilt).
    pub original_sha1: Option<String>,
}

/// Fetches the manifest of a mod loader
pub async fn fetch_manifest(url: &str) -> Result<Manifest, Error> {
    Ok(serde_json::from_slice(&download_file(url, None).await?)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version_info(libraries: serde_json::Value) -> VersionInfo {
        serde_json::from_value(serde_json::json!({
            "assetIndex": {
                "id": "17",
                "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                "size": 1,
                "totalSize": 1,
                "url": "https://example.com/17.json"
            },
            "assets": "17",
            "downloads": {},
            "id": "1.20.1",
            "libraries": libraries,
            "mainClass": "net.minecraft.client.main.Main",
            "minimumLauncherVersion": 21,
            "releaseTime": "2023-06-12T13:25:51+00:00",
            "time": "2023-06-12T13:25:51+00:00",
            "type": "release"
        }))
        .unwrap()
    }

    fn partial_info(libraries: serde_json::Value) -> PartialVersionInfo {
        serde_json::from_value(serde_json::json!({
            "id": "forge-47.2.0",
            "inheritsFrom": "1.20.1",
            "releaseTime": "2023-06-12T13:25:51+00:00",
            "time": "2023-06-12T13:25:51+00:00",
            "libraries": libraries,
            "type": "release"
        }))
        .unwrap()
    }

    #[test]
    fn merge_drops_vanilla_libraries_shadowed_by_the_loader() {
        let vanilla = version_info(serde_json::json!([
            {"name": "org.apache.logging.log4j:log4j-core:2.0-beta9"},
            {"name": "org.lwjgl:lwjgl:3.3.3:natives-linux"},
            {"name": "com.mojang:brigadier:1.1.8"}
        ]));
        let loader = partial_info(serde_json::json!([
            {"name": "org.apache.logging.log4j:log4j-core:2.17.1"},
            {"name": "net.minecraftforge:forge:1.20.1-47.2.0"}
        ]));

        let merged = merge_partial_version(loader, vanilla);
        let names: Vec<String> =
            merged.libraries.iter().map(|l| l.name.to_string()).collect();

        // The loader's log4j wins; the vanilla copy is gone.
        assert!(
            names.contains(&"org.apache.logging.log4j:log4j-core:2.17.1".into())
        );
        assert!(
            !names
                .contains(&"org.apache.logging.log4j:log4j-core:2.0-beta9".into())
        );
        // Unrelated vanilla libraries and classifier'd natives survive.
        assert!(names.contains(&"com.mojang:brigadier:1.1.8".into()));
        assert!(names.contains(&"org.lwjgl:lwjgl:3.3.3:natives-linux".into()));
    }

    #[test]
    fn merge_keeps_vanilla_when_loader_copy_is_off_classpath() {
        let vanilla = version_info(serde_json::json!([
            {"name": "org.apache.logging.log4j:log4j-core:2.0-beta9"}
        ]));
        let loader = partial_info(serde_json::json!([
            {
                "name": "org.apache.logging.log4j:log4j-core:2.17.1",
                "include_in_classpath": false
            }
        ]));

        let merged = merge_partial_version(loader, vanilla);
        let names: Vec<String> =
            merged.libraries.iter().map(|l| l.name.to_string()).collect();
        assert!(
            names.contains(&"org.apache.logging.log4j:log4j-core:2.0-beta9".into())
        );
    }

    #[test]
    fn loader_version_original_sha1_roundtrips_and_is_backward_compatible() {
        // Round-trips when present.
        let v = LoaderVersion {
            id: "1.20.1-47.1.0".to_string(),
            url: "https://cdn/v5/objects/ab/cd".to_string(),
            stable: true,
            original_sha1: Some(
                "3c60231dd737ff84073c1693af0fdf58dce09e96".to_string(),
            ),
        };
        let json = serde_json::to_string(&v).unwrap();
        assert!(json.contains("original_sha1"));
        let back: LoaderVersion = serde_json::from_str(&json).unwrap();
        assert_eq!(
            back.original_sha1.as_deref(),
            Some("3c60231dd737ff84073c1693af0fdf58dce09e96")
        );

        // None is omitted, so published JSON is byte-unchanged for loaders
        // without an installer (fabric/quilt).
        let none = LoaderVersion {
            id: "x".to_string(),
            url: "y".to_string(),
            stable: false,
            original_sha1: None,
        };
        assert!(!serde_json::to_string(&none).unwrap().contains("original_sha1"));

        // An OLD manifest entry with no original_sha1 field deserialises to None
        // (the first-run sidecar check then treats it as "reprocess to be safe").
        let old = r#"{"id":"x","url":"y","stable":true}"#;
        let parsed: LoaderVersion = serde_json::from_str(old).unwrap();
        assert_eq!(parsed.original_sha1, None);
    }
}
