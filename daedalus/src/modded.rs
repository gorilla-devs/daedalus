use crate::{BRANDING, Error, download_file};

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
///
/// # Panics
/// Panics if `Branding::set_branding` was never called. Previously this fell back
/// to a hard-coded `unbranded` default, which silently no-op'd the dummy-version
/// substitution for any consumer using a real brand. Calling `set_branding`
/// before this function is required.
pub fn merge_partial_version(
    partial: PartialVersionInfo,
    merge: VersionInfo,
) -> VersionInfo {
    let merge_id = merge.id.clone();
    let dummy_replace_string = &BRANDING
        .get()
        .expect(
            "Branding must be set via Branding::set_branding before merge_partial_version",
        )
        .dummy_replace_string;

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
            .chain(merge.libraries)
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
}

/// Fetches the manifest of a mod loader
pub async fn fetch_manifest(url: &str) -> Result<Manifest, Error> {
    Ok(serde_json::from_slice(&download_file(url, None).await?)?)
}
