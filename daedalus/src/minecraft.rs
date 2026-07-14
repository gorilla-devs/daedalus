use crate::modded::{Processor, SidedDataEntry};
use crate::{Error, GradleSpecifier, download_file};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::convert::TryFrom;

/// The latest version of the format the model structs deserialize to
pub const CURRENT_FORMAT_VERSION: usize = 2;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
/// The version type
pub enum VersionType {
    /// A major version, which is stable for all players to use
    Release,
    /// An experimental version, which is unstable and used for feature previews and beta testing
    Snapshot,
    /// The oldest versions before the game was released
    OldAlpha,
    /// Early versions of the game
    OldBeta,
    #[serde(untagged)]
    /// Catch-all for upstream version types we don't recognise yet (e.g. Mojang
    /// adds a new "experiment" type). Deserialises any unknown string so the
    /// whole manifest doesn't fail; consumers can detect this via `is_known()`
    /// and surface a warning to operators.
    Unknown(String),
}

impl VersionType {
    /// Converts the version type to a string. Returns the borrowed string for
    /// the `Unknown` variant so callers can still serialize round-trip.
    pub fn as_str(&self) -> &str {
        match self {
            VersionType::Release => "release",
            VersionType::Snapshot => "snapshot",
            VersionType::OldAlpha => "old_alpha",
            VersionType::OldBeta => "old_beta",
            VersionType::Unknown(s) => s.as_str(),
        }
    }

    /// True if this is one of the recognised variants. False for `Unknown(...)`
    /// — callers should warn-and-pass-through to keep the manifest publishable
    /// while flagging that the upstream changed.
    pub fn is_known(&self) -> bool {
        !matches!(self, VersionType::Unknown(_))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
/// A game version of Minecraft
pub struct Version {
    /// A unique identifier of the version
    pub id: String,
    #[serde(rename = "type")]
    /// The release type of the version
    pub type_: VersionType,
    /// A link to additional information about the version
    pub url: String,
    /// The latest time a file in this version was updated
    pub time: DateTime<Utc>,
    /// The time this version was released
    pub release_time: DateTime<Utc>,
    /// Hash of the version JSON. The algorithm depends on which manifest this
    /// came from: on the UPSTREAM Mojang manifest it is the upstream SHA-1; on a
    /// GDLauncher-PUBLISHED manifest it is instead the **SHA-256** of the
    /// post-processed JSON we serve (the CAS object key), so it changes whenever
    /// our pipeline tweaks the file. Compare against `original_sha1` to detect
    /// upstream changes from Mojang. Because the two manifests use different
    /// algorithms in this one field, only verify it with SHA-1 against upstream
    /// data — see [`fetch_version_info`].
    pub sha1: String,
    /// Whether the version supports the latest player safety features
    pub compliance_level: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// (GDLauncher Provided) The Mojang-provided SHA1 of the upstream version JSON,
    /// preserved across our processing so we can detect upstream changes between runs
    /// without re-downloading every version.
    pub original_sha1: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// (GDLauncher Provided) The link to the assets index for this version
    /// This is only available when using the GDLauncher mirror
    pub assets_index_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// (GDLauncher Provided) The SHA1 hash of the assets index for this version
    /// This is only available when using the GDLauncher mirror
    pub assets_index_sha1: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// (GDLauncher Provided) The java profile required to run this mc version
    pub java_profile: Option<MinecraftJavaProfile>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
/// Java profile required to run this mc version
pub enum MinecraftJavaProfile {
    /// Java 8
    JreLegacy,
    /// Java 16
    JavaRuntimeAlpha,
    /// Java 17
    JavaRuntimeBeta,
    /// Java 17
    JavaRuntimeGamma,
    /// Java 17
    JavaRuntimeGammaSnapshot,
    /// Java 14
    MinecraftJavaExe,
    /// Java 21
    JavaRuntimeDelta,
    /// Java 25
    JavaRuntimeEpsilon,
    #[serde(untagged)]
    /// Unknown
    Unknown(String),
}

impl MinecraftJavaProfile {
    /// Converts the version type to a string
    pub fn as_str(&self) -> Result<&'static str, Error> {
        match self {
            MinecraftJavaProfile::JreLegacy => Ok("jre-legacy"),
            MinecraftJavaProfile::JavaRuntimeAlpha => Ok("java-runtime-alpha"),
            MinecraftJavaProfile::JavaRuntimeBeta => Ok("java-runtime-beta"),
            MinecraftJavaProfile::JavaRuntimeGamma => Ok("java-runtime-gamma"),
            MinecraftJavaProfile::JavaRuntimeGammaSnapshot => {
                Ok("java-runtime-gamma-snapshot")
            }
            MinecraftJavaProfile::JavaRuntimeDelta => Ok("java-runtime-delta"),
            MinecraftJavaProfile::JavaRuntimeEpsilon => {
                Ok("java-runtime-epsilon")
            }
            MinecraftJavaProfile::MinecraftJavaExe => Ok("minecraft-java-exe"),
            MinecraftJavaProfile::Unknown(value) => {
                Err(Error::InvalidMinecraftJavaProfile(value.to_string()))
            }
        }
    }
}

impl MinecraftJavaProfile {
    /// Whether this is one of the known/recognised Java profile names.
    ///
    /// Returns `false` for the catch-all `Unknown(...)` variant. Useful for callers
    /// that want to skip processing when Mojang ships a new profile id we haven't
    /// taught the launcher about yet.
    pub fn is_known(&self) -> bool {
        !matches!(self, MinecraftJavaProfile::Unknown(_))
    }
}

impl TryFrom<&str> for MinecraftJavaProfile {
    type Error = Error;

    /// Parse a Java profile name. Unknown strings produce `Unknown(...)` (matching
    /// what the serde deserializer does for unknown values via the untagged
    /// `Unknown(String)` variant) — call `is_known()` to distinguish.
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(match value {
            "jre-legacy" => MinecraftJavaProfile::JreLegacy,
            "java-runtime-alpha" => MinecraftJavaProfile::JavaRuntimeAlpha,
            "java-runtime-beta" => MinecraftJavaProfile::JavaRuntimeBeta,
            "java-runtime-gamma" => MinecraftJavaProfile::JavaRuntimeGamma,
            "java-runtime-gamma-snapshot" => {
                MinecraftJavaProfile::JavaRuntimeGammaSnapshot
            }
            "java-runtime-delta" => MinecraftJavaProfile::JavaRuntimeDelta,
            "java-runtime-epsilon" => MinecraftJavaProfile::JavaRuntimeEpsilon,
            "minecraft-java-exe" => MinecraftJavaProfile::MinecraftJavaExe,
            other => MinecraftJavaProfile::Unknown(other.to_string()),
        })
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
/// The latest snapshot and release of the game
pub struct LatestVersion {
    /// The version id of the latest release
    pub release: String,
    /// The version id of the latest snapshot
    pub snapshot: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
/// Data of all game versions of Minecraft
pub struct VersionManifest {
    /// A struct containing the latest snapshot and release of the game
    pub latest: LatestVersion,
    /// A list of game versions of Minecraft
    pub versions: Vec<Version>,
}

/// The URL to the version manifest
pub const VERSION_MANIFEST_URL: &str =
    "https://piston-meta.mojang.com/mc/game/version_manifest_v2.json";

/// Fetches a version manifest from the specified URL. If no URL is specified, the default is used.
pub async fn fetch_version_manifest(
    url: Option<&str>,
) -> Result<VersionManifest, Error> {
    Ok(serde_json::from_slice(
        &download_file(url.unwrap_or(VERSION_MANIFEST_URL), None).await?,
    )?)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
/// Information about the assets of the game
pub struct AssetIndex {
    /// The game version ID the assets are for
    pub id: String,
    /// The SHA1 hash of the assets index
    pub sha1: String,
    /// The size of the assets index
    pub size: u32,
    /// The size of the game version's assets
    pub total_size: u32,
    /// A URL to a file which contains information about the version's assets
    pub url: String,
}

#[derive(
    Serialize, Deserialize, Debug, Eq, PartialEq, PartialOrd, Ord, Hash, Clone,
)]
#[serde(rename_all = "snake_case")]
/// The type of download
pub enum DownloadType {
    /// The download is for the game client
    Client,
    /// The download is mappings for the game
    ClientMappings,
    /// The download is for the game server
    Server,
    /// The download is mappings for the game server
    ServerMappings,
    /// The download is for the windows server
    WindowsServer,
    #[serde(untagged)]
    /// Catch-all for new download types Mojang ships before we know about them.
    /// Used as a map key in `VersionInfo::downloads`, so it must round-trip
    /// through serde. The wrapped string is the raw key Mojang published.
    Unknown(String),
}

impl DownloadType {
    /// True if this is one of the recognised variants.
    pub fn is_known(&self) -> bool {
        !matches!(self, DownloadType::Unknown(_))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
/// Download information of a file
pub struct Download {
    /// The SHA1 hash of the file
    pub sha1: String,
    /// The size of the file
    pub size: u32,
    /// The URL where the file can be downloaded
    pub url: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
/// Download information of a library
pub struct LibraryDownload {
    /// The path that the library should be saved to
    pub path: String,
    /// The SHA1 hash of the library
    pub sha1: String,
    /// The size of the library
    pub size: u32,
    /// The URL where the library can be downloaded
    pub url: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
/// A list of files that should be downloaded for libraries
pub struct LibraryDownloads {
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The primary library artifact
    pub artifact: Option<LibraryDownload>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Conditional files that may be needed to be downloaded alongside the library
    /// The HashMap key specifies a classifier as additional information for downloading files
    pub classifiers: Option<BTreeMap<String, LibraryDownload>>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
/// The action a rule can follow
pub enum RuleAction {
    /// The rule's status allows something to be done
    Allow,
    /// The rule's status disallows something to be done
    Disallow,
    #[serde(untagged)]
    /// Catch-all for rule actions Mojang ships before we know about them.
    /// Deserialises any unknown string so a single new action doesn't fail the
    /// whole version JSON; the wrapped string round-trips on serialize.
    /// Consumers evaluating rules should treat an unknown action as
    /// non-matching and surface a warning.
    Unknown(String),
}

impl RuleAction {
    /// True if this is one of the recognised variants.
    pub fn is_known(&self) -> bool {
        !matches!(self, RuleAction::Unknown(_))
    }
}

#[derive(
    Serialize, Deserialize, Debug, Eq, PartialEq, PartialOrd, Ord, Hash, Clone,
)]
#[serde(rename_all = "kebab-case")]
/// An enum representing the different types of operating systems
pub enum Os {
    /// MacOS (x86)
    Osx,
    /// M1-Based Macs
    OsxArm64,
    /// Windows (x86)
    Windows,
    /// Windows ARM
    WindowsArm64,
    /// Linux (x86) and its derivatives
    Linux,
    /// Linux ARM 64
    LinuxArm64,
    /// Linux ARM 32
    LinuxArm32,
    /// Linux RISC-V 64
    LinuxRiscv64,
    #[serde(untagged)]
    /// Catch-all for OS names we don't recognise yet (Mojang's literal
    /// "unknown" placeholder as well as any future OS/arch key like a new
    /// natives platform). Deserialises any unknown string so one new OS name
    /// doesn't fail the whole version JSON; the wrapped string round-trips on
    /// serialize. Rule evaluation should treat an unrecognised OS as
    /// non-matching.
    Unknown(String),
}

impl Os {
    /// True if this is one of the recognised variants.
    pub fn is_known(&self) -> bool {
        !matches!(self, Os::Unknown(_))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
/// A rule which depends on what OS the user is on
pub struct OsRule {
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The name of the OS
    pub name: Option<Os>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The version of the OS. This is normally a RegEx
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The architecture of the OS
    pub arch: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
/// A rule which depends on the toggled features of the launcher
pub struct FeatureRule {
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Whether the user is in demo mode
    pub is_demo_user: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Whether the user is using a custom resolution
    pub has_custom_resolution: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Whether the launcher has quick plays support
    pub has_quick_plays_support: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Whether the instance is being launched to a single-player world
    pub is_quick_play_singleplayer: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Whether the instance is being launched to a multi-player world
    pub is_quick_play_multiplayer: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ///  Whether the instance is being launched to a realms world
    pub is_quick_play_realms: Option<bool>,
    #[serde(flatten)]
    /// Feature keys Mojang ships before we know about them (precedent: the
    /// three quick-play keys all arrived at once in 23w14a). Captured so the
    /// published rule keeps its conditions instead of silently becoming
    /// vacuous on re-serialize. Mojang feature values are booleans; a future
    /// non-boolean value fails deserialization rather than being dropped.
    pub other: BTreeMap<String, bool>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
/// A rule deciding whether a file is downloaded, an argument is used, etc.
pub struct Rule {
    /// The action the rule takes
    pub action: RuleAction,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The OS rule
    pub os: Option<OsRule>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The feature rule
    pub features: Option<FeatureRule>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
/// Information delegating the extraction of the library
pub struct LibraryExtract {
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Files/Folders to be excluded from the extraction of the library
    pub exclude: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
/// Information about the java version the game needs
pub struct JavaVersion {
    /// The component needed for the Java installation
    pub component: String,
    /// The major Java version number
    pub major_version: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
/// A library which the game relies on to run
pub struct Library {
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The files the library has
    pub downloads: Option<LibraryDownloads>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Rules of the extraction of the file
    pub extract: Option<LibraryExtract>,
    /// The maven name of the library. The format is `groupId:artifactId:version`
    pub name: GradleSpecifier,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The URL to the repository where the library can be downloaded
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// SHA1 of the artifact, as published by loader metas (fabric/quilt
    /// profile libraries carry one alongside `url`). Verified when the
    /// artifact is mirrored and republished for consumers.
    pub sha1: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Size in bytes of the artifact, when the loader meta provides it.
    pub size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Native files that the library relies on
    pub natives: Option<BTreeMap<Os, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Rules deciding whether the library should be downloaded or not
    pub rules: Option<Vec<Rule>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// SHA1 Checksums for validating the library's integrity. Only present for forge libraries
    pub checksums: Option<Vec<String>>,
    #[serde(default = "default_include_in_classpath")]
    /// Whether the library should be included in the classpath at the game's launch
    pub include_in_classpath: bool,
    #[serde(skip)]
    /// if this library was patched or added by a patch
    pub patched: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Game-version-specific hash mapping for libraries that vary by Minecraft version
    /// Maps minecraft_version → SHA256 hash of the artifact
    /// e.g., {"1.16.5": "abc123...", "1.17.1": "def456..."}
    /// When present, clients should look up their game version and construct CAS URL from hash
    /// Uses BTreeMap for deterministic key ordering (output is hashed downstream).
    pub version_hashes: Option<BTreeMap<String, String>>,
}

impl Library {
    /// Resolves the URL for this library based on the minecraft version.
    ///
    /// For libraries with `version_hashes`, looks up the hash for the given version
    /// and constructs a CAS URL. Falls back to the library's `url` field if
    /// `version_hashes` is not present or doesn't contain the version.
    ///
    /// # Arguments
    /// * `minecraft_version` - The Minecraft version to resolve the URL for
    /// * `base_url` - The base URL for the CAS (e.g., "https://maven.modrinth.com")
    /// * `cas_version` - The CAS version number (e.g., 0)
    ///
    /// # Returns
    /// * `Some(String)` - The resolved URL, either from CAS or the url field
    /// * `None` - If neither version_hashes nor url contain a valid URL
    ///
    /// # Example
    /// ```
    /// # use daedalus::minecraft::Library;
    /// # use daedalus::GradleSpecifier;
    /// # use std::collections::BTreeMap;
    /// let mut library = Library {
    ///     name: "net.fabricmc:intermediary:1.16.5".parse().unwrap(),
    ///     url: None,
    ///     downloads: None,
    ///     extract: None,
    ///     natives: None,
    ///     rules: None,
    ///     sha1: None,
    ///     size: None,
    ///     checksums: None,
    ///     include_in_classpath: true,
    ///     patched: false,
    ///     version_hashes: Some({
    ///         let mut map = BTreeMap::new();
    ///         map.insert("1.16.5".to_string(), "abc123def456".to_string());
    ///         map
    ///     }),
    /// };
    ///
    /// let url = library.resolve_url("1.16.5", "https://maven.modrinth.com", 0);
    /// assert_eq!(url, Some("https://maven.modrinth.com/v0/objects/ab/c123def456".to_string()));
    /// ```
    pub fn resolve_url(
        &self,
        minecraft_version: &str,
        base_url: &str,
        cas_version: u32,
    ) -> Option<String> {
        // First try version_hashes if present
        if let Some(ref hashes) = self.version_hashes {
            if let Some(hash) = hashes.get(minecraft_version) {
                // A malformed hash (too short, or starting with a multibyte
                // character) comes from untrusted metadata — reject it
                // instead of panicking on the byte slice.
                if hash.len() < 2 || !hash.is_char_boundary(2) {
                    return None;
                }
                return Some(format!(
                    "{}/v{}/objects/{}/{}",
                    base_url,
                    cas_version,
                    &hash[..2],
                    &hash[2..]
                ));
            }
        }

        // Fall back to the url field. It carries one of two forms: a full
        // artifact URL, or a maven repository base (trailing slash — the form
        // forge-legacy libraries use) that must be joined with the library's
        // maven path to address the artifact.
        match self.url.as_deref() {
            Some(base) if base.ends_with('/') => {
                Some(format!("{}{}", base, self.name.path()))
            }
            other => other.map(str::to_string),
        }
    }
}

#[derive(Deserialize, Debug, Clone)]
/// A partial library which should be merged with a full library
pub struct PartialLibrary {
    /// The files the library has
    pub downloads: Option<LibraryDownloads>,
    /// Rules of the extraction of the file
    pub extract: Option<LibraryExtract>,
    /// The maven name of the library. The format is `groupId:artifactId:version`
    pub name: Option<GradleSpecifier>,
    /// The URL to the repository where the library can be downloaded
    pub url: Option<String>,
    /// Native files that the library relies on
    pub natives: Option<BTreeMap<Os, String>>,
    /// Rules deciding whether the library should be downloaded or not
    pub rules: Option<Vec<Rule>>,
    /// SHA1 Checksums for validating the library's integrity. Only present for forge libraries
    pub checksums: Option<Vec<String>>,
    /// Whether the library should be included in the classpath at the game's launch
    pub include_in_classpath: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
/// A dependency rule, either suggests or equals
pub enum DependencyRule {
    /// A rule to specify the version exactly
    Equals(String),
    /// A rule to suggest a soft requirement
    Suggests(String),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
/// A library dependency
pub struct Dependency {
    /// A group name that identifies a library group this dependency refers to, ie. `"lwjgl"`
    pub name: String,
    /// a component uid like `"org.lwjgl"`
    pub uid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    /// a rule to specify the version exactly
    pub rule: Option<DependencyRule>,
}

/// Merges a partial library definition into a complete library
///
/// This function takes a partial library (which may override specific fields)
/// and merges it with an existing complete library. Fields present in the partial
/// library will override the corresponding fields in the complete library.
///
/// # Arguments
///
/// * `partial` - Partial library with fields to override
/// * `merge` - Complete library to merge into
///
/// # Returns
///
/// A complete library with merged fields. The `patched` flag is set to true
/// to indicate this library has been modified by a partial library.
pub fn merge_partial_library(
    partial: PartialLibrary,
    mut merge: Library,
) -> Library {
    if let Some(downloads) = partial.downloads {
        if let Some(merge_downloads) = &mut merge.downloads {
            if let Some(artifact) = downloads.artifact {
                merge_downloads.artifact = Some(artifact);
            }
            if let Some(classifiers) = downloads.classifiers {
                if let Some(merge_classifiers) =
                    &mut merge_downloads.classifiers
                {
                    for classifier in classifiers {
                        merge_classifiers.insert(classifier.0, classifier.1);
                    }
                } else {
                    merge_downloads.classifiers = Some(classifiers);
                }
            }
        } else {
            merge.downloads = Some(downloads)
        }
    }
    if let Some(extract) = partial.extract {
        merge.extract = Some(extract)
    }
    if let Some(name) = partial.name {
        merge.name = name
    }
    if let Some(url) = partial.url {
        merge.url = Some(url)
    }
    if let Some(natives) = partial.natives {
        if let Some(merge_natives) = &mut merge.natives {
            for native in natives {
                merge_natives.insert(native.0, native.1);
            }
        } else {
            merge.natives = Some(natives);
        }
    }
    if let Some(rules) = partial.rules {
        if let Some(merge_rules) = &mut merge.rules {
            for rule in rules {
                merge_rules.push(rule);
            }
        } else {
            merge.rules = Some(rules)
        }
    }
    if let Some(checksums) = partial.checksums {
        merge.checksums = Some(checksums)
    }
    if let Some(include_in_classpath) = partial.include_in_classpath {
        merge.include_in_classpath = include_in_classpath
    }
    merge.patched = true;

    merge
}

/// Default value for include_in_classpath field
///
/// Returns `true` because libraries should be included in the classpath by default.
/// Only specialized libraries (like native libraries that are extracted but not loaded)
/// should set this to false explicitly.
fn default_include_in_classpath() -> bool {
    true
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
/// A container for an argument or multiple arguments
pub enum ArgumentValue {
    /// The container has one argument
    Single(String),
    /// The container has multiple arguments
    Many(Vec<String>),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
/// A command line argument passed to a program
pub enum Argument {
    /// An argument which is applied no matter what
    Normal(String),
    /// An argument which is only applied if certain conditions are met.
    /// When rules is empty (or not provided in JSON), the argument is always applied.
    Ruled {
        /// The rules deciding whether the argument(s) is used or not.
        /// Defaults to empty (always apply) when not present in JSON.
        #[serde(default)]
        rules: Vec<Rule>,
        /// The container of the argument(s) that should be applied accordingly
        value: ArgumentValue,
    },
}

#[derive(
    Serialize, Deserialize, Debug, Eq, PartialEq, PartialOrd, Ord, Hash, Clone,
)]
#[serde(rename_all = "kebab-case")]
/// The type of argument
pub enum ArgumentType {
    /// The argument is passed to the game
    Game,
    /// The argument is passed to the JVM
    Jvm,
    /// Default JVM arguments that users can customize
    DefaultUserJvm,
    #[serde(untagged)]
    /// Catch-all for argument map keys Mojang ships before we know about them
    /// (this enum keys `VersionInfo::arguments`, so an unrecognised key would
    /// otherwise fail the whole version JSON). The wrapped string is the raw
    /// key and round-trips on serialize.
    Unknown(String),
}

impl ArgumentType {
    /// True if this is one of the recognised variants.
    pub fn is_known(&self) -> bool {
        !matches!(self, ArgumentType::Unknown(_))
    }
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Hash, Clone)]
#[serde(rename_all = "kebab-case")]
/// Java Logging type
pub enum LoggingType {
    /// Log4j XML config file
    Log4j2Xml,
    #[serde(untagged)]
    /// Catch-all for logging types Mojang ships before we know about them.
    /// The wrapped string is the raw value and round-trips on serialize.
    Unknown(String),
}

#[derive(
    Serialize, Deserialize, Debug, Eq, PartialEq, PartialOrd, Ord, Hash, Clone,
)]
#[serde(rename_all = "kebab-case")]
/// Java Logging config names
pub enum LoggingConfigName {
    /// Client logging config
    Client,
    #[serde(untagged)]
    /// Catch-all for logging config names Mojang ships before we know about
    /// them (this enum keys `VersionInfo::logging`, so an unrecognised key
    /// would otherwise fail the whole version JSON). The wrapped string is the
    /// raw key and round-trips on serialize.
    Unknown(String),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
/// Java Logging artifact for download
pub struct LoggingArtifact {
    /// The Name of the artifact
    pub id: String,
    /// The Sha1 hash of the file
    pub sha1: String,
    /// The Size of the file
    pub size: u32,
    /// The url where this file cna be reached
    pub url: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
/// Java Logging configuration
pub struct LoggingConfig {
    /// Logging config file
    pub file: LoggingArtifact,
    /// JVM config arg
    pub argument: String,
    #[serde(rename = "type")]
    /// Logging type
    pub type_: LoggingType,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
/// Information about a version
pub struct VersionInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Arguments passed to the game or JVM
    pub arguments: Option<BTreeMap<ArgumentType, Vec<Argument>>>,
    /// Assets for the game
    pub asset_index: AssetIndex,
    /// The version ID of the assets
    pub assets: String,
    /// Game downloads of the version
    pub downloads: BTreeMap<DownloadType, Download>,
    /// The version ID of the version
    pub id: String,

    /// When merged with a partial version, this is the vanilla id, otherwise it's the same as `id`
    pub inherits_from: Option<String>,

    /// The Java version this version supports
    pub java_version: Option<JavaVersion>,
    /// Libraries that the version depends on
    pub libraries: Vec<Library>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// dependencies not included in libraries
    pub requires: Option<Vec<Dependency>>,
    /// The classpath to the main class to launch the game
    pub main_class: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// (Legacy) Arguments passed to the game
    pub minecraft_arguments: Option<String>,
    /// The minimum version of the Minecraft Launcher that can run this version of the game
    pub minimum_launcher_version: u32,
    /// The time that the version was released
    pub release_time: DateTime<Utc>,
    /// The latest time a file in this version was updated
    pub time: DateTime<Utc>,
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

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
/// Information about grouping of libraries
pub struct LibraryGroup {
    /// The version ID of the version
    pub id: String,
    /// The version string for this group
    pub version: String,
    /// The uid aka maven package group id of this group
    pub uid: String,
    /// The time that the version was released
    pub release_time: DateTime<Utc>,
    /// The type of version
    pub type_: VersionType,
    /// The library listing for this group
    pub libraries: Vec<Library>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// libraries required by this group
    pub requires: Option<Vec<Dependency>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// libraries that conflict with this group
    pub conflicts: Option<Vec<Dependency>>,
    #[serde(default, skip_serializing)]
    /// group has libs with split natives
    pub has_split_natives: Option<bool>,
}

#[derive(Debug, Clone)]
/// A paring of a library group with a sha1 of it's json representation
pub struct LWJGLEntry {
    /// The sha1 of the groups json representation
    pub sha1: String,
    /// LibraryGroup for the entry
    pub group: LibraryGroup,
}

impl LWJGLEntry {
    /// Construct a entry from a LibraryGroup
    pub fn from_group(group: LibraryGroup) -> Self {
        use sha1::Sha1;

        // compute a human readable hash of the group's contents less the release time
        let mut group_copy = group.clone();
        group_copy.release_time = DateTime::default(); // reset so the hash doesn't account for it
        let mut hasher = Sha1::new();
        hasher.update(
            &serde_json::to_vec(&group_copy)
                .expect("library group to serialize"),
        );

        let hash = hasher.hexdigest();
        LWJGLEntry { sha1: hash, group }
    }
}

/// Fetches detailed information about a version from the manifest.
///
/// The download is verified with **SHA-1** against `version.sha1`, so this is
/// for the UPSTREAM Mojang manifest, where that field is the upstream SHA-1 of
/// the version JSON. It must NOT be used on a GDLauncher-published manifest:
/// there `sha1` holds the SHA-256 of the post-processed JSON (the CAS object
/// key — see [`Version::sha1`]), so this SHA-1 check would always fail.
/// Published version JSONs are content-addressed by their URL, so a consumer
/// needs no separate checksum.
pub async fn fetch_version_info(
    version: &Version,
) -> Result<VersionInfo, Error> {
    Ok(serde_json::from_slice(
        &download_file(&version.url, Some(&version.sha1)).await?,
    )?)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
/// An asset of the game
pub struct Asset {
    /// The SHA1 hash of the asset file
    pub hash: String,
    /// The size of the asset file
    pub size: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
/// An index containing all assets the game needs
pub struct AssetsIndex {
    /// A hashmap containing the filename (key) and asset (value)
    pub objects: HashMap<String, Asset>,
    #[serde(default)]
    #[serde(rename = "virtual")]
    /// If the index should be reconstructed at a virtual path
    pub map_virtual: bool,
    #[serde(default)]
    /// If the index should be reconstructed in the instance's resource directory
    pub map_to_resources: bool,
}

/// Fetches the assets index from the version info
pub async fn fetch_assets_index(
    version: &VersionInfo,
) -> Result<AssetsIndex, Error> {
    Ok(serde_json::from_slice(
        &download_file(
            &version.asset_index.url,
            Some(&version.asset_index.sha1),
        )
        .await?,
    )?)
}

#[cfg(test)]
mod schema_drift_tests {
    use super::*;

    #[test]
    fn version_type_unknown_round_trips() {
        let unknown: VersionType = serde_json::from_str("\"experiment\"")
            .expect("untagged Unknown deserialises");
        assert!(
            matches!(unknown, VersionType::Unknown(ref s) if s == "experiment")
        );
        assert!(!unknown.is_known());
        assert_eq!(unknown.as_str(), "experiment");
        let back = serde_json::to_string(&unknown).expect("serializes");
        assert_eq!(back, "\"experiment\"");
    }

    #[test]
    fn version_type_known_variants_still_deserialise() {
        let release: VersionType = serde_json::from_str("\"release\"").unwrap();
        assert!(matches!(release, VersionType::Release));
        assert!(release.is_known());

        let snapshot: VersionType =
            serde_json::from_str("\"snapshot\"").unwrap();
        assert!(matches!(snapshot, VersionType::Snapshot));
    }

    #[test]
    fn download_type_unknown_round_trips() {
        let unknown: DownloadType = serde_json::from_str("\"android_client\"")
            .expect("untagged Unknown deserialises");
        assert!(
            matches!(unknown, DownloadType::Unknown(ref s) if s == "android_client")
        );
        assert!(!unknown.is_known());
    }

    #[test]
    fn download_type_known_variants_still_deserialise() {
        let client: DownloadType = serde_json::from_str("\"client\"").unwrap();
        assert!(matches!(client, DownloadType::Client));
        assert!(client.is_known());
    }

    #[test]
    fn java_profile_unknown_round_trips() {
        // A profile name Mojang ships before we add it should parse as Unknown,
        // not panic or fail the whole version.
        let unknown: MinecraftJavaProfile =
            serde_json::from_str("\"java-runtime-zeta\"")
                .expect("untagged Unknown deserialises");
        assert!(
            matches!(unknown, MinecraftJavaProfile::Unknown(ref s) if s == "java-runtime-zeta")
        );
        assert!(!unknown.is_known());
        // as_str() must return Err (not panic) for Unknown.
        assert!(unknown.as_str().is_err());
        // Round-trips through serde.
        let back = serde_json::to_string(&unknown).expect("serializes");
        assert_eq!(back, "\"java-runtime-zeta\"");
    }

    #[test]
    fn java_profile_known_variants_still_deserialise() {
        let profile: MinecraftJavaProfile =
            serde_json::from_str("\"jre-legacy\"").unwrap();
        assert!(matches!(profile, MinecraftJavaProfile::JreLegacy));
        assert!(profile.is_known());
        assert_eq!(profile.as_str().unwrap(), "jre-legacy");
    }

    #[test]
    fn java_profile_try_from_unknown_is_not_known() {
        let profile =
            MinecraftJavaProfile::try_from("java-runtime-omega").unwrap();
        assert!(
            matches!(profile, MinecraftJavaProfile::Unknown(ref s) if s == "java-runtime-omega")
        );
        assert!(!profile.is_known());
    }

    #[test]
    fn os_unknown_round_trips() {
        let unknown: Os = serde_json::from_str("\"linux-loongarch64\"")
            .expect("untagged Unknown deserialises");
        assert!(matches!(unknown, Os::Unknown(ref s) if s == "linux-loongarch64"));
        assert!(!unknown.is_known());
        assert_eq!(
            serde_json::to_string(&unknown).unwrap(),
            "\"linux-loongarch64\""
        );
        // Mojang's literal "unknown" placeholder lands in the same bucket.
        let literal: Os = serde_json::from_str("\"unknown\"").unwrap();
        assert!(matches!(literal, Os::Unknown(ref s) if s == "unknown"));
        // Known variants are unaffected.
        let known: Os = serde_json::from_str("\"linux-riscv64\"").unwrap();
        assert!(matches!(known, Os::LinuxRiscv64));
    }

    #[test]
    fn rule_action_unknown_round_trips() {
        let unknown: RuleAction = serde_json::from_str("\"audit\"")
            .expect("untagged Unknown deserialises");
        assert!(matches!(unknown, RuleAction::Unknown(ref s) if s == "audit"));
        assert!(!unknown.is_known());
        assert_eq!(serde_json::to_string(&unknown).unwrap(), "\"audit\"");
        let known: RuleAction = serde_json::from_str("\"allow\"").unwrap();
        assert!(matches!(known, RuleAction::Allow));
    }

    #[test]
    fn argument_type_unknown_map_key_round_trips() {
        // A new arguments key must not fail the whole map and must survive
        // a deserialize → serialize round trip unchanged.
        let json = r#"{"game": ["--demo"], "wasm": ["--experimental"]}"#;
        let args: BTreeMap<ArgumentType, Vec<Argument>> =
            serde_json::from_str(json).expect("unknown key tolerated");
        assert!(args.contains_key(&ArgumentType::Game));
        assert!(args.contains_key(&ArgumentType::Unknown("wasm".to_string())));
        let back = serde_json::to_string(&args).unwrap();
        assert!(back.contains("\"wasm\""));
    }

    #[test]
    fn feature_rule_unknown_keys_round_trip() {
        // A new feature key must survive deserialize → serialize so the
        // published rule keeps its condition instead of becoming vacuous.
        let json = r#"{"is_demo_user": true, "is_quick_play_dimension": true}"#;
        let rule: FeatureRule = serde_json::from_str(json).unwrap();
        assert_eq!(rule.is_demo_user, Some(true));
        assert_eq!(rule.other.get("is_quick_play_dimension"), Some(&true));
        let back = serde_json::to_string(&rule).unwrap();
        assert!(back.contains("is_quick_play_dimension"));
        // Absent optional fields stay absent — no spurious nulls.
        assert!(!back.contains("is_quick_play_realms"));
    }

    #[test]
    fn resolve_url_rejects_malformed_hashes() {
        let lib: Library = serde_json::from_value(serde_json::json!({
            "name": "org.example:lib:1.0",
            "versionHashes": {"1.20.1": "\u{20bf}xyz", "1.20.2": "a"}
        }))
        .unwrap();
        // Multibyte first character: must return None, not panic on slicing.
        assert_eq!(lib.resolve_url("1.20.1", "https://cdn.example", 5), None);
        // Too short.
        assert_eq!(lib.resolve_url("1.20.2", "https://cdn.example", 5), None);
    }

    #[test]
    fn resolve_url_joins_maven_base_urls() {
        let base: Library = serde_json::from_value(serde_json::json!({
            "name": "com.example:thing:2.0",
            "url": "https://libraries.minecraft.net/"
        }))
        .unwrap();
        assert_eq!(
            base.resolve_url("1.20.1", "https://cdn.example", 5).as_deref(),
            Some(
                "https://libraries.minecraft.net/com/example/thing/2.0/thing-2.0.jar"
            )
        );

        let full: Library = serde_json::from_value(serde_json::json!({
            "name": "com.example:thing:2.0",
            "url": "https://cdn.example/v5/objects/ab/cdef"
        }))
        .unwrap();
        assert_eq!(
            full.resolve_url("1.20.1", "https://cdn.example", 5).as_deref(),
            Some("https://cdn.example/v5/objects/ab/cdef")
        );
    }

    #[test]
    fn logging_unknown_keys_round_trip() {
        let json = r#"{
            "server": {
                "file": {"id": "x.xml", "sha1": "a", "size": 1, "url": "u"},
                "argument": "-Dlog4j",
                "type": "json-config"
            }
        }"#;
        let logging: BTreeMap<LoggingConfigName, LoggingConfig> =
            serde_json::from_str(json).expect("unknown key+type tolerated");
        let (name, config) = logging.iter().next().unwrap();
        assert!(matches!(name, LoggingConfigName::Unknown(s) if s == "server"));
        assert!(
            matches!(&config.type_, LoggingType::Unknown(s) if s == "json-config")
        );
    }
}
