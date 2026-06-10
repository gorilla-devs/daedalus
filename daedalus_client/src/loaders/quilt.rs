use super::{
    GameVersionInfo, LoaderStrategy, LoaderVersionInfo, LoaderVersionsList,
};
use serde::{Deserialize, Serialize};

/// Quilt loader versions known to be broken upstream.
///
/// Mirrors Modrinth daedalus's Quilt blacklist. Each entry has a real upstream
/// problem (missing artifact, malformed coordinates, etc.) that makes the loader
/// version impossible to process; better to skip cleanly than to log a fetch
/// failure on every cycle.
const QUILT_SKIP_LIST: &[&str] = &[
    "0.17.5-beta.4", // Broken coordinate publication on Quilt's maven
];

/// Quilt loader strategy implementation
pub struct QuiltStrategy;

impl LoaderStrategy for QuiltStrategy {
    fn name(&self) -> &str {
        "Quilt"
    }

    fn meta_url(&self) -> &str {
        "https://meta.quiltmc.org/v3"
    }

    fn maven_fallback(&self) -> &str {
        // Quilt serves artifacts under /repository/release/ — the bare host
        // 404s for every path, so a profile library shipped without an
        // explicit url would be undownloadable with the shorter base.
        "https://maven.quiltmc.org/repository/release/"
    }

    fn manifest_path_prefix(&self) -> &str {
        "quilt"
    }

    fn is_stable(&self, _loader: &dyn LoaderVersionInfo) -> bool {
        // Quilt API does not include stability information
        // Default to false (unstable)
        false
    }

    fn should_skip(&self, loader_version: &str) -> bool {
        QUILT_SKIP_LIST.contains(&loader_version)
    }
}

/// Quilt API response structure
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct QuiltVersions {
    pub game: Vec<QuiltGameVersion>,
    pub loader: Vec<QuiltLoaderVersion>,
    /// Game versions with a published hashed-mojmap mapping — the installable
    /// set. Quilt's game list runs ahead of its mappings (no `hashed`
    /// artifacts exist for the 26.x era), so this is the load-bearing list.
    /// Required on purpose: a meta response without it must fail the parse
    /// loudly rather than publish loaders no client can resolve.
    pub hashed: Vec<QuiltMappingVersion>,
}

/// One entry of the meta API's mapping list (`hashed`).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct QuiltMappingVersion {
    pub version: String,
}

impl LoaderVersionsList for QuiltVersions {
    type Loader = QuiltLoaderVersion;
    type Game = QuiltGameVersion;

    fn loader(&self) -> &[Self::Loader] {
        &self.loader
    }

    fn game(&self) -> &[Self::Game] {
        &self.game
    }

    fn mapping_versions(&self) -> Vec<&str> {
        self.hashed.iter().map(|m| m.version.as_str()).collect()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct QuiltGameVersion {
    pub version: String,
    // `stable` may be absent on some Quilt API responses; default to `false`
    // so a missing field doesn't abort the entire game-version-list parse.
    #[serde(default)]
    pub stable: bool,
}

impl GameVersionInfo for QuiltGameVersion {
    fn version(&self) -> &str {
        &self.version
    }

    fn stable(&self) -> bool {
        self.stable
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct QuiltLoaderVersion {
    // The pipeline only reads `version`; the descriptive fields default so a
    // benign upstream API change (dropping or renaming one of them) cannot
    // fail the whole versions-list parse and halt quilt processing. The
    // fabric twin defaults its equivalents for the same reason.
    #[serde(default)]
    pub separator: String,
    #[serde(default)]
    pub build: u32,
    #[serde(default)]
    pub maven: String,
    pub version: String,
    // Note: Quilt API does not include a 'stable' field
}

impl LoaderVersionInfo for QuiltLoaderVersion {
    fn version(&self) -> &str {
        &self.version
    }

    fn stable(&self) -> Option<bool> {
        // Quilt doesn't provide stability information
        None
    }
}
