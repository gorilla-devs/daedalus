use super::{
    GameVersionInfo, LoaderStrategy, LoaderVersionInfo, LoaderVersionsList,
};
use serde::{Deserialize, Serialize};

/// Fabric loader strategy implementation
pub struct FabricStrategy;

impl LoaderStrategy for FabricStrategy {
    fn name(&self) -> &str {
        "Fabric"
    }

    fn meta_url(&self) -> &str {
        "https://meta.fabricmc.net/v2"
    }

    fn maven_fallback(&self) -> &str {
        "https://maven.fabricmc.net/"
    }

    fn manifest_path_prefix(&self) -> &str {
        "fabric"
    }

    fn is_stable(&self, loader: &dyn LoaderVersionInfo) -> bool {
        // Fabric API includes stability information
        loader.stable().unwrap_or(false)
    }
}

/// Fabric API response structure
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FabricVersions {
    pub game: Vec<FabricGameVersion>,
    pub loader: Vec<FabricLoaderVersion>,
    /// Game versions with a published intermediary mapping — the set that is
    /// actually installable. Required on purpose: if the meta API stops
    /// listing mappings, the parse must fail loudly (carry-forward keeps the
    /// previous manifest live) rather than publish loaders no client can
    /// resolve.
    pub intermediary: Vec<FabricMappingVersion>,
}

/// One entry of the meta API's mapping list (`intermediary`).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FabricMappingVersion {
    pub version: String,
}

impl LoaderVersionsList for FabricVersions {
    type Loader = FabricLoaderVersion;
    type Game = FabricGameVersion;

    fn loader(&self) -> &[Self::Loader] {
        &self.loader
    }

    fn game(&self) -> &[Self::Game] {
        &self.game
    }

    fn mapping_versions(&self) -> Vec<&str> {
        self.intermediary
            .iter()
            .map(|m| m.version.as_str())
            .collect()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FabricGameVersion {
    pub version: String,
    // `stable` was added to the Fabric API; treat absence as `false` so a
    // single missing field doesn't fail the entire version-list parse.
    #[serde(default)]
    pub stable: bool,
}

impl GameVersionInfo for FabricGameVersion {
    fn version(&self) -> &str {
        &self.version
    }

    fn stable(&self) -> bool {
        self.stable
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FabricLoaderVersion {
    #[serde(default)]
    pub separator: String,
    #[serde(default)]
    pub build: u32,
    pub maven: String,
    pub version: String,
    // `stable` may be absent on older loader entries; default to `false`.
    #[serde(default)]
    pub stable: bool,
}

impl LoaderVersionInfo for FabricLoaderVersion {
    fn version(&self) -> &str {
        &self.version
    }

    fn stable(&self) -> Option<bool> {
        Some(self.stable)
    }
}
