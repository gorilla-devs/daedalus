use super::{GameVersionInfo, LoaderStrategy, LoaderVersionInfo, LoaderVersionsList};
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
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FabricGameVersion {
    pub version: String,
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
    pub separator: String,
    pub build: u32,
    pub maven: String,
    pub version: String,
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
