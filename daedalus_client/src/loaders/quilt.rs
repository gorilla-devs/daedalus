use super::{GameVersionInfo, LoaderStrategy, LoaderVersionInfo, LoaderVersionsList};
use serde::{Deserialize, Serialize};

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
        "https://maven.quiltmc.org/"
    }

    fn manifest_path_prefix(&self) -> &str {
        "quilt"
    }

    fn is_stable(&self, _loader: &dyn LoaderVersionInfo) -> bool {
        // Quilt API does not include stability information
        // Default to false (unstable)
        false
    }
}

/// Quilt API response structure
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct QuiltVersions {
    pub game: Vec<QuiltGameVersion>,
    pub loader: Vec<QuiltLoaderVersion>,
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
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct QuiltGameVersion {
    pub version: String,
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
    pub separator: String,
    pub build: u32,
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
