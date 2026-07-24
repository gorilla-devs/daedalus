use crate::loaders::LoaderProcessor;
use crate::loaders::fabric::{FabricStrategy, FabricVersions};
use crate::services::upload::BatchUploader;
use daedalus::minecraft::VersionManifest;
use std::sync::Arc;
use tokio::sync::Semaphore;

/// Retrieve Fabric loader data by running the generic `LoaderProcessor` with
/// the Fabric strategy.
pub async fn retrieve_data(
    minecraft_versions: &VersionManifest,
    uploader: &BatchUploader,
    manifest_builder: &crate::services::cas::ManifestBuilder,
    s3_client: &s3::Bucket,
    semaphore: Arc<Semaphore>,
) -> Result<(), crate::infrastructure::error::Error> {
    let processor = LoaderProcessor::new(FabricStrategy);
    processor
        .retrieve_data::<FabricVersions>(
            minecraft_versions,
            uploader,
            manifest_builder,
            s3_client,
            semaphore,
        )
        .await
}
