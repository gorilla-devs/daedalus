use crate::loaders::fabric::{FabricStrategy, FabricVersions};
use crate::loaders::LoaderProcessor;
use crate::services::upload::UploadQueue;
use daedalus::minecraft::VersionManifest;
use std::sync::Arc;
use tokio::sync::Semaphore;

/// Retrieve Fabric loader data using the strategy pattern
///
/// This is now a thin wrapper around the generic LoaderProcessor.
/// All the common logic has been extracted to the strategy pattern,
/// eliminating hundreds of lines of duplicated code.
pub async fn retrieve_data(
    minecraft_versions: &VersionManifest,
    upload_queue: &UploadQueue,
    manifest_builder: &crate::services::cas::ManifestBuilder,
    semaphore: Arc<Semaphore>,
) -> Result<(), crate::infrastructure::error::Error> {
    let processor = LoaderProcessor::new(FabricStrategy);
    processor
        .retrieve_data::<FabricVersions>(minecraft_versions, upload_queue, manifest_builder, semaphore)
        .await
}
