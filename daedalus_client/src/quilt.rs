use crate::loaders::quilt::{QuiltStrategy, QuiltVersions};
use crate::loaders::LoaderProcessor;
use crate::services::upload::BatchUploader;
use daedalus::minecraft::VersionManifest;
use std::sync::Arc;
use tokio::sync::Semaphore;

/// Retrieve Quilt loader data using the strategy pattern
///
/// This is now a thin wrapper around the generic LoaderProcessor.
/// All the common logic has been extracted to the strategy pattern,
/// eliminating hundreds of lines of duplicated code.
pub async fn retrieve_data(
    minecraft_versions: &VersionManifest,
    uploader: &BatchUploader,
    manifest_builder: &crate::services::cas::ManifestBuilder,
    s3_client: &s3::Bucket,
    semaphore: Arc<Semaphore>,
) -> Result<(), crate::infrastructure::error::Error> {
    let processor = LoaderProcessor::new(QuiltStrategy);
    processor
        .retrieve_data::<QuiltVersions>(minecraft_versions, uploader, manifest_builder, s3_client, semaphore)
        .await
}
