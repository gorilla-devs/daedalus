use crate::loaders::LoaderProcessor;
use crate::loaders::quilt::{QuiltStrategy, QuiltVersions};
use crate::services::upload::BatchUploader;
use daedalus::minecraft::VersionManifest;
use std::sync::Arc;
use tokio::sync::Semaphore;

/// Retrieve Quilt loader data by running the generic `LoaderProcessor` with
/// the Quilt strategy.
pub async fn retrieve_data(
    minecraft_versions: &VersionManifest,
    uploader: &BatchUploader,
    manifest_builder: &crate::services::cas::ManifestBuilder,
    s3_client: &s3::Bucket,
    semaphore: Arc<Semaphore>,
) -> Result<(), crate::infrastructure::error::Error> {
    let processor = LoaderProcessor::new(QuiltStrategy);
    processor
        .retrieve_data::<QuiltVersions>(
            minecraft_versions,
            uploader,
            manifest_builder,
            s3_client,
            semaphore,
        )
        .await
}
