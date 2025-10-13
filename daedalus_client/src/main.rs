use backon::{ExponentialBuilder, Retryable};
use daedalus::Branding;
use tracing::{error, info, warn, instrument, Instrument};
use s3::creds::Credentials;
use s3::{Bucket, Region};
use std::ffi::OsStr;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tokio::sync::{Mutex, Semaphore};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

mod fabric;
mod infrastructure;
mod forge;
mod loaders;
mod minecraft;
mod neoforge;
mod quilt;
mod services;

fn main() -> Result<(), crate::infrastructure::error::Error> {
    #[cfg(feature = "sentry")]
    let _guard = sentry::init((
        dotenvy::var("SENTRY_DSN").unwrap(),
        sentry::ClientOptions {
            release: sentry::release_name!(),
            ..Default::default()
        },
    ));

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let use_json = dotenvy::var("LOG_FORMAT")
                .map(|v| v == "json")
                .unwrap_or(false);

            let filter = if std::env::var("RUST_LOG").is_ok() {
                println!("Loaded logger directives from RUST_LOG env");
                EnvFilter::from_env("RUST_LOG")
            } else {
                EnvFilter::new("daedalus_client=info")
            };

            let betterstack_token = dotenvy::var("BETTERSTACK_TOKEN").ok();
            let _betterstack_handle = if let Some(ref token) = betterstack_token {
                let (betterstack_layer, handle) = services::betterstack::BetterstackLayer::new(
                    token.clone(),
                    None,
                    None,
                );

                if use_json {
                    let json_layer = tracing_subscriber::fmt::layer()
                        .json()
                        .with_target(true)
                        .with_thread_ids(true)
                        .with_thread_names(true)
                        .with_file(true)
                        .with_line_number(true);

                    tracing_subscriber::registry()
                        .with(json_layer)
                        .with(betterstack_layer)
                        .with(filter)
                        .init();

                    info!(
                        version = env!("CARGO_PKG_VERSION"),
                        format = "json",
                        betterstack_enabled = true,
                        "Initialized JSON logging with Betterstack integration"
                    );
                } else {
                    let pretty_layer = tracing_subscriber::fmt::layer()
                        .with_target(true)
                        .with_ansi(true)
                        .pretty()
                        .with_thread_names(true);

                    tracing_subscriber::registry()
                        .with(pretty_layer)
                        .with(betterstack_layer)
                        .with(filter)
                        .init();

                    info!(
                        version = env!("CARGO_PKG_VERSION"),
                        format = "pretty",
                        betterstack_enabled = true,
                        "Initialized pretty logging with Betterstack integration"
                    );
                }

                Some(handle)
            } else {
                if use_json {
                    let json_layer = tracing_subscriber::fmt::layer()
                        .json()
                        .with_target(true)
                        .with_thread_ids(true)
                        .with_thread_names(true)
                        .with_file(true)
                        .with_line_number(true);

                    tracing_subscriber::registry()
                        .with(json_layer)
                        .with(filter)
                        .init();

                    info!(
                        version = env!("CARGO_PKG_VERSION"),
                        format = "json",
                        "Initialized JSON logging (production mode)"
                    );
                } else {
                    let pretty_layer = tracing_subscriber::fmt::layer()
                        .with_target(true)
                        .with_ansi(true)
                        .pretty()
                        .with_thread_names(true);

                    tracing_subscriber::registry()
                        .with(pretty_layer)
                        .with(filter)
                        .init();

                    info!(
                        version = env!("CARGO_PKG_VERSION"),
                        format = "pretty",
                        "Initialized pretty logging (development mode)"
                    );
                }

                None
            };

            if check_env_vars() {
                return Err(crate::infrastructure::error::invalid_input("Some environment variables are missing!"));
            }

            Branding::set_branding(Branding::new(
                dotenvy::var("BRAND_NAME").unwrap(),
                dotenvy::var("SUPPORT_EMAIL").unwrap(),
            ))
            .unwrap();

            let mut timer = tokio::time::interval(Duration::from_secs(60 * 60));
            let semaphore = Arc::new(Semaphore::new(10));

            {
                let uploaded_files = Arc::new(Mutex::new(Vec::new()));

                match upload_static_files(&uploaded_files, semaphore.clone())
                    .await
                {
                    Ok(()) => {}
                    Err(err) => {
                        error!("{:?}", err);
                    }
                }
            }

            let mut is_first_run = true;

            loop {
                let loop_span = tracing::info_span!("processing_cycle", is_first_run);
                async {
                    info!("Waiting for next update timer");
                    timer.tick().await;

                    let upload_queue = services::upload::UploadQueue::new();
                    let manifest_builder = services::cas::ManifestBuilder::new();

                    let versions = {
                        let span = tracing::info_span!("minecraft_processing");
                        async {
                            match MINECRAFT_BREAKER.call(async {
                                minecraft::retrieve_data(
                                    &upload_queue,
                                    &manifest_builder,
                                    semaphore.clone(),
                                    is_first_run,
                                )
                                .await
                            })
                            .await
                            {
                                Ok(res) => {
                                    info!(version_count = res.versions.len(), "Minecraft data retrieved");
                                    Some(res)
                                }
                                Err(crate::infrastructure::circuit_breaker::CircuitBreakerError::Open) => {
                                    warn!("Minecraft circuit breaker is open, skipping");
                                    None
                                }
                                Err(crate::infrastructure::circuit_breaker::CircuitBreakerError::Failed(err)) => {
                                    error!(error = %err, "Minecraft processing failed");
                                    None
                                }
                            }
                        }
                        .instrument(span)
                        .await
                    };

                    if let Some(manifest) = versions {
                        if cfg!(feature = "fabric") {
                            let span = tracing::info_span!("fabric_processing");
                            async {
                                match FABRIC_BREAKER.call(async {
                                    fabric::retrieve_data(
                                        &manifest,
                                        &upload_queue,
                                        &manifest_builder,
                                        semaphore.clone(),
                                    )
                                    .await
                                })
                                .await
                                {
                                    Ok(_) => info!("Fabric processing completed"),
                                    Err(crate::infrastructure::circuit_breaker::CircuitBreakerError::Open) => {
                                        warn!("Fabric circuit breaker is open, skipping");
                                    }
                                    Err(crate::infrastructure::circuit_breaker::CircuitBreakerError::Failed(err)) => {
                                        error!(error = %err, "Fabric processing failed");
                                    }
                                }
                            }
                            .instrument(span)
                            .await;
                        }

                        if cfg!(feature = "forge") {
                            let span = tracing::info_span!("forge_processing");
                            async {
                                match FORGE_BREAKER.call(async {
                                    forge::retrieve_data(
                                        &manifest,
                                        &upload_queue,
                                        &manifest_builder,
                                        semaphore.clone(),
                                    )
                                    .await
                                })
                                .await
                                {
                                    Ok(_) => info!("Forge processing completed"),
                                    Err(crate::infrastructure::circuit_breaker::CircuitBreakerError::Open) => {
                                        warn!("Forge circuit breaker is open, skipping");
                                    }
                                    Err(crate::infrastructure::circuit_breaker::CircuitBreakerError::Failed(err)) => {
                                        error!(error = %err, "Forge processing failed");
                                    }
                                }
                            }
                            .instrument(span)
                            .await;
                        }

                        if cfg!(feature = "quilt") {
                            let span = tracing::info_span!("quilt_processing");
                            async {
                                match QUILT_BREAKER.call(async {
                                    quilt::retrieve_data(
                                        &manifest,
                                        &upload_queue,
                                        &manifest_builder,
                                        semaphore.clone(),
                                    )
                                    .await
                                })
                                .await
                                {
                                    Ok(_) => info!("Quilt processing completed"),
                                    Err(crate::infrastructure::circuit_breaker::CircuitBreakerError::Open) => {
                                        warn!("Quilt circuit breaker is open, skipping");
                                    }
                                    Err(crate::infrastructure::circuit_breaker::CircuitBreakerError::Failed(err)) => {
                                        error!(error = %err, "Quilt processing failed");
                                    }
                                }
                            }
                            .instrument(span)
                            .await;
                        }

                        if cfg!(feature = "neoforge") {
                            let span = tracing::info_span!("neoforge_processing");
                            async {
                                match NEOFORGE_BREAKER.call(async {
                                    neoforge::retrieve_data(
                                        &manifest,
                                        &upload_queue,
                                        &manifest_builder,
                                        semaphore.clone(),
                                    )
                                    .await
                                })
                                .await
                                {
                                    Ok(_) => info!("NeoForge processing completed"),
                                    Err(crate::infrastructure::circuit_breaker::CircuitBreakerError::Open) => {
                                        warn!("NeoForge circuit breaker is open, skipping");
                                    }
                                    Err(crate::infrastructure::circuit_breaker::CircuitBreakerError::Failed(err)) => {
                                        error!(error = %err, "NeoForge processing failed");
                                    }
                                }
                            }
                            .instrument(span)
                            .await;
                        }

                        info!(queued_count = upload_queue.len(), "Flushing CAS objects and path-based files");
                        let flush_result = upload_queue.flush(&CLIENT, semaphore.clone()).await;
                        if let Err(e) = flush_result {
                            error!(error = %e, "Failed to flush upload queue - skipping manifest upload this cycle");
                        } else {
                            info!("Upload queue flushed successfully");
                        let timestamp = chrono::Utc::now().format("%Y-%m-%dT%H-%M-%SZ").to_string();
                        let mut loader_references = std::collections::HashMap::new();
                        let mut uploaded_manifest_urls = Vec::new();

                        let all_loaders = manifest_builder.get_loaders();
                        info!(loader_count = all_loaders.len(), "Building loader manifests");

                        for loader in &all_loaders {
                            if let Some(loader_manifest) = manifest_builder.build_loader_manifest(loader) {
                                let manifest_path = format!("v{}/manifests/{}/{}.json", crate::services::cas::CAS_VERSION, loader, loader_manifest.timestamp);

                                info!(
                                    loader = %loader,
                                    version_count = loader_manifest.versions.len(),
                                    path = %manifest_path,
                                    "Uploading loader manifest"
                                );

                                match serde_json::to_vec_pretty(&loader_manifest) {
                                    Ok(manifest_bytes) => {
                                        match upload_file_to_bucket(
                                            manifest_path.clone(),
                                            manifest_bytes,
                                            Some("application/json".to_string()),
                                            &tokio::sync::Mutex::new(Vec::new()),
                                            semaphore.clone(),
                                        ).await {
                                            Ok(_) => {
                                                info!(loader = %loader, "Loader manifest uploaded successfully");
                                                loader_references.insert(
                                                    loader.clone(),
                                                    services::cas::LoaderReference::new(loader, loader_manifest.timestamp.clone())
                                                );
                                                uploaded_manifest_urls.push(format!("{}/{}", dotenvy::var("BASE_URL").unwrap(), manifest_path));
                                            }
                                            Err(e) => {
                                                error!(loader = %loader, error = %e, "Failed to upload loader manifest");
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        error!(loader = %loader, error = %e, "Failed to serialize loader manifest");
                                    }
                                }
                            }
                        }

                        if !loader_references.is_empty() {
                            let root_manifest = services::cas::RootManifest::new(loader_references);
                            let root_path = format!("v{}/manifest.json", crate::services::cas::CAS_VERSION);

                            info!("Uploading root manifest (atomic commit point)");

                            match serde_json::to_vec_pretty(&root_manifest) {
                                Ok(root_bytes) => {
                                    match upload_file_to_bucket(
                                        root_path.clone(),
                                        root_bytes.clone(),
                                        Some("application/json".to_string()),
                                        &tokio::sync::Mutex::new(Vec::new()),
                                        semaphore.clone(),
                                    ).await {
                                        Ok(_) => {
                                            info!("Root manifest uploaded successfully - all changes are now live");
                                            uploaded_manifest_urls.push(format!("{}/{}", dotenvy::var("BASE_URL").unwrap(), root_path));
                                        }
                                        Err(e) => {
                                            error!(error = %e, "Failed to upload root manifest - changes NOT committed");
                                        }
                                    }

                                    let backup_path = format!("v{}/history/manifest-{}.json", crate::services::cas::CAS_VERSION, timestamp);
                                    info!(backup_path = %backup_path, "Creating backup of root manifest");

                                    match upload_file_to_bucket(
                                        backup_path,
                                        root_bytes,
                                        Some("application/json".to_string()),
                                        &tokio::sync::Mutex::new(Vec::new()),
                                        semaphore.clone(),
                                    ).await {
                                        Ok(_) => info!("Backup created successfully"),
                                        Err(e) => warn!(error = %e, "Failed to create backup (non-fatal)"),
                                    }
                                }
                                Err(e) => {
                                    error!(error = %e, "Failed to serialize root manifest");
                                }
                            }

                            info!("Processing cycle completed successfully");

                            if !uploaded_manifest_urls.is_empty() {
                                let cloudflare_enabled = dotenvy::var("CLOUDFLARE_INTEGRATION")
                                    .map(|v| v == "true")
                                    .unwrap_or(false);

                                if cloudflare_enabled {
                                    match (
                                        dotenvy::var("CLOUDFLARE_TOKEN"),
                                        dotenvy::var("CLOUDFLARE_ZONE_ID"),
                                    ) {
                                        (Ok(token), Ok(zone_id)) => {
                                            match services::cloudflare::purge_cloudflare_cache(&token, &zone_id, &uploaded_manifest_urls).await {
                                                Ok(_) => {
                                                    info!("Cloudflare cache purge successful");
                                                }
                                                Err(e) => {
                                                    warn!(error = %e, "Cloudflare cache purge failed, but continuing");
                                                }
                                            }
                                        }
                                        _ => {
                                            warn!(
                                                "CLOUDFLARE_INTEGRATION is enabled but CLOUDFLARE_TOKEN or \
                                                 CLOUDFLARE_ZONE_ID is missing"
                                            );
                                        }
                                    }
                                } else {
                                    info!("Cloudflare cache purging disabled (set CLOUDFLARE_INTEGRATION=true to enable)");
                                }
                            }
                        } else {
                            warn!("No loader manifests were built - skipping root manifest upload");
                        }
                    }
                    }

                    is_first_run = false;
                }
                .instrument(loop_span)
                .await;
            }
        })
}

fn check_env_vars() -> bool {
    let mut failed = false;

    fn check_var<T: std::str::FromStr>(var: &str) -> bool {
        if dotenvy::var(var)
            .ok()
            .and_then(|s| s.parse::<T>().ok())
            .is_none()
        {
            warn!(
                "Variable `{}` missing in dotenvy or not of type `{}`",
                var,
                std::any::type_name::<T>()
            );
            true
        } else {
            false
        }
    }

    failed |= check_var::<String>("BASE_URL");

    failed |= check_var::<String>("S3_ACCESS_TOKEN");
    failed |= check_var::<String>("S3_SECRET");
    failed |= check_var::<String>("S3_URL");
    failed |= check_var::<String>("S3_REGION");
    failed |= check_var::<String>("S3_BUCKET_NAME");

    failed |= check_var::<String>("BRAND_NAME");
    failed |= check_var::<String>("SUPPORT_EMAIL");

    failed
}

static CLIENT: LazyLock<Bucket> = LazyLock::new(|| {
    let bucket = Bucket::new(
        &dotenvy::var("S3_BUCKET_NAME").unwrap(),
        if &*dotenvy::var("S3_REGION").unwrap() == "r2" {
            Region::R2 {
                account_id: dotenvy::var("S3_URL").unwrap(),
            }
        } else {
            Region::Custom {
                region: dotenvy::var("S3_REGION").unwrap(),
                endpoint: dotenvy::var("S3_URL").unwrap(),
            }
        },
        Credentials::new(
            Some(&*dotenvy::var("S3_ACCESS_TOKEN").unwrap()),
            Some(&*dotenvy::var("S3_SECRET").unwrap()),
            None,
            None,
            None,
        )
        .unwrap(),
    )
    .unwrap();

    bucket.with_path_style()
});

static MINECRAFT_BREAKER: LazyLock<crate::infrastructure::circuit_breaker::CircuitBreaker> = LazyLock::new(|| {
    crate::infrastructure::circuit_breaker::CircuitBreaker::new("minecraft", 5, Duration::from_secs(300))
});

static FORGE_BREAKER: LazyLock<crate::infrastructure::circuit_breaker::CircuitBreaker> = LazyLock::new(|| {
    crate::infrastructure::circuit_breaker::CircuitBreaker::new("forge", 5, Duration::from_secs(300))
});

static FABRIC_BREAKER: LazyLock<crate::infrastructure::circuit_breaker::CircuitBreaker> = LazyLock::new(|| {
    crate::infrastructure::circuit_breaker::CircuitBreaker::new("fabric", 5, Duration::from_secs(300))
});

static QUILT_BREAKER: LazyLock<crate::infrastructure::circuit_breaker::CircuitBreaker> = LazyLock::new(|| {
    crate::infrastructure::circuit_breaker::CircuitBreaker::new("quilt", 5, Duration::from_secs(300))
});

static NEOFORGE_BREAKER: LazyLock<crate::infrastructure::circuit_breaker::CircuitBreaker> = LazyLock::new(|| {
    crate::infrastructure::circuit_breaker::CircuitBreaker::new("neoforge", 5, Duration::from_secs(300))
});

#[instrument(skip(bytes, uploaded_files, semaphore), fields(size = bytes.len()))]
pub async fn upload_file_to_bucket(
    path: String,
    bytes: Vec<u8>,
    content_type: Option<String>,
    uploaded_files: &tokio::sync::Mutex<Vec<String>>,
    semaphore: Arc<Semaphore>,
) -> Result<(), crate::infrastructure::error::Error> {
    let _permit = semaphore.acquire().await?;

    info!(path = %path, "Started uploading");

    (|| async {
        let key = path.clone();

        let result = if let Some(ref content_type) = content_type {
            CLIENT
                .put_object_with_content_type(key.clone(), &bytes, content_type)
                .await
        } else {
            CLIENT.put_object(key.clone(), &bytes).await
        }
        .map_err(|err| {
            error!(path = %path, error = %err, "Failed to upload");
            crate::infrastructure::error::s3_error(err, path.clone())
        });

        match result {
            Ok(_) => {
                {
                    info!(path = %path, "Upload completed");
                    let mut uploaded_files = uploaded_files.lock().await;
                    uploaded_files.push(key);
                }

                Ok(())
            }
            Err(err) => {
                error!(path = %path, error = %err, "Upload failed");
                Err(err)
            }
        }
    })
    .retry(
        ExponentialBuilder::default()
            .with_max_times(10)
            .with_max_delay(Duration::from_secs(1800)),
    )
    .await
}

pub fn format_url(path: &str) -> String {
    let base_url = &*dotenvy::var("BASE_URL").unwrap();
    let full_url = format!("{}/{}", base_url, path);
    info!(path = %path, url = %full_url, "Formatted URL");
    full_url
}

pub use services::download::{download_file, download_file_mirrors};

#[instrument(skip(uploaded_files, semaphore))]
pub async fn upload_static_files(
    uploaded_files: &tokio::sync::Mutex<Vec<String>>,
    semaphore: Arc<Semaphore>,
) -> Result<(), crate::infrastructure::error::Error> {
    use path_slash::PathExt as _;
    let cdn_upload_dir =
        dotenvy::var("CDN_UPLOAD_DIR").unwrap_or("./upload_cdn".to_string());

    info!(dir = %cdn_upload_dir, "Uploading static files");

    if !std::path::Path::new(&cdn_upload_dir).exists() {
        panic!("CDN_UPLOAD_DIR does not exist");
    }

    for entry in walkdir::WalkDir::new(&cdn_upload_dir) {
        let entry = entry.map_err(|e| {
            crate::infrastructure::error::ErrorKind::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to walk directory: {}", e),
            ))
        })?;
        if entry.path().is_file() {
            let upload_path = entry.path()
                .strip_prefix(&cdn_upload_dir)
                .expect("Unwrap to be safe because we are striping the prefix to the directory walked")
                 .to_slash()
                .ok_or_else(|| {
                    crate::infrastructure::error::invalid_input(format!(
                        "Failed to convert path to utf8 string {}",
                        entry.path().display()
                    ))
                })?;

            if upload_path.ends_with(".DS_Store") {
                continue;
            }

            info!(
                file = %entry.path().display(),
                cdn_path = %upload_path,
                "Uploading static file to CDN"
            );

            let content_type =
                match entry.path().extension().and_then(OsStr::to_str) {
                    Some("json") => Some("application/json".to_string()),
                    Some("jar") => Some("application/java-archive".to_string()),
                    _ => None,
                };

            upload_file_to_bucket(
                upload_path.to_string(), // NOTE: if path is non utf8 this will not be a pretty path
                std::fs::read(entry.path())?,
                content_type,
                uploaded_files,
                semaphore.clone(),
            )
            .await?;
        }
    }
    Ok(())
}
