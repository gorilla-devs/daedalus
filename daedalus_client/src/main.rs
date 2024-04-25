use anyhow::bail;
use backon::{ExponentialBuilder, Retryable};
use daedalus::Branding;
use log::{error, info, warn};
use s3::creds::Credentials;
use s3::{Bucket, Region};
use std::ffi::OsStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, Semaphore};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

mod fabric;
mod forge;
mod minecraft;
mod neoforge;
mod quilt;

fn main() -> Result<(), anyhow::Error> {
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
            let printer = tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_ansi(true)
                .pretty()
                .with_thread_names(true);

            let filter = EnvFilter::builder();

            let filter = if std::env::var("RUST_LOG").is_ok() {
                println!("loaded logger directives from `RUST_LOG` env");

                filter.from_env().expect("logger directives are invalid")
            } else {
                filter
                    .parse("info")
                    .expect("default logger directives are invalid")
            };

            tracing_subscriber::registry()
                .with(printer)
                .with(filter)
                .init();

            if check_env_vars() {
                bail!("Some environment variables are missing!");
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
                info!("Waiting for next update timer");
                timer.tick().await;

                let mut uploaded_files = Vec::new();

                let versions = match minecraft::retrieve_data(
                    &mut uploaded_files,
                    semaphore.clone(),
                    is_first_run,
                )
                .await
                {
                    Ok(res) => {
                        info!("Minecraft data retrieved");

                        Some(res)
                    }
                    Err(err) => {
                        error!("MC Error: {:?}", err);

                        None
                    }
                };

                if let Some(manifest) = versions {
                    if cfg!(feature = "fabric") {
                        fabric::retrieve_data(
                            &manifest,
                            &mut uploaded_files,
                            semaphore.clone(),
                        )
                        .await?;
                    }
                    if cfg!(feature = "forge") {
                        forge::retrieve_data(
                            &manifest,
                            &mut uploaded_files,
                            semaphore.clone(),
                        )
                        .await?;
                    }
                    if cfg!(feature = "quilt") {
                        quilt::retrieve_data(
                            &manifest,
                            &mut uploaded_files,
                            semaphore.clone(),
                        )
                        .await?;
                    }
                    if cfg!(feature = "neoforge") {
                        neoforge::retrieve_data(
                            &manifest,
                            &mut uploaded_files,
                            semaphore.clone(),
                        )
                        .await?;
                    }
                }

                is_first_run = false;
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

lazy_static::lazy_static! {
    static ref CLIENT : Bucket = {
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
            ).unwrap(),
        ).unwrap();

        bucket.with_path_style()
    };
}

pub async fn upload_file_to_bucket(
    path: String,
    bytes: Vec<u8>,
    content_type: Option<String>,
    uploaded_files: &tokio::sync::Mutex<Vec<String>>,
    semaphore: Arc<Semaphore>,
) -> Result<(), anyhow::Error> {
    let _permit = semaphore.acquire().await?;

    info!("{} started uploading", path);

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
            error!("{} failed to upload: {:?}", path, err);
            err
        });

        match result {
            Ok(_) => {
                {
                    info!("{} done uploading", path);
                    let mut uploaded_files = uploaded_files.lock().await;
                    uploaded_files.push(key);
                }

                return Ok(());
            }
            Err(err) => {
                error!("{} failed to upload: {:?}", path, err);
                return Err(err.into());
            }
        }
    })
    .retry(
        &ExponentialBuilder::default()
            .with_max_times(10)
            .with_max_delay(Duration::from_secs(1800)),
    )
    .await
}

pub fn format_url(path: &str) -> String {
    info!("{}/{}", &*dotenvy::var("BASE_URL").unwrap(), path);
    format!("{}/{}", &*dotenvy::var("BASE_URL").unwrap(), path)
}

pub async fn download_file(
    url: &str,
    sha1: Option<&str>,
    semaphore: Arc<Semaphore>,
) -> Result<bytes::Bytes, anyhow::Error> {
    let _permit = semaphore.acquire().await?;
    info!("{} started downloading", url);
    let val = daedalus::download_file(url, sha1).await?;
    info!("{} finished downloading", url);
    Ok(val)
}

pub async fn download_file_mirrors(
    base: &str,
    mirrors: &[&str],
    sha1: Option<&str>,
    semaphore: Arc<Semaphore>,
) -> Result<bytes::Bytes, anyhow::Error> {
    let _permit = semaphore.acquire().await?;
    info!("{} started downloading", base);
    let val = daedalus::download_file_mirrors(base, mirrors, sha1).await?;
    info!("{} finished downloading", base);

    Ok(val)
}

pub async fn upload_static_files(
    uploaded_files: &tokio::sync::Mutex<Vec<String>>,
    semaphore: Arc<Semaphore>,
) -> Result<(), anyhow::Error> {
    use path_slash::PathExt as _;
    let cdn_upload_dir =
        dotenvy::var("CDN_UPLOAD_DIR").unwrap_or("./upload_cdn".to_string());

    info!("uploading static files from {}", cdn_upload_dir);

    if !std::path::Path::new(&cdn_upload_dir).exists() {
        panic!("CDN_UPLOAD_DIR does not exist");
    }

    for entry in walkdir::WalkDir::new(&cdn_upload_dir) {
        let entry = entry?;
        if entry.path().is_file() {
            let upload_path = entry.path()
                .strip_prefix(&cdn_upload_dir)
                .expect("Unwrap to be safe because we are striping the prefix to the directory walked")
                 .to_slash()
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Failed to convert path to utf8 string {}",
                        entry.path().display()
                    )
                })?;
            info!(
                "uploading {} to cdn at path {}",
                entry.path().display(),
                upload_path
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
