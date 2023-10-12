use daedalus::Branding;
use log::{error, info, warn};
use s3::creds::Credentials;
use s3::error::S3Error;
use s3::{Bucket, Region};
use std::ffi::OsStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, Semaphore};

mod fabric;
mod forge;
mod minecraft;
mod neoforged;
mod quilt;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("{0}")]
    DaedalusError(#[from] daedalus::Error),
    #[error("Error while deserializing JSON")]
    SerdeError(#[from] serde_json::Error),
    #[error("Error while deserializing XML")]
    XMLError(#[from] serde_xml_rs::Error),
    #[error("Unable to fetch {item}")]
    FetchError { inner: reqwest::Error, item: String },
    #[error("Error while managing asynchronous tasks")]
    TaskError(#[from] tokio::task::JoinError),
    #[error("Error while uploading file to S3")]
    S3Error { inner: S3Error, file: String },
    #[error("Error while parsing version as semver: {0}")]
    SemVerError(#[from] semver::Error),
    #[error("Error while reading zip file: {0}")]
    ZipError(#[from] zip::result::ZipError),
    #[error("Error while reading zip file: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Error while obtaining strong reference to Arc")]
    ArcError,
    #[error("Error acquiring semaphore: {0}")]
    AcquireError(#[from] tokio::sync::AcquireError),
    #[error("Error parsing libraries: {0}")]
    LibraryError(String),
    #[error("Error uploading file: {0}")]
    WalkDirError(#[from] walkdir::Error),
    #[error("Error uploading file: {0}")]
    StaticUploadPathError(String),
}

#[tokio::main]
async fn main() {
    env_logger::init();

    if check_env_vars() {
        error!("Some environment variables are missing!");

        return;
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

        match upload_static_files(&uploaded_files, semaphore.clone()).await {
            Ok(()) => {}
            Err(err) => {
                error!("{:?}", err);
            }
        }
    }

    loop {
        info!("Waiting for next update timer");
        timer.tick().await;

        let mut uploaded_files = Vec::new();

        let versions = match minecraft::retrieve_data(
            &mut uploaded_files,
            semaphore.clone(),
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
                match fabric::retrieve_data(
                    &manifest,
                    &mut uploaded_files,
                    semaphore.clone(),
                )
                .await
                {
                    Ok(..) => {
                        info!("Fabric data retrieved")
                    }
                    Err(err) => error!("Fabric error: {:?}", err),
                };
            }
            if cfg!(feature = "forge") {
                match forge::retrieve_data(
                    &manifest,
                    &mut uploaded_files,
                    semaphore.clone(),
                )
                .await
                {
                    Ok(..) => {
                        info!("Forge data retrieved")
                    }
                    Err(err) => error!("Forge error: {:?}", err),
                };
            }
            if cfg!(feature = "quilt") {
                match quilt::retrieve_data(
                    &manifest,
                    &mut uploaded_files,
                    semaphore.clone(),
                )
                .await
                {
                    Ok(..) => {
                        info!("Quilt data retrieved")
                    }
                    Err(err) => error!("Quilt error: {:?}", err),
                };
            }
            if cfg!(feature = "neoforged") {
                match neoforged::retrieve_data(
                    &manifest,
                    &mut uploaded_files,
                    semaphore.clone(),
                )
                .await
                {
                    Ok(..) => {
                        info!("Neoforged data retrieved")
                    }
                    Err(err) => error!("Neoforged error: {:?}", err),
                };
            }
        }
    }
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
    static ref CLIENT : Bucket = Bucket::new(
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
}

pub async fn upload_file_to_bucket(
    path: String,
    bytes: Vec<u8>,
    content_type: Option<String>,
    uploaded_files: &tokio::sync::Mutex<Vec<String>>,
    semaphore: Arc<Semaphore>,
) -> Result<(), Error> {
    let _permit = semaphore.acquire().await?;

    if cfg!(feature = "save_local") {
        return save_file_local(path, bytes, uploaded_files).await;
    }

    info!("{} started uploading", path);
    let key = path.clone();

    for attempt in 1..=4 {
        let result = if let Some(ref content_type) = content_type {
            CLIENT
                .put_object_with_content_type(key.clone(), &bytes, content_type)
                .await
        } else {
            CLIENT.put_object(key.clone(), &bytes).await
        }
        .map_err(|err| Error::S3Error {
            inner: err,
            file: path.clone(),
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
            Err(_) if attempt <= 3 => continue,
            Err(_) => {
                result?;
            }
        }
    }
    unreachable!()
}

pub const LOCAL_SAVE_PATH: &str = "./bucket/";

/// mainly for testing
pub async fn save_file_local(
    path: String,
    bytes: Vec<u8>,
    uploaded_files: &tokio::sync::Mutex<Vec<String>>,
) -> Result<(), Error> {
    info!("{} saving locally", path);

    let local_save_dir = std::path::Path::new(&LOCAL_SAVE_PATH);
    let save_path = local_save_dir.join(&path);

    std::fs::create_dir_all(
        save_path.parent().expect("save path not to be a root path"),
    )
    .map_err(|err| Error::IoError(err))?;

    std::fs::write(&save_path, bytes).map_err(|err| Error::IoError(err))?;
    let mut uploaded_files = uploaded_files.lock().await;
    uploaded_files.push(path.clone());

    Ok(())
}

/// Load a local file
/// mainly for testing
pub fn load_file_local(path: String) -> Result<Vec<u8>, Error> {
    info!("{} saving locally", path);

    let local_save_dir = std::path::Path::new(&LOCAL_SAVE_PATH);
    let load_path = local_save_dir.join(&path);

    let bytes = std::fs::read(&load_path).map_err(|err| Error::IoError(err))?;

    Ok(bytes)
}

pub fn format_url(path: &str) -> String {
    format!("{}/{}", &*dotenvy::var("BASE_URL").unwrap(), path)
}

pub async fn download_file(
    url: &str,
    sha1: Option<&str>,
    semaphore: Arc<Semaphore>,
) -> Result<bytes::Bytes, Error> {
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
) -> Result<bytes::Bytes, Error> {
    let _permit = semaphore.acquire().await?;
    info!("{} started downloading", base);
    let val = daedalus::download_file_mirrors(base, mirrors, sha1).await?;
    info!("{} finished downloading", base);

    Ok(val)
}

pub async fn upload_static_files(
    uploaded_files: &tokio::sync::Mutex<Vec<String>>,
    semaphore: Arc<Semaphore>,
) -> Result<(), Error> {
    use path_slash::PathExt as _;
    let cdn_upload_dir =
        dotenvy::var("CDN_UPLOAD_DIR").unwrap_or("./upload_cdn".to_string());
    for entry in walkdir::WalkDir::new(&cdn_upload_dir) {
        let entry = entry?;
        if entry.path().is_file() {
            let upload_path = entry.path()
                .strip_prefix(&cdn_upload_dir)
                .expect("Unwrap to be safe because we are striping the prefix to the directory walked")
                 .to_slash()
                .ok_or_else(|| {
                    Error::StaticUploadPathError(
                        format!("Path {} contains non unicode characters", entry.path().display())
                    )
                })?;
            info!(
                "uploading {} to cnd at path {}",
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
