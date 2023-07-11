//! # Daedalus
//!
//! Daedalus is a library which provides models and methods to fetch metadata about games

#![warn(missing_docs, unused_import_braces, missing_debug_implementations)]

use std::{convert::TryFrom, fmt::Display, str::FromStr};

use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};

/// Models and methods for fetching metadata for Minecraft
pub mod minecraft;
/// Models and methods for fetching metadata for Minecraft mod loaders
pub mod modded;

/// Your branding, used for the user agent and similar
#[derive(Debug)]
pub struct Branding {
    /// The name of your application
    pub header_value: String,
    /// The string to replace in the name of the application
    pub dummy_replace_string: String,
}

/// The branding of your application
pub static BRANDING: OnceCell<Branding> = OnceCell::new();

impl Branding {
    /// Creates a new branding instance
    pub fn new(name: String, email: String) -> Branding {
        let email = format!(
            "{}/daedalus/{} <{}>",
            name,
            env!("CARGO_PKG_VERSION"),
            email
        );
        let dummy_replace_string = format!("${{{}.gameVersion}}", name);

        Branding {
            header_value: email,
            dummy_replace_string,
        }
    }

    /// Returns the branding instance
    pub fn set_branding(branding: Branding) -> Result<(), Error> {
        BRANDING
            .set(branding)
            .map_err(|_| Error::BrandingAlreadySet)
    }
}

impl Default for Branding {
    fn default() -> Self {
        Branding::new("unbranded".to_string(), "unbranded".to_string())
    }
}

#[derive(thiserror::Error, Debug)]
/// An error type representing possible errors when fetching metadata
pub enum Error {
    #[error("Failed to validate file checksum at url {url} with hash {hash} after {tries} tries")]
    /// A checksum was failed to validate for a file
    ChecksumFailure {
        /// The checksum's hash
        hash: String,
        /// The URL of the file attempted to be downloaded
        url: String,
        /// The amount of tries that the file was downloaded until failure
        tries: u32,
    },
    /// There was an error while deserializing metadata
    #[error("Error while deserializing JSON")]
    SerdeError(#[from] serde_json::Error),
    /// There was a network error when fetching an object
    #[error("Unable to fetch {item}")]
    FetchError {
        /// The internal reqwest error
        inner: reqwest::Error,
        /// The item that was failed to be fetched
        item: String,
    },
    /// There was an error when managing async tasks
    #[error("Error while managing asynchronous tasks")]
    TaskError(#[from] tokio::task::JoinError),
    /// Error while parsing input
    #[error("{0}")]
    ParseError(String),
    /// The branding has already been set
    #[error("Branding already set")]
    BrandingAlreadySet,
    /// Invalid Minecraft Java Profile
    #[error("Invalid Minecraft Java Profile")]
    InvalidMinecraftJavaProfile(String),
}

#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Clone, Default)]
/// A specifier string for Gradle
pub struct GradleSpecifier {
    /// The groups of the artifact
    pub package: String,
    /// Artifact name
    pub artifact: String,
    /// Classifier of the artifact
    pub data: Option<String>,
    /// Version of the artifact
    pub version: String,
    /// File extension
    pub extension: String,
}

impl GradleSpecifier {
    /// Returns the filename of the artifact
    pub fn filename(&self) -> String {
        if let Some(classifier) = &self.data {
            format!(
                "{}-{}-{}.{}",
                self.artifact, self.version, classifier, self.extension
            )
        } else {
            format!("{}-{}.{}", self.artifact, self.version, self.extension)
        }
    }

    /// returns the base path of the artifact
    pub fn base(&self) -> String {
        format!(
            "{}/{}/{}",
            self.package.replace(".", "/"),
            self.artifact,
            self.version
        )
    }

    /// Returns the full path of the artifact
    pub fn path(&self) -> String {
        format!("{}/{}", self.base(), self.filename())
    }

    /// Returns if specifier belongs to a lwjgl library
    pub fn is_lwjgl(&self) -> bool {
        vec![
            "org.lwjgl",
            "org.lwjgl.lwjgl",
            "net.java.jinput",
            "net.java.jutils",
        ]
        .contains(&self.package.as_str())
    }

    /// returns if the specifier belongs to a log4j library
    pub fn is_log4j(&self) -> bool {
        self.package.as_str() == "org.apache.logging.log4j"
    }
}

impl FromStr for GradleSpecifier {
    type Err = Error;

    fn from_str(specifier: &str) -> Result<Self, Self::Err> {
        let at_split = specifier.split('@').collect::<Vec<&str>>();

        let name_items = at_split
            .first()
            .ok_or_else(|| {
                Error::ParseError(format!(
                    "Invalid Gradle Specifier for library {}",
                    &specifier
                ))
            })?
            .split(':')
            .collect::<Vec<&str>>();

        let package = name_items
            .first()
            .ok_or_else(|| {
                Error::ParseError(format!(
                    "Unable to find package for library {}",
                    &specifier
                ))
            })?
            .to_string();
        let artifact = name_items
            .get(1)
            .ok_or_else(|| {
                Error::ParseError(format!(
                    "Unable to find name for library {}",
                    &specifier
                ))
            })?
            .to_string();
        let version = name_items
            .get(2)
            .ok_or_else(|| {
                Error::ParseError(format!(
                    "Unable to find version for library {}",
                    &specifier
                ))
            })?
            .to_string();

        let extension = if at_split.len() == 2 {
            at_split[1].to_string()
        } else {
            "jar".to_string()
        };

        let data = if name_items.len() == 4 {
            Some(
                name_items
                    .get(3)
                    .ok_or_else(|| {
                        Error::ParseError(format!(
                            "Unable to find data for library {}",
                            &specifier
                        ))
                    })?
                    .to_string(),
            )
        } else {
            None
        };
        Ok(GradleSpecifier {
            package,
            artifact,
            data,
            version,
            extension,
        })
    }
}

impl TryFrom<&str> for GradleSpecifier {
    type Error = Error;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl Display for GradleSpecifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let extension = if self.extension != "jar" {
            format!("@{}", self.extension)
        } else {
            String::new()
        };

        if let Some(classifier) = self.data.as_ref() {
            write!(
                f,
                "{}:{}:{}:{}{}",
                self.package,
                self.artifact,
                self.version,
                classifier,
                extension
            )
        } else {
            write!(
                f,
                "{}:{}:{}{}",
                self.package, self.artifact, self.version, extension
            )
        }
    }
}

impl Serialize for GradleSpecifier {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for GradleSpecifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// Converts a maven artifact to a path
pub fn get_path_from_artifact(artifact: &str) -> Result<String, Error> {
    let gradle_spec: GradleSpecifier = artifact.parse()?;

    Ok(gradle_spec.path())
}

/// Downloads a file from specified mirrors
pub async fn download_file_mirrors(
    base: &str,
    mirrors: &[&str],
    sha1: Option<&str>,
) -> Result<bytes::Bytes, Error> {
    if mirrors.is_empty() {
        return Err(Error::ParseError("No mirrors provided!".to_string()));
    }

    for (index, mirror) in mirrors.iter().enumerate() {
        let result = download_file(&format!("{}{}", mirror, base), sha1).await;

        if result.is_ok() || (result.is_err() && index == (mirrors.len() - 1)) {
            return result;
        }
    }

    unreachable!()
}

/// Downloads a file with retry and checksum functionality
pub async fn download_file(
    url: &str,
    sha1: Option<&str>,
) -> Result<bytes::Bytes, Error> {
    let mut headers = reqwest::header::HeaderMap::new();
    if let Ok(header) = reqwest::header::HeaderValue::from_str(
        &BRANDING.get_or_init(Branding::default).header_value,
    ) {
        headers.insert(reqwest::header::USER_AGENT, header);
    }
    let client = reqwest::Client::builder()
        .tcp_keepalive(Some(std::time::Duration::from_secs(10)))
        .timeout(std::time::Duration::from_secs(15))
        .default_headers(headers)
        .build()
        .map_err(|err| Error::FetchError {
            inner: err,
            item: url.to_string(),
        })?;

    for attempt in 1..=4 {
        let result = client.get(url).send().await;

        match result {
            Ok(x) => {
                let bytes = x.bytes().await;

                if let Ok(bytes) = bytes {
                    if let Some(sha1) = sha1 {
                        if &*get_hash(bytes.clone()).await? != sha1 {
                            if attempt <= 3 {
                                continue;
                            } else {
                                return Err(Error::ChecksumFailure {
                                    hash: sha1.to_string(),
                                    url: url.to_string(),
                                    tries: attempt,
                                });
                            }
                        }
                    }

                    return Ok(bytes);
                } else if attempt <= 3 {
                    continue;
                } else if let Err(err) = bytes {
                    return Err(Error::FetchError {
                        inner: err,
                        item: url.to_string(),
                    });
                }
            }
            Err(_) if attempt <= 3 => continue,
            Err(err) => {
                return Err(Error::FetchError {
                    inner: err,
                    item: url.to_string(),
                })
            }
        }
    }

    unreachable!()
}

/// Computes a checksum of the input bytes
pub async fn get_hash(bytes: bytes::Bytes) -> Result<String, Error> {
    let hash =
        tokio::task::spawn_blocking(|| sha1::Sha1::from(bytes).hexdigest())
            .await?;

    Ok(hash)
}
