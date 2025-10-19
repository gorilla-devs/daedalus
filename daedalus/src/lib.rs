//! # Daedalus
//!
//! Daedalus is a library which provides models and methods to fetch metadata about games

#![warn(missing_docs, unused_import_braces, missing_debug_implementations)]

use std::{
    cmp::Ordering, convert::TryFrom, fmt::Display, path::PathBuf, str::FromStr,
    sync::LazyLock, time::Duration,
};

use backon::{ExponentialBuilder, Retryable};
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};

/// Models and methods for fetching metadata for Minecraft
pub mod minecraft;
/// Models and methods for fetching metadata for Minecraft mod loaders
pub mod modded;

/// HTTP client configuration constants
/// TCP keepalive interval for persistent connections
const TCP_KEEPALIVE_SECS: u64 = 10;
/// Overall request timeout including reading response
const REQUEST_TIMEOUT_SECS: u64 = 120;
/// Connection establishment timeout
const CONNECT_TIMEOUT_SECS: u64 = 30;
/// Maximum idle connections per host in the pool
const MAX_IDLE_CONNECTIONS_PER_HOST: usize = 10;

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

/// Global HTTP client with connection pooling and TCP keepalive
///
/// # Panics
/// Panics if the HTTP client fails to initialize. This is intentional as
/// the application cannot function without a working HTTP client (e.g., if
/// TLS initialization fails, which is extremely rare on modern systems).
static HTTP_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    let mut headers = reqwest::header::HeaderMap::new();
    if let Ok(header) = reqwest::header::HeaderValue::from_str(
        &BRANDING.get_or_init(Branding::default).header_value,
    ) {
        headers.insert(reqwest::header::USER_AGENT, header);
    }

    reqwest::Client::builder()
        .tcp_keepalive(Some(Duration::from_secs(TCP_KEEPALIVE_SECS)))
        .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
        .connect_timeout(Duration::from_secs(CONNECT_TIMEOUT_SECS))
        .default_headers(headers)
        .pool_max_idle_per_host(MAX_IDLE_CONNECTIONS_PER_HOST)
        .build()
        .expect("Failed to create HTTP client")
});

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
    #[error("Failed to validate file checksum at url {url} with hash {hash}")]
    /// A checksum was failed to validate for a file
    ChecksumFailure {
        /// The checksum's hash
        hash: String,
        /// The URL of the file attempted to be downloaded
        url: String,
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
    #[error("Mirrors failed to download")]
    /// Mirrors failed to download
    MirrorsFailed(String),
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Clone, Default)]
/// A specifier string for Gradle
pub struct GradleSpecifier {
    /// The groups of the artifact
    pub package: String,
    /// Artifact name
    pub artifact: String,
    /// Classifier of the artifact
    pub identifier: Option<String>,
    /// Version of the artifact
    pub version: String,
    /// File extension
    pub extension: String,
}

impl GradleSpecifier {
    /// Returns the filename of the artifact
    pub fn filename(&self) -> String {
        if let Some(identifier) = &self.identifier {
            format!(
                "{}-{}-{}.{}",
                &self.artifact, &self.version, identifier, &self.extension
            )
        } else {
            format!("{}-{}.{}", &self.artifact, &self.version, &self.extension)
        }
    }

    /// returns the base path of the artifact
    pub fn base(&self) -> String {
        format!(
            "{}/{}/{}",
            &self.package.replace('.', "/"),
            &self.artifact,
            &self.version
        )
    }

    /// Returns the full path of the artifact
    pub fn path(&self) -> String {
        format!("{}/{}", self.base(), self.filename())
    }

    /// full path of the artifact as a PathBuf
    pub fn into_path(&self) -> PathBuf {
        let mut path = PathBuf::new();
        for part in self.package.split('.') {
            path = path.join(part);
        }
        path.join(&self.artifact)
            .join(&self.version)
            .join(self.filename())
    }

    /// Construct a url for the artifact from a given base
    pub fn into_url(
        &self,
        base_url: &str,
    ) -> Result<url::Url, url::ParseError> {
        let url = url::Url::parse(base_url)?;
        url.join(&self.path())
    }

    /// Returns if specifier belongs to a lwjgl library
    pub fn is_lwjgl(&self) -> bool {
        ["org.lwjgl",
            "org.lwjgl.lwjgl",
            "net.java.jinput",
            "net.java.jutils"]
        .contains(&self.package.as_str())
    }

    /// returns if the specifier belongs to a log4j library
    pub fn is_log4j(&self) -> bool {
        self.package.as_str() == "org.apache.logging.log4j"
    }

    /// Returns if the specifier matches the other specifier
    pub fn get_computed_name(&self) -> String {
        format!(
            "{}:{}:{}",
            self.package,
            self.artifact,
            self.identifier.as_deref().unwrap_or("")
        )
    }

    /// Compares two versions
    /// Returns Ordering::Equal if they are equal
    /// Returns Ordering::Greater if self is greater than other
    /// Returns Ordering::Less if self is less than other
    pub fn compare_versions(&self, other: &Self) -> Result<Ordering, Error> {
        let x = lenient_semver::parse(self.version.as_str())
            .map_err(|_| Error::ParseError("Unable to parse version".to_string()))?;
        let y = lenient_semver::parse(other.version.as_str())
            .map_err(|_| Error::ParseError("Unable to parse version".to_string()))?;

        Ok(x.cmp(&y))
    }
}

impl FromStr for GradleSpecifier {
    type Err = Error;

    fn from_str(specifier: &str) -> Result<Self, Self::Err> {
        let mut at_split = specifier.split('@');

        let mut name_items = at_split
            .next()
            .ok_or_else(|| {
                Error::ParseError(format!(
                    "Invalid Gradle Specifier for library {}",
                    &specifier
                ))
            })?
            .split(':');

        let extension = at_split.next().unwrap_or("jar").to_string();
        if extension.is_empty() {
            return Err(Error::ParseError(format!(
                "Empty file extension for library {}",
                &specifier
            )));
        }

        let package = name_items
            .next()
            .ok_or_else(|| {
                Error::ParseError(format!(
                    "Unable to find package for library {}",
                    &specifier
                ))
            })?
            .to_string();
        let artifact = name_items
            .next()
            .ok_or_else(|| {
                Error::ParseError(format!(
                    "Unable to find name for library {}",
                    &specifier
                ))
            })?
            .to_string();
        let version = name_items
            .next()
            .ok_or_else(|| {
                Error::ParseError(format!(
                    "Unable to find version for library {}",
                    &specifier
                ))
            })?
            .to_string();

        let remaining_parts = name_items.collect::<Vec<&str>>();
        let identifier = if remaining_parts.is_empty() {
            None
        } else {
            Some(remaining_parts.join("-"))
        };

        Ok(GradleSpecifier {
            package,
            artifact,
            identifier,
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

        if let Some(classifier) = self.identifier.as_ref() {
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

    Err(Error::MirrorsFailed("No mirrors succeeded!".to_string()))
}

/// Downloads a file with retry and checksum functionality
pub async fn download_file(
    url: &str,
    sha1: Option<&str>,
) -> Result<bytes::Bytes, Error> {
    (|| async {
        let result = HTTP_CLIENT.get(url).send().await;

        match result {
            Ok(x) => {
                let bytes = x.bytes().await;

                match bytes {
                    Ok(bytes) => {
                        if let Some(sha1) = sha1 {
                            if &*get_hash(bytes.clone()).await? != sha1 {
                                return Err(Error::ChecksumFailure {
                                    hash: sha1.to_string(),
                                    url: url.to_string(),
                                });
                            }
                        }

                        Ok(bytes)
                    }
                    Err(err) => Err(Error::FetchError {
                        inner: err,
                        item: url.to_string(),
                    }),
                }
            }
            Err(err) => Err(Error::FetchError {
                inner: err,
                item: url.to_string(),
            }),
        }
    })
    .retry(
        ExponentialBuilder::default()
            .with_max_times(10)
            .with_max_delay(Duration::from_secs(1800)),
    )
    .await
}

/// Computes a checksum of the input bytes
pub async fn get_hash(bytes: bytes::Bytes) -> Result<String, Error> {
    let hash =
        tokio::task::spawn_blocking(|| sha1::Sha1::from(bytes).hexdigest())
            .await?;

    Ok(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_maven_coordinates(maven_coordinates: &str) -> bool {
        let gradle_spec = maven_coordinates.parse::<GradleSpecifier>();
        gradle_spec.is_ok()
    }

    fn parse_maven_coordinates(
        maven_coordinates: &str,
    ) -> Result<GradleSpecifier, Error> {
        maven_coordinates.parse::<GradleSpecifier>()
    }

    #[test]
    fn test_valid_coordinates() {
        assert!(is_maven_coordinates("com.example:example:1.0.0"));
        assert!(is_maven_coordinates("com.example:example:1.0.0:identifier"));
        assert!(is_maven_coordinates("com.example:example:1.0"));
        assert!(is_maven_coordinates(
            "com.example:example:1.0:identifier@zip"
        ));
        assert!(is_maven_coordinates(
            "com.example:example-something:full-text-version"
        ));
        assert!(is_maven_coordinates(
            "com.example:example-something:1.0.final"
        ));
        assert!(is_maven_coordinates(
            "com.example:example-something:1.0.0.Final-beta.1"
        ));
        assert!(is_maven_coordinates(
            "com.example.example:example-example:1.0.0"
        ));
        assert!(is_maven_coordinates(
            "com.example.example:example-example:1.0.0.0"
        ));
        assert!(is_maven_coordinates(
            "com.example.example:example-example:1.0.0.0.0.0.0" // Do we want this?
        ));
        assert!(is_maven_coordinates(
            "com.example.example:example-example:1.0.0-SNAPSHOT"
        ));
        assert!(is_maven_coordinates(
            "com.example.example:example-example:1.0.0-beta.1"
        ));

        assert!(is_maven_coordinates(
            "com.example.example:example-example:1.0.0+beta.1"
        ));
    }

    #[test]
    fn test_invalid_coordinates() {
        assert!(!is_maven_coordinates(""));
        assert!(!is_maven_coordinates("com.example:example"));
        assert!(!is_maven_coordinates("@com.example:example:1.0.0"));
        assert!(!is_maven_coordinates("com.example:example:1.0.0:@"));
        assert!(!is_maven_coordinates("com.example@:example:1.0.0"));
        assert!(!is_maven_coordinates("com.example:example:1.0.0@"));
        assert!(!is_maven_coordinates("justsometext"));
    }

    #[test]
    fn test_parse_coordinates() {
        let coordinates = "com.example:example:1.0.0".to_string();
        let parsed_coordinates = parse_maven_coordinates(&coordinates).unwrap();
        assert_eq!(parsed_coordinates.package, "com.example");
        assert_eq!(parsed_coordinates.artifact, "example");
        assert_eq!(parsed_coordinates.version, "1.0.0");
        assert_eq!(parsed_coordinates.identifier, None);
        assert_eq!(parsed_coordinates.extension, "jar");

        let coordinates =
            "com.example.example:example-example:1.0.0-SNAPSHOT".to_string();
        let parsed_coordinates = parse_maven_coordinates(&coordinates).unwrap();
        assert_eq!(parsed_coordinates.package, "com.example.example");
        assert_eq!(parsed_coordinates.artifact, "example-example");
        assert_eq!(parsed_coordinates.version, "1.0.0-SNAPSHOT");
        assert_eq!(parsed_coordinates.identifier, None);
        assert_eq!(parsed_coordinates.extension, "jar");

        let coordinates =
            "com.example.example:example-example:1.0.0-SNAPSHOT@zip"
                .to_string();
        let parsed_coordinates = parse_maven_coordinates(&coordinates).unwrap();
        assert_eq!(parsed_coordinates.package, "com.example.example");
        assert_eq!(parsed_coordinates.artifact, "example-example");
        assert_eq!(parsed_coordinates.version, "1.0.0-SNAPSHOT");
        assert_eq!(parsed_coordinates.identifier, None);
        assert_eq!(parsed_coordinates.extension, "zip");

        let coordinates =
            "com.example.example:example-example:1.0.0-SNAPSHOT:identifier"
                .to_string();
        let parsed_coordinates = parse_maven_coordinates(&coordinates).unwrap();
        assert_eq!(parsed_coordinates.package, "com.example.example");
        assert_eq!(parsed_coordinates.artifact, "example-example");
        assert_eq!(parsed_coordinates.version, "1.0.0-SNAPSHOT");
        assert_eq!(
            parsed_coordinates.identifier,
            Some("identifier".to_string())
        );
        assert_eq!(parsed_coordinates.extension, "jar");

        let coordinates =
            "com.example.example:example-example:1.0.0-SNAPSHOT:identifier@zip"
                .to_string();
        let parsed_coordinates = parse_maven_coordinates(&coordinates).unwrap();
        assert_eq!(parsed_coordinates.package, "com.example.example");
        assert_eq!(parsed_coordinates.artifact, "example-example");
        assert_eq!(parsed_coordinates.version, "1.0.0-SNAPSHOT");
        assert_eq!(
            parsed_coordinates.identifier,
            Some("identifier".to_string())
        );
        assert_eq!(parsed_coordinates.extension, "zip");
    }

    #[test]
    fn test_try_from() {
        let coordinates = "com.example:example:1.0.0".to_string();
        let parsed_coordinates =
            GradleSpecifier::from_str(&coordinates).unwrap();
        assert_eq!(parsed_coordinates.package, "com.example");
        assert_eq!(parsed_coordinates.artifact, "example");
        assert_eq!(parsed_coordinates.version, "1.0.0");
        assert_eq!(parsed_coordinates.identifier, None);

        let coordinates = "com.example:example:1.0.0".to_string();
        let parsed_coordinates =
            GradleSpecifier::from_str(&coordinates).unwrap();
        assert_eq!(parsed_coordinates.package, "com.example");
        assert_eq!(parsed_coordinates.artifact, "example");
        assert_eq!(parsed_coordinates.version, "1.0.0");
        assert_eq!(parsed_coordinates.identifier, None);

        let coordinates = "com.example:example:1.0.0@zip".to_string();
        let parsed_coordinates =
            GradleSpecifier::from_str(&coordinates).unwrap();
        assert_eq!(parsed_coordinates.package, "com.example");
        assert_eq!(parsed_coordinates.artifact, "example");
        assert_eq!(parsed_coordinates.version, "1.0.0");
        assert_eq!(parsed_coordinates.identifier, None);
        assert_eq!(parsed_coordinates.extension, "zip");

        let coordinates =
            "com.example:example:1.0.0:identifier@zip".to_string();
        let parsed_coordinates =
            GradleSpecifier::from_str(&coordinates).unwrap();
        assert_eq!(parsed_coordinates.package, "com.example");
        assert_eq!(parsed_coordinates.artifact, "example");
        assert_eq!(parsed_coordinates.version, "1.0.0");
        assert_eq!(
            parsed_coordinates.identifier,
            Some("identifier".to_owned())
        );
        assert_eq!(parsed_coordinates.extension, "zip");

        let coordinates =
            "com.example:example:1.0.0:identifier-natives-something@zip"
                .to_string();
        let parsed_coordinates =
            GradleSpecifier::from_str(&coordinates).unwrap();
        assert_eq!(parsed_coordinates.package, "com.example");
        assert_eq!(parsed_coordinates.artifact, "example");
        assert_eq!(parsed_coordinates.version, "1.0.0");
        assert_eq!(
            parsed_coordinates.identifier,
            Some("identifier-natives-something".to_owned())
        );
        assert_eq!(parsed_coordinates.extension, "zip");

        let coordinates = "".to_string();
        assert!(GradleSpecifier::from_str(&coordinates).is_err());

        let coordinates = "justsometext".to_string();
        assert!(GradleSpecifier::from_str(&coordinates).is_err());
    }

    #[test]
    fn test_into_path() {
        let coordinates = "com.example:example:1.0.0".to_string();
        let parsed_coordinates =
            GradleSpecifier::from_str(&coordinates).unwrap();
        let path = parsed_coordinates.into_path();
        assert_eq!(
            path,
            PathBuf::from("com")
                .join("example")
                .join("example")
                .join("1.0.0")
                .join("example-1.0.0.jar")
        );

        let coordinates = "com.example:example:1.0.0+beta1.2".to_string();
        let parsed_coordinates =
            GradleSpecifier::from_str(&coordinates).unwrap();
        let path = parsed_coordinates.into_path();
        assert_eq!(
            path,
            PathBuf::from("com")
                .join("example")
                .join("example")
                .join("1.0.0+beta1.2")
                .join("example-1.0.0+beta1.2.jar")
        );

        let coordinates =
            "com.example:example-mc:1.0.0:natives-example".to_string();
        let parsed_coordinates =
            GradleSpecifier::from_str(&coordinates).unwrap();
        let path = parsed_coordinates.into_path();
        assert_eq!(
            path,
            PathBuf::from("com")
                .join("example")
                .join("example-mc")
                .join("1.0.0")
                .join("example-mc-1.0.0-natives-example.jar")
        );

        let coordinates = "com.example:example:1.0.0@zip".to_string();
        let parsed_coordinates =
            GradleSpecifier::from_str(&coordinates).unwrap();
        let path = parsed_coordinates.into_path();
        assert_eq!(
            path,
            PathBuf::from("com")
                .join("example")
                .join("example")
                .join("1.0.0")
                .join("example-1.0.0.zip")
        );

        let coordinates =
            "com.example:example:1.0.0:identifier@zip".to_string();
        let parsed_coordinates =
            GradleSpecifier::from_str(&coordinates).unwrap();
        let path = parsed_coordinates.into_path();
        assert_eq!(
            path,
            PathBuf::from("com")
                .join("example")
                .join("example")
                .join("1.0.0")
                .join("example-1.0.0-identifier.zip")
        );
    }

    #[test]
    fn test_library_compare() {
        let x = GradleSpecifier {
            package: "org.lwjgl".to_string(),
            artifact: "lwjgl".to_string(),
            identifier: None,
            version: "2.9.4-nightly-20150209".to_string(),
            extension: "jar".to_string(),
        };
        let y = GradleSpecifier {
            package: "org.lwjgl".to_string(),
            artifact: "lwjgl".to_string(),
            identifier: None,
            version: "2.9.4-nightly-20150209".to_string(),
            extension: "jar".to_string(),
        };

        assert_eq!(x.compare_versions(&y).unwrap(), Ordering::Equal);

        let x = GradleSpecifier {
            package: "org.lwjgl".to_string(),
            artifact: "lwjgl".to_string(),
            identifier: None,
            version: "2.9.4-nightly-20150209".to_string(),
            extension: "jar".to_string(),
        };
        let y = GradleSpecifier {
            package: "org.lwjgl".to_string(),
            artifact: "lwjgl".to_string(),
            identifier: None,
            version: "2.9.3".to_string(),
            extension: "jar".to_string(),
        };

        assert_eq!(x.compare_versions(&y).unwrap(), Ordering::Greater);

        let x = GradleSpecifier {
            package: "org.lwjgl".to_string(),
            artifact: "lwjgl".to_string(),
            identifier: None,
            version: "2.9.3".to_string(),
            extension: "jar".to_string(),
        };
        let y = GradleSpecifier {
            package: "org.lwjgl".to_string(),
            artifact: "lwjgl".to_string(),
            identifier: None,
            version: "2.9.4-nightly-20150209".to_string(),
            extension: "jar".to_string(),
        };

        assert_eq!(x.compare_versions(&y).unwrap(), Ordering::Less);

        let x = GradleSpecifier {
            package: "org.lwjgl".to_string(),
            artifact: "lwjgl".to_string(),
            identifier: None,
            version: "2.9.4-nightly-20150209".to_string(),
            extension: "jar".to_string(),
        };
        let y = GradleSpecifier {
            package: "org.lwjgl".to_string(),
            artifact: "lwjgl".to_string(),
            identifier: None,
            version: "2.9.4".to_string(),
            extension: "jar".to_string(),
        };

        assert_eq!(x.compare_versions(&y).unwrap(), Ordering::Less);

        let x = GradleSpecifier {
            package: "org.lwjgl".to_string(),
            artifact: "lwjgl".to_string(),
            identifier: None,
            version: "2.9.4-SNAPSHOT".to_string(),
            extension: "jar".to_string(),
        };
        let y = GradleSpecifier {
            package: "org.lwjgl".to_string(),
            artifact: "lwjgl".to_string(),
            identifier: None,
            version: "2.9.4".to_string(),
            extension: "jar".to_string(),
        };

        assert_eq!(x.compare_versions(&y).unwrap(), Ordering::Less);
    }
}
