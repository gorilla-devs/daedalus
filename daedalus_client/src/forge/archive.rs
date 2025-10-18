//! Functions for reading data from Forge installer archives

use super::types::{ForgeInstallerProfileV1, ForgeInstallerProfileV2};
use daedalus::modded::PartialVersionInfo;
use std::io::Read;

/// Read and parse install_profile.json from a V1 Forge installer archive
pub async fn read_install_profile_v1(
    mut archive: zip::ZipArchive<std::io::Cursor<bytes::Bytes>>,
) -> Result<ForgeInstallerProfileV1, crate::infrastructure::error::Error> {
    tokio::task::spawn_blocking(move || {
        let mut install_profile = archive.by_name("install_profile.json")?;

        let mut contents = String::new();
        install_profile.read_to_string(&mut contents)?;

        Ok::<ForgeInstallerProfileV1, crate::infrastructure::error::Error>(
            serde_json::from_str::<ForgeInstallerProfileV1>(&contents)?,
        )
    })
    .await?
}

/// Read and parse install_profile.json from a V2+ Forge installer archive
pub async fn read_install_profile_v2(
    mut archive: zip::ZipArchive<std::io::Cursor<bytes::Bytes>>,
) -> Result<ForgeInstallerProfileV2, crate::infrastructure::error::Error> {
    tokio::task::spawn_blocking(move || {
        let mut install_profile = archive.by_name("install_profile.json")?;

        let mut contents = String::new();
        install_profile.read_to_string(&mut contents)?;

        Ok::<ForgeInstallerProfileV2, crate::infrastructure::error::Error>(
            serde_json::from_str::<ForgeInstallerProfileV2>(&contents)?,
        )
    })
    .await?
}

/// Read and parse version.json from a V2+ Forge installer archive
pub async fn read_version_json(
    mut archive: zip::ZipArchive<std::io::Cursor<bytes::Bytes>>,
) -> Result<PartialVersionInfo, crate::infrastructure::error::Error> {
    tokio::task::spawn_blocking(move || {
        let mut install_profile = archive.by_name("version.json")?;

        let mut contents = String::new();
        install_profile.read_to_string(&mut contents)?;

        Ok::<PartialVersionInfo, crate::infrastructure::error::Error>(
            serde_json::from_str::<PartialVersionInfo>(&contents)?,
        )
    })
    .await?
}

/// Read the Forge universal JAR from the installer archive (V1 format)
pub async fn read_forge_universal(
    mut archive: zip::ZipArchive<std::io::Cursor<bytes::Bytes>>,
    file_path: String,
) -> Result<bytes::Bytes, crate::infrastructure::error::Error> {
    tokio::task::spawn_blocking(move || {
        let mut forge_universal_file = archive.by_name(&file_path)?;
        let mut forge_universal = Vec::new();
        forge_universal_file.read_to_end(&mut forge_universal)?;

        Ok::<bytes::Bytes, crate::infrastructure::error::Error>(bytes::Bytes::from(
            forge_universal,
        ))
    })
    .await?
}

/// Read a library from the maven/ directory in the installer archive
pub async fn read_library_from_archive(
    mut archive: zip::ZipArchive<std::io::Cursor<bytes::Bytes>>,
    lib_name: daedalus::GradleSpecifier,
) -> Result<Option<bytes::Bytes>, crate::infrastructure::error::Error> {
    tokio::task::spawn_blocking(move || {
        let entry_name = format!("maven/{}", lib_name.path());
        let lib_file = archive.by_name(&entry_name).map_err(|err| {
            crate::infrastructure::error::invalid_input(format!(
                "Failed to find entry {} in installer jar: {}",
                entry_name, err
            ))
        });

        // Thank you forge for always making it hard to parse your data
        // 1.20.4+ has a local lib that doesn't exist in the installer jar
        // Not sure what it does, but it doesn't seem to be needed
        if lib_file.is_err() && &*lib_name.artifact == "forge" {
            return Ok::<_, crate::infrastructure::error::Error>(None);
        }

        let mut lib_file = lib_file?;

        let mut lib_bytes = Vec::new();
        lib_file.read_to_end(&mut lib_bytes)?;

        let result = Some(bytes::Bytes::from(lib_bytes));

        Ok::<_, crate::infrastructure::error::Error>(result)
    })
    .await?
}

/// Read a data file from the installer archive (for V2+ installer data entries)
pub async fn read_data_file(
    mut archive: zip::ZipArchive<std::io::Cursor<bytes::Bytes>>,
    path: String,
) -> Result<bytes::Bytes, crate::infrastructure::error::Error> {
    tokio::task::spawn_blocking(move || {
        let mut lib_file = archive.by_name(&path[1..path.len()])?;
        let mut lib_bytes = Vec::new();
        lib_file.read_to_end(&mut lib_bytes)?;

        Ok::<bytes::Bytes, crate::infrastructure::error::Error>(bytes::Bytes::from(lib_bytes))
    })
    .await?
}
