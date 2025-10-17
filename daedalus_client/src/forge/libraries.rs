//! Library processing functions for Forge

use daedalus::minecraft::Library;

/// Check if a library should be loaded from the installer archive
/// rather than downloaded from a remote repository
pub fn is_local_lib(lib: &Library) -> bool {
    lib.downloads
        .as_ref()
        .and_then(|x| {
            x.artifact.as_ref().and_then(|x| {
                x.url
                    .as_ref()
                    .map(|lib| lib.is_empty())
            })
        })
        .unwrap_or(false)
        || lib.url.is_some()
}
