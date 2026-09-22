// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Private file write performed by the workload identity.
//!
//! The boundary process must already be that uid. A root boundary is refused
//! rather than writing a credential as root.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use nix::unistd::Uid;

pub const PRIVATE_FILE_MODE: u32 = 0o600;
pub const MAX_PRIVATE_FILE_BYTES: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrivateFileReport {
    pub written: bool,
    pub length: u64,
    pub mode: u32,
}

pub fn provision_private_file(
    path: &str,
    contents: &[u8],
    overwrite: bool,
    expected_uid: u32,
) -> Result<PrivateFileReport, String> {
    if expected_uid == 0 {
        return Err("workload identity must not be root".into());
    }
    let actual = Uid::effective().as_raw();
    if actual != expected_uid {
        return Err("boundary is not the workload identity".into());
    }
    if contents.is_empty() || contents.len() > MAX_PRIVATE_FILE_BYTES {
        return Err(format!(
            "private file must contain 1..={MAX_PRIVATE_FILE_BYTES} bytes"
        ));
    }
    let destination = normalize_private_path(path)?;
    let parent = destination
        .parent()
        .ok_or_else(|| "private file path has no parent".to_string())?;
    let leaf = destination
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "private file name is not portable".to_string())?;
    create_private_parents(parent)?;
    if let Some(existing) = existing_private_file(&destination, expected_uid)? {
        if !overwrite {
            return Ok(PrivateFileReport {
                written: false,
                length: existing,
                mode: PRIVATE_FILE_MODE,
            });
        }
    }
    let temporary = parent.join(format!(
        ".{leaf}.mitosu-provision-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0)
    ));
    let write_result = write_exclusive(&temporary, contents);
    if let Err(error) = write_result {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    if let Err(error) = fs::rename(&temporary, &destination) {
        let _ = fs::remove_file(&temporary);
        return Err(format!("publishing private file failed: {error}"));
    }
    sync_directory(parent)?;
    Ok(PrivateFileReport {
        written: true,
        length: contents.len() as u64,
        mode: PRIVATE_FILE_MODE,
    })
}

fn normalize_private_path(path: &str) -> Result<PathBuf, String> {
    if !path.starts_with('/') || path.contains('\0') {
        return Err("private file path must be absolute".into());
    }
    let mut out = PathBuf::new();
    for component in Path::new(path).components() {
        match component {
            Component::RootDir => out.push("/"),
            Component::Normal(part) => {
                let part = part.to_str().ok_or("private file path is not UTF-8")?;
                if part.contains(['\\', '\n']) {
                    return Err("private file path is not portable".into());
                }
                out.push(part);
            }
            _ => return Err("private file path must not contain '.' or '..'".into()),
        }
    }
    let text = out.to_string_lossy();
    if text == "/.openshell" || text.starts_with("/.openshell/") {
        return Err("private file path overlaps /.openshell".into());
    }
    if out.parent().is_none() || out.file_name().is_none() {
        return Err("private file path cannot replace a filesystem root".into());
    }
    Ok(out)
}

fn create_private_parents(parent: &Path) -> Result<(), String> {
    let mut prefix = PathBuf::from("/");
    for component in parent.components().skip(1) {
        let Component::Normal(part) = component else {
            return Err("private file parent is not a normalized directory".into());
        };
        prefix.push(part);
        match fs::symlink_metadata(&prefix) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(format!(
                    "private file parent contains a symbolic link: {}",
                    prefix.display()
                ));
            }
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => {
                return Err(format!(
                    "private file parent is not a directory: {}",
                    prefix.display()
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&prefix)
                    .map_err(|error| format!("creating {}: {error}", prefix.display()))?;
                fs::set_permissions(&prefix, fs::Permissions::from_mode(0o700))
                    .map_err(|error| format!("setting permissions on {}: {error}", prefix.display()))?;
            }
            Err(error) => return Err(format!("reading {}: {error}", prefix.display())),
        }
    }
    Ok(())
}

fn existing_private_file(path: &Path, expected_uid: u32) -> Result<Option<u64>, String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("reading {}: {error}", path.display())),
    };
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "private file path is a symbolic link: {}",
            path.display()
        ));
    }
    if !metadata.is_file() {
        return Err(format!(
            "private file path is not a regular file: {}",
            path.display()
        ));
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode != PRIVATE_FILE_MODE {
        return Err("existing private file is not mode 0600".into());
    }
    let owner = std::os::unix::fs::MetadataExt::uid(&metadata);
    if owner != expected_uid {
        return Err("existing private file is not owned by the workload identity".into());
    }
    Ok(Some(metadata.len()))
}

fn write_exclusive(path: &Path, contents: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(PRIVATE_FILE_MODE)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("creating private file: {error}"))?;
    file.write_all(contents)
        .map_err(|error| format!("writing private file: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("syncing private file: {error}"))?;
    fs::set_permissions(path, fs::Permissions::from_mode(PRIVATE_FILE_MODE))
        .map_err(|error| format!("setting private file mode: {error}"))?;
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), String> {
    let directory = fs::File::open(path)
        .map_err(|error| format!("opening {}: {error}", path.display()))?;
    directory
        .sync_all()
        .map_err(|error| format!("syncing {}: {error}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uid() -> u32 {
        Uid::effective().as_raw()
    }

    #[test]
    fn rejects_root_identity_parent_escape_and_openshell() {
        let error = provision_private_file("/tmp/secret", b"x", false, 0).unwrap_err();
        assert!(error.contains("must not be root"));
        assert!(normalize_private_path("/tmp/../etc/passwd").is_err());
        assert!(normalize_private_path("/.openshell/secret").is_err());
        assert!(normalize_private_path("relative").is_err());
    }

    #[test]
    fn writes_mode_0600_and_retains_without_overwrite() {
        if uid() == 0 {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let destination = root.path().join("nested/token");
        let path = destination.to_str().unwrap();
        let first = provision_private_file(path, b"secret-token-v1", false, uid()).unwrap();
        assert!(first.written);
        assert_eq!(first.length, 15);
        assert_eq!(first.mode, 0o600);
        let mode = fs::metadata(&destination).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let retained = provision_private_file(path, b"should-not-replace", false, uid()).unwrap();
        assert!(!retained.written);
        assert_eq!(retained.length, 15);
        assert_eq!(fs::read(&destination).unwrap(), b"secret-token-v1");
        let replaced = provision_private_file(path, b"secret-token-v2", true, uid()).unwrap();
        assert!(replaced.written);
        assert_eq!(fs::read(&destination).unwrap(), b"secret-token-v2");
        for entry in fs::read_dir(destination.parent().unwrap()).unwrap() {
            let name = entry.unwrap().file_name();
            assert!(!name.to_string_lossy().contains(".mitosu-provision-"));
        }
    }

    #[test]
    fn rejects_a_symlink_at_the_destination() {
        if uid() == 0 {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("real");
        fs::write(&target, b"x").unwrap();
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let error = provision_private_file(link.to_str().unwrap(), b"secret", true, uid()).unwrap_err();
        assert!(error.contains("symbolic link"), "{error}");
        assert_eq!(fs::read(&target).unwrap(), b"x");
    }
}
