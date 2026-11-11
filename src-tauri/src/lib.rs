use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use argon2::{Algorithm, Argon2, Params, Version, password_hash::SaltString};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sysinfo::Disks;
use tauri::Emitter;
use walkdir::WalkDir;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LockFolderRequest {
    pub source_path: String,
    pub password: String,
    pub confirm_remove_original: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LockFolderResponse {
    pub vault_path: String,
    pub file_count: usize,
    pub locked_folder_path: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RestoreVaultRequest {
    pub vault_path: String,
    pub destination_path: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RestoreVaultResponse {
    pub restore_path: String,
    pub file_count: usize,
    pub locked_folder: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DriveAudit {
    pub name: String,
    #[serde(rename = "type")]
    pub type_name: String,
    pub capacity: String,
    pub available: String,
    pub filesystem: String,
    pub removable: bool,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct EncryptionProgress {
    current: usize,
    total: usize,
    file_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct EncryptedFileEntry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    relative_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    path_nonce: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    encrypted_path: Option<String>,
    nonce: String,
    ciphertext: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct VaultMetadata {
    version: u32,
    created_at: u64,
    salt: String,
    #[serde(default)]
    directories: Vec<EncryptedPath>,
    files: Vec<EncryptedFileEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct EncryptedPath {
    nonce: String,
    ciphertext: String,
}

struct FolderContents {
    files: Vec<PathBuf>,
    directories: Vec<PathBuf>,
}

fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    let params = Params::new(65536, 4, 1, Some(32))
        .map_err(|error| format!("Invalid Argon2 parameters: {error}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut raw_key = [0u8; 32];

    argon2
        .hash_password_into(password.as_bytes(), salt, &mut raw_key)
        .map_err(|error| format!("Failed to derive encrypted key: {error}"))?;

    Ok(raw_key)
}

fn walk_source_tree(source_path: &Path) -> Result<FolderContents, String> {
    let mut files = Vec::new();
    let mut directories = Vec::new();

    for entry in WalkDir::new(source_path) {
        let entry = entry.map_err(|error| format!("Could not inspect selected folder: {error}"))?;
        if entry.depth() == 0 {
            continue;
        }
        if entry.file_type().is_symlink() {
            return Err(format!(
                "Locking folders that contain symbolic links is not supported: {}",
                entry.path().display()
            ));
        }
        if entry.file_type().is_file() {
            files.push(entry.into_path());
        } else if entry.file_type().is_dir() {
            directories.push(entry.into_path());
        }
    }

    files.sort();
    directories.sort();
    Ok(FolderContents { files, directories })
}

fn encrypt_relative_path(
    cipher: &Aes256Gcm,
    rng: &mut impl Rng,
    relative: &Path,
) -> Result<EncryptedPath, String> {
    let nonce_bytes: [u8; 12] = rng.r#gen();
    let path = relative
        .components()
        .map(|component| {
            let std::path::Component::Normal(part) = component else {
                return Err("Folder contains a path that cannot be represented safely.".to_string());
            };
            let part = part.to_str().ok_or_else(|| {
                "Folder contains a path that cannot be represented safely.".to_string()
            })?;
            if part.contains('\\') {
                return Err("Folder contains a path that cannot be represented safely.".to_string());
            }
            Ok(part)
        })
        .collect::<Result<Vec<_>, _>>()?
        .join("/");
    let encrypted_path = cipher
        .encrypt(&Nonce::from(nonce_bytes), path.as_bytes())
        .map_err(|error| format!("Could not encrypt a folder path: {error}"))?;
    Ok(EncryptedPath {
        nonce: BASE64.encode(nonce_bytes),
        ciphertext: BASE64.encode(encrypted_path),
    })
}

fn decrypt_relative_path(cipher: &Aes256Gcm, encrypted: &EncryptedPath) -> Result<String, String> {
    let nonce_bytes = BASE64
        .decode(&encrypted.nonce)
        .map_err(|error| format!("Vault contains an invalid path nonce: {error}"))?;
    let nonce: [u8; 12] = nonce_bytes
        .try_into()
        .map_err(|_| "Vault contains a path nonce with an invalid length.".to_string())?;
    let ciphertext = BASE64
        .decode(&encrypted.ciphertext)
        .map_err(|error| format!("Vault contains invalid encrypted path data: {error}"))?;
    let plaintext = cipher
        .decrypt(&Nonce::from(nonce), ciphertext.as_ref())
        .map_err(|_| "Password is incorrect or vault integrity verification failed.".to_string())?;
    String::from_utf8(plaintext)
        .map_err(|_| "Vault contains an invalid encrypted path.".to_string())
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

#[tauri::command]
fn get_drive_analysis() -> Vec<DriveAudit> {
    let disks = Disks::new_with_refreshed_list();
    disks
        .list()
        .iter()
        .map(|disk| {
            let mount_name = disk.mount_point().display().to_string();
            let name = disk.name().to_string_lossy().trim().to_string();
            DriveAudit {
                name: if name.is_empty() {
                    mount_name.clone()
                } else {
                    name
                },
                type_name: if disk.is_removable() {
                    "Removable mounted volume".to_string()
                } else {
                    "Mounted volume".to_string()
                },
                capacity: format_bytes(disk.total_space()),
                available: format_bytes(disk.available_space()),
                filesystem: disk.file_system().to_string_lossy().to_string(),
                removable: disk.is_removable(),
            }
        })
        .collect()
}

fn encrypt_folder_to_vault(
    app: &tauri::AppHandle,
    source_path: &Path,
    password: &str,
) -> Result<(PathBuf, usize), String> {
    if !source_path.exists() || !source_path.is_dir() {
        return Err("Selected path must be an existing folder.".to_string());
    }
    if password.is_empty() {
        return Err("A non-empty vault password is required.".to_string());
    }

    let source_path = source_path
        .canonicalize()
        .map_err(|error| format!("Could not resolve selected folder: {error}"))?;
    let parent_dir = source_path
        .parent()
        .ok_or_else(|| "The filesystem root cannot be locked.".to_string())?;
    let folder_name = source_path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty() && *name != "." && *name != "..")
        .ok_or_else(|| "Could not determine the selected folder name.".to_string())?;
    let vault_dir = parent_dir.join(format!("{folder_name}.securevault"));

    if vault_dir.exists() {
        return Err(format!(
            "A vault already exists at {}.",
            vault_dir.display()
        ));
    }

    let mut rng = rand::thread_rng();
    let salt = SaltString::generate(&mut rng);
    let salt_bytes = salt.as_salt().as_str().as_bytes();
    let key_bytes = derive_key(password, salt_bytes)?;
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|error| format!("Invalid AES key: {error}"))?;

    let contents = walk_source_tree(&source_path)?;
    let total_entries = contents.files.len() + contents.directories.len();
    let mut encrypted_directories = Vec::with_capacity(contents.directories.len());
    let mut manifest = Vec::with_capacity(contents.files.len());
    let mut progress = 0;
    for directory_path in &contents.directories {
        let relative = directory_path
            .strip_prefix(&source_path)
            .map_err(|error| format!("Could not determine relative directory path: {error}"))?;
        encrypted_directories.push(encrypt_relative_path(&cipher, &mut rng, relative)?);
        progress += 1;
        app.emit(
            "vault-encryption-progress",
            EncryptionProgress {
                current: progress,
                total: total_entries,
                file_name: directory_path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string(),
            },
        )
        .map_err(|error| format!("Could not report encryption progress: {error}"))?;
    }

    for file_path in &contents.files {
        let relative = file_path
            .strip_prefix(&source_path)
            .map_err(|error| format!("Could not determine relative file path: {error}"))?;

        let file_bytes = fs::read(&file_path)
            .map_err(|error| format!("Could not read {:?}: {error}", file_path))?;
        let nonce_bytes: [u8; 12] = rng.r#gen();
        let nonce = Nonce::from(nonce_bytes);
        let ciphertext = cipher
            .encrypt(&nonce, file_bytes.as_ref())
            .map_err(|error| format!("Encryption failed for {:?}: {error}", file_path))?;
        let encrypted_path = encrypt_relative_path(&cipher, &mut rng, relative)?;

        manifest.push(EncryptedFileEntry {
            relative_path: None,
            path_nonce: Some(encrypted_path.nonce),
            encrypted_path: Some(encrypted_path.ciphertext),
            nonce: BASE64.encode(nonce_bytes),
            ciphertext: BASE64.encode(ciphertext),
        });

        progress += 1;
        app.emit(
            "vault-encryption-progress",
            EncryptionProgress {
                current: progress,
                total: total_entries,
                file_name: file_path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string(),
            },
        )
        .map_err(|error| format!("Could not report encryption progress: {error}"))?;
    }

    let staging_dir = parent_dir.join(format!(".securevault-staging-{}", rng.r#gen::<u64>()));
    fs::create_dir(&staging_dir)
        .map_err(|error| format!("Could not create temporary vault folder: {error}"))?;

    let write_result = (|| {
        let metadata = VaultMetadata {
            version: 3,
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|error| format!("Could not read current time: {error}"))?
                .as_secs(),
            salt: salt.to_string(),
            directories: encrypted_directories,
            files: manifest,
        };

        let metadata_path = staging_dir.join("vault.meta.json");
        fs::write(
            &metadata_path,
            serde_json::to_string_pretty(&metadata)
                .map_err(|error| format!("Could not serialize metadata: {error}"))?,
        )
        .map_err(|error| format!("Could not write metadata file: {error}"))?;

        fs::rename(&staging_dir, &vault_dir)
            .map_err(|error| format!("Could not finalize vault folder: {error}"))?;

        Ok::<(), String>(())
    })();

    if let Err(error) = write_result {
        return match fs::remove_dir_all(&staging_dir) {
            Ok(()) => Err(error),
            Err(cleanup_error) => Err(format!(
                "{error}; encrypted staging data could not be removed at {}: {cleanup_error}",
                staging_dir.display()
            )),
        };
    }

    Ok((vault_dir, contents.files.len()))
}

fn verify_vault_matches_source(
    vault_path: &Path,
    source_path: &Path,
    password: &str,
) -> Result<(), String> {
    let metadata_bytes = fs::read(vault_path.join("vault.meta.json"))
        .map_err(|error| format!("Could not read staged vault for verification: {error}"))?;
    let metadata: VaultMetadata = serde_json::from_slice(&metadata_bytes)
        .map_err(|error| format!("Could not verify staged vault metadata: {error}"))?;
    if metadata.version != 3 {
        return Err("Vault verification failed: unsupported lock format.".to_string());
    }

    let key = derive_key(password, metadata.salt.as_bytes())?;
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|error| format!("Invalid AES key: {error}"))?;
    let contents = walk_source_tree(source_path)?;
    if metadata.files.len() != contents.files.len()
        || metadata.directories.len() != contents.directories.len()
    {
        return Err(
            "Vault verification failed: folder contents changed during encryption.".to_string(),
        );
    }

    let expected_directories: std::collections::HashSet<String> = contents
        .directories
        .iter()
        .map(|path| {
            path.strip_prefix(source_path)
                .map(|relative| relative.to_string_lossy().replace('\\', "/"))
                .map_err(|error| format!("Could not determine relative directory path: {error}"))
        })
        .collect::<Result<_, _>>()?;
    let mut actual_directories =
        std::collections::HashSet::with_capacity(metadata.directories.len());
    for directory in &metadata.directories {
        let path = decrypt_relative_path(&cipher, directory)?;
        let safe_path = safe_restore_path(source_path, &path)?;
        if !safe_path.is_dir() || !actual_directories.insert(path) {
            return Err(
                "Vault verification failed: a folder path is missing or duplicated.".to_string(),
            );
        }
    }
    if actual_directories != expected_directories {
        return Err(
            "Vault verification failed: folder structure changed during encryption.".to_string(),
        );
    }

    let expected_files: std::collections::HashSet<String> = contents
        .files
        .iter()
        .map(|path| {
            path.strip_prefix(source_path)
                .map(|relative| relative.to_string_lossy().replace('\\', "/"))
                .map_err(|error| format!("Could not determine relative file path: {error}"))
        })
        .collect::<Result<_, _>>()?;
    let mut actual_files = std::collections::HashSet::with_capacity(metadata.files.len());
    for entry in &metadata.files {
        let relative_path = if metadata.version == 1 {
            entry
                .relative_path
                .clone()
                .ok_or_else(|| "Legacy vault is missing a file path.".to_string())?
        } else {
            let encrypted = EncryptedPath {
                nonce: entry.path_nonce.clone().ok_or_else(|| {
                    "Vault verification failed: encrypted path nonce is missing.".to_string()
                })?,
                ciphertext: entry.encrypted_path.clone().ok_or_else(|| {
                    "Vault verification failed: encrypted path is missing.".to_string()
                })?,
            };
            decrypt_relative_path(&cipher, &encrypted)?
        };
        let file_path = safe_restore_path(source_path, &relative_path)?;
        if !file_path.is_file() || !actual_files.insert(relative_path) {
            return Err(
                "Vault verification failed: a file path is missing or duplicated.".to_string(),
            );
        }
        let file_nonce: [u8; 12] = BASE64
            .decode(&entry.nonce)
            .map_err(|error| format!("Vault verification failed: {error}"))?
            .try_into()
            .map_err(|_| "Vault verification failed: invalid file nonce.".to_string())?;
        let ciphertext = BASE64
            .decode(&entry.ciphertext)
            .map_err(|error| format!("Vault verification failed: {error}"))?;
        let encrypted_bytes = cipher
            .decrypt(&Nonce::from(file_nonce), ciphertext.as_ref())
            .map_err(|_| {
                "Vault verification failed: encrypted file authentication failed.".to_string()
            })?;
        let source_bytes = fs::read(&file_path).map_err(|error| {
            format!("Vault verification could not read {:?}: {error}", file_path)
        })?;
        if source_bytes != encrypted_bytes {
            return Err(
                "Vault verification failed: a source file changed during encryption.".to_string(),
            );
        }
    }
    if actual_files != expected_files {
        return Err(
            "Vault verification failed: file contents changed during encryption.".to_string(),
        );
    }
    Ok(())
}

#[tauri::command]
fn lock_folder(
    app: tauri::AppHandle,
    request: LockFolderRequest,
) -> Result<LockFolderResponse, String> {
    if !request.confirm_remove_original {
        return Err(
            "Confirm that the original plaintext folder should be removed after verification."
                .to_string(),
        );
    }

    let selected_path = PathBuf::from(&request.source_path);
    let selected_metadata = fs::symlink_metadata(&selected_path)
        .map_err(|error| format!("Could not inspect selected folder: {error}"))?;
    if selected_metadata.file_type().is_symlink() {
        return Err("Select the actual folder, not a symbolic link to a folder.".to_string());
    }
    let source_path = selected_path
        .canonicalize()
        .map_err(|error| format!("Could not resolve selected folder: {error}"))?;
    let (vault_path, file_count) = encrypt_folder_to_vault(&app, &source_path, &request.password)?;

    let parent = source_path
        .parent()
        .ok_or_else(|| "The filesystem root cannot be locked.".to_string())?;
    let mut rng = rand::thread_rng();
    let quarantine_path = parent.join(format!(".securevault-locking-{}", rng.r#gen::<u64>()));
    fs::rename(&source_path, &quarantine_path).map_err(|error| {
        format!(
            "The encrypted vault is safe at {} but the source folder could not be staged for locking: {error}. The plaintext folder remains at {}.",
            vault_path.display(),
            source_path.display()
        )
    })?;

    if let Err(verification_error) =
        verify_vault_matches_source(&vault_path, &quarantine_path, &request.password)
    {
        let restore_error = fs::rename(&quarantine_path, &source_path).err();
        let cleanup_error = fs::remove_dir_all(&vault_path).err();
        let mut message = format!("Folder lock verification failed: {verification_error}");
        if let Some(error) = restore_error {
            message.push_str(&format!(
                " The original folder could not be restored to {}; plaintext remains at {}: {error}.",
                source_path.display(),
                quarantine_path.display()
            ));
        }
        if let Some(error) = cleanup_error {
            message.push_str(&format!(
                " The unverified vault could not be removed at {}: {error}.",
                vault_path.display()
            ));
        }
        return Err(message);
    }

    if let Err(error) = fs::remove_dir_all(&quarantine_path) {
        let restore_error = fs::rename(&quarantine_path, &source_path).err();
        let mut message = format!(
            "The encrypted vault is verified at {} but plaintext cleanup failed: {error}.",
            vault_path.display()
        );
        if let Some(restore_error) = restore_error {
            message.push_str(&format!(
                " The remaining plaintext could not be restored to {}; inspect {}: {restore_error}.",
                source_path.display(),
                quarantine_path.display()
            ));
        } else {
            message.push_str(&format!(
                " The plaintext folder remains at {}.",
                source_path.display()
            ));
        }
        return Err(message);
    }

    Ok(LockFolderResponse {
        vault_path: vault_path.to_string_lossy().to_string(),
        locked_folder_path: source_path.to_string_lossy().to_string(),
        file_count,
    })
}

fn safe_restore_path(root: &Path, relative_path: &str) -> Result<PathBuf, String> {
    let relative = Path::new(relative_path);
    if relative.as_os_str().is_empty()
        || relative_path.contains('\\')
        || relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err("Vault contains an unsafe file path; restore was stopped.".to_string());
    }
    Ok(root.join(relative))
}

#[tauri::command]
fn restore_encrypted_vault(
    app: tauri::AppHandle,
    request: RestoreVaultRequest,
) -> Result<RestoreVaultResponse, String> {
    if request.password.is_empty() {
        return Err("The vault password is required.".to_string());
    }
    let vault_path = PathBuf::from(&request.vault_path);
    if !vault_path.is_dir() {
        return Err("Select an existing .securevault folder.".to_string());
    }
    let destination = if request.destination_path.trim().is_empty() {
        vault_path
            .parent()
            .ok_or_else(|| "Could not determine the vault's parent folder.".to_string())?
            .to_path_buf()
    } else {
        PathBuf::from(&request.destination_path)
    };
    if !destination.is_dir() {
        return Err("Select an existing destination folder.".to_string());
    }

    let metadata_path = vault_path.join("vault.meta.json");
    let metadata_bytes = fs::read(&metadata_path)
        .map_err(|error| format!("Could not read vault metadata: {error}"))?;
    let metadata: VaultMetadata = serde_json::from_slice(&metadata_bytes)
        .map_err(|error| format!("Vault metadata is invalid: {error}"))?;
    if !matches!(metadata.version, 1 | 2 | 3) {
        return Err(format!(
            "Unsupported vault format version: {}",
            metadata.version
        ));
    }
    if metadata.version < 3 && metadata.files.is_empty() {
        return Err("Vault contains no files.".to_string());
    }

    let key_bytes = derive_key(&request.password, metadata.salt.as_bytes())?;
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|error| format!("Invalid AES key: {error}"))?;
    let vault_name = vault_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("RestoredVault")
        .strip_suffix(".securevault")
        .unwrap_or("RestoredVault");
    let restored_path = destination.join(vault_name);
    if restored_path.exists() {
        return Err(format!(
            "Restore destination already exists: {}",
            restored_path.display()
        ));
    }

    let staging_path = destination.join(format!(
        ".securevault-restore-{}",
        rand::thread_rng().r#gen::<u64>()
    ));
    fs::create_dir(&staging_path)
        .map_err(|error| format!("Could not create temporary restore folder: {error}"))?;
    let total_files = metadata.files.len();
    let total_entries = total_files + metadata.directories.len();
    let mut seen_paths = std::collections::HashSet::with_capacity(total_entries);

    let restore_result = (|| {
        let mut progress = 0;
        for directory in &metadata.directories {
            let relative_path = decrypt_relative_path(&cipher, directory)?;
            if !seen_paths.insert(relative_path.clone()) {
                return Err("Vault contains duplicate paths; restore was stopped.".to_string());
            }
            let output_path = safe_restore_path(&staging_path, &relative_path)?;
            fs::create_dir_all(&output_path)
                .map_err(|error| format!("Could not create restored folder: {error}"))?;
            progress += 1;
            app.emit(
                "vault-restore-progress",
                EncryptionProgress {
                    current: progress,
                    total: total_entries,
                    file_name: output_path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string(),
                },
            )
            .map_err(|error| format!("Could not report restore progress: {error}"))?;
        }

        for (index, entry) in metadata.files.iter().enumerate() {
            let relative_path = if metadata.version == 1 {
                entry
                    .relative_path
                    .clone()
                    .ok_or_else(|| "Legacy vault is missing a file path.".to_string())?
            } else {
                let encrypted_path = EncryptedPath {
                    nonce: entry
                        .path_nonce
                        .clone()
                        .ok_or_else(|| "Vault is missing an encrypted path nonce.".to_string())?,
                    ciphertext: entry
                        .encrypted_path
                        .clone()
                        .ok_or_else(|| "Vault is missing encrypted path data.".to_string())?,
                };
                decrypt_relative_path(&cipher, &encrypted_path)?
            };
            if !seen_paths.insert(relative_path.clone()) {
                return Err("Vault contains duplicate file paths; restore was stopped.".to_string());
            }

            let nonce_bytes = BASE64
                .decode(&entry.nonce)
                .map_err(|error| format!("Vault contains an invalid nonce: {error}"))?;
            let nonce_array: [u8; 12] = nonce_bytes
                .try_into()
                .map_err(|_| "Vault contains a nonce with an invalid length.".to_string())?;
            let ciphertext = BASE64
                .decode(&entry.ciphertext)
                .map_err(|error| format!("Vault contains invalid encrypted data: {error}"))?;
            let plaintext = cipher
                .decrypt(&Nonce::from(nonce_array), ciphertext.as_ref())
                .map_err(|_| {
                    "Password is incorrect or vault integrity verification failed.".to_string()
                })?;

            let output_path = safe_restore_path(&staging_path, &relative_path)?;
            let parent = output_path
                .parent()
                .ok_or_else(|| "Vault contains an invalid output path.".to_string())?;
            fs::create_dir_all(parent)
                .map_err(|error| format!("Could not create restored folder: {error}"))?;
            fs::write(&output_path, plaintext)
                .map_err(|error| format!("Could not write restored file: {error}"))?;

            progress += 1;
            app.emit(
                "vault-restore-progress",
                EncryptionProgress {
                    current: progress.max(index + 1),
                    total: total_entries,
                    file_name: output_path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string(),
                },
            )
            .map_err(|error| format!("Could not report restore progress: {error}"))?;
        }

        fs::rename(&staging_path, &restored_path)
            .map_err(|error| format!("Could not finalize restored folder: {error}"))?;
        Ok::<(), String>(())
    })();

    if let Err(error) = restore_result {
        return match fs::remove_dir_all(&staging_path) {
            Ok(()) => Err(error),
            Err(cleanup_error) => Err(format!(
                "{error}; plaintext staging data could not be removed at {}: {cleanup_error}",
                staging_path.display()
            )),
        };
    }

    let locked_folder = metadata.version == 3;
    if locked_folder {
        if let Err(error) = fs::remove_dir_all(&vault_path) {
            let rollback_error = fs::rename(&restored_path, &staging_path).err();
            if let Some(rollback_error) = rollback_error {
                return Err(format!(
                    "The folder was unlocked at {} but its encrypted vault could not be removed at {}: {error}. Plaintext could not be moved back to staging: {rollback_error}.",
                    restored_path.display(),
                    vault_path.display()
                ));
            }
            let cleanup_error = fs::remove_dir_all(&staging_path).err();
            let mut message = format!(
                "The encrypted vault could not be removed at {}: {error}. The folder was not left unlocked.",
                vault_path.display()
            );
            if let Some(cleanup_error) = cleanup_error {
                message.push_str(&format!(
                    " Plaintext staging data could not be removed at {}: {cleanup_error}.",
                    staging_path.display()
                ));
            }
            return Err(message);
        }
    }

    Ok(RestoreVaultResponse {
        restore_path: restored_path.to_string_lossy().to_string(),
        file_count: total_files,
        locked_folder,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restore_paths_reject_traversal_and_absolute_paths() {
        let root = Path::new("/tmp/securevault-test");
        assert!(safe_restore_path(root, "../outside.txt").is_err());
        assert!(safe_restore_path(root, "/absolute.txt").is_err());
        assert!(safe_restore_path(root, "folder\\outside.txt").is_err());
        assert_eq!(
            safe_restore_path(root, "folder/file.txt").unwrap(),
            root.join("folder/file.txt")
        );
    }

    #[test]
    fn password_derived_aes_key_authenticates_encrypted_data() {
        let salt = b"stable-test-salt";
        let key = derive_key("correct horse battery staple", salt).unwrap();
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let nonce = Nonce::from([7u8; 12]);
        let encrypted = cipher.encrypt(&nonce, b"vault test data".as_ref()).unwrap();
        assert_eq!(
            cipher.decrypt(&nonce, encrypted.as_ref()).unwrap(),
            b"vault test data"
        );

        let wrong_key = derive_key("wrong password", salt).unwrap();
        let wrong_cipher = Aes256Gcm::new_from_slice(&wrong_key).unwrap();
        assert!(wrong_cipher.decrypt(&nonce, encrypted.as_ref()).is_err());
    }

    #[test]
    fn verified_lock_archive_preserves_files_and_empty_directories() {
        let test_root = std::env::temp_dir().join(format!(
            "securevault-test-{}",
            rand::thread_rng().r#gen::<u64>()
        ));
        let source = test_root.join("source");
        let vault = test_root.join("source.securevault");
        fs::create_dir_all(source.join("empty/nested")).unwrap();
        fs::write(source.join("notes.txt"), b"secret test contents").unwrap();
        fs::create_dir_all(&vault).unwrap();

        let password = "test-only-password";
        let mut rng = rand::thread_rng();
        let salt = SaltString::generate(&mut rng);
        let key = derive_key(password, salt.as_salt().as_str().as_bytes()).unwrap();
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let contents = walk_source_tree(&source).unwrap();
        let directories = contents
            .directories
            .iter()
            .map(|path| {
                encrypt_relative_path(&cipher, &mut rng, path.strip_prefix(&source).unwrap())
                    .unwrap()
            })
            .collect();
        let files = contents
            .files
            .iter()
            .map(|path| {
                let relative = path.strip_prefix(&source).unwrap();
                let encrypted_path = encrypt_relative_path(&cipher, &mut rng, relative).unwrap();
                let nonce_bytes: [u8; 12] = rng.r#gen();
                let plaintext = fs::read(path).unwrap();
                let ciphertext = cipher
                    .encrypt(&Nonce::from(nonce_bytes), plaintext.as_ref())
                    .unwrap();
                EncryptedFileEntry {
                    relative_path: None,
                    path_nonce: Some(encrypted_path.nonce),
                    encrypted_path: Some(encrypted_path.ciphertext),
                    nonce: BASE64.encode(nonce_bytes),
                    ciphertext: BASE64.encode(ciphertext),
                }
            })
            .collect();
        let metadata = VaultMetadata {
            version: 3,
            created_at: 0,
            salt: salt.to_string(),
            directories,
            files,
        };
        fs::write(
            vault.join("vault.meta.json"),
            serde_json::to_vec(&metadata).unwrap(),
        )
        .unwrap();

        verify_vault_matches_source(&vault, &source, password).unwrap();
        assert_eq!(
            walk_source_tree(&source).unwrap().directories.len(),
            2,
            "empty directories must be included in the lock archive"
        );

        fs::write(source.join("notes.txt"), b"changed after encryption").unwrap();
        assert!(verify_vault_matches_source(&vault, &source, password).is_err());
        fs::remove_dir_all(test_root).unwrap();
    }

    #[test]
    fn empty_folders_can_be_verified_for_locking() {
        let test_root = std::env::temp_dir().join(format!(
            "securevault-empty-test-{}",
            rand::thread_rng().r#gen::<u64>()
        ));
        let source = test_root.join("empty");
        let vault = test_root.join("empty.securevault");
        fs::create_dir_all(&source).unwrap();
        fs::create_dir_all(&vault).unwrap();
        let password = "test-only-password";
        let mut rng = rand::thread_rng();
        let salt = SaltString::generate(&mut rng);
        let metadata = VaultMetadata {
            version: 3,
            created_at: 0,
            salt: salt.to_string(),
            directories: Vec::new(),
            files: Vec::new(),
        };
        fs::write(
            vault.join("vault.meta.json"),
            serde_json::to_vec(&metadata).unwrap(),
        )
        .unwrap();

        verify_vault_matches_source(&vault, &source, password).unwrap();
        fs::remove_dir_all(test_root).unwrap();
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            lock_folder,
            restore_encrypted_vault,
            get_drive_analysis
        ])
        .setup(|app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while building tauri application");
}
