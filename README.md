# SecureVault

SecureVault is a Tauri desktop application with a React/TypeScript interface and a Rust backend.

## Run in development

Install Node.js, Rust, and the platform prerequisites listed in the [Tauri v2 prerequisites](https://v2.tauri.app/start/prerequisites/), then run:

```sh
npm ci
npm run desktop:dev
```

On macOS, ensure Xcode Command Line Tools are installed. On Linux, install the WebKitGTK and GTK development packages required by Tauri.

## Build a desktop installer

Build for the operating system you are currently using:

```sh
npm ci
npm run desktop:build
```

Tauri writes installers under `src-tauri/target/release/bundle/`. macOS builds include a `.dmg`; Linux builds include `.deb` and/or `.AppImage` packages, depending on installed system libraries.

Build a macOS disk image specifically:

```sh
npm run desktop:build -- --bundles dmg
```

Native builds are platform-specific. Build Linux packages on Linux (or use the included GitHub Actions workflow); building on macOS does not produce a Linux app.

## Automated macOS and Linux builds

The workflow at `.github/workflows/desktop-build.yml` builds macOS and Linux installers and uploads them as workflow artifacts. Run it from GitHub Actions with **Build desktop apps**, or push to `main`/`master`.

The GitHub-hosted macOS job creates an Apple Silicon `.dmg`. The Linux job creates `.deb` and `.AppImage` packages. These unsigned builds are intended for testing; public macOS distribution requires signing and notarization.

## Current encryption scope

Folder Lock creates a sibling `.securevault` archive, verifies its encrypted file data and paths, then removes the selected plaintext folder only after the user confirms that destructive step. This filesystem removal is not a secure erase: SSD wear-leveling, snapshots, backups, or filesystem recovery may retain old data. Unlocking verifies and restores the folder to its original sibling path, then removes the archive. Existing destination folders are never overwritten. Keep an independent backup; failures are reported explicitly and can leave the verified archive or plaintext folder in place.

Automatic locking runs ten minutes after a folder is unlocked, regardless of app activity, and the app attempts to lock an unlocked folder before closing. This is not an operating-system encrypted mount: it cannot intercept access from Finder or other applications, and an application that already opened a file may retain access. A crash, force-quit, or power loss can also leave the restored plaintext folder on disk. For protection against those cases, use a native encrypted volume rather than this app-level workflow.

Folder contents and empty directories are encrypted; symbolic links are rejected. File permissions, timestamps, extended attributes, and other platform metadata are not preserved. Avoid modifying the folder from another process while it is being locked.

## App sections

- **Dashboard** shows available workflows and current app capabilities.
- **Folder Lock** encrypts and verifies selected folders, then removes their plaintext source after explicit confirmation.
- **Smart Format** shows mounted-volume capacity, available space, filesystem, and removable status. It does not inspect unmounted partitions or modify disk layouts.
- **Secure Volumes** lists vaults created during the current app session and unlocks `.securevault` folders beside their archive.
- **Connected Drives** shows the mounted-volume inventory; it does not identify every physical drive.
- **Settings** provides persistent appearance and reduced-motion preferences and reports the ten-minute auto-lock policy.

Biometric authentication is intentionally not claimed: there is no platform credential/key-store integration yet, so Touch ID or fingerprint prompts would not be safely unlocking a protected vault key. Likewise, Smart Format does not resize, convert, partition, or format physical disks. Those operations require platform-specific privilege handling, tested filesystem support, explicit destructive-operation confirmations, and validated recovery workflows. No physical disk changes are made by this build.
