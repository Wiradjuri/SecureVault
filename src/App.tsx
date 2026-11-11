import { useEffect, useRef, useState } from 'react'
import { invoke, isTauri } from '@tauri-apps/api/core'
import { listen } from '@tauri-apps/api/event'
import { getCurrentWindow } from '@tauri-apps/api/window'
import { open } from '@tauri-apps/plugin-dialog'
import './App.css'

type EncryptionProgress = {
  current: number
  total: number
  fileName: string
}

type RestoreResult = {
  restorePath: string
  fileCount: number
  lockedFolder: boolean
}

type LockResult = {
  vaultPath: string
  fileCount: number
  lockedFolderPath: string
}

type UnlockedSession = {
  folderPath: string
  password: string
  expiresAt: number
}

type DriveAudit = {
  name: string
  type: string
  capacity: string
  available: string
  filesystem: string
  removable: boolean
}

const navItems = [
  'Dashboard',
  'Folder Lock',
  'Smart Format',
  'Secure Volumes',
  'Connected Drives',
  'Settings',
]

function App() {
  const [activeTab, setActiveTab] = useState('Dashboard')
  const [drives, setDrives] = useState<DriveAudit[]>([])
  const [isLoadingDrives, setIsLoadingDrives] = useState(false)
  const [createdVaults, setCreatedVaults] = useState<string[]>([])
  const [selectedFolder, setSelectedFolder] = useState('')
  const [isSelectingFolder, setIsSelectingFolder] = useState(false)
  const [selectedVault, setSelectedVault] = useState('')
  const [restorePassword, setRestorePassword] = useState('')
  const [restoreStatus, setRestoreStatus] = useState('')
  const [isRestoring, setIsRestoring] = useState(false)
  const [password, setPassword] = useState('')
  const [statusText, setStatusText] = useState('Choose a folder, then confirm to encrypt and remove its plaintext contents.')
  const [isCreating, setIsCreating] = useState(false)
  const [confirmRemoveOriginal, setConfirmRemoveOriginal] = useState(false)
  const [isProgressListenerReady, setIsProgressListenerReady] = useState(false)
  const [isRestoreListenerReady, setIsRestoreListenerReady] = useState(false)
  const [isCloseLockReady, setIsCloseLockReady] = useState(false)
  const [encryptionProgress, setEncryptionProgress] = useState<EncryptionProgress | null>(null)
  const [restoreProgress, setRestoreProgress] = useState<EncryptionProgress | null>(null)
  const [unlockedSession, setUnlockedSession] = useState<UnlockedSession | null>(null)
  const [idleSeconds, setIdleSeconds] = useState(600)
  const unlockedSessionRef = useRef<UnlockedSession | null>(null)
  const lockOperationRef = useRef<Promise<LockResult> | null>(null)
  const lockingSessionRef = useRef(false)
  const isBusyRef = useRef(false)
  const lockFailedRef = useRef(false)
  const [appearance, setAppearance] = useState<'dark' | 'light'>(() =>
    localStorage.getItem('securevault-appearance') === 'light' ? 'light' : 'dark',
  )
  const [reduceMotion, setReduceMotion] = useState(() =>
    localStorage.getItem('securevault-reduce-motion') === 'true',
  )

  useEffect(() => {
    let unlisten: (() => void) | undefined
    let unlistenRestore: (() => void) | undefined
    let cancelled = false

    void listen<EncryptionProgress>('vault-encryption-progress', (event) => {
      setEncryptionProgress(event.payload)
    }).then((stopListening) => {
      if (cancelled) {
        stopListening()
      } else {
        unlisten = stopListening
        setIsProgressListenerReady(true)
      }
    }).catch((error: unknown) => {
      setStatusText(`Could not listen for encryption progress: ${String(error)}`)
    })
    void listen<EncryptionProgress>('vault-restore-progress', (event) => {
      setRestoreProgress(event.payload)
    }).then((stopListening) => {
      if (cancelled) {
        stopListening()
      } else {
        unlistenRestore = stopListening
        setIsRestoreListenerReady(true)
      }
    }).catch((error: unknown) => {
      setRestoreStatus(`Could not listen for restore progress: ${String(error)}`)
    })

    return () => {
      cancelled = true
      unlisten?.()
      unlistenRestore?.()
    }
  }, [])

  useEffect(() => {
    localStorage.setItem('securevault-appearance', appearance)
    localStorage.setItem('securevault-reduce-motion', String(reduceMotion))
  }, [appearance, reduceMotion])

  const refreshDriveInventory = async () => {
    setIsLoadingDrives(true)
    try {
      const result = await invoke<DriveAudit[]>('get_drive_analysis')
      setDrives(result)
    } catch (error) {
      setStatusText(`Drive inventory failed: ${String(error)}`)
    } finally {
      setIsLoadingDrives(false)
    }
  }

  const navigateTo = (tab: string) => {
    setActiveTab(tab)
    if (tab === 'Connected Drives' || tab === 'Smart Format') {
      void refreshDriveInventory()
    }
  }

  const updateUnlockedSession = (session: UnlockedSession | null) => {
    unlockedSessionRef.current = session
    setUnlockedSession(session)
    if (!session) setIdleSeconds(600)
    lockFailedRef.current = false
  }

  const lockOpenedFolder = (session: UnlockedSession): Promise<LockResult> => {
    if (lockOperationRef.current) return lockOperationRef.current

    lockingSessionRef.current = true
    isBusyRef.current = true
    setIsCreating(true)
    setEncryptionProgress({ current: 0, total: 0, fileName: '' })
    setStatusText('Verifying and locking the unlocked folder…')
    const operation = invoke<LockResult>('lock_folder', {
      request: {
        sourcePath: session.folderPath,
        password: session.password,
        confirmRemoveOriginal: true,
      },
    }).then((result) => {
      updateUnlockedSession(null)
      setSelectedFolder('')
      setSelectedVault(result.vaultPath)
      setCreatedVaults((previous) =>
        previous.includes(result.vaultPath) ? previous : [...previous, result.vaultPath],
      )
      setPassword('')
      setStatusText(`Folder locked and verified. Encrypted data is at ${result.vaultPath}.`)
      return result
    }).catch((error: unknown) => {
      lockFailedRef.current = true
      setStatusText(`Folder lock failed: ${String(error)}`)
      throw error
    }).finally(() => {
      lockOperationRef.current = null
      lockingSessionRef.current = false
      isBusyRef.current = false
      setIsCreating(false)
    })
    lockOperationRef.current = operation
    return operation
  }

  useEffect(() => {
    if (!unlockedSession) {
      return
    }

    const updateCountdown = () => {
      const remaining = Math.max(0, Math.ceil((unlockedSession.expiresAt - Date.now()) / 1000))
      setIdleSeconds(remaining)
      if (remaining === 0 && !lockingSessionRef.current && !lockFailedRef.current) {
        void lockOpenedFolder(unlockedSession).catch(() => undefined)
      }
    }
    updateCountdown()
    const interval = window.setInterval(updateCountdown, 1000)
    return () => window.clearInterval(interval)
  }, [unlockedSession])

  useEffect(() => {
    if (!isTauri()) return
    const appWindow = getCurrentWindow()
    let unlisten: (() => void) | undefined
    let cancelled = false
    void appWindow.onCloseRequested(async (event) => {
      if (isBusyRef.current) {
        event.preventDefault()
        setStatusText('Wait for the current encryption or unlock operation to finish before closing.')
        return
      }
      const session = unlockedSessionRef.current
      if (!session) return
      event.preventDefault()
      try {
        await lockOpenedFolder(session)
        await appWindow.close()
      } catch {
        // Keep the app open so the user can address a failed lock operation.
      }
    }).then((stopListening) => {
      if (cancelled) stopListening()
      else {
        unlisten = stopListening
        setIsCloseLockReady(true)
      }
    }).catch((error: unknown) => {
      setIsCloseLockReady(false)
      const message = `Could not enable close-time folder locking: ${String(error)}`
      setStatusText(message)
      setRestoreStatus(message)
    })
    return () => {
      cancelled = true
      unlisten?.()
    }
  }, [])

  const handleSelectFolder = async () => {
    setIsSelectingFolder(true)
    try {
      const folder = await open({
        directory: true,
        multiple: false,
        title: 'Select folder to lock',
      })

      if (typeof folder === 'string') {
        setSelectedFolder(folder)
        setConfirmRemoveOriginal(false)
        setStatusText(`Folder selected: ${folder}`)
      } else {
        setStatusText('Folder selection cancelled.')
      }
    } catch (error) {
      setStatusText(`Folder picker error: ${error instanceof Error ? error.message : String(error)}`)
    } finally {
      setIsSelectingFolder(false)
    }
  }

  const handleSelectVault = async () => {
    try {
      const path = await open({
        directory: true,
        multiple: false,
        title: 'Select a .securevault folder to restore',
      })
      if (typeof path === 'string') {
        setSelectedVault(path)
        setRestoreStatus('Vault selected. Enter its password to unlock it beside the vault.')
      } else {
        setRestoreStatus('Vault selection cancelled.')
      }
    } catch (error) {
      setRestoreStatus(`Vault picker error: ${error instanceof Error ? error.message : String(error)}`)
    }
  }

  const handleLockFolder = async () => {
    if (!isProgressListenerReady) {
      setStatusText('Encryption progress is not ready yet. Please try again in a moment.')
      return
    }

    if (!selectedFolder) {
      setStatusText('Select a folder before locking it.')
      return
    }

    if (!password.trim()) {
      setStatusText('Enter a password to protect the vault.')
      return
    }

    if (!confirmRemoveOriginal) {
      setStatusText('Confirm that the plaintext folder should be removed after verification.')
      return
    }

    setIsCreating(true)
    isBusyRef.current = true
    setEncryptionProgress({ current: 0, total: 0, fileName: '' })
    setStatusText('Encrypting and verifying the selected folder…')

    try {
      const result = await invoke<LockResult>('lock_folder', {
        request: {
          sourcePath: selectedFolder,
          password,
          confirmRemoveOriginal: true,
        },
      })

      setStatusText(`Folder locked. ${result.fileCount} file(s) are encrypted at ${result.vaultPath}.`)
      setCreatedVaults((previous) => [...previous, result.vaultPath])
      setSelectedVault(result.vaultPath)
      setSelectedFolder('')
      setPassword('')
      setConfirmRemoveOriginal(false)
    } catch (error) {
      setEncryptionProgress(null)
      setStatusText(`Folder lock failed: ${String(error)}`)
    } finally {
      isBusyRef.current = false
      setIsCreating(false)
    }
  }

  const handleRestoreVault = async () => {
    if (!isCloseLockReady) {
      setRestoreStatus('Close-time locking is not ready. SecureVault will not unlock a folder until this safeguard is available.')
      return
    }

    if (!isRestoreListenerReady) {
      setRestoreStatus('Restore progress is not ready yet. Please try again in a moment.')
      return
    }

    if (!selectedVault || !restorePassword) {
      setRestoreStatus('Choose a vault and enter its password.')
      return
    }

    setIsRestoring(true)
    isBusyRef.current = true
    setRestoreProgress({ current: 0, total: 0, fileName: '' })
    setRestoreStatus('Verifying and restoring encrypted files…')
    try {
      const result = await invoke<RestoreResult>('restore_encrypted_vault', {
        request: {
          vaultPath: selectedVault,
          destinationPath: '',
          password: restorePassword,
        },
      })
      if (result.lockedFolder) {
        updateUnlockedSession({
          folderPath: result.restorePath,
          password: restorePassword,
          expiresAt: Date.now() + 10 * 60 * 1000,
        })
        lockFailedRef.current = false
        setIdleSeconds(600)
        setSelectedVault('')
        setRestoreStatus(`Folder unlocked at ${result.restorePath}. It will auto-lock 10 minutes after unlocking.`)
      } else {
        setRestoreStatus(`Legacy vault copied to ${result.restorePath}; it will not auto-lock.`)
      }
      setRestorePassword('')
    } catch (error) {
      setRestoreProgress(null)
      setRestoreStatus(`Restore failed: ${String(error)}`)
    } finally {
      isBusyRef.current = false
      setIsRestoring(false)
    }
  }

  return (
    <div className={`app-shell ${appearance === 'light' ? 'theme-light' : ''} ${reduceMotion ? 'reduce-motion' : ''}`}>
      <aside className="sidebar">
        <div className="brand-block">
          <div className="brand-mark">S</div>
          <div>
            <p className="eyebrow">Premium security</p>
            <h1>SecureVault</h1>
          </div>
        </div>

        <nav className="nav" aria-label="Primary navigation">
          {navItems.map((item) => (
            <button
              key={item}
              type="button"
              className={item === activeTab ? 'nav-item active' : 'nav-item'}
              aria-current={item === activeTab ? 'page' : undefined}
              onClick={() => navigateTo(item)}
            >
              {item}
            </button>
          ))}
        </nav>

        <div className="status-panel">
          <p className="panel-label">Vault protection</p>
          <div className="security-state">AES-256-GCM</div>
          <p className="panel-copy">Locking encrypts, verifies, then removes the selected plaintext folder. Biometrics and physical drive operations are not enabled.</p>
        </div>
      </aside>

      <main className="content-panel">
        <header className="topbar">
          <div>
            <p className="eyebrow">Secure storage</p>
            <h2>{activeTab}</h2>
          </div>
          <div className="toolbar">
            {activeTab === 'Dashboard' && (
              <>
                <button type="button" className="ghost-button" onClick={() => navigateTo('Connected Drives')}>
                  Connected drives
                </button>
                <button type="button" className="primary-button" onClick={() => navigateTo('Folder Lock')}>
                  Lock a folder
                </button>
              </>
            )}
            {activeTab === 'Smart Format' && (
              <button type="button" className="ghost-button" onClick={() => navigateTo('Connected Drives')}>
                View connected drives
              </button>
            )}
            {activeTab === 'Secure Volumes' && (
              <button type="button" className="primary-button" onClick={() => navigateTo('Folder Lock')}>
                Lock a folder
              </button>
            )}
          </div>
        </header>

        {unlockedSession && (
          <div className="session-banner" role="status">
            <div>
              <strong>Folder unlocked</strong>
              <span>{unlockedSession.folderPath}</span>
              <small>
                Auto-lock in {Math.floor(idleSeconds / 60)}:{String(idleSeconds % 60).padStart(2, '0')}.
                Other applications may retain access to files they already opened.
              </small>
              {statusText.startsWith('Folder lock failed:') && (
                <small className="session-error" role="alert">{statusText}</small>
              )}
            </div>
            <button
              type="button"
              className="primary-button"
              onClick={() => { void lockOpenedFolder(unlockedSession).catch(() => undefined) }}
              disabled={isCreating}
            >
              {isCreating ? 'Locking…' : 'Lock now'}
            </button>
          </div>
        )}

        {activeTab === 'Dashboard' && (
          <>
            <section className="metrics-grid" aria-label="Application status">
              <article className="metric-card">
                <p>Vaults created this session</p>
                <strong>{createdVaults.length}</strong>
                <span>Encrypted folders</span>
              </article>
              <article className="metric-card">
                <p>Encryption</p>
                <strong>AES-256-GCM</strong>
                <span>Password-derived Argon2id key</span>
              </article>
              <article className="metric-card">
                <p>Drive operations</p>
                <strong>Read-only</strong>
                <span>Mounted volume inventory only</span>
              </article>
            </section>

            <section className="content-grid">
              <article className="panel">
                <div className="panel-header">
                  <div>
                    <p className="eyebrow">Get started</p>
                    <h3>Choose an action</h3>
                  </div>
                </div>
                <div className="quick-actions">
                  <button type="button" className="quick-action" onClick={() => navigateTo('Folder Lock')}>
                    <strong>Lock a folder</strong>
                    <span>Encrypt, verify, then remove the plaintext folder.</span>
                  </button>
                  <button type="button" className="quick-action" onClick={() => navigateTo('Secure Volumes')}>
                    <strong>Unlock a folder</strong>
                    <span>Open a .securevault with its password.</span>
                  </button>
                  <button type="button" className="quick-action" onClick={() => navigateTo('Smart Format')}>
                    <strong>Smart Format</strong>
                    <span>Review current disk-management support and safety.</span>
                  </button>
                </div>
              </article>
              <article className="panel">
                <div className="panel-header">
                  <div>
                    <p className="eyebrow">Platform support</p>
                    <h3>Protection status</h3>
                  </div>
                </div>
                <ul className="risk-list">
                  <li><span>Biometric unlock</span><strong>Not implemented</strong></li>
                  <li><span>Recovery keys</span><strong>Not available</strong></li>
                  <li><span>Mounted volume inventory</span><strong>Available</strong></li>
                  <li><span>Disk modification</span><strong>Disabled</strong></li>
                </ul>
              </article>
            </section>
          </>
        )}

        {activeTab === 'Folder Lock' && (
          <section className="action-panel panel">
            <div className="panel-header">
              <div>
                <p className="eyebrow">Folder Lock</p>
                <h3>Lock a folder</h3>
                <p className="section-description">SecureVault encrypts and verifies the folder, then removes the plaintext source. The encrypted .securevault is created beside it.</p>
              </div>
            </div>

            <div className="action-form">
              <label>
                Folder to lock
                <div className="input-row">
                  <input
                    type="text"
                    readOnly
                    value={selectedFolder}
                    placeholder="Select a folder to lock"
                  />
                  <button type="button" className="secondary-button compact" onClick={handleSelectFolder} disabled={isCreating || isSelectingFolder}>
                    {isSelectingFolder ? 'Opening…' : 'Browse'}
                  </button>
                </div>
              </label>

              <label>
                Vault password
                <input
                  type="password"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  placeholder="Use a strong password"
                  disabled={isCreating}
                />
              </label>

              <label className="confirmation-row">
                <input
                  type="checkbox"
                  checked={confirmRemoveOriginal}
                  onChange={(event) => setConfirmRemoveOriginal(event.target.checked)}
                  disabled={isCreating}
                />
                <span>I understand the plaintext folder will be removed after verification; removal is not a secure wipe of disk blocks, snapshots, or backups.</span>
              </label>

              <button type="button" className="primary-button full-width" onClick={handleLockFolder} disabled={isCreating || !isProgressListenerReady || !confirmRemoveOriginal}>
                {isCreating ? 'Locking…' : isProgressListenerReady ? 'Lock selected folder' : 'Preparing…'}
              </button>

              {(isCreating || encryptionProgress !== null) && (
                <div className="encryption-progress" aria-live="polite">
                  <div className="progress-heading">
                    <span>{isCreating ? 'Encrypting and verifying' : 'Folder locked'}</span>
                    {encryptionProgress && encryptionProgress.total > 0 && (
                      <span>{encryptionProgress.current} / {encryptionProgress.total}</span>
                    )}
                  </div>
                  <div
                    className="progress-track"
                    role="progressbar"
                    aria-label="Folder encryption progress"
                    aria-valuemin={0}
                    aria-valuemax={encryptionProgress?.total || 100}
                    aria-valuenow={
                      encryptionProgress && encryptionProgress.total > 0
                        ? encryptionProgress.current
                        : 0
                    }
                  >
                    <div
                      className="progress-fill"
                      style={{
                        width: `${encryptionProgress && encryptionProgress.total > 0
                          ? (encryptionProgress.current / encryptionProgress.total) * 100
                          : 0}%`,
                      }}
                    />
                  </div>
                  <span className="progress-file">
                    {encryptionProgress?.fileName
                      ? `Encrypted: ${encryptionProgress.fileName}`
                      : isCreating ? 'Preparing secure vault…' : 'Vault verified; plaintext removed'}
                  </span>
                </div>
              )}

              <p className="status-text" role="status">{statusText}</p>
            </div>
          </section>
        )}

        {activeTab === 'Smart Format' && (
          <section className="panel page-panel">
            <p className="eyebrow">Safe storage guidance</p>
            <h3>Mounted storage analysis</h3>
            <button type="button" className="secondary-button compact" onClick={refreshDriveInventory} disabled={isLoadingDrives}>
              {isLoadingDrives ? 'Scanning…' : 'Refresh inventory'}
            </button>
            <p className="section-description">
              SecureVault inspects mounted volumes on this device. Physical partitioning, resizing, conversion, and formatting are intentionally disabled; this inventory does not inspect unmounted partitions or establish backup safety.
            </p>
            <div className="drive-grid">
              {drives.map((drive) => (
                <article key={`${drive.name}:${drive.type}`} className="drive-card">
                  <div className="drive-topline">
                    <span className="drive-name">{drive.name}</span>
                    <span className="risk-badge low">{drive.removable ? 'Removable' : 'Mounted'}</span>
                  </div>
                  <p>{drive.type}</p>
                  <ul>
                    <li><span>Capacity</span><strong>{drive.capacity}</strong></li>
                    <li><span>Available</span><strong>{drive.available}</strong></li>
                    <li><span>Filesystem</span><strong>{drive.filesystem}</strong></li>
                  </ul>
                </article>
              ))}
            </div>
            <p className="status-text" role="status">
              {isLoadingDrives ? 'Scanning mounted volumes…' : `${drives.length} mounted volume(s) found. No disk changes are performed.`}
            </p>
            <div className="support-grid">
              <article><strong>New volume</strong><span>Requires live partition and filesystem analysis.</span></article>
              <article><strong>New partition</strong><span>Requires privileged disk tools and explicit confirmation.</span></article>
              <article><strong>Resize or convert</strong><span>Filesystem-specific support and verified backups are required.</span></article>
              <article><strong>Reformat</strong><span>Destructive; not offered in this build.</span></article>
            </div>
            <button type="button" className="primary-button" onClick={() => navigateTo('Folder Lock')}>
              Create a file-based encrypted vault instead
            </button>
          </section>
        )}

        {activeTab === 'Secure Volumes' && (
          <section className="panel page-panel">
            <p className="eyebrow">Encrypted file vaults</p>
            <h3>Secure volumes</h3>
            <p className="section-description">
              Locked folders are stored as encrypted .securevault archives beside their original location. Unlocking restores the folder there and removes the archive after verification.
            </p>
            {createdVaults.length === 0 ? (
              <div className="empty-state">
                <strong>No vaults created in this session</strong>
                <span>Lock a folder or select an existing .securevault archive to unlock it.</span>
                <button type="button" className="primary-button" onClick={() => navigateTo('Folder Lock')}>
                  Go to Folder Lock
                </button>
              </div>
            ) : (
              <ul className="created-vault-list">
                {createdVaults.map((vaultPath) => (
                  <li key={vaultPath}>
                    <span>{vaultPath}</span>
                    <strong>Encrypted copy</strong>
                  </li>
                ))}
              </ul>
            )}
            <div className="restore-form">
              <h4>Unlock a folder</h4>
              <div className="input-row">
                <input aria-label="Vault folder" readOnly value={selectedVault} placeholder="Select a .securevault folder" />
                <button type="button" className="secondary-button compact" onClick={handleSelectVault} disabled={isRestoring || isCreating}>Choose vault</button>
              </div>
              <input
                aria-label="Vault password for restore"
                type="password"
                value={restorePassword}
                onChange={(event) => setRestorePassword(event.target.value)}
                placeholder="Vault password"
                disabled={isRestoring}
              />
              <button type="button" className="primary-button" onClick={handleRestoreVault} disabled={isRestoring || !isRestoreListenerReady || !isCloseLockReady || Boolean(unlockedSession)}>
                {isRestoring ? 'Verifying and unlocking…' : !isCloseLockReady ? 'Preparing close protection…' : isRestoreListenerReady ? 'Unlock folder' : 'Preparing…'}
              </button>
              {(isRestoring || restoreProgress !== null) && (
                <div className="encryption-progress" aria-live="polite">
                  <div className="progress-heading">
                    <span>{isRestoring ? 'Restoring files' : 'Restore complete'}</span>
                    {restoreProgress && restoreProgress.total > 0 && (
                      <span>{restoreProgress.current} / {restoreProgress.total}</span>
                    )}
                  </div>
                  <div
                    className="progress-track"
                    role="progressbar"
                    aria-label="Vault restore progress"
                    aria-valuemin={0}
                    aria-valuemax={restoreProgress?.total || 100}
                    aria-valuenow={restoreProgress?.current || 0}
                  >
                    <div
                      className="progress-fill"
                      style={{
                        width: `${restoreProgress && restoreProgress.total > 0
                          ? (restoreProgress.current / restoreProgress.total) * 100
                          : 0}%`,
                      }}
                    />
                  </div>
                  <span className="progress-file">
                    {restoreProgress?.fileName || (isRestoring ? 'Checking vault integrity…' : 'All files restored')}
                  </span>
                </div>
              )}
              <p className="status-text" role="status">{restoreStatus}</p>
            </div>
          </section>
        )}

        {activeTab === 'Connected Drives' && (
          <section className="panel page-panel">
            <div className="panel-header">
              <div>
                <p className="eyebrow">Drive overview</p>
                <h3>Connected drives</h3>
              </div>
              <button type="button" className="secondary-button compact" onClick={() => navigateTo('Smart Format')}>
                Smart Format support
              </button>
              <button type="button" className="secondary-button compact" onClick={refreshDriveInventory} disabled={isLoadingDrives}>
                {isLoadingDrives ? 'Scanning…' : 'Refresh'}
              </button>
            </div>
            <div className="empty-state">
              <strong>{isLoadingDrives ? 'Scanning mounted volumes…' : `Found ${drives.length} mounted volume(s)`}</strong>
              <span>Inventory shows mounted filesystems only; it does not identify every physical drive or unmounted partition.</span>
            </div>
            {drives.length > 0 && (
              <div className="drive-grid">
                {drives.map((drive) => (
                  <article key={`${drive.name}:${drive.type}`} className="drive-card">
                    <div className="drive-topline">
                      <span className="drive-name">{drive.name}</span>
                      <span className="risk-badge low">{drive.removable ? 'Removable' : 'Mounted'}</span>
                    </div>
                    <p>{drive.type}</p>
                    <ul>
                      <li><span>Capacity</span><strong>{drive.capacity}</strong></li>
                      <li><span>Available</span><strong>{drive.available}</strong></li>
                      <li><span>Filesystem</span><strong>{drive.filesystem}</strong></li>
                    </ul>
                  </article>
                ))}
              </div>
            )}
          </section>
        )}

        {activeTab === 'Settings' && (
          <section className="panel page-panel">
            <p className="eyebrow">Preferences</p>
            <h3>Settings</h3>
            <div className="settings-list">
              <label className="setting-row">
                <span><strong>Appearance</strong><small>Choose the app color theme.</small></span>
                <select value={appearance} onChange={(event) => setAppearance(event.target.value as 'dark' | 'light')}>
                  <option value="dark">Dark</option>
                  <option value="light">Light</option>
                </select>
              </label>
              <label className="setting-row">
                <span><strong>Reduce motion</strong><small>Disable interface animations.</small></span>
                <input type="checkbox" checked={reduceMotion} onChange={(event) => setReduceMotion(event.target.checked)} />
              </label>
              <div className="setting-row">
                <span><strong>Automatic locking</strong><small>Re-encrypts the unlocked folder 10 minutes after it is unlocked.</small></span>
                <span className="pill neutral">10 minutes</span>
              </div>
              <div className="setting-row">
                <span><strong>Biometric unlock</strong><small>Platform key-store integration is not implemented; biometrics cannot securely unlock vault keys yet.</small></span>
                <span className="pill neutral">Not implemented</span>
              </div>
            </div>
          </section>
        )}
      </main>
    </div>
  )
}

export default App
