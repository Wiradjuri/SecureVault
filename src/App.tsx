import { useEffect, useRef, useState } from 'react'
import { invoke } from '@tauri-apps/api/core'
import { listen } from '@tauri-apps/api/event'
import { open } from '@tauri-apps/plugin-dialog'
import './App.css'

type EncryptionProgress = {
  current: number
  total: number
  fileName: string
}

type Vault = {
  path: string
  name: string
  fileCount: number
  unlockedPath?: string
  unlockedAt?: number
}

const navItems = ['Dashboard', 'My Vaults', 'Create Vault', 'Settings']

function App() {
  const [activeTab, setActiveTab] = useState('Dashboard')
  const [vaults, setVaults] = useState<Vault[]>([])
  const [password, setPassword] = useState('')
  const [vaultName, setVaultName] = useState('')
  const [selectedLocation, setSelectedLocation] = useState('')
  const [statusText, setStatusText] = useState('Welcome to SecureVault. Create a vault or add files to an existing vault.')
  const [isCreating, setIsCreating] = useState(false)
  const [encryptionProgress, setEncryptionProgress] = useState<EncryptionProgress | null>(null)
  const [isProgressListenerReady, setIsProgressListenerReady] = useState(false)
  const [appearance, setAppearance] = useState<'dark' | 'light'>(() =>
    localStorage.getItem('securevault-appearance') === 'light' ? 'light' : 'dark',
  )
  const [reduceMotion, setReduceMotion] = useState(() =>
    localStorage.getItem('securevault-reduce-motion') === 'true',
  )
  const isBusyRef = useRef(false)

  useEffect(() => {
    let unlisten: (() => void) | undefined
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

    return () => {
      cancelled = true
      unlisten?.()
    }
  }, [])

  useEffect(() => {
    localStorage.setItem('securevault-appearance', appearance)
    localStorage.setItem('securevault-reduce-motion', String(reduceMotion))
  }, [appearance, reduceMotion])

  const handleSelectLocation = async () => {
    try {
      const folder = await open({
        directory: true,
        multiple: false,
        title: 'Select location for new vault',
      })

      if (typeof folder === 'string') {
        setSelectedLocation(folder)
        setStatusText(`Location selected: ${folder}`)
      } else {
        setStatusText('Location selection cancelled.')
      }
    } catch (error) {
      setStatusText(`Folder picker error: ${error instanceof Error ? error.message : String(error)}`)
    }
  }

  const handleCreateVault = async () => {
    if (!isProgressListenerReady) {
      setStatusText('Encryption progress is not ready yet. Please try again in a moment.')
      return
    }

    if (!vaultName.trim()) {
      setStatusText('Enter a vault name.')
      return
    }

    if (!selectedLocation) {
      setStatusText('Select a location for the vault.')
      return
    }

    if (!password.trim()) {
      setStatusText('Enter a password to protect the vault.')
      return
    }

    setIsCreating(true)
    isBusyRef.current = true

    try {
      const result = await invoke<{ vaultPath: string }>('create_vault', {
        location: selectedLocation,
        vaultName,
        password,
      })

      const vaultPath = result.vaultPath
      const name = vaultName.trim()
      setVaults((prev) => [...prev, { path: vaultPath, name, fileCount: 0 }])
      setStatusText(`Vault created: ${name}`)
      setVaultName('')
      setPassword('')
      setSelectedLocation('')
    } catch (error) {
      setStatusText(`Vault creation failed: ${String(error)}`)
    } finally {
      isBusyRef.current = false
      setIsCreating(false)
    }
  }

  const handleAddFilesToVault = async (vault: Vault) => {
    try {
      const files = await open({
        multiple: true,
        title: 'Select files to add to vault',
      })

      if (Array.isArray(files) && files.length > 0) {
        setIsCreating(true)
        isBusyRef.current = true
        setEncryptionProgress({ current: 0, total: files.length, fileName: '' })
        setStatusText('Adding files to vault...')

        const result = await invoke<{ filesAdded: number; totalFiles: number }>('add_files_to_vault', {
          vaultPath: vault.path,
          filePaths: files,
          password,
        })

        setVaults((prev) =>
          prev.map((v) =>
            v.path === vault.path ? { ...v, fileCount: result.totalFiles } : v,
          ),
        )
        setStatusText(`Added ${result.filesAdded} file(s). Vault now contains ${result.totalFiles} file(s).`)
        setPassword('')
      }
    } catch (error) {
      setStatusText(`Could not add files: ${String(error)}`)
    } finally {
      isBusyRef.current = false
      setIsCreating(false)
      setEncryptionProgress(null)
    }
  }

  const handleUnlockVault = async (vault: Vault) => {
    if (!password.trim()) {
      setStatusText('Enter the vault password.')
      return
    }

    try {
      const result = await invoke<{ unlockPath: string; fileCount: number }>('unlock_vault_container', {
        vaultPath: vault.path,
        password,
      })

      setVaults((prev) =>
        prev.map((v) =>
          v.path === vault.path ? { ...v, unlockedPath: result.unlockPath, unlockedAt: Date.now() } : v,
        ),
      )
      setStatusText(`Vault unlocked at ${result.unlockPath}. Folder is read-only for protection.`)
      setPassword('')
    } catch (error) {
      setStatusText(`Could not unlock vault: ${String(error)}`)
    }
  }

  const handleLockVault = async (vault: Vault) => {
    if (!vault.unlockedPath) return

    try {
      await invoke<void>('lock_unlocked_folder', {
        folderPath: vault.unlockedPath,
      })

      setVaults((prev) =>
        prev.map((v) =>
          v.path === vault.path ? { ...v, unlockedPath: undefined, unlockedAt: undefined } : v,
        ),
      )
      setStatusText('Vault locked and folder made read-only.')
    } catch (error) {
      setStatusText(`Could not lock vault: ${String(error)}`)
    }
  }

  const handleEnableAccess = async (vault: Vault) => {
    if (!vault.unlockedPath) return

    try {
      await invoke<void>('unlock_folder_for_modification', {
        folderPath: vault.unlockedPath,
      })
      setStatusText('Folder is now writable. Remember to lock it when done.')
    } catch (error) {
      setStatusText(`Could not enable access: ${String(error)}`)
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
              onClick={() => setActiveTab(item)}
            >
              {item}
            </button>
          ))}
        </nav>

        <div className="status-panel">
          <p className="panel-label">Vault protection</p>
          <div className="security-state">AES-256-GCM</div>
          <p className="panel-copy">Vaults are encrypted containers. Files are encrypted and stored securely.</p>
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
              <button type="button" className="primary-button" onClick={() => setActiveTab('Create Vault')}>
                Create a vault
              </button>
            )}
            {activeTab === 'My Vaults' && (
              <button type="button" className="primary-button" onClick={() => setActiveTab('Create Vault')}>
                New vault
              </button>
            )}
          </div>
        </header>

        {activeTab === 'Dashboard' && (
          <>
            <section className="metrics-grid" aria-label="Application status">
              <article className="metric-card">
                <p>Vaults created</p>
                <strong>{vaults.length}</strong>
                <span>Encrypted containers</span>
              </article>
              <article className="metric-card">
                <p>Encryption</p>
                <strong>AES-256-GCM</strong>
                <span>Password-derived Argon2id key</span>
              </article>
              <article className="metric-card">
                <p>Storage model</p>
                <strong>Container</strong>
                <span>Add files to vaults anytime</span>
              </article>
            </section>

            <section className="content-grid">
              <article className="panel">
                <div className="panel-header">
                  <div>
                    <p className="eyebrow">Get started</p>
                    <h3>Create your first vault</h3>
                  </div>
                </div>
                <div className="quick-actions">
                  <button type="button" className="quick-action" onClick={() => setActiveTab('Create Vault')}>
                    <strong>Create a vault</strong>
                    <span>Set up an encrypted container for your files.</span>
                  </button>
                  <button type="button" className="quick-action" onClick={() => setActiveTab('My Vaults')}>
                    <strong>View vaults</strong>
                    <span>Access and manage your existing vaults.</span>
                  </button>
                </div>
              </article>
            </section>
          </>
        )}

        {activeTab === 'Create Vault' && (
          <section className="action-panel panel">
            <div className="panel-header">
              <div>
                <p className="eyebrow">Create Vault</p>
                <h3>New encrypted container</h3>
                <p className="section-description">Vaults are encrypted containers where you can store files. Create one and then drag files into it.</p>
              </div>
            </div>

            <div className="action-form">
              <label>
                Vault name
                <input
                  type="text"
                  value={vaultName}
                  onChange={(event) => setVaultName(event.target.value)}
                  placeholder="e.g., Personal Documents"
                  disabled={isCreating}
                />
              </label>

              <label>
                Location
                <div className="input-row">
                  <input
                    type="text"
                    readOnly
                    value={selectedLocation}
                    placeholder="Select where to create the vault"
                  />
                  <button type="button" className="secondary-button compact" onClick={handleSelectLocation} disabled={isCreating}>
                    Browse
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

              <button type="button" className="primary-button full-width" onClick={handleCreateVault} disabled={isCreating}>
                {isCreating ? 'Creating…' : 'Create vault'}
              </button>

              {(isCreating || encryptionProgress !== null) && (
                <div className="encryption-progress" aria-live="polite">
                  <div className="progress-heading">
                    <span>{isCreating ? 'Adding files' : 'Complete'}</span>
                    {encryptionProgress && encryptionProgress.total > 0 && (
                      <span>{encryptionProgress.current} / {encryptionProgress.total}</span>
                    )}
                  </div>
                  <div
                    className="progress-track"
                    role="progressbar"
                    aria-label="Encryption progress"
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
                </div>
              )}

              <p className="status-text" role="status">{statusText}</p>
            </div>
          </section>
        )}

        {activeTab === 'My Vaults' && (
          <section className="panel page-panel">
            <p className="eyebrow">Your vaults</p>
            <h3>Encrypted containers</h3>
            <p className="section-description">
              Click a vault to add files to it. Unlock to view contents temporarily.
            </p>

            {vaults.length === 0 ? (
              <div className="empty-state">
                <strong>No vaults yet</strong>
                <span>Create a vault to get started storing encrypted files.</span>
                <button type="button" className="primary-button" onClick={() => setActiveTab('Create Vault')}>
                  Create your first vault
                </button>
              </div>
            ) : (
              <div style={{ display: 'grid', gap: '1rem' }}>
                {vaults.map((vault) => (
                  <article key={vault.path} className="panel" style={{ padding: '1.5rem', borderLeft: '4px solid var(--color-accent)' }}>
                    <div style={{ marginBottom: '1rem' }}>
                      <strong>{vault.name}</strong>
                      <small style={{ display: 'block', marginTop: '0.25rem', opacity: 0.7 }}>{vault.fileCount} file(s)</small>
                      <small style={{ display: 'block', opacity: 0.6, fontSize: '0.8em', marginTop: '0.5rem', wordBreak: 'break-all' }}>
                        {vault.path}
                      </small>
                    </div>

                    {vault.unlockedPath ? (
                      <div style={{ marginBottom: '1rem', padding: '0.75rem', backgroundColor: 'var(--color-surface-alt)', borderRadius: '0.5rem' }}>
                        <small style={{ display: 'block' }}>
                          <strong>Unlocked at:</strong> {vault.unlockedPath}
                        </small>
                      </div>
                    ) : null}

                    <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                      {!vault.unlockedPath ? (
                        <>
                          <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: 0 }}>
                            <input
                              type="password"
                              value={password}
                              onChange={(event) => setPassword(event.target.value)}
                              placeholder="Password"
                              disabled={isCreating}
                              style={{ width: '150px' }}
                            />
                          </label>
                          <button
                            type="button"
                            className="secondary-button"
                            onClick={() => handleAddFilesToVault(vault)}
                            disabled={isCreating || !password.trim()}
                          >
                            Add files
                          </button>
                          <button
                            type="button"
                            className="secondary-button"
                            onClick={() => handleUnlockVault(vault)}
                            disabled={isCreating || !password.trim()}
                          >
                            Unlock
                          </button>
                        </>
                      ) : (
                        <>
                          <button
                            type="button"
                            className="secondary-button"
                            onClick={() => handleEnableAccess(vault)}
                            disabled={isCreating}
                          >
                            Enable access
                          </button>
                          <button
                            type="button"
                            className="primary-button"
                            onClick={() => handleLockVault(vault)}
                            disabled={isCreating}
                          >
                            Lock vault
                          </button>
                        </>
                      )}
                    </div>
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
                <span><strong>Encryption</strong><small>All vaults use AES-256-GCM with Argon2id key derivation.</small></span>
                <span className="pill neutral">Military-grade</span>
              </div>
            </div>
          </section>
        )}
      </main>
    </div>
  )
}

export default App
