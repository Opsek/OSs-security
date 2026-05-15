# How to factory reset your macOS (Intel & Silicon)

## Why & when
**Factory resetting your device is the only way to make sure your device isn't infected and will clear any doubts you have.**
Moreover, it's recommended to do this step twice a year.
👍 You know your new device is clean, you test your backups.
👎 It can take up to 90 minutes.

**Back up your data!**
This guide shows how to fully erase a Mac and reinstall macOS, covering both Intel-based and Apple Silicon (ARM) models. The reset steps themselves don't include backup, so work through the data preservation plan below **first**.

For any questions regarding key management, see: https://opsek.github.io/holy-opsek/

---

## Step 0. Close the laptop. Think first.

Take 10 minutes with pen and paper. Answer:

- If this laptop disappeared tonight, what would actually hurt to lose?
- What do I open in the first hour of a normal workday?
- What tools/apps did I configure once and forget about?

That list is your real backup target. Everything else is noise.

## Step 1. Inventory

Note what exists and where. Don't move anything yet.

**Credentials & access**
- [ ] **Password manager**: confirm everything you need is actually in it. Do **not** rely on browser-saved passwords, and do **not** export your vault to a file.
- [ ] **2FA / MFA**: YubiKey only. 2FA should not live on the laptop you're wiping, including inside your password manager. If any account is still on a TOTP app or SMS, switch it to YubiKey before wiping. Confirm multiple YubiKeys are registered for backup on every account that supports it.
- [ ] **Backup codes / recovery codes**: collect them for every account that issued any. These go on an encrypted drive. **Never** store them in your password manager.
- [ ] **SSH keys**: `~/.ssh/` (`id_*`, `config`, `known_hosts`)
- [ ] **GPG / PGP keys**: `~/.gnupg/`
- [ ] **API tokens & CLI creds**: `~/.aws/`, `~/.config/gh/`, `~/.netrc`, `~/.docker/config.json`, kubeconfig, project `.env` files
- [ ] **VPN configs / certificates**: `.ovpn`, `.mobileconfig`, work VPN profiles
- [ ] **Browser**: export bookmarks; note extensions

For any questions on handling keys, see: https://opsek.github.io/holy-opsek/

**Files**
- [ ] `~/Documents`, `~/Desktop`, `~/Downloads`, `~/Pictures`, `~/Movies`
- [ ] **Code repos**: for each, pushed to remote? Clean working tree? Untracked files that matter?
- [ ] **Cloud sync folders**: confirm they're actually synced *up*, not just present locally
- [ ] **App-specific data**: Notes, Obsidian vaults, Signal desktop, IDE workspaces

**Configuration (saves you the painful week after)**
- [ ] **Dotfiles**: `~/.zshrc`, `~/.bashrc`, `~/.gitconfig`, `~/.vimrc`, `~/.config/`
- [ ] **App list**: `brew list`, `brew list --cask`, screenshot Applications folder
- [ ] **Editor settings**: enable Settings Sync (VS Code, JetBrains)
- [ ] **System preferences**: screenshot keyboard shortcuts, dock, input sources

## Step 2. Sort into three buckets

**Bucket A. Cloud-safe (Proton Drive / Google Drive):** personal docs, photos, notes, bookmarks, app lists, settings screenshots.

**Bucket B. Encrypted backup only, NEVER in plain cloud:** SSH/GPG keys, API tokens, `.env` files, VPN certs, backup/recovery codes, anything with credentials or client data.

Use one of:
- Encrypted disk image (macOS Disk Utility, encrypted `.dmg`)
- Hardware-encrypted USB drive
- If it absolutely must go to cloud, encrypt locally first (`age`, `gpg`, password-protected 7z) so the cloud sees only ciphertext

**Bucket C. Don't keep:** Downloads junk, installers, caches, `node_modules`, build artifacts. If you can't say in one sentence why you'd open it again, it's Bucket C.

## Step 3. Verify before you wipe

- [ ] Open your backup on a **different device** and confirm files are readable
- [ ] Log into your password manager from another device
- [ ] Confirm YubiKey 2FA works on another device (your 2FA shouldn't be tied to the laptop you're wiping, and shouldn't live in your password manager either)
- [ ] Confirm backup/recovery codes are stored on your encrypted drive and readable
- [ ] `git status` clean in every repo, everything pushed
- [ ] Sign out of device-limited services: iMessage, iCloud, Adobe, JetBrains, Apple Music, etc.

## Step 4. After the wipe: restore deliberately

Do **not** restore from a full disk image. It defeats the purpose.

1. Fresh OS install, apply hardening from your 1:1 session
2. Install password manager, enroll YubiKey
3. Install apps **as you need them**, not all at once. If you don't miss it in a month, you didn't need it
4. Pull Bucket A files on demand
5. Restore Bucket B only where required, with correct permissions (`chmod 600` for SSH keys)

## Summary

1. Close the laptop. Write down what would hurt to lose.
2. Password manager working from another device, multiple YubiKeys registered for backup.
3. SSH/GPG keys, API tokens, `.env`, backup/recovery codes go to an encrypted drive. **Never** plain cloud, **never** in your password manager.
4. All git repos pushed, working trees clean.
5. Personal files to Proton Drive or Google Drive. Credentials never in plain cloud.
6. Screenshot app list and settings.
7. Sign out of license-limited services before wiping.

Questions on key management: https://opsek.github.io/holy-opsek/

---

# Factory reset

## Steps

| What to do                         | Why this is important                                                                 | Intel Macs (2012 to 2020)                                                                 | Apple Silicon Macs (M1, M2, etc.)                                                                 |
|------------------------------------|----------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------|
| Sign out of iCloud                 | Disconnects the device from your Apple ID to prevent activation lock                  | System Preferences > Apple ID > Overview > Sign out                                      | System Settings > Apple ID > Sign out                                                             |
| Reset NVRAM                        | Resets system settings like screen resolution and security configurations             | Restart and hold `command + option + P + R` for 10 to 20 seconds                         | Not needed, handled automatically by the system                                                   |
| Enter recovery mode                | Access recovery tools to erase the disk and reinstall macOS                           | Restart and hold `command + R` until Apple logo appears                                  | Shut down, then hold the power button until "loading startup options" appears, then click Options > Continue |
| Erase the hard drive               | Deletes your files and system from internal storage                                   | In recovery: Utilities > Disk Utility > Select "Macintosh HD" > Erase volume group or Erase | Same steps using Disk Utility                                                                     |
| Delete other internal volumes      | Cleans up extra partitions or volumes left by system or apps                          | Select extra internal volumes in Disk Utility and click the minus button                 | Same process                                                                                       |
| Reinstall macOS                    | Installs a fresh copy of macOS, ready for new user                                    | In recovery: Choose Reinstall macOS and follow on-screen instructions                    | Same process                                                                                       |
| Wait for install to complete       | Final step; once done, the Mac will be ready for setup                                | Takes 30 to 90 minutes depending on internet and Mac speed                               | Same duration and setup                                                                           |
