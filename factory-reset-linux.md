# How to factory reset your Linux 

## Why & when 

**Factory resetting your device is the only way to make sure your device isn't infected and will clear any doubts you have.** 
Moreover, it’s recommended to do this step twice a year. 

👍 You know your new device is clean, you test your backups.   
👎 It can take up to 90 minutes. 

**Back up your data!**  

This guide shows how to fully erase a Windows and reinstall the operating system, it doesn’t include the backup steps.

## Steps  

| What to do                                   | Why this is important                                                                 | Linux                                                                                                                                                      |
|----------------------------------------------|----------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Sign out of synced services (Google Drive, Nextcloud, Dropbox, etc.) | Prevents your personal data, credentials, or browsing history from being recovered      | **Google Drive** & more → Log out from all accounts                                                                                                        |
| Securely wipe all personal data from the drive | Ensures the system is in a clean state before selling, recycling, or handing it off.<br>• **HDDs**: Run the `shred` command **once**; it overwrites the disk multiple times automatically.<br>• **SSDs**: Run **both** `hdparm` commands in sequence (set password, then erase). | Open a terminal and run a secure erase command:<br>• HDD: `sudo shred -vzn 3 /dev/sda`<br>• SSD: <br>`sudo hdparm --user-master u --security-set-pass p /dev/sda`<br>`sudo hdparm --user-master u --security-erase p /dev/sda` |
| Reinstall Linux from a clean ISO image        | Reduces risk of leaving malware, misconfigurations, or recoverable data behind          | 1. Download a clean ISO from the official site:<br>• [Ubuntu](https://ubuntu.com/download)<br>• [Fedora](https://getfedora.org/)<br>• [Debian](https://www.debian.org/distrib/)<br><br>2. Create a bootable USB:<br>• [Rufus](https://rufus.ie) (Windows)<br>• `dd` (built into Linux)<br>• [balenaEtcher](https://etcher.balena.io/) (Linux/Mac/Windows)<br><br>3. Boot from USB → select **Erase disk and install** during setup. |
