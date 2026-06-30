# Restore coverage matrix

Every hardening function in `config/profiles.conf` (recommended + paranoid),
how it is reverted by a snapshot, and how that revert is proven.

Two revert mechanisms exist:

- **file** — `backup_file` / `user_backup_file` saves the pre-Apply file; the
  generated rollback `cp`s it back (per-user files are `chown`ed to the owner).
- **journal** — `snapshot_system_state` records the inverse command in
  `revert_state.sh` before Apply; the rollback replays it. Used for live toggles
  and for configd/daemon-owned plists a raw `cp` cannot restore.

A third class is **irreversible by design**: undoing it would weaken the Mac or
cannot be done safely. These are intentionally not reverted AND are not read by
any scored audit check, so a post-restore re-check can still reach baseline.

The round-trip harness (`tests/roundtrip_test.sh`) executes the REAL capture and
the REAL rollback against stubbed system commands and asserts every toggle
returns to its pre-Apply value. Update this table AND the harness when adding a
control.

## Recommended profile

| Function | Mechanism | Notes |
|---|---|---|
| update_system | file | SoftwareUpdate.plist |
| disable_remote_apple_events | journal | launchctl AEServer (FDA-independent); absent on most Macs |
| disable_internet_sharing | journal | nat (SystemConfiguration) via defaults |
| disable_printer_sharing | journal | cupsctl + cupsd reload |
| enable_firewall | journal | socketfilterfw global/stealth (was the main stuck control) |
| enable_gatekeeper | journal | spctl |
| configure_screensaver | file | per-user screensaver/loginwindow |
| disable_automatic_login | file | loginwindow autoLoginUser |
| require_password_wake | n/a | detect-only on macOS 13+, changes nothing |
| disable_guest_account | file (+ irreversible part) | GuestEnabled reverts via plist; `sysadminctl -guestAccount off` account-level not reverted, not scored |
| show_filename_extensions | file | per-user .GlobalPreferences |
| disable_safari_safe_files | file | per-user Safari.plist |
| enable_filevault | n/a | requires user interaction; rarely activates from script |
| enable_security_auditing | file | audit_control; rollback reloads auditd |
| configure_time_sync | n/a | not journaled (not scored, systemsetup needs FDA) |
| disable_bonjour | file | mDNSResponder.plist |
| secure_home_folders | **irreversible** | chmod 700 homes; not scored |
| configure_password_policy | journal-equivalent | rollback clears account policies |
| configure_keychain_lock | soft | per-user keychain timeout; not scored, not reverted |
| enable_certificate_checking | file | per-user revocation.plist |
| disable_root_account | **irreversible** | root stays disabled; not scored |
| configure_hibernate_mode | journal | pmset |
| set_login_message | file | loginwindow LoginwindowText |
| disable_password_hints | file | loginwindow RetriesUntilHint |
| disable_guest_shared_folders | journal | AppleFileServer + smb.server guest via defaults |
| disable_siri_dictation | file | per-user assistant/Siri/speech plists |
| disable_diagnostics | file | CrashReporter DiagnosticMessagesHistory |
| secure_safari | file | per-user Safari.plist |

## Paranoid profile (additional)

| Function | Mechanism | Notes |
|---|---|---|
| disable_screen_sharing | journal | launchd screensharing |
| disable_file_sharing | journal | launchd AppleFileServer + smbd |
| disable_remote_management | journal | ARDAgent kickstart -activate (if was running) |
| enable_firewall_block_all | journal | socketfilterfw blockall |
| disable_wake_on_lan | journal | pmset womp |
| configure_audit_flags / retention | file | audit_control |
| disable_airdrop | file | per-user sharingd / NetworkBrowser |
| disable_http_server / disable_nfs_server | journal | launchd httpd / nfsd |
| check_application_permissions | **irreversible** | chmod o-w /Applications; not scored |
| fix_system_permissions / fix_library_permissions | **irreversible** | chmod o-w; not scored |
| configure_sudo_timeout | file | sudoers + rollback removes sudoers.d/timeout |
| configure_keychain_sleep_lock / secure_keychains | soft | per-user keychain; not scored |
| require_admin_system_prefs | journal | authorizationdb system.preferences shared (best-effort) |
| disable_fast_user_switching | journal | system .GlobalPreferences MultipleSessionEnabled |
| configure_login_window_style | file | loginwindow SHOWFULLNAME |
| remove_guest_home | **irreversible** | /Users/Guest not recreated; not scored |
| disable_location_services | journal | locationd via defaults |
| disable_spotlight_suggestions | file | per-user spotlight.plist |
| disable_unnecessary_daemons | journal | netbiosd, dhcp6d, alf.useragent, AppleShareClientCore |
| configure_privacy_settings | file + journal | diagnostics/AdLib/Handoff file; AirPlay controlcenter ByHost file (scored) |
| enhance_logging | file | installer.plist + audit_control |
| disable_ipv6_on_interfaces | journal | networksetup setv6automatic |
| disable_bluetooth_completely | file + journal | Bluetooth plists (power) + blued reload + nvram |
| disable_all_bluetooth_services | journal | reloads bluetooth helper daemons/agents (kext reload needs restart) |
| secure_keyboard_settings | file | per-user .GlobalPreferences + universalaccess |
| disable_wifi | file + journal | airport power (journal) + association flags (journal) + menu (file) |
| harden_kernel | journal | nvram boot-args + pmset |

## Known soft cases (effect may need a restart/relogin)

Daemon-cached domains (sharingd, controlcenter, locationd, useractivityd) are
restored to the pre-Apply value, but the running daemon may only pick up the
change after its next launch or a restart. The stored value is correct; the
live effect can lag. The rollback restarts cfprefsd/SystemUIServer/Finder.
