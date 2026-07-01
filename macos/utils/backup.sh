#!/usr/bin/env bash

# ==============================================================================
# Backup system for macOS hardening script
# ==============================================================================

# ------------------------------------------------------------------------------
# Revert journal
#
# Hardening applies two kinds of change: file edits (handled by backup_file and
# restored by the rollback script) and live system toggles (socketfilterfw,
# spctl, systemsetup, launchctl, pmset, nvram, networksetup) that no file
# captures. The revert journal records, before any toggle is changed, the
# command that puts each toggle back to its pre-Apply value. The rollback runs
# the journal so Restore actually undoes the hardening, not just the files.
#
# DISCIPLINE: when you add a toggle-based hardening function, add its capture to
# snapshot_system_state below (mirrors the "define function AND add to profile"
# rule). Settings backed by a plist do not belong here; give them a backup_file
# call in their function instead.
# ------------------------------------------------------------------------------

# Create the journal file inside the snapshot dir. No-op under dry-run.
init_revert_journal() {
    [[ "$DRY_RUN" == true ]] && return 0
    [[ -z "${REVERT_JOURNAL:-}" ]] && return 0
    {
        printf '# OPSEK revert journal generated %s\n' "${TIMESTAMP:-unknown}"
        printf '# One restore command per line; executed by the rollback script.\n'
    } > "$REVERT_JOURNAL" 2>/dev/null || true
    chmod 600 "$REVERT_JOURNAL" 2>/dev/null || true
}

# Append one restore command to the journal. The command is eval'd verbatim by
# the rollback (as root), so it must already be fully expanded. No-op under
# dry-run or before the journal exists.
record_revert() {
    local cmd="$1"
    [[ "$DRY_RUN" == true ]] && return 0
    [[ -z "${REVERT_JOURNAL:-}" ]] && return 0
    printf '%s\n' "$cmd" >> "$REVERT_JOURNAL" 2>/dev/null || true
}

# If a launchd job is currently loaded, record the command that loads it again,
# so a later `launchctl unload -w` during hardening can be reversed.
_record_launchd_revert() {
    local label="$1" plist="$2"
    if launchctl list 2>/dev/null | grep -q "$label"; then
        record_revert "launchctl load -w '$plist'"
    fi
}

# Journal the inverse of a `defaults write <domain> <key>`: restore the prior
# value, or delete the key if it was absent before Apply. FDA-independent and
# configd-safe (it replays through defaults, not a raw cp), so it is the right
# tool for configd-owned SystemConfiguration plists and for keys that did not
# exist before hardening. <domain> may be a bare domain or a full plist path.
_record_defaults_revert() {
    local domain="$1" key="$2" type="${3:-}"
    local cur
    cur="$(defaults read "$domain" "$key" 2>/dev/null || true)"
    if [[ -n "$cur" ]]; then
        # `defaults read` returns 0/1 for booleans, but `defaults write -bool`
        # only accepts true|false|yes|no (a bare 0/1 errors out). Translate.
        if [[ "$type" == "bool" ]]; then
            case "$cur" in
                1|true|TRUE|yes|YES) cur=true ;;
                0|false|FALSE|no|NO) cur=false ;;
            esac
        fi
        if [[ -n "$type" ]]; then
            record_revert "defaults write $domain '$key' -$type '$cur'"
        else
            record_revert "defaults write $domain '$key' '$cur'"
        fi
    else
        record_revert "defaults delete $domain '$key' 2>/dev/null || true"
    fi
}

# Capture the pre-Apply state of every live toggle the profiles change, recording
# the inverse into the journal. Reads run as root (Apply context); each read is
# guarded so a missing tool or `set -e` never aborts the run. Captures common to
# both profiles always run; paranoid-only toggles are gated on the profile so the
# recommended snapshot does not list reverts for things it never touched.
snapshot_system_state() {
    local profile="${1:-recommended}"

    [[ "$DRY_RUN" == true ]] && return 0
    [[ -z "${REVERT_JOURNAL:-}" ]] && return 0

    debug "Capturing system state for revert journal (profile: $profile)"

    # --- Common to recommended and paranoid -----------------------------------

    # Gatekeeper (enable_gatekeeper). Faithful: re-disable if it was off.
    if spctl --status 2>/dev/null | grep -q "assessments enabled"; then
        record_revert "spctl --master-enable"
    else
        record_revert "spctl --master-disable"
    fi

    # Application firewall (enable_firewall, enable_firewall_block_all). Captured
    # to a DEDICATED file, NOT the journal, because the rollback must apply the
    # firewall LAST, after cfprefsd and the firewall daemon have restarted.
    # com.apple.alf.plist is owned by com.apple.alf.agent; restoring it by cp and
    # then killing cfprefsd makes the daemon re-sync and overwrite an earlier
    # toggle, which is why a journal-time `setglobalstate off` ran yet did not
    # stick. Applying the firewall once at the very end avoids that race.
    # OPSEK_SOCKETFILTERFW lets the round-trip harness point this at a function
    # stub; command -v matches both an absolute path and a function name.
    local fw="${OPSEK_SOCKETFILTERFW:-/usr/libexec/ApplicationFirewall/socketfilterfw}"
    local fw_target="$(dirname "$REVERT_JOURNAL")/firewall_restore.sh"
    if command -v "$fw" >/dev/null 2>&1; then
        local fw_global fw_stealth fw_block g s b
        fw_global="$("$fw" --getglobalstate 2>/dev/null || true)"
        fw_stealth="$("$fw" --getstealthmode 2>/dev/null || true)"
        fw_block="$("$fw" --getblockall 2>/dev/null || true)"
        # "(State = 0)" is the only off state; 1 and 2 are both on. "disabled"
        # never contains the substring "enabled", so -i is safe for the others.
        echo "$fw_global"  | grep -q  "State = 0" && g=off || g=on
        echo "$fw_stealth" | grep -qi "enabled"   && s=on  || s=off
        echo "$fw_block"   | grep -qi "enabled"   && b=on  || b=off
        # Global state last: if it ends up off, stealth/blockall are moot anyway.
        {
            printf "'%s' --setstealthmode %s\n" "$fw" "$s"
            printf "'%s' --setblockall %s\n"    "$fw" "$b"
            printf "'%s' --setglobalstate %s\n" "$fw" "$g"
        } > "$fw_target" 2>/dev/null || true
        chmod 600 "$fw_target" 2>/dev/null || true
    fi

    # Remote Apple Events (disable_remote_apple_events). systemsetup
    # -setremoteappleevents needs Full Disk Access (it warns under the GUI's
    # root-without-FDA context) and the feature is absent on most modern Macs.
    # Revert through the launchd job instead, which is FDA-independent: only
    # record a revert when the AEServer job actually exists and is currently
    # loaded (RAE on), so a Mac without RAE journals nothing to fail.
    if launchctl print system/com.apple.AEServer >/dev/null 2>&1; then
        record_revert "launchctl enable system/com.apple.AEServer"
    fi

    # Network time (configure_time_sync) is intentionally NOT journaled: no audit
    # check reads it, and systemsetup -setusingnetworktime needs Full Disk Access
    # so it only ever produced a guaranteed-to-fail revert line.

    # Internet Sharing NAT (disable_internet_sharing). A SystemConfiguration
    # plist owned by configd, so it is reverted via defaults (the restore loop
    # skips that directory). Read the nested NAT dict and journal the inverse.
    local nat_enabled
    nat_enabled="$(defaults read /Library/Preferences/SystemConfiguration/com.apple.nat NAT 2>/dev/null | grep -oE 'Enabled = [0-9]' | grep -oE '[0-9]' || true)"
    if [[ "$nat_enabled" == "1" ]]; then
        record_revert "defaults write /Library/Preferences/SystemConfiguration/com.apple.nat NAT -dict Enabled -int 1"
    elif [[ "$nat_enabled" == "0" ]]; then
        record_revert "defaults write /Library/Preferences/SystemConfiguration/com.apple.nat NAT -dict Enabled -int 0"
    fi

    # Guest access to shared folders (disable_guest_shared_folders). Only the SMB
    # plist lives under SystemConfiguration (configd-owned, skipped by the cp
    # loop) so it needs the journal. AppleFileServer.plist is a normal
    # /Library/Preferences file and is restored by the cp loop, so journaling it
    # too would be redundant (and was the source of a spurious revert warning).
    _record_defaults_revert "/Library/Preferences/SystemConfiguration/com.apple.smb.server" "AllowGuestAccess" "bool"

    # Printer sharing (disable_printer_sharing).
    if cupsctl 2>/dev/null | grep -q "_share_printers=1"; then
        record_revert "cupsctl --share-printers"
        record_revert "launchctl load -w '/System/Library/LaunchDaemons/org.cups.cupsd.plist'"
    fi

    # Wake-on-LAN + hibernate (disable_wake_on_lan, configure_hibernate_mode,
    # harden_kernel). Capture the currently active pmset values.
    local pm key
    for key in womp hibernatemode standby standbydelay DestroyFVKeyOnStandby; do
        pm="$(pmset -g 2>/dev/null | awk -v k="$key" '$1==k{print $2; exit}' || true)"
        if [[ -n "$pm" ]]; then
            case "$key" in
                DestroyFVKeyOnStandby) record_revert "pmset -a destroyfvkeyonstandby $pm" ;;
                *) record_revert "pmset -a $key $pm" ;;
            esac
        fi
    done

    # --- Aggressive toggles (paranoid, and custom per-module runs) ------------
    # Anything that is not the recommended profile may touch these, so capture
    # the full set. Recording a revert for a toggle that was not actually changed
    # is safe: on Restore it is set back to the value it already has (a no-op).
    if [[ "$profile" != "recommended" ]]; then
        # Sharing / remote-access daemons (disable_screen_sharing,
        # disable_file_sharing, disable_http_server, disable_nfs_server,
        # disable_unnecessary_daemons).
        _record_launchd_revert "com.apple.screensharing" "/System/Library/LaunchDaemons/com.apple.screensharing.plist"
        _record_launchd_revert "com.apple.AppleFileServer" "/System/Library/LaunchDaemons/com.apple.AppleFileServer.plist"
        _record_launchd_revert "com.apple.smbd" "/System/Library/LaunchDaemons/com.apple.smbd.plist"
        _record_launchd_revert "org.apache.httpd" "/System/Library/LaunchDaemons/org.apache.httpd.plist"
        _record_launchd_revert "com.apple.nfsd" "/System/Library/LaunchDaemons/com.apple.nfsd.plist"
        _record_launchd_revert "com.apple.netbiosd" "/System/Library/LaunchDaemons/com.apple.netbiosd.plist"
        _record_launchd_revert "com.apple.AppleShareClientCore" "/System/Library/LaunchDaemons/com.apple.AppleShareClientCore.plist"
        # Remaining daemons from disable_unnecessary_daemons not covered above.
        _record_launchd_revert "com.apple.dhcp6d" "/System/Library/LaunchDaemons/com.apple.dhcp6d.plist"
        _record_launchd_revert "com.apple.alf.useragent" "/System/Library/LaunchDaemons/com.apple.alf.useragent.plist"

        # Bluetooth service daemons/agents (disable_all_bluetooth_services). Power
        # state itself reverts via the Bluetooth plists; these reload the helper
        # services that were unloaded. Best effort: only if currently loaded.
        local bt_svc
        for bt_svc in com.apple.bluetoothReporter com.apple.bluetoothaudiod com.apple.BluetoothReporter com.apple.bluetooth.cupsd; do
            _record_launchd_revert "$bt_svc" "/System/Library/LaunchDaemons/$bt_svc.plist"
            _record_launchd_revert "$bt_svc" "/System/Library/LaunchAgents/$bt_svc.plist"
        done

        # Wi-Fi association flags (disable_wifi). SystemConfiguration plist owned
        # by configd: revert via defaults, restored as the live Wi-Fi power is.
        _record_defaults_revert "/Library/Preferences/SystemConfiguration/com.apple.airport.preferences" "DisableAssociation" "bool"
        _record_defaults_revert "/Library/Preferences/SystemConfiguration/com.apple.airport.preferences" "AllowEnable" "bool"

        # Location services (disable_location_services). Owned by the locationd
        # daemon; journal the inverse so the revert does not depend on a raw cp.
        _record_defaults_revert "/var/db/locationd/Library/Preferences/ByHost/com.apple.locationd" "LocationServicesEnabled" "bool"

        # Fast user switching (disable_fast_user_switching) writes the SYSTEM
        # .GlobalPreferences, which no backup_file captures (the function backs up
        # loginwindow.plist by mistake). Journal the inverse here.
        _record_defaults_revert "/Library/Preferences/.GlobalPreferences" "MultipleSessionEnabled" "bool"

        # Admin password for system-wide preferences (require_admin_system_prefs)
        # flips the system.preferences authorization right's "shared" flag. It is
        # not file-backed; capture the current value and journal a best-effort
        # restore through authorizationdb.
        local sp_shared
        sp_shared="$(security authorizationdb read system.preferences 2>/dev/null | plutil -extract shared raw - 2>/dev/null || true)"
        if [[ "$sp_shared" == "true" || "$sp_shared" == "false" ]]; then
            record_revert "__opsek_tmp=\$(mktemp) && security authorizationdb read system.preferences > \"\$__opsek_tmp\" 2>/dev/null && defaults write \"\$__opsek_tmp\" shared -bool $sp_shared && security authorizationdb write system.preferences < \"\$__opsek_tmp\"; rm -f \"\$__opsek_tmp\""
        fi

        # Remote Management / ARD (disable_remote_management). Best effort: only
        # if the agent is currently running.
        if pgrep -x ARDAgent >/dev/null 2>&1; then
            record_revert "/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -access -on -restart -agent"
        fi

        # Wi-Fi power per interface (disable_wifi). Only if currently on.
        local wifi_ifaces iface pw
        wifi_ifaces="$(networksetup -listallhardwareports 2>/dev/null | awk '/Wi-Fi|AirPort/{getline; print $2}' || true)"
        for iface in $wifi_ifaces; do
            [[ -z "$iface" ]] && continue
            pw="$(networksetup -getairportpower "$iface" 2>/dev/null || true)"
            echo "$pw" | grep -qi "): On" && record_revert "networksetup -setairportpower '$iface' on"
        done

        # IPv6 per network service (disable_ipv6_on_interfaces). Record a revert
        # only where IPv6 is currently automatic (the common case we change).
        local services svc
        services="$(networksetup -listallnetworkservices 2>/dev/null | tail -n +2 || true)"
        while IFS= read -r svc; do
            [[ -z "$svc" || "$svc" == *"*"* ]] && continue
            if networksetup -getinfo "$svc" 2>/dev/null | grep -qi "IPv6: Automatic"; then
                record_revert "networksetup -setv6automatic '$svc'"
            fi
        done <<< "$services"

        # Bluetooth runtime (disable_bluetooth_completely,
        # disable_all_bluetooth_services). The plist (ControllerPowerState) is
        # file-backed; here we revert the nvram override and reload blued.
        local bt_nvram
        bt_nvram="$(nvram bluetoothHostControllerSwitchBehavior 2>/dev/null | awk '{print $2}' || true)"
        if [[ -n "$bt_nvram" ]]; then
            record_revert "nvram bluetoothHostControllerSwitchBehavior='$bt_nvram'"
        else
            record_revert "nvram -d bluetoothHostControllerSwitchBehavior"
        fi
        record_revert "launchctl load -w '/System/Library/LaunchDaemons/com.apple.blued.plist'"

        # Kernel boot-args (harden_kernel). Restore the prior value, or remove
        # the variable if none was set.
        local bootargs
        bootargs="$(nvram boot-args 2>/dev/null | sed -e 's/^boot-args[[:space:]]*//' || true)"
        if [[ -n "$bootargs" ]]; then
            record_revert "nvram boot-args='$bootargs'"
        else
            record_revert "nvram -d boot-args"
        fi
    fi

    debug "Revert journal capture complete"
    # Always succeed: this runs as a standalone statement inside apply_profile
    # under `set -e`, and the captures above are all best-effort.
    return 0
}

# Generate rollback script
generate_rollback_script() {
    local backup_dir="$1"
    local timestamp="$2"
    
    if [[ -z "$backup_dir" || -z "$timestamp" ]]; then
        error "Backup directory and timestamp are required"
        return 1
    fi
    
    local rollback_script="$backup_dir/rollback_hardening_$timestamp.sh"
    
    cat > "$rollback_script" <<'ROLL'
#!/usr/bin/env bash
# Rollback script generated by mac_hardening
set -euo pipefail

BACKUP_DIR="$(dirname "${BASH_SOURCE[0]}")"

echo "Starting rollback from $BACKUP_DIR"

# Restore every backed-up file to its original absolute path. backup_file stored
# each file mirroring its full path under the snapshot dir, so stripping that
# prefix recovers the destination. This handles per-user files (under
# /Users/<name>/...) and system files alike. /etc/sudoers is left to the
# validated block below; the rollback script, the revert journal and the .meta
# sidecar are bookkeeping, not system files, so they are skipped.
restore_failures=0
# Read from a process substitution, not a pipe, so the loop runs in this shell
# and restore_failures survives (a `find | while` body runs in a subshell).
while IFS= read -r -d '' src; do
    dest="${src#"$BACKUP_DIR"}"
    if [[ "$dest" == "$src" || "$dest" != /* || "$dest" == "/etc/sudoers" ]]; then
        continue
    fi
    # Daemon-owned plists must not be cp'd back: configd (SystemConfiguration)
    # rejects the write, and com.apple.alf.plist (the firewall) gets re-synced
    # and overwritten by its daemon, clobbering the firewall toggle. These are
    # reverted through the journal / dedicated firewall pass instead.
    case "$dest" in
        /Library/Preferences/SystemConfiguration/*) continue ;;
        /Library/Preferences/com.apple.alf.plist) continue ;;
    esac
    mkdir -p "$(dirname "$dest")" 2>/dev/null || true
    if cp -p "$src" "$dest" 2>/dev/null; then
        # Give per-user files back to their owner: cp as root would otherwise
        # leave the account unable to manage its own preferences.
        case "$dest" in
            /Users/*/*)
                owner="$(echo "$dest" | cut -d/ -f3)"
                if [[ -n "$owner" && "$owner" != "Shared" ]]; then
                    chown "$owner" "$dest" 2>/dev/null || true
                fi
                ;;
        esac
        echo "Restored $dest"
    else
        echo "Failed to restore $dest"
        restore_failures=$((restore_failures + 1))
    fi
done < <(find "$BACKUP_DIR" -type f \
    ! -name 'rollback_hardening_*.sh' \
    ! -name 'revert_state.sh' \
    ! -name 'firewall_restore.sh' \
    ! -name '*.meta' \
    -print0)

if [[ -f "$BACKUP_DIR/etc/sudoers" ]]; then
    echo "Validating sudoers file before restore"

    if visudo -c -f "$BACKUP_DIR/etc/sudoers"; then
        echo "Sudoers file valid, restoring"
        cp "$BACKUP_DIR/etc/sudoers" "/etc/sudoers"
        chmod 0440 /etc/sudoers
    else
        echo "ERROR: Backup sudoers file is invalid, restore aborted"
    fi
fi

# Remove timeout sudoers file if it exists
rm -f /etc/sudoers.d/timeout 2>/dev/null || true

# Clear any password policy applied by the hardening (configure_password_policy).
# Safe no-op when none was set. Prevents a restored system from keeping content
# rules the user no longer wants.
pwpolicy -clearaccountpolicies 2>/dev/null || true
pwpolicy -n /Local/Default -setglobalpolicy "" 2>/dev/null || true

# Replay the revert journal: re-apply each captured toggle to its pre-Apply
# value. Best effort; some reverts (a service that was not present, an nvram
# variable that was already unset) can warn without being a real failure.
reverted=0
revert_warnings=0
if [[ -f "$BACKUP_DIR/revert_state.sh" ]]; then
    echo "Reverting system toggles from the revert journal"
    while IFS= read -r line; do
        case "$line" in
            ''|\#*) continue ;;
        esac
        if eval "$line" >/dev/null 2>&1; then
            reverted=$((reverted + 1))
        else
            revert_warnings=$((revert_warnings + 1))
            echo "  warning: could not apply revert: $line"
        fi
    done < "$BACKUP_DIR/revert_state.sh"
fi

# Restart affected services
launchctl unload /System/Library/LaunchDaemons/com.apple.auditd.plist 2>/dev/null || true
launchctl load /System/Library/LaunchDaemons/com.apple.auditd.plist 2>/dev/null || true

# Reload the preferences daemon so restored per-user plists take effect without
# a logout (cfprefsd caches preferences in memory).
killall cfprefsd 2>/dev/null || true
killall SystemUIServer 2>/dev/null || true
killall Finder 2>/dev/null || true

# Re-apply the firewall LAST, once the daemons above have settled. Done earlier,
# restoring com.apple.alf.plist and killing cfprefsd makes the firewall daemon
# re-sync and overwrite the toggle, so the firewall is applied here at the very
# end (and the alf.plist file is deliberately not restored, see the cp loop).
if [[ -f "$BACKUP_DIR/firewall_restore.sh" ]]; then
    echo "Re-applying firewall state (final pass)"
    while IFS= read -r fwline; do
        case "$fwline" in ''|\#*) continue ;; esac
        eval "$fwline" >/dev/null 2>&1 || true
    done < "$BACKUP_DIR/firewall_restore.sh"
fi

echo ""
echo "Rollback summary:"
echo "  Files restored from snapshot (failures: $restore_failures)."
echo "  System toggles reverted: $reverted (warnings: $revert_warnings)."
echo "Some settings take full effect only after a restart."
echo "Note: a few steps are intentionally not reverted because undoing them would"
echo "weaken the Mac or cannot be undone safely. The root account stays disabled,"
echo "tightened file permissions are left in place, and a removed Guest home is not"
echo "recreated."
# File restores are the hard guarantee, so they decide OK vs PARTIAL. Toggle
# revert warnings are best-effort (a service that was not loaded, an nvram
# variable already unset) and are reported above without failing the restore.
if [[ "$restore_failures" -eq 0 ]]; then
    echo "OPSEK_ROLLBACK_OK"
else
    echo "OPSEK_ROLLBACK_PARTIAL restore_failures=$restore_failures"
fi
ROLL
    
    chmod +x "$rollback_script"
    info "Rollback helper saved: $rollback_script"
}

# Write a world-readable <backup_dir>.meta sidecar so the non-root GUI can show
# the file count, size and rollback name without descending into the 700
# snapshot dir. Format: fileCount|sizeBytes|rollbackScriptName
write_snapshot_metadata() {
    local backup_dir="$1"
    local timestamp="$2"

    if [[ -z "$backup_dir" || -z "$timestamp" ]]; then
        return 0
    fi
    if [[ "$DRY_RUN" == true ]]; then
        return 0
    fi
    [[ -d "$backup_dir" ]] || return 0

    # `|| true` so a non-zero find/du under pipefail does not trip set -e.
    # The displayed count is "restorable changes": backed-up config files (not the
    # rollback helper or the journal itself) plus the number of toggle reverts
    # captured in the journal. This keeps the count meaningful and never shows 0
    # for a real Apply that only changed system toggles.
    local file_count revert_count change_count size_kb size_bytes meta_file
    file_count="$(find "$backup_dir" -type f ! -name 'rollback_hardening_*.sh' ! -name 'revert_state.sh' 2>/dev/null | wc -l | tr -d ' ' || true)"
    revert_count=0
    if [[ -f "$backup_dir/revert_state.sh" ]]; then
        revert_count="$(grep -cvE '^[[:space:]]*(#|$)' "$backup_dir/revert_state.sh" 2>/dev/null | tr -d ' ' || true)"
    fi
    change_count=$(( ${file_count:-0} + ${revert_count:-0} ))
    size_kb="$(du -sk "$backup_dir" 2>/dev/null | awk '{print $1}' || true)"
    size_bytes=$(( ${size_kb:-0} * 1024 ))
    meta_file="${backup_dir}.meta"

    printf '%s|%s|%s\n' "${change_count:-0}" "${size_bytes:-0}" "rollback_hardening_${timestamp}.sh" \
        > "$meta_file" 2>/dev/null || true
    chmod 644 "$meta_file" 2>/dev/null || true
    debug "Snapshot metadata written: $meta_file"
}

# Create backup of a file
backup_file_to_dir() {
    local file="$1"
    local backup_dir="$2"
    
    if [[ ! -f "$file" ]]; then
        debug "File does not exist, skipping backup: $file"
        return 0
    fi
    
    if [[ "$DRY_RUN" == true ]]; then
        debug "[DRY-RUN] Would backup: $file"
        return 0
    fi
    
    local backup_path="$backup_dir$(dirname "$file")"
    execute "mkdir -p '$backup_path'"
    execute "cp -p '$file' '$backup_path/'"
    debug "Backed up to dir: $file"
}

# Clean up old backups
cleanup_old_backups_in_dir() {
    local backup_root="$1"
    local retention_days="$2"
    
    if [[ -d "$backup_root" ]]; then
        find "$backup_root" -type d -name "backup_*" -mtime +$retention_days -exec rm -rf {} \; 2>/dev/null || true
        # Remove the matching .meta sidecars too.
        find "$backup_root" -type f -name "backup_*.meta" -mtime +$retention_days -exec rm -f {} \; 2>/dev/null || true
        info "Old backups cleaned up in $backup_root (older than $retention_days days)"
    fi
}

# Check available disk space
check_disk_space() {
    local backup_dir="$1"
    local required_space_mb="$2"
    
    if [[ -d "$backup_dir" ]]; then
        local available_space=$(df "$backup_dir" | awk 'NR==2 {print $4}')
        local available_mb=$((available_space / 1024))
        
        if [[ $available_mb -lt $required_space_mb ]]; then
            warn "Insufficient disk space: $available_mb MB available, $required_space_mb MB required"
            return 1
        fi
    fi
    
    return 0
}

# Create compressed archive of backup
compress_backup() {
    local backup_dir="$1"
    local archive_name="$2"
    
    if [[ "$BACKUP_COMPRESSION" == true ]]; then
        local archive_path="$backup_dir/../$archive_name.tar.gz"
        execute "tar -czf '$archive_path' -C '$backup_dir' ."
        info "Backup compressed: $archive_path"
    fi
}

# Restore from backup
restore_from_backup() {
    local backup_dir="$1"
    local file="$2"
    
    if [[ -f "$backup_dir$file" ]]; then
        execute "cp -p '$backup_dir$file' '$file'"
        success "Restored: $file"
        return 0
    else
        warn "Backup not found: $backup_dir$file"
        return 1
    fi
}

# List available backups
list_backups() {
    local backup_root="$1"
    
    if [[ -d "$backup_root" ]]; then
        echo "Available backups:"
        find "$backup_root" -type d -name "backup_*" | sort -r | head -10
    else
        warn "No backup directory found: $backup_root"
    fi
}

# Verify backup integrity
verify_backup() {
    local backup_dir="$1"
    
    if [[ ! -d "$backup_dir" ]]; then
        error "Backup directory not found: $backup_dir"
        return 1
    fi
    
    local backup_files=$(find "$backup_dir" -type f | wc -l)
    info "Backup contains $backup_files files"
    
    # Check critical files
    local critical_files=(
        "/Library/Preferences/com.apple.loginwindow.plist"
        "/etc/security/audit_control"
        "/etc/sudoers"
    )
    
    for file in "${critical_files[@]}"; do
        if [[ -f "$backup_dir$file" ]]; then
            success "✓ Critical file backed up: $file"
        else
            warn "✗ Critical file missing: $file"
        fi
    done
}
