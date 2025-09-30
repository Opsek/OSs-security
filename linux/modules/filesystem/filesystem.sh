#!/usr/bin/env bash

secure_temp_directories() {
    local targets=(/tmp /var/tmp)
    for t in "${targets[@]}"; do
        if mount | awk '{print $3}' | grep -qx "$t"; then
            if [[ "${HARDEN_DRY_RUN:-false}" == "true" ]]; then
                log_info "[dry-run] mount -o remount,nodev,nosuid,noexec $t"
            else
                mount -o remount,nodev,nosuid,noexec "$t" 2>/dev/null || true
            fi
        fi
    done
}

check_partition_entries() {
    for t in /home /var /var/tmp /tmp; do
        if grep -Eqs "\s$t\s" /etc/fstab; then
            :
        else
            log_warn "No fstab entry for $t; consider configuring separate partition with secure options"
        fi
    done
}




