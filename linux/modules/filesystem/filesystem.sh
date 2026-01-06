#!/usr/bin/env bash

secure_temp_directories() {
    local targets=(/tmp /var/tmp)
    local options="nodev,nosuid,noexec"

    for t in "${targets[@]}"; do
        log_info "Securing $t"

        # Ensure entry exists in fstab
        if ! grep -Eq "^[^#].*\s+$t\s+" /etc/fstab; then
            log_warn "$t not found in /etc/fstab — skipping persistence"
            continue
        fi

        # Backup fstab before modification
        backup_file /etc/fstab

        # Update fstab entry safely
        if [[ "${HARDEN_DRY_RUN:-false}" == "true" ]]; then
            log_info "[dry-run] would update /etc/fstab for $t"
        else
            awk -v target="$t" -v opts="$options" '
                $2 == target {
                    if ($4 ~ opts) print;
                    else {
                        n=split($4,a,",");
                        seen="";
                        for(i=1;i<=n;i++) seen[a[i]]=1;
                        split(opts,b,",");
                        for(i in b) seen[b[i]]=1;
                        out="";
                        for(k in seen) out=(out?out",":"")k;
                        $4=out;
                        print;
                    }
                    next
                }
                { print }
            ' /etc/fstab > /etc/fstab.hardened

            mv /etc/fstab.hardened /etc/fstab
        fi

        # Apply immediately
        if [[ "${HARDEN_DRY_RUN:-false}" == "true" ]]; then
            log_info "[dry-run] mount -o remount,$options $t"
        else
            mount -o remount,"$options" "$t" || log_warn "Remount failed for $t"
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




