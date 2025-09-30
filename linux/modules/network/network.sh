#!/usr/bin/env bash

blacklist_uncommon_filesystems() {
    local fs_modules=(
        cramfs
        freevxfs
        jffs2
        hfs
        hfsplus
        udf
    )
    return "$fs_modules"
}

blacklist_uncommon_protocols() {
    local net_modules=(
        dccp
        sctp
        rds
        tipc
    )
    return "$net_modules"
}

configure_module_blacklist() {
    log_info "Configuring kernel module blacklist for enhanced security"
    log_info "Disabling unnecessary and potentially dangerous filesystem and network protocols"
    local modprobe=/etc/modprobe.d/harden.conf
    backup_file "$modprobe"
    
    if [[ "${HARDEN_DRY_RUN:-false}" == "true" ]]; then
        log_info "[dry-run] blacklist cramfs freevxfs jffs2 hfs hfsplus udf dccp sctp rds tipc"
        return
    fi
    
    cat > "$modprobe" <<'BLK'
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install udf /bin/true
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
BLK
}




