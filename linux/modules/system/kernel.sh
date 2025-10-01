#!/usr/bin/env bash

harden_ipv4_settings() {
    log_info "Configuring IPv4 network security parameters"
    log_info "Disabling IP forwarding and securing network protocol settings"
    # Basic IPv4 security
    sysctl_apply net.ipv4.ip_forward 0
    
    # ICMP redirects
    sysctl_apply net.ipv4.conf.all.send_redirects 0
    sysctl_apply net.ipv4.conf.default.send_redirects 0
    sysctl_apply net.ipv4.conf.all.accept_redirects 0
    sysctl_apply net.ipv4.conf.default.accept_redirects 0
    
    # Source routing
    sysctl_apply net.ipv4.conf.all.accept_source_route 0
    sysctl_apply net.ipv4.conf.default.accept_source_route 0
    
    # ICMP broadcast and errors
    sysctl_apply net.ipv4.icmp_echo_ignore_broadcasts 1
    sysctl_apply net.ipv4.icmp_ignore_bogus_error_responses 1
    
    # TCP SYN cookies
    sysctl_apply net.ipv4.tcp_syncookies 1
}

harden_ipv6_settings() {
    log_info "Configuring IPv6 security settings based on profile"
    local ipv6_enabled
    ipv6_enabled=$(get_profile_setting "IPV6_ENABLED")

    if [[ "$ipv6_enabled" == "no" ]]; then
        log_info "IPv6 is disabled in current profile - completely disabling IPv6 stack"
        # Completely disable IPv6
        sysctl_apply net.ipv6.conf.all.disable_ipv6 1
        sysctl_apply net.ipv6.conf.default.disable_ipv6 1
        sysctl_apply net.ipv6.conf.lo.disable_ipv6 1
    else
        log_info "IPv6 is enabled - applying security restrictions to IPv6 configuration"
        # Just secure IPv6 if enabled
        sysctl_apply net.ipv6.conf.all.accept_redirects 0
        sysctl_apply net.ipv6.conf.default.accept_redirects 0
        sysctl_apply net.ipv6.conf.all.accept_ra 0
        sysctl_apply net.ipv6.conf.default.accept_ra 0
    fi
}

harden_kernel_settings() {
    log_info "Applying kernel hardening parameters"
    log_info "Enabling address space layout randomization and kernel security features"
    # Address space layout randomization
    sysctl_apply kernel.randomize_va_space 2
    
    # Kernel pointer restriction
    sysctl_apply kernel.kptr_restrict 2
    
    # Restrict access to kernel messages
    sysctl_apply kernel.dmesg_restrict 1
}




