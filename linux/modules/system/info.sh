#!/usr/bin/env bash

get_hostname_info() {
    log_info "Collecting system hostname information"
    echo "Hostname: $(hostname)"
}

get_kernel_info() {
    log_info "Gathering kernel version information"
    echo "Kernel: $(uname -sr)"
}

get_os_info() {
    log_info "Collecting operating system details"
    echo "OS: $PLATFORM_ID $PLATFORM_VERSION ($PLATFORM_FAMILY)"
}

get_uptime_info() {
    log_info "Checking system uptime"
    echo "Uptime: $(uptime -p 2>/dev/null || true)"
}

get_cpu_info() {
    log_info "Retrieving CPU specifications"
    echo "CPU: $(lscpu 2>/dev/null | grep -E 'Model name|Architecture' | sed 's/^\s\+//')"
}

get_memory_info() {
    log_info "Analyzing system memory configuration"
    echo "Memory: $(free -h 2>/dev/null | awk '/Mem:/ {print $2" total"}')"
}

get_disk_info() {
    log_info "Scanning disk partitions and storage configuration"
    echo "Disks: $(lsblk -o NAME,SIZE,TYPE,MOUNTPOINT -nr 2>/dev/null | tr '\n' '; ')"
}

get_network_interfaces() {
    log_info "Enumerating network interfaces and IP addresses"
    echo "Interfaces:\n$(ip -o -4 addr show 2>/dev/null | awk '{print $2": "$4}' | sed 's/^/  - /')"
}

get_listening_ports() {
    log_info "Scanning for open network ports and services"
    echo "Listening ports:\n$(ss -tulpen 2>/dev/null | sed 's/^/  /')"
}

get_logged_users() {
    log_info "Checking currently logged-in users"
    echo "Logged in users: $(who 2>/dev/null | wc -l)"
}




