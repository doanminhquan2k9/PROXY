#!/usr/bin/env bash
# Mass Proxy Creator - Create multiple proxies with one selection
# Supports SOCKS5 (Dante), Shadowsocks-libev, and HTTP Proxy (Squid)

set -euo pipefail

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a /var/log/mass-proxy-creator.log
}

# Error handling function
error_exit() {
    log "ERROR: $1"
    exit 1
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root. Use: sudo $0"
    fi
}

# Draw box around text
draw_box() {
    local title="$1"
    local content="$2"
    local width=70
    
    echo ""
    echo "┌$(printf '─%.0s' $(seq 1 $((width-2))))┐"
    echo "│ $(printf "%-*s" $((width-4)) "$title") │"
    echo "├$(printf '─%.0s' $(seq 1 $((width-2))))┤"
    
    while IFS= read -r line; do
        if [[ -n "$line" ]]; then
            echo "│ $(printf "%-*s" $((width-4)) "$line") │"
        fi
    done <<< "$content"
    
    echo "└$(printf '─%.0s' $(seq 1 $((width-2))))┘"
    echo ""
}

# Detect OS
detect_os() {
    OS=""
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        case "$ID" in
            ubuntu|debian) OS="debian"; PACKAGE_MANAGER="apt-get";;
            centos|rhel|almalinux|rocky) 
                OS="redhat" 
                if command -v dnf >/dev/null; then
                    PACKAGE_MANAGER="dnf"
                else
                    PACKAGE_MANAGER="yum"
                fi
                ;;
            *) error_exit "Unsupported OS: $ID";;
        esac
    else
        error_exit "Cannot detect OS."
    fi
    log "Detected OS: $OS with package manager: $PACKAGE_MANAGER"
}

# Get public IP
get_public_ip() {
    PUBLIC_IP=$(curl -4 -s http://api.ipify.org || curl -4 -s http://icanhazip.com)
    [[ -z "$PUBLIC_IP" ]] && error_exit "Could not determine public IP"
    log "Public IP: $PUBLIC_IP"
}

# Generate random port
generate_port() {
    local port
    while true; do
        port=$(shuf -i 10000-60000 -n 1)
        if ! ss -tuln | grep -q ":$port "; then
            echo "$port"
            return
        fi
    done
}

# Install required packages
install_packages() {
    local packages=("$@")
    log "Installing packages: ${packages[*]}"
    
    if [[ "$OS" = "debian" ]]; then
        apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y "${packages[@]}"
    else
        $PACKAGE_MANAGER install -y epel-release
        $PACKAGE_MANAGER install -y "${packages[@]}"
    fi
}

# Configure firewall
manage_firewall() {
    local port=$1
    local protocol=${2:-tcp}
    
    if command -v ufw >/dev/null; then
        ufw allow "$port/$protocol"
    elif command -v firewall-cmd >/dev/null; then
        firewall-cmd --permanent --add-port="$port/$protocol"
        firewall-cmd --reload
    else
        iptables -A INPUT -p "$protocol" --dport "$port" -j ACCEPT
        service iptables save
    fi
}

# Install and configure SOCKS5 proxy
install_socks5() {
    local count=$1
    local credentials=()
    
    install_packages dante-server
    
    # Create main config if doesn't exist
    if [[ ! -f /etc/danted.conf ]]; then
        cat > /etc/danted.conf <<EOF
logoutput: syslog
user.privileged: root
user.unprivileged: nobody

internal: 0.0.0.0 port = 1080
external: eth0

method: pam
clientmethod: none

client pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
    log: connect disconnect error
}

socks pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
    log: error connect disconnect
}
EOF
    fi
    
    for ((i=1; i<=count; i++)); do
        local username="socksuser$i"
        local password=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 12)
        local port=$(generate_port)
        
        # Add user
        useradd -M -s /bin/false "$username"
        echo "$username:$password" | chpasswd
        
        # Add to Dante config
        sed -i "/^internal:/a internal: 0.0.0.0 port = $port" /etc/danted.conf
        
        manage_firewall "$port"
        credentials+=("socks5://$PUBLIC_IP:$port:$username:$password")
    done
    
    systemctl restart danted
    
    # Print credentials
    local output=""
    for cred in "${credentials[@]}"; do
        output+="$cred\n"
    done
    draw_box "🧦 SOCKS5 PROXIES CREATED ($count)" "$output"
}

# Install and configure Shadowsocks proxies
install_shadowsocks() {
    local count=$1
    local credentials=()
    
    install_packages shadowsocks-libev
    
    for ((i=1; i<=count; i++)); do
        local password=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 16)
        local port=$(generate_port)
        local method="aes-256-gcm"
        
        # Create config
        mkdir -p "/etc/shadowsocks/$i"
        cat > "/etc/shadowsocks/$i/config.json" <<EOF
{
    "server":"0.0.0.0",
    "server_port":$port,
    "password":"$password",
    "timeout":300,
    "method":"$method",
    "mode":"tcp_and_udp"
}
EOF
        
        # Create systemd service
        cat > "/etc/systemd/system/shadowsocks-$i.service" <<EOF
[Unit]
Description=Shadowsocks-Libev Server $i
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/ss-server -c /etc/shadowsocks/$i/config.json
Restart=always

[Install]
WantedBy=multi-user.target
EOF
        
        systemctl daemon-reload
        systemctl enable shadowsocks-$i
        systemctl start shadowsocks-$i
        
        manage_firewall "$port"
        manage_firewall "$port" udp
        
        credentials+=("ss://$(echo -n "$method:$password" | base64 -w 0)@$PUBLIC_IP:$port#Proxy$i")
    done
    
    # Print credentials
    local output=""
    for cred in "${credentials[@]}"; do
        output+="$cred\n"
    done
    draw_box "👻 SHADOWSOCKS PROXIES CREATED ($count)" "$output"
}

# Install and configure HTTP proxies
install_http_proxy() {
    local count=$1
    local credentials=()
    
    install_packages squid apache2-utils
    
    # Backup original config
    cp /etc/squid/squid.conf /etc/squid/squid.conf.bak
    
    # Base config
    cat > /etc/squid/squid.conf <<EOF
acl localnet src 0.0.0.0/0
acl SSL_ports port 443
acl Safe_ports port 80
acl Safe_ports port 443
acl CONNECT method CONNECT

http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access allow localnet

http_port 3128

cache deny all
EOF
    
    for ((i=1; i<=count; i++)); do
        local username="httpuser$i"
        local password=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 12)
        local port=$(generate_port)
        
        # Add port to config
        echo "http_port $port" >> /etc/squid/squid.conf
        
        # Add user
        htpasswd -b /etc/squid/passwd "$username" "$password"
        
        manage_firewall "$port"
        credentials+=("http://$PUBLIC_IP:$port:$username:$password")
    done
    
    # Add authentication to config
    echo "auth_param basic program /usr/lib/squid/basic_ncsa_auth /etc/squid/passwd" >> /etc/squid/squid.conf
    echo "auth_param basic realm proxy" >> /etc/squid/squid.conf
    echo "acl authenticated proxy_auth REQUIRED" >> /etc/squid/squid.conf
    echo "http_access allow authenticated" >> /etc/squid/squid.conf
    
    systemctl restart squid
    
    # Print credentials
    local output=""
    for cred in "${credentials[@]}"; do
        output+="$cred\n"
    done
    draw_box "🌐 HTTP PROXIES CREATED ($count)" "$output"
}

# Main menu
main_menu() {
    echo ""
    echo "┌─────────────────────────────────────────────────────┐"
    echo "│         MASS PROXY CREATOR - MAIN MENU              │"
    echo "├─────────────────────────────────────────────────────┤"
    echo "│ 1. Create multiple SOCKS5 proxies                   │"
    echo "│ 2. Create multiple Shadowsocks proxies              │"
    echo "│ 3. Create multiple HTTP proxies                     │"
    echo "│ 4. Create all three types                           │"
    echo "│ 5. Exit                                             │"
    echo "└─────────────────────────────────────────────────────┘"
    echo ""
}

# Main function
main() {
    check_root
    detect_os
    get_public_ip
    
    while true; do
        main_menu
        read -p "Select option [1-5]: " choice
        
        case $choice in
            1)
                read -p "How many SOCKS5 proxies to create? " count
                install_socks5 "$count"
                ;;
            2)
                read -p "How many Shadowsocks proxies to create? " count
                install_shadowsocks "$count"
                ;;
            3)
                read -p "How many HTTP proxies to create? " count
                install_http_proxy "$count"
                ;;
            4)
                read -p "How many proxies of each type to create? " count
                install_socks5 "$count"
                install_shadowsocks "$count"
                install_http_proxy "$count"
                ;;
            5)
                echo "Exiting..."
                exit 0
                ;;
            *)
                echo "Invalid option!"
                ;;
        esac
        
        read -p "Press Enter to continue..."
    done
}

# Start main function
main
