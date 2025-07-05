#!/usr/bin/env bash
# Mass Proxy Creator - Stable Version
# Supports: SOCKS5 (Dante), Shadowsocks-libev, HTTP Proxy (Squid)

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Logging
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $*" | tee -a /var/log/mass-proxy.log
}

error_exit() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1" | tee -a /var/log/mass-proxy.log
    exit 1
}

# Check root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root. Use: sudo $0"
    fi
}

# Draw box with title and content
draw_box() {
    local title="$1"
    local content="$2"
    local width=70
    local padding=$(( (width - ${#title} - 2) / 2 ))
    
    echo
    echo -e "${YELLOW}┌$(printf '─%.0s' $(seq 1 $((width-2))))┐${NC}"
    printf "${YELLOW}│%${padding}s %s %${padding}s│${NC}\n" "" "$title" ""
    echo -e "${YELLOW}├$(printf '─%.0s' $(seq 1 $((width-2))))┤${NC}"
    
    while IFS= read -r line; do
        if [[ -n "$line" ]]; then
            echo -e "${YELLOW}│${NC} $line$(printf ' %.0s' $(seq 1 $((width-${#line}-4)))) ${YELLOW}│${NC}"
        fi
    done <<< "$content"
    
    echo -e "${YELLOW}└$(printf '─%.0s' $(seq 1 $((width-2))))┘${NC}"
    echo
}

# Detect OS and package manager
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        case "$ID" in
            ubuntu|debian)
                OS="debian"
                PACKAGE_MANAGER="apt-get"
                ;;
            centos|rhel|almalinux|rocky)
                OS="redhat"
                PACKAGE_MANAGER="yum"
                command -v dnf >/dev/null && PACKAGE_MANAGER="dnf"
                ;;
            *)
                error_exit "Unsupported OS: $ID"
                ;;
        esac
    else
        error_exit "Cannot detect OS."
    fi
    log "Detected OS: $OS with package manager: $PACKAGE_MANAGER"
}

# Get public IP
get_public_ip() {
    PUBLIC_IP=$(curl -4 -s --connect-timeout 10 https://api.ipify.org || 
                curl -4 -s --connect-timeout 10 https://icanhazip.com || 
                curl -4 -s --connect-timeout 10 https://ipecho.net/plain)
    [[ -z "$PUBLIC_IP" ]] && error_exit "Could not determine public IP"
    log "Public IP: $PUBLIC_IP"
}

# Generate random available port
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

# Install packages with error handling
install_packages() {
    local packages=("$@")
    log "Installing packages: ${packages[*]}"
    
    if [[ "$OS" = "debian" ]]; then
        apt-get update -qq || error_exit "Failed to update package list"
        DEBIAN_FRONTEND=noninteractive apt-get install -y "${packages[@]}" || error_exit "Failed to install packages"
    else
        if [[ "$PACKAGE_MANAGER" = "dnf" ]]; then
            dnf install -y epel-release || true
            dnf install -y "${packages[@]}" || error_exit "Failed to install packages"
        else
            yum install -y epel-release || true
            yum install -y "${packages[@]}" || error_exit "Failed to install packages"
        fi
    fi
}

# Configure firewall
manage_firewall() {
    local port=$1
    local protocol=${2:-tcp}
    
    log "Configuring firewall for port $port/$protocol"
    
    if command -v ufw >/dev/null; then
        ufw allow "$port/$protocol" >/dev/null
    elif command -v firewall-cmd >/dev/null; then
        firewall-cmd --permanent --add-port="$port/$protocol" >/dev/null
        firewall-cmd --reload >/dev/null
    else
        iptables -A INPUT -p "$protocol" --dport "$port" -j ACCEPT
        if command -v iptables-save >/dev/null; then
            iptables-save > /etc/iptables.rules
        fi
    fi
}

# Install SOCKS5 proxies
install_socks5() {
    local count=$1
    local credentials=()
    
    install_packages dante-server
    
    # Backup existing config
    [[ -f /etc/danted.conf ]] && cp /etc/danted.conf /etc/danted.conf.bak
    
    # Base config
    cat > /etc/danted.conf <<EOF
logoutput: syslog /var/log/danted.log
user.privileged: root
user.unprivileged: nobody

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
    
    for ((i=1; i<=count; i++)); do
        local username="socksuser$i"
        local password=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 16)
        local port=$(generate_port)
        
        # Create user if not exists
        if ! id "$username" &>/dev/null; then
            useradd -M -s /bin/false "$username" || error_exit "Failed to create user $username"
        fi
        echo "$username:$password" | chpasswd || error_exit "Failed to set password for $username"
        
        # Add port to config
        echo "internal: 0.0.0.0 port = $port" >> /etc/danted.conf
        
        manage_firewall "$port"
        credentials+=("socks5://$PUBLIC_IP:$port:$username:$password")
    done
    
    systemctl restart danted || error_exit "Failed to restart danted service"
    
    local output=$(printf "%s\n" "${credentials[@]}")
    draw_box "🧦 SOCKS5 PROXIES CREATED ($count)" "$output"
}

# Install Shadowsocks proxies
install_shadowsocks() {
    local count=$1
    local credentials=()
    
    install_packages shadowsocks-libev qrencode
    
    for ((i=1; i<=count; i++)); do
        local password=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 20)
        local port=$(generate_port)
        local method="aes-256-gcm"
        
        # Create config directory
        mkdir -p "/etc/shadowsocks/$i"
        
        # Config file
        cat > "/etc/shadowsocks/$i/config.json" <<EOF
{
    "server": "0.0.0.0",
    "server_port": $port,
    "password": "$password",
    "timeout": 300,
    "method": "$method",
    "mode": "tcp_and_udp",
    "fast_open": false
}
EOF
        
        # Systemd service
        cat > "/etc/systemd/system/shadowsocks-$i.service" <<EOF
[Unit]
Description=Shadowsocks-Libev Server $i
After=network.target

[Service]
Type=simple
User=nobody
Group=nogroup
ExecStart=/usr/bin/ss-server -c /etc/shadowsocks/$i/config.json
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
        
        systemctl daemon-reload
        systemctl enable shadowsocks-$i
        systemctl start shadowsocks-$i || error_exit "Failed to start shadowsocks-$i"
        
        manage_firewall "$port" tcp
        manage_firewall "$port" udp
        
        credentials+=("ss://$(echo -n "$method:$password" | base64 -w 0)@$PUBLIC_IP:$port#Proxy$i")
    done
    
    local output=$(printf "%s\n" "${credentials[@]}")
    draw_box "👻 SHADOWSOCKS PROXIES CREATED ($count)" "$output"
}

# Install HTTP proxies
install_http_proxy() {
    local count=$1
    local credentials=()
    
    install_packages squid apache2-utils
    
    # Backup config
    [[ -f /etc/squid/squid.conf ]] && cp /etc/squid/squid.conf /etc/squid/squid.conf.bak
    
    # Initialize password file
    echo -n > /etc/squid/passwd
    chmod 600 /etc/squid/passwd
    
    # Base config
    cat > /etc/squid/squid.conf <<EOF
acl localnet src 0.0.0.0/0
acl SSL_ports port 443
acl Safe_ports port 80
acl Safe_ports port 443
acl CONNECT method CONNECT

http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports

cache deny all
max_filedesc 8192

# Authentication
auth_param basic program /usr/lib/squid/basic_ncsa_auth /etc/squid/passwd
auth_param basic realm proxy
auth_param basic children 5
auth_param basic credentialsttl 2 hours
acl authenticated proxy_auth REQUIRED
http_access allow authenticated
EOF
    
    for ((i=1; i<=count; i++)); do
        local username="httpuser$i"
        local password=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 16)
        local port=$(generate_port)
        
        # Add port
        echo "http_port $port" >> /etc/squid/squid.conf
        
        # Add user (use -c for first user only)
        if [[ $i -eq 1 ]]; then
            htpasswd -b -c /etc/squid/passwd "$username" "$password" || error_exit "Failed to create password file"
        else
            htpasswd -b /etc/squid/passwd "$username" "$password" || error_exit "Failed to add user $username"
        fi
        
        manage_firewall "$port"
        credentials+=("http://$PUBLIC_IP:$port:$username:$password")
    done
    
    # Set proper ownership
    chown proxy:proxy /etc/squid/passwd || error_exit "Failed to set ownership on password file"
    
    systemctl restart squid || error_exit "Failed to restart squid service"
    
    local output=$(printf "%s\n" "${credentials[@]}")
    draw_box "🌐 HTTP PROXIES CREATED ($count)" "$output"
}

# Main menu
main_menu() {
    clear
    echo -e "${YELLOW}"
    echo "┌─────────────────────────────────────────────────────┐"
    echo "│           MASS PROXY CREATOR - MAIN MENU            │"
    echo "├─────────────────────────────────────────────────────┤"
    echo "│ 1. Create multiple SOCKS5 proxies                   │"
    echo "│ 2. Create multiple Shadowsocks proxies              │"
    echo "│ 3. Create multiple HTTP proxies                     │"
    echo "│ 4. Create all three types                           │"
    echo "│ 5. Exit                                             │"
    echo "└─────────────────────────────────────────────────────┘"
    echo -e "${NC}"
}

# Validate number input
validate_number() {
    local num="$1"
    [[ "$num" =~ ^[1-9][0-9]*$ ]] && [[ "$num" -le 1000 ]]
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
                while true; do
                    read -p "How many SOCKS5 proxies to create? (1-1000): " count
                    validate_number "$count" && break
                    echo -e "${RED}Invalid input! Please enter a number between 1-1000${NC}"
                done
                install_socks5 "$count"
                ;;
            2)
                while true; do
                    read -p "How many Shadowsocks proxies to create? (1-1000): " count
                    validate_number "$count" && break
                    echo -e "${RED}Invalid input! Please enter a number between 1-1000${NC}"
                done
                install_shadowsocks "$count"
                ;;
            3)
                while true; do
                    read -p "How many HTTP proxies to create? (1-1000): " count
                    validate_number "$count" && break
                    echo -e "${RED}Invalid input! Please enter a number between 1-1000${NC}"
                done
                install_http_proxy "$count"
                ;;
            4)
                while true; do
                    read -p "How many proxies of each type to create? (1-1000): " count
                    validate_number "$count" && break
                    echo -e "${RED}Invalid input! Please enter a number between 1-1000${NC}"
                done
                install_socks5 "$count"
                install_shadowsocks "$count"
                install_http_proxy "$count"
                ;;
            5)
                echo -e "${GREEN}Exiting...${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid option!${NC}"
                ;;
        esac
        
        read -p "Press Enter to continue..."
    done
}

# Start
main
