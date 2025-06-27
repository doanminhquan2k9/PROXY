#!/usr/bin/env bash
# Enhanced Combined installer for SOCKS5 (Dante) and/or Shadowsocks-libev on Ubuntu/Debian/RedHat

# ==================================================================================
#                            🚀 AMAZON AWS ACCOUNT SERVICES 🚀
# ==================================================================================
#  Need AWS Account? VPS? Cloud Services? Contact us for the best prices!
#  📧 Contact: https://www.facebook.com/vunghia.bui.750
#  💰 Amazon AWS Account - Verified & Ready to use
#  🌐 VPS & Cloud Solutions - Professional Support
#  ⚡ Fast Setup - Reliable Service - Competitive Prices
# ==================================================================================

set -euo pipefail  # Enhanced error handling

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a /var/log/proxy-installer.log
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

# Display advertising header
display_header() {
    echo "=================================================================================="
    echo "                          🚀 AMAZON AWS ACCOUNT SERVICES 🚀"
    echo "=================================================================================="
    echo " Need AWS Account? VPS? Cloud Services? Contact us for the best prices!"
    echo " 📧 Contact: https://www.facebook.com/vunghia.bui.750"
    echo " 💰 Amazon AWS Account - Verified & Ready to use"
    echo " 🌐 VPS & Cloud Solutions - Professional Support"
    echo " ⚡ Fast Setup - Reliable Service - Competitive Prices"
    echo "=================================================================================="
    echo ""
}

# Function to draw box around text
draw_box() {
    local title="$1"
    local content="$2"
    local width=60
    
    # Colors
    local GREEN='\033[0;32m'
    local BLUE='\033[0;34m'
    local YELLOW='\033[1;33m'
    local NC='\033[0m' # No Color
    local BOLD='\033[1m'
    
    echo ""
    echo -e "${GREEN}┌$(printf '─%.0s' $(seq 1 $((width-2))))┐${NC}"
    echo -e "${GREEN}│${BOLD}${YELLOW} $(printf "%-*s" $((width-4)) "$title") ${NC}${GREEN}│${NC}"
    echo -e "${GREEN}├$(printf '─%.0s' $(seq 1 $((width-2))))┤${NC}"
    
    # Split content by newlines and format each line
    while IFS= read -r line; do
        if [[ -n "$line" ]]; then
            echo -e "${GREEN}│${NC} $(printf "%-*s" $((width-4)) "$line") ${GREEN}│${NC}"
        fi
    done <<< "$content"
    
    echo -e "${GREEN}└$(printf '─%.0s' $(seq 1 $((width-2))))┘${NC}"
    echo ""
}

# Detect OS with enhanced validation
detect_os() {
    OS=""
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        case "$ID" in
            ubuntu|debian) 
                OS="debian" 
                PACKAGE_MANAGER="apt-get"
                ;;        
            amzn|centos|rhel|rocky|almalinux|fedora) 
                OS="redhat" 
                if command -v dnf >/dev/null 2>&1; then
                    PACKAGE_MANAGER="dnf"
                else
                    PACKAGE_MANAGER="yum"
                fi
                ;;        
            *) error_exit "Unsupported OS: $ID" ;;    
        esac
    else
        error_exit "Cannot detect OS."
    fi
    log "Detected OS: $OS with package manager: $PACKAGE_MANAGER"
}

# Get network interface and public IP with validation
get_network_info() {
    EXT_IF=$(ip route | awk '/default/ {print $5; exit}')
    EXT_IF=${EXT_IF:-eth0}
    
    # Try multiple services to get public IP
    PUBLIC_IP=""
    for service in "https://api.ipify.org" "https://icanhazip.com" "https://ipecho.net/plain"; do
        if PUBLIC_IP=$(curl -4 -s --connect-timeout 10 "$service" 2>/dev/null); then
            if [[ $PUBLIC_IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
                break
            fi
        fi
    done
    
    if [[ -z "$PUBLIC_IP" ]]; then
        error_exit "Could not determine public IP address"
    fi
    
    log "Network interface: $EXT_IF, Public IP: $PUBLIC_IP"
}

# Validate port number (return true/false instead of exit)
validate_port() {
    local port=$1
    if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        echo "❌ Invalid port number: $port (must be 1-65535)"
        return 1
    fi
    
    # Check if port is already in use
    if ss -tuln | grep -q ":$port "; then
        echo "❌ Port $port is already in use"
        return 1
    fi
    return 0
}

# Validate username (return true/false instead of exit)
validate_username() {
    local username=$1
    if [[ ! "$username" =~ ^[a-zA-Z0-9_-]+$ ]] || [ ${#username} -lt 2 ] || [ ${#username} -gt 32 ]; then
        echo "❌ Invalid username: $username (must be 2-32 characters, alphanumeric with _ and - allowed)"
        return 1
    fi
    return 0
}

# Generate secure random password (alphanumeric only for compatibility)
generate_password() {
    local length=${1:-16}
    tr -dc 'A-Za-z0-9' </dev/urandom | head -c"$length"
}

# Generate secure random username
generate_username() {
    echo "user_$(tr -dc 'a-z0-9' </dev/urandom | head -c8)"
}

# User input prompts
prompt_user_choice() {
    echo "Select server(s) to install:"
    echo "  1) SOCKS5 (Dante)"
    echo "  2) Shadowsocks-libev"
    echo "  3) HTTP Proxy (Squid)"
    echo "  4) SOCKS5 + HTTP Proxy"
    echo "  5) Shadowsocks + HTTP Proxy"
    echo "  6) SOCKS5 + Shadowsocks"
    echo "  7) All three (SOCKS5 + Shadowsocks + HTTP)"
    
    while true; do
        read -p "Enter choice [1-7]: " choice
        if [[ "$choice" =~ ^[1-7]$ ]]; then
            break
        else
            echo "❌ Invalid choice. Please enter a number between 1 and 7."
        fi
    done
}

prompt_config_mode() {
    echo ""
    echo "Select configuration mode:"
    echo "  1) Automatic (random credentials)"
    echo "  2) Manual (custom credentials)"
    
    while true; do
        read -p "Enter choice [1 or 2]: " config_mode
        if [[ "$config_mode" =~ ^[12]$ ]]; then
            break
        else
            echo "❌ Invalid choice. Please enter 1 or 2."
        fi
    done
}

# Function to get manual credentials for SOCKS5
get_manual_socks5_credentials() {
    echo ""
    echo "=== Manual SOCKS5 Configuration ==="
    
    while true; do
        read -p "Enter port (default: 1080): " MANUAL_PORT
        MANUAL_PORT=${MANUAL_PORT:-1080}
        validate_port "$MANUAL_PORT" && break
    done
    
    while true; do
        read -p "Enter username (default: socks5user): " MANUAL_USERNAME
        MANUAL_USERNAME=${MANUAL_USERNAME:-socks5user}
        validate_username "$MANUAL_USERNAME" && break
    done
    
    read -p "Enter password (default: auto-generate): " MANUAL_PASSWORD
    if [[ -z "$MANUAL_PASSWORD" ]]; then
        MANUAL_PASSWORD=$(generate_password 12)
        echo "Generated password: $MANUAL_PASSWORD"
    fi
}

# Function to get manual credentials for Shadowsocks
get_manual_shadowsocks_credentials() {
    echo ""
    echo "=== Manual Shadowsocks Configuration ==="
    
    while true; do
        read -p "Enter port (default: 8388): " MANUAL_SS_PORT
        MANUAL_SS_PORT=${MANUAL_SS_PORT:-8388}
        validate_port "$MANUAL_SS_PORT" && break
    done
    
    read -p "Enter password (default: auto-generate): " MANUAL_SS_PASSWORD
    if [[ -z "$MANUAL_SS_PASSWORD" ]]; then
        MANUAL_SS_PASSWORD=$(generate_password 16)
        echo "Generated password: $MANUAL_SS_PASSWORD"
    fi
    
    echo "Select encryption method:"
    echo "  1) aes-256-gcm (recommended)"
    echo "  2) chacha20-ietf-poly1305"
    echo "  3) aes-128-gcm"
    
    while true; do
        read -p "Enter choice [1-3]: " method_choice
        case "$method_choice" in
            1) MANUAL_SS_METHOD="aes-256-gcm"; break ;;
            2) MANUAL_SS_METHOD="chacha20-ietf-poly1305"; break ;;
            3) MANUAL_SS_METHOD="aes-128-gcm"; break ;;
            *) echo "❌ Invalid choice. Please enter 1, 2, or 3." ;;
        esac
    done
}

# Function to get manual credentials for HTTP Proxy
get_manual_http_credentials() {
    echo ""
    echo "=== Manual HTTP Proxy Configuration ==="
    
    while true; do
        read -p "Enter port (default: 3128): " MANUAL_HTTP_PORT
        MANUAL_HTTP_PORT=${MANUAL_HTTP_PORT:-3128}
        validate_port "$MANUAL_HTTP_PORT" && break
    done
    
    while true; do
        read -p "Enter username (default: proxyuser): " MANUAL_HTTP_USERNAME
        MANUAL_HTTP_USERNAME=${MANUAL_HTTP_USERNAME:-proxyuser}
        validate_username "$MANUAL_HTTP_USERNAME" && break
    done
    
    read -p "Enter password (default: auto-generate): " MANUAL_HTTP_PASSWORD
    if [[ -z "$MANUAL_HTTP_PASSWORD" ]]; then
        MANUAL_HTTP_PASSWORD=$(generate_password 12)
        echo "Generated password: $MANUAL_HTTP_PASSWORD"
    fi
}

# Enhanced package installation with error handling
install_packages() {
    local packages=("$@")
    log "Installing packages: ${packages[*]}"
    
    if [[ "$OS" = "debian" ]]; then
        apt-get update -qq >/dev/null 2>&1 || error_exit "Failed to update package list"
        DEBIAN_FRONTEND=noninteractive apt-get install -y "${packages[@]}" >/dev/null 2>&1 || error_exit "Failed to install packages"
    else
        if [[ "$PACKAGE_MANAGER" = "dnf" ]]; then
            dnf install -y epel-release >/dev/null 2>&1 || true
            dnf install -y "${packages[@]}" >/dev/null 2>&1 || error_exit "Failed to install packages"
        else
            yum install -y epel-release >/dev/null 2>&1 || true
            yum install -y "${packages[@]}" >/dev/null 2>&1 || error_exit "Failed to install packages"
        fi
    fi
}

# Enhanced firewall management
manage_firewall() {
    local port=$1
    local protocol=${2:-tcp}
    
    log "Opening firewall for port $port/$protocol"
    
    if [[ "$OS" = "debian" ]]; then
        if command -v ufw >/dev/null 2>&1; then
            ufw --force enable >/dev/null 2>&1 || true
            ufw allow "$port/$protocol" >/dev/null 2>&1 || log "Warning: Failed to configure UFW"
        else
            # Install iptables-persistent if not present
            if ! dpkg -l | grep -q iptables-persistent; then
                DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent
            fi
            iptables -I INPUT -p "$protocol" --dport "$port" -j ACCEPT
            netfilter-persistent save || iptables-save > /etc/iptables/rules.v4
        fi
    else
        if systemctl is-active --quiet firewalld; then
            firewall-cmd --permanent --add-port="$port/$protocol"
            firewall-cmd --reload
        else
            systemctl enable iptables >/dev/null 2>&1 || true
            systemctl start iptables >/dev/null 2>&1 || true
            iptables -I INPUT -p "$protocol" --dport "$port" -j ACCEPT
            service iptables save >/dev/null 2>&1 || iptables-save > /etc/sysconfig/iptables
        fi
    fi
}

# Install SOCKS5 with enhanced configuration
install_socks5() {
    local USERNAME PASSWORD PORT
    
    log "Starting SOCKS5 installation"
    
    if [[ "$config_mode" = "1" ]]; then
        # Automatic mode
        USERNAME=$(generate_username)
        PASSWORD=$(generate_password 12)
        PORT=$(shuf -i 1025-65000 -n1)
        
        # Ensure port is not in use
        while ss -tuln | grep -q ":$PORT "; do
            PORT=$(shuf -i 1025-65000 -n1)
        done
    else
        # Manual mode
        get_manual_socks5_credentials
        USERNAME="$MANUAL_USERNAME"
        PASSWORD="$MANUAL_PASSWORD"
        PORT="$MANUAL_PORT"
    fi

    # Install packages
    install_packages dante-server curl iptables

    # Create user
    if ! id "$USERNAME" >/dev/null 2>&1; then
        useradd -M -N -s /usr/sbin/nologin "$USERNAME" >/dev/null 2>&1 || error_exit "Failed to create user $USERNAME"
    fi
    echo "${USERNAME}:${PASSWORD}" | chpasswd >/dev/null 2>&1 || error_exit "Failed to set password for user $USERNAME"

    # Backup existing config
    if [[ -f /etc/danted.conf ]]; then
        cp /etc/danted.conf "/etc/danted.conf.bak.$(date +%F_%T)" >/dev/null 2>&1
    fi

    # Create enhanced Dante configuration
    cat > /etc/danted.conf <<EOF
# Dante SOCKS5 server configuration - Global Access
logoutput: syslog /var/log/danted.log

# Network configuration - Listen on all interfaces
internal: 0.0.0.0 port = ${PORT}
external: ${EXT_IF}

# Authentication method
method: pam

# User privileges
user.privileged: root
user.notprivileged: nobody

# Client rules - Allow connections from anywhere
client pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
    log: connect disconnect error
}

# SOCKS rules - Allow global access but block dangerous destinations
socks pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
    command: bind connect udpassociate
    log: connect disconnect error
    protocol: tcp udp
}

# Security: Block access to private networks from external clients
socks block {
    from: 0.0.0.0/0 to: 127.0.0.0/8
    log: connect error
}

socks block {
    from: 0.0.0.0/0 to: 169.254.0.0/16
    log: connect error
}
EOF

    chmod 644 /etc/danted.conf

    # Enable and start service
    systemctl daemon-reload >/dev/null 2>&1
    systemctl enable danted >/dev/null 2>&1 || error_exit "Failed to enable danted service"
    systemctl restart danted >/dev/null 2>&1 || error_exit "Failed to start danted service"

    # Verify service is running
    sleep 2
    if ! systemctl is-active --quiet danted; then
        error_exit "SOCKS5 service failed to start"
    fi

    # Configure firewall
    manage_firewall "$PORT" tcp

    log "SOCKS5 installation completed successfully"
    echo "socks5://${PUBLIC_IP}:${PORT}:${USERNAME}:${PASSWORD}"
}

# Install Shadowsocks with enhanced configuration
install_shadowsocks() {
    local PASSWORD SERVER_PORT METHOD
    local CONFIG_PATH="/etc/shadowsocks-libev/config.json"
    
    log "Starting Shadowsocks installation"
    
    if [[ "$config_mode" = "1" ]]; then
        # Automatic mode
        PASSWORD=$(generate_password 16)
        SERVER_PORT=$(shuf -i 10000-60000 -n1)
        METHOD="aes-256-gcm"
        
        # Ensure port is not in use
        while ss -tuln | grep -q ":$SERVER_PORT "; do
            SERVER_PORT=$(shuf -i 10000-60000 -n1)
        done
    else
        # Manual mode
        get_manual_shadowsocks_credentials
        PASSWORD="$MANUAL_SS_PASSWORD"
        SERVER_PORT="$MANUAL_SS_PORT"
        METHOD="$MANUAL_SS_METHOD"
    fi

    # Install packages
    if [[ "$OS" = "debian" ]]; then
        install_packages shadowsocks-libev qrencode curl
    else
        # For RedHat systems, we might need to compile from source or use snap
        if ! command -v ss-server >/dev/null 2>&1; then
            log "Installing Shadowsocks from EPEL or compiling from source..."
            install_packages shadowsocks-libev qrencode curl || {
                log "Package installation failed, trying alternative method..."
                # Alternative installation method for CentOS/RHEL
                if command -v snap >/dev/null 2>&1; then
                    snap install shadowsocks-libev
                else
                    error_exit "Shadowsocks installation failed. Please install manually."
                fi
            }
        fi
    fi

    # Create config directory if it doesn't exist
    mkdir -p "$(dirname "$CONFIG_PATH")" >/dev/null 2>&1

    # Create enhanced Shadowsocks configuration
    cat > "$CONFIG_PATH" <<EOF
{
    "server": "0.0.0.0",
    "server_port": ${SERVER_PORT},
    "password": "${PASSWORD}",
    "timeout": 300,
    "method": "${METHOD}",
    "fast_open": false,
    "nameserver": "1.1.1.1",
    "mode": "tcp_and_udp",
    "no_delay": true,
    "reuse_port": true
}
EOF

    chmod 600 "$CONFIG_PATH"

    # Create systemd service if it doesn't exist
    if [[ ! -f /etc/systemd/system/shadowsocks-libev.service ]]; then
        cat > /etc/systemd/system/shadowsocks-libev.service <<EOF
[Unit]
Description=Shadowsocks-Libev Server
Documentation=man:ss-server(1)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=nobody
Group=nogroup
ExecStart=/usr/bin/ss-server -c ${CONFIG_PATH}
Restart=on-failure
RestartSec=5
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=shadowsocks-libev

[Install]
WantedBy=multi-user.target
EOF
    fi

    # Configure firewall
    manage_firewall "$SERVER_PORT" tcp
    manage_firewall "$SERVER_PORT" udp

    # Enable and start service
    systemctl daemon-reload >/dev/null 2>&1
    systemctl enable shadowsocks-libev >/dev/null 2>&1 || error_exit "Failed to enable shadowsocks service"
    systemctl restart shadowsocks-libev >/dev/null 2>&1 || error_exit "Failed to start shadowsocks service"

    # Verify service is running
    sleep 2
    if ! systemctl is-active --quiet shadowsocks-libev; then
        error_exit "Shadowsocks service failed to start"
    fi

    log "Shadowsocks installation completed successfully"
    echo "ss://${PUBLIC_IP}:${SERVER_PORT}:${METHOD}:${PASSWORD}"
}

# Install Squid HTTP Proxy with enhanced configuration
install_squid() {
    local USERNAME PASSWORD PORT
    
    log "Starting HTTP Proxy (Squid) installation"
    
    if [[ "$config_mode" = "1" ]]; then
        # Automatic mode
        USERNAME=$(generate_username)
        PASSWORD=$(generate_password 12)
        PORT=$(shuf -i 1025-65000 -n1)
        
        # Ensure port is not in use
        while ss -tuln | grep -q ":$PORT "; do
            PORT=$(shuf -i 1025-65000 -n1)
        done
    else
        # Manual mode
        get_manual_http_credentials
        USERNAME="$MANUAL_HTTP_USERNAME"
        PASSWORD="$MANUAL_HTTP_PASSWORD"
        PORT="$MANUAL_HTTP_PORT"
    fi

    # Install packages
    if [[ "$OS" = "debian" ]]; then
        install_packages squid apache2-utils curl
    else
        install_packages squid httpd-tools curl
    fi

    # Create password file
    htpasswd -cb /etc/squid/passwd "$USERNAME" "$PASSWORD" >/dev/null 2>&1 || error_exit "Failed to create password file"

    # Backup original config
    if [[ -f /etc/squid/squid.conf ]]; then
        cp /etc/squid/squid.conf "/etc/squid/squid.conf.bak.$(date +%F_%T)" >/dev/null 2>&1
    fi

    # Create enhanced Squid configuration
    cat > /etc/squid/squid.conf <<EOF
# Squid HTTP Proxy Configuration - Global Access

# Port configuration
http_port ${PORT}

# Authentication
auth_param basic program /usr/lib/squid/basic_ncsa_auth /etc/squid/passwd
auth_param basic children 5 startup=5 idle=1
auth_param basic realm Squid Proxy Server
auth_param basic credentialsttl 2 hours

# Access Control Lists
acl all_networks src 0.0.0.0/0          # Allow from anywhere
acl localnet src 10.0.0.0/8
acl localnet src 172.16.0.0/12
acl localnet src 192.168.0.0/16
acl localnet src fc00::/7
acl localnet src fe80::/10

acl SSL_ports port 443
acl Safe_ports port 80          # http
acl Safe_ports port 21          # ftp
acl Safe_ports port 443         # https
acl Safe_ports port 70          # gopher
acl Safe_ports port 210         # wais
acl Safe_ports port 1025-65535  # unregistered ports
acl Safe_ports port 280         # http-mgmt
acl Safe_ports port 488         # gss-http
acl Safe_ports port 591         # filemaker
acl Safe_ports port 777         # multiling http

acl CONNECT method CONNECT
acl authenticated proxy_auth REQUIRED

# Access rules - Allow global access with authentication
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access allow localhost manager
http_access deny manager
http_access allow authenticated all_networks
http_access deny all

# Security headers
reply_header_access X-Forwarded-For deny all
reply_header_access Via deny all
reply_header_access Cache-Control deny all

# Logging
access_log /var/log/squid/access.log squid
cache_log /var/log/squid/cache.log

# Cache configuration
cache_mem 256 MB
maximum_object_size_in_memory 512 KB
maximum_object_size 1024 MB
cache_dir ufs /var/spool/squid 1000 16 256

# DNS configuration
dns_nameservers 8.8.8.8 1.1.1.1 8.8.4.4 1.0.0.1

# Performance tuning
client_lifetime 1 hour
half_closed_clients off
pconn_timeout 60 seconds
request_timeout 60 seconds
persistent_request_timeout 30 seconds

# Privacy and security
forwarded_for delete
via off

# Refresh patterns
refresh_pattern ^ftp:           1440    20%     10080
refresh_pattern ^gopher:        1440    0%      1440
refresh_pattern -i (/cgi-bin/|\?) 0     0%      0
refresh_pattern .               0       20%     4320
EOF

    # Set permissions
    chmod 644 /etc/squid/squid.conf
    chmod 600 /etc/squid/passwd
    
    # Set ownership based on the system
    if id squid >/dev/null 2>&1; then
        chown squid:squid /etc/squid/passwd >/dev/null 2>&1
    elif id proxy >/dev/null 2>&1; then
        chown proxy:proxy /etc/squid/passwd >/dev/null 2>&1
    fi

    # Initialize cache directory
    squid -z >/dev/null 2>&1 || true

    # Configure firewall
    manage_firewall "$PORT" tcp

    # Enable and start service
    systemctl daemon-reload >/dev/null 2>&1
    systemctl enable squid >/dev/null 2>&1 || error_exit "Failed to enable squid service"
    systemctl restart squid >/dev/null 2>&1 || error_exit "Failed to start squid service"

    # Verify service is running
    sleep 3
    if ! systemctl is-active --quiet squid; then
        error_exit "Squid service failed to start"
    fi

    log "HTTP Proxy installation completed successfully"
    echo "http://${PUBLIC_IP}:${PORT}:${USERNAME}:${PASSWORD}"
}

# Main execution
main() {
    log "Starting proxy server installation script"
    
    # Initial checks
    check_root
    display_header
    detect_os
    get_network_info
    
    # User input
    prompt_user_choice
    prompt_config_mode
    
    # Installation based on choice
    case "$choice" in
        1)
            echo "🚀 Installing SOCKS5 server..."
            socks_info=$(install_socks5)
            draw_box "🧦 SOCKS5 PROXY SERVER" "$socks_info"
            ;;
        2)
            echo "🚀 Installing Shadowsocks server..."
            ss_info=$(install_shadowsocks)
            draw_box "👻 SHADOWSOCKS SERVER" "$ss_info"
            ;;
        3)
            echo "🚀 Installing HTTP Proxy server..."
            http_info=$(install_squid)
            draw_box "🌐 HTTP PROXY SERVER" "$http_info"
            ;;
        4)
            echo "🚀 Installing SOCKS5 + HTTP Proxy servers..."
            socks_info=$(install_socks5)
            http_info=$(install_squid)
            combined_info="${socks_info}\n${http_info}"
            draw_box "🚀 SOCKS5 + HTTP PROXY SERVERS" "$combined_info"
            ;;
        5)
            echo "🚀 Installing Shadowsocks + HTTP Proxy servers..."
            ss_info=$(install_shadowsocks)
            http_info=$(install_squid)
            combined_info="${ss_info}\n${http_info}"
            draw_box "🚀 SHADOWSOCKS + HTTP PROXY SERVERS" "$combined_info"
            ;;
        6)
            echo "🚀 Installing SOCKS5 + Shadowsocks servers..."
            socks_info=$(install_socks5)
            ss_info=$(install_shadowsocks)
            combined_info="${socks_info}\n${ss_info}"
            draw_box "🚀 SOCKS5 + SHADOWSOCKS SERVERS" "$combined_info"
            ;;
        7)
            echo "🚀 Installing all three servers..."
            socks_info=$(install_socks5)
            ss_info=$(install_shadowsocks)
            http_info=$(install_squid)
            combined_info="${socks_info}\n${ss_info}\n${http_info}"
            draw_box "🚀 ALL PROXY SERVERS INSTALLED" "$combined_info"
            ;;
        *)
            error_exit "Invalid choice: $choice"
            ;;
    esac
    
    # Final status check
    echo ""
    echo "🎉 Installation completed successfully!"
    echo "📝 Installation log saved to: /var/log/proxy-installer.log"
    echo ""
    echo "🔧 Service Management Commands:"
    case "$choice" in
        1|4|6|7) echo "   SOCKS5: systemctl {start|stop|restart|status} danted" ;;
    esac
    case "$choice" in
        2|5|6|7) echo "   Shadowsocks: systemctl {start|stop|restart|status} shadowsocks-libev" ;;
    esac
    case "$choice" in
        3|4|5|7) echo "   HTTP Proxy: systemctl {start|stop|restart|status} squid" ;;
    esac
    
    log "Installation script completed successfully"
}

# Execute main function
main "$@"
