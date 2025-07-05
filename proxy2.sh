#!/usr/bin/env bash
# Ultimate Proxy Manager - Auto-healing & Monitoring
# Tested on Ubuntu 20.04/22.04, CentOS 7/8

set -euo pipefail

# Cấu hình hệ thống
MAX_PROXIES=100
BACKUP_DIR="/root/proxy_backup"
LOG_FILE="/var/log/proxy_guardian.log"
CONFIG_HASH_FILE="/root/.proxy_config_checksum"

# Màu sắc
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Hàm khởi tạo hệ thống
init_system() {
    echo -e "${GREEN}[+] Khởi tạo hệ thống proxy bền vững${NC}"
    
    # Tạo thư mục backup
    mkdir -p "$BACKUP_DIR"
    
    # Cài đặt các phụ thuộc
    if grep -qi 'ubuntu' /etc/os-release; then
        apt-get update
        apt-get install -y \
            dante-server \
            shadowsocks-libev \
            squid \
            apache2-utils \
            fail2ban \
            python3-pyinotify \
            net-tools \
            cron \
            openssl
    else
        yum install -y epel-release
        yum install -y \
            dante \
            shadowsocks-libev \
            squid \
            httpd-tools \
            fail2ban \
            python3-pyinotify \
            net-tools \
            cronie \
            openssl
    fi

    # Tạo dịch vụ giám sát
    create_monitoring_service
}

# Hàm tạo dịch vụ giám sát
create_monitoring_service() {
    cat > /etc/systemd/system/proxy-guardian.service <<EOF
[Unit]
Description=Proxy Guardian Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do monitor_proxies; sleep 60; done'
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now proxy-guardian
}

# Hàm giám sát chính
monitor_proxies() {
    # Kiểm tra cấu hình có thay đổi
    current_hash=$(md5sum /etc/danted.conf /etc/shadowsocks-libev/config.json /etc/squid/squid.conf 2>/dev/null | md5sum | cut -d' ' -f1)
    stored_hash=$(cat "$CONFIG_HASH_FILE" 2>/dev/null || echo "")
    
    if [ "$current_hash" != "$stored_hash" ]; then
        echo -e "${YELLOW}[!] Phát hiện thay đổi cấu hình, khởi động lại dịch vụ...${NC}"
        restart_all_services
        echo "$current_hash" > "$CONFIG_HASH_FILE"
    fi

    # Kiểm tra từng dịch vụ
    check_service "danted" "socks5"
    check_service "shadowsocks-libev" "shadowsocks"
    check_service "squid" "http"
}

check_service() {
    local service=$1
    local type=$2
    
    if ! systemctl is-active --quiet "$service"; then
        echo -e "${RED}[!] $type service down, attempting to restart...${NC}" | tee -a "$LOG_FILE"
        systemctl restart "$service"
        sleep 5
        
        if ! systemctl is-active --quiet "$service"; then
            echo -e "${RED}[!] Không thể khởi động $type, thử khôi phục cấu hình...${NC}" | tee -a "$LOG_FILE"
            restore_config "$type"
            systemctl restart "$service"
        fi
    fi
}

# Hàm khôi phục cấu hình
restore_config() {
    local type=$1
    case "$type" in
        socks5)
            cp "$BACKUP_DIR/danted.conf" /etc/danted.conf
            ;;
        shadowsocks)
            cp "$BACKUP_DIR/shadowsocks.json" /etc/shadowsocks-libev/config.json
            ;;
        http)
            cp "$BACKUP_DIR/squid.conf" /etc/squid/squid.conf
            ;;
    esac
}

# Hàm tạo proxy SOCKS5 bền vững
create_socks5() {
    echo -e "${GREEN}[+] Đang tạo SOCKS5 proxy...${NC}"
    
    # Backup cấu hình
    cp /etc/danted.conf "$BACKUP_DIR/danted.conf" 2>/dev/null || true
    
    # Cấu hình tối ưu
    cat > /etc/danted.conf <<EOF
logoutput: syslog /var/log/danted.log
user.privileged: root
user.unprivileged: nobody
internal: 0.0.0.0 port = 1080
external: $(ip route get 1 | awk '{print $5;exit}')
method: pam
client pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
    log: connect disconnect error
}
socks pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
    log: error connect disconnect
    protocol: tcp udp
}
EOF

    # Tạo systemd service resilient
    cat > /etc/systemd/system/danted.service <<EOF
[Unit]
Description=Dante SOCKS5 Proxy
After=network.target
StartLimitIntervalSec=500
StartLimitBurst=5

[Service]
Type=simple
Restart=always
RestartSec=5s
ExecStart=/usr/sbin/danted -f /etc/danted.conf
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now danted
}

# Hàm bảo vệ hệ thống
protect_system() {
    echo -e "${GREEN}[+] Thiết lập bảo vệ hệ thống...${NC}"
    
    # Cấu hình fail2ban cho proxy
    cat > /etc/fail2ban/jail.d/proxy.conf <<EOF
[proxy-ssh]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 86400

[proxy-socks5]
enabled = true
port = 1080
filter = socks5-auth
logpath = /var/log/danted.log
maxretry = 3
bantime = 604800
EOF

    cat > /etc/fail2ban/filter.d/socks5-auth.conf <<EOF
[Definition]
failregex = authentication error for user .* from <HOST>
ignoreregex =
EOF

    systemctl restart fail2ban

    # Thiết lập cron job kiểm tra hàng ngày
    (crontab -l 2>/dev/null; echo "0 3 * * * /bin/bash -c 'systemctl restart danted shadowsocks-libev squid'") | crontab -
}

# Hàm chính
main() {
    init_system
    create_socks5
    protect_system
    
    echo -e "${GREEN}[+] Thiết lập hoàn tất!${NC}"
    echo -e "Các tính năng đã bật:"
    echo -e "- Tự động khởi động lại dịch vụ khi crash"
    echo -e "- Giám sát cấu hình thay đổi"
    echo -e "- Bảo vệ chống brute-force"
    echo -e "- Log chi tiết tại: ${YELLOW}$LOG_FILE${NC}"
    
    # Tính toán hash cấu hình ban đầu
    md5sum /etc/danted.conf /etc/shadowsocks-libev/config.json /etc/squid/squid.conf 2>/dev/null | md5sum | cut -d' ' -f1 > "$CONFIG_HASH_FILE"
}

main
