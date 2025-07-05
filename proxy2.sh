#!/usr/bin/env bash
# Proxy Creator - Stable Version with Auto-Healing
# Tested on Ubuntu/Debian/CentOS

set -euo pipefail

# Config
MAX_PROXIES=200  # Giới hạn an toàn
BACKUP_DIR="/root/proxy_backup"
LOG_FILE="/var/log/proxy_keeper.log"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Hàm giám sát tự động
monitor_proxies() {
    while true; do
        # Kiểm tra SOCKS5
        if [[ $(systemctl is-active danted) != "active" ]]; then
            echo -e "${RED}[$(date)] SOCKS5 Service Down - Restarting...${NC}" | tee -a $LOG_FILE
            systemctl restart danted
        fi

        # Kiểm tra Shadowsocks
        for service in $(systemctl list-units --type=service | grep shadowsocks | awk '{print $1}'); do
            if [[ $(systemctl is-active $service) != "active" ]]; then
                echo -e "${RED}[$(date)] $service Down - Restarting...${NC}" | tee -a $LOG_FILE
                systemctl restart $service
            fi
        done

        # Kiểm tra Squid
        if [[ $(systemctl is-active squid) != "active" ]]; then
            echo -e "${RED}[$(date)] Squid Service Down - Restarting...${NC}" | tee -a $LOG_FILE
            systemctl restart squid
        fi

        sleep 60  # Kiểm tra mỗi phút
    done
}

# Hàm tạo proxy bền vững
create_stable_proxy() {
    local type=$1
    local count=$2

    case $type in
        socks5)
            # Tạo config với failover
            cat > /etc/danted.conf <<EOF
logoutput: syslog
user.privileged: root
user.unprivileged: nobody
internal: 0.0.0.0 port = 1080
external: $(ip route get 1 | awk '{print $5;exit}')
method: pam
client pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
}
socks pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
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

[Install]
WantedBy=multi-user.target
EOF

            systemctl daemon-reload
            systemctl enable --now danted
            ;;
        shadowsocks)
            # Cấu hình Shadowsocks tự động sửa lỗi
            cat > /etc/shadowsocks-libev/config.json <<EOF
{
    "server":"0.0.0.0",
    "mode":"tcp_and_udp",
    "server_port":8388,
    "local_port":1080,
    "password":"$(tr -dc A-Za-z0-9 </dev/urandom | head -c 16)",
    "timeout":300,
    "method":"aes-256-gcm",
    "fast_open":true,
    "reuse_port":true,
    "no_delay":true
}
EOF

            systemctl restart shadowsocks-libev
            ;;
        http)
            # Cấu hình Squid ổn định
            cat > /etc/squid/squid.conf <<EOF
acl localnet src 0.0.0.0/0
http_access allow localnet
http_port 3128
cache deny all
max_filedesc 8192
workers $(nproc)
EOF

            systemctl restart squid
            ;;
    esac
}

# Hàm bảo vệ cổng
protect_ports() {
    # Cài đặt fail2ban cho các cổng proxy
    apt-get install -y fail2ban
    cat > /etc/fail2ban/jail.d/proxy.conf <<EOF
[sshd]
enabled = true
port = $(grep -oP "port\s*=\s*\K[0-9]+" /etc/danted.conf)
logpath = /var/log/auth.log
maxretry = 3
bantime = 86400
EOF
    systemctl restart fail2ban
}

# Hàm chính
main() {
    # Tạo thư mục backup
    mkdir -p $BACKUP_DIR

    # Cài đặt các gói cần thiết
    apt-get update
    apt-get install -y \
        dante-server \
        shadowsocks-libev \
        squid \
        apache2-utils \
        curl \
        net-tools

    # Bật giám sát tự động (chạy nền)
    monitor_proxies &

    # Tạo proxy
    create_stable_proxy "socks5" 10
    create_stable_proxy "shadowsocks" 5
    create_stable_proxy "http" 5

    # Bảo vệ cổng
    protect_ports

    echo -e "${GREEN}Proxy đã được tạo thành công với cơ chế tự động sửa lỗi!${NC}"
    echo -e "Xem log tại: ${YELLOW}$LOG_FILE${NC}"
}

main
