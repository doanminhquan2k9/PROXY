# 🛡️ Shadowsocks-libev Auto Installer Script
[**Support** Tele Cr4ckpwd/ARRAY CYBER MMO](https://t.me/cr4ckpwd)

Một script đơn giản để cài đặt **Shadowsocks-libev** trên máy chủ Ubuntu/Debian, với các tính năng:
- Tự động random password (16 ký tự)
- Tự động random port (10000–60000)
- Luôn dùng địa chỉ **IPv4**
- Tự động mở port (qua `ufw` hoặc `iptables`)
- In thông tin cấu hình và tạo mã QR code

## 📥 Cài đặt

```bash
curl -O https://gitlab.com/mikproxylink/one-click-shadowsocks/-/raw/main/install.sh
chmod +x install.sh
sudo ./install.sh
```

> ⚠️ Cần quyền `sudo`

## ☁️ Cài đặt tự động qua Amazon EC2 (User Data)

Khi tạo EC2 instance mới, bạn có thể dán đoạn sau vào ô **User data** để tự động cài SOCKS5 (Dante) với thông tin cố định:

```bash
#!/bin/bash
curl -O https://gitlab.com/mikproxylink/one-click-shadowsocks/-/raw/main/install.sh
chmod +x install.sh
echo -e "1\n2\n8888\nUSER_HERE\nPASS_HERE" | ./install.sh
```

- `1` = Cài SOCKS5 (Dante)  
- `2` = Cấu hình thủ công  
- `8888` = Port  
- `USER_HERE` = Username  
- `PASS_HERE` = Password  

> 📌 Lưu ý:
> - Không cần dùng `sudo` vì EC2 User Data đã chạy với quyền root.  
> - Đảm bảo **mở cổng 8888 (TCP)** trong Security Group.

---

Nếu bạn muốn script tự động gửi thông tin qua Telegram, hãy dùng đoạn bên dưới:

```bash
#!/bin/bash
# Tải script aws.sh về và cấp quyền thực thi
curl -O https://gitlab.com/mikproxylink/one-click-shadowsocks/-/raw/main/aws.sh
chmod +x aws.sh

# Chạy aws.sh tự động với:
# 1 = Cài SOCKS5 (Dante)
# 2 = Cấu hình thủ công
# 1 = Nhận thông báo Telegram
# Bot Token: 7557122184:AAF2NyHAEATM-dU40vCEAZPG-zzGtvHz_nU
# User ID: 1810862844
# Port: 7777 #Change your port
# Username: vunghiabui # Change your user
# Password: 123456 # Change your password
echo -e "1\n2\n1\nTELEGRAM_BOT_TOKEN_HERE\nTELEGRAM_ID_HERE\nPORT_HERE\nUSER_HERE\nPASS_HERE\n" | bash aws.sh
```

> 📌 Lưu ý:
> - Không cần dùng `sudo` vì EC2 User Data đã chạy với quyền root.  
> - Đảm bảo **mở cổng 7777 (TCP)** trong Security Group để SOCKS5 truy cập.

## 📋 Ví dụ kết quả

```text
🔧 Installing SOCKS5 proxy...
✅ Telegram notification sent successfully

=== SOCKS5 PROXY INSTALLED ===
123.45.67.89:7777:vunghiabui:123456

🎉 Installation completed successfully!
📱 Connection details have been sent to your Telegram!
```

## 🧱 Yêu cầu

- Ubuntu hoặc Debian (Debian 10/11 hoặc Ubuntu 18.04+)
- Có `sudo` quyền (trừ khi chạy qua EC2 User Data)
- Internet

## 🛠 Script chứa

- Cài `shadowsocks-libev`, `qrencode`
- Tạo file config `/etc/shadowsocks-libev/config.json`
- Khởi động dịch vụ
- In mã QR cho scan app Shadowsocks (nếu chọn Shadowsocks)
- Tích hợp gửi thông tin kết nối qua Telegram (nếu chọn)

## 🧰 Tham khảo

- [Shadowsocks-libev GitHub](https://github.com/shadowsocks/shadowsocks-libev)
- [QRencode](https://fukuchi.org/works/qrencode/)

## 📄 License

MIT
