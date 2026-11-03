# 🔑 AES 与哈希攻击全技巧

> CTF Crypto 补充：对称密码（AES/DES）与哈希的常见考点。对应课程 C3。

---

## 一、🟢 AES 基础与识别

```text
AES：分组 128bit（16 字节），密钥 128/192/256
模式：ECB / CBC / CTR / GCM —— 题目必给 iv 和 mode
pycryptodome 是标准工具库

识别：题目给 key + iv + 密文（hex/base64）→ 大概率 AES
```

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
key = b'0123456789abcdef'      # 16 字节
iv  = b'abcdefghijklmnop'
cipher = AES.new(key, AES.MODE_CBC, iv)
ct = cipher.encrypt(pad(b'flag{...}', 16))
# 解密
pt = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16)
```

---

## 二、🟡 ECB 模式攻击（最常考）

```text
ECB 特点：每个 16 字节块独立加密 → 相同明文块 = 相同密文块
考点①：密文块重排/删除 → 语义攻击（ECB penguin）
考点②：字节逐位爆破（oracle 泄露填充是否正确 → Padding Oracle）
考点③：图像 ECB 加密后还能看出轮廓 → 直接读图
```

### 2.1 Padding Oracle（经典）
```text
条件：服务端告诉你 padding 是否正确（返回差异）
效果：无需密钥逐字节解出明文
思路：篡改前一块密文，利用 padding 校验逐字节恢复中间值
工具：github.com/mpgn/Padding-oracle-attack
```

### 2.2 CBC 字节翻转攻击
```text
条件：CBC 解密 + 服务端校验明文内容（如检查 admin）
思路：修改前一块密文的对应字节 → 下一块明文按位翻转
target_byte = plain_byte XOR delta
```

---

## 三、🟡 哈希考点速查

| 考点 | 思路 | 工具 |
|---|---|---|
| MD5/SHA 碰撞 | fastcoll 生成同 hash 不同内容 | fastcoll |
| 长度扩展攻击 | hash(padded_msg + suffix) 可从 hash(msg) 推 | hash_extender |
| 哈希截断比较 | 爆破短哈希 | hashcat / 手写 |
| 弱随机 | mt_rand / random 预测 | 已知种子回推 |
| MD5 弱比较 | `==0` / `md5(a)==md5(b)` 数组绕过（PHP） | 见 PHP 审计篇 |

```python
# 长度扩展核心：append = glue_padding + suffix
# state = 原hash，构造 new_msg = msg || glue || suffix
# 工具：hash_extender --data ... --signature ... -s 32
```

---

## 四、🟡 其他对称/流密码

| 密码 | CTF 特征 | 攻击 |
|---|---|---|
| XOR | 密文 = 明文 ^ key，key 循环 | 已知明文（flag{）求 key / 重复密钥 XOR 分析 |
| RC4 | 流密码，key 可知 | 直接实现（20 行） |
| DES | 同 AES 结构，8 字节块 | 弱密钥/半块特性 |
| Hill/Playfair | 矩阵/双字母表 | 在线工具 dcode.fr |

```python
# 重复密钥 XOR：已知 flag{ 开头 → key 前 5 位 → 推周期 → 全解
ct = bytes.fromhex(open('ct.hex').read().strip())
key = bytes([ct[i] ^ b'flag{'[i] for i in range(5)])
pt = bytes([c ^ key[i % len(key)] for i, c in enumerate(ct)])
```

---

## 五、🔴 解题决策树

```text
Crypto 题拿到一堆 hex/base64：
1. 有 key/iv + 长度 16 倍数 → AES（看 mode）
2. 纯异或特征（明文可猜） → XOR 分析
3. 哈希比较类 → 见上表（PHP 绕过/碰撞/扩展）
4. 密文块重复 → ECB → 块攻击
5. n/e/c 大整数 → 见《RSA 攻击全技巧》
6. 都不是 → 回去查编码（见《编码与古典密码全技巧》）
```

---

## 六、练习题单（对应课程 C3）

- BUUCTF Crypto：Morning（XOR）、[GKCTF]HexString、临时文件夹
- CTFHub：信息中的 aes、ECB 系列题
- pycryptodome 官方示例 + CyberChef 的 AES/Hash 分支
---

## 🎓 上课流程卡（C3 · AES 与哈希 · 120 分钟）

> 给讲师：非密码学背景可照卡讲。本课结构 = "一个主线（AES 用库解）+ 三个考点（ECB/哈希绕过/XOR）"，零数学推导。

**教学目标**：下课时学员能①用 pycryptodome 解一道给 key/iv 的 AES 题 ②识别 ECB 块重复特征 ③掌握 flag{ 已知明文 XOR 攻击。

**课前准备**：
- 发脚本包：AES 解密模板 + XOR 分析脚本
- 准备 3 道练习：给 key/iv 的 AES-CBC 题、XOR 题（flag{ 开头）、PHP md5 绕过题

| 时间 | 环节 | 讲师动作 |
|---|---|---|
| 0-10 | 导入 | "上节课 RSA 是数学题，这节课是填空题——题目会把 key 和 iv 直接给你，你只需要调对库" |
| 10-30 | 讲解+演示 | §一 AES 基础：16 字节分组/mode/key 三个词；现场跑解密模板（改 key/iv/密文三处就能出 flag）——强调"模板三改" |
| 30-50 | 讲解 | §二 ECB：密文块重复特征（现场展示两个相同块）；CBC 字节翻转讲思想（改前一块影响后一块）即可，演示可选 |
| 50-70 | 讲解+演示 | §三 哈希考点：重点两个——MD5 弱比较（PHP `==` 绕过，0e 开头魔法哈希）+ 已知明文 XOR；长度扩展提概念不展开 |
| 70-110 | 实操 | 三道题：①AES-CBC 模板三改 ②XOR 已知明文攻击 ③PHP md5 绕过（非密码学，但本课统一收）。巡场重点：key 必须 bytes 字面量（b''）、padding 报错（unpad 的长度问题）、XOR 脚本索引越界 |
| 110-120 | 收口 | 过 §五 决策树 + 布置作业：BUUCTF Morning + CTFHub AES 题 |

**学员常见卡点（预判）**：
1. key/iv 字符串没加 b 前缀 → Python3 高频，模板里注释标红
2. unpad 报错 → 明文长度不是 16 倍数/填充错，教先打印 len
3. XOR 找不到 key 周期 → 教"已知明文对齐"：flag{ 五个字符对前五位
4. ECB 特征看不出来 → 教 hex 编辑器分块看，或 CyberChef 分块高亮

**被问倒的兜底**：AES 内部轮函数/为什么不安全 → "AES 本身没被攻破，考的是使用方式（mode/key 管理）——内部结构是密码学专业的课，CTF 只考你怎么用错它"。