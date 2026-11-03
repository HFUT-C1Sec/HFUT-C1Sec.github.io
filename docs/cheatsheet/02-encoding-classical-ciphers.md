# 🔤 编码与古典密码全技巧

> CTF 第一课：拿到一串"看不懂的东西"，第一步永远是识别编码/密码类型。Misc 起手 + Crypto 入门的共同地基。

---

## 一、🟢 编码全家桶（可逆，无密钥）

### 1.1 Base 系列速查

| 编码 | 字符集 | 识别特征 |
|---|---|---|
| Base16 (Hex) | 0-9 A-F | 长度偶数，纯十六进制字符 |
| Base32 | A-Z 2-7 + = | 全大写字母+数字，尾部多个 = |
| Base58 | 比特币字母表（去 0OIl） | 无 +/ ，常见于币圈 |
| Base62 | 0-9a-zA-Z | 无符号，短串 |
| **Base64** | 0-9a-zA-Z+/ = | 尾部 1-2 个 = 填充，最常见 |
| Base85/Ascii85 | 更多符号 | `<!~>` 或 z 开头变体 |
| Base91 | 91 字符 | 混合符号 |

```python
import base64
base64.b64decode('ZmxhZ3tpc19oZXJlfQ==')
base64.b32decode('MZVWS5DINFZCA===')
# CyberChef 一步到位：From Base64 / Magic
```

### 1.2 其他常见编码

```text
URL 编码：%20 %41（%xx 形式，decodeURIComponent）
Unicode：\u4f60 或 &#20320;（HTML 实体）
HTML 实体：&amp; &lt; &#x41;
摩斯电码：. - / （在线表 + CyberChef From Morse）
敲击码（Tap code）：数字对 (2,3)=H，用 .. --- 格式表
猪圈密码：图形符号 → 查表
布尔/二进制：01000001 → 逐 8 位转 ASCII
 телефон/¥瞳文/火星文：查对应转换表
```

---

## 二、🟢 古典密码（有密钥/有规则，但非现代密码学）

### 2.1 移位类

```text
凯撒（Caesar）：整体移位 n 位 → 全 26 个偏移暴力试（CyberChef ROT13 Bruteforce）
ROT13：凯撒特例 n=13（英文字符串常见）
栅栏（Rail fence）：分 n 组之字重排 → 枚举组数
维吉尼亚（Vigenère）：密钥循环移位 → 已知开头（flag{）爆破密钥 / kasiski + 重合指数

工具：CyberChef、dcode.fr（最强古典密码站）、Vigenère Solver
```

### 2.2 替换类

```text
单表替换：字母频率分析（英文高频 e t a o）+ 词频 + quadgram 统计
  → https://www.guballa.de/substitution-solver 自动破
仿射密码：E(x)=(ax+b) mod 26，爆破 a(与26互质)×b 共 312 组
猪圈/圣堂武士：图形→查表
键盘密码：手机九宫格（数字对→字母）、键盘位移（GYBNQYURP→HELLOWORLD 位置偏移）
培根密码：A/B 五位一组（aaaaa=a ...）只 26 字母
```

### 2.3 图形/特殊密码速查表

| 密码 | 特征 | 破法 |
|---|---|---|
| 猪圈 | ∧>∪< 图形 | 查表 |
| 银河字母/标准 Galactic | 外星符号 | 查表 |
| 与佛论禅 | 佛曰： | 在线工具+密钥（通常"新佛曰"）|
| 当铺密码 | 汉字笔画出头数 | 数笔画→数字 |
| 盲文 | ⠺⠗ | 查表 |
| 舞动小人 | 小人图形 | 福尔摩斯查表 |

---

## 三、🟢 识别决策树（拿到密文第一步）

```text
1. 只含 0-9A-F，偶数长度 → Hex
2. 全大写 A-Z2-7 多个= → Base32
3. 含 + / 尾部 1-2 个 = → Base64
4. 纯点划/空格分隔 → 摩斯
5. 纯字母，像乱码但像英文 → 替换密码 → 频率分析/quipqiup
6. 移位后出现单词 → 凯撒/ROT
7. 有密钥提示（题目给词） → 维吉尼亚
8. 图形/符号 → 查表类（猪圈/盲文/银河）
9. 一串数字 → 电话键盘/ASCII/坐标
10. 中文乱码 → 编码套娃（GBK↔UTF8→Base64 套娃）

万金油：CyberChef -> Magic 模块自动猜 + 递归解码
```

---

## 四、🟡 编码套娃实战要点

```python
# 常见套娃：Base64 -> Hex -> Base32 -> 摩斯 -> 凯撒 -> flag
# 自动递归解：CyberChef「Magic」+「Recursive Recipe」
# 手写循环解（示例骨架）
import base64, codecs
data = open('cipher.txt').read().strip()
while True:
    if data.endswith('='): data = base64.b64decode(data).decode()
    elif all(c in '0123456789abcdef' for c in data): data = bytes.fromhex(data).decode()
    else: break
print(data)
```

---

## 五、练习题单（对应课程 1.4 / 关卡赛 I）

- 攻防世界 Misc 新手区：base64 风.data、青莲绿波、许多人
- BUUCTF：一眼就解密的、温暖的新星、Redis
- CTFHub 技能树：编码与古典密码全分支
- 工具：**CyberChef（必装）**、dcode.fr、quipqiup（替换密码自动破）

> 下一步：现代密码 → 见《RSA 攻击全技巧》《AES 与哈希攻击全技巧》
---

## 🎓 上课流程卡（1.4 下半 · 编码与古典密码 · 120 分钟）

> 给讲师：非密码学背景可照卡讲。本课零数学，全是"识别 → 套工具"——核心是把 CyberChef 用熟。

**教学目标**：下课时学员拿到一串密文能在 5 分钟内识别类型并解出 Base/摩斯/凯撒三件套。

**课前准备**：
- 全员浏览器收藏 CyberChef（gchq.github.io/CyberChef）+ dcode.fr
- 准备 6 道识别题的密文卡片（打印或投屏抢答）

| 时间 | 环节 | 讲师动作 |
|---|---|---|
| 0-10 | 导入 | 抢答游戏：投屏 6 段密文（Base64/Hex/摩斯/二进制/凯撒/Base32），让学员"看长相猜类型"——猜对不讲理由也表扬，建立信心 |
| 10-40 | 讲解 | §1.1 Base 系列速查表逐行过（重点 Base64 的 = 填充和 Base32 全大写特征）；现场 CyberChef From Base64/From Hex 演示 |
| 40-60 | 讲解 | §1.2 其他编码：URL/Unicode/摩斯——现场摩斯在线解码一个；敲击码/猪圈快速过（认识即可，查表解决） |
| 60-85 | 讲解+演示 | §二 古典密码：凯撒现场 ROT13 Bruteforce（CyberChef 一键枚举 26 位）；维吉尼亚讲思想即可（密钥循环），不推数学；替换密码演示 quipqiup 自动破英文 |
| 85-110 | 实操 | 学员做编码套娃题一题（Base64→Hex→摩斯三层）+ 凯撒题一题；巡场重点：CyberChef Recipe 拖拽顺序、套娃层数判断 |
| 110-120 | 收口 | 过 §三 识别决策树（拍照页）+ 布置作业：CTFHub 编码分支 + 每人自编一道三层套娃题互考 |

**学员常见卡点（预判）**：
1. Base64 解出来还是乱码 → 这是套娃，教"解一层看一眼类型"的节奏，别贪一步到位
2. Hex 判断错（把 Base64 当 Hex）→ 强调字符集范围检查：出现 g-z 就不可能是 Hex
3. 凯撒枚举 26 位没出英文 → 可能是维吉尼亚或不是英文语种，回到决策树
4. 古典密码图形类记不住 → 明说：不用背，考试现场查表（dcode.fr），考的是"想到去查"

**被问倒的兜底**：复杂置换密码/Enigma → "古典密码在现代比赛里是送分题方向，dcode.fr 能覆盖 95%，真遇到冷门的现场查表，这题考的是识别不是背诵"。

**给非密码学背景讲师的补充**：本课全程不涉及任何数学证明——"编码=无密钥可逆，古典=有规则可查表"这两句话讲清楚，学员就不会把 Crypto 想象成高数课。真正的 Crypto 在 C1-C4（RSA 那几课）才出现。