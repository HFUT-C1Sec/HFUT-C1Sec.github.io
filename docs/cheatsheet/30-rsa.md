# 🔐 RSA 攻击全技巧

> CTF Crypto 主力考点。RSA 的题 90% 是数学题：看参数找弱点 → 选攻击 → 套脚本。对应课程 C2。

---

## 一、🟢 RSA 基础（5 分钟版）

```text
n = p*q        （模数，公开）
e              （公钥指数，常见 65537）
d ≡ e⁻¹ mod φ(n)（私钥，φ(n)=(p-1)(q-1)）
c = m^e mod n  （加密）
m = c^d mod n  （解密）

CTF 里拿到 n, e, c 求 m —— 本质：能不能求出 d，即能不能分解 n 或利用参数弱点。
```

```python
# 标准解密骨架（拿到 p q 后）
from Crypto.Util.number import long_to_bytes
p, q, e, c = ?, ?, 65537, ?
n = p * q
phi = (p-1) * (q-1)
d = pow(e, -1, phi)
m = pow(c, d, n)
print(long_to_bytes(m))
```

---

## 二、🟢 分解 n（第一步永远是它）

```bash
# 1. 在线查：factordb.com（90% 的 CTF n 都在里面）
# 2. yafu：本地分解（小因子/特殊形式）
./yafu "factor(1000007)"
# 3. sympy：试除小因子
python -c "from sympy import factorint; print(factorint(1000007))"
```

```python
# p 和 q 相邻 / 都在附近 → 费马分解
def fermat(n):
    import gmpy2
    a = gmpy2.isqrt(n)
    while True:
        a += 1
        b2 = a*a - n
        if gmpy2.is_square(b2):
            b = gmpy2.isqrt(b2)
            return int(a-b), int(a+b)
```

---

## 三、🟡 经典攻击速查（按参数弱点）

### 3.1 低指数攻击（e 很小，如 e=3）
```python
# m^e < n 时：直接开 e 次方
from gmpy2 import iroot
m = iroot(c, 3)[0]
# m^e 略超 n：加 k*n 后开方（遍历 k）
for k in range(1000):
    r = iroot(c + k*n, 3)
    if r[1]: m = r[0]; break
```

### 3.2 共模攻击（同 m，两个 e，同一 n）
```python
# 条件：n 相同，e1 e2 互质 → 扩展欧几里得求 s1 s2
# m = c1^s1 * c2^s2 mod n
from Crypto.Util.number import inverse
import gmpy2
def egcd(a, b):
    if b == 0: return (a, 1, 0)
    g, x, y = egcd(b, a % b)
    return (g, y, x - (a//b)*y)
g, s1, s2 = egcd(e1, e2)
m = (pow(c1, s1 if s1>0 else -s1, n) if s1>0 else inverse(pow(c1, -s1, n), n))
# 标准写法：m = pow(c1, s1, n) * pow(c2, s2, n) % n（s 为负时先求逆元）
```

### 3.3 Wiener 攻击（e 很大 + d 很小）
```python
# 特征：e 巨大（接近 n），q < p < 2q → 连分数展开
# 工具：github.com/pablocelayes/rsa-wiener-attack 或手写连分数
from fractions import Fraction
def wiener(e, n):
    cf = []
    x = Fraction(e, n)
    while x.numerator:
        cf.append(int(x))
        x = 1 / (x - int(x))
    # 连分数收敛项试 d ... （或直接用现成库）
```

### 3.4 给了多组线索的组合题
| 泄露 | 攻击 |
|---|---|
| dp 或 dq 泄露 | dp 泄露攻击（遍历 x：`p = gcd(pow(2, e*dp) - 2, n)`）|
| e1·e2 = φ(n) 或倍数 | e2 = k*φ+1 直接 m = c2^e' 结构 |
| n = p^q（平方数） | φ(n) = p*(p-1)，开方先 |
| p、q 有公共因子 | gcd(n1, n2) ≠ 1 |
| e 与 φ 不互质 | 先求 d'（对 g = gcd(e, φ)），再开 g 次方 |
| 明文 m 小且规律 | Bulk/短明文爆破 |

### 3.5 🔵 Coppersmith 入门
```python
# 已知 m 的高位/p 的高位 → 用 sage 的 small_roots
# 场景：leak = m >> 100（已知高 bit），未知低位 < n^(1/e)
# 工具：https://github.com/mimoo/RSA-and-LLL-attacks
```

---

## 四、🟡 OpenSSL/公钥文件处理

```bash
openssl rsa -pubin -in pubkey.pem -text -noout   # 从公钥文件提取 n、e
# n 拆两半 = p、q（p、q 相邻时）
```

---

## 五、🔴 攻击决策树

```text
拿到 n, e, c：
1. factordb 分解 n → 能分解 → 标准 decrypt
2. e=3/17 小 → 低指数/短明文
3. 多组 (n 相同, e 不同) → 共模
4. e 巨大 → Wiener
5. 给 dp/dq → dp 泄露攻击
6. n 是特殊形式（p²、相邻素数） → 费马/开方
7. 给高位泄露 → Coppersmith
8. 全都没有 → 回看题目描述（提示藏给了线索）
```

---

## 六、练习题单（对应课程 C2）

- BUUCTF Crypto：rsarsa、RSA、RSA1/2/3、RSA（dp 泄露）、rsa2
- CTFHub 技能树：RSA 全分支（低指数/共模/Wiener）
- 脚本库：**RsaCtfTool**（自动试攻击）、Cryptodome、gmpy2

> 前置：见《CTF Python 速成与脚本化》；对称密码 → 见《AES 与哈希攻击全技巧》
---

## 🎓 上课流程卡（C2 · RSA 攻击 · 120 分钟）

> 给讲师：非密码学背景可照卡讲。本课最大的风险是把学员讲跑——**全程不推导数学，只讲"看参数找弱点"**。RSA 在 CTF 里的真实体验是查表匹配，不是数学考试。

**教学目标**：下课时学员拿到一组 (n,e,c) 能按决策树独立处理 factordb 可解题和低指数题。

**课前准备**：
- 发脚本包：标准解密骨架 + 费马分解 + 共模模板（学员全程改参数复用）
- 学员环境验证：pycryptodome + gmpy2 装好（课前一天群里发检查脚本）
- 自己预跑全部 4 道练习题

| 时间 | 环节 | 讲师动作 |
|---|---|---|
| 0-15 | 导入 | "RSA 题在 CTF 里是数学题吗？不是，是填表题"——现场演示：拿一题扔进 factordb 直接分解 → 套骨架 30 秒出 flag。先建立"能做"的信心再讲原理 |
| 15-35 | 讲解 | §一 基础 5 分钟版（n/e/c/m 四个字母的关系，一句话版：能分解 n 就能解密）；§二 三个分解手段：factordb → yafu → 费马（**只演示操作，不推导为什么**） |
| 35-60 | 讲解+演示 | §三 攻击速查：重点演示两个——低指数（e=3 开立方）和共模（现场跑 egcd 脚本）；Wiener/dp 泄露讲到"识别特征"即可，模板已给 |
| 60-110 | 实操 | 题目阶梯：①factordb 直接分解题 ②费马题（p q 相邻）③低指数题 ④共模题。巡场重点：long_to_bytes 忘记调（打印出大整数吓到学员）、pow(e,-1,phi) 报错（Python 版本需 3.8+）、共模负指数处理 |
| 110-120 | 收口 | 过 §五 决策树（拍照页）+ 布置作业：BUUCTF rsarsa + RSA1 两题 |

**学员常见卡点（预判）**：
1. 被 "数学不好" 恐惧劝退 → 开课就明说：本课零数学推导，全部查表+模板
2. factordb 打不开/没分解结果 → 教 yafu 备选；都没有说明该题弱点不在分解，回决策树看 e
3. pow 报错 "base not invertible" → c 大于 n 或参数抄错，教打印检查 n,e,c
4. 解出大整数 → 忘 long_to_bytes，这是每届必犯，提前预告

**被问倒的兜底**：学员问"为什么 e 和 φ 互质"/"RSA 安全性证明" → "这门课的边界是把 RSA 当黑盒用：认参数、套模板、出 flag。想懂为什么，课后我给你推资料（注意：真感兴趣再给，别现场展开）"。