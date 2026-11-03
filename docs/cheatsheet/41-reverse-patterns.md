# 🧩 逆向套路与算法还原全技巧

> Reverse 进阶：入门赛后常见的校验逻辑套路、算法识别与还原方法。对应课程 R3-R4。

---

## 一、🟢 经典校验结构（80% 入门题的形状）

```c
// 万年不变的三段式：
scanf("%s", input);
transform(input);              // ① 变换函数（加密/异或/置换）
if (memcmp(input, enc_data, len) == 0)  // ② 与硬编码比较
    puts("Correct!");

// 解题 = 逆着 ① 写：enc_data --逆变换--> flag
```

### 1.1 常见变换识别表

| 变换 | 伪代码特征 | 还原 |
|---|---|---|
| 单字节 XOR | `input[i] ^ key` | 再异或一次（自反） |
| 加减 | `input[i] + i` / `+key` | 反向减 |
| 大小写/位运算 | `^0x20`、`>>2`、`<<1` 溢出 | 注意溢出截断 |
| Base64 自定义表 | 查表 + 移位 + 6bit | 找到表 → 改 CyberChef 表 |
| TEA/XTEA | 轮循环 + delta 0x9E3779B9 | 脚本逆向轮 |
| MD5/AES 调用 | magic number（0x67452301 等） | 直接调库解（key 在代码里）|
| 置换/移位 | 下标重排数组 | 写逆置换 |

---

## 二、🟡 标准还原流程（四步法）

```text
1. 提取硬编码数据（IDA 里 shift+E 导出数组 / 数据窗口 dump）
2. 精读变换函数（F5 伪代码逐行，不确定的动态验证）
3. 写 Python 逆脚本（从输出倒推输入）
4. 验证：把 flag 输回程序 / 与程序正向加密结果对比

# 动态验证技巧：改程序！把 memcmp 改成 printf 输出中间数组
# patch 后运行 = 白嫖正向加密器（逆不出来时反着用）
```

---

## 三、🟡 常见套路集

### 3.1 反调试 + 反模拟
```c
IsDebuggerPresent() / ptrace(PTRACE_TRACEME)   # 发现调试器就退出
# 对策：patch 跳转 / LD_PRELOAD 覆盖 ptrace / 改标志位
```

### 3.2 多层嵌套与调度器
```text
控制流平坦化（巨大 switch(state)）→ 记录 state 序列 → 手动/脚本跟一遍
状态机逆推：从 Correct 状态反向找路径（DFS）
```

### 3.3 Python 逆向（高频道）
```bash
pyinstxtractor.py flag.exe          # 解包 pyc
uncompyle6 / decompyle3 flag.pyc    # 反编译成源码
# pyc 头被抹：补 magic number（16 字节头）
# marshal 版本错：用对应 Python 版本的反编译
```

### 3.4 迷宫/模拟类
```text
题目：读入移动序列，走出迷宫 / 虚拟机执行字节码
思路：
  迷宫 → 从终点 BFS/DFS 反推路径
  自定义虚拟机（VM） → 提取 opcode 表 → 写解释器 → 自动求解
```

### 3.5 🔵 angr 符号执行（自动化神器）
```python
import angr
p = angr.Project('./chall', auto_load_libs=False)
st = p.factory.entry_state()
sim = p.factory.simulation_manager(st)
sim.explore(find=lambda s: b'Correct' in s.posix.dumps(1),
            avoid=lambda s: b'Wrong' in s.posix.dumps(1))
if sim.found:
    print(sim.found[0].posix.dumps(0))   # 输入！
```

---

## 四、🟡 算法特征识别速查

| 特征 | 算法 |
|---|---|
| delta = 0x9E3779B9 | TEA / XTEA / XXTEA |
| 0x67452301, 0xEFCDAB89... | MD5 |
| 0x6A09E667（8 个常数） | SHA256 |
| 255 长度查表 + 异或循环 | CRC |
| S 盒 0x63,0x7c,0x77... | AES |
| 固定表 {0x243F6A88...} | RC6/ Blowfish 类 |
| 大量位旋转 + 非线性 | 自研轻量算法（逆推即可） |

> 遇到标准算法 → 认出来直接调库；自研算法 → 老实逆推

---

## 五、🔴 决策树

```text
静态可读？→ 四步法还原
静态复杂？→ 动态 dump 比较点数据
算法认识？→ 调库直接解
标准算法魔改？→ 先试原版解密，不行再逆 delta
控制流平坦化？→ deflat / 动态跟
输入空间小？→ 爆破 / angr
二进制语言特殊（Go/Rust/Python）？→ 对应专门工具链
```

---

## 六、练习题单（对应课程 R3-R4）

- BUUCTF Reverse：[BJDCTF]JustRE、[ACTF]大一新生系列、findkey（迷宫）、[GWCTF]pyre（pyc）
- 攻防世界 RE 进阶：insanity 系列之后全部
- angr 官方示例 CTF 集（github.com/angr/angr-doc/examples）
- 推荐：crackmes.one 按难度刷（Windows patch 练习）
---

## 🎓 上课流程卡（R3+R4 · 逆向套路与算法还原 · 两课时 2×120 分钟）

> 给讲师：学员已会三板斧（F5/动态/patch）。本课教的是"认出套路 → 选还原路径"。核心演示三个：四步法还原一个 xor 题、pyc 反编译、angr 自动求解。

**教学目标**：下课时学员能①独立完成一道"变换→比较"题的完整四步法还原 ②用 pyinstxtractor 反编译一个 pyinstaller 程序 ③跑通一个 angr 模板。

**课前准备**：
- 发题包：xor 变换题、TEA 特征题、pyinstaller 打包题、angr 模板题
- 确认学员环境：uncompyle6 装好、angr 装（angr 安装慢，提前一天发指令装）

### 第一课时（R3 套路还原）：

| 时间 | 环节 | 讲师动作 |
|---|---|---|
| 0-10 | 导入 | "上节课你们会看程序了，这节课学认程序——80% 的逆向题长同一个样子"（投 §一 三段式） |
| 10-40 | 讲解+演示 | §一 变换识别表（重点 TEA 的 delta 魔数、Base64 自定义表）→ **现场演示四步法**：dump 数组→读变换→Python 逆推→回验（这是本课最重要 30 分钟，慢讲） |
| 40-70 | 讲解+演示 | §3.3 Python 逆向：pyinstxtractor 解包 → 补 pyc 头 → uncompyle6 出源码（现场完整走一遍，卡点在补头） |
| 70-110 | 实操 | 两题：①简单 xor/加减变换还原 ②pyinstaller 打包题。巡场重点：pyc 头补错版本（教查 Python 版本对应 magic）、逆推脚本方向写反（加密解密对称性） |
| 110-120 | 收口 | 过 §四 算法特征表（拍照页）+ 作业：BUUCTF pyre |

### 第二课时（R4 进阶套路+angr）：

| 时间 | 环节 | 讲师动作 |
|---|---|---|
| 0-15 | 导入 | 演示：一道多层校验题，静态逆推要一小时 → angr 跑 40 秒出输入——"自动化是逆向的作弊器，但要先懂原理才能喂它" |
| 15-40 | 讲解 | §3.5 angr 模板逐行讲（find/avoid 的写法）；§3.4 迷宫/VM 题讲思路（BFS 反推/写解释器） |
| 40-70 | 讲解+演示 | §3.1 反调试 + §3.2 平坦化：各演示一个识别特征（本环节"见过即达标"） |
| 70-110 | 实操 | 两题：①迷宫题（BFS 反推）②angr 模板题（改 find/avoid 字符串）。巡场重点：angr 装不上（劝退点：发预装镜像或 docker）、迷宫坐标系统搞反 |
| 110-120 | 收口 | 总结 Reverse 全线知识地图（R1-R4 串联）+ 布置作业：BUUCTF findkey + angr examples 一题 |

**学员常见卡点（预判）**：
1. 四步法第 2 步伪代码看不懂变换 → 教动态验证法（写个小程序调用同逻辑对比）
2. 逆推脚本加密解密搞反 → 教"先正向跑一遍对比密文"校验方向
3. pyc 反编译报语法错 → Python 版本不匹配，教用对应版本的 decompyle
4. angr 求解无结果 → find/avoid 条件写错或路径爆炸，教限制输入长度

**被问倒的兜底**：学员问 ARM/智能合约/游戏逆向 → "方向对但超纲，本课把 x86 思路打通后其他平台是一样的方法论+新工具链，感兴趣课后聊"。