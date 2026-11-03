# 🔍 逆向分析入门全技巧

> Reverse 方向入门：静态分析 + 动态调试。对应课程 R1-R2。逆向的本质：把二进制还原成"人在思维上能理解的逻辑"，然后找出正确的输入（flag）或绕过校验。

---

## 一、🟢 基础知识地图

### 1.1 两种二进制格式

| | Windows (PE) | Linux (ELF) |
|---|---|---|
| 可执行 | .exe | 无后缀 ELF |
| 动态库 | .dll | .so |
| 静态库 | .lib | .a |
| 查看工具 | CFF Explorer / PE-bear | `readelf -a` / `checksec` |
| 关键节 | .text .data .rdata .rsrc | .text .data .rodata .bss |

### 1.2 CTF 逆向常见编译环境
```text
C/C++ → gcc/MSVC（最常见）
Go → 符号巨大，字符串特征明显（go.buildid）
Python → pyinstaller 打包（解包：pyinstxtractor → 反编译 pyc：uncompyle6）
Rust/Java（jar → jd-gui）
```

---

## 二、🟢 静态分析

### 2.1 第一步永远是这三个命令
```bash
file flag.exe              # 确认类型/位数/静态动态
strings flag.exe | grep -i flag   # 碰运气（老出 flag）
checksec flag              # Linux 保护机制（与 pwn 通用）
```

### 2.2 IDA / Ghidra 上手

```text
IDA（ industry 标准，免费版 IDA Free）：
  F5   → 反编译为伪 C 代码（核心技能）
  空格 → 图形/文本视图切换
  shift+F12 → 字符串窗口（找 flag / Wrong / Success）
  X    → 交叉引用（谁调用了这个函数/谁引用了字符串）
  N    → 重命名变量/函数（把 a1 v3 改成人话）
  G    → 跳转地址

Ghidra（免费开源）：
  几乎同 IDA 的功能集，反编译窗口 Search -> For Strings
```

### 2.3 🟢 静态找 main 的套路
```text
1. shift+F12 搜字符串："Wrong" "Correct" "flag{"
2. 交叉引用到校验函数
3. F5 看伪代码：理解校验逻辑
4. 常见结构：输入 → 变换（加密/异或/置换）→ 与硬编码比较
5. 硬编码数据（一个数组/字符串）= 加密后的 flag → 逆向变换
```

---

## 三、🟢 动态调试

### 3.1 Windows：x64dbg
```text
F7 单步进入 / F8 单步跳过 / F9 运行 / F2 断点
右键 -> Follow in Dump（内存跟随）
字符串引用窗口 -> 找 Wrong/Correct -> 下断 -> 回溯
patch：改指令字节（jne → jmp / nop 掉跳转）直接绕过校验
```

### 3.2 Linux：gdb + pwndbg
```bash
gdb ./chall
b main / b *0x401234        # 断点
r < input.txt               # 带输入运行
ni / si                     # 单步
x/s $rdi                    # 看内存字符串
x/32xb $rsp                 # 看栈
cyclic 100                  # pwndbg 偏移计算
```

### 3.3 🟡 动态的思想
```text
静态看不懂 → 动态跑起来看：
  输入什么变化？哪里比较？比较的数据在内存里长什么样？
  校验前内存 dump：flag 可能在运行时才解密/生成
  → 在比较处下断，直接从内存拿 flag（不用懂算法）
```

---

## 四、🟡 常见保护与反调试（入门级）

| 手法 | 识别 | 应对 |
|---|---|---|
| 反调试（IsDebuggerPresent） | 运行即退出/弹窗 | x64dbg 选项隐藏调试器 / patch 返回值 |
| 花指令 | IDA 反编译失败/错位 | 找垃圾字节 nop 掉，重新分析 |
| OLLVM 控制流平坦化 | 巨大 switch 主循环 | deflat 脚本 / 动态跑 |
| 加壳 | UPX（`upx -d`）/ section 异常 | 脱壳后重分析 |

---

## 五、🔴 快速解题决策树

```text
1. strings 找 flag → 有就完事
2. pyinstaller？→ pyinstxtractor + uncompyle6 直接读源码
3. IDA F5 伪代码可读？→ 分析校验逻辑 → 逆向算法（脚本还原）
4. 算法复杂？→ 动态调试在比较处 dump 内存
5. 只判断对错（不输出 flag）？→ patch 跳转 / 约束求解
6. angr 符号执行：自动求出使路径到达 Correct 的输入
   import angr; p=angr.Project('./chall') ... （对付复杂校验的自动化神器）
```

---

## 六、工具速查表

| 工具 | 用途 |
|---|---|
| IDA / Ghidra | 反编译主力 |
| x64dbg / gdb-pwndbg | 动态调试 |
| pyinstxtractor + uncompyle6 | Python 逆向 |
| upx -d | 脱壳 |
| angr | 符号执行自动化 |
| die（Detect It Easy） | 查壳/编译器 |
| CyberChef | 数据变换辅助 |

---

## 七、练习题单（对应课程 R1-R2）

- BUUCTF Reverse 入门区：re1（ida 里的 xor）、re2（jz/jnz patch）、easyre
- 攻防世界 RE 新手区：hello world、open-source、simple-unpack
- picoCTF Reverse 系列（英文友好入门）
- CTFHub 技能树：Reverse（IDA/静态分析/动态调试分支）

> 进阶套路 → 见《逆向套路与算法还原全技巧》
---

## 🎓 上课流程卡（R1+R2 · 逆向入门 · 两课时 2×120 分钟）

> 给讲师：逆向是最容易"讲师讲得爽学员听天书"的课。本卡的核心纪律：**每讲一个工具动作，学员必须同步操作一次**。工具：IDA Free + x64dbg（Windows）/ gdb-pwndbg（Linux）。

**教学目标**：下课时学员能①独立完成 strings→IDA F5→读懂一个简单校验逻辑 ②用 x64dbg 在比较处下断并改跳转绕过。

**课前准备**：
- 发题包：3 个入门 exe（一个 strings 有 flag、一个简单 xor 校验、一个 patch 题）——**全部用 32 位**（64 位对新手多一些无关干扰）
- 自己预打全部 3 题 + 准备每题的 IDA F5 截图

### 第一课时（R1 静态）：

| 时间 | 环节 | 讲师动作 |
|---|---|---|
| 0-10 | 导入 | 演示：一个 exe，strings 直接拖出 flag——"逆向第一步永远不花钱" |
| 10-35 | 讲解+跟做 | §一 格式地图（PE/ELF 只讲概念 5 分钟）+ §二 IDA 三板斧：shift+F12 字符串 → X 交叉引用 → F5 伪代码。**学员同步对同一个 exe 操作** |
| 35-60 | 讲解+跟做 | 读懂伪代码：带学员逐行看一个 xor 校验函数（变量重命名 N 键示范：a1→input, v3→enc） |
| 60-110 | 实操 | 两题：①strings/IDA 直接拿 flag ②xor 校验题（读逻辑→写 3 行 Python 还原）。巡场重点：IDA Free 装 F5 插件问题、伪代码里数组下标看不懂（教鼠标悬停看类型）、Python 还原时 signed/unsigned |
| 110-120 | 收口 | 总结"静态三板斧"+ 预告下节课动态调试 |

### 第二课时（R2 动态）：

| 时间 | 环节 | 讲师动作 |
|---|---|---|
| 0-15 | 导入 | 演示：一道静态看不懂（OLLVM 花指令）的题 → x64dbg 字符串引用 → 比较处断点 → 内存里直接躺着一个解密好的 flag。"看不懂算法没关系，等它算完" |
| 15-45 | 讲解+跟做 | §三 x64dbg 四键教学：F2/F7/F8/F9 + 字符串引用窗口 + patch（jne→jmp/nop）。**每个动作学员跟做一次** |
| 45-110 | 实操 | 两题：①patch 绕过校验题（改跳转）②动态 dump 题（比较处内存拿 flag）。巡场重点：x64dbg 找不到字符串引用（教先运行起来再搜）、patch 后保存文件（Edit-Patch-Patch All）、gdb 学员卡在命令（给 pwndbg 常用命令小抄） |
| 110-120 | 收口 | 过 §五 决策树 + 布置作业：BUUCTF re1+re2 |

**学员常见卡点（预判）**：
1. IDA F5 反编译失败/一片红 → 花指令或免费版限制，本课直接换题（别现场脱坑）
2. x64dbg 改了跳转没效果 → 忘了 Patch All 保存 / 改的是调试内存不是文件
3. 汇编看不懂恐慌 → 明说：本课只需要认识 jne/jmp/cmp 三个词，其余交给 F5
4. "逆向是不是要学很久" → 入门题三板斧一天能会，进阶才需要积累（正好接 R3-R4）

**被问倒的兜底**：某学员问高级混淆/VMProtect → "脱壳和 VM 还原是进阶 R3-R4 和以后的事，本期要求是把三板斧用熟——你先把入门三题都独立解出来"。