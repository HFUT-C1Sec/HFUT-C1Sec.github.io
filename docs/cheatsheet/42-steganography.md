# 🖼️ 隐写术全技巧

> CTF Misc 方向核心技能。隐写 = 把信息藏进正常载体（图片/音频/视频/文档）。入门赛题最高频考点，第一血最常见出处。

---

## 一、🟢 图片隐写

### 1.1 文件结构附加（最常见）
图片尾部追加压缩包/文本——文件头尾之间藏数据。

```bash
# 识别：看文件尾之后有没有多余数据
# PNG 尾标识: 49 45 4E 44 AE (IEND)
# JPG 尾标识: FF D9
binwalk flag.png            # 自动识别嵌入文件
binwalk -e flag.png         # 自动提取
foremost flag.png           # 备用提取工具

# 手动分离（python）
with open('flag.png','rb') as f: data = f.read()
idx = data.find(b'IEND')
open('out.zip','wb').write(data[idx+8:])
```

### 1.2 LSB（最低有效位）隐写
像素最低位改动肉眼不可见，一张图藏一张图/文本。

```bash
# 工具三件套
zsteg flag.png              # BMP/PNG LSB 自动检测（ruby）
stegsolve                    # Java 图形化：通道分离/色阶/帧查看
python -c "from PIL import Image; im=Image.open('f.png'); print(im.mode)"

# stegsolve 关键操作：
# Analyze -> Data Extract：勾选 R/G/B 的 0 位（LSB），按行/列序导出
# Analyze -> Colour Inversion / Bit Planes：翻通道看隐藏图层
```

```python
# 手写 LSB 提取
from PIL import Image
im = Image.open('flag.png')
pix = list(im.getdata())
bits = ''.join(str(p & 1) for p in pix[:8*100])
print(''.join(chr(int(bits[i:i+8],2)) for i in range(0,len(bits),8)))
```

### 1.3 PNG/IPUS 特殊结构
- **PNG**：关注辅助数据块 tEXt / zTXt / ITXt（可能直接藏 flag）、宽高被改（CRC 报错 → 用脚本爆破正确宽高恢复图像）
- **GIF**：多帧分离（stegsolve -> Frame Browser / identify 命令），帧间隔藏信息
- **JPG**：steghide（需要密码，先爆破）、outguess、F5

```bash
# PNG 宽高爆破：改 IHDR 后 CRC 校验失败 → 爆破正确宽高
steghide extract -sf flag.jpg -p 123456
stegcracker flag.jpg rockyou.txt
```

---

## 二、🟢 音频隐写

| 工具 | 场景 | 要点 |
|---|---|---|
| **Audacity** | 频谱图 | 拉出频谱视图（Spectrogram），flag 可能直接写在频谱上 |
| **MP3Stego** | MP3 | extract 需要密码 |
| **steghide** | WAV | 同 JPG 用法 |
| **Morse 音频** | 滴滴声 | 听/看波形识别摩斯电码 |
| **DeepSound** | WAV | 图形化提取 |

```bash
# Audacity：File -> Import -> 拉 spectrogram 视图
# 波形幅度异常（某一段突然规律起伏）= 藏了摩斯/数据
```

---

## 三、🟡 其他载体速查

| 载体 | 工具/手法 | 特征 |
|---|---|---|
| PDF | pdftotext、binwalk、PDF Stream Dumper | 附件嵌入、JS、不可见图层 |
| Word/Excel | 改后缀 zip 解包、宏分析 | document.xml 藏文本、vbaProject.bin 宏 |
| 视频 | 分帧（ffmpeg）、音轨分离 | 帧里藏二维码、音轨藏摩斯 |
| 压缩包 | 伪加密（改标志位）、明文攻击、CRC 爆破 | 见《压缩包攻防》|
| 文本 | 零宽字符、SNOW、字体隐写 | 在线零宽检测工具 |
| NTFS 流 | `dir /r`、Alternate Data Streams | Windows 特有 |

---

## 四、🟡 零宽字符与文本隐写

```text
零宽字符：U+200B / U+200C / U+200D / U+FEFF
肉眼不可见，复制进在线检测器（330k.dev/zerowidth）解码
SNOW：行尾空格 TAB 藏信息，`snow -C -p 密码 file`
```

---

## 五、🔴 通用解题流程（决策树）

```text
拿到文件
1. file 命令确认真实类型 → 类型不符先改后缀
2. binwalk / foremost → 有嵌入文件直接分离
3. strings + grep{flag,ctf,key} → 碰运气
4. 图片：stegsolve 通道分离 → zsteg LSB → steghide（尝试空密码/常见密码）
5. 音频：Audacity 频谱 → 波形 → MP3Stego
6. 压缩包有密码 → 伪加密检查 → CRC 爆破 → 字典攻击
7. 都没有 → 回头看题目描述/附件名（提示常在题面）
```

---

## 六、工具速查表

| 工具 | 用途 | 命令示例 |
|---|---|---|
| binwalk | 识别/分离嵌入文件 | `binwalk -e f.png` |
| foremost | 文件雕刻 | `foremost f.png` |
| stegsolve | 图像通道分析 | 图形化操作 |
| zsteg | PNG/BMP LSB | `zsteg f.png` |
| steghide | JPG/WAV | `steghide extract -sf f.jpg` |
| exiftool | 元数据查看 | `exiftool f.jpg` |
| ffmpeg | 音视频处理 | `ffmpeg -i in.mp4 frames/%d.png` |
| Audacity | 音频频谱 | 图形化操作 |

---

## 七、练习题单（对应课程 1.4 / 关卡赛 I）

- BUUCTF Misc 入门区：神奇的二维码、ord、LSB、Nikoo
- 攻防世界 Misc 新手区：gif、VeryEasy、掀桌子
- CTFHub 技能树：图片隐写全分支（宽高还原/LSB/文件结构）

> 下一步：解不出压缩包密码 → 见《压缩包攻防》；文件类型 → 见《取证分析》
---

## 🎓 上课流程卡（1.4 上半 · 隐写 · 120 分钟）

> 给讲师：本卡按"非 Misc 专长讲师"标准编写，照卡即讲。核心演示只有两个命令（binwalk、stegsolve），课前务必自己跑一遍。

**教学目标**：下课时学员能独立用「binwalk → stegsolve → steghide」三件套解出一张基础隐写图。

**课前准备**：
- 学员环境已装 stegsolve（jar）+ binwalk；发 3 张练习图（一张尾部藏 zip、一张 LSB、一张 steghide 弱密码）
- 自提：预先跑通 3 张图的完整解法，截图备用（现场翻车时贴截图救场）

| 时间 | 环节 | 讲师动作 |
|---|---|---|
| 0-10 | 导入 | 现场演示：一张"正常"图片 → `binwalk -e` → 直接拖出 flag。话术："图片里能藏第二个文件，这是 Misc 第一课的原因——最快拿到第一血的就在这类题" |
| 10-30 | 讲解 | §1.1 文件结构附加：画 PNG 结构（IHDR→数据→IEND），强调"看 IEND 之后有什么"；带学员跑一遍 strings + binwalk |
| 30-55 | 讲解+演示 | §1.2 LSB：先讲原理（每像素最低位改 1，肉眼不可见），再现场 stegsolve 操作 Data Extract——**这一步边投屏边手把手，位序勾选是第一个卡点** |
| 55-95 | 实操 | 学员做 3 张练习图。巡场优先级：①stegsolve 打不开（Java 环境问题）②Data Extract 位序勾不对 ③binwalk -e 提取后不知道去哪个目录（教 `ls _flag.png.extracted`） |
| 95-110 | 进阶速览 | §二 音频：Audacity 打开示例 wav → 切 Spectrogram 视图，flag 直接写在频谱上（本环节只需"见过"，不要求掌握） |
| 110-120 | 收口 | 过一遍 §五 决策树（这页让他们拍照）；布置作业：CTFHub 图片隐写分支 3 题 |

**学员常见卡点（预判）**：
1. stegsolve 打不开 → 检查 java -version；发预配置包
2. Data Extract 勾选位序出不来 → 给"默认配置截图"（Red 0 / Blue 0 / Green 0 逐个试）
3. steghide 密码猜不到 → 提前说明：出题人会在题面/图片属性里留提示，教 exiftool 看注释
4. 一张图什么都没有 → 强调决策树第 7 步：回题面找提示，不是所有图都有隐写

**被问倒的兜底**：DCT/小波域隐写、彩虹频谱这类进阶 → "这是省级赛水平，本期只要求掌握本课四件套，进阶内容课后可以单独找我聊"。

**本课与下一篇的衔接**：隐写出的密文串（Base64/摩斯）解不开？——这正是下半场《编码与古典密码》的内容。