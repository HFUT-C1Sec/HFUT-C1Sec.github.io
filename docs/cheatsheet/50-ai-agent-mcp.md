---
title: "AI Agent 与 MCP 安全工具大全"
tags: [security, agent, mcp, bug-bounty, pentesting, automation, ai-sec]
status: completed
date-created: 2026-07-26
date-modified: 2026-07-26
category: BugBounty
difficulty: intermediate
---

# AI Agent 与 MCP 安全工具大全

> 本文档整理了 2025-2026 年最前沿的 Bug Bounty 和渗透测试专用 AI Agent、MCP Server 和安全自动化框架。所有内容仅供授权安全测试使用。

---

## 一、自主 AI 渗透测试 Agent（Tier 1）

这些是完全自主的 AI Agent，能端到端执行渗透测试任务，最小化人工干预。

| 工具 | GitHub | 核心技术栈 | 特色 |
|:-----|:-------|:-----------|:-----|
| **XBOW** | hackerone.com/xbow | 自主 Agent | HackerOne 全球第一，90天完成 1,060+ 漏洞提交，单条攻击链 48 跳 |
| **PentAGI** | github.com/pentagi | Docker 沙箱 + Neo4j | 14,700+ Stars，4 个子 Agent，20+ 内置工具（nmap/metasploit/sqlmap） |
| **ARTEMIS** | Stanford Trinity | OpenAI GPT-4 | 击败 10 个真人 pentester 中的 9 个，$18/hour，8,000 主机规模 |
| **Shannon** | github.com/alceas/shannon | Claude Agent SDK | 96.15% XBOW Benchmark 成功率，端到端自动化 |
| **Strix** | github.com/strix-ai | Claude API | 开源 AI Hacker，动态生成代码、发现漏洞并验证 PoC |
| **Decepticon** | github.com/Decepticon-AI | LangGraph + MCP | 模块化多 Agent 架构，红队演练专用 |

### XBOW 突破
- 传统渗透测试：40 小时覆盖 104 场景
- XBOW Agent：**28 分钟**覆盖同样场景（85x 加速）
- CVSS 9.8 RCE 漏洞发现（Microsoft Devices Pricing Program）
- Google 2026 年 3 月起拒绝 AI 生成的低质量报告

### ARTEMIS 关键数据
- 82% 有效提交率（真人平均 ~40%）
- 发现 9 个有效漏洞
- 无需睡眠、无 PTO、零上下文 ramp-up 时间

---

## 二、全功能安全平台（平台级）⭐ 重点

### 2.0 XuanMu（玄幕）RedTeam Agent ⭐ 中文首选推荐

**链接**: <https://github.com/guaidao2/XuanMu-RedTeam-Agent>

> 基于 [Z3r0](https://github.com/yv1ing/Z3r0) 汉化改进，融入 [Cairn](https://github.com/oritera/Cairn) 协作理念。MIT 开源协议。

**核心理念**: 无需 Docker、直接在 Kali Linux 上运行的红队多智能体协作平台。所有命令通过 Python asyncio subprocess 在主机执行，简化部署依赖。

**核心特性**:
- **无需 Docker 运行**：命令直接在主机上执行
- **黑板式共享推理图**：受 Cairn 启发实现 Stigmergy 信标协同——智能体通过共享白板协调而非相互干扰
- **结构化证据平面**：资产、发现、关系图、攻击路径作为显式应用数据持久化
- **可重放时间线**：实时流式传输或加载历史标准化时间线事件
- **本地优先 LLM**：直接调用 OpenAI 兼容 API，支持 DeepSeek/Qwen/GLM 等多种模型
- **知识库系统**：结构化方法论文档供智能体参考
- **技能系统**：可复用的工具定义（`.xuanmu/agents/skills/`）

**多智能体角色体系**:

| 代号 | 中文名 | 角色职责 |
|:-----|:-------|:---------|
| `cso` | **玄幕** (XuanMu) | 安全主管：任务分解、协调、推理 |
| `cae` | **守拙** (ShouZhuo) | 代码审计工程师 |
| `cie` | **观星** (GuanXing) | 情报与侦察工程师 |
| `cpe` | **破军** (PoJun) | 渗透测试工程师 |
| `cre` | **溯源** (SuYuan) | 逆向分析工程师 |
| `cce` | **破阵** (PoZhen) | 密码学工程师 |

**黑板相关 API 工具**:

| 工具 | 说明 |
|:-----|:-----|
| `create_fact` | 创建事实节点 |
| `create_intent` | 创建意图节点 |
| `create_hint` | 创建提示节点 |
| `read_blackboard` | 读取黑板 |
| `update_node_status` | 更新节点状态 |
| `trace_reasoning_path` | 追踪推理路径 |

**架构设计（五层）**:
1. **React 操作控制台** — Playground + Project Workspace、黑板标签页、图可视化
2. **FastAPI 控制平面** — REST + WebSocket、用户/代理/项目管理
3. **智能体运行时** — 会话级多 Agent、任务委派执行
4. **黑板推理图** — Fact/Intent/Hint 共享黑板，协调 Agent 协作
5. **证据平面** — 资产、漏洞发现、关系边（GraphEdge）、攻击路径

**快速启动**:
```bash
# 前置条件：Python >= 3.12, PostgreSQL >= 14, Node.js >= 18
bash setup.sh
bash config-tool.sh
bash start.sh
# 访问 http://localhost:8000 （admin@admin.com / admin123）
```

---

### 2.1 CyberStrikeAI ⭐ 重磅推荐

**链接**: <https://github.com/zhuxindong/CyberStrikeAI>（主仓库，485+ commits）

**核心特性**:
- **AI-native 安全测试平台**，Golang 编写
- **100+ 内置安全工具**，YAML 插件式扩展系统
- 原生 **MCP 协议**（HTTP + stdio 双模式），支持外部 MCP 联邦
- **AI 决策引擎**：兼容 OpenAI 格式（GPT / Claude / DeepSeek 等）
- **多 Agent 角色系统**：预定义安全角色 + 技能（Skills）体系
- **攻击链可视化**：节点图、风险评分、逐步回放
- **知识库**：向量搜索 + 混合检索，AI 对话中可查询安全知识
- **Web 控制台**：密码保护 UI、审计日志、SQLite 持久化
- **漏洞生命周期管理**：CRUD、严重程度跟踪、状态工作流
- **批量任务队列**：创建任务队列，顺序执行多个任务

**工具覆盖（100+ 工具分类）**:

| 类别 | 工具示例 |
|:-----|:---------|
| 网络扫描 | nmap, masscan, rustscan, arp-scan, nbtscan |
| Web & 应用 | sqlmap, nikto, dirb, gobuster, feroxbuster, ffuf, httpx |
| 漏洞扫描 | nuclei, wpscan, wafw00f, dalfox, xsser |
| 子域名 | subfinder, amass, findomain, dnsenum, fierce |
| 网络空间引擎 | FOFA 搜索, ZoomEye 搜索 |
| API 安全 | graphql-scanner, arjun, api-fuzzer |
| 容器安全 | trivy, clair, docker-bench-security, kube-bench, kube-hunter |
| 云安全 | prowler, scout-suite, cloudmapper, pacu, terrascan, checkov |
| 二进制分析 | gdb, radare2, ghidra, objdump, strings, binwalk |
| 漏洞利用 | metasploit, msfvenom, pwntools, ropper, ropgadget |
| 密码破解 | hashcat, john, hashpump |
| 取证分析 | volatility, foremost, steghide, exiftool |
| 后渗透 | linpeas, winpeas, mimikatz, bloodhound, impacket, responder |
| CTF | stegsolve, zsteg, hash-identifier, fcrackzip, pdfcrack, cyberchef |

**快速启动**:
```bash
git clone https://github.com/zhuxindong/CyberStrikeAI.git
cd CyberStrikeAI
go mod download
./run.sh
```

---

### 2.2 Z3r0 — AI 红队协作工作台

**链接**: <https://github.com/yv1ing/Z3r0>

**核心理念**: 对话不是唯一事实来源——项目范围、资产、漏洞发现、关系图、攻击路径都作为显式应用数据管理。

**核心特性**:
- **控制平面架构**：四个独立平面，职责分离清晰
- **多专家智能体协作**：情报收集 + 代码审计 + 渗透测试 + 逆向工程 + 密码学专家团队
- **图结构**管理资产和攻击链路（非线性，更像真实红队工作）
- **Docker 沙箱**隔离执行，集成 Nmap/Sqlmap/Ghidra 等工具
- **人工接管**：Shell/VNC/文件管理器，随时介入 Agent 工作
- **证据平面**：项目范围、资产、漏洞发现、关系图、攻击路径、时间线回放
- **LightRAG 知识库**：上下文检索增强
- **受控出口层**：出站网络策略管理

**四架构平面**:

| 平面 | 职责 |
|:-----|:-----|
| 控制平面 | 用户、系统配置、Agent、会话、WorkProject、托管主机、沙箱镜像/容器、出口代理 |
| 运行时平面 | 多 Agent 会话执行、实时事件流、长周期任务连续性、历史投影、时间线回放 |
| 证据平面 | 项目范围、资产、漏洞发现、关系图、攻击路径、任务进度、Agent 摘要 |
| 执行平面 | Docker 主机、沙箱容器、Shell/文件/noVNC 访问、命令执行、出站网络策略 |

**快速启动**:
```bash
git clone https://github.com/yv1ing/Z3r0.git && cd Z3r0
cd sandbox && bash build.sh
cp .z3r0/config.json.example .z3r0/config.json
docker compose -f docker-compose.prod.yml up -d --build
# 访问 http://ip:8000/
```

**实战验证**: 作者在 CTF 比赛中全程只丢题目信息，2小时 AK。

---

### 2.3 RedTeam-Agent（ktol1）— AI 自动化红队框架

**链接**: <https://github.com/ktol1/RedTeam-Agent>

**核心理念**: AI 直接调用渗透工具，无需手动操作。

**核心特性**:
- **Skill + 终端模式**：AI 读取 SKILL.md 并直接调用渗透工具
- **Token 优化**：智能输出压缩，节省 80% Token 消耗
- **域渗透全链路**：BloodHound + impacket + Responder 完整 AD 攻击链
- **多客户端支持**：Cursor / Claude Desktop / VS Code Cline
- **Windows 一键部署**：15+ 渗透工具自动安装

**工具矩阵**:

| 类别 | 工具 | 特性 | 场景 |
|:-----|:-----|:-----|:-----|
| 网络扫描 | gogo | 极速资产发现 | 内网主机探测 |
| 网络扫描 | fscan | 综合扫描 | 端口/漏洞/弱口令 |
| Web 安全 | httpx | Web 指纹识别 | 网站技术栈识别 |
| Web 安全 | nuclei | POC 批量扫描 | 已知漏洞检测 |
| Web 安全 | ffuf | 目录 fuzzing | Web 目录爆破 |
| 活动目录 | SharpHound / bloodhound-python | Windows 域数据采集 | AD 攻击路径分析 |
| 活动目录 | GetNPUsers / GetUserSPN | AS-REP Roast / Kerberoasting | 凭证获取 |
| 活动目录 | secretsdump | LSASS Dump | 提取明文和哈希 |
| 活动目录 | ntlmrelayx | NTLM Relay | 中继攻击 |
| 活动目录 | pywerview / ldapdomaindump | 域信息枚举 / 转储 | 域内信息收集 |
| 横向移动 | nxc (NetExec) | SMB / WinRM / SSH | 远程执行 |
| 横向移动 | wmiexec / psexec | WMI / PSEXEC | 无文件横向 |
| 代理与凭据 | chisel | HTTP 隧道 | 端口转发 |
| 代理与凭据 | responder | LLMNR 欺骗 | 哈希收集 |

**快速启动**:
```bash
git clone https://github.com/ktol1/RedTeam-Agent.git
cd RedTeam-Agent
python -m venv venv
python scripts/install_tools.py
```

---

### 2.4 Cairn — 通用状态空间搜索引擎

**链接**: <https://github.com/oritera/Cairn>

**核心理念**: *渗透测试只是"找路问题"的第一个应用场景*——任何"知道起点和目标，但不知道中间路径"的问题都可以用 Cairn 解决。

**核心特性**:
- **黑板架构（Blackboard Architecture）**：无固定角色、无预设工作流

**三个原语驱动探索**:

| 原语 | 含义 |
|:-----|:-----|
| **Fact（事实）** | 已确认的客观发现，写回白板 |
| **Intent（意图）** | 计划探索的方向，尚未执行 |
| **Hint（提示）** | 人类可随时注入指导建议 |

- **同构 Worker**：所有 Worker 完全相同，任务从图中当前状态动态生成
- **OODA 循环**：每个 Worker 不断 Observe → Orient → Decide → Act
- **支持多种后端**：Claude Code / Codex / Pi
- **Stigmergy 协调**：Worker 间接协作，无直接通信
- **AGPLv3 许可**

**实战成绩（腾讯云黑客松第二届）**:
- 610 支队伍、1,345 名参赛者
- **54/54 全部正确** — 唯一全 AK 队伍
- **全场第 3 名**
- 比赛当天凌晨 4 点首次运行，未经训练/调参/专用工具/MCP/RAG

**快速启动**:
```bash
git clone https://github.com/oritera/Cairn.git && cd Cairn
docker pull ghcr.io/oritera/cairn-worker-container:latest
cp dispatch.example.yaml dispatch.yaml
docker compose up --build
```

---

## 三、MCP Server - 安全工具集成

### 3.1 mcp-security-hub（FuzzingLabs）⭐ 推荐

**链接**: <https://github.com/FuzzingLabs/mcp-security-hub>

**核心特性**:
- **28 个 MCP Servers** 覆盖 163+ 安全工具
- 全部 Docker 容器化部署，非 root 运行
- CI/CD 就绪，Trivy 扫描加固镜像

**可用 MCP Server 分类**:

#### 侦察类 (Reconnaissance)
| MCP Server | 工具 | 说明 |
|:-----------|:-----|:-----|
| `nmap-mcp` | Nmap | 端口扫描、服务探测、OS 指纹、NSE 脚本 |
| `masscan-mcp` | Masscan | 超高速大规模端口扫描 |
| `shodan-mcp` | Shodan | 互联网搜索引擎 |
| `pd-tools-mcp` | Subfinder/Naabu/Katana | ProjectDiscovery 全套工具 |
| `whatweb-mcp` | WhatWeb | Web 技术指纹识别 |
| `zoomeye-mcp` | ZoomEye | 网络空间搜索引擎 |

#### Web 安全类 (Web Security)
| MCP Server | 工具 | 说明 |
|:-----------|:-----|:-----|
| `nuclei-mcp` | Nuclei | 模板化漏洞扫描（8000+ 模板） |
| `sqlmap-mcp` | SQLMap | SQL 注入检测与利用 |
| `ffuf-mcp` | ffuf | 目录/参数/虚拟主机模糊测试 |
| `nikto-mcp` | Nikto | Web 服务器扫描 |
| `waybackurls-mcp` | Wayback Machine | 历史 URL 发现 |
| `burp-mcp` | Burp Suite | Web 安全测试 |

#### 二进制分析类 (Binary Analysis)
| MCP Server | 工具 | 说明 |
|:-----------|:-----|:-----|
| `radare2-mcp` | Radare2 | 反汇编/反编译（32 工具） |
| `ghidra-mcp` | Ghidra | AI 驱动逆向工程 |
| `ida-mcp` | IDA Pro | IDA Pro 集成 |
| `binwalk-mcp` | Binwalk | 固件分析 |
| `yara-mcp` | YARA | 恶意软件模式匹配（7 规则） |
| `capa-mcp` | Capa | 可执行文件能力检测 |

#### 云安全类 (Cloud Security)
| MCP Server | 工具 | 说明 |
|:-----------|:-----|:-----|
| `trivy-mcp` | Trivy | 容器/IaC 漏洞扫描（7 工具） |
| `prowler-mcp` | Prowler | AWS/Azure/GCP 安全审计（6 工具） |

#### 密钥检测（Secrets Detection）
| MCP Server | 工具 | 说明 |
|:-----------|:-----|:-----|
| `gitleaks-mcp` | Gitleaks | Git 仓库凭据泄露检测 |

#### 漏洞利用（Exploitation）
| MCP Server | 工具 | 说明 |
|:-----------|:-----|:-----|
| `searchsploit-mcp` | Exploit-DB | 漏洞数据库检索（5 工具） |

#### OSINT
| MCP Server | 工具 | 说明 |
|:-----------|:-----|:-----|
| `maigret-mcp` | Maigret | 用户名跨 2500+ 站点搜索 |
| `dnstwist-mcp` | DNSWatch | Typosquatting/钓鱼域名检测 |

#### 威胁情报（Threat Intelligence）
| MCP Server | 工具 | 说明 |
|:-----------|:-----|:-----|
| `virustotal-mcp` | VirusTotal | 恶意软件分析 |
| `otx-mcp` | OTX | AlienVault 开放威胁交换 |

#### Active Directory
| MCP Server | 工具 | 说明 |
|:-----------|:-----|:-----|
| `bloodhound-mcp` | BloodHound | AD 攻击路径分析（75+ 工具） |

#### 密码破解（Password Cracking）
| MCP Server | 工具 | 说明 |
|:-----------|:-----|:-----|
| `hashcat-mcp` | Hashcat | 自然语言哈希破解 |

**Claude Desktop 配置示例**:
```json
{
  "mcpServers": {
    "nmap": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "--cap-add=NET_RAW", "nmap-mcp:latest"]
    },
    "nuclei": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "nuclei-mcp:latest"]
    },
    "sqlmap": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "sqlmap-mcp:latest"]
    }
  }
}
```

---

### 3.2 pentesting-cyber-mcp（hackersatyamrastogi）

**链接**: <https://github.com/hackersatyamrastogi/aiptx-cyber-mcp>

**核心特性**:
- **50+ MCP Security Servers**，覆盖更广的工具范围
- 提供统一聚合服务器（unified），一条连接访问所有工具
- MIT 协议，社区驱动

**独有工具**（相比 mcp-security-hub）:

#### 漏洞利用增强
| MCP Server | 工具 | 说明 |
|:-----------|:-----|:-----|
| `metasploit-mcp` | Metasploit | 漏洞利用框架 |
| `hydra-mcp` | THC-Hydra | 密码暴力破解 |
| `dalfox-mcp` | Dalfox | XSS 扫描 |
| `zap-mcp` | OWASP ZAP | Web 应用扫描器 |
| `smuggler-mcp` | Smuggler | HTTP 请求走私 |
| `wpscan-mcp` | WPScan | WordPress 扫描 |
| `nessus-mcp` | Nessus | 企业级漏洞扫描 |

#### 专项扫描
| MCP Server | 工具 | 说明 |
|:-----------|:-----|:-----|
| `acunetix-mcp` | Acunetix | Web 漏洞扫描 |
| `mobsf-mcp` | MobSF | 移动安全分析 |
| `sslscan-mcp` | SSLScan | SSL/TLS 测试 |
| `commix-mcp` | Commix | 命令注入检测 |
| `nextjs-scanner-mcp` | NextJS Scanner | Next.js 专项 CVE |

#### Kubernetes 安全
| MCP Server | 工具 | 说明 |
|:-----------|:-----|:-----|
| `kube-hunter-mcp` | kube-hunter | K8s 渗透测试 |
| `kubeaudit-mcp` | kubeaudit | K8s 安全审计 |
| `kube-bench-mcp` | kube-bench | CIS K8s 基准检查 |

#### 代码与基础设施安全
| MCP Server | 工具 | 说明 |
|:-----------|:-----|:-----|
| `semgrep-mcp` | Semgrep | 静态代码分析 |
| `scoutsuite-mcp` | ScoutSuite | 云安全审计 |
| `checkov-mcp` | Checkov | IaC 安全检查 |

#### 域安全
| MCP Server | 工具 | 说明 |
|:-----------|:-----|:-----|
| `crackmapexec-mcp` | CrackMapExec | AD/SMB 工具集 |
| `ghidra-mcp` | Ghidra | 逆向工程 |

#### 子域名发现增强
| MCP Server | 工具 | 说明 |
|:-----------|:-----|:-----|
| `cero-mcp` | Cero | 基于证书的子域名发现 |
| `crtsh-mcp` | crt.sh | 证书透明度日志 |
| `katana-mcp` | Katana | Web 爬虫 |
| `gowitness-mcp` | Gowitness | 网页截图 |
| `shuffledns-mcp` | ShuffleDNS | DNS 爆破 |
| `uncover-mcp` | Uncover | Shodan/Censys/FOFA 搜索 |
| `waybackurls-mcp` | Waybackurls | 历史 URL 提取 |
| `alterx-mcp` | Alterx | 子域名词表生成器 |
| `assetfinder-mcp` | Assetfinder | 资产发现 |
| `dnsx-mcp` | dnsx | DNS 工具箱 |
| `httpx-mcp` | httpx | HTTP 探测 |
| `subfinder-mcp` | Subfinder | 子域名枚举 |
| `notify-mcp` | Notify | 通知流 |
| `anew-mcp` | Anew | 去重输出流 |

---

### 3.3 其他独立 MCP Server

| 工具 | 作者 | 说明 |
|:-----|:-----|:-----|
| **BurpMCP** | swgee | Burp Suite 扩展，8181 端口 SSE 模式，支持 Claude Desktop stdio 桥接 |
| **Bug Bounty MCP** | akinabudu | 综合 Bug Bounty 工作流，含范围验证、伦理边界 |
| **ProjectDiscovery MCP** | intelligent-ears | 集成 subfinder/dnsx/naabu/httpx/katana/nuclei |
| **Yogosha MCP** | mohdhaji87 | Yogosha 平台 API 桥接 |
| **Intigriti MCP** | yourusername | Intigriti 漏洞赏金平台 API |
| **MCP Vulnerability Reporting** | badchars | 专业漏洞报告生成器，符合行业标准 |
| **mcp-vanguard** | skyvanguard | Windows/WSL 桥接安全测试 MCP |
| **Bounty Board MCP** | madisoncarter1234 | AI Bounty Board API 集成 |

---

## 四、AI 赋能的 Bug Bounty 平台与 Agent

### 4.1 Advanced Bug Bounty MCP Server（Coding-with-Mayank）

**链接**: <https://github.com/Coding-with-Mayank/advanced-bugbounty-mcp>

**特点**: 21 种工具功能集成，AI 引导漏洞分析和下一步建议，一键 `./setup.sh` 安装，支持 Docker 容器化部署

### 4.2 HexStrike AI

**链接**: <https://github.com/0x4m4/hexstrike-ai>

**特点**: 150+ 安全工具，500+ 贡献者社区，首周发现 15+ 严重漏洞，报告生成速度提升 144x

### 4.3 PentestGPT（学术界认可）

**链接**: 发表于 USENIX Security 2024

**特点**: LLM 驱动的自动化渗透测试框架，GPT-4 API 驱动，学术论文支持的方法论

---

## 五、开源知识 & 资料库 MCP

### 5.1 Bug Bounty MCP Server（rs0n）

**链接**: <https://github.com/rs0n/rs0n-bug-bounty-mcp-server>

**核心功能**: 14 个工具，提供完整的 Bug Bounty 知识库查询

| 工具 | 说明 |
|:-----|:-----|
| `search_techniques` | 全知识库全文搜索 |
| `get_payloads` | 25 种漏洞类型 Payload |
| `get_methodology` | 按目标类型的测试方法论 |
| `get_rs0n_methodology` | DEFCON32 方法论 |
| `get_bounty_reports` | 778+ 真实 accepted/rejected 报告 |
| `assess_report_quality` | 评估报告被接受概率 |
| `get_cloud_security` | AWS/Azure/GCP/K8s 攻击技巧 |
| `get_waf_bypass` | WAF 绕过技巧 |
| `browse_knowledge_base` | 浏览知识库结构 |
| `list_wordlists` | SecLists 词表分类 |
| `get_wordlist` | 获取特定词表 |

**知识库来源**: PayloadsAllTheThings, HackTricks, HackTricks-Cloud, SecLists, DEFCON32 Workshop

---

## 六、DARPA AIxCC 开源系统

DARPA 2025 年 AI Cyber Challenge 决赛的 7 个系统全部开源：

| 团队 | 排名 | 奖金 | 特点 |
|:-----|:----:|:----:|:-----|
| **Atlantis** (Georgia Tech) | 1st | $4M | 多 Agent RL + LLM + 符号分析 |
| **Buttercup** (Trail of Bits) | 2nd | $3M | 4 组件：漏洞发现、上下文分析、补丁生成（7 Agent）、验证 |
| **Theori** | 3rd | $1.5M | 完整 CRS 开源 |
| ARTIPHISHELL (Shellphish) | - | - | 基于 angr 二进制分析 |
| 其他 4 队伍 | - | - | 全部开源参考实现 |

---

## 七、专项工具与环境

### 7.1 Zade MCP（全自动 Kali Linux 容器）
**链接**: <https://github.com/delgalizador/zade>
通过 Docker Desktop 暴露完整 Kali Linux 容器给任何 LLM，硬件直访（USB/Webcam）

### 7.2 AIDA
连接 AI 到 **400+ 渗透测试工具** 通过 MCP，Exegol 容器环境，自然语言驱动安全工作流

### 7.3 NeuroSploit
AI 驱动渗透测试框架，100 种漏洞类型，隔离 Kali 容器，9 种专用 Agent 人格

### 7.4 VulnHuntr（Protect AI）
LLM 驱动的静态代码分析，追踪完整调用链（输入 → 输出），7 种漏洞类型，已发现 12+ 生产级 Zero-day

---

## 八、趋势与行业洞察

### 8.1 市场现状（截至 2026 年中）
- **40+ 开源 AI 渗透测试 Agent** 在 GitHub 上可用
- **7 大架构模式**：单 Agent、多 Agent Planner-Executor、专用角色、Swarm、MCP-based、Claude Code Native、黑板搜索（Cairn）
- **$665M+ 风险投资**投入该领域
- **Anthropic Mythos**：发现数千高危漏洞后选择内部发布
- **Google**：2026 年 3 月停止接受 AI 生成的漏洞报告
- **curl**：2026 年 1 月关停付费 Bug Bounty 项目

### 8.2 性能对比
| 指标 | AI Agent | 人工专家 | 优势 |
|:-----|:---------|:---------|:-----|
| 测试速度（XBOW） | 28 分钟 | 40 小时 | 85x |
| 每小时成本 | ~$18 | ~$60 | 3.3x |
| 可用性 | 24/7 | 8h/天 | 3x |

### 8.3 实验室 vs 现实差距
- GPT-4 在受控环境中可 exploit **87%** 的已知 CVE
- 在 CVE-Bench 现实测试中仅 **13%**
- **结论**: 当前 Agent 更适合结构性扫描，创造性攻击仍需人工

### 8.4 最佳实践建议
1. **多层 Agent 架构胜出**：分层团队比单体 Agent 提升 4.3x
2. **微调小模型 > 通用大模型**：Qwen3-32B 微调版得分 79.17%，超越 GPT-4
3. **混合人机协作**：Agent 负责重复性工作，人工处理创造性推理
4. **报告质量是核心瓶颈**：AI 生成大量低质量报告，人工审核是关键

---

## 九、相关资源

- bugbounty项目/补天SRC浙江旅游职业学院项目sql注入漏洞.md
- [信息收集全技巧](06-recon.md)
- [OWASP Top 10 速查表](08-owasp-top10.md)

### 外部链接

| 资源 | 链接 |
|:-----|:-----|
| Awesome AI Pentesting | github.com/skyvanguard/awesome-ai-pentesting |
| Awesome MCP Security | github.com/jeffrawling/awesome-mcp-security |
| XuanMu 红队 Agent | github.com/guaidao2/XuanMu-RedTeam-Agent |
| CyberStrikeAI 综合安全平台 | github.com/zhuxindong/CyberStrikeAI |
| Z3r0 红队工作台 | github.com/yv1ing/Z3r0 |
| RedTeam-Agent 红队框架 | github.com/ktol1/RedTeam-Agent |
| Cairn 黑板搜索引擎 | github.com/oritera/Cairn |
| PayloadsAllTheThings | github.com/swisskyrepo/PayloadsAllTheThings |
| HackTricks | hacktricks.live |
| AppSec Santa AI Pentesting 报告 | appsecsanta.com/research/ai-pentesting-agents-2026 |

---

> **法律声明**: 所有工具仅限**获得明确书面授权**的安全测试使用。未经授权扫描他人系统是违法行为。
