# SRC实战报告：信息收集与工具联动全攻略

> **信息收集是SRC漏洞挖掘的地基**，高效的信息收集能直接找到敏感信息泄露、弱口令等漏洞，甚至决定挖洞成败。
> **关联知识**：[安全配置错误（A05）全技巧](24-a05-security-misconfiguration.md) | [软件和数据完整性失效（A08）全技巧](27-a08-integrity-failures.md) | [反序列化注入全技巧](18-deserialization.md)

---

## 一、SRC信息收集核心思维

### 攻击面拆解四维度

```
目标系统
├── 域名层 ──→ 主域名 / 子域名 / 泛域名
├── 应用层 ──→ Web应用 / API接口 / 客户端程序
├── 数据层 ──→ 用户数据 / 业务数据 / 配置文件
└── 基础设施 ──→ CDN / 云服务 / IP节点 / 容器
```

### 挖掘思维三重维度

| 思维 | 说明 |
|:---|:---|
| **攻击面拆解思维** | 把目标当"资产网络"拆解，不漏掉任何一个暴露点 |
| **业务逻辑对抗思维** | 跳出SQL/XSS等技术漏洞局限，理解业务流程 |
| **防御机制绕过思维** | 思考如何绕过WAF/风控/JS校验 |

---

## 二、域名与子域名收集

### 2.1 核心工具链

```bash
# 工具联动流程
OneForAll → FOFA → Nmap → Wappalyzer
（子域名枚举）（存活筛选）（端口扫描）（技术栈识别）
```

#### OneForAll 子域名枚举

```bash
python oneforall.py --target target.com run
```

#### crt.sh 证书透明度查询

```
https://crt.sh/?q=%25.target.com
```

#### FOFA 资产筛选

```fofa
domain="target.com" && status_code="200"
domain="target.com" && protocol="https"
# 查找开放特定端口的资产
domain="target.com" && port="8080"
# 查找特定标题的资产
domain="target.com" && title="管理"
```

### 2.2 实战技巧

> **优先测试子域名**！主域名防御严密，子域名因管理分散，更易存在漏洞。

| 类型 | 优先级 | 原因 |
|:---|:---|:---|
| 管理后台 | ⭐⭐⭐ | 弱口令高发区 |
| 用户中心 | ⭐⭐⭐ | 越权漏洞集中 |
| 支付接口 | ⭐⭐⭐ | 逻辑漏洞高价值 |
| 帮助中心 | ⭐⭐ | 偶尔有XSS |
| 公告栏 | ⭐ | 低危信息泄露 |

### 2.3 关联资产挖掘

#### 子公司/关联企业

```bash
# 通过天眼查/企查查查询目标厂商的子公司
# 挖掘子公司的域名和业务系统
```

#### 历史资产残留（Wayback Machine）

```
https://web.archive.org/web/*/target.com
# 发现已下线但未删除的敏感功能（测试接口、旧版后台）
```

---

## 三、IP与服务器探测

### 3.1 端口扫描

```bash
# 全端口扫描
nmap -sV -p- target.com

# 常见端口快速扫描
nmap -sV -p 80,443,8080,8443,3306,1433,6379,27017 target.com

# 服务版本识别
nmap -sV --version-intensity 9 -p 80,443 target.com
```

### 3.2 重点关注端口

| 端口 | 服务 | 可能漏洞 |
|:---|:---|:---|
| 22 | SSH | 弱口令、爆破 |
| 3306 | MySQL | 弱口令、未授权 |
| 1433 | MSSQL | 弱口令、SA权限 |
| 6379 | Redis | 未授权访问、RCE |
| 27017 | MongoDB | 未授权访问 |
| 9200 | Elasticsearch | 未授权访问 |
| 8080 | Tomcat | 默认口令、CVE |
| 8443 | WebLogic | CVE-2020-14882等 |

### 3.3 CDN绕过技巧

```bash
# 方法1：历史DNS记录查询
# viewdns.info 查看历史DNS解析记录

# 方法2：子域名直接解析
# 部分子域名未使用CDN

# 方法3：全球ping
# ping.chinaz.com 多地ping找到真实IP
```

---

## 四、Web应用指纹识别

### 4.1 识别工具

| 工具 | 用途 |
|:---|:---|
| Wappalyzer（浏览器插件） | 快速识别前端/后端技术栈 |
| WhatWeb | 命令行指纹识别 |
| Nmap -sV | 服务版本+指纹 |
| 御剑指纹识别 | 国产工具，中文支持好 |

### 4.2 技术栈与对应漏洞

| 识别到 | 可测试的漏洞 |
|:---|:---|
| Struts2 | S2-045/S2-048/S2-057 RCE |
| Spring Boot | Actuator泄露、SpEL注入 |
| ThinkPHP | 5.x 远程代码执行 |
| WordPress | 插件/主题漏洞、后台弱口令 |
| Django | 调试模式泄露、SSTI |
| Vue.js | 模板注入、敏感信息泄露 |
| jQuery 旧版本 | 已知XSS CVE |

---

## 五、API接口发现

### 5.1 目录爆破

```bash
# Dirsearch
python dirsearch.py -u https://target.com -e php,asp,aspx,jsp
dirsearch.py -u https://target.com -w /api/common.txt

# Gobuster
gobuster dir -u https://target.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

### 5.2 重点关注路径

```
/api/
/api/v1/
/api/v2/
/swagger-ui.html
/swagger-resources
/api-docs/
/v2/api-docs
/actuator/
/actuator/health
/actuator/env
/graphql
/ws/
```

### 5.3 Swagger文档泄露案例

> 某金融平台SRC中，白帽通过公开的Swagger文档获取用户信息查询接口，发现**未授权访问漏洞**。

---

## 六、敏感信息泄露挖掘

### 6.1 GitHub搜索技巧

```github
# 搜索目标公司代码泄露
"target.com" password
"公司名" config
org:"公司名" secret
"target" database

# 按最近更新排序，关注员工个人仓库
```

### 6.2 配置文件扫描

```bash
# 常见配置文件
/config.php
/config.ini
/config.xml
/.env
/backup.sql
/db_backup.zip
/web.xml
/application.properties
/.git/config
```

### 6.3 敏感文件实战案例

某教育平台SRC中，通过 `/db_backup.sql` 获取数据库结构及部分用户明文密码。

某SRC案例中扫描到的泄露：

```
target.com/log/               → 服务器日志文件
target.com/data/Setting.xml   → 数据库用户名、密码、IP地址 🔥
target.com/old/               → 服务器名称、密码
target.com/trace.axd          → 应用程序源代码
target.com/update/Setting.xml → 服务名、IP、密码
```

---

## 七、工具联动实战流程

### 完整挖洞流水线

```
阶段1：资产收集
┌─────────────┐    ┌──────────────┐    ┌──────────┐
│ OneForAll   │ →  │ FOFA/Hunter  │ →  │ Nmap     │
│ 子域名枚举  │    │ 存活筛选     │    │ 端口扫描 │
└─────────────┘    └──────────────┘    └──────────┘
                                                  │
                                                  ↓
阶段2：指纹识别                                  │
┌─────────────┐    ┌──────────────┐              │
│ Wappalyzer  │ →  │ WhatWeb      │ ←───────────┘
│ 浏览器插件  │    │ 命令行识别   │
└─────────────┘    └──────────────┘
                          │
                          ↓
阶段3：漏洞扫描
┌─────────────┐    ┌──────────────┐    ┌──────────┐
│ Crawlergo   │ →  │ Xray         │ →  │ Burp     │
│ 爬虫爬取   │    │ 自动扫描     │    │ 手工验证 │
└─────────────┘    └──────────────┘    └──────────┘
                          │
                          ↓
阶段4：深度挖掘
┌─────────────┐    ┌──────────────┐
│ SQLMap      │    │ 手动逻辑测试 │
│ 注入利用   │    │ 越权/支付等  │
└─────────────┘    └──────────────┘
```

### Crawlergo + Xray 联动命令

```bash
crawlergo -c 10 -t 5 http://target.com | xray webscan --stdin
```

### 新手核心工具建议

> 熟练掌握 **Burp Suite + Xray + OneForAll** 三个工具，联动使用，即可满足80%的SRC挖洞需求。

---

## 八、信息收集Checklist

### 每日挖掘前检查清单

- [ ] 目标厂商SRC规则是否已阅读？（不读规则=白干）
- [ ] 是否已在FOFA/Hunter中搜索最新资产？
- [ ] 子域名是否已用OneForAll枚举？
- [ ] 是否扫描了常见端口（22/3306/6379/27017/9200）？
- [ ] 是否检查了Swagger/Actuator文档？
- [ ] 是否在GitHub搜索了敏感信息？
- [ ] 是否扫描了常见敏感路径？
- [ ] 是否有新上线的活动/功能？
- [ ] 是否记录了所有API接口和参数？

### 🔗 关联学习

- [安全配置错误（A05）全技巧](24-a05-security-misconfiguration.md) - 信息泄露的更多案例
- [服务端请求伪造SSRF（A10）全技巧](15-ssrf.md) - 从信息收集到SSRF利用
- [命令注入全技巧](11-command-injection.md) - 端口扫描后的RCE利用
