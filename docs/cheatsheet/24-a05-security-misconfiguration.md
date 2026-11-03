# ⚙️ 安全配置错误（A05: Security Misconfiguration）全技巧

> **OWASP Top 10 2021 — 第5位**  
> 由于不安全的默认配置、不完整的临时配置、错误的HTTP头配置等导致的安全问题。

---

## 📋 一、漏洞基础

### 1.1 什么是安全配置错误？

安全配置错误是指应用程序、服务器、数据库或框架因为**配置不当**而导致的安全漏洞。这是最常见且最容易利用的漏洞之一。

### 1.2 常见场景

| 场景 | 说明 | 示例 |
|------|------|------|
| 🚫 **默认凭证** | 未修改默认账号密码 | admin/admin, root/root |
| 🚫 **目录列表** | Web目录列表未关闭 | 可浏览服务器所有文件 |
| 🚫 **调试模式** | 生产环境开启调试 | 堆栈信息泄露敏感数据 |
| 🚫 **错误处理** | 详细错误信息暴露 | 数据库类型、路径、版本 |
| 🚫 **HTTP头缺失** | 安全相关的HTTP头缺失 | 缺少CSP、X-Frame-Options等 |
| 🚫 **云存储配置** | S3等存储桶权限配置错误 | 公开可读写存储桶 |
| 🚫 **多余服务** | 运行不必要的服务 | 暴露未使用的端口 |

### 1.3 危害

- 敏感信息泄露（路径、版本、配置）
- 未授权访问管理面板
- 服务器被完全控制
- 数据泄露/篡改

---

## 🔍 二、基础检测技巧

### 2.1 目录列表检测

```bash
# 检测目录列表是否开启
curl -s https://target.com/images/ | grep -i "<title>Index of"
curl -s https://target.com/uploads/ | grep -i "Index of"
curl -s https://target.com/backup/ | grep -i "Index of"

# 常用敏感目录列表
# /backup/ /wp-content/ /uploads/ /logs/ /admin/ /config/
# /.git/ /.env/ /robots.txt /sitemap.xml /crossdomain.xml
```

### 2.2 HTTP头安全检测

```bash
# 检查安全相关的HTTP头
curl -sI https://target.com | grep -iE "strict-transport|content-security|x-frame|x-content|x-xss"

# 缺少以下头都算配置问题：
# - Strict-Transport-Security (HSTS)
# - Content-Security-Policy (CSP)
# - X-Frame-Options (防点击劫持)
# - X-Content-Type-Options (防MIME嗅探)
# - Referrer-Policy
# - Permissions-Policy
```

### 2.3 默认凭证测试

```bash
# 常见默认账号密码测试
# 使用hydra进行暴力破解
hydra -l admin -P /usr/share/wordlists/common_passwords.txt target.com http-post-form "/login:user=^USER^&pass=^PASS^:F=incorrect"

# 常见默认凭证列表
admin:admin
admin:password
admin:123456
root:root
administrator:administrator
tomcat:tomcat
guest:guest
```

### 2.4 信息泄露检测

```bash
# 检测服务器信息泄露
curl -sI https://target.com | grep -i "server\|x-powered-by\|x-aspnet-version"

# 检测调试页面
curl -s https://target.com/phpinfo.php
curl -s https://target.com/info.php
curl -s https://target.com/debug/
curl -s https://target.com/.env
curl -s https://target.com/.git/config

# 检测错误信息泄露
curl -s "https://target.com/?id='"   # 触发SQL错误
curl -s "https://target.com/%00"      # 触发空字节错误
curl -s "https://target.com/{{config}}"  # SSTI测试
```

---

## 🚀 三、进阶利用技巧

### 3.1 .Git 泄露利用

```bash
# 发现.git目录泄露
curl -s https://target.com/.git/HEAD

# 使用工具下载整个git仓库
# GitHack
python GitHack.py https://target.com/.git/

# git-dumper
git-dumper https://target.com/.git/ output_dir

# 分析历史版本中的敏感信息
cd output_dir
git log -p | grep -i "password\|secret\|key\|token\|api"
```

### 3.2 云存储桶配置错误

```bash
# 枚举AWS S3存储桶
# 工具：s3scanner, awscli

# 检测公开桶
s3scanner --bucket target-backup
s3scanner --bucket target-dev
s3scanner --bucket target-assets

# 列出公开桶内容
aws s3 ls s3://target-backup/ --no-sign-request

# 下载公开桶数据
aws s3 sync s3://target-backup/ ./backup/ --no-sign-request

# 检测可写入桶
aws s3 cp test.txt s3://target-backup/test.txt --no-sign-request

# GCP存储桶检测
gsutil ls gs://target-bucket
```

### 3.3 Docker/K8s 配置错误

```bash
# Docker守护进程暴露
curl http://target.com:2375/version
curl http://target.com:2375/containers/json

# 利用暴露的Docker API
# 创建特权容器获取宿主机权限
docker -H tcp://target.com:2375 run -it --privileged --pid=host ubuntu bash

# Kubernetes Dashboard 未授权访问
curl https://target.com:6443/api/v1/namespaces

# kubelet 未认证API
curl -k https://target.com:10250/pods
curl -k https://target.com:10250/run/namespace/pod/container -d "cmd=id"

# etcd 未认证访问
curl http://target.com:2379/v2/keys/
```

### 3.4 CORS 配置错误

```bash
# 测试CORS配置
curl -H "Origin: https://evil.com" -H "Access-Control-Request-Method: GET" \
  -X OPTIONS https://target.com/api/sensitive -v

# 如果返回 Access-Control-Allow-Origin: https://evil.com
# 或 Access-Control-Allow-Origin: *
# 则存在CORS配置错误

# 反射型Origin（不安全模式）
curl -H "Origin: https://attacker.com" https://target.com/api/user -v
# 如果响应头包含 Access-Control-Allow-Origin: https://attacker.com
# 说明Origin被反射，可做数据窃取
```

### 3.5 管理面板暴露

```bash
# 常见管理面板路径检测
for path in admin login dashboard cpanel wp-admin manager \
            administrator phpmyadmin pgadmin jenkins \
            grafana kibana sonar nexus; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/$path")
    echo "$path -> $code"
done

# 如果发现管理面板，尝试默认凭证
# Tomcat: admin/admin, tomcat/tomcat
# Jenkins: admin/admin, admin/password
# Grafana: admin/admin, admin/grafana
# Kibana: elastic/changeme
# phpMyAdmin: root/(空密码)
```

### 3.6 TLS/SSL 配置错误

```bash
# 全面SSL评估
testssl.sh https://target.com

# 检测心脏出血漏洞（CVE-2014-0160）
nmap -sV --script ssl-heartbleed -p 443 target.com

# 检测CCS注入
nmap --script ssl-ccs-injection -p 443 target.com

# 检测是否支持不安全的重新协商
nmap --script ssl-known-key -p 443 target.com
```

### 3.7 第三方组件缺省配置

```json
// Spring Boot Actuator 未安全配置
// 如果未配置security，可直接访问
GET /actuator
GET /actuator/health
GET /actuator/env          // 环境变量（含密钥！）
GET /actuator/beans
GET /actuator/mappings
GET /actuator/heapdump     // JVM堆转储（含敏感数据！）

// 分析heapdump中的密码
// 使用 Eclipse Memory Analyzer (MAT) 或
// 使用 jhat 分析
jhat heapdump.hprof
```

### 3.8 日志/备份文件泄露

```bash
# 常见备份文件
curl -s https://target.com/backup.zip
curl -s https://target.com/backup.tar.gz
curl -s https://target.com/db_backup.sql
curl -s https://target.com/www.zip
curl -s https://target.com/nginx.conf

# 日志泄露
curl -s https://target.com/log.txt
curl -s https://target.com/access.log
curl -s https://target.com/error.log
curl -s https://target.com/var/log/

# 版本控制文件
curl -s https://target.com/.svn/entries
curl -s https://target.com/.hg/
curl -s https://target.com/BUILD
curl -s https://target.com/Dockerfile
```

---

## 🛡️ 四、防御方案

### 4.1 Web服务器安全配置

```nginx
# Nginx 安全配置示例
# 隐藏服务器版本
server_tokens off;

# 禁用目录列表
autoindex off;

# 安全HTTP头
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Content-Security-Policy "default-src 'self'" always;
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# 限制敏感路径访问
location ~ /\.(git|svn|hg|env) {
    deny all;
    return 404;
}

location ~ (backup|dump|log|sql)\.(zip|tar|gz|sql|txt|log) {
    deny all;
    return 404;
}
```

### 4.2 通用配置加固清单

| 项目 | 检查项 | 操作 |
|------|--------|------|
| 🛡️ 默认凭证 | 是否修改所有默认密码？ | 强制首次修改 |
| 🛡️ 调试模式 | 生产环境是否关闭？ | 设置 `DEBUG=False` |
| 🛡️ 错误处理 | 是否返回详细错误？ | 使用自定义错误页 |
| 🛡️ 最小服务 | 是否运行多余服务？ | 关闭不必要的端口 |
| 🛡️ 最小权限 | 服务是否以root运行？ | 使用非root用户 |
| 🛡️ 定期更新 | 组件是否最新？ | 建立更新策略 |
| 🛡️ 配置审计 | 是否定期审计配置？ | 自动化配置检查 |

### 4.3 云环境安全配置

```bash
# AWS S3 桶策略（只允许HTTPS访问）
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::target-bucket/*",
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    }
  ]
}
```

### 4.4 自动化配置检查工具

```bash
# 使用 lynis 进行系统安全审计
lynis audit system

# 使用 OpenSCAP 合规检查
oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_cis \
  --results results.xml /usr/share/xml/scap/ssg/content/ssg-centos7-ds.xml

# Docker安全扫描
docker scan image_name

# 使用 kube-bench 检查K8s配置
kube-bench run --targets master,node
```

---

## 🎯 五、实战检查清单

### 5.1 渗透测试重点

- [ ] 目录列表是否开启？
- [ ] 是否存在默认/弱凭证？
- [ ] 是否暴露 `.git/.env/backup` 等文件？
- [ ] HTTP安全头是否完整？
- [ ] 错误信息是否泄露敏感数据？
- [ ] 云存储桶是否配置正确？
- [ ] Docker/K8s API是否暴露？
- [ ] 调试模式是否开启？
- [ ] CORS是否配置过松？
- [ ] 管理面板是否暴露在外网？

### 5.2 推荐工具

| 工具 | 用途 |
|------|------|
| nuclei | 模板化漏洞扫描 |
| testssl.sh | SSL/TLS安全检测 |
| s3scanner | S3存储桶枚举 |
| GitHack | .git泄露利用 |
| lynis | 系统安全审计 |
| kube-bench | K8s安全检测 |

---

> **💡 核心原则**：安全的系统不是"配置了安全功能"，而是**默认就是安全的**！最小化攻击面、最小权限、最小化信息泄露。
