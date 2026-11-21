---
title: 第 3 周

---

前置阅读材料：

- [HTB Academy-Session Security 模组](https://academy.hackthebox.com/course/preview/session-security)：了解 Cookie 与 Session 的运作，会话是访问控制的身份边界，这周实验里越权就是拿别人的会话做不该做的事
- [HTB Academy-File Upload Attacks 模组](https://academy.hackthebox.com/course/preview/file-upload-attacks)：了解文件上传的攻击面，作为这周实验的阅读材料，可能会因为收费无法阅读，只看 PortSwigger 本站的內容也可以满足需求

参考阅读材料：

- [OWASP WSTG - Authorization](https://wstg.owasp.org/latest/09-Authorization/)：授权测试章节总览
- [OWASP WSTG - Bypassing Authorization Schema](https://wstg.owasp.org/latest/09-Authorization/02-Bypassing_Authorization_Schema/)：绕过授权方案
- [OWASP WSTG - Insecure Direct Object References](https://wstg.owasp.org/latest/09-Authorization/04-Insecure_Direct_Object_References/)：IDOR，水平越权的经典形态
- [OWASP Cheat Sheet - Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)：防御视角看访问控制应该怎么做，防御清单就是绕过手法的反面
- [OWASP WSTG - Upload of Malicious Files](https://wstg.owasp.org/latest/14-Business_Logic/09-Upload_of_Malicious_Files/)
- [OWASP Cheat Sheet - File Upload](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)：防御视角看上传校验应该怎么做

拓展材料：

- 本站速查表-[失效的访问控制（A01）](../cheatsheet/21-a01-broken-access-control.md)：越权手法速查
- 本站速查表-[文件上传与包含](../cheatsheet/14-file-upload-lfi.md)：上传绕过与文件包含联动速查
- 本站速查表-[SRC 实战：文件上传与 API 安全](../cheatsheet/54-src-upload-api.md)：实战视角的上传利用
- [HackTricks - File Upload](https://book.hacktricks.xyz/pentesting-web/file-upload)：上传绕过手法合集，覆盖面比靶场广得多
- [PayloadsAllTheThings - Upload Insecure Files](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files)：上传 Payload 字典，可以直接拿去做 Intruder 的字典
- [WSTG - API Broken Object Level Authorization](https://wstg.owasp.org/latest/16-API_Testing/02-API_Broken_Object_Level_Authorization/)：越权在 API 场景的形态（BOLA）
- [AntSword-Loader](https://github.com/AntSwordProject/AntSword-Loader)：蚁剑，webshell 管理工具。PortSwigger 的上传实验到 RCE 就停了，想继续深入 webshell 管理可以自行了解

实验內容：

- Access Control Vulnerabilities：访问控制/越权，13个实验
- File Upload Vulnerabilities：文件上传，7个实验

访问控制可以联系 week1 中的 Authentication 思考：认证回答“你是谁”，访问控制回答“你能做什么”。认证给了你合法身份，访问控制决定这个身份的边界，两者的校验都必须落在服务端。week1 中说过一个数据安全的核心思想是：不要信任前端，访问控制会继续深化这个理念。

文件上传可以联系 week1 中的路径遍历/文件包含思考：上传是往服务器放文件，文件包含是把文件执行进来。上传能拿到 RCE 的本质，就是两者联动——上传一个含 PHP 代码的文件，再让服务器把它当代码执行。文件上传、文件包含、RCE 是一套经典的 web 攻击链。
