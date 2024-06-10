---
title: savesanta
author: hgbe02
date: 2024-03-20
categories: [Training platform,Hackmyvm]  
tags: [Hackmyvm,web]  
permalink: "/Hackmyvm/savesanta.html"
---

# savesanta

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403201453895.png" alt="image-20240320130010943" style="zoom:50%;" />

不知道是不是，打开看一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403201453901.png" alt="image-20240320130047900" style="zoom:50%;" />

看样子应该是的了，开始入手。

## 信息搜集

### 扫描开放端口

```bash
nmap -sT -T4 -sV -p- 10.0.2.6 
```

```text
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.0p1 Ubuntu 1ubuntu8.7 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### 目录爆破

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403201453902.png" alt="image-20240320132439826" style="zoom:50%;" />

我超，黑页。

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403201453904.png" alt="image-20240320134116416" style="zoom:50%;" />

```bash
dirb http://10.0.2.6
```

```text
---- Scanning URL: http://10.0.2.6/ ----
==> DIRECTORY: http://10.0.2.6/administration/                                                                        
+ http://10.0.2.6/index.html (CODE:200|SIZE:1012)                                                                     
==> DIRECTORY: http://10.0.2.6/javascript/                                                                            
+ http://10.0.2.6/robots.txt (CODE:200|SIZE:70)                                                                       
+ http://10.0.2.6/server-status (CODE:403|SIZE:199)                                                                   
                                                                                                                      
---- Entering directory: http://10.0.2.6/administration/ ----
                                                                                                                      
---- Entering directory: http://10.0.2.6/javascript/ ----
==> DIRECTORY: http://10.0.2.6/javascript/jquery/                                                                     
                                                                                                                      
---- Entering directory: http://10.0.2.6/javascript/jquery/ ----
+ http://10.0.2.6/javascript/jquery/jquery (CODE:200|SIZE:289782)                                                   
```

再`fuzz`一下：

```bash
ffuf -u http://10.0.2.6/FUZZ -w directory-list-lowercase-2.3-medium.txt
```

```text
javascript              [Status: 301, Size: 235, Words: 14, Lines: 8, Duration: 1ms]
administration          [Status: 301, Size: 239, Words: 14, Lines: 8, Duration: 28ms]
santa                   [Status: 301, Size: 230, Words: 14, Lines: 8, Duration: 1ms]
                        [Status: 200, Size: 1012, Words: 278, Lines: 24, Duration: 0ms]
server-status           [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 30ms]
```

## 漏洞利用

### 访问敏感目录

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403201453905.png" alt="image-20240320133247463" style="zoom:50%;" />

是一个登录界面，尝试弱口令以及sql注入，但是未果，逐渐暴躁，突然就不见了，继续搜集信息：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403201453906.png" alt="image-20240320134225529" style="zoom:50%;" />

打开主页发现：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403201453907.png" alt="image-20240320134417753" style="zoom:50%;" />

看来被篡改了，重新信息搜集：

```bash
sudo nmap -sC -sV -T4 -A -p- 10.0.2.6
```

```text
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 9.0p1 Ubuntu 1ubuntu8.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 76:06:46:f1:83:85:a4:22:8c:2b:12:d4:2d:58:27:49 (ECDSA)
|_  256 76:54:26:9d:e8:4a:72:5e:6e:7f:68:58:20:6e:bb:d4 (ED25519)
80/tcp    open  http    Apache httpd
|_http-title: Merry Christmas to everyone - Santa Claus
|_http-server-header: Apache
54571/tcp open  unknown
MAC Address: 08:00:27:99:CD:C7 (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.8
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

发现多开了一个端口！尝试连接一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403201453908.png" alt="image-20240320135157399" style="zoom:50%;" />

阿哲。。。

## 提权

老样子信息搜集，信息搜集还是信息搜集！

### 升级一下shell

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

拿到第一个flag！

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403201453909.png" alt="image-20240320135625158" style="zoom:50%;" />

```bash
echo $PATH
# /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
```

这俩`games`都没啥东西：

去home找到五个用户：

```text
alabaster  bill  bushy  pepper  santa  shinny  sugurplum  wunorse
```

然后就是漫长的信息搜集，最后发现了一个东西：

```text
alabaster@santa:/var/www/html$ cd ../
cd ../
alabaster@santa:/var/www$ ls
ls
html
alabaster@santa:/var/www$ cd ../
cd ../
alabaster@santa:/var$ ls
ls
backups  crash  local  log   opt  snap   tmp
cache    lib    lock   mail  run  spool  www
alabaster@santa:/var$ ls -l mail
ls -l mail
total 4
-rw-rw---- 1 alabaster mail 1156 Mar 20 05:35 alabaster
-rw------- 1 root      mail    0 Jan  4 10:41 root
alabaster@santa:/var$ mail
mail
"/var/mail/alabaster": 1 message 1 new
>N   1 Santa Claus        Wed Mar 20 05:35  25/1108  Important update about th
? fuck
fuck
Unknown command: fuck
? 1
1
Return-Path: <santa@santa.hmv>
Received: from santa.hmv (localhost [127.0.0.1])
        by santa.hmv (8.17.1.9/8.17.1.9/Debian-2) with ESMTP id 42K5Z35o002068
        for <alabaster@santa.hmv>; Wed, 20 Mar 2024 05:35:03 GMT
Received: (from santa@localhost)
        by santa.hmv (8.17.1.9/8.17.1.9/Submit) id 42K5Z3LN002067;
        Wed, 20 Mar 2024 05:35:03 GMT
From: Santa Claus <santa@santa.hmv>
Message-Id: <202403200535.42K5Z3LN002067@santa.hmv>
Subject: Important update about the hack
To: <alabaster@santa.hmv>
User-Agent: mail (GNU Mailutils 3.15)
Date: Wed, 20 Mar 2024 05:35:03 +0000

Dear Alabaster, 

As you know our systems have been compromised. You have been assigned to restore all systems as soon as possible. 

I heard you have kicked out the Naughty Elfs so they cannot come back into the system. To be more secure we have hired Bill Gates. 

His account has been created and ready to logon. When Bill arrives, tell him his--More--
 username is 'bill'. The password has been set to: 'JingleBellsPhishingSmellsHac--More--
kersGoAway' He will know what to do next. 
--More--
        
--More--
Please help Bill as much as possible so Christmas can go on! 
--More--
        
--More--
- Santa
```

他给了我们ssh的凭证，我们尝试切换一下吧：

### 切换用户bill

```bash
su bill
JingleBellsPhishingSmellsHackersGoAway
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403201453910.png" alt="image-20240320140923834" style="zoom:50%;" />

### 提权root

使用一下：

```bash
sudo /usr/bin/wine cmd
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403201453911.png" alt="image-20240320141446367" style="zoom:50%;" />

wtf，什么情况。

经过群主提点一下，尝试使用ssh登录，发现可以正常使用了：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403201453912.png" alt="image-20240320144905939" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403201453913.png" alt="image-20240320144701752" style="zoom:50%;" />

获取flag！

```bash
Z:\home\bill>cd /root

Z:\root>dir
Volume in drive Z has no label.
Volume Serial Number is 4afb-ec36

Directory of Z:\root

  1/4/2024  12:25 PM  <DIR>         .
12/30/2023   6:55 PM  <DIR>         ..
12/30/2023   8:10 PM         3,130  root.txt
12/30/2023   7:16 PM  <DIR>         snap
       1 file                     3,130 bytes
       3 directories      2,250,649,600 bytes free


Z:\root>type root.txt
                               ..,,,,,,,,,,,,,,,,..
                        ..,,;;;;;;;;;;;;;;;;;;;;;;;;;;,,.
                    .,::::;;;;aaaaaaaaaaaaaaaaaaaaaaaaaaa;;,,.
                .,;;,:::a@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@a,
              ,;;;;.,a@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@a
           ,;;;;%;.,@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@a,
        ,;%;;;;%%;,@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
     ,;;%%;;;;;%%;;@@@@@@@@@@@@@@'%v%v%v%v%v%v%v%v%v%v%v%v`@@@@@@@@@
   ,;;%%;;;;:;;;%;;@@@@@@@@@'%vvvvvvvvvnnnnnnnnnnnnnnnnvvvvvv%`@@@@'
  ,;%%;;;;;:;;;;;;;;@@@@@'%vvva@@@@@@@@avvnnnnnnnnnnvva@@@@@@@OOov,
 ,;%;;;;;;:::;;;;;;;@@'OO%vva@@@@@@@@@@@@vvnnnnnnnnvv@@@@@@@@@@@Oov
 ;%;;;;;;;:::;;;;;;;;'oO%vvn@@%nvvvvvvvv%nnnnnnnnnnnnn%vvvvvvnn%@Ov
 ;;;;;;;;;:::;;;;;;::;oO%vvnnnn>>nn.   `nnnnnnnnnnnn>>nn.   `nnnvv'
 ;;;;;;;;;:::;;;;;;::;oO%vvnnvvmmmmmmmmmmvvvnnnnnn;%mmmmmmmmmmmmvv,
 ;;;;;;;;;:::;;;;;;::;oO%vvmmmmmmmmmmmmmmmmmvvnnnv;%mmmmmmmmmmmmmmmv,
 ;;;;;;;;;;:;;;;;;::;;oO%vmmmmnnnnnnnnnnnnmmvvnnnvmm;%vvnnnnnnnnnmmmv
  `;%;;;;;;;:;;;;::;;o@@%vvmmnnnnnnnnnnnvnnnnnnnnnnmmm;%vvvnnnnnnmmmv
   `;;%%;;;;;:;;;::;.oO@@%vmmnnnnnnnnnvv%;nnnnnnnnnmmm;%vvvnnnnnnmmv'
     `;;;%%;;;:;;;::;.o@@%vvnnnnnnnnnnnvv%;nnnnnnnmm;%vvvnnnnnnnv%'@a.
      a`;;;%%;;:;;;::;.o@@%vvvvvvvvvvvvvaa@@@@@@@@@@@@aa%%vvvvv%%@@@@o.
     .@@o`;;;%;;;;;;::;,o@@@%vvvvvvva@@@@@@@@@@@@@@@@@@@@@avvvva@@@@@%O,
    .@@@@@Oo`;;;;;;;;::;o@@@@@@@@@@@@@@@@@@@@"""""""@@@@@@@@@@@@@@@@@OO@a
  .@@@@@@@@@OOo`;;;;;;:;o@@@@@@@@@@@@@@@@"           "@@@@@@@@@@@@@@oOO@@@,
 .@@@@o@@@@@@@OOo`;;;;:;o,@@@@@@@@@@%vvvvvvvvvvvvvvvvvv%%@@@@@@@@@oOOO@@@@@,
 @@@@o@@@@@@@@@OOo;::;'oOOooooooooOOOo%vvvvvvvvvvvvvv%oOOooooooooOOO@@@O@@@,
 @@@oO@@@@@@@@@OOa@@@@@a,oOOOOOOOOOOOOOOoooooooooooooOOOOOOOOOOOOOO@@@@Oo@@@
 @@@oO@@@@@@@OOa@@@@@@@@Oo,oO@@@@@@@@@@OOOOOOOOOOOOOO@@@@@@@@@@@@@@@@@@Oo@@@
 @@@oO@@@@@@OO@@@@@@@@@@@OO,oO@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@Oo@@@
 @@@@o@@@@@@OO@@@@@@@@@@OOO,oO@@@@@@@@@O@@@@@@@@@@@@@@@@@@@@@o@@@@@@@@@O@@@@
 @@@@@o@@@@@OOo@@@@@@@OOOO'oOO@@@@@@@@Oo@@@@@@@@@@@@O@@@@@@@@Oo@@@@@@@@@@@@a
`@@@@@@@O@@@OOOo`OOOOOOO'oOO@@@@@@@@@O@@@@@@@@@@@@@@@O@@@@@@@@Oo@@@@@@@@@@@@
 `@@@@@OO@@@@@OOOooooooooOO@@@@@@@@@@@@@@@@@@@@@@@@@@Oo@@@@@@@Oo@@@@@@oO@@@@
   `@@@OO@@@@@@@@@@@@@@@@@@@O@@@@@@@@@@@@@@@@@@@@@@@@Oo@@@@@@@O@@@@@@@oO@@@'
      `@@`O@@@@@@@@@@@@@@@@@@@Oo@@@@@@@@@@@@@@@@@@@@@@Oo@@@@@@@@@@@@@@@O@@@'
        `@ @@@@@@@@@@@@@@@@@@@OOo@@@@@@@@@@@@@@@@@@@@@O@@@@@@@@@@@@@@@'@@'
           `@@@@@@@@@@@@@@@@@@OOo@@@@@@@@@@@@@@@@@@@@O@@@@@@@@@@@@@@@ a'
               `@@@@@@@@@@@@@@OOo@@@@@@@@@@@@@@@@@@@@@@@@Oo@@@@@@@@'
                  `@@@@@@@@@@@Oo@@@@@@@@@@@@@@@@@@@@@@@@@Oo@@@@'
                      `@@@@@@Oo@@@@O@@@@@@@@@@@@@@@@@@@'o@@'
                          `@@@@@@@@oO@@@@@@@@@@@@@@@@@ a'
                              `@@@@@oO@@@@@@@@@@@@@@' '
                                '@@@o'`@@@@@@@@'
                                 @'   .@@@@'
                                     @@'
                                   @'

```

同时还感谢[mikannse]()师傅提的意见:

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403201456822.png" alt="image-20240320145547626" style="zoom:50%;" />

(这样的话不就白模糊了。。。。。)