---
title: KIOPTRIX:LEVEL1
author: hgbe02
date: 2024-01-25 20:00:00 +0800
categories: [Training platform,Vulnhub]  
tags: [Vulnhub,web]  
permalink: "/Vulnhub/Kioptrix-level1.html"
---

# KIOPTRIX: LEVEL 1

![image-20240125154640719](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401252122606.png)

今天尝试`KIOPTRIX: LEVEL 1`靶场。

打开靶场：

![image-20240125160225054](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401252122607.png)

## 解决靶机网络配置失败的问题(已解决)

打开以后扫描没扫出来，遇到这个bug好几次了，今天必要把他解决掉，查阅[相关资料](https://www.bilibili.com/video/BV1mu411t7Wq/?spm_id_from=333.337.search-card.all.click&vd_source=8981ead94b755f367ac539f6ccd37f77)，Z神给出了答复：

> 更改 Kioptix Level 1.vmx ，以文本打开，找到	ethernet0.connectionType = "bridged" 改为 ethernet0.connectionType = "VMnet0"

![image-20240125162315007](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401252122609.png)

修改以后：

```shell
┌──(kali㉿kali)-[~]
└─$ sudo netdiscover -i etho
pcap_open_live(): etho: No such device exists (No such device exists)
                                                                                              
┌──(kali㉿kali)-[~]
└─$ nmap 192.168.244.1/24 -sn --min-rate 2000 -r
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-25 03:26 EST
Nmap scan report for 192.168.244.2
Host is up (0.00064s latency).
Nmap scan report for 192.168.244.133
Host is up (0.000059s latency).
Nmap done: 256 IP addresses (2 hosts up) scanned in 2.82 seconds
```

坏了，这个网络配置原因还是搞不好，将`.vxm里的bridged改成nat`试试，再将网络适配器改为NAT，老样子，扫不到，这时候发现了[一个师傅的做法](https://www.youtube.com/watch?v=23-ycrZBMDw)，前几步和我一摸一样，尝试总结一下，重新试试：

> ①右键文本打开 .vmx 文件
>
> ②修改 ethernet0.networkName = "Bridged" > ethernet0.networkName = "nat"
>
> ③网络适配器改为NAT.
>
> ④升级靶场为 VMware Station 16.x .
>
> ⑤开启虚拟机，及时查看连接方式，如果变为桥接赶紧改成NAT（实测确实变了。。。）

扫描一下，看看是不是有效：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401252122610.png" alt="image-20240125170026839" style="zoom:50%;" />

 查看一下靶机MAC地址：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401252122611.png" alt="image-20240125170110710" style="zoom: 33%;" />

看来是成功了，访问一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401252122612.png" alt="image-20240125170200095" style="zoom:50%;" />

只能说对的一塌糊涂，牛逼，小飞侠的师傅。

## 踩点一下

随便看看网站，使用`wappaylyzer`查看一下相关配置：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401252122613.png" alt="image-20240125170532711" style="zoom: 25%;" />

没有发现什么有意思的东西，源代码里也没有啥提醒。

## 端口扫描

使用 `nmap` 进行端口扫描：

```shell
sudo nmap -A -n- IP
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401252122614.png" alt="image-20240125171852922" style="zoom: 50%;" />

可以看到开放了一个139端口还有一个22端口，139端口是一个Samba服务的端口：

> Samba是用来完成SMB的一种软件，由澳大利亚的Andew Tridgell开发，是一种在Linux(Unix)环境下运行的免费软件。
>
>  SAMBA 最初发展的主要目就是要用来沟通 Windows 与 Unix Like 这两个不同的作业平台
>
> - 分享档案与打印机服务；
> - 可以提供用户登入 SAMBA 主机时的身份认证，以提供不同身份者的个别数据；
> - 可以进行 Windows 网络上的主机名解析 (NetBIOS name)
> - 可以进行装置的分享 (例如 Zip, CDROM...)

## 目录扫描

```shell
disearch -u IP
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401252122615.png" alt="image-20240125193737275" style="zoom: 67%;" />

尝试访问`/mrtg`还有`test.php`:

> Multi Router Traffic Grapher------MRTG**是一个监控网络链路流量负载的工具软件**，通过snmp协议得到设备的流量信息，并将流量负载以包含PNG格式的图形的HTML 文档方式显示给用户，以非常直观的形式显示流量负载。

![192.168.244.137_mrtg_](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401252122616.png)

![image-20240125193950552](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401252122617.png)

尝试搜索一下`MRTG 2.9.6`的漏洞，可以找到目录遍历漏洞，但是这里似乎并不能实现。

## Apache远程代码执行漏洞

`Zer0-hex`师傅做成功过，我也试试，尝试搜索相关漏洞：

![image-20240125195628697](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401252122618.png)

找到一个`Apache 1.3.x mod_mylo - Remote Code Execution`，这个漏洞不戳。

```shell
┌──(kali㉿kali)-[~]
└─$ searchsploit Apache -m 67.c
[!] Could not find EDB-ID #
  Exploit: Apache 1.3.x mod_mylo - Remote Code Execution
      URL: https://www.exploit-db.com/exploits/67
     Path: /usr/share/exploitdb/exploits/multiple/remote/67.c
    Codes: OSVDB-10976, CVE-2003-0651
 Verified: True
File Type: C source, ASCII text
Copied to: /home/kali/67.c
```

但是当我编译完以后进行exploit的时候就出现了错误：

```shell
gcc 67.c   # ->a.out
┌──(kali㉿kali)-[~]
└─$ ./a.out -t 192.168.244.137
[-] Attempting attack [ SuSE 8.1, Apache 1.3.27 (installed from source) (default) ] ...
[*] Bruteforce failed.... 
Have a nice day!
```

嘶，看来在我这里是不行的。。。（尝试很多次了，重启也试过了）

## MSF使用Samba trans2open漏洞

去瞅瞅的那个139端口的那个服务看看有没有漏洞，先查看一下版本：

```shell
use auxiliary/scanner/smb/smb_version
info
set RHOST  IP
run/exploit
```

![image-20240125205155513](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401252122619.png)

发现这里的Samba版本是`2.2.1a`，搜索一下相关漏洞，然后下载一下，这里发现一个远程执行漏洞：

![image-20240125205948006](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401252122620.png)

编译执行一下，这里我没看到有个必要参数需要填一下：

![image-20240125210048394](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401252122621.png)

如图我们已经拿到了root。
