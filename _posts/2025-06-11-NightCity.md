---
title: NightCity
author: hgbe02
date: 2025-06-11 02:05:26 +0800
categories: [Training platform,Hackmyvm]  
tags: [Hackmyvm,web]  
permalink: "/Hackmyvm/NightCity.html"
---

# NightCity

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506110209158.png" alt="image-20250610235946862" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506110209159.png" alt="image-20250611000748513" style="zoom:50%;" />

## 信息搜集

### 端口扫描

```bash
┌──(kali㉿kali)-[~/temp/NightCity]
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
RustScan: Exploring the digital landscape, one IP at a time.

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 192.168.10.105:21
Open 192.168.10.105:22
Open 192.168.10.105:80

PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 64 vsftpd 2.0.8 or later
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 192.168.10.106
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxrwxrwx    2 0        0            4096 Jun 09  2022 reminder [NSE: writeable]
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ce:ac:1c:04:d6:f6:64:d6:d9:9d:88:c9:0d:66:a9:45 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCg0hWxl3bxSzzZNd+khD0gsax/BKxpgSokX+YNR9qlWd472Usw2A89TxEd/kX/E+jhzoTcNkHSC2fD1k+HOCxcCepciA/URvncuq14eRsTmKZZvDyxv6GM3K4ImESyao1h3VLGhsi2PVkDEl0FRUq/VDu6eV5lKCbqhBvu7x2S0h3y9oswcwdQg416n8EQt05HaKjTUhs5o7Bn3qSnB6DLIb7m+PjfTqEtRz+xREd4JO/ZFS8GeGVjY1bINMlQkOb7wPFfkAliKtH5RrLSH01xdVH1LENPzckSDdwUlNfGrfrF9IjmlTqs11VG/mMe/k3HhpVJJAV5mUFYC82+u1H7
|   256 4f:f1:7b:69:5c:47:b2:91:b8:d2:2f:82:73:b7:fc:03 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLKNPh3DeZrMYPPzC9eqiYl3qj5NgTmO4cQggBcm+6Rurlr/62SPZg0vusxQqUPWu4Mh3aLIXWKvClMD5xRBeVw=
|   256 65:6b:3b:8c:89:81:4d:f3:98:98:5a:ed:57:cf:58:c9 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKCn8PIIg7Le9a2M+piz2m281CaS68sL6vCSUlufOxMa
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.29 ((Ubuntu))
|_http-title: NightCity Web Server
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
MAC Address: 08:00:27:2F:24:00 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### 目录扫描

```bash
┌──(kali㉿kali)-[~/temp/NightCity]
└─$ gobuster dir -u http://$IP/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html,zip
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.10.105/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,html,zip,php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 8407]
/.html                (Status: 403) [Size: 279]
/images               (Status: 301) [Size: 317] [--> http://192.168.10.105/images/]
/about.html           (Status: 200) [Size: 7744]
/contact.html         (Status: 200) [Size: 6349]
/gallery.html         (Status: 200) [Size: 8768]
/js                   (Status: 301) [Size: 313] [--> http://192.168.10.105/js/]
/robots.txt           (Status: 200) [Size: 136]
/secret               (Status: 301) [Size: 317] [--> http://192.168.10.105/secret/]
/robin                (Status: 200) [Size: 1873]
/.html                (Status: 403) [Size: 279]
/server-status        (Status: 403) [Size: 279]
```

## 漏洞发现

### 踩点

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506110209161.png" alt="image-20250611001021142" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506110209162.png" alt="image-20250611001042100" style="zoom:50%;" />

### 敏感目录

```bash
┌──(kali㉿kali)-[~/temp/NightCity]
└─$ curl -s http://$IP/robots.txt                                                                                                                
#Good Job

To continue, you need a workmate. Our lastest news is that Robin is close to
NightCity. Try to find him, Robin has the key!!
```

发现了一个人名字叫`Robin`，这个人有我们想要的东西。

```bash
┌──(kali㉿kali)-[~/temp/NightCity]
└─$ curl -s http://$IP/secret/ | html2text
****** Index of /secret ******
[[ICO]]       Name              Last modified    Size Description
===========================================================================
[[PARENTDIR]] Parent Directory                      -  
[[IMG]]       most-wanted.jpg   2022-06-09 19:43 128K  
[[IMG]]       some-light.jpg    2022-06-09 19:42 214K  
[[IMG]]       veryImportant.jpg 2022-06-03 13:33 185K  
===========================================================================
     Apache/2.4.29 (Ubuntu) Server at 192.168.10.105 Port 80

# wget http://$IP/secret/most-wanted.jpg
# wget http://$IP/secret/some-light.jpg                                                 
# wget http://$IP/secret/veryImportant.jpg

┌──(kali㉿kali)-[~/temp/NightCity]
└─$ exiftool *                                               
======== most-wanted.jpg
ExifTool Version Number         : 13.10
File Name                       : most-wanted.jpg
Directory                       : .
File Size                       : 131 kB
File Modification Date/Time     : 2022:06:09 13:43:07-04:00
File Access Date/Time           : 2025:06:10 12:13:20-04:00
File Inode Change Date/Time     : 2025:06:10 12:13:20-04:00
File Permissions                : -rw-rw-r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : None
X Resolution                    : 1
Y Resolution                    : 1
Image Width                     : 1334
Image Height                    : 750
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 1334x750
Megapixels                      : 1.0
======== some-light.jpg
ExifTool Version Number         : 13.10
File Name                       : some-light.jpg
Directory                       : .
File Size                       : 219 kB
File Modification Date/Time     : 2022:06:09 13:42:53-04:00
File Access Date/Time           : 2025:06:10 12:13:30-04:00
File Inode Change Date/Time     : 2025:06:10 12:13:30-04:00
File Permissions                : -rw-rw-r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
Exif Byte Order                 : Big-endian (Motorola, MM)
X Resolution                    : 72
Y Resolution                    : 72
Resolution Unit                 : inches
Y Cb Cr Positioning             : Centered
GPS Version ID                  : 2.3.0.0
GPS Latitude Ref                : North
GPS Longitude Ref               : East
XMP Toolkit                     : Image::ExifTool 12.41
Description                     : 26º21'28.59"N,127º47'0.99"E
Author                          : GothamCity
Image Width                     : 2048
Image Height                    : 1179
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 2048x1179
Megapixels                      : 2.4
GPS Latitude                    : 26 deg 21' 28.59" N
GPS Longitude                   : 127 deg 47' 0.99" E
GPS Position                    : 26 deg 21' 28.59" N, 127 deg 47' 0.99" E
======== veryImportant.jpg
ExifTool Version Number         : 13.10
File Name                       : veryImportant.jpg
Directory                       : .
File Size                       : 190 kB
File Modification Date/Time     : 2022:06:03 07:33:09-04:00
File Access Date/Time           : 2025:06:10 12:13:39-04:00
File Inode Change Date/Time     : 2025:06:10 12:13:39-04:00
File Permissions                : -rw-rw-r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.02
Resolution Unit                 : None
X Resolution                    : 1
Y Resolution                    : 1
Image Width                     : 1200
Image Height                    : 740
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 1200x740
Megapixels                      : 0.888
    3 image files read
```

接着看`Robin`目录：

```bash
┌──(kali㉿kali)-[~/temp/NightCity]
└─$ curl -s http://$IP/robin | html2text
****** BATMAN Y ROBIN VOL. 01. PARTE I. ******
Hay un nuevo DÃºo DinÃ¡mico en la ciudad. Tras la desapariciÃ³n de Bruce Wayne,
y concluida La Batalla por la Capucha, el Hombre MurciÃ©lago es ahora Dick
Grayson. Pero tendrÃ¡ que llevar a cabo su misiÃ³n como justiciero junto a un
acompaÃ±ante imprevisto: Damian Wayne, hijo de Bruce y Talia al Ghul, ha
asumido el papel de Robin... despuÃ©s de que Tim Drake, el anterior titular,
haya adoptado otra identidad y emprendido una difÃ­cil bÃºsqueda destinada a
arrojar increÃ­bles resultados sobre el verdadero destino del mentor de todos
ellos. Sin embargo, mientras tanto, Dick y Damian deberÃ¡n afrontar una Gotham
que parece mÃ¡s enloquecida que nunca: a villanos cada vez mÃ¡s insÃ³litos,
entre ellos el Profesor Pyg y los demÃ¡s miembros de su Circo de lo ExtraÃ±o,
se une el regreso de otro excompaÃ±ero de Batman. Jason Todd, alias Capucha
Roja, no solo cuenta con alguien muy sorprendente para ayudarle... Â¡tambiÃ©n
estÃ¡ decidido a poner fin al reinado de los nuevos Batman y Robin antes
incluso de que empiece!
Grant Morrison y Frank Quitely, un tÃ¡ndem con obras tan reconocidas como All-
Star Superman y New X-Men, toma las riendas de la primera colecciÃ³n del
Caballero Oscuro y el Chico Maravilla que lleva sus nombres en el tÃ­tulo...
aunque los integrantes de este equipo no sean los habituales ni por asomo.
Junto a Philip Tan (Batman del Futuro: La ciudad de japon), los dos aclamados
autores escoceses abren una etapa repleta de innovadores conceptos y
situaciones sin parangÃ³n que no dejarÃ¡n indiferente a ningÃºn lector. Lo
demuestran a la perfecciÃ³n los dos arcos argumentales iniciales de la serie,
Batman renacido y La venganza de Capucha Roja, que se incluyen Ã­ntegramente en
este tomo de Batman Saga
```

看不懂，浏览器翻译一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506110209163.png" alt="image-20250611001653609" style="zoom:50%;" />

emmmmmm。。。。。。。。。。。

### ftp服务探测

发现开放了`ftp`服务，且允许匿名登录，尝试登录一下：

```bash
┌──(kali㉿kali)-[~/temp/NightCity]
└─$ lftp $IP
lftp 192.168.10.105:~> dir
drwxrwxrwx    2 0        0            4096 Jun 09  2022 reminder
lftp 192.168.10.105:/> cd reminder/
lftp 192.168.10.105:/reminder> dir
-rwxr-xr-x    1 0        0              33 Jun 09  2022 reminder.txt
lftp 192.168.10.105:/reminder> get reminder.txt 
33 bytes transferred                                
lftp 192.168.10.105:/reminder> exit

┌──(kali㉿kali)-[~/temp/NightCity]
└─$ cat reminder.txt           
Local user is in the coordinates
```

### 文件隐藏信息

之前三个图片啥东西都没有，看一下是否是一个`misc`，进行提取：

```bash
┌──(kali㉿kali)-[~/temp/NightCity]
└─$ stegseek most-wanted.jpg
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "japon"          
[i] Original filename: "pass.txt".
[i] Extracting to "most-wanted.jpg.out".

┌──(kali㉿kali)-[~/temp/NightCity]
└─$ stegseek some-light.jpg 
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Progress: 99.48% (132.7 MB)           
[!] error: Could not find a valid passphrase.

┌──(kali㉿kali)-[~/temp/NightCity]
└─$ stegseek veryImportant.jpg
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Progress: 99.99% (133.4 MB)           
[!] error: Could not find a valid passphrase.

┌──(kali㉿kali)-[~/temp/NightCity]
└─$ cat most-wanted.jpg.out    
VGhpc0lzVGhlUmVhbFBhc3N3MHJkIQ==

┌──(kali㉿kali)-[~/temp/NightCity]
└─$ cat most-wanted.jpg.out | base64 -d
ThisIsTheRealPassw0rd!
```

拿到了密码？？？？尝试搜寻一下用户名，可能藏在刚刚那一堆关于蝙蝠侠的段落里，尝试一下：

```bash
┌──(kali㉿kali)-[~/temp/NightCity]
└─$ cewl http://$IP/robin --lowercase > dict

┌──(kali㉿kali)-[~/temp/NightCity]
└─$ cat dict | grep robin                   
CeWL 6.2.1 (More Fixes) Robin Wood (robin@digi.ninja) (https://digi.ninja/)
robin

┌──(kali㉿kali)-[~/temp/NightCity]
└─$ hydra -L dict -p ThisIsTheRealPassw0rd! -f ssh://192.168.10.105:22 2>/dev/null
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-06-10 12:35:07
[DATA] max 16 tasks per 1 server, overall 16 tasks, 176 login tries (l:176/p:1), ~11 tries per task
[DATA] attacking ssh://192.168.10.105:22/
[22][ssh] host: 192.168.10.105   login: batman   password: ThisIsTheRealPassw0rd!
[STATUS] attack finished for 192.168.10.105 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-06-10 12:35:09
```

拿到了一个用户凭证！

```text
batman:ThisIsTheRealPassw0rd!
```

进行`ssh`登录：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506110209164.png" alt="image-20250611003634094" style="zoom: 33%;" />

## 提权

### 信息搜集

```bash
batman@NightCity:~$ ls -la
total 308
drwxr-xr-x 5 batman        batman          4096 jun 15  2022 .
drwxr-xr-x 6 root          root            4096 jun  9  2022 ..
-rw------- 1 batman        batman           972 jun 15  2022 .bash_history
-rw-r--r-- 1 batman        batman           220 jun  8  2022 .bash_logout
-rw-r--r-- 1 batman        batman          3771 jun  8  2022 .bashrc
drwx------ 2 batman        batman          4096 jun  9  2022 .cache
-rw-r--r-- 1 root          root              66 jun  9  2022 flag.txt
drwx------ 3 batman        batman          4096 jun  9  2022 .gnupg
-rw-rw-r-- 1 administrator administrator 272105 jun  9  2022 iknowyou.jpg
drwxrwxr-x 3 batman        batman          4096 jun 15  2022 .local
-rw-r--r-- 1 batman        batman           807 jun  8  2022 .profile
batman@NightCity:~$ cat flag.txt 
Nice try! but, this is not the flag. You have to keep working >:)
batman@NightCity:~$ sudo -l
[sudo] contraseña para batman: 
Lo sentimos, el usuario batman no puede ejecutar sudo en NightCity.
batman@NightCity:~$ file iknowyou.jpg
iknowyou.jpg: JPEG image data, Exif standard: [TIFF image data, big-endian, direntries=0], baseline, precision 8, 1200x454, frames 3
```

将文件传到本地进行查看：

```bash
# wget http://$IP:8888/iknowyou.jpg
┌──(kali㉿kali)-[~/temp/NightCity]
└─$ stegseek  iknowyou.jpg 
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Progress: 99.99% (133.4 MB)           
[!] error: Could not find a valid passphrase.
```

### 图片隐藏信息

顺便看一下前几个图片看看是啥样的：

`some-light.jpg`

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506110209165.png" alt="image-20250611004638221" style="zoom:50%;" />

`veryImportant.jpg`

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506110209166.png" alt="image-20250611004724462" style="zoom:50%;" />

`most-wanted.jpg`

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506110209167.png" alt="image-20250611004750293" style="zoom:50%;" />

`iknowyou.jpg`

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506110209168.png" alt="image-20250611004813932" style="zoom:50%;" />

最后一个图片肯定有问题，尝试使用`rockyou`字典进行探测一下：

```bash
┌──(kali㉿kali)-[~/temp/NightCity]
└─$ stegseek -wl /usr/share/wordlists/rockyou.txt iknowyou.jpg -v    
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek
based on steghide version 0.5.1

[v] Using stegofile "iknowyou.jpg".
[v] Running on 2 threads.
[v] Using wordlist file "/usr/share/wordlists/rockyou.txt".
[v] Added password guess: "".
[v] Added password guess: "iknowyou.jpg".
[v] Added password guess: "iknowyou".
[i] Progress: 99.99% (133.4 MB)           
[!] error: Could not find a valid passphrase.
```

尝试使用`stegsolve`分离图层看看：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506110209169.png" alt="image-20250611010135206" style="zoom:50%;" />

隐约可以看到烟囱有些字，但是看不清

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506110209170.png" alt="image-20250611010233770" style="zoom:50%;" />

好像是`ThatMadeMeLAugh`，但是不确定，尝试使用`ps`进行处理，选择"图像" > "调整" > "曲线"，通过调整曲线来控制图片的亮度和暗部：

![image-20250611011217521](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506110209171.png)

### 爆破

看出来是`ThatMadeMeL4ugh!`，又想到之前给出的提示，尝试再次进行爆破：

> User Flag -> Password of the first user accessing the system. Root Flag -> Password of the user who can see flag.txt

```bash
batman@NightCity:~$ cat /etc/passwd | grep sh | cut -d: -f1
root
administrator
joker
batman
sshd
anonymous
```

存一下，尝试爆破：

![image-20250611011721649](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506110209172.png)

尝试进行切换：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506110209173.png" alt="image-20250611011836567" style="zoom:50%;" />

尝试看一下作者提到的那个`flag.txt`在哪：

```bash
joker@NightCity:/home$ cd .joker
joker@NightCity:/home/.joker$ ls -la
total 28
drwxrwx--- 2 joker joker 4096 jun 13  2022 .
drwxr-xr-x 6 root  root  4096 jun  9  2022 ..
-rwxrwx--- 1 joker joker  220 jun  8  2022 .bash_logout
-rwxrwx--- 1 joker joker 3771 jun  8  2022 .bashrc
-rw-r--r-- 1 root  root  7157 jun  9  2022 flag.txt
-rwxrwx--- 1 joker joker  807 jun  8  2022 .profile
joker@NightCity:/home/.joker$ cat flag.txt 
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣴⣤⣶⡶⠛⠉⠉⠀⣀⣀⣀⣤⣤⣤⣶⣶⣒⣛⣉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣴⣿⣿⣿⡿⠋⢀⣠⣴⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣶⢤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⡴⣿⣿⣿⣿⣿⣿⣷⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⣟⡽⣟⣫⣭⣶⣶⣿⣿⣦⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢠⠏⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠋⠙⠉⠁⠀⢿⣿⣿⣿⣿⡿⠿⠿⣿⡿⣶⣦⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡄⠀
⠀⠀⠀⠀⠀⠀⣴⠃⠀⠀⠈⠻⠿⠿⠿⠿⠟⠛⠉⠁⠙⠿⠿⠛⠋⠉⠀⠀⠀⢀⣠⣴⣶⣾⣿⣿⣿⣿⣷⣶⣦⣙⠻⢿⣿⣿⣿⣶⣶⣶⣦⣤⣤⣴⢶⣾⠟⠀⠀
⠀⠀⠀⠀⠀⠰⡏⣴⣄⠀⠀⠀⠀⠀⢀⣠⣴⣤⣄⣀⠀⠀⠀⠀⠀⠀⢀⣴⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⡉⠙⠛⠛⠛⠛⠛⠉⣉⡴⢟⣡⣴⠏⠀
⠀⠀⠀⠀⠀⠀⠳⣿⣿⣷⣦⣀⠀⢠⣿⣿⣿⣿⣿⣿⣿⣶⡄⠀⣀⣶⣿⣿⡿⠿⠟⠛⠛⠛⠛⠛⠛⠛⠿⣿⣿⣿⣿⣿⣿⣶⠀⠀⠀⠀⣰⣾⣷⣾⣿⡿⠃⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠈⠛⠿⣿⣿⣷⣿⣿⣿⣿⣿⣿⣿⣿⣿⣣⢞⣭⠿⠋⠁⠀⠀⠀⠀⠀⠀⠠⣤⣤⣶⣾⣿⣿⣿⣯⣭⣿⣿⣶⣶⣿⣿⣿⣿⣿⣿⡟⠁⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠛⢿⡿⣿⣿⣿⣿⣿⣿⣿⡵⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠏⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⠀⠀⠉⠉⠛⠿⠿⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⣻⣿⣿⣿⣿⣿⣿⣿⣿⠿⠿⢿⣿⣿⠟⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡶⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠿⣿⣿⣿⣿⣿⠟⠁⠀⣠⣶⣿⠇⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⠀⠀⠀⠀⠀⠈⠳⣄⠀⠀⠀⣾⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⠀⠈⠻⣿⣿⡏⠀⣰⠊⠱⠛⡆⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡟⠀⠀⠀⠀⠀⠀⠀⠈⠳⣄⠈⠁⠀⠀⠀⠀⣀⣀⣠⠤⠶⠶⠿⣫⠟⠁⠀⠀⠀⠈⠻⣁⣼⠗⣿⠀⢠⡇⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡇⠀⠀⠀⠀⠀⣀⣀⣀⣀⣈⣷⠦⠤⠶⠖⠿⣭⣁⣀⣀⣠⣶⡾⠋⠀⠀⠀⠀⠀⠀⠀⠋⠁⢠⡇⠀⣼⠁⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⠿⠶⣶⣾⣯⣍⣉⠉⠙⠛⣿⠁⠀⠀⠀⠀⠀⠀⠉⠛⠿⠿⠛⠀⠀⠀⠀⣤⣀⣀⠀⠀⢸⡄⠀⣠⡜⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢈⡏⠉⠻⢷⣶⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⠤⠤⠤⢤⣄⣀⡀⠀⠀⠀⠀⠀⢿⠉⠁⠙⢦⡀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡾⠀⠀⢀⣀⣈⣼⠀⠀⠀⠀⠀⣀⣀⡴⠂⠉⠀⠀⠀⣠⢾⠁⠀⣽⠲⡄⠀⠀⠀⢸⡆⠀⠀⠀⠉⠳⢄⡀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⡇⠀⣴⣏⣁⠀⢻⠀⠀⢀⡴⣺⠝⠀⠀⠀⢀⣀⢶⠛⠁⠸⡄⠀⣿⠀⠹⠄⠀⠀⠈⡇⠀⠀⠀⠀⠀⠀⢙⠲⢄⡀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣷⢸⡇⠈⠻⣷⣾⠀⠀⣨⠟⣁⣀⣤⣴⠶⠋⠁⢸⠀⠀⠀⣷⠀⣿⠀⠀⠀⠀⠀⢠⡇⠀⠀⠀⢀⡟⠀⢸⠀⠀⠉⠒⠄
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢷⡳⠀⠀⠙⢿⣀⡶⠉⣿⠉⠉⠉⣧⠀⠀⠀⢸⠀⠀⠀⣿⣠⣿⠀⠀⠀⠀⢀⣾⠇⠀⠀⠀⡼⠁⠀⡟⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠳⣄⠀⠀⠸⠿⣷⡀⠸⡀⠀⠀⠹⡄⠀⠀⠸⢀⣀⡴⠟⣿⠇⠀⠀⠀⠀⣾⡏⠀⠀⠀⣸⠃⠀⢰⡇⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⣄⠀⠀⠀⠻⣧⣠⢧⡤⠤⠤⠿⣆⠀⠚⠉⣧⠀⢰⡿⠀⠀⠀⢀⣾⡟⠀⠀⠀⢠⠇⠀⠀⣸⠀⠀⠀⠀⠀⠀
⠀⠀⠀⣀⣀⢀⣤⡦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢧⠀⠀⣾⠉⠀⠀⣷⠀⠀⠀⢻⡀⠀⠀⢻⠀⣿⠁⠀⠀⢠⣾⡿⠀⠀⠀⢠⡞⠀⠀⢠⡇⠀⠀⠀⠀⠀⠀
⠀⢰⣾⣿⠷⣿⣿⠵⠖⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠳⡀⠘⣆⠀⠀⣿⠀⠀⠀⠀⣧⠀⠀⣸⣾⠃⠀⠀⣠⣿⠟⠀⠀⠀⢀⡞⠀⠀⠀⣸⠁⠀⠀⠀⠀⠀⠀
⠀⠈⡻⠉⠋⠉⢁⣤⣼⡏⢠⣆⡾⠃⠀⠀⠀⠀⠀⠀⠀⠀⠹⣄⣿⣶⣤⣼⣤⣀⣀⣀⡽⠶⣚⡿⠁⠀⢀⣾⣿⠋⠀⠀⠀⠀⡼⠁⠀⠀⢠⡇⠀⠀⠀⠀⠀⠀⠀
⢰⣶⢟⡴⢾⢇⣏⣤⡿⠀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⣦⠉⠉⠉⠉⠙⠛⠛⠋⠉⠉⠀⠀⣠⣿⣟⠁⠐⠒⠒⠶⡾⠁⠀⠀⠀⡼⠀⠀⠀⠀⠀⠀⠀⠀
⣸⣃⣽⣣⠜⠿⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢷⡀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠟⠁⠈⠳⡄⠀⠀⡼⠁⠀⠀⠀⢰⡇⠀⠀⠀⠀⠀⠀⠀⠀
⠿⠉⠀⠀⠀⠀⠀⠀⣀⠀⠀⠀⠀⠀⠀⣶⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣳⡀⠀⠀⠀⠀⠀⢀⣴⠟⠧⣄⠀⠀⠀⠙⣦⡞⠁⠀⠀⠀⣀⣺⠴⠶⢲⡆⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢀⣸⡏⠀⠀⠀⠀⣀⣴⡏⠀⠀⠀⠀⠀⠀⠀⢀⡠⠞⠉⠹⣄⠀⠀⠀⣠⠟⠁⠀⠀⠈⠓⣦⣀⣠⢟⠀⣠⠴⠞⠉⠁⠀⠀⠀⢀⡇⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢠⣶⠏⢻⣶⡶⣾⣿⣟⡯⠞⠃⠀⠀⠀⠀⠀⢀⡴⠋⠀⠀⠀⠀⠹⣄⣠⣞⠉⠉⠉⠉⠉⠓⠲⢶⠾⠶⢿⠋⠁⠀⠀⠀⠀⠀⠀⠀⢰⡇⠀⠀⠀⠀⠀
⠀⠀⠈⠀⠉⠉⣉⣻⠉⠉⠈⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀⠉⠉⠹⣆⠀⠀⠀⠀⠀⠀⠘⣦⠀⠘⡇⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⠀⠀⠀⠀⠀
⠀⠀⢀⣠⣶⠋⡽⠃⠀⢀⣀⡴⠞⠀⠀⠀⠀⠀⣀⣠⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣄⠀⠀⠀⠀⠀⠀⠈⣳⢶⣿⣀⠀⠀⠀⠀⠀⠀⠀⢸⠁⠀⠀⠀⠀⠀
⠀⠀⠎⠀⣼⠋⠀⠰⢊⣯⡟⠀⢀⣀⡤⠶⠒⠉⠉⠁⠀⢻⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⡄⠀⠀⠀⠀⢀⣾⠁⣸⠇⢹⠳⣄⠀⠀⠀⠀⠀⡜⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣯⢉⡶⡆⣸⡉⠓⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠘⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣇⠹⡀⠀⠀⣰⠏⡾⠀⣿⠀⢸⠀⠈⣿⢦⡀⠀⢰⡇⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢀⡿⠋⠁⠁⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠀⢻⣀⡜⠁⢠⠇⠀⣧⠀⢸⠀⠀⡇⠀⠙⠲⡽⠁⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠀⠀⠉⠀⠀⣿⠀⠀⣿⠀⢸⠀⢸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⡀⠀⠀⠀⠀⠀⠀⠀⠀⢻⠀⠀⠀⠀⠀⠉⠉⠛⢿⡆⢸⡇⢸⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⡀⠀⠀⠀⠀⠀⠀⠀⠸⡄⠀⠀⠀⠀⠀⠀⠀⠘⣧⡾⠃⡜⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⣄⠀⠀⠀⠀⠀⠀⠀⣧⠀⠀⠀⠀⠀⠀⠀⠀⠉⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠀⠀⠀⠀⠀⠀⠀⠿⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠟⠀⠀⠀⠀

           Good job!! You just discovered the criminal!



joker@NightCity:/home/.joker$ sudo -l
[sudo] contraseña para joker: 
Lo sentimos, el usuario joker no puede ejecutar sudo en NightCity.
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506110209174.png" alt="image-20250611011939114" style="zoom:50%;" />

其实到这里就结束了，我上传了个`linpeas.sh`看看有没有别的彩蛋：

![image-20250611012831373](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506110209175.png)

发现这个版本好像是可以提权的，进行尝试：

![exploit.c执行逻辑](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506110209176.png)

很遗憾，尝试失败，多次尝试依然：

```bash
joker@NightCity:/tmp$ ./exp.py 
[+] Creating shared library for exploit code.
[-] GCONV_PATH=. directory already exists, continuing.
[+] Calling execve()
pkexec --version |
       --help |
       --disable-internal-agent |
       [--user username] PROGRAM [ARGUMENTS...]

See the pkexec manual page for more details.
```

后来查到这个漏洞被修复了，就到此为止吧。。。。

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202506110209177.png" alt="image-20250611020850951" style="zoom:50%;" />

## 关于PS那块平替工具

看师傅们采用的是`stegoveritas`这个工具，可以尝试使用一下，注意不要使用太新的 python 版本：

```bash
$ pip3 install stegoveritas
$ stegoveritas_install_deps
```

这个也不能直接搞出那个密码，只是和stegsolve一样可以分离不同色道的图层。。。。。还是得肉眼看。。。