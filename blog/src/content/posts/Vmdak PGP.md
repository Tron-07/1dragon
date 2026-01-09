---
title: Vmdak PGP walkthrough
description: Target - Vmdak, OS - Linux, Difficulty - Hard
readTime: 15 min read
image: ../assets/images/vmd/fast_5.png
date: 01-05-2026
---

#### ***Enumeration***

Started off with a nmap scan and gathered information about the target  network, systems, services, open ports.

```
nmap -sVC -p- -T5 -Pn -n --open -oN vmdak-nmap 192.168.123.103

Nmap scan report for 192.168.123.103
Host is up (0.33s latency).
Not shown: 58607 closed tcp ports (reset), 6924 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE  VERSION
21/tcp   open  ftp      vsftpd 3.0.5
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0            1752 Sep 19 15:01 config.xml
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 192.168.45.229
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.5 - secure, fast, stable
|_End of status
22/tcp   open  ssh      OpenSSH 9.6p1 Ubuntu 3ubuntu13.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 76:18:f1:19:6b:29:db:da:3d:f6:7b:ab:f4:b5:63:e0 (ECDSA)
|_  256 cb:d8:d6:ef:82:77:8a:25:32:08:dd:91:96:8d:ab:7d (ED25519)
80/tcp   open  http     Apache httpd 2.4.58 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.58 (Ubuntu)
9443/tcp open  ssl/http Apache httpd 2.4.58 ((Ubuntu))
|_http-title:  Home - Prison Management System
|_http-server-header: Apache/2.4.58 (Ubuntu)
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=vmdak.local/organizationName=PrisonManagement/stateOrProvinceName=California/countryName=US
| Subject Alternative Name: DNS:vmdak.local
| Not valid before: 2024-08-20T09:21:33
|_Not valid after:  2025-08-20T09:21:33
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel


```

Nmap revealed the ftp port is accessible as anonymous user.
Logged into ftp and discovered  `config.xml` downloaded that to local.

![ftp](/1dragon/assets/images/vmd/Pasted%20image%2020260106220057.png)

The config.xml had these contents
![config](/1dragon/assets/images/vmd/Pasted%20image%2020260106220447.png)

That was a possible `Jenkins Instance version 2.401.2`. It might be hosted internally. This is a piece of lead for now.

Further browsed the site hosted on port 9443 named as 'Prison Management System'

![web-page](/1dragon/assets/images/vmd/Pasted%20image%2020260106172959.png)

Discovered a login page while default credential combinations didn't work SQL injection technique helped to bypass login.

Entered username as `admin-- -` and logged in.

![admin-logn](/1dragon/assets/images/vmd/Pasted%20image%2020260106173838.png)

logged in as admin but user name `Caroline Bassey`

![dash](/1dragon/assets/images/vmd/Pasted%20image%2020260106175048.png)

Further clicked on `Leave Management`  tab in the side menu bar noted the the Password in the Reason tab. This might help further for authentication and logging into the target.

![lm](/1dragon/assets/images/vmd/Pasted%20image%2020260106175308.png)

---
#### ***Initial Access***

Analyzed the website functions for a while and discovered that profile image can be changed by uploading a new one. Uploaded a php reverse shell with modified file extension as `rev.php.png` as the site only allows image extensions.

![upld-shl](/1dragon/assets/images/vmd/Pasted%20image%2020260106191840.png)

Had Burpsuite Interceptor running and captured the upload request as follows and modified the `rev.php.png` to `rev.php` so the payload might get executed buy the target server.

![intrcpt](/1dragon/assets/images/vmd/Pasted%20image%2020260106191801.png)

After the upload request was successful tried to reload the profile image as shown below which triggered the payload reverse shell.
![reload](/1dragon/assets/images/vmd/Pasted%20image%2020260106190834.png)

Had a nc listener running at port 4444`rlwrap nc -lnvp 4444`
Captured the reverse shell as expected.
The user was www-data which is a low-privileged user. 

![www](/1dragon/assets/images/vmd/Pasted%20image%2020260106190744.png)
Local.txt was under the user vmdak's home directory but perm denied for user www-data to access it. 

Remembering the earlier noted password from the leave management tab on the web page
Executed `su vmdak` with password as `RonnyCache001`
Successfully Changed to user vmdak 

![vmdk](/1dragon/assets/images/vmd/Pasted%20image%2020260106195456.png)

Captured the local.txt.

![local](/1dragon/assets/images/vmd/Pasted%20image%2020260106195605.png)

---
#### ***Privilege Escalation***

Transferred from local and executed `linpeas.sh` on the target.
Discovered the port 8080 was hosting something which could be accessed only internally. 
![port-8080](/1dragon/assets/images/vmd/Pasted%20image%2020260106195835.png)

Set up a local port forward for user vmdak.

```
ssh -R 8080:127.0.0.1:80 vmdak@192.168.182.103
```

Accessed the target's internally hosted app via local port forwarded port at 8080 and discovered a `Jenkins instance` the earlier discovered config.xml showed that Jenkins version 2.401.2. 
It also showed that directory path from which initial admin password can be derived.

![jnkns](/1dragon/assets/images/vmd/Pasted%20image%2020260106201354.png)

There were multiple exploit available but this [exploit](https://github.com/godylockz/CVE-2024-23897/blob/main/jenkins_fileread.py) worked well.
Executed the exploit with required parameters such has target url  and file need to be  fetched.
As the the Jenkins instance showed the directory where initial admin password is stored passed that directory for the -f parameter in the exploit.

![exp](/1dragon/assets/images/vmd/Pasted%20image%2020260106204257.png)
The exploit fetched the initial password. The password fetched was used to log into the Jenkins instance.

![jnkns](/1dragon/assets/images/vmd/Pasted%20image%2020260106204851.png)
 
 After skipping the initial setups from the build tab entered item name as shell. Selected the Freestyle project and OK.
 
![jenkins-new-item](/1dragon/assets/images/vmd/Pasted%20image%2020260106205643.png)

After naming the build under `Build Steps` selected the option to Execute shell and entered a classic bash reverse shell in the box and saved it.

![build](/1dragon/assets/images/vmd/Pasted%20image%2020260106210917.png)

In a minute the build executed and reverse shell was successfully captured.

![](/1dragon/assets/images/vmd/Pasted%20image%2020260106210838.png)
Got the shell as user root and captured the root flag.

---
										Target compromised - |^| ^ ( |< 3 D

