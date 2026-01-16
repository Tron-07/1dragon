---
title: Payday PGP Walkthrough
description: Target - Payday, OS - Linux, Difficulty - Intermediate
readTime: 10 min read
date: 01-16-2026
image: ../assets/images/pyd/CS_cart.png
---

---
#### ***Enumeration

Started off with a nmap scan and gathered information about the target  network, systems, services, open ports.

```
nmap -sVC -p- -T5 -Pn -n --open -oN Payday-nmap 192.168.221.39

Nmap scan report for 192.168.221.39
Host is up (0.29s latency).

PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 4.6p1 Debian 5build1 (/1dragon/assets/images/pyd/protocol 2.0)
| ssh-hostkey: 
|   1024 f3:6e:87:04:ea:2d:b3:60:ff:42:ad:26:67:17:94:d5 (DSA)
|_  2048 bb:03:ce:ed:13:f1:9a:9e:36:03:e2:af:ca:b2:35:04 (RSA)
80/tcp  open  http        Apache httpd 2.2.4 ((Ubuntu) PHP/5.2.3-1ubuntu6)
|_http-server-header: Apache/2.2.4 (Ubuntu) PHP/5.2.3-1ubuntu6
|_http-title: CS-Cart. Powerful PHP shopping cart software
110/tcp open  pop3        Dovecot pop3d
|_pop3-capabilities: STLS RESP-CODES SASL TOP PIPELINING CAPA UIDL
| ssl-cert: Subject: commonName=ubuntu01/organizationName=OCOSA/stateOrProvinceName=There is no such thing outside US/countryName=XX
| Not valid before: 2008-04-25T02:02:48
|_Not valid after:  2008-05-25T02:02:48
|_ssl-date: 2024-12-18T08:05:24+00:00; +7s from scanner time.
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_RC2_128_CBC_WITH_MD5
|     SSL2_RC4_128_EXPORT40_WITH_MD5
|     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
|     SSL2_RC4_128_WITH_MD5
|_    SSL2_DES_192_EDE3_CBC_WITH_MD5
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: MSHOME)
143/tcp open  imap        Dovecot imapd
|_ssl-date: 2024-12-18T08:05:24+00:00; +7s from scanner time.
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_RC2_128_CBC_WITH_MD5
|     SSL2_RC4_128_EXPORT40_WITH_MD5
|     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
|     SSL2_RC4_128_WITH_MD5
|_    SSL2_DES_192_EDE3_CBC_WITH_MD5
|_imap-capabilities: completed IMAP4rev1 THREAD=REFERENCES Capability UNSELECT NAMESPACE LOGINDISABLEDA0001 SASL-IR MULTIAPPEND STARTTLS LOGIN-REFERRALS SORT OK LITERAL+ IDLE CHILDREN
| ssl-cert: Subject: commonName=ubuntu01/organizationName=OCOSA/stateOrProvinceName=There is no such thing outside US/countryName=XX
| Not valid before: 2008-04-25T02:02:48
|_Not valid after:  2008-05-25T02:02:48
445/tcp open  netbios-ssn Samba smbd 3.0.26a (workgroup: MSHOME)
993/tcp open  ssl/imap    Dovecot imapd
|_ssl-date: 2024-12-18T08:05:23+00:00; +6s from scanner time.
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_RC2_128_CBC_WITH_MD5
|     SSL2_RC4_128_EXPORT40_WITH_MD5
|     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
|     SSL2_RC4_128_WITH_MD5
|_    SSL2_DES_192_EDE3_CBC_WITH_MD5
| ssl-cert: Subject: commonName=ubuntu01/organizationName=OCOSA/stateOrProvinceName=There is no such thing outside US/countryName=XX
| Not valid before: 2008-04-25T02:02:48
|_Not valid after:  2008-05-25T02:02:48
995/tcp open  ssl/pop3    Dovecot pop3d
| ssl-cert: Subject: commonName=ubuntu01/organizationName=OCOSA/stateOrProvinceName=There is no such thing outside US/countryName=XX
| Not valid before: 2008-04-25T02:02:48
|_Not valid after:  2008-05-25T02:02:48
|_ssl-date: 2024-12-18T08:05:23+00:00; +6s from scanner time.
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_RC2_128_CBC_WITH_MD5
|     SSL2_RC4_128_EXPORT40_WITH_MD5
|     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
|     SSL2_RC4_128_WITH_MD5
|_    SSL2_DES_192_EDE3_CBC_WITH_MD5
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.26a)
|   Computer name: payday
|   NetBIOS computer name: 
|   Domain name: 
|   FQDN: payday
|_  System time: 2024-12-18T03:05:09-05:00
|_nbstat: NetBIOS name: PAYDAY, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
|_clock-skew: mean: 50m06s, deviation: 2h02m29s, median: 6s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Dec 18 00:05:21 2024 -- 1 IP address (1 host up) scanned in 33.04 seconds

```

Discovered a web-page on port 80

![cs_cart_page](/1dragon/assets/images/pyd/Pasted%20image%2020260116081722.png)

Fuzzed the web-page which was build using CS-CART Template and discovered  multiple directories but `/admin` looked as a lead.

```
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -u "http://192.168.221.39/FUZZ" -ac -t 500 --fc 403,404  

imagess                  [Status: 301, Size: 335, Words: 21, Lines: 10, Duration: 80ms]
skins                   [Status: 301, Size: 334, Words: 21, Lines: 10, Duration: 79ms]
admin                   [Status: 200, Size: 9483, Words: 393, Lines: 263, Duration: 295ms]
core                    [Status: 301, Size: 333, Words: 21, Lines: 10, Duration: 78ms]
payments                [Status: 301, Size: 337, Words: 21, Lines: 10, Duration: 76ms]
index                   [Status: 200, Size: 28074, Words: 1558, Lines: 676, Duration: 109ms]
include                 [Status: 301, Size: 336, Words: 21, Lines: 10, Duration: 5719ms]
catalog                 [Status: 301, Size: 336, Words: 21, Lines: 10, Duration: 5719ms]
config                  [Status: 200, Size: 13, Words: 2, Lines: 1, Duration: 8732ms]
install                 [Status: 200, Size: 7731, Words: 346, Lines: 220, Duration: 9147ms]
var                     [Status: 301, Size: 332, Words: 21, Lines: 10, Duration: 95ms]
classes                 [Status: 301, Size: 336, Words: 21, Lines: 10, Duration: 95ms]
images                   [Status: 200, Size: 1971, Words: 16, Lines: 12, Duration: 101ms]
addons                  [Status: 301, Size: 335, Words: 21, Lines: 10, Duration: 88ms]
chart                   [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 138ms]
shippings               [Status: 301, Size: 338, Words: 21, Lines: 10, Duration: 79ms]
init                    [Status: 200, Size: 13, Words: 2, Lines: 1, Duration: 77ms]
apache2-default         [Status: 301, Size: 344, Words: 21, Lines: 10, Duration: 78ms]
targets                 [Status: 301, Size: 336, Words: 21, Lines: 10, Duration: 81ms]
prepare                 [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 78ms]
:: Progress: [26583/26583] :: Job [1/1] :: 151 req/sec :: Duration: [0:00:47] :: Errors: 17 ::

```

Logged into the webpage via /admin page as admin user. The default credentials
`admin:admin` worked.

![](/1dragon/assets/images/pyd/Pasted%20image%2020260116082818.png)

Searchsploit showed and exploit and RCE - 48891.txt. Mirrored the exploit.

![](/1dragon/assets/images/pyd/Pasted%20image%2020260116082428.png)

---
#### ***Initial Access***

After logging in as admin moved into the tab look and feel tab > Templated editor

![](/1dragon/assets/images/pyd/Pasted%20image%2020260116082940.png)

In template editor discovered an upload functionality as mentioned in the exploit. Uploaded a  php reverse shell with .phtml

![](/1dragon/assets/images/pyd/Pasted%20image%2020260116084636.png)

Accessed the payload at http://192.168.221.39/skins/rev.phtml

Had a nc listener running at port 445 and got shell as www-data.

![](/1dragon/assets/images/pyd/Pasted%20image%2020260116084828.png)

Discovered another user patrick. 
Captured local.txt under patrick's home directory.

![](/1dragon/assets/images/pyd/Pasted%20image%2020260116084903.png)

---
#### ***Privilege Escalation***

`su patrick` with password as patrick  and got the shell as user patrick. Patrick was also a member of adm group with which log files under `/var/log` can be read.

![](/1dragon/assets/images/pyd/Pasted%20image%2020260116084942.png)

`sudo -l` showed user patrick can execute commands (ALL) ALL

further executed `sudo su` and got the shell as user root and captured the root flag under `/root`

![](/1dragon/assets/images/pyd/Pasted%20image%2020260116094744.png)

---


										Target compromised - |^| ^ ( |< 3 D