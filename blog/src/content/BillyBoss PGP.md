#### ***Enumeration***

```
nmap -sVC -p- -Pn -n -T4 --open -oN BillyBoss-nmap 192.168.175.61

PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
==80/tcp    open  http          Microsoft IIS httpd 10.0==
==|_http-server-header: Microsoft-IIS/10.0==
==|_http-cors: HEAD GET POST PUT DELETE TRACE OPTIONS CONNECT PATCH==
==|_http-title: BaGet==
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5040/tcp  open  unknown
7680/tcp  open  tcpwrapped
==8081/tcp  open  http          Jetty 9.4.18.v20190429==
|_http-title: Nexus Repository Manager
|_http-server-header: Nexus/3.21.0-05 (OSS)
| http-robots.txt: 2 disallowed entries 
|_/repository/ /service/

```


![baget80](Pasted%20image%2020260110075327.png)



![Nexus_Repo](Pasted%20image%2020260110075014.png)


![](Pasted%20image%2020260110075925.png)

![exp](Pasted%20image%2020260110080246.png)


---
#### ***Initial Access***


![](Pasted%20image%2020260110080718.png)



![](Pasted%20image%2020260110080658.png)

```
CMD='.\\\\\\\rev.exe'
```


![local](Pasted%20image%2020260110085103.png)



---
#### ***Privilege Escalation***

![Priv](Pasted%20image%2020260110085232.png)

![](Pasted%20image%2020260110092533.png)

![](Pasted%20image%2020260110092442.png)

---

										Target compromised - |^| ^ ( |< 