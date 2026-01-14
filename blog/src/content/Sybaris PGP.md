```
Nmap scan report for 192.168.210.93

Host is up (0.00038s latency).
Not shown: 65531 closed ports
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.2
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxrwxrwx    2 0        0               6 Apr 01 04:55 pub [NSE: writeable]
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 192.168.120.217
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.2 - secure, fast, stable
|_End of status
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 03:7d:0f:d6:77:1f:09:74:dd:c4:32:3f:7a:f4:a2:4f (RSA)
|   256 1e:d3:b8:e9:f0:f8:6b:61:94:e8:aa:25:ec:aa:fe:bb (ECDSA)
|_  256 61:14:59:6d:d7:84:b6:2f:dc:2c:8e:55:f2:dc:62:55 (ED25519)
80/tcp   open  http    Apache httpd 2.4.6 ((CentOS) PHP/7.3.22)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-generator: HTMLy v2.7.5
| http-robots.txt: 11 disallowed entries 
| /config/ /system/ /themes/ /vendor/ /cache/ 
| /changelog.txt /composer.json /composer.lock /composer.phar /search/ 
|_/admin/
|_http-server-header: Apache/2.4.6 (CentOS) PHP/7.3.22
|_http-title: Sybaris - Just another HTMLy blog
6379/tcp open  redis   Redis key-value store 5.0.9
MAC Address: 00:0C:29:CE:37:CC (VMware)
Service Info: OS: Unix

```


![web_page](Pasted%20image%2020260112095849.png)


![ftp_mod](Pasted%20image%2020260112202717.png)

