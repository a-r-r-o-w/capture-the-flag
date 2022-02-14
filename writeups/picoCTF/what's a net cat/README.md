
# what's a net cat? 

### Author: Sanjay C/Danny Tunitis

### Description

```
Category: General Skills

Using netcat (nc) is going to be pretty important. Can you connect to <code>jupiter.challenges.picoctf.org</code> at port <code>41120</code> to get the flag?

Hints:

(1) nc <a href="https://linux.die.net/man/1/nc">tutorial</a>

```

### Solution

Connect to the net cat service and retrieve the flag.

```bash
┌──(arrow) 💀 [~/…/capture-the-flag/Writeups/picoCTF/what's a net cat]
└─$ nc jupiter.challenges.picoctf.org 41120                                                   1 ⨯
You're on your way to becoming the net cat master
picoCTF{nEtCat_Mast3ry_3214be47}
```

##### Flag: `picoCTF{nEtCat_Mast3ry_3214be47}`
