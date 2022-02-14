
# Bases 

### Author: Sanjay C/Danny T

### Description

```
Category: General Skills

What does this <code>bDNhcm5fdGgzX3IwcDM1</code> mean? I think it has something to do with bases.

Hints:

(1) Submit your answer in our flag format. For example, if your answer was 'hello', you would submit 'picoCTF{hello}' as the flag.

```

### Solution

The provided value (`bDNhcm5fdGgzX3IwcDM1`) looks like base64 encoded text. We get the flag after decoding it.

```bash
┌──(arrow) 💀 [~/…/capture-the-flag/Writeups/picoCTF/Bases]
└─$ echo bDNhcm5fdGgzX3IwcDM1 | base64 -d
l3arn_th3_r0p35 
```

##### Flag: `picoCTF{l3arn_th3_r0p35}`
