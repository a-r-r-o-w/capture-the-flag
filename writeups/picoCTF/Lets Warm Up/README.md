
# Lets Warm Up 

### Author: Sanjay C/Danny Tunitis

### Description

```
Category: General Skills

If I told you a word started with 0x70 in hexadecimal, what would it start with in ASCII? 

Hints:

(1) Submit your answer in our flag format. For example, if your answer was 'hello', you would submit 'picoCTF{hello}' as the flag.

```

### Solution

This is a very simple challenge. We can convert the hex value into it's ascii representation.

```bash
┌──(arrow) 💀 [~/…/capture-the-flag/Writeups/picoCTF/Lets Warm Up]
└─$ python3 -c "print(chr(0x70))"                    
p
```

##### Flag: `picoCTF{p}`
