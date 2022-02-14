
# strings it 

### Author: Sanjay C/Danny Tunitis

### Description

```
Category: General Skills

Can you find the flag in <a href='//jupiter.challenges.picoctf.org/static/fae9ac5267cd6e44124e559b901df177/strings'>file</a> without running it?

Hints:

(1) <a href="https://linux.die.net/man/1/strings">strings</a>

```

### Solution

Like the challenge name suggests, just use `strings` and find the flag using `grep`.

```bash
┌──(arrow) 💀 [~/…/capture-the-flag/Writeups/picoCTF/strings it]
└─$ strings strings | grep -i picoctf
picoCTF{5tRIng5_1T_7f766a23}
```

##### Flag: `picoCTF{5tRIng5_1T_7f766a23}`
