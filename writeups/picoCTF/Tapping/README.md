
# Tapping 

### Author: Danny

### Description

```
Category: Cryptography

Theres tapping coming in from the wires. What's it saying <code>nc jupiter.challenges.picoctf.org 48247</code>.

Hints:

(1) What kind of encoding uses dashes and dots?

(2) The flag is in the format PICOCTF{}

```

### Solution

```bash
┌──(arrow 💀)-[~/Desktop/ctf/picoctf/Tapping]
└─$ nc jupiter.challenges.picoctf.org 48247                                                   1 ⚙
.--. .. -.-. --- -.-. - ..-. { -- ----- .-. ... ...-- -.-. ----- -.. ...-- .---- ... ..-. ..- -. .---- ..--- -.... .---- ....- ...-- ---.. .---- ---.. .---- } 
```

Looks like morse code. After decoding it, we get the flag.

##### Flag: `PICOCTF{M0RS3C0D31SFUN1261438181}`
