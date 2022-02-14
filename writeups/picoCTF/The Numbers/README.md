
# The Numbers 

### Author: Danny

### Description

```
Category: Cryptography

The <a href='//jupiter.challenges.picoctf.org/static/f209a32253affb6f547a585649ba4fda/the_numbers.png'>numbers</a>... what do they mean?

Hints:

(1) The flag is in the format PICOCTF{}

```

### Solution

![](./the_numbers.png)

The values in the image seem like they are positions of the alphabet.

```python
l = [16, 9, 3, 15, 3, 20, 6]
r = [20, 8, 5, 14, 21, 13, 2, 5, 18, 19, 13, 1, 19, 15, 14]

for i in l:
    print(chr(ord('A') + i), end = '')
print('{', end = '')
for i in r:
    print(chr(ord('A') + i), end = '')
print('}')

# Output: QJDPDUG{UIFOVNCFSTNBTPO}
```

The output looks like some sort of ROT cipher. Trying different shift amounts, we find the flag.

```python
#!/usr/bin/env python3

import sys
import argparse

def main ():
    parser = argparse.ArgumentParser(description = 'Caesar cipher')
    parser.add_argument('text', help = 'Cipher text')

    args = parser.parse_args()

    s = args.text

    for shift in range(26):
        t = ''
        for c in s:
            if c.isupper():
                t += chr(ord('A') + (ord(c) - ord('A') + shift) % 26)
            elif c.islower():
                t += chr(ord('a') + (ord(c) - ord('a') + shift) % 26)
            else:
                t += c
        print('(+{0:>2}) {1}'.format(shift, t))

if __name__ == '__main__':
    main()
```

```bash
┌──(arrow 💀)-[~/Desktop/ctf/picoctf/The Numbers]
└─$ caesar `python3 main.py`
(+ 0) QJDPDUG{UIFOVNCFSTNBTPO}
(+ 1) RKEQEVH{VJGPWODGTUOCUQP}
(+ 2) SLFRFWI{WKHQXPEHUVPDVRQ}
(+ 3) TMGSGXJ{XLIRYQFIVWQEWSR}
(+ 4) UNHTHYK{YMJSZRGJWXRFXTS}
(+ 5) VOIUIZL{ZNKTASHKXYSGYUT}
(+ 6) WPJVJAM{AOLUBTILYZTHZVU}
(+ 7) XQKWKBN{BPMVCUJMZAUIAWV}
(+ 8) YRLXLCO{CQNWDVKNABVJBXW}
(+ 9) ZSMYMDP{DROXEWLOBCWKCYX}
(+10) ATNZNEQ{ESPYFXMPCDXLDZY}
(+11) BUOAOFR{FTQZGYNQDEYMEAZ}
(+12) CVPBPGS{GURAHZOREFZNFBA}
(+13) DWQCQHT{HVSBIAPSFGAOGCB}
(+14) EXRDRIU{IWTCJBQTGHBPHDC}
(+15) FYSESJV{JXUDKCRUHICQIED}
(+16) GZTFTKW{KYVELDSVIJDRJFE}
(+17) HAUGULX{LZWFMETWJKESKGF}
(+18) IBVHVMY{MAXGNFUXKLFTLHG}
(+19) JCWIWNZ{NBYHOGVYLMGUMIH}
(+20) KDXJXOA{OCZIPHWZMNHVNJI}
(+21) LEYKYPB{PDAJQIXANOIWOKJ}
(+22) MFZLZQC{QEBKRJYBOPJXPLK}
(+23) NGAMARD{RFCLSKZCPQKYQML}
(+24) OHBNBSE{SGDMTLADQRLZRNM}
(+25) PICOCTF{THENUMBERSMASON}
```

##### Flag: `PICOCTF{THENUMBERSMASON}`
