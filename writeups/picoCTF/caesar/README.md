
# caesar 

### Author: Sanjay C/Daniel Tunitis

### Description

```
Category: Cryptography

Decrypt this <a href='//jupiter.challenges.picoctf.org/static/7d707a443e95054dc4cf30b1d9522ef0/ciphertext'>message</a>.

Hints:

(1) caesar cipher <a href="https://learncryptography.com/classical-encryption/caesar-cipher">tutorial</a>

```

### Solution

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
┌──(arrow 💀)-[~/Desktop/ctf/picoctf/caesar]
└─$ cat ciphertext                             
picoCTF{gvswwmrkxlivyfmgsrhnrisegl}                                                                                                  
┌──(arrow 💀)-[~/Desktop/ctf/picoctf/caesar]
└─$ caesar gvswwmrkxlivyfmgsrhnrisegl      
(+ 0) gvswwmrkxlivyfmgsrhnrisegl
(+ 1) hwtxxnslymjwzgnhtsiosjtfhm
(+ 2) ixuyyotmznkxahoiutjptkugin
(+ 3) jyvzzpunaolybipjvukqulvhjo
(+ 4) kzwaaqvobpmzcjqkwvlrvmwikp
(+ 5) laxbbrwpcqnadkrlxwmswnxjlq
(+ 6) mbyccsxqdrobelsmyxntxoykmr
(+ 7) nczddtyrespcfmtnzyouypzlns
(+ 8) odaeeuzsftqdgnuoazpvzqamot
(+ 9) pebffvatgurehovpbaqwarbnpu
(+10) qfcggwbuhvsfipwqcbrxbscoqv
(+11) rgdhhxcviwtgjqxrdcsyctdprw
(+12) sheiiydwjxuhkrysedtzdueqsx
(+13) tifjjzexkyvilsztfeuaevfrty
(+14) ujgkkafylzwjmtaugfvbfwgsuz
(+15) vkhllbgzmaxknubvhgwcgxhtva
(+16) wlimmchanbylovcwihxdhyiuwb
(+17) xmjnndiboczmpwdxjiyeizjvxc
(+18) ynkooejcpdanqxeykjzfjakwyd
(+19) zolppfkdqeboryfzlkagkblxze
(+20) apmqqglerfcpszgamlbhlcmyaf
(+21) bqnrrhmfsgdqtahbnmcimdnzbg
(+22) crossingtherubicondjneoach
(+23) dspttjohuifsvcjdpoekofpbdi
(+24) etquukpivjgtwdkeqpflpgqcej
(+25) furvvlqjwkhuxelfrqgmqhrdfk
```

We find the shift to be +22.

##### Flag: `picoCTF{crossingtherubicondjneoach}`
