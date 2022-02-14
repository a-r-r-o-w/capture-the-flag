
# Mind your Ps and Qs 

### Author: Sara

### Description

```
Category: Cryptography

In RSA, a small <code>e</code> value can be problematic, but what about <code>N</code>? Can you decrypt this? <a href='//mercury.picoctf.net/static/51d68e61bb41207a55f24e753f07c5a3/values'>values</a>

Hints:

(1) Bits are expensive, I used only a little bit over 100 to save money

```

### Solution

Using [RsaCtfTool.py](https://github.com/Ganapati/RsaCtfTool), we can find the flag.

Using small `n` for RSA is easy to break because we can factor it easily into `p` and `q`.

```
n = p * q
e
c = m ** e % n

e * d = 1 (mod phi(n))
d = e ** -1 (mod phi(n))

phi(n) = (p - 1) * (q - 1)

m = c ** (e ** -1) % n
```

```bash
┌──(arrow 💀)-[~/Desktop/ctf/picoctf/Mind your Ps and Qs]
└─$ cat values                  
Decrypt my super sick RSA:
c: 62324783949134119159408816513334912534343517300880137691662780895409992760262021
n: 1280678415822214057864524798453297819181910621573945477544758171055968245116423923
e: 65537                                                                                                  
┌──(arrow 💀)-[~/Desktop/ctf/picoctf/Mind your Ps and Qs]
└─$ rsatool -n 1280678415822214057864524798453297819181910621573945477544758171055968245116423923 -e 65537 --uncipher 62324783949134119159408816513334912534343517300880137691662780895409992760262021
private argument is not set, the private key will not be displayed, even if recovered.

[*] Testing key /tmp/tmpinhlfxsw.
[*] Performing fibonacci_gcd attack on /tmp/tmpinhlfxsw.
100%|█████████████████████████████████████████████████████| 9999/9999 [00:00<00:00, 251057.15it/s]
[*] Performing pastctfprimes attack on /tmp/tmpinhlfxsw.
100%|███████████████████████████████████████████████████████| 113/113 [00:00<00:00, 991540.49it/s]
[*] Performing factordb attack on /tmp/tmpinhlfxsw.
[*] Attack success with factordb method !

Results for /tmp/tmpinhlfxsw:

Unciphered data :
HEX : 0x007069636f4354467b736d6131315f4e5f6e305f67306f645f30353031323736377d
INT (big endian) : 13016382529449106065927291425342535437996222135352905256639555654677400177227645
INT (little endian) : 3711739942918996135095564070444078210974633154646265969428826141271237837554544640
utf-8 : picoCTF{sma11_N_n0_g0od_05012767}
utf-16 : 瀀捩䍯䙔獻慭ㄱ也湟弰で摯た〵㈱㘷紷
STR : b'\x00picoCTF{sma11_N_n0_g0od_05012767}'
```

Alternatively, we could also write our own script that performs the RSA decryption once we have `p` and `q`.

```python
#!/usr/bin/env python3

from Crypto.Util.number import long_to_bytes

n = 1280678415822214057864524798453297819181910621573945477544758171055968245116423923
e = 65537
c = 62324783949134119159408816513334912534343517300880137691662780895409992760262021

# from factor.db
p = 1899107986527483535344517113948531328331
q = 674357869540600933870145899564746495319033

phi = (p - 1) * (q - 1)

d = pow(e, -1, phi)
m = pow(c, d, n)

print(long_to_bytes(m).decode())
```

##### Flag: `picoCTF{sma11_N_n0_g0od_05012767}`
