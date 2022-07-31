# [Easy] Identify Yourself (100 points)

> The smart city is implementing a digital identity to keep sensitive data away from the AI. Can you confirm that it is securely implemented?
>
> Author information: This challenge is developed by [Bob@DeloitteBe](https://www.linkedin.com/in/bob-van-der-smissen/).

- Decompile the APK
- AES CBC mode
- Initialisation Vector present
- 4 digit pin repeated four times to create AES key
- Bruteforcing all 4 digit positions -> 10^4 total combinations

```py
import base64
import string

from Crypto.Util.number import *
from Crypto.Cipher import AES

with open('session.raw') as file:
  content = file.read().strip()

enc_key = base64.b64decode(content.split(':')[0])
enc_data = base64.b64decode(content.split(':')[1])
iv = b'1234567812345678'

for a in range(0, 10):
  for b in range(0, 10):
    for c in range(0, 10):
      for d in range(0, 10):
        pin = str(a) + str(b) + str(c) + str(d)
        key = pin * 4
        cipher = AES.new(key.encode(), AES.MODE_CBC, iv)
        dec = cipher.decrypt(enc_key)
        cipher = AES.new(dec[:32], AES.MODE_CBC, iv)
        dec = cipher.decrypt(enc_data)
        
        if b'CTF' in dec:
          print('Pin:', pin)
          print(dec.decode())

```
