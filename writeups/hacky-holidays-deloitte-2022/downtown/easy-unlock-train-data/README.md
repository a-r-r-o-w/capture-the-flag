# [Easy] Unlock Train Data (150 points)

> The AI has taken over the Train ticket scanner! Citizens can no longer make use of the railway system of Locked City Railway Corporation. Due to its custom protocol and validation system it will take significant time to rewrite the application. Can you help the city to regain immediate access to their railway infrastructure?
>
> Author information: This challenge is developed by [RvanderHam@DeloitteNL](https://linkedin.com/in/rubenvdham).

Decompile the APK.

### Tickets Please [75 points]

> The AI has gone rogue on the ticket app and left a backdoor. Can you gain a valid ticket which enables the citizens to travel again?

Install application on Android device and click the train background image 26 times. Or, create a BMP file as shown in decompiled output.

**Flag:** `CTF{Keep_Clicking_For_The_Win}`

### Something was Added [75 points]

> The application has been modified by the AI. At least one file was added. Yet we don't know what it is, can you figure it out?

- AES ECB encryption
- Reverse the algorithm for encryption

**Flag:** `CTF{Thou_Shall_Not_Roll_Your_Own_Crypto}`

```py
import hashlib
import string
import sys

from Crypto.Util.number import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import *
from pwn import *

def AES_encrypt (key, value):
  value = pad(value, 16)
  cipher = AES.new(key, AES.MODE_ECB)
  enc = cipher.encrypt(value)
  return enc

def AES_decrypt (key, value):
  cipher = AES.new(key, AES.MODE_ECB)
  dec = cipher.decrypt(value)
  # try:
  #   dec = unpad(dec, 16)
  # except ValueError:
  #   pass
  return dec

def encrypt (key, value):
  digest = hashlib.md5(key).digest()
  key = hashlib.md5(bytes([digest[1], digest[len(digest) // 2], digest[len(digest) - 1]])).digest()
  current_data = value

  # print('key:', key.hex())

  for _ in range(8):
    current_data = AES_encrypt(key, current_data)
    key = hashlib.md5(key).digest()
    # print('key:', key.hex())
  
  return current_data

def decrypt (key, value):
  digest = hashlib.md5(key).digest()
  key = hashlib.md5(bytes([digest[1], digest[len(digest) // 2], digest[len(digest) - 1]])).digest()
  keys = []
  current_data = value

  for _ in range(8):
    keys.append(key)
    key = hashlib.md5(key).digest()
  
  keys = keys[::-1]

  for i in range(8):
    current_data = AES_decrypt(keys[i], current_data)
  
  return current_data

def decrypt_with_digest (a, b, c, value):
  key = hashlib.md5(bytes([a, b, c])).digest()
  keys = []
  current_data = value

  for _ in range(8):
    keys.append(key)
    key = hashlib.md5(key).digest()
  
  keys = keys[::-1]

  for i in range(8):
    current_data = AES_decrypt(keys[i], current_data)
  
  return current_data

def brute ():
  value = long_to_bytes(0xb9725f22659b4469f84b4b800b740379bcafbb1fee9c941c0cca89a9ac2718f52e03df787f41bc568a63353b0084b956dc7a1ff0a58d88e20594c4fab8ee5df86e3da18d2ddcb579ff664636fa5a8e583ad2d35e7fe986f78754c7377a4f95a55aae80992da22547123374ea13235d9fc34e846f69b876a8e80d211f19b1c7a32ed4e48101b91448b5d5f9b5fe02488410015780353e14a9ef726073197d1377)
  
  with open('file.txt', 'w') as file:
    for a in range(256):
      print(a, file = sys.stderr)
      for b in range(256):
        for c in range(256):
          # key = (a + b + c).encode()
          # dec = decrypt(key, value)

          key = bytes([a, b, c])
          dec = decrypt_with_digest(a, b, c, value)

          if b'CTF{' in dec:
            print(key, dec, file = file)

brute()

# name = b'aaa'
# flag = b'CTF{fake_flag00}'

# enc = encrypt(name, flag)
# print(hex(bytes_to_long(enc))[2:][-32:])
# print(hex(bytes_to_long(encrypt(name, b'CTF{')))[2:][-32:])
# print(decrypt(name, enc))
```
