The InCTF Finals started on 7th January 2022 and lasted 2 days. The challenges were great. Many thanks to the organizers for the great challenges.

Our team (ISFCR PESU) of 5 members ranked #21 during the event. We started very well and remained in top 5 for quite some time but gradually started to fall due to us being slightly weak at Reversing and Pwn challenges. Nevertheless, it was a great learning experience. Great performance by all the other teams! Here's the scoreboard:

![scoreboard](./images/scoreboard.png)



## Web

- [x] Lite Data (100)
- [x] RenderrorV2 (200)
- [x] Simple Forgery (200)
- [x] Flag Shop (400)
- [x] Proxy Service (400)
- [ ] RenderrorV3 (400)
- [ ] Sticky-notes (400)



## Cryptography

- [x] Robin_Messup (100)
- [x] Multi_prime (100)
- [x] DpDq (100)
- [x] XchangE (200)
- [ ] bad_pad2 (200)
- [ ] baby_log (200)
- [ ] Eerie RSA (400)



## Forensics

- [x] XOXO (100)
- [x] CHUNKlet (100)
- [x] Tracery (200)
- [x] Look Deeper (200)
- [x] Breach 1 (200)
- [ ] MAL3FIC3NT (400)
- [x] Breach 2 (400)



## Misc

- [x] Pyjail (200)
- [x] Pyjail-k8s (400)



## Pwn

- [x] Warm Up (100)
- [x] r0pk1ng (100)
- [x] l1br4ry (200)
- [ ] bufferUp (200)
- [ ] theBet (200)
- [ ] viserions_call (400)
- [ ] armoury (400)
- [ ] MIPSunderstanding (400)



## Reversing

- [ ] broken (100)
- [ ] Matrix_Reloaded (200)
- [ ] Rebirth of Nagini (200)
- [ ] Keylock (200)
- [ ] Based Kee (200)
- [ ] Stars MM (400)



## Cryptography

### Multi_prime

>  More primes the better!

We are provided with the challenge file and the output file.

```python
# chall.py

from Crypto.Util.number import *
from secret import flag
pt=bytes_to_long(flag)
p,q,r=[getPrime(1024) for _ in [1,1,1]]
n=p*q*r
e=65537
x=(getPrime(77)*p+n)%(q*r)
ct=pow(pt,e,n)
print(f"{ct=}\n{n=}\n{x=}")

# out.txt

ct=395194141435798550648329991848070349794798252798746662068420749813369750665268883328843534931437426604892501825443389293531999192771985389445783436704907163312563472384752682053250203351326257696477475967990212557213272050830469205670120009162392873243583672881310036848670950831883559284726562547765550581194610835498039358881918099619956927087874453889001872936895771655628760855149241855640717633624310754162512198418433745346222950641365701261648007742316410514254012415660841961114292422789121483906818233279411139978985409393981277942431505058710241041938902842874046094174290925898336452210117254242693927316359020576939861396812864714127511336880923297828788415282943403148615796109782889565170421164017531829313843341509921374116414318738786074179710597338708141142185799693445351627074184891898301303416152503497721063955188198697521258912685373610854469344229084807360449713447019289445943695248010394837114531692
n=2337785490672139591349117734107848684372806761135825760241612019435125716440395391949934723783356677122561045664341548404198285715994483863841789812222752603086589531950737784993753795720933325149882861815308675621540895195019023615401123477713312993050954033266644851064437508980916850789425040351584900889623497593918974218810237816070883150369080731069136107001860551615628215414493399051220082191103221330746778278679296908181335228283879199064420195765743112243406871506787766798298319411415659603149888246472935828722463149693826513887346742796159106878811774942771543354957111505380264481584560297614379712366341484529998868512963928909708681518233976397976780562156616517247566201610270672346335823236751450520857153859226581785593681412902096573843026194279879056985706349965721832273903477779734156619958818563350192628275840370447100564249852067580119184151615445572679340304244557840598198250944249825555571887891
x=15658988505270327788660779458629481794724894505252859561908392350725280253678990785639557748532122962472760234904131849391897637791888572878822746568183249061450058716532096453122737460277044669245197773987367308797393325097360704288408662956396200001871777772420168353707197462767426119968371288391359010790577356877739554578945459
```

We can see that the provided relation for `x` will help us retrieve the value of `p`. Let's see how:

```
x = (PRIME_77 * p + n) % (q * r)
x = (PRIME_77 * p + p * q * r) % (q * r)
x = (PRIME_77 * p) % (q * r) # as n % (q * r) is 0
x = PRIME_77 * p # because q and r are both 1024 bit primes, and product of 77-bit and 1024-bit prime must be less than the former

We can, therefore, find the GCD of x and n to retrieve p
```

Okay, so now we have `p`. As we have `p`, we can find `q * r` using the relation `q * r = n / p`. How do we find `q` and `r` though? There's no other relation that we could use to find the two values. It turns out that we don't actually need to find the values and can simply use `p` for decryption. This can be done because `p` is sufficiently greater than `m` (the flag) which will just be a few characters.

Final exploit script:

```python
from Crypto.Util.number import GCD, long_to_bytes

x = 15658988505270327788660779458629481794724894505252859561908392350725280253678990785639557748532122962472760234904131849391897637791888572878822746568183249061450058716532096453122737460277044669245197773987367308797393325097360704288408662956396200001871777772420168353707197462767426119968371288391359010790577356877739554578945459
e = 65537
n = 2337785490672139591349117734107848684372806761135825760241612019435125716440395391949934723783356677122561045664341548404198285715994483863841789812222752603086589531950737784993753795720933325149882861815308675621540895195019023615401123477713312993050954033266644851064437508980916850789425040351584900889623497593918974218810237816070883150369080731069136107001860551615628215414493399051220082191103221330746778278679296908181335228283879199064420195765743112243406871506787766798298319411415659603149888246472935828722463149693826513887346742796159106878811774942771543354957111505380264481584560297614379712366341484529998868512963928909708681518233976397976780562156616517247566201610270672346335823236751450520857153859226581785593681412902096573843026194279879056985706349965721832273903477779734156619958818563350192628275840370447100564249852067580119184151615445572679340304244557840598198250944249825555571887891
ct = 395194141435798550648329991848070349794798252798746662068420749813369750665268883328843534931437426604892501825443389293531999192771985389445783436704907163312563472384752682053250203351326257696477475967990212557213272050830469205670120009162392873243583672881310036848670950831883559284726562547765550581194610835498039358881918099619956927087874453889001872936895771655628760855149241855640717633624310754162512198418433745346222950641365701261648007742316410514254012415660841961114292422789121483906818233279411139978985409393981277942431505058710241041938902842874046094174290925898336452210117254242693927316359020576939861396812864714127511336880923297828788415282943403148615796109782889565170421164017531829313843341509921374116414318738786074179710597338708141142185799693445351627074184891898301303416152503497721063955188198697521258912685373610854469344229084807360449713447019289445943695248010394837114531692

# p = GCD(n, x)
p = 139082012823524473877797519777469875682906314433764228009518904896443717398510199346793255059371883147243332287692688002630819129094558982355172451689916174179394233450984119273587474971824120873949671150163347543520081962613673739215429338080501449423260643614294552555285624864887279198481359762809228495483
R = 112588164259165441554473
qr = n // p

assert(n % p == 0)
assert(p * qr == n)
assert(x == (R * p + n) % qr)

dp = pow(e, -1, p - 1)
m = pow(ct, dp, p)

print(long_to_bytes(m))
```

Flag: `inctf{Y0u_Ar3_g00f_w1th_numb3rs}`



### DpDq

> Everything is infront you what else you require to get the flag

We are provided with a text file that contains some values.

```
# dpdq.txt

e = 0x10001

ct = 0x45357160eefa4b9d80e6b621788b24d213f5cda7a6660a0d8473bd92c20e853a0a48c6ee28f444efcd3df8f905f3009aec88b3265da785e6cd1b5c1b892eaa92463837266a2f14342fa2ec15578ee063026071030f587c56468b9e97f844c3e0bdf67cec6156332b0c58a6470b0501b297150976a106e3d8c786b8f093fca39994b6c112a32d93f181d90afadb6cd002df5bba2cd8321ccc272c8cb6bb87cbbe4f3143eeb20bd3cb291d47dab96375d533a2bfc51ed8c91d37272d6fb4b657f47c6ac29b50a7b3879fd15449a36c867b50d99ca5d2104bbd87c856cab2b696fb745f293d94668128f4bd2c1e7e0f94e707bae3719aa4a9f83db2d0b19dbf2007cfcc1ce561d74e59e900170d0c18caf662812e6a91adb151120dccda39d4c1e5ae49af473ea6d5d66595d3b0813cc3a4625eee34b53478d85f9bedbaea72be910bf4ff6fdc54a9eced5b068126a956aa1e477fbe48db5e4d5aa4bea6899af0f0b48e28f73d6416403e487d6fa64c04764358bceae4ea5f913a9f83df16b96bbb4a1d3805b69648309e551f36f66def7d9192b91871e056abd08dab12a999a0b8ade94b615f3daeadac167b7225c575e1dab75935f018108cd12f65d5014d8be218be207ea0729f0d654a3b192616e62c5ccdf505c4418f2d9cd77848ce8f3b354ba66d3d8c7a6ca06e8b4f7e3901b365f3547e9b00bbe6c154009acb560d1a9c

#dp=d%(p-1)

dp = 0x1239b43e9757bfeb45404678d158b587a0b4e815dace9ec22e0ca460e1640fc0cff8e32b1c3674ffda73803ef43521ef3ac426d9a8ff7ecfda81ae37c47c20bbc1fcc6a3d30642c3d7afc76974ff1c6c169cc70ef5bd3bc2d2854288efa6186dc3a3d71eeb63de905ccb0c8ad457d6929d00fcca693b087e27d1dd99a59b806886d3a270034b96f6442646b9d3ced76326cff8bdd9e88baecb06638fa7ef34acf7e3c1a522402b4570358126f9c515cf0c8a2df0717ffda5527e95ec277ceffb209046d916cb81395072f681a7d15103b38d3fb1f19ad544c32f1a090684eabd65cb52966a9efcb6ee970c2eccec162d41ef84003f30fdc00a75f0bc196f5ed5

#dq=d%(q-1)

dq = 0x2c4665456a6178f5311b5ff4d20ce7ef586f74747896a1fac53b4acc1a21079312e65706c4f157c2f57d2a09dfad2b53587939e380afd8fdbc217e3101863840b50f84e02c97ee9da79afc49833972a5ea7985a617c571de458604f7c0205eb6d8c19f8849ce704400ed8abb573841523c7c1bff4ff50330645afdd789bfdf15960c37b0e4a72f7b8ca8e72a898b9787734252730fae414474473d601b5e86967f007de499e510d1623886ce2a8e4d0e2a9a952aba4b74b07105ee9cd96a6386c2c652f42f5e767edfc2259afcbf231c33614fca6aa60157047edee81182543b21d9a0a4fd638403dcde194f1c70d369667e445ed769a0f438f0891c65ea6f19
```

Let's understand what `dp` and `dq` are in RSA. 

```python
n = p * q
phi = (p - 1) * (q - 1)

d = pow(e, -1, phi)
dp = d % (p - 1)
dq = d % (q - 1)

assert(d * e % ((p - 1)(q - 1)) == 1)
assert(dp * e % (p - 1) == 1)
assert(dq * e % (q - 1) == 1)

We can rewrite the relations as:
  dp * e = 1 (mod (p - 1))
  dp * e - 1 = 0 (mod (p - 1))
  dp * e - 1 = k * (p - 1) # for some value k

Once we have the value for k, we can find the value of p as:
  p = (dp * e - 1) / k + 1

Proceed similarly for dq.
```

Now, we must try and factorise `dp * e - 1` into two values instead of trying to factor `n`. There could be multiple solutions but we want the solution where `p` is a prime value. We can iterate over all such `p` and check which ones are prime. In this case, we get one a single candidate for both `p` and `q`. 

Final exploit script:

```python
from Crypto.Util.number import *

e = 0x10001
ct = 0x45357160eefa4b9d80e6b621788b24d213f5cda7a6660a0d8473bd92c20e853a0a48c6ee28f444efcd3df8f905f3009aec88b3265da785e6cd1b5c1b892eaa92463837266a2f14342fa2ec15578ee063026071030f587c56468b9e97f844c3e0bdf67cec6156332b0c58a6470b0501b297150976a106e3d8c786b8f093fca39994b6c112a32d93f181d90afadb6cd002df5bba2cd8321ccc272c8cb6bb87cbbe4f3143eeb20bd3cb291d47dab96375d533a2bfc51ed8c91d37272d6fb4b657f47c6ac29b50a7b3879fd15449a36c867b50d99ca5d2104bbd87c856cab2b696fb745f293d94668128f4bd2c1e7e0f94e707bae3719aa4a9f83db2d0b19dbf2007cfcc1ce561d74e59e900170d0c18caf662812e6a91adb151120dccda39d4c1e5ae49af473ea6d5d66595d3b0813cc3a4625eee34b53478d85f9bedbaea72be910bf4ff6fdc54a9eced5b068126a956aa1e477fbe48db5e4d5aa4bea6899af0f0b48e28f73d6416403e487d6fa64c04764358bceae4ea5f913a9f83df16b96bbb4a1d3805b69648309e551f36f66def7d9192b91871e056abd08dab12a999a0b8ade94b615f3daeadac167b7225c575e1dab75935f018108cd12f65d5014d8be218be207ea0729f0d654a3b192616e62c5ccdf505c4418f2d9cd77848ce8f3b354ba66d3d8c7a6ca06e8b4f7e3901b365f3547e9b00bbe6c154009acb560d1a9c
dp = 0x1239b43e9757bfeb45404678d158b587a0b4e815dace9ec22e0ca460e1640fc0cff8e32b1c3674ffda73803ef43521ef3ac426d9a8ff7ecfda81ae37c47c20bbc1fcc6a3d30642c3d7afc76974ff1c6c169cc70ef5bd3bc2d2854288efa6186dc3a3d71eeb63de905ccb0c8ad457d6929d00fcca693b087e27d1dd99a59b806886d3a270034b96f6442646b9d3ced76326cff8bdd9e88baecb06638fa7ef34acf7e3c1a522402b4570358126f9c515cf0c8a2df0717ffda5527e95ec277ceffb209046d916cb81395072f681a7d15103b38d3fb1f19ad544c32f1a090684eabd65cb52966a9efcb6ee970c2eccec162d41ef84003f30fdc00a75f0bc196f5ed5
dq = 0x2c4665456a6178f5311b5ff4d20ce7ef586f74747896a1fac53b4acc1a21079312e65706c4f157c2f57d2a09dfad2b53587939e380afd8fdbc217e3101863840b50f84e02c97ee9da79afc49833972a5ea7985a617c571de458604f7c0205eb6d8c19f8849ce704400ed8abb573841523c7c1bff4ff50330645afdd789bfdf15960c37b0e4a72f7b8ca8e72a898b9787734252730fae414474473d601b5e86967f007de499e510d1623886ce2a8e4d0e2a9a952aba4b74b07105ee9cd96a6386c2c652f42f5e767edfc2259afcbf231c33614fca6aa60157047edee81182543b21d9a0a4fd638403dcde194f1c70d369667e445ed769a0f438f0891c65ea6f19

# for kq in range(1, e):
#     q_mul = dq * e - 1
#     if q_mul % kq == 0:
#         q = (q_mul // kq) + 1
#         if isPrime(q):
#             print("Potential q: " + str(q))

# for kp in range(1, e):
#     p_mul = dp * e - 1
#     if p_mul % kp == 0:
#         p = (p_mul // kp) + 1
#         if isPrime(p):
#             print("Potential p: " + str(p))

p = 20236731690625966950279445377257426226537556667301816484473979829192706105537602237585298155716403674059780848904006299882200289526870589352968886049771301617931074630636934292815812105345134202988099324034820843412106815478976942852397508357836302221974701113980624629689714370785789193013969522944395650991637377371159218420657468888980077517319267885072961188995801149060763475373296344953811248567716872490322411602506390098274490343736471678716346499153365613746404794317371057708166740233191699317212274431104307289662354910568525995734374834120333123512860825992417680081672245730805062196173078769986720755133
q = 16258292068792803127734616552705983617224322980808679174289762471886412343828560977783159700757978921616317333639760434098567476718844321512245847255063040843374879451560803024232008023370020692043819731168617612236702976152667540521279405049292439975844185153918129284243218553983047104694508039272396005782897267292535943459336329016931709219236894553275587965548810133011802742968933322605807257866785514345574652076896278552817492988920066851400192709531616453742808174728167133267229670713593363130228104568391403971890506232309342968750038673070856268647078982974174222110235079951738456783068233765202095875981

n = p * q
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
m = pow(ct, d, n)
# print(e * d % phi)
print(long_to_bytes(m))
```

Flag: `inctf{Y0u_Ar3_really_g00d_w1th_numb3rs}`



## XchangE

> Derive the key

We are provided with one challenge file and a spawnable instance to test our exploit on. Here's the source code:

```python
# chall.py

#!/usr/bin/python3

from Crypto.Util.number import bytes_to_long, inverse, long_to_bytes
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randint
from Crypto.Protocol.KDF import scrypt
from secret import FLAG, FAKEFLAG
import hashlib, binascii

P = (1 << 1024) - 1093337
G = 7
IV = b"y3ll0w subm4r1n3"

class PublicKey:
    
    def __init__(self, h, p, g, q):
        self.h = h
        self.p = p
        self.g = g
        self.q = q

class PrivateKey:
   
    def __init__(self, x, p, g, q):
        self.x = x
        self.p = p
        self.g = g
        self.q = q

def generate_key():

    p = P
    x = randint(2, p-2)
    g = G
    q = p - 1
    h = pow(g, x, p)

    pubkey = PublicKey(h, p, g, q)
    privkey = PrivateKey(x, p, g, q)

    return (pubkey, privkey)
    
def kdf(secret):
 
    password = long_to_bytes(secret)
    salt = IV
    pswd = scrypt(password, salt, 16, N=2**14, r=8, p=1)
    
    key = binascii.hexlify(pswd[:16])

    return str(key)

if __name__ == "__main__":

    print("(p,g) = ({0},{1})\n".format(P,G))
    
    pub_alice, priv_alice = generate_key()
    print("Message from alice:",pub_alice.h)
    
    print("\nsend to Bob->")
    T_alice = int(input())
    
    pub_bob, priv_bob = generate_key()
    print("\nMessage from bob:",pub_bob.h)
    
    print("\nsend to Alice->")
    T_bob = int(input())
    
    y = randint(2, P-2)
    pub, priv = generate_key()
    
    nonce_alice = pow(pub.h, priv.x*y,P) 
    
    print("\nnonce send to Alice:", nonce_alice)
    
    print("\nsend nonce value to Bob->")
    nonce_bob = int(input())
    
    secret_bob =  pow(T_alice, priv_bob.x, P) ^  nonce_bob
    secret_alice = pow(T_bob, priv_alice.x,P) ^ nonce_alice

    if secret_bob == 0 or secret_alice == 0 or T_alice == 0 or T_bob == 0 or T_alice == 1 or T_bob == 1:
        print("sorry cant do!!")
        exit()

    assert secret_bob == secret_alice , b"you messed up"

    key = kdf(secret_alice)

    print("\nsend s->")
    s = input()
    
    if s == key :
        print(FLAG)

    else:
        print(FAKEFLAG)
```

The challenge is based on [Diffie-Hellman key exchange](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange). We are to play the role of an attacker in the key exchange and perform a Man-in-the-Middle (MitM) attack.

We can perform the attack as follows:

- Alice sends a message $g^a$ to Bob but we intercept the message. Instead we send the message $g^c$ to Bob where we choose $c$
- Bob sends a message $g^b$ to Alice but we intercept the message. Instead we send the message $g^d$ to Alice where we choose $d$
- We know Alice's nonce value $n_a$. We also know that the secret message shared by the two should be the same value. But, because we intercepted the messages sent by them to each other, the secret message shared by the two is different. How could we make the secret message shared by the two the same?
- Turns out, we also have control over Bob's nonce value. We require ${(g^a)}^c \oplus n_a$ to be equal to ${(g^b)^d \oplus n_b}$. We already know $g^a$, $g^b$, $c$, $d$ and $n_a$. We can simply calculate the required nonce Bob _must_ have and send that as input.
- So $n_b = {(g^a)}^c \oplus {(g^b)^d} \oplus n_a$ and we send this as Bob's nonce.
- To calculate the key, we can simply use the same function provided in the challenge file

Final exploit script:

```python
from pwn import *
from Crypto.Util.number import *
from Crypto.Protocol.KDF import *

P = (1 << 1024) - 1093337
G = 7
IV = b"y3ll0w subm4r1n3"

context.log_level = 'debug'
con = remote('gc1.eng.run', 32360)

con.recvuntil(b'alice: ')
alice_message = con.recvline()
con.recvuntil(b'>')
# con.send(alice_message)
con.sendline(b'49')

con.recvuntil(b'bob: ')
bob_message = con.recvline()
con.recvuntil(b'>')
# con.send(bob_message)
con.sendline(b'343')

con.recvuntil(b'Alice: ')
alice_nonce = con.recvline()

alice_message = int(alice_message)
bob_message = int(bob_message)
alice_nonce = int(alice_nonce)
alice_message_2 = 49
bob_message_2 = 343
# bob_nonce = alice_message ^ bob_message ^ alice_nonce
bob_nonce = (pow(alice_message, 3, P) ^ pow(bob_message, 2, P) ^ alice_nonce) % P

con.recvuntil(b'>\n')
# con.send(f'{bob_nonce}'.encode())
# con.sendline(f'{alice_nonce}'.encode())
con.sendline(f'{bob_nonce}'.encode())

# print(alice_message)
# print(bob_message)
# print(alice_nonce)

secret_alice = (pow(alice_message, 3, P) ^ alice_nonce) % P
secret_bob = (pow(alice_message, 2, P) ^ bob_nonce) % P

# assert(secret_alice == secret_bob)

def kdf(secret):
  password = long_to_bytes(secret)
  salt = IV
  pswd = scrypt(password, salt, 16, N=2**14, r=8, p=1)
  key = binascii.hexlify(pswd[:16])
  return str(key)

key = kdf(secret_alice)
print('Key:', key)
con.recv()
con.sendline(key)

con.interactive()
```

Flag: `inctf{U_got_the_DHKX_MTProto_vuln_in_Telegram!!}`



