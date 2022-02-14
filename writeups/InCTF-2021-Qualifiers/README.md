# InCTF 2021 Qualifiers

The all-India qualifiers for Amrita InCTF started on 17th December 2021 and lasted for 2 days. It felt great to take part with my university team and friends. Thanks to the problemsetters and organizers for their effort in making really good challenges and conducting the event without many issues.

Our team (ISFCR PESU) of 5 members from our university ranked #19 during the event. We were #2 and #4 for quite a significant duration (I think), but eventually lost our spots because of the our team being weak at pwning challenges and unable to participate with complete effort due to ongoing semester final examination. Great performance by other teams!

![scoreboard](./images/scoreboard.png)



To qualify to the final round, the selection criteria was: Top 5 teams in each state exclusive of Top 30 teams. Official announcement is yet to come out but as we ranked #19, we most likely qualified and will do our best in the finals :)



## Web

- [x] NOt SQL (231)
- [x] Figlet (331)
- [x] Simple Calculator (361)
- [x] LFI-University (383)
- [x] World Map (388)
- [x] Blog-X (396)
- [x] PDF Generator (404)
- [x] Polluted (448)



## Cryptography

- [x] common-extender (419)
- [x] HakUnA MaTaTa (442)
- [x] Duplicates (451)
- [x] cubRSAic (462)
- [x] OFB-Madness (469)
- [x] copper_copper_copper (487)
- [ ] Bad_Pad (497)



## Forensics

- [x] Journey to the Center of the Earth (139)
- [x] Follow Me (269)
- [x] RAW (423)
- [x] Secret 1 (436)
- [ ] Secret 2 (469)
- [x] Look deep into me (471)
- [x] Hash Browns (487)



## Misc

- [x] Feedback (10)
- [x] sanity (10)
- [x] S3cur3 buck3t (454)
- [x] blue-whale (479)



## Pwn

- [ ] Harry Pwns (484)
- [ ] pack_alpha (488)
- [ ] Overwrite Simulator (491)
- [ ] SecureIT (496)
- [ ] Fast Cars (497)



## Reversing

- [x] sundae (439)
- [ ] Big Numbers (464)
- [ ] Dungeon (494)
- [ ] Chequered_flag (500)
- [ ] USLS Encrypter (500)



## Web

As the CTF has concluded, access to the instances have been frozen. The web category was pretty standard as can be seen by the points of the problems.



### NOt SQL

> Last time i used SQL, i got hacked /(O_0/) /_/ and now from my experience i am never using SQL again. Can you hack me now?

Very simple NO-SQL injection. The site was likely using a NO-SQL backend such as MongoDB. As input, a username and password prompt was present on the site. By intercepting the request using Burp, one could see the request query looked something like:

```
http://ip.add.re.ss:port/endpoint?username=someUsername&password=somePassword
```

In MongoDB, if you try to search for a record that does not match a given record, you could something like `$ne` which stands for `not equal to`. One can lookup common no-sql exploits and find the strategy used below. Changing the request to the following leaked the flag.

```
http://ip.add.re.ss:port/endpoint?username[$ne]=someUsername&password[$ne]=somePassword
```



### Figlet

> here is a figlet as a service , it's only running the "figlet" command , try to hack it!

We are provided with a prompt that takes some input and runs figlet with our input as the parameter. Essentially it provides us the output of `figlet <OUR_INPUT_HERE>`. We could try some basic tricks to run other commands on the prompt but most of the ways are filtered.

Things like `figlet Arrow; cat flag.txt` or `figlet Arrow && cat flag.txt` don't seem to work as the characters are probably filtered. After some trial and error, I found the following to work (passing output of a command as parameter to another):

```
figlet `cat flag.txt`
```



### Simple Calculator

> Meet my new Calculator works Faster than Light

I don't remember much about the challenge at the time of writing this writeup. What I can recall is that you're provided with a calculator app that works like any other calculator. However, input is not filtered. So, if you use curl or Burp to manipulate the requests, you could provide input other than numbers and math operations. After some trial and error, I figured that python `eval` was being used to calculate the output. Providing `os.system('cat flag.txt')` didn't seem to work but I soon figured that that's probably because the `os` module wasn't imported. Providing `import os; os.system('cat flag.txt')` as input did the trick.



### LFI-University

> Seems like you have a lot of assignments due today

We are provided with an assignment submission portal. The website contains a few sections with things like Leaderboard, Assignment Submission Upload, Incomplete Assignments, Login, Dashboard, etc. Taking a look at the leaderboard, you could see that person called `Cedric_Kelly` at the top had an extra assignment submitted called `flag`.

If you logged in as some user, say `admin` and uploaded a file called `filename` as assignment, the site displayed a message at the top saying something similar to `Assignment submitted! Located at submits/admin_filename.txt` . Now, we know where the submissions are stored; and so the flag might be present in a file called `submits/Cedric_Kelly_flag.txt`. We now only have to find the Local File Inclusion vulnerability.

Taking a look at the Assignment download section in the source code, you could see that there was a request being sent to the server with a `?file=<SOME_FILENAME_HERE>` parameter. It had a basic filter that did not allow more than three `.` or `\` characters. Simply sending a download request to `file=../submits/Cedric_Kelly_flag.txt` (the `../submits` part can be figured out with some trial and error) will download the flag for us.



### World Map

> Hi, I have hidden a treasure in this map. Can you try finding it?
>
> I'm sure that you are familiar with `robots.txt`, but let's see if you know something more. XD
>
> Good luck!

I don't remember what the challenge was at the time of writing this writeup but it was something fairly simple :(



### Blog-X

> Oh, just the proxy is broken. I think you can replicate it

This was a very simple challenge but might have been very frustrating for people who do not know about the exploit from previous reading or challenges. The name of the problem hints towards `X-` headers in HTML requests.

There was a normal page that showed a few topics and some small descriptions of them like a normal blog site (one of them said "flag" in title but with an empty description) and a challenge endpoint `http://ip.add.re.ss/proxy` that was provided. The proxy endpoint just said that the site is under construction.

Clicking on the flag blog showed an error message saying that the page is only accessible by localhost `127.0.0.1`.

Simply changing the `X-Forwarded-For` header to that of the localhost gave us the flag.



### PDF Generator

> I developed this secure PDF generator. I am giving out flags to all those people who reach my [http://localhost ](http://localhost/). Can you reach there?

We are provided with a service that takes in a URL as input and then provides us with a PDF of the webpage of that site. The challenge is a simple SSRF (Server Side Request Forgery) Attack which can be carried out by providing any URL that would cause a redirection to localhost.

But there are many filters that make it difficult to get a successful redirection and most popular redirection sites have been blocked. None of the loopback ip addresses nor common techniques to bypass work either. However, if you were lucky and could find a site that was not filtered, you'd get the flag. After some searching and lots of trial and error, I came across two sites that seemed to work and caused a successful redirection to localhost, giving us the flag: `https://beeceptor.com/` to create an endpoint specifically to target the service, or `http://bugbounty.dod.network` (which is what I luckily found and initially used).



### Polluted

> Can you have a look at our new website? we only have a single functionality and we are pretty sure we are safe from attacks :)

This problem was a standard textbook polluted parameter injection attack. Many resources are available online for the same.



## Cryptography

### common-extender

> Break the box to get the flag

We are provided with two files:

```python
# chall.py

from Crypto.Util.number import *
from secret import *
p=getPrime(1024)
q=getPrime(1024)
n=p*q
e=65537
e1=5**e 
e2=7**e
m=bytes_to_long(flag)
c1=pow(m,e1,n)
c2=pow(m,e2,n)
f=open('common.txt','wb')
f.write('c1 ='+str(c1)+'\n')
f.write('c2 ='+str(c2)+'\n')
f.write('n ='+str(n)+'\n')
```

```
# common.txt

c1=4723005985613543187020628938921653359117769920118354915283034471439951923751100042324993738873335720499784832162124494724397874077445927539518170906182303071332375503334377466642151794243893906686488318314054581277279339354540824560289281377642476956195085157598596806724741328453851091266048989755240316042334268749726482498290550751421726074890664103854548877867102449424289393328824577607388404132540469861201309536143850843812921167352182401864201559799676471710328882434530114454019475040002543619441854896467180130953718013265450930254533163800232807408091288735463359738179843762952219190997088933076463800937

c2=10661271147018941693868519425015420669304227031149199140791386970019096952927137416689438586221525636852501069518071596639264468645491045897884647407076730835292758137798902431649278166782296895082822129633563506818700870154189144836361676276555629751239323641469875120324974236823100525239750663787201418512480903774505519091161838612044303655990682336151817250392594652014609590192456834512948777394553397026821855860329964005565294653826280257960557756783979076491069339465500539440222774123086569145442457693185866956898675083518702635078528584279392938595697812726333735052589820594259874406841682091739678524166

n=11155969736975030321603841672525295227570716210595590699453614058237981426469332282238600717214610633264384213690995769680221614766192515074958634372975469729171515398846583529856706120844739718236545956568085134178568177454529312263751145892952154745569078370817794422735815658766976052106764697692513578131712594084459526863090016695367406601060344189805521965430081209261308855001306956480675881885019593474575445953467735810323250937035075578541754977140680224088631592773035911479161549529768832799346709755779715883372921257849085412674123966236800311386984918023151443206911776079574398957068052132081309547789
```

This is a very basic RSA challenge that can be solved using common modulus attack. We can find the extended gcd of c1 and c2 such that:

`x * c1 + y * c2 == 1` where `x` and `y` are integers obtained as the solution to extended gcd.

Once we have `x` and `y`, we can do the following the obtain the flag:

```
Given:
m ** e1 mod n = c1
m ** e2 mod n = c2

Solution:
c1 ** x => (m ** e1) ** x => m ** (e1 * x)
c2 ** y => (m ** e2) ** y => m ** (e2 * y)

Multiplying the two values obtained, we get:
m ** (e1 * x + e2 * y)
m ** (1)
m # yay!
```

Here's the solution in python:

```python
import sys
from Crypto.Util.number import long_to_bytes

sys.setrecursionlimit(100000)

def extended_euclid(a,b):
    if b == 0:
        return a, 1, 0

    d1,x1,y1 = extended_euclid(b, a % b)
    d = d1
    x = y1
    y = x1 - (a // b) * y1
    return d, x, y

import gmpy2

class RSAModuli:
    def __init__(self):
        self.a = 0
        self.b = 0
        self.m = 0
        self.i = 0
    def gcd(self, num1, num2):
        """
        This function os used to find the GCD of 2 numbers.
        :param num1:
        :param num2:
        :return:
        """
        if num1 < num2:
            num1, num2 = num2, num1
        while num2 != 0:
            num1, num2 = num2, num1 % num2
        return num1
    def extended_euclidean(self, e1, e2):
        """
        The value a is the modular multiplicative inverse of e1 and e2.
        b is calculated from the eqn: (e1*a) + (e2*b) = gcd(e1, e2)
        :param e1: exponent 1
        :param e2: exponent 2
        """
        _, self.a, self.b = extended_euclid(e1, e2)
        # self.a = gmpy2.invert(e1, e2)
        # self.b = (float(self.gcd(e1, e2)-(self.a*e1)))/float(e2)
    def modular_inverse(self, c1, c2, N):
        """
        i is the modular multiplicative inverse of c2 and N.
        i^-b is equal to c2^b. So if the value of b is -ve, we
        have to find out i and then do i^-b.
        Final plain text is given by m = (c1^a) * (i^-b) %N
        :param c1: cipher text 1
        :param c2: cipher text 2
        :param N: Modulus
        """
        i = gmpy2.invert(c2, N)
        mx = pow(c1, self.a, N)
        my = pow(i, int(-self.b), N)
        self.m= mx * my % N
    def print_value(self):
        print("Plain Text: ", self.m)
        return self.m

def main():
    c = RSAModuli()
    N  = 11155969736975030321603841672525295227570716210595590699453614058237981426469332282238600717214610633264384213690995769680221614766192515074958634372975469729171515398846583529856706120844739718236545956568085134178568177454529312263751145892952154745569078370817794422735815658766976052106764697692513578131712594084459526863090016695367406601060344189805521965430081209261308855001306956480675881885019593474575445953467735810323250937035075578541754977140680224088631592773035911479161549529768832799346709755779715883372921257849085412674123966236800311386984918023151443206911776079574398957068052132081309547789
    c1 = 4723005985613543187020628938921653359117769920118354915283034471439951923751100042324993738873335720499784832162124494724397874077445927539518170906182303071332375503334377466642151794243893906686488318314054581277279339354540824560289281377642476956195085157598596806724741328453851091266048989755240316042334268749726482498290550751421726074890664103854548877867102449424289393328824577607388404132540469861201309536143850843812921167352182401864201559799676471710328882434530114454019475040002543619441854896467180130953718013265450930254533163800232807408091288735463359738179843762952219190997088933076463800937
    c2 = 10661271147018941693868519425015420669304227031149199140791386970019096952927137416689438586221525636852501069518071596639264468645491045897884647407076730835292758137798902431649278166782296895082822129633563506818700870154189144836361676276555629751239323641469875120324974236823100525239750663787201418512480903774505519091161838612044303655990682336151817250392594652014609590192456834512948777394553397026821855860329964005565294653826280257960557756783979076491069339465500539440222774123086569145442457693185866956898675083518702635078528584279392938595697812726333735052589820594259874406841682091739678524166
    e1 = 5 ** 65537
    e2 = 7 ** 65537
    c.extended_euclidean(e1, e2)
    c.modular_inverse(c1, c2, N)
    c.print_value()
    print(long_to_bytes(c.print_value()))


if __name__ == '__main__':
    main()

```

**Flag:** `inctf{common_modulus_uses_extended_gcd}`



### HakUnA MaTaTa

> My friend said that no one can find his message. Is it so? Help me to retrieve that message.

We are given a file containing some information about RSA

```
# parameter.txt

n= 176761571208207012415104998714596408301750400405256242985416759062950343063581762981549330162494657679457228005027706486975181662262022630561794614317969075124125317405890618375349258122857970874783283331306015606502527083552449658631772271993457846851450158171082817214843608062810655788283192168155075475033

publickey_factors=[13,4410317,3503090458121,1787448132402352730231919365956562215780010188225948494099055254148746819284760979919032994965974299927086267543424246654464054743220910777053514594577772477081375429741060310438880197018372947090569183433805681685094237700877854589478992875314150034441676675035103332579789642879492251]

c= 64705229719616953499618671343545641623043176468818932627792545485250020716349796561576551079269927746253595018629167137753299865685555409247164742357601590413993926183392568247214089883027699319306718399837516788223830037840626900525450740884857152047880456955305220457169101462244557867578665264644074661128
```

The `publickey_factors` is essentially the factors of the exponent `e` in RSA. We can notice that the exponent would be very large after taking the product of values. It is possible that very large exponents can be exploited using the `wiener` attack. I took a guess that that's all we had to do, and in fact wiener attack worked. I used [RsaCtfTool](https://github.com/Ganapati/RsaCtfTool) for the attack.

```python
# main.py

n= 176761571208207012415104998714596408301750400405256242985416759062950343063581762981549330162494657679457228005027706486975181662262022630561794614317969075124125317405890618375349258122857970874783283331306015606502527083552449658631772271993457846851450158171082817214843608062810655788283192168155075475033

publickey_factors=[13,4410317,3503090458121,1787448132402352730231919365956562215780010188225948494099055254148746819284760979919032994965974299927086267543424246654464054743220910777053514594577772477081375429741060310438880197018372947090569183433805681685094237700877854589478992875314150034441676675035103332579789642879492251]

c= 64705229719616953499618671343545641623043176468818932627792545485250020716349796561576551079269927746253595018629167137753299865685555409247164742357601590413993926183392568247214089883027699319306718399837516788223830037840626900525450740884857152047880456955305220457169101462244557867578665264644074661128


e = 1
for i in publickey_factors:
    e *= i

import os

os.system(f'rsatool -n {n} -e {e} --uncipher {c} --timeout 5 --attack wiener')
```

**Flag:** `inctf{w7ap_tHe_Tr@p_trAp_tHe_Wrap}`



### Duplicates

> Is it possible to duplicate?

We are provided with a `nc` service that we can connect to. Also, the challenge files are also provided.

```python
# chall.py

from Crypto.Util.number import getPrime
from secret import flag
pt=int(flag.hex(),16)

def gen():
    p,q=getPrime(512),getPrime(512)
    e,n=65537,p*q
    ct=pow(pt,e,n)
    d=pow(e,-1,(p-1)*(q-1))
    return ct,d,n,[p,q]

if __name__ == '__main__':
    ct,d1,n,pq=gen()
    print(pq)
    d2=int(input("> "))
    if d2!=d1:
        if pow(ct,d2,n)==pt:
            print(f"Good Job!!\n{flag.decode()}")
        else:
            print("bruh")
    else:
        print("Are you for real??")
```



We need to provide a private key `d2` different from the original private key `d1` that can decode the ciphertext. The challenge was solved by my teammate and the solution was as follows:

```
We know the values of p, q, e, n

calculate phi = (p - 1) * (q - 1)
calculate d1 = (e ** -1) mod phi

let d2 = d1 + phi

Provide d2 as key to decrypt and retrieve the flag
```

The reason why this works is because multiple private keys can be used to decode the ciphertext that follow certain properties under modular arithmetic. We used `d1 + phi` as decryption key but essentially any key of the following form would work:

```
add anything to d1 such that it remains d1 modulo phi
(d1 + k * phi) with (1 <= k)

multiply anything to d1 such that it remains d1 modulo phi
(d1 * ((d1 * e) ^ k)) with (1 <= k)
```

**Flag:** `forgot storing the flag...`



### cubRSAic

> Find the roots and get the flag :))

We are provided with two files:

```python
# rsa.py

from Crypto.Util.number import *
from flag import flag,x,p,q,r
n=p*q*r
a=1
b=193397088739638251960555612436875600986330023883750295571725584630414480365724395898270141722031329748156082442012506741700345490623652456944752641259299481648189663225789316735492124809430246787061623943122992972555612870003055978190998434876318194750716018238436902415663573233192086436098541111277008199813
c=8728831297832120843336404142494383487861941996882802023565995709954417891405655853020017387748976733140991007940950795977416209344692420808833741595065361790155014723446976903204381140455085622575477064605600925830092628718070785954578133863918237568921639276619726474929358824725452522548936820930316044199781907769975116642583087228056122086340804371487673925003430886366328940606581590239833871087344153426940165114190628567985514860529931412375128745713119805742019339702063634799522188535333496263711303227429950221230519245843532481700865129308471919982350847692475752700865209968245261953392636533410992980775
d=63070596256679484662413410207373928004736001790383956853307898306602698350449502470396308261161065806877977215076829311908943777778986616540253214462303167277670756699548339028092316959537033018041441628359647493347189674598031375658196799172454802634799166223829305392192521613748720703056322649928224065867121497675495400662468690132676998903424015988906876418063546949676385421158504886275413258353832927820154529362504173957845256741347439175151413191454309190779489182687927387632163531223048994443162863182633645603482086186470861356033199650558396270818562930850023584234133180617891209746554867462265585965013354965873061584035287994018488964953755160036085993213998304861556792215861795195160484204162254562357064980532222046820367893936950321067965117665776931
assert b*(x**2)+d == x**3 + c*x
flag=bytes_to_long(flag)
e=0x10001
ct=pow(flag,e,n)
f=open('out.txt','w')
f.write('n ='+ hex(n) +'\n')
f.write('e ='+hex(e)+'\n')
f.write('ct = '+hex(ct))
```

```
# out.txt

n =0x540fa632c6fb3c9d26d1927addf3775f15c44651636068ca9e7ba57cc5c0eecfae7fccb7174ad9594fee114551ded48029203c2cf2775f48e755b9275cf5be199dcfbe110ff480166ce902726c08560f9e05a0c823d5603c34c10e2b1df09d5121c804fb980d718d45c508d1a760f7c6068f19d53787deb1c9b89c3b64e5360498bed3d5be6d30aa1964d09a6ba179064345cfadce5916f32ec295653e8fc7c1fb9f225253566c9a8c168800e58d5141eff1c2be8e9f47b4a083992c39ceb6a9
e =0x10001
ct = 0xa17638f7fb80df8e96d78fddb3324d26395aaf30aa49610db4ed4bf3ef9864a32f32a7e11468440540abef648754a11e98fd836f077ac6d9bc33d6df0190fe62e900b02e62a95268b76ae2d673b3c614a82c267f213219ebd9ba8313fc078a541eeff0fcc1dfec568539098682c824d0bdd78933f2421d52d57aaf2c82bcaff304d3d3dd251c289d2fc93292c5c9734871cf491b355ce20277558902484fd9dc85de87caccbb5474b14b9664037f213344d9d77a1e10fb8f1d6f42f11e9247b
```



### OFB Madness

>  Why always block try stream !!

```python
# chall.py

#!/usr/sbin/python
from secret import flag
from Crypto.Cipher import AES
from os import urandom

key=urandom(16)

def encrypt(msg, iv):
    cipher = AES.new(key, AES.MODE_OFB,iv)
    ct = cipher.encrypt(msg)
    return ct if ct not in flag else b"try_harder"

def main():
    print('Welcome to inctf.\nHere is a gift from my side:')
    iv=urandom(16)
    print(iv.hex()+encrypt(flag,iv).hex())
    print("You can encrypt any string you want 3 times.")
    for _ in range(3):
        x=bytes.fromhex(input("> ").strip())
        iv,msg=x[:16],x[16:]
        print(encrypt(msg,iv).hex())

if __name__=='__main__':
    main()
```

```python
# secret.py

flag = b"inctf{fake_flag_for_testing}"
```



Solved by teammate.



### copper_copper_copper

```python
# chall.py

from flag import flag
from Crypto.Util.number import bytes_to_long, getPrime
from random import randbytes, getrandbits

msg=b'copper copper copper copper copper copper copper copper!'
assert len(flag)==103

def pad(msg,l):
    return msg+randbytes(l-len(msg))

e=[3,65537]
p,q=getPrime(1024),getPrime(1024)
n=p*q

assert n.bit_length()==2048

k=(n+getrandbits(16))>>2

m1=bytes_to_long(pad(flag,110))
m2=bytes_to_long(pad(flag,110))

c=pow(bytes_to_long(msg),e[1],n)

c1=pow(m1,e[0],n)
c2=pow(m2,e[0],n)

with open('out.txt','w') as f:
    f.write('k = ' + hex(k)+'\n')
    f.write('c = ' + hex(c)+'\n')
    f.write('c1 = '+ hex(c1)+'\n')
    f.write('c2 = ' + hex(c2)+'\n')

# out.txt

k = 0x35818bb5f5d0239881b936495803b4cf1fdfe032df38554b7b390ebdeb74980801107890aeb6ba7156c9108f7607fc151c7b922416666c163a795feee5df5eff1afea12f5efe41210859f50e76a4d55bb804b5aba3e428db08c704dcc3ba5673bb07e8af0ef1b070ccc87f2ccea16ccc4b288eb4d19c656598cd78f5d8e29856093db2425984b186b65a7c124bae0d7503512d0429babada931f2218752e6c0d3f68e5bfc0d08e1aa3369037fd01795500a8318cd33743e3a82b4a59e6a690d15c9b17706e1809cef0eddaaad8328916e391f9b49186c1f25326aa0149cd856b435c31615a272d1dee4c605dd034294c78ea8c9bd935a5adbbad49f78dad5600
c = 0x402c78559a350b06aafc83acdb46cd2ed498031d3ea049dea632e4fb55f566a520b699aa3c5b3631b31fc14c0ea6871ddbded3806ac2567b7ef8351491abe624fcd47257948f31313aff13ba1122af1db1cab398bd1ba47b763a17a81435d7c1544795e2eab347f8f36cb576bd1358aa22f4948ec88a0d4860ecced9cf7513286b9cbdca9ab64177a64120b7e488083552c8e794d1df04742446208d90e70e33d2912544caa2997e1776b27a60e50789c6e5257b4e055533f163edfe71063df65f7afbc6675d212f5456f2e1ed39777a611725f2db7894cdf21c108c9e3b972c004ec04ec88a23e7c5deae0bc3104a7aa5ea106c381affaf6dd715c665555d3
c1 = 0x26fa28c50c33ae2050f9f3b07e0fa3fbc07f15ae250a053db9785a7b227940c067a0da4e0210eb3f63a1cc116a52ff93b43a60b2126aaf9f0c28e0b8e238877a91dfc4635ee3fe2cf7020ab56488e1cda0ac94b99b9944a866e55b9826121e7c9c59f5f77ee3875698f475120aed4cf84d254285c48fdfcf5eb6f9e56fa203e76c7b6900e9e05b5b5b3aa8205bc9b91d4938986520d7894d8bbeccf63e1adcf2b1294926934b966afcc14822a63ceba511f45027859a4b61d501e18035233e4ec4733a8e944fa48ee39a640df974849dda8466fa429c8a82cfe2e4fca127ae602bdb084ce715c8208646c0803b4351e8ca19b80e5b3fd07f79db7d80ba29c40a
c2 = 0x26fa28c50c33ae2050f9f3b07e0fa3fbc07f15ae250a053db9785a7b222299197077e22ffb106412eacd246c87fbf31116bf55bb3096482f613040c553645eb7f4a8536bb688b15f30a250d1b648c05ec70badc143366ee7704965aee389517f8f1ee7d33324b6754d8b7a54af2f41f796f3b12afecd17f7e2a487d9af2d531fc6f1ef2c59445b01ea967438b04a68eb3346dda341d9cb3056810f247abc17c8a45e3c854115577802388a93c21c067b3ce5ab1d3524ce731b4e23f8cc12bbb72cc8a56cbf2b3f358dd446cb005c4cff102216b72e6c61ed590e9f065812ea9ce3355bf11f7acb8a3f84ae80a15274ad3779ddab3cea37d2eeabe824fe9fadc8
```



Solved by teammate.

Find the correct bits of modulus using brute force as we know the value `msg`, its ciphertext and exponent. Use [Coppersmith Short Pad Attack](https://en.wikipedia.org/wiki/Coppersmith%27s_attack#Coppersmith%E2%80%99s_short-pad_attack) once you have the modulus.

```python
# exploit.py

import binascii
from Crypto.Util.number import bytes_to_long

msg=b'copper copper copper copper copper copper copper copper!'

gk = 0x35818bb5f5d0239881b936495803b4cf1fdfe032df38554b7b390ebdeb74980801107890aeb6ba7156c9108f7607fc151c7b922416666c163a795feee5df5eff1afea12f5efe41210859f50e76a4d55bb804b5aba3e428db08c704dcc3ba5673bb07e8af0ef1b070ccc87f2ccea16ccc4b288eb4d19c656598cd78f5d8e29856093db2425984b186b65a7c124bae0d7503512d0429babada931f2218752e6c0d3f68e5bfc0d08e1aa3369037fd01795500a8318cd33743e3a82b4a59e6a690d15c9b17706e1809cef0eddaaad8328916e391f9b49186c1f25326aa0149cd856b435c31615a272d1dee4c605dd034294c78ea8c9bd935a5adbbad49f78dad5600
gc = 0x402c78559a350b06aafc83acdb46cd2ed498031d3ea049dea632e4fb55f566a520b699aa3c5b3631b31fc14c0ea6871ddbded3806ac2567b7ef8351491abe624fcd47257948f31313aff13ba1122af1db1cab398bd1ba47b763a17a81435d7c1544795e2eab347f8f36cb576bd1358aa22f4948ec88a0d4860ecced9cf7513286b9cbdca9ab64177a64120b7e488083552c8e794d1df04742446208d90e70e33d2912544caa2997e1776b27a60e50789c6e5257b4e055533f163edfe71063df65f7afbc6675d212f5456f2e1ed39777a611725f2db7894cdf21c108c9e3b972c004ec04ec88a23e7c5deae0bc3104a7aa5ea106c381affaf6dd715c665555d3
gc1 = 0x26fa28c50c33ae2050f9f3b07e0fa3fbc07f15ae250a053db9785a7b227940c067a0da4e0210eb3f63a1cc116a52ff93b43a60b2126aaf9f0c28e0b8e238877a91dfc4635ee3fe2cf7020ab56488e1cda0ac94b99b9944a866e55b9826121e7c9c59f5f77ee3875698f475120aed4cf84d254285c48fdfcf5eb6f9e56fa203e76c7b6900e9e05b5b5b3aa8205bc9b91d4938986520d7894d8bbeccf63e1adcf2b1294926934b966afcc14822a63ceba511f45027859a4b61d501e18035233e4ec4733a8e944fa48ee39a640df974849dda8466fa429c8a82cfe2e4fca127ae602bdb084ce715c8208646c0803b4351e8ca19b80e5b3fd07f79db7d80ba29c40a
gc2 = 0x26fa28c50c33ae2050f9f3b07e0fa3fbc07f15ae250a053db9785a7b222299197077e22ffb106412eacd246c87fbf31116bf55bb3096482f613040c553645eb7f4a8536bb688b15f30a250d1b648c05ec70badc143366ee7704965aee389517f8f1ee7d33324b6754d8b7a54af2f41f796f3b12afecd17f7e2a487d9af2d531fc6f1ef2c59445b01ea967438b04a68eb3346dda341d9cb3056810f247abc17c8a45e3c854115577802388a93c21c067b3ce5ab1d3524ce731b4e23f8cc12bbb72cc8a56cbf2b3f358dd446cb005c4cff102216b72e6c61ed590e9f065812ea9ce3355bf11f7acb8a3f84ae80a15274ad3779ddab3cea37d2eeabe824fe9fadc8

e=[3,65537]

t=gk<<2
for i in range(t-2**16,t):
    if gc==pow(bytes_to_long(msg),e[1],i):
        n=i
        break

# we get: n=27018046204288301076057926047344204505353252829984381965050954539974186296724141673936863891947871162798035322173963436622467945406195420759017839331561883848361120717249845753206072039769715959634133203455961163514317810317452730532304925163609984220730526713093680555882065406743403870940096629103367392623829911534587612102480165989692244079012428546227169615344200399086572686133242031233126542106007590483765696766152986663025394577442312674370266218451618218761644383394976993752002773554189530620888573426420144384166213099020036284107941926348554240101454417960184096925910281193441191713548460354557021813611

# Now we have e,n,c1,c2 which satify the constraints to make Coppersmith Short pad attack work

# Found this code to perform Coppersmith Short pad attack work, need to install sage first.

from sage.all_cmdline import Integer   # import sage library

_sage_const_3 = Integer(3); _sage_const_2 = Integer(2); _sage_const_1 = Integer(1); _sage_const_0 = Integer(0); _sage_const_11 = Integer(11); _sage_const_8 = Integer(8); _sage_const_512 = Integer(512); _sage_const_8192 = Integer(8192); _sage_const_16 = Integer(16); _sage_const_30 = Integer(30); _sage_const_400 = Integer(400); _sage_const_25 = Integer(25)
from sage.all import PolynomialRing,ZZ,Zmod
# https://github.com/ValarDragon/CTF-Crypto/blob/master/RSA/FranklinReiter.sage
# Franklin-Reiter attack against RSA.
# If two messages differ only by a known fixed difference between the two messages
# and are RSA encrypted under the same RSA modulus N
# then it is possible to recover both of them.

# Inputs are modulus, known difference, ciphertext 1, ciphertext2.
# Ciphertext 1 corresponds to smaller of the two plaintexts. (The one without the fixed difference added to it)
def franklinReiter(n,e,r,c1,c2):
    R = Zmod(n)['X']; (X,) = R._first_ngens(1)
    f1 = X**e - c1
    f2 = (X + r)**e - c2
    # coefficient 0 = -m, which is what we wanted!
    return Integer(n-(compositeModulusGCD(f1,f2)).coefficients()[_sage_const_0 ])

  # GCD is not implemented for rings over composite modulus in Sage
  # so we do our own implementation. Its the exact same as standard GCD, but with
  # the polynomials monic representation
def compositeModulusGCD(a, b):
    if(b == _sage_const_0 ):
        return a.monic()
    else:
        return compositeModulusGCD(b, a % b)

def CoppersmithShortPadAttack(e,n,C1,C2,eps=_sage_const_1 /_sage_const_30 ):
    """
    Coppersmith's Shortpad attack!
    Figured out from: https://en.wikipedia.org/wiki/Coppersmith's_attack#Coppersmith.E2.80.99s_short-pad_attack
    """
    P = PolynomialRing(ZZ, names=('x', 'y',)); (x, y,) = P._first_ngens(2)
    ZmodN = Zmod(n)
    g1 = x**e - C1
    g2 = (x+y)**e - C2
    res = g1.resultant(g2)
    P = PolynomialRing(ZmodN, names=('y',)); (y,) = P._first_ngens(1)
    # Convert Multivariate Polynomial Ring to Univariate Polynomial Ring
    rres = _sage_const_0 
    for i in range(len(res.coefficients())):
        rres += res.coefficients()[i]*(y**(res.exponents()[i][_sage_const_1 ]))

    diff = rres.small_roots(epsilon=eps)
    recoveredM1 = franklinReiter(n,e,diff[_sage_const_0 ],C1,C2)
    return str(recoveredM1)

flag=CoppersmithShortPadAttack(e[0],n,Integer(gc2),Integer(gc1))
flag=hex(int(flag))[:-14][2:]
print(binascii.unhexlify(flag).decode('ASCII'))
```