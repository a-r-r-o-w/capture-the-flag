
# Nice netcat... 

### Author: syreal

### Description

```
Category: General Skills

There is a nice program that you can talk to by using this command in a shell: <code>$ nc mercury.picoctf.net 43239</code>, but it doesn't speak English...

Hints:

(1) You can practice using netcat with this picoGym problem: <a href='https://play.picoctf.org/practice/challenge/34'>what's a netcat?</a>

(2) You can practice reading and writing ASCII with this picoGym problem: <a href='https://play.picoctf.org/practice/challenge/22'>Let's Warm Up</a>

```

### Solution

Connecting with nc, we get the following result:

```bash
┌──(arrow) 💀 [~/Desktop/ctf/picoctf/Nice netcat...]
└─$ nc mercury.picoctf.net 43239 
112 
105 
99 
111 
67 
84 
70 
123 
103 
48 
48 
100 
95 
107 
49 
116 
116 
121 
33 
95 
110 
49 
99 
51 
95 
107 
49 
116 
116 
121 
33 
95 
55 
99 
48 
56 
50 
49 
102 
53 
125 
10 
                                                                                                  
┌──(arrow) 💀 [~/Desktop/ctf/picoctf/Nice netcat...]
└─$ nc mercury.picoctf.net 43239 > numbers.txt
```

Looks like ASCII values for what might be the flag?

```python
with open('numbers.txt') as file:
  content = file.readlines()

for line in content:
  print(chr(int(line.strip())), end = '')
```

##### Flag: `picoCTF{g00d_k1tty!_n1c3_k1tty!_7c0821f5}`
