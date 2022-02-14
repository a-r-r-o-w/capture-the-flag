
# Obedient Cat 

### Author: syreal

### Description

```
Category: General Skills

This file has a flag in plain sight (aka "in-the-clear"). <a href='//mercury.picoctf.net/static/217686fc11d733b80be62dcfcfca6c75/flag'>Download flag</a>.

Hints:

(1) Any hints about entering a command into the Terminal (such as the next one), will start with a '$'... everything after the dollar sign will be typed (or copy and pasted) into your Terminal.

(2) To get the file accessible in your shell, enter the following in the Terminal prompt: <code>$ wget https://mercury.picoctf.net/static/217686fc11d733b80be62dcfcfca6c75/flag</code>

(3) <code>$ man cat</code>

```

### Solution

The challenge only requires us to look at the file contents.

```bash
┌──(arrow 💀)-[~/Desktop/ctf/picoctf/Obedient Cat]
└─$ cat flag                 
picoCTF{s4n1ty_v3r1f13d_b5aeb3dd}
```

##### Flag: `picoCTF{s4n1ty_v3r1f13d_b5aeb3dd}`
