
# plumbing 

### Author: Alex Fulton/Danny Tunitis

### Description

```
Category: General Skills

Sometimes you need to handle process data outside of a file. Can you find a way to keep the output from this program and search for the flag? Connect to <code>jupiter.challenges.picoctf.org 4427</code>.

Hints:

(1) Remember the flag format is picoCTF{XXXX}

(2) What's a pipe? No not that kind of pipe... This <a href="http://www.linfo.org/pipes.html">kind</a>

```

### Solution

On connection to the service using `nc jupiter.challenges.picoctf.org 4427`, there seems to be a lot of output. We can pipe it into grep to search for the flag.

`nc jupiter.challenges.picoctf.org 4427 | grep pico`

##### Flag: `picoCTF{digital_plumb3r_5ea1fbd7}`
