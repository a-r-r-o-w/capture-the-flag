
# Glory of the Garden 

### Author: jedavis/Danny

### Description

```
Category: Forensics

This <a href='//jupiter.challenges.picoctf.org/static/4153422e18d40363e7ffc7e15a108683/garden.jpg'>garden</a> contains more than it seems.

Hints:

(1) What is a hex editor?

```

### Solution

We simply use `strings` and find the flag at the bottom of the text content.

```bash
┌──(arrow) 💀 [~/…/capture-the-flag/Writeups/picoCTF/Glory of the Garden]
└─$ strings garden.jpg
...
...
... bunch of nonsense text
...
...
...
Here is a flag "picoCTF{more_than_m33ts_the_3y33dd2eEF5}"
```

##### Flag: `picoCTF{more_than_m33ts_the_3y33dd2eEF5}`
