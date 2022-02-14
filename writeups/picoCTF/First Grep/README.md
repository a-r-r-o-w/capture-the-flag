
# First Grep 

### Author: Alex Fulton/Danny Tunitis

### Description

```
Category: General Skills

Can you find the flag in <a href='//jupiter.challenges.picoctf.org/static/515f19f3612bfd97cd3f0c0ba32bd864/file'>file</a>? This would be really tedious to look through manually, something tells me there is a better way.

Hints:

(1) grep <a href="https://ryanstutorials.net/linuxtutorial/grep.php">tutorial</a>

```

### Solution

`strings file | grep pico`

##### Flag: `picoCTF{grep_is_good_to_find_things_5af9d829}`
