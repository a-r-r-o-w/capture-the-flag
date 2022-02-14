
# Mod 26 

### Author: Pandu

### Description

```
Category: Cryptography

Cryptography can be easy, do you know what ROT13 is? <code>cvpbPGS{arkg_gvzr_V'yy_gel_2_ebhaqf_bs_ebg13_MAZyqFQj}</code>

Hints:

(1) This can be solved online if you don't want to do it by hand!

```

### Solution

Shift every character by 13 positions.

```python
s = "cvpbPGS{arkg_gvzr_V'yy_gel_2_ebhaqf_bs_ebg13_MAZyqFQj}"

for i in s:
    if i.isupper():
        i = chr(ord('A') + (ord(i) - ord('A') + 13) % 26)
    elif i.islower():
        i = chr(ord('a') + (ord(i) - ord('a') + 13) % 26)
    
    print(i, end = '')
```

##### Flag: `picoCTF{next_time_I'll_try_2_rounds_of_rot13_ZNMldSDw}`
