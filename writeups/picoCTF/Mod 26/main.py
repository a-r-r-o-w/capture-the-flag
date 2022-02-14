s = "cvpbPGS{arkg_gvzr_V'yy_gel_2_ebhaqf_bs_ebg13_MAZyqFQj}"

for i in s:
    if i.isupper():
        i = chr(ord('A') + (ord(i) - ord('A') + 13) % 26)
    elif i.islower():
        i = chr(ord('a') + (ord(i) - ord('a') + 13) % 26)
    
    print(i, end = '')
