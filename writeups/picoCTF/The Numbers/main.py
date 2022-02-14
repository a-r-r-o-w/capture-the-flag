l = [16, 9, 3, 15, 3, 20, 6]
r = [20, 8, 5, 14, 21, 13, 2, 5, 18, 19, 13, 1, 19, 15, 14]

for i in l:
    print(chr(ord('A') + i), end = '')
print('{', end = '')
for i in r:
    print(chr(ord('A') + i), end = '')
print('}')
