with open('numbers.txt') as file:
  content = file.readlines()

for line in content:
  print(chr(int(line.strip())), end = '')
