#include <stdio.h>

int main () {
  char buffer[100] = {0};
  int password = 0x31337;
  gets(buffer);
  
  if (password == 0x1337)
    puts("flag{secret_flag}");
  else
    puts(":(");

  return 0;
}
