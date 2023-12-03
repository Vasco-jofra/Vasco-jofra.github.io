#include "stdio.h"

int main() {
  // Declare the buffers
  char buf_before[8] = {'A', 'A', 'A', 'A', 'A', 'A', 'A', '\0'};
  char        buf[8] = {'X', 'X', 'X', 'X', 'X', 'X', 'X', '\0'};
  char  buf_after[8] = {'B', 'B', 'B', 'B', 'B', 'B', 'B', '\0'};

  // Read into buf
  printf("Enter a string: ");
  int ret = scanf("%8s", buf);

  // Print the variable's values
  printf("%s\n", buf_before); // AAAAAAA
  printf("%s\n", buf);        // XXXXXXXX
  printf("%s\n", buf_after);  // (nothing) 
  // The last print does not print anything, because `scanf` writes `\x00` in the first byte of `buf_after`

  return ret;
}