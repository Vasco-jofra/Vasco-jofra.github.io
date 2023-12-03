#include <stdio.h>
#include <stdlib.h>

// ====================
// Good scanf usages
void good_scanf_percentage_XX_s() {
  char buf[64];
  scanf("%63s", buf);
}

void good_scanf_percentage_XX_s_with_other_formats() {
  char buf[64];
  int i;
  scanf("Test %d %63s", &i, buf);
}

void good_scanf_percentage_XX_s_with_other_formats_2() {
  char buf_1[32];
  char buf_2[64];
  char buf_3[100];
  scanf("%31s%63s%100s", buf_1, buf_2, buf_3);
}

void good_scanf_percentage_XX_s_with_asterisk_modifier() {
  char buf[64];
  scanf("Test %*100s %63s", buf);
}

void good_scanf_percentage_XX_s_malloc_1() {
  char* buf = malloc(64);
  scanf("%63s", buf);
}

void good_scanf_percentage_XX_s_malloc_2() {
  char* buf;
  buf = malloc(64);
  scanf("%63s", buf);
}

void good_scanf_percentage_XX_s_malloc_3() {
  char* buf;
  int i = 64;
  buf = malloc(i);
  scanf("%63s", buf);
}

// ====================
// Bad scanf usages
void vuln_scanf_percentage_s() {
  char buf[100];
  // This may overflow `buf` if the user enters a string longer than 100 characters
  scanf("Test %s test", buf);
}

void vuln_scanf_percentage_brackets() {
  char buf[100];
  // This may overflow `buf` if the user enters a string longer than 100 characters
  scanf("Test %[A] test", buf);
}

void vuln_scanf_percentage_brackets_not() {
  char buf[100];
  // This may overflow `buf` if the user enters a string longer than 100 characters
  scanf("Test %[^\n] test", buf);
}

void vuln_scanf_percentage_s_arg(char* buf) {
  scanf("%64s", buf);
}

void vuln_scanf_percentage_XX_s() {
  char buf[64];
  // This may overflow `buf` by 1 `\x00` if the user enters a string with 64 characters
  scanf("Test %64s test", buf);
}

void vuln_scanf_percentage_XX_s_malloc_1() {
  char* buf = malloc(64);
  scanf("%64s", buf);
}

void vuln_scanf_percentage_XX_s_malloc_2() {
  char* buf;
  buf = malloc(64);
  scanf("%64s", buf);
}

void vuln_scanf_percentage_XX_s_malloc_3() {
  char* buf;
  int i = 64;
  buf = malloc(i);
  scanf("%64s", buf);
}

void unkown_scanf_percentage_s_malloc_arg(int sz) {
  char* buf;
  buf = malloc(sz);
  scanf("%64s", buf);
}

// ====================
// Good fscanf usages
void good_fscanf_percentage_XX_s() {
  FILE* fp = fopen("test.txt", "r");

  char buf[64];
  fscanf(fp, "%63s", buf);
}

void good_fscanf_percentage_XX_s_with_other_formats() {
  FILE* fp = fopen("test.txt", "r");

  char buf[64];
  int i;
  fscanf(fp, "Test %d %63s", &i, buf);
}

void good_fscanf_percentage_XX_s_with_asterisk_modifier() {
  FILE* fp = fopen("test.txt", "r");

  char buf[64];
  fscanf(fp, "Test %*100s %63s", buf);
}

void good_fscanf_percentage_XX_s_malloc_1() {
  FILE* fp = fopen("test.txt", "r");

  char* buf = malloc(64);
  fscanf(fp, "%63s", buf);
}

void good_fscanf_percentage_XX_s_malloc_2() {
  FILE* fp = fopen("test.txt", "r");

  char* buf;
  buf = malloc(64);
  fscanf(fp, "%63s", buf);
}

void good_fscanf_percentage_XX_s_malloc_3() {
  FILE* fp = fopen("test.txt", "r");

  char* buf;
  int i = 64;
  buf = malloc(i);
  fscanf(fp, "%63s", buf);
}

// ====================
// Bad fscanf usages
void vuln_fscanf_percentage_s() {
  FILE* fp = fopen("test.txt", "r");

  char buf[100];
  // This may overflow `buf` if the file contains a string longer than 100 characters
  fscanf(fp, "%s", buf);
}

void vuln_fscanf_percentage_s_arg(FILE* fp, char* buf) {
  fscanf(fp, "%s", buf);
}

void vuln_fscanf_percentage_XX_s() {
  FILE* fp = fopen("test.txt", "r");

  char buf[64];
  // This may overflow `buf` by 1 `\x00` if the file contains a string with 64 characters
  fscanf(fp, "%64s", buf);
}

void vuln_fscanf_percentage_XX_s_malloc_1() {
  FILE* fp = fopen("test.txt", "r");

  char* buf = malloc(64);
  fscanf(fp, "%64s", buf);
}

void vuln_fscanf_percentage_XX_s_malloc_2() {
  FILE* fp = fopen("test.txt", "r");

  char* buf;
  buf = malloc(64);
  fscanf(fp, "%64s", buf);
}

void vuln_fscanf_percentage_XX_s_malloc_3() {
  FILE* fp = fopen("test.txt", "r");

  char* buf;
  int i = 64;
  buf = malloc(i);
  fscanf(fp, "%64s", buf);
}
// void vuln_sscanf_percentage_s() {
//   char input[100];
//   fgets(input, 100, stdin);

//   char buf[64];
//   // This may overflow `buf` if the user enters a string longer than 64 characters
//   sscanf(input, "%s", buf);
// }

// void good_sscanf_percentage_s() {
//   char input[100];
//   fgets(input, 100, stdin);

//   char buf[100];
//   // This is safe we know fgets will make input[99] `\x00` when we pass it the larger string we can
//   sscanf(input, "%s", buf);
// }

// void vuln_scanf_format_string() {
//   char input[100];
//   fgets(input, 100, stdin);

//   // A classic format string vulnerability (in this case with scanf)
//   scanf(input);
// }

int main() {
}
