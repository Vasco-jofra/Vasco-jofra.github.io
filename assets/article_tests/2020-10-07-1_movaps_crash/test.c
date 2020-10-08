#include <stdio.h>
#include <stdlib.h>

int put_system_in_got() {
    system("/bin/ls");
}

int main() {
    printf("'main' leak @ %p\n", main);
    char buf[256];
    printf("buf:");
    scanf("%512s", buf);
}