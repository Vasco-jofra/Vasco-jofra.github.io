#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if(argc != 3) {
        printf("I want 3 arguments");
        return -1;
    }

    memcpy(argv[0], "hidden_prog", strlen(argv[0]));
    memcpy(argv[1], "xxxxxxxxxxxxxxxx", strlen(argv[1]));
    memcpy(argv[2], "yyyyyyyyyyyyyyyy", strlen(argv[2]));

    sleep(1000);
    return 0;
}