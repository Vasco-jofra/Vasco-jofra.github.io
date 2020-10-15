#include <stdio.h>
#include <string.h>
#include <unistd.h>

void get_comm_name(char *buf, size_t buf_sz) {
    FILE *f = fopen("/proc/self/comm", "r");
    memset(buf, 0, buf_sz);
    fread(buf, buf_sz, 1, f);
    fclose(f);
}

void set_comm_name(char *buf, size_t buf_sz) {
    FILE *f = fopen("/proc/self/comm", "w");
    fwrite(buf, buf_sz, 1, f);
    fclose(f);
}

int main(int argc, char *argv[]) {
    if(argc != 3) {
        printf("I want 3 arguments");
        return -1;
    }

    memcpy(argv[0], "hidden_prog", strlen(argv[0]));
    memcpy(argv[1], "xxxxxxxxxxxxxxxx", strlen(argv[1]));
    memcpy(argv[2], "yyyyyyyyyyyyyyyy", strlen(argv[2]));

    char buf[64];
    get_comm_name(buf, sizeof(buf));
    printf("old_comm = %s", buf);

    set_comm_name("hidden_prog", 11);

    get_comm_name(buf, sizeof(buf));
    printf("new_comm = %s", buf);

    sleep(1000);


    return 0;
}