#include <stdio.h>
#include <stdlib.h>

void ping_host(const char *host) {
    char command[256];
    if (host == NULL) {
        return;
    }
    snprintf(command, sizeof(command), "ping -c 1 %s", host);
    system(command);
}

