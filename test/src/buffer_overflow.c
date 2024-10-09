#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void vulnerable_function(char *input) {
    char buffer[64];
    if (strlen(input) > 64) {
        printf("Buffer overflow detected!\n");
        return;
    }
    strcpy(buffer, input); // Vulnerable to buffer overflow
    printf("You entered: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }
    vulnerable_function(argv[1]);
    return 0;
}

