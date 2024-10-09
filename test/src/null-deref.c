#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void vulnerable_function(char *input) {
    char *null_ptr = NULL;

    if (strlen(input) >= 2 && input[1] == 0x41) {
        printf("Second byte is 0x41, triggering null dereference!\n");
        *null_ptr = 'x';
    } else {
        printf("Input does not trigger null dereference.\n");
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        return 1;
    }
    vulnerable_function(argv[1]);
    return 0;
}

