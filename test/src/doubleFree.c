#include <stdlib.h>
#include <stdio.h>

int main() {
    char *buffer = (char*)malloc(10);
    if (buffer == NULL) return 1;

    printf("Enter some text: ");
    fgets(buffer, 10, stdin);

    free(buffer);  // First free
    free(buffer);  // Double free - should crash

    return 0;
}

