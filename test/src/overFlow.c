#include <stdio.h>
#include <limits.h>

int main() {
    unsigned int num = UINT_MAX -1;
    unsigned int in;
    printf("Enter a number: ");
    scanf("%u", &in);
    unsigned int overflow = num + in;
    // Unsigned integer overflow vulnerability
    if (overflow < UINT_MAX -1) {
        printf("Integer overflow detected!\n");
    } else {
        printf("Number is safe: %u\n", in);
    }

    return 0;
}

