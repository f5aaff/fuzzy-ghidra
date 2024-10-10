#include <stdio.h>

int main() {
    unsigned int num = 5; // Start with a small positive number

    // Subtract a constant value that will cause an underflow
    num -= 10;

    // Check for underflow (this condition will always be true)
    if (num > 5) {
        printf("Integer underflow detected! num = %u\n", num);
    } else {
        printf("No underflow detected! num = %u\n", num);
    }

    return 0;
}

