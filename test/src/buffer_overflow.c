#include <stdio.h>

int main() {
    char buffer[10]; // Buffer with a fixed size of 10 characters

    printf("Enter some text: ");
    //scanf("%s",buffer); // Vulnerable to buffer overflow as there's no size check
    fgets(buffer,sizeof(buffer), stdin);
    printf("You entered: %s\n", buffer);

    return 0;
}
