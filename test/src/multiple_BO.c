#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define BUFFER_SIZE 10

void vulnerable_function1(char *input) {
    char buffer[BUFFER_SIZE];
    // Vulnerable: No bounds checking, directly copying input to buffer
    strcpy(buffer, input);
    printf("You entered: %s\n", buffer);
    exit(0);
}

void vulnerable_function2(char *input) {
    char buffer[BUFFER_SIZE];
    // Vulnerable: No bounds checking, directly concatenating input to buffer
    strcat(buffer, input);  // strcat will cause an overflow if input is large enough
    printf("Concatenated string: %s\n", buffer);
    exit(0);
}

void vulnerable_function3() {
    char buffer[BUFFER_SIZE];
    // Vulnerable: Reading input without ensuring it fits in the buffer
    printf("Enter input (vulnerable): ");
    fgets(buffer, sizeof(buffer) + 100, stdin);  // Incorrect size passed to fgets
    printf("You entered: %s\n", buffer);
    exit(0);
}

void vulnerable_function4(char *input) {
    char buffer[BUFFER_SIZE];
    // Vulnerable: sprintf with no bounds checking
    sprintf(buffer, "User input: %s", input);
    printf("%s\n", buffer);
    exit(0);
}

void menu() {
    printf("Choose a function to call:\n");
    printf("1. vulnerable_function1 (strcpy)\n");
    printf("2. vulnerable_function2 (strcat)\n");
    printf("3. vulnerable_function3 (fgets)\n");
    printf("4. vulnerable_function4 (sprintf)\n");
    printf("5. Exit\n");
}

int main() {
    char input[128];
    int choice = 0;

    while (1) {
        menu();
        printf("Enter your choice: ");
        fgets(input, sizeof(input), stdin);  // Read user choice
        choice = atoi(input);

        if (choice == 5) {
            printf("Exiting...\n");
            break;
        }

        printf("Enter your input string: ");
        fgets(input, sizeof(input), stdin);  // Read input for vulnerable functions
        input[strcspn(input, "\n")] = '\0';  // Remove newline

        // Call the selected vulnerable function
        switch (choice) {
            case 1:
                vulnerable_function1(input);
                break;
            case 2:
                vulnerable_function2(input);
                break;
            case 3:
                vulnerable_function3();
                break;
            case 4:
                vulnerable_function4(input);
                break;
            default:
                printf("Invalid choice.\n");
        }
    }

    return 0;
}
