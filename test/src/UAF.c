#include <stdlib.h>
#include <stdio.h>

int main()
{
    char *buffer = (char*)malloc(10);
    if (buffer == NULL) return 1;

    printf("enter some text: ");
    fgets(buffer, 10, stdin);

    free(buffer);

    printf("entered stuff: %s\n",buffer);

    return 0;
}
