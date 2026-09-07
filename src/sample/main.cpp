#include <stdio.h>

void printHi() {
    for (int i = 0; i < 10; i++) {
        printf("Hi!\n");
    }
}

void printBye() {
    for (int i = 0; i < 10; i++) {
        printf("Bye!\n");
    }
}

int main() {
    printHi();
    printBye();
}