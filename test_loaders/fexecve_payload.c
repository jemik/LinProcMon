/*
 * Simple payload that gets loaded via fexecve
 * Prints identifying messages and sleeps to allow memory dumping
 */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int main(int argc, char** argv) {
    printf("\n");
    printf("============================================\n");
    printf(" PAYLOAD EXECUTED VIA FEXECVE\n");
    printf("============================================\n");
    printf("[PAYLOAD] PID: %d\n", getpid());
    printf("[PAYLOAD] This process was loaded from memfd\n");
    printf("[PAYLOAD] Comm should show 'memfd:...'\n");
    printf("[PAYLOAD] Sleeping for 3 seconds to allow dumping...\n");
    printf("============================================\n");
    fflush(stdout);
    
    sleep(3);
    
    printf("[PAYLOAD] Sleep complete, exiting with code 42\n");
    return 42;
}
