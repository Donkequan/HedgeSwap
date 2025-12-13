#include <stdio.h>
#include <string.h>
#include "schnorr.h"

void ecdsa_test(void);

int main(int argc, char* argv[]) {
    int run_schnorr = 1;
    int run_ecdsa = 1;

    if (argc > 1) {
        run_schnorr = 0;
        run_ecdsa = 0;
        for (int i = 1; i < argc; ++i) {
            if (strcmp(argv[i], "schnorr") == 0) {
                run_schnorr = 1;
            }
            else if (strcmp(argv[i], "ecdsa") == 0) {
                run_ecdsa = 1;
            }
            else if (strcmp(argv[i], "all") == 0) {
                run_schnorr = 1;
                run_ecdsa = 1;
            }
            else {
                fprintf(stderr, "Unknown option '%s'. Use schnorr, ecdsa, or all.\n", argv[i]);
                return 1;
            }
        }
    }

    if (run_schnorr) {
        printf("                  SIG_AS Experiment for Schnorr:\n");
        schnorr_test();
    }

    if (run_schnorr && run_ecdsa) {
        printf("\n");
        printf("*****************************************************************\n");
        printf("\n");
    }

    if (run_ecdsa) {
        printf("                  SIG_AS Experiment for ECDSA:\n");
        ecdsa_test();
    }

    return 0;
}