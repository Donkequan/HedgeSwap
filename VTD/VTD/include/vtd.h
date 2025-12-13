

#ifndef __VTD__
#define __VTD__

#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>
#include "params.h"
#include "lhp.h"
#include "proof.h" 

#define VTD_THRESHOLD_NUM 1



void commit ( LHP_puzzle_t * puzzle_array_output, RP_wit_t * wit_array_output, RP_proof_t * proof_array, 
mpz_t * h_output, mpz_t * h_output_array,  RP_param_t rp_params, mpz_t wit, int value_t, unsigned char * seed, 
size_t seedlen, int value_n, LHP_puzzle_t * threshold_puzzle_array);

int verify ( RP_param_t rp_params, mpz_t h_output, mpz_t * h_output_array, LHP_puzzle_t * puzzle_array, RP_proof_t * proof_array, RP_wit_t * wit_array, mpz_t * h_array,  int value_I, int value_t, unsigned char * seed, size_t seedlen, int value_n );

void force_open ( LHP_puzzle_sol_t * sol,  LHP_puzzle_t * puzzle_array, RP_param_t rp_params, int value_t, int value_n );

void commit_aagregate (RP_param_t rp_params, LHP_puzzle_t ** threshold_puzzle_array, 
int index);
#endif
