

#ifndef __RP_PROVER__
#define __RP_PROVER__

#include "proof.h"
#include "params-rp.h"

int RP_verifier ( RP_proof_t * proof_array, LHP_puzzle_t * puzzle_array, size_t value_l, RP_param_t rp_params, unsigned char * seed, size_t seedlen, int value_n ) ;

#endif
