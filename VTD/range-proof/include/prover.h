

#ifndef __RP_PROVER__
#define __RP_PROVER__

#include "proof.h"
#include "params-rp.h"

void RP_prover_seeded ( RP_proof_t * proof_array, RP_param_t rp_params, unsigned char* seed, size_t seedlen, LHP_puzzle_t * puzzle_array, RP_wit_t * wit_array, int value_l, int value_n ) ;

#endif
