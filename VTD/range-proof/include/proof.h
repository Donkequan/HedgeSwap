

#ifndef __RP_PROOF__
#define __RP_PROOF__

#include "lhp.h"

typedef struct RP_proof_t {
	LHP_puzzle_t puzzle;
	mpz_t v;
	mpz_t w;
} RP_proof_t ;

typedef struct RP_wit_t {
	mpz_t x;
	mpz_t r; } RP_wit_t;

void RP_init_proof ( RP_proof_t* proof ) ;

void RP_clear_proof ( RP_proof_t* proof ) ;

void RP_init_wit ( RP_wit_t* wit ) ;

void RP_clear_wit ( RP_wit_t* wit ) ;

#endif
