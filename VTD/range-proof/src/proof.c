

#include "proof.h"

void RP_init_proof ( RP_proof_t* proof ) 
{
	
	LHP_init_puzzle ( &(proof->puzzle) );
	mpz_init ( proof->v );
	mpz_init ( proof->w );
	
}

void RP_clear_proof ( RP_proof_t* proof ) 
{
	
	LHP_clear_puzzle ( &(proof->puzzle) );
	mpz_clear ( proof->v );
	mpz_clear ( proof->w );
	
}


void RP_init_wit ( RP_wit_t* wit ) 
{
	
	mpz_init ( wit->x );
	mpz_init ( wit->r );
	
}

void RP_clear_wit ( RP_wit_t* wit ) 
{
	
	mpz_clear ( wit->x );
	mpz_clear ( wit->r );
	
}
