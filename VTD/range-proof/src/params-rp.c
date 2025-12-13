

#include "gmp.h"

#include "params.h"
#include "params-rp.h"


void RP_init_param ( RP_param_t* param, uint64_t lambda, uint64_t L, uint64_t B ) 
{
	LHP_init_param ( &(param->pp) );
	LHP_PSetup ( &(param->pp) , lambda , 1000000 ) ;
	mpz_init ( param->N );
	mpz_set ( param->N, param->pp.N);
	mpz_init_set_ui ( param->L, L );
	mpz_init_set_ui ( param->B, B );
}

void RP_clear_param ( RP_param_t* param ) 
{
	
	LHP_clear_param ( &(param->pp) );
	mpz_clear ( param->N );
	mpz_clear ( param->L );
	mpz_clear ( param->B );
}

