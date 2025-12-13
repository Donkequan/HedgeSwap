

#ifndef __RP_PARAM__
#define __RP_PARAM__

#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>
#include "params.h"
#include "lhp.h"
#include "proof.h" 

typedef struct RP_param_t {
	
	LHP_param_t pp;
	mpz_t N;
	mpz_t L;
	mpz_t B;
	
} RP_param_t;


void RP_init_param ( RP_param_t* params, uint64_t lambda, uint64_t L, uint64_t B) ;

void RP_clear_param ( RP_param_t* params) ;

#endif
