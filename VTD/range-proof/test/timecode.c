

#include "params.h"
#include "params-rp.h"
#include "util.h"
#include "proof.h"
#include "prover.h"
#include "config.h"



#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <gmp.h>

#include "lhp.h"
#include "util.h"

#define VALUE_L 100
#define VALUE_B 50
#define VALUE_l 20
#define VALUE_N 256
#define SEC_PARAM 256

// Experimental Parameters
char* str = "111111111111111111111"
	"11111111111111111111111111111"
	"11111111111111111111111111111"
	"111111111111111111111" ;
int len = 100 ;
char *seed = "00000000000000000000"
	"00000000000000000000000000000"
	"00000000000000000000000000000"
	"0000000000000000000000" ;
int seedlen = 100 ;

 char* seed_y = "111111111111111111111"
	"11111111111111111111111111111"
	"11111111111111111111111111111"
	"111111111111111111111" ;
int seed_y_len = 100 ;
char *seed_r_prime = "00000000000000000000"
	"00000000000000000000000000000"
	"00000000000000000000000000000"
	"0000000000000000000000" ;
int seed_r_prime_len = 100 ;


/* Some variables to declare */
LHP_puzzle_t *puzzle_array;
RP_param_t rp_params;
uint64_t L = VALUE_L;
uint64_t B = VALUE_B;
RP_proof_t *proof_array;
RP_wit_t *wit_array;

int RP_verifier ( RP_proof_t * proof_array, LHP_puzzle_t * puzzle_array, size_t value_l, RP_param_t rp_params, unsigned char * seed, size_t seedlen, size_t value_n );

static void SETUP ()
{
	RP_init_param ( &rp_params, SEC_PARAM, L, B );
	
	SUCCESS ( "Setup" ) ;
}

static void INIT ()
{
	puzzle_array = malloc ( sizeof ( LHP_puzzle_t ) * VALUE_l ) ;
	wit_array = malloc ( sizeof ( RP_wit_t ) * VALUE_l ) ;
	proof_array = malloc ( sizeof ( RP_proof_t ) * SEC_PARAM ) ;
	
	
	for ( int i = 0 ; i < SEC_PARAM; i++ ) 
	{
		RP_init_proof ( proof_array + i ) ;
	}
	
	for ( int i = 0 ; i < VALUE_l ; i ++ ) 
	{	
		RP_init_wit ( wit_array + i ) ;
		LHP_init_puzzle ( puzzle_array + i ) ;
		LHP_PGen_seeded ( puzzle_array + i, &(rp_params.pp), str, len, seed, seedlen ) ;
		
		
		mpz_init_set_ui ( wit_array[i].x , 0 ) ;
		for( int j = 0 ; j < len ; j++ ) {
			mpz_mul_ui ( wit_array[i].x , wit_array[i].x , 1 << 8 ) ;
			mpz_add_ui ( wit_array[i].x , wit_array[i].x , (uint8_t)str[j] ) ;
		}
		
		mpz_init_set_ui ( wit_array[i].r , 0 ) ;
		for( int j = 0 ; j < seedlen ; j++ ) {
			mpz_mul_ui ( wit_array[i].r , wit_array[i].r , 1 << 8 ) ;
			mpz_add_ui ( wit_array[i].r , wit_array[i].r , (uint8_t)seed[j] ) ;
		}

	}
	
	
	SUCCESS ( "RP Init" ) ;
}


static void PROVER_LIB ()
{

	RP_prover_seeded ( proof_array, rp_params, seed, seedlen,  puzzle_array, wit_array, VALUE_l, VALUE_N );
	SUCCESS ( "Prover library" ) ;
}


static void VERIFIER_LIB () 
{
	
	if ( RP_verifier ( proof_array, puzzle_array, VALUE_l, rp_params, seed, seedlen, VALUE_N ) )
	{
		SUCCESS ( "Verify Lib" ) ;
	}
	else
	{
		FAILED ( "Verify Lib" ) ;
	}
}



static void TEST_STRING_MPZ () 
{
	mpz_t s ;
	mpz_init_set_ui ( s , 0 ) ;
	for(int i = 0 ; i < len ; i++) {
		mpz_mul_ui ( s , s , 1 << 8 ) ;
		mpz_add_ui ( s , s , (uint8_t)str[i] ) ;
	}

	
	unsigned char * str_back ;
	size_t count_p;
	
	printf ("setup done \n");
	mpz_export ( NULL, &count_p, 1, 1, 0, 0, s );
	str_back = malloc ( count_p ) ;
	mpz_export ( str_back, &count_p, 1, 1, 0, 0, s );
	printf ("one done \n");
	
	for ( int i = 0; i < count_p; i++ ) {
		if ( str_back[0] == str[i] ) {
			printf ( " position %d ok \n", i );
		}
	}
	
	printf ( "str_back: %s\n \t of length %d \n", (unsigned char *)str_back, count_p );

}

static void CLEAN ()
{
	RP_clear_param ( &rp_params );
	for ( int i = 0; i < VALUE_l; i++ ) {
		LHP_clear_puzzle ( puzzle_array + i );
		RP_clear_wit ( wit_array + i );
		RP_clear_proof ( proof_array + i );
	}
	free ( puzzle_array );
	free ( wit_array );
	free ( proof_array );
	SUCCESS ( "Clean" ) ;
}

int main ( int argc , char* argv[] )
{
	SETUP ();
	INIT ();
	PROVER_LIB ();
	VERIFIER_LIB ();
	CLEAN ();
	return 0 ;
}
