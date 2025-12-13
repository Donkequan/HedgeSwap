

#include "params.h"
#include "params-rp.h"
#include "util.h"
#include "proof.h"
#include "vtd.h"

//setup parameters
#define VALUE_L 20
#define VALUE_B 10
#define SECRET_KEY 1234
#define VALUE_T 32
#define VALUE_I 32
#define VALUE_N 64

char *seed = "00000000000000000000"
	"00000000000000000000000000000"
	"00000000000000000000000000000"
	"0000000000000000000000" ;
int seedlen = 100 ;

//global variables
RP_param_t rp_params;
LHP_puzzle_t * puzzle_array_output;
RP_proof_t * proof_array_output;
RP_wit_t * wit_array_output;
mpz_t wit_x;
mpz_t h_output;
mpz_t * h_output_array; 
LHP_puzzle_sol_t sol;
LHP_puzzle_t ** threshold_puzzle_array ;

/* Timing Statistics */
struct timeval start , end ;

static void INIT ()
{
	gettimeofday ( &start , NULL ) ;
	RP_init_param ( &rp_params, VALUE_N, VALUE_L, VALUE_B) ;
	
	puzzle_array_output = malloc ( sizeof ( LHP_puzzle_t ) * VALUE_N ) ;
	wit_array_output = malloc ( sizeof ( RP_wit_t ) * VALUE_N ) ;
	proof_array_output = malloc ( sizeof ( RP_proof_t ) * VALUE_N ) ;
	h_output_array = malloc ( sizeof ( mpz_t ) * VALUE_N );
	
	for ( int i = 0; i < VALUE_N; i++ )
	{
		LHP_init_puzzle ( puzzle_array_output + i );
		RP_init_wit ( wit_array_output + i );
		RP_init_proof ( proof_array_output + i );
		mpz_init ( h_output_array[i] );
		
	}

	threshold_puzzle_array = malloc(VTD_THRESHOLD_NUM * sizeof(LHP_puzzle_t *));
	for (int i = 0; i < VTD_THRESHOLD_NUM; i++) {
        	threshold_puzzle_array[i] = malloc(VALUE_N * sizeof(LHP_puzzle_t)); 
			for (int j = 0; j < VALUE_N; j++) {
		    	LHP_init_puzzle(*(threshold_puzzle_array + i) + j); 
			}
    }
	
	mpz_init_set_ui ( wit_x, SECRET_KEY );
	
	mpz_init ( sol.s );
	
	gettimeofday ( &end , NULL ) ; // End of experiment
	print_exp_info ( &start , &end , "Init" ) ; // Print Info
	
	SUCCESS ( "Init" ) ;
}

static void COMMIT ()
{
	gettimeofday ( &start , NULL ) ;
	for (int i=0; i<VTD_THRESHOLD_NUM; i++){
		commit ( puzzle_array_output, wit_array_output, proof_array_output, 
		&h_output, h_output_array, rp_params, wit_x, VALUE_T, seed, seedlen, VALUE_N ,
		*(threshold_puzzle_array + i));
	}
	gettimeofday ( &end , NULL ) ; // End of experiment
	print_exp_info ( &start , &end , "TCommit" ) ; // Print Info
	SUCCESS ( "TCommit" ) ;
}

static void VERIFY ()
{ 
	gettimeofday ( &start , NULL ) ;
	int res = 0;
	res = verify ( rp_params, h_output, h_output_array, puzzle_array_output, proof_array_output, 
		wit_array_output, h_output_array,  VALUE_I , VALUE_T, seed, seedlen, VALUE_N );
	gettimeofday ( &end , NULL ) ; // End of experiment
	print_exp_info ( &start , &end , "Verfiy" ) ; // Print Info
	
	if ( res == 0 )
	{
		FAILED ( "Verify" );
	}
	else
	{
		SUCCESS ( "Verify" );
	}
}

static void FORCE_OPEN ()
{
	force_open ( &sol, puzzle_array_output , rp_params, VALUE_T, VALUE_N );
	
	SUCCESS ( "Force Open" );
}

static void CLEAN ()
{
	RP_clear_param ( &rp_params );
	
	for ( int i = 0; i < VALUE_N; i++ )
	{
		LHP_clear_puzzle ( puzzle_array_output + i );
		RP_clear_proof ( proof_array_output + i );
		RP_clear_wit ( wit_array_output + i );
	}
	SUCCESS ( "Clean" ) ;
}


int main ( int argc , char* argv[] )
{
	
	INIT ();
	COMMIT ();
	VERIFY ();
	FORCE_OPEN ();
	CLEAN ();
	
	return 0 ;
}
