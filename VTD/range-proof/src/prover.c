
 
 #include "gmp.h"
 #include "proof.h"
 #include "prover.h"
 #include "params-rp.h"
 
 

 void RP_prover_seeded ( RP_proof_t * proof_array, RP_param_t rp_params, unsigned char* seed, size_t seedlen, LHP_puzzle_t * puzzle_array, RP_wit_t * wit_array, int value_l, int value_n ) 
 {
	 
	//Preparation data structures
	mpz_t * y_array = malloc ( sizeof ( mpz_t ) * value_n ) ;
	mpz_t * r_prime_array = malloc ( sizeof ( mpz_t ) * value_n ) ;
	mpz_t * t_arrays [value_n]; 
	
	//Setup the seed randomness in a gmp state variable
	mpz_t seed_mpz ;
	mpz_init ( seed_mpz ) ;
	mpz_import ( seed_mpz , seedlen , 1 , 1 , 0 , 0 , seed ) ;
	gmp_randstate_t state;
	gmp_randinit_default ( state ) ;
	gmp_randseed ( state , seed_mpz ) ;
	
	//First bullet point
	for ( int i = 0; i < value_n; i++ ) 
	{
		mpz_init ( y_array[i] ) ;
		mpz_urandomm ( y_array[i], state , rp_params.L ) ; //FIXME: put the correct bound here
		mpz_init ( r_prime_array[i] ) ;
		mpz_urandomm ( r_prime_array[i], state , rp_params.N ) ; //FIXME: put the correct bound here
	}
	
	
	//Second bullet point
	unsigned char * str_y;
	unsigned char * str_r_prime;
	size_t count_y;
	size_t count_r_prime;
	
	for ( int i = 0; i < value_n; i++ ) 
	{
		mpz_export ( NULL, &count_y, 1, 1, 0, 0, y_array[i] );
		mpz_export ( NULL, &count_r_prime, 1, 1, 0, 0, r_prime_array[i] );
		str_y = malloc ( count_y );
		str_r_prime = malloc ( count_r_prime );
		mpz_export ( str_y, &count_y, 1, 1, 0, 0, y_array[i] );
		mpz_export ( str_r_prime, &count_r_prime, 1, 1, 0, 0, r_prime_array[i] );
		LHP_PGen_seeded ( &((proof_array + i)->puzzle) , &(rp_params.pp), str_y, count_y, str_r_prime, count_r_prime ) ;
		free ( str_y );
		free ( str_r_prime );
	}

	
	//Third bullet point
	mpz_t bound_t; 
	mpz_init_set_ui ( bound_t, 2 );
	for ( int i = 0; i < value_n; i++ ) 
	{
		t_arrays[i] = malloc ( sizeof ( mpz_t ) * value_l ) ;
		
		for ( int j = 0; j < value_l; j++ ) 
		{
			mpz_init ( t_arrays[i][j] );
			mpz_urandomm ( t_arrays[i][j], state, bound_t );
		}
	}
	
	
	//Fourth bullet point
	mpz_t acc_t_x;
	mpz_t acc_t_r;
	mpz_t temp;
	mpz_init ( temp );
	
	
	for ( int i = 0; i < value_n; i++ )
	{
		mpz_init_set_ui ( acc_t_x, 0 );
		mpz_init_set_ui ( acc_t_r, 0 );
		
		for ( int j = 0; j < value_l; j++ ) 
		{
			
			mpz_mul ( temp, t_arrays[i][j],  wit_array[j].x ) ;
			mpz_add ( acc_t_x, acc_t_x, temp );
			mpz_mul ( temp, t_arrays[i][j],  wit_array[j].r ) ;
			mpz_add ( acc_t_r, acc_t_r, temp ) ;
		}
		
		mpz_add ( proof_array[i].v, y_array[i], acc_t_x ) ;
		mpz_add ( proof_array[i].w, r_prime_array[i], acc_t_r) ;
	}
	
	free ( y_array );
	free ( r_prime_array );
	for ( int i = 0; i < value_n; i++ ) {
		free ( t_arrays[i] );
	}
 }

/*
void RP_prover_two ( RP_proof_t * proof_array, RP_param_t rp_params, unsigned char* seed_randomness, size_t seed_randomenss_len, unsigned char* seed_r_prime, size_t seed_r_prime_len, LHP_puzzle_t * puzzle_array, RP_wit_t * wit_array, size_t value_l ) 
{
	
	//Preparation data structures
	mpz_t * y_array = malloc ( sizeof ( mpz_t ) * value_n ) ;
	mpz_t * r_prime_array = malloc ( sizeof ( mpz_t ) * value_n ) ;
	mpz_t * t_arrays [value_n]; 
	
	//Setup the seed randomness in a gmp state variable
	mpz_t seed_mpz ;
	mpz_init ( seed_mpz ) ;
	mpz_import ( seed_mpz , seed_randomness_len , 1 , 1 , 0 , 0 , seed_randomness ) ;
	gmp_randstate_t state;
	gmp_randinit_default ( state ) ;
	gmp_randseed ( state , seed_mpz ) ;
	
	//First bullet point
	for ( int i = 0; i < value_n; i++ ) {
		mpz_init_set_ui ( y_array[i], 0 ) ;
		mpz_urandomm ( y_array[i], state , (rp_params.L)/4 ) ; //FIXME: put the correct bound here
		mpz_init_set_ui ( r_prime_array[i], 0 ) ;
		mpz_urandomm ( r_prime_array[i], state , rp_params.N ) ; //FIXME: put the correct bound here
	}
	
	unsigned char * str_y;
	size_t str_y
}
* */
