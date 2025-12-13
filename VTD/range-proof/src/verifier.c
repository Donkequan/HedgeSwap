
 
 #include "gmp.h"
 #include "proof.h"
 #include "prover.h"
 #include "params-rp.h"
 
 int RP_verifier ( RP_proof_t * proof_array, LHP_puzzle_t * puzzle_array, size_t value_l, RP_param_t rp_params, unsigned char * seed, size_t seedlen, int value_n ) {
	 
	 //Preparation data structures
	mpz_t * t_arrays [value_n]; 
	int verification_flag = 1;
	
	//Setup the seed randomness in a gmp state variable
	mpz_t seed_mpz ;
	mpz_init ( seed_mpz ) ;
	mpz_import ( seed_mpz , seedlen , 1 , 1 , 0 , 0 , seed ) ;
	gmp_randstate_t state;
	gmp_randinit_default ( state ) ;
	gmp_randseed ( state , seed_mpz ) ;
	
	//First bullet point
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
	
	
	//Second bullet point
	//FIXME: Missing check that v_i is in the range
	mpz_t tmp_u;
	mpz_t tmp_v;
	mpz_t acc_u;
	mpz_t acc_v;
	
	unsigned char * str_v;
	size_t count_v;
	unsigned char * str_w;
	size_t count_w;
	
	LHP_puzzle_t * puzzle_f_array = malloc ( sizeof ( LHP_puzzle_t ) * value_n ) ;
	LHP_puzzle_t * puzzle_f_comp_array = malloc ( sizeof ( LHP_puzzle_t ) * value_n ) ;
	
	for ( int i = 0; i < value_n; i++ )
	{
		mpz_init_set_ui ( tmp_u, 1 );
		mpz_init_set_ui ( tmp_v, 1 );
		mpz_init_set_ui ( acc_u, 1 );
		mpz_init_set_ui ( acc_v, 1 );
		LHP_init_puzzle ( puzzle_f_array + i );
		LHP_init_puzzle ( puzzle_f_comp_array + i );
		 
		for ( int j = 0; j < value_l; j++ )
		{
			mpz_powm ( tmp_u , puzzle_array[j].u , t_arrays[i][j] , rp_params.pp.N ) ;
			mpz_powm ( tmp_v , puzzle_array[j].v , t_arrays[i][j] , rp_params.pp.N ) ;
			mpz_mul ( acc_u, acc_u, tmp_u );
			mpz_mul ( acc_v, acc_v, tmp_v );
		}
		
		mpz_mul ( puzzle_f_array[i].u, proof_array[i].puzzle.u, acc_u );
		mpz_mul ( puzzle_f_array[i].v, proof_array[i].puzzle.v, acc_v );
	
		
		mpz_export ( NULL, &count_v, 1, 1, 0, 0, proof_array[i].v );
		str_v = malloc ( count_v ) ;
		mpz_export ( NULL, &count_w, 1, 1, 0, 0, proof_array[i].w );
		str_w = malloc ( count_w ) ;
		mpz_export ( str_v, &count_v, 1, 1, 0, 0, proof_array[i].v );
		mpz_export ( str_w, &count_w, 1, 1, 0, 0, proof_array[i].w );
		
	
		LHP_PGen_seeded (  puzzle_f_comp_array + i, &(rp_params.pp), str_v, count_v, str_w, count_w ) ; 
		
		free ( str_v );
		free ( str_w );
			
		
		if ( LHP_puzzle_cmp ( puzzle_f_array + i , puzzle_f_comp_array + i ) == 0 ) 
		{
			verification_flag = 0;
		}
	}
	
	
	
	for ( int i=0; i < value_n; i++ ) 
	{
		free ( t_arrays[i] );
	}
	free ( puzzle_f_array );
	free (puzzle_f_comp_array );
	
	return verification_flag;
	
 }
