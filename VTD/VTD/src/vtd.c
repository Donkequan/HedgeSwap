#include "params.h"
#include "params-rp.h"
#include "util.h"
#include "puzzle.h"
#include "proof.h"
#include "prover.h"
#include "lhp.h" 
#include "verifier.h"
#include "vtd.h"

int RP_verifier ( RP_proof_t * proof_array, LHP_puzzle_t * puzzle_array, size_t value_l, RP_param_t rp_params, unsigned char * seed, size_t seedlen, int value_n ) ;

// Compute Lagrange coefficient for the subset {x_subset[0], ..., x_subset[k-1]}
static void lagrange_coefficient(mpz_t result, const int x_subset[], int k, int point_idx, const mpz_t mod) {
	mpz_t prod, diff, inv_diff, term;
	mpz_inits(prod, diff, inv_diff, term, NULL);
	mpz_set_ui(prod, 1);

	const int xi = x_subset[point_idx];

	for (int j = 0; j < k; ++j) {
		if (j == point_idx) {
			continue;
		}

		const int xj = x_subset[j];
		mpz_set_si(diff, xj - xi);
		mpz_mod(diff, diff, mod);

		if (mpz_cmp_ui(diff, 0) == 0 || mpz_invert(inv_diff, diff, mod) == 0) {
			mpz_set_ui(prod, 0);
			break;
		}

		mpz_set_si(term, xj);
		mpz_mul(term, term, inv_diff);
		mpz_mod(term, term, mod);
		mpz_mul(prod, prod, term);
		mpz_mod(prod, prod, mod);
	}

	mpz_set(result, prod);
	mpz_clears(prod, diff, inv_diff, term, NULL);
}

// Generate random shares
void share_random(mpz_t shares[], int x_values[], int n, int k, const mpz_t mod, gmp_randstate_t state) {
    for (int i = 0; i < n; i++) {
        x_values[i] = i + 1;
        if (i < k - 1) {
            mpz_urandomm(shares[i], state, mod);
        } else {
            mpz_set_ui(shares[i], 0);
        }
    }
}

// Compute final share
void cal_finalx(mpz_t secret, int x_values[], mpz_t shares[], int final_i, int k, const mpz_t mod) {
	mpz_t sum, result_i, lag_coff_i, final_share;
	mpz_inits(sum, result_i, lag_coff_i, final_share, NULL);
    mpz_set_ui(sum, 0);

	int x_subset[k];
	for (int j = 0; j < k - 1; ++j) {
		x_subset[j] = x_values[j];
	}
	x_subset[k - 1] = final_i;

    // Compute sum
    for (int i = 0; i < k - 1; i++) {
		lagrange_coefficient(lag_coff_i, x_subset, k, i, mod);
        mpz_mul(result_i, shares[i], lag_coff_i);
        mpz_mod(result_i, result_i, mod);
        mpz_add(sum, sum, result_i);
        mpz_mod(sum, sum, mod);
    }

    // Compute final Lagrange coefficient
	lagrange_coefficient(lag_coff_i, x_subset, k, k - 1, mod);
    mpz_sub(final_share, secret, sum);
    mpz_mod(final_share, final_share, mod);

    if (mpz_sgn(final_share) < 0) {
        mpz_add(final_share, final_share, mod);
    }

    mpz_invert(lag_coff_i, lag_coff_i, mod);
    mpz_mul(final_share, final_share, lag_coff_i);
    mpz_mod(final_share, final_share, mod);

    // Update final share
	mpz_set(shares[final_i - 1], final_share);

    mpz_clears(sum, result_i, lag_coff_i, final_share, NULL);
}

// Reconstruct the secret using Lagrange interpolation
void reconstruct_secret(mpz_t result, int x_samples[], mpz_t y_samples[], int k, int final_i, const mpz_t mod) {
	mpz_t term, lag_coff;
	mpz_inits(term, lag_coff, NULL);
    mpz_set_ui(result, 0);

	int x_subset[k];
	for (int j = 0; j < k - 1; ++j) {
		x_subset[j] = x_samples[j];
	}
	x_subset[k - 1] = final_i;

	for (int i = 0; i < k - 1; ++i) {
		lagrange_coefficient(lag_coff, x_subset, k, i, mod);
		mpz_mul(term, y_samples[i], lag_coff);
        mpz_mod(term, term, mod);
        if (mpz_sgn(term) < 0) {
            mpz_add(term, term, mod);
        }
        mpz_add(result, result, term);
        mpz_mod(result, result, mod);
    }

	lagrange_coefficient(lag_coff, x_subset, k, k - 1, mod);
	mpz_mul(term, y_samples[final_i - 1], lag_coff);
	mpz_mod(term, term, mod);
	if (mpz_sgn(term) < 0) {
		mpz_add(term, term, mod);
	}
	mpz_add(result, result, term);
	mpz_mod(result, result, mod);

    if (mpz_sgn(result) < 0) {
        mpz_add(result, result, mod);
    }

    mpz_clears(term, lag_coff, NULL);
}

void commit ( LHP_puzzle_t * puzzle_array_output, RP_wit_t * wit_array_output, RP_proof_t * proof_array, 
mpz_t * h_output, mpz_t * h_output_array,  RP_param_t rp_params, mpz_t wit, int value_t, unsigned char * seed, 
size_t seedlen, int value_n , LHP_puzzle_t * threshold_puzzle_array) {
	
	//Setup the seed randomness in a gmp state variable
	mpz_t seed_mpz ;
	mpz_init ( seed_mpz ) ;
	mpz_import ( seed_mpz , seedlen , 1 , 1 , 0 , 0 , seed ) ;
	gmp_randstate_t state;
	gmp_randinit_default ( state ) ;
	gmp_randseed ( state , seed_mpz ) ;
	
	
	//First bullet point
	mpz_powm ( *h_output , rp_params.pp.g , wit , rp_params.pp.N ) ;
	
	//Second bullet point
	mpz_t * x_array;
	int x_values[value_n];
	x_array = malloc ( sizeof ( mpz_t ) * value_n ) ;

	for (int i = 0; i < value_n; i++) 
	{
	        mpz_init(x_array[i]);
	}
	share_random(x_array, x_values, value_n, value_t, rp_params.pp.N, state);

	for ( int i = 0 ; i < value_t-1; i++ ) 
	{
		mpz_powm ( h_output_array[i] , rp_params.pp.g ,  x_array[i] , rp_params.pp.N ) ;
	}
	
	//Third bullet point
	for (int final_i = value_t; final_i <= value_n; final_i++) 
	{
        	cal_finalx(wit, x_values, x_array, final_i, value_t, rp_params.pp.N);
        	cal_finalx(*h_output, x_values, h_output_array, final_i, value_t, rp_params.pp.N);
    	}
    	
	
	//Fourth bullet point
	mpz_t * r_array;
	r_array = malloc ( sizeof ( mpz_t ) * value_n ) ;
	unsigned char * str_x;
	unsigned char * str_r;
	size_t count_r;
	size_t count_x;
	
	for ( int i = 0; i < value_n; i++ ) 
	{
		mpz_init ( r_array[i] );
		mpz_urandomm ( r_array[i], state , rp_params.pp.N ) ; //fixme: put the proper bound
		
		mpz_init_set_ui ( wit_array_output[i].x, 0 );
		mpz_add ( wit_array_output[i].x, wit_array_output[i].x, x_array[i] );
		mpz_init_set_ui ( wit_array_output[i].r, 0 );
		mpz_add ( wit_array_output[i].r, wit_array_output[i].r, r_array[i] );
		
		mpz_export ( NULL, &count_x, 1, 1, 0, 0, x_array[i] );
		mpz_export ( NULL, &count_r, 1, 1, 0, 0, r_array[i] );
		str_x = malloc ( count_x );
		str_r = malloc ( count_r );
		mpz_export ( str_x, &count_x, 1, 1, 0, 0, x_array[i] );
		mpz_export ( str_r, &count_r, 1, 1, 0, 0, r_array[i] );
		LHP_PGen_seeded ( puzzle_array_output + i , &(rp_params.pp), str_x, count_x, str_r, count_r ) ;
		LHP_PGen_seeded ( threshold_puzzle_array + i , &(rp_params.pp), str_x, count_x, str_r, count_r ) ;
		free ( str_x );
		free ( str_r );
		
	}
	
	RP_prover_seeded ( proof_array, rp_params, seed, seedlen,  puzzle_array_output, wit_array_output, value_t, value_n ); 
	
	
	//Bullet points 5,6,7 can be extracted from the information created so far
	
	mpz_clear ( seed_mpz ) ;
	gmp_randclear ( state );
	for ( int i = 0; i < value_n; i++ )
	{
		mpz_clear ( x_array[i] );
		mpz_clear ( r_array[i] );
	}
	free ( x_array );
	free ( r_array );
}

int verify ( RP_param_t rp_params, mpz_t h_output, mpz_t * h_output_array, LHP_puzzle_t * puzzle_array, RP_proof_t * proof_array, RP_wit_t * wit_array, mpz_t * h_array,  int value_I, int value_t, unsigned char * seed, size_t seedlen, int value_n ) { //Fixme: I is fixed
	
	//variables
	int verify = 1;
	
	int x_values[value_n];
	for (int i=0; i < value_n; i++){
		x_values[i] = i+1;
	}
	
	//Condition 1
	mpz_t * x_array = malloc ( sizeof ( mpz_t ) * value_n );
	for ( int i = 0; i < value_n; i++ )
	{
		mpz_init_set_ui ( x_array[i], 0 );
		mpz_add ( x_array[i], x_array[i], wit_array[i].x );
	}
	

	mpz_t aux;
	mpz_init ( aux );

	for (int final_i = value_t; final_i<=value_n;  final_i++){
		reconstruct_secret(aux, x_values, h_output_array, value_t, final_i, rp_params.pp.N);
		if ( mpz_cmp ( aux, h_output ) != 0 )
		{
			verify = 0;
		}
	}
	
	
	//Condition 2
	int temp_aux;
	temp_aux =  RP_verifier ( proof_array, puzzle_array, value_n, rp_params, seed, seedlen, value_n );
	if ( temp_aux == 0 )
	{
		verify = 0;
	}
	
	//Condition 3
	unsigned char * str_x;
	unsigned char * str_r;
	size_t count_r;
	size_t count_x;
	LHP_puzzle_t * puzzle_array_output;
	puzzle_array_output = malloc ( sizeof ( LHP_puzzle_t ) * value_n );
	
	mpz_t h_i_temp;
	mpz_init ( h_i_temp ); 
	int tmp;
	
	for ( int i = 0; i < value_I-1; i++ ) 
	{
		
		LHP_init_puzzle ( puzzle_array_output + i );
		mpz_export ( NULL, &count_x, 1, 1, 0, 0, wit_array[i].x );
		mpz_export ( NULL, &count_r, 1, 1, 0, 0, wit_array[i].r );
		str_x = malloc ( count_x );
		str_r = malloc ( count_r );
		
		mpz_export ( str_x, &count_x, 1, 1, 0, 0, wit_array[i].x );
		mpz_export ( str_r, &count_r, 1, 1, 0, 0, wit_array[i].r );
		LHP_PGen_seeded ( puzzle_array_output + i , &(rp_params.pp), str_x, count_x, str_r, count_r ) ;
		
		tmp = LHP_puzzle_cmp ( puzzle_array + i , puzzle_array_output + i );
		
		free ( str_x );
		free ( str_r );
		
		if ( tmp != 0 )
		{
			verify = 0;
		}
		
		mpz_powm ( h_i_temp , rp_params.pp.g ,  wit_array[i].x , rp_params.pp.N ) ;
		
		if ( mpz_cmp ( h_i_temp, h_array[i] ) != 0 )
		{
			verify = 0;
		}

	}

	
	//Condition 4
	//Fixme: omitted in this proof of concept
	
	
	//free variables
	for ( int i = 0; i < value_I - 1; i++ )
	{
		LHP_clear_puzzle ( puzzle_array_output + i );
	}
	mpz_clear ( aux );
	mpz_clear ( h_i_temp ); 
	for ( int i = 0; i < value_n; i++ )
	{
		mpz_clear ( x_array[i] );
	}
	free ( x_array );
	free ( puzzle_array_output );
		
	//return
	return verify;
}
 
void force_open ( LHP_puzzle_sol_t * sol,  LHP_puzzle_t * puzzle_array, RP_param_t rp_params, int value_t, int value_n )
{
	int x_values[value_n];
	for (int i=0; i < value_n; i++){
		x_values[i] = i+1;
	}
	
	//First bullet
	LHP_puzzle_sol_t * sol_array;
	sol_array = malloc ( sizeof ( LHP_puzzle_sol_t ) * value_n );
	
	mpz_t * x_array;
	x_array = malloc ( sizeof ( mpz_t ) * value_n );
	
	for ( int i = 0; i < value_n; i++ )//fixme: not all puzzles are required
	{
		mpz_init ( sol_array[i].s );
		LHP_PSolve ( &(rp_params.pp) , puzzle_array + i , sol_array + i );
		mpz_init_set_ui ( x_array[i], 0 );
		mpz_add ( x_array[i], x_array[i], sol_array[i].s );
	}
	
	
	//Second bullet

	mpz_t recovered_secret;
        mpz_init(recovered_secret);
	int final_i = value_t;
	reconstruct_secret(recovered_secret, x_values, x_array, value_t, final_i, rp_params.pp.N);
	gmp_printf("Recovered Secret: %Zd\n", recovered_secret);

	
	// free variables
	for ( int i = 0; i < value_n; i++ )
	{
		mpz_clear ( sol_array[i].s );
		mpz_clear ( x_array[i] );
	}
	free ( sol_array );
	free ( x_array );
	mpz_clear ( recovered_secret );
}


void commit_aagregate (RP_param_t rp_params, LHP_puzzle_t ** threshold_puzzle_array, 
int index)
{
	LHP_puzzle_t dest_puzzle;
	LHP_init_puzzle ( &dest_puzzle ) ;

	LHP_puzzle_t *transposed = malloc(VTD_THRESHOLD_NUM * sizeof(LHP_puzzle_t));
	for (int j = 0; j < VTD_THRESHOLD_NUM; j++) {
		LHP_init_puzzle ( transposed + j );
		mpz_set(transposed[j].u, threshold_puzzle_array[j][index].u);
		mpz_set(transposed[j].v, threshold_puzzle_array[j][index].v);
	}
	LHP_PEval ( &(rp_params.pp) , transposed, VTD_THRESHOLD_NUM , &dest_puzzle) ;
	
	for (int j = 0; j < VTD_THRESHOLD_NUM; j++) {
		LHP_clear_puzzle ( transposed + j );
	}
	free ( transposed );
	LHP_clear_puzzle ( &dest_puzzle );
}
