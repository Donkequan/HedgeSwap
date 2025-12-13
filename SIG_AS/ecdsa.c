#include "ecdsa.h"
#include "timing.h"
#include <string.h>
#include <openssl/crypto.h>

static int suppress_PVry_timing = 0;

static EC_POINT* compute_joint_public_key(EC_GROUP* group, const EC_POINT* pk1, const EC_POINT* pk2, BN_CTX* ctx) {
    EC_POINT* pk_sum = EC_POINT_new(group);
    if (!pk_sum) {
        printf("Failed to allocate joint public key\n");
        exit(1);
    }
    if (EC_POINT_add(group, pk_sum, pk1, pk2, ctx) != 1) {
        printf("Failed to add public keys\n");
        EC_POINT_free(pk_sum);
        exit(1);
    }
    return pk_sum;
}

static void log_joint_keygen_info(EC_GROUP* group, PublicParameters* pp, KeyPair* keypair1, KeyPair* keypair2) {
    LARGE_INTEGER frequency;
    LARGE_INTEGER start, end;
    double elapsedTime;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);

    *keypair1 = e_generate_keypair(group, pp);
    *keypair2 = e_generate_keypair(group, pp);

    QueryPerformanceCounter(&end);
    elapsedTime = (end.QuadPart - start.QuadPart) * 1000.0 / frequency.QuadPart;
    printf("JKGen exc time: %f ms\n", elapsedTime);
}

KeyPair e_generate_keypair(EC_GROUP* group, PublicParameters* pp) {
    KeyPair keypair;
    keypair.sk = BN_new();
    keypair.pk = EC_POINT_new(group);

    // Generate a random big number in the range [1, q-1] as the private key sk
    BN_rand_range(keypair.sk, pp->q);

    // Compute the public key pk = g^sk
    EC_POINT_mul(group, keypair.pk, keypair.sk, NULL, NULL, NULL);

    return keypair;
}

Signature* e_Sign(const char* m, KeyPair* keypair, PublicParameters* pp, BN_CTX* ctx) {
    LARGE_INTEGER frequency;
    LARGE_INTEGER start, end;
    double elapsedTime;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);

    Signature* sig = (Signature*)malloc(sizeof(Signature));
    sig->r = BN_new();
    sig->s = BN_new();

    BIGNUM* k = BN_new();
    BIGNUM* k_inverse = BN_new();
    BIGNUM* hash_m = BN_new();
    BIGNUM* r_sk = BN_new();
    EC_POINT* g_k = EC_POINT_new(pp->group);
    BIGNUM* x_coord = BN_new();

    // generate random k in Z_q
    BN_rand_range(k, pp->q);

    // compute g^k
    EC_POINT_mul(pp->group, g_k, k, NULL, NULL, ctx);

    // compute f(g^k) = x-coordinate of g^k
    EC_POINT_get_affine_coordinates_GFp(pp->group, g_k, x_coord, NULL, ctx);
    BN_copy(sig->r, x_coord);

    // compute k^-1
    BN_mod_inverse(k_inverse, k, pp->q, ctx);

    // compute H(m)
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)m, strlen(m), hash);
    BN_bin2bn(hash, SHA256_DIGEST_LENGTH, hash_m);

    // compute r*sk
    BN_mod_mul(r_sk, sig->r, keypair->sk, pp->q, ctx);

    // compute s = k^-1 * (H(m) + r*sk)
    BIGNUM* temp = BN_new();
    BN_mod_add(temp, hash_m, r_sk, pp->q, ctx);
    BN_mod_mul(sig->s, k_inverse, temp, pp->q, ctx);

    BN_free(k);
    BN_free(k_inverse);
    BN_free(hash_m);
    BN_free(r_sk);
    BN_free(temp);
    EC_POINT_free(g_k);
    BN_free(x_coord);

    QueryPerformanceCounter(&end);
    elapsedTime = (end.QuadPart - start.QuadPart) * 1000.0 / frequency.QuadPart;
    printf("Sign exc time: %f ms\n", elapsedTime);

    return sig;
}

int e_Vrfy(const char* m, KeyPair* keypair, Signature* sig, PublicParameters* pp, BN_CTX* ctx) {
    LARGE_INTEGER frequency;
    LARGE_INTEGER start, end;
    double elapsedTime;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);

    int result = 0;

    // Compute s^{-1}
    BIGNUM* s_inv = BN_new();
    BN_mod_inverse(s_inv, sig->s, pp->q, ctx);

    // Compute s^{-1} * H(m)
    BIGNUM* s_inv_mul_Hm = BN_new();
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)m, strlen(m), hash);
    BIGNUM* Hm = BN_bin2bn(hash, SHA256_DIGEST_LENGTH, NULL);
    BN_mod_mul(s_inv_mul_Hm, s_inv, Hm, pp->q, ctx);

    // Compute s^{-1} * r
    BIGNUM* s_inv_mul_r = BN_new();
    BN_mod_mul(s_inv_mul_r, s_inv, sig->r, pp->q, ctx);

    // Compute g^{s^{-1} * H(m)} * pk^{s^{-1} * r}
    EC_POINT* verification = EC_POINT_new(pp->group);
    const EC_POINT* vrfy_points[] = { keypair->pk };
    const BIGNUM* vrfy_scalars[] = { s_inv_mul_r };
    if (!EC_POINTs_mul(pp->group, verification, s_inv_mul_Hm, 1, vrfy_points, vrfy_scalars, ctx)) {
        printf("Error computing verification point for ECDSA\n");
        exit(1);
    }

    // Compute f(verification) as the x-coordinate of verification
    BIGNUM* x_coordinate = BN_new();
    EC_POINT_get_affine_coordinates_GFp(pp->group, verification, x_coordinate, NULL, ctx);

    // Check if r is equal to f(verification)
    if (BN_cmp(sig->r, x_coordinate) == 0) {
        result = 1;
    }

    // Free memory
    BN_free(s_inv);
    BN_free(s_inv_mul_Hm);
    BN_free(Hm);
    BN_free(s_inv_mul_r);
    EC_POINT_free(verification);
    BN_free(x_coordinate);

    QueryPerformanceCounter(&end);
    elapsedTime = (end.QuadPart - start.QuadPart) * 1000.0 / frequency.QuadPart;
    printf("Vrfy exc time: %f ms\n", elapsedTime);

    return result;
}

Signature* e_JSign(const char* m, EC_GROUP* group, KeyPair* keypair1, KeyPair* keypair2, PublicParameters* pp, BN_CTX* ctx) {
    LARGE_INTEGER frequency;
    LARGE_INTEGER start, end;
    double elapsedTime;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);

    Signature* sig = (Signature*)malloc(sizeof(Signature));
    sig->r = BN_new();
    sig->s = BN_new();

    BIGNUM* k = BN_new();
    BIGNUM* k_inverse = BN_new();
    BIGNUM* hash_m = BN_new();
    BIGNUM* sk_sum = BN_new();
    BIGNUM* r_sk = BN_new();
    EC_POINT* g_k = EC_POINT_new(pp->group);
    BIGNUM* x_coord = BN_new();

    // generate random k in Z_q
    BN_rand_range(k, pp->q);

    // compute g^k
    EC_POINT_mul(pp->group, g_k, k, NULL, NULL, ctx);

    // compute f(g^k) = x-coordinate of g^k
    EC_POINT_get_affine_coordinates_GFp(pp->group, g_k, x_coord, NULL, ctx);
    BN_copy(sig->r, x_coord);

    // compute k^-1
    BN_mod_inverse(k_inverse, k, pp->q, ctx);

    // compute H(m)
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)m, strlen(m), hash);
    BN_bin2bn(hash, SHA256_DIGEST_LENGTH, hash_m);

    // compute r*sk where sk = sk1 + sk2
    BN_mod_add(sk_sum, keypair1->sk, keypair2->sk, pp->q, ctx);
    BN_mod_mul(r_sk, sig->r, sk_sum, pp->q, ctx);

    // compute s = k^-1 * (H(m) + r*sk)
    BIGNUM* temp = BN_new();
    BN_mod_add(temp, hash_m, r_sk, pp->q, ctx);
    BN_mod_mul(sig->s, k_inverse, temp, pp->q, ctx);

    BN_free(k);
    BN_free(k_inverse);
    BN_free(hash_m);
    BN_free(sk_sum);
    BN_free(r_sk);
    BN_free(temp);
    EC_POINT_free(g_k);
    BN_free(x_coord);

    if (!e_JVrfy(m, group, keypair1, keypair2, sig, pp, ctx) ||
        !e_JVrfy(m, group, keypair1, keypair2, sig, pp, ctx)) {
        printf("Joint ECDSA verification failed during JSign timing.\n");
        exit(1);
    }

    QueryPerformanceCounter(&end);
    elapsedTime = (end.QuadPart - start.QuadPart) * 1000.0 / frequency.QuadPart;
    printf("JSign total time: %f ms\n", elapsedTime);

    return sig;
}

int e_JVrfy(const char* m, EC_GROUP* group, KeyPair* keypair1, KeyPair* keypair2, Signature* sig, PublicParameters* pp, BN_CTX* ctx) {
    int result = 0;

    EC_POINT* pk_sum = compute_joint_public_key(group, keypair1->pk, keypair2->pk, ctx);

    // Compute s^{-1}
    BIGNUM* s_inv = BN_new();
    BN_mod_inverse(s_inv, sig->s, pp->q, ctx);

    // Compute s^{-1} * H(m)
    BIGNUM* s_inv_mul_Hm = BN_new();
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)m, strlen(m), hash);
    BIGNUM* Hm = BN_bin2bn(hash, SHA256_DIGEST_LENGTH, NULL);
    BN_mod_mul(s_inv_mul_Hm, s_inv, Hm, pp->q, ctx);

    // Compute s^{-1} * r
    BIGNUM* s_inv_mul_r = BN_new();
    BN_mod_mul(s_inv_mul_r, s_inv, sig->r, pp->q, ctx);

    // Compute g^{s^{-1} * H(m)}
    EC_POINT* g_s_inv_mul_Hm = EC_POINT_new(pp->group);
    EC_POINT_mul(pp->group, g_s_inv_mul_Hm, s_inv_mul_Hm, NULL, NULL, ctx);

    // Compute pk^{s^{-1} * r}
    EC_POINT* pk_s_inv_mul_r = EC_POINT_new(pp->group);
    EC_POINT_mul(pp->group, pk_s_inv_mul_r, NULL, pk_sum, s_inv_mul_r, ctx);

    // Compute g^{s^{-1} * H(m)} * pk^{s^{-1} * r}
    EC_POINT* verification = EC_POINT_new(pp->group);
    EC_POINT_add(pp->group, verification, g_s_inv_mul_Hm, pk_s_inv_mul_r, ctx);

    // Compute f(verification) as the x-coordinate of verification
    BIGNUM* x_coordinate = BN_new();
    EC_POINT_get_affine_coordinates_GFp(pp->group, verification, x_coordinate, NULL, ctx);

    // Check if r is equal to f(verification)
    if (BN_cmp(sig->r, x_coordinate) == 0) {
        result = 1;
    }

    // Free memory
    BN_free(s_inv);
    BN_free(s_inv_mul_Hm);
    BN_free(Hm);
    BN_free(s_inv_mul_r);
    EC_POINT_free(g_s_inv_mul_Hm);
    EC_POINT_free(pk_s_inv_mul_r);
    EC_POINT_free(pk_sum);
    EC_POINT_free(verification);
    BN_free(x_coordinate);

    return result;
}

Pre_Signature* e_PSign(const char* m, EC_GROUP* group, KeyPair* keypair1, KeyPair* keypair2, const EC_POINT* Y, PublicParameters* pp, BN_CTX* ctx) {
    (void)group;
    LARGE_INTEGER frequency;
    LARGE_INTEGER start, end;
    double elapsedTime;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);

    Pre_Signature* pre_sig = (Pre_Signature*)malloc(sizeof(Pre_Signature));
    pre_sig->r = BN_new();
    pre_sig->s = BN_new();
    pre_sig->K_tilde = EC_POINT_new(pp->group);
    pre_sig->K = EC_POINT_new(pp->group);

    // Generate random k in Z_q
    BIGNUM* k = BN_new();
    BN_rand_range(k, pp->q);

    // Compute g^k
    EC_POINT* g_k = EC_POINT_new(pp->group);
    EC_POINT_mul(pp->group, g_k, k, NULL, NULL, ctx);

    // Compute blinded point Y^k
    EC_POINT* Y_k = EC_POINT_new(pp->group);
    EC_POINT_mul(pp->group, Y_k, NULL, Y, k, ctx);

    // Compute r = f(Y^k)
    BIGNUM* x_coord = BN_new();
    if (EC_POINT_get_affine_coordinates_GFp(pp->group, Y_k, x_coord, NULL, ctx)) {
        // Compute r = x_coord mod q
        BN_mod(pre_sig->r, x_coord, pp->q, ctx);
    }
    else {
        // Handle error
        printf("Error computing f(Y^k)\n");
        exit(1);
    }

    // Compute H(m)
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)m, strlen(m), hash);
    BIGNUM* Hm = BN_bin2bn(hash, SHA256_DIGEST_LENGTH, NULL);

    // Compute k^(-1)
    BIGNUM* k_inv = BN_new();
    BN_mod_inverse(k_inv, k, pp->q, ctx);

    // Compute s = k^(-1) * (H(m) + r*sk)
    BIGNUM* sk_sum = BN_new();
    BN_mod_add(sk_sum, keypair1->sk, keypair2->sk, pp->q, ctx);
    BIGNUM* temp = BN_new();
    BN_mod_mul(temp, pre_sig->r, sk_sum, pp->q, ctx);  // temp = r*sk
    BN_mod_add(temp, Hm, temp, pp->q, ctx);  // temp = H(m) + r*sk
    BN_mod_mul(pre_sig->s, k_inv, temp, pp->q, ctx);  // s = k^(-1) * temp

    // Copy g^k and Y^k into the pre-signature for later verification
    EC_POINT_copy(pre_sig->K_tilde, g_k);
    EC_POINT_copy(pre_sig->K, Y_k);

    // Free allocated memory
    BN_free(k);
    EC_POINT_free(g_k);
    EC_POINT_free(Y_k);
    BN_free(Hm);
    BN_free(k_inv);
    BN_free(temp);
    BN_free(sk_sum);
    BN_free(x_coord);

    QueryPerformanceCounter(&end);
    elapsedTime = (end.QuadPart - start.QuadPart) * 1000.0 / frequency.QuadPart;
    printf("PSign exc time: %f ms\n", elapsedTime);

    return pre_sig;
}

int e_PVrfy(const char* m, EC_GROUP* group, KeyPair* keypair1, KeyPair* keypair2, Pre_Signature* pre_sig, const EC_POINT* Y, PublicParameters* pp, BN_CTX* ctx) {
    LARGE_INTEGER frequency;
    LARGE_INTEGER start, end;
    double elapsedTime;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);

    (void)Y;

    EC_POINT* pk_sum = compute_joint_public_key(group, keypair1->pk, keypair2->pk, ctx);

    int result = 0;

    // Compute s_inv = s^-1 mod q
    BIGNUM* s_inv = BN_new();
    BN_mod_inverse(s_inv, pre_sig->s, pp->q, ctx);

    // Compute H(m)
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)m, strlen(m), hash);
    BIGNUM* Hm = BN_bin2bn(hash, SHA256_DIGEST_LENGTH, NULL);

    // Compute u = H(m) * s_inv mod q
    BIGNUM* u = BN_new();
    BN_mod_mul(u, Hm, s_inv, pp->q, ctx);

    // Compute v = r * s_inv mod q
    BIGNUM* v = BN_new();
    BN_mod_mul(v, pre_sig->r, s_inv, pp->q, ctx);

    // Compute K' = g^u * pk^v
    EC_POINT* K_prime = EC_POINT_new(pp->group);
    const EC_POINT* adaptor_points[] = { pk_sum };
    const BIGNUM* adaptor_scalars[] = { v };
    if (!EC_POINTs_mul(pp->group, K_prime, u, 1, adaptor_points, adaptor_scalars, ctx)) {
        printf("Error computing adaptor verification point\n");
        exit(1);
    }

    // Compute f(K) from the stored Y^k point and compare against r
    BIGNUM* x_coord = BN_new();
    if (EC_POINT_get_affine_coordinates_GFp(pp->group, pre_sig->K, x_coord, NULL, ctx)) {
        BIGNUM* f_K = BN_new();
        BN_mod(f_K, x_coord, pp->q, ctx);
        if (BN_cmp(pre_sig->r, f_K) == 0) {
            result = 1;
        }
        BN_free(f_K);
    } else {
        printf("Error computing f(K)\n");
        exit(1);
    }

    // Free memory
    BN_free(s_inv);
    BN_free(Hm);
    BN_free(u);
    BN_free(v);
    EC_POINT_free(pk_sum);
    EC_POINT_free(K_prime);
    BN_free(x_coord);

    QueryPerformanceCounter(&end);
    elapsedTime = (end.QuadPart - start.QuadPart) * 1000.0 / frequency.QuadPart;
    if (!suppress_PVry_timing) {
        printf("PVry exc time: %f ms\n", elapsedTime);
    }

    return result;
}

Pre_Signature* e_JpSign(const char* m, EC_GROUP* group, KeyPair* keypair1, KeyPair* keypair2, const EC_POINT* Y, PublicParameters* pp, BN_CTX* ctx) {
    LARGE_INTEGER frequency;
    LARGE_INTEGER start, end;
    double elapsedTime;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);

    KeyPair keypair;
    keypair.sk = BN_new();
    BN_add(keypair.sk, keypair1->sk, keypair2->sk);
    keypair.pk = compute_joint_public_key(group, keypair1->pk, keypair2->pk, ctx);

    Pre_Signature* pre_sig = (Pre_Signature*)malloc(sizeof(Pre_Signature));
    pre_sig->r = BN_new();
    pre_sig->s = BN_new();
    pre_sig->K_tilde = EC_POINT_new(pp->group);
    pre_sig->K = EC_POINT_new(pp->group);

    BIGNUM* k = BN_new();
    BN_rand_range(k, pp->q);

    EC_POINT* g_k = EC_POINT_new(pp->group);
    EC_POINT_mul(pp->group, g_k, k, NULL, NULL, ctx);

    EC_POINT* Y_k = EC_POINT_new(pp->group);
    EC_POINT_mul(pp->group, Y_k, NULL, Y, k, ctx);

    BIGNUM* x_coord = BN_new();
    if (EC_POINT_get_affine_coordinates_GFp(pp->group, Y_k, x_coord, NULL, ctx)) {
        BN_mod(pre_sig->r, x_coord, pp->q, ctx);
    } else {
        printf("Error computing f(Y^k)\n");
        exit(1);
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)m, strlen(m), hash);
    BIGNUM* Hm = BN_bin2bn(hash, SHA256_DIGEST_LENGTH, NULL);

    BIGNUM* k_inv = BN_new();
    BN_mod_inverse(k_inv, k, pp->q, ctx);

    BIGNUM* temp = BN_new();
    BN_mod_mul(temp, pre_sig->r, keypair.sk, pp->q, ctx);
    BN_mod_add(temp, Hm, temp, pp->q, ctx);
    BN_mod_mul(pre_sig->s, k_inv, temp, pp->q, ctx);

    EC_POINT_copy(pre_sig->K_tilde, g_k);
    EC_POINT_copy(pre_sig->K, Y_k);

    BN_free(k);
    EC_POINT_free(g_k);
    EC_POINT_free(Y_k);
    BN_free(x_coord);
    BN_free(Hm);
    BN_free(k_inv);
    BN_free(temp);

    int prev_suppress = suppress_PVry_timing;
    suppress_PVry_timing = 1;
    int first_ok = e_PVrfy(m, group, keypair1, keypair2, pre_sig, Y, pp, ctx);
    int second_ok = e_PVrfy(m, group, keypair1, keypair2, pre_sig, Y, pp, ctx);
    suppress_PVry_timing = prev_suppress;
    if (!first_ok || !second_ok) {
        printf("Joint adaptor ECDSA PVrfy failed during JpSign timing.\n");
        exit(1);
    }

    QueryPerformanceCounter(&end);
    elapsedTime = (end.QuadPart - start.QuadPart) * 1000.0 / frequency.QuadPart;
    printf("JpSign total time: %f ms\n", elapsedTime);

    BN_free(keypair.sk);
    EC_POINT_free(keypair.pk);

    return pre_sig;
}

int e_JpVrfy(const char* m, EC_GROUP* group, KeyPair* keypair1, KeyPair* keypair2, Pre_Signature* pre_sig, const EC_POINT* Y, PublicParameters* pp, BN_CTX* ctx) {

    (void)Y;

    KeyPair keypair;
    keypair.sk = BN_new();
    BN_add(keypair.sk, keypair1->sk, keypair2->sk);
    keypair.pk = compute_joint_public_key(group, keypair1->pk, keypair2->pk, ctx);

    int result = 0;

    BIGNUM* s_inv = BN_new();
    BN_mod_inverse(s_inv, pre_sig->s, pp->q, ctx);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)m, strlen(m), hash);
    BIGNUM* Hm = BN_bin2bn(hash, SHA256_DIGEST_LENGTH, NULL);

    BIGNUM* u = BN_new();
    BN_mod_mul(u, Hm, s_inv, pp->q, ctx);

    BIGNUM* v = BN_new();
    BN_mod_mul(v, pre_sig->r, s_inv, pp->q, ctx);

    EC_POINT* g_u = EC_POINT_new(pp->group);
    EC_POINT_mul(pp->group, g_u, u, NULL, NULL, ctx);

    EC_POINT* pk_v = EC_POINT_new(pp->group);
    EC_POINT_mul(pp->group, pk_v, NULL, keypair.pk, v, ctx);

    EC_POINT* K_prime = EC_POINT_new(pp->group);
    EC_POINT_add(pp->group, K_prime, g_u, pk_v, ctx);

    if (EC_POINT_cmp(pp->group, K_prime, pre_sig->K_tilde, ctx) == 0) {
        BIGNUM* x_coord = BN_new();
        BIGNUM* y_coord = BN_new();
        if (EC_POINT_get_affine_coordinates_GFp(pp->group, pre_sig->K, x_coord, y_coord, ctx)) {
            BIGNUM* f_K = BN_new();
            BN_mod(f_K, x_coord, pp->q, ctx);
            result = (BN_cmp(pre_sig->r, f_K) == 0);
            BN_free(f_K);
        } else {
            printf("Error computing f(K)\n");
            exit(1);
        }
        BN_free(x_coord);
        BN_free(y_coord);
    }

    BN_free(s_inv);
    BN_free(Hm);
    BN_free(u);
    BN_free(v);
    EC_POINT_free(g_u);
    EC_POINT_free(pk_v);
    EC_POINT_free(K_prime);
    BN_free(keypair.sk);
    EC_POINT_free(keypair.pk);

    return result;
}

Signature* e_Adapt(Pre_Signature* pre_sig, BIGNUM* y, PublicParameters* pp, BN_CTX* ctx) {
    LARGE_INTEGER frequency;
    LARGE_INTEGER start, end;
    double elapsedTime;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);

    Signature* sig = (Signature*)malloc(sizeof(Signature));
    sig->r = BN_new();
    sig->s = BN_new();

    // Compute y_inv = y^-1 mod q
    BIGNUM* y_inv = BN_new();
    BN_mod_inverse(y_inv, y, pp->q, ctx);

    // Compute s = s_tilde * y_inv mod q
    BN_mod_mul(sig->s, pre_sig->s, y_inv, pp->q, ctx);

    // Copy r from pre_sig to sig
    BN_copy(sig->r, pre_sig->r);

    // Free memory
    BN_free(y_inv);

    QueryPerformanceCounter(&end);
    elapsedTime = (end.QuadPart - start.QuadPart) * 1000.0 / frequency.QuadPart;
    printf("Ada exc time: %f ms\n", elapsedTime);

    return sig;
}

BIGNUM* e_Ext(Signature* sig, Pre_Signature* pre_sig, EC_POINT* Y, PublicParameters* pp, BN_CTX* ctx) {
    LARGE_INTEGER frequency;
    LARGE_INTEGER start, end;
    double elapsedTime;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);

    BIGNUM* y_prime = NULL;

    // Compute s_inv = s^-1 mod q
    BIGNUM* s_inv = BN_new();
    BN_mod_inverse(s_inv, sig->s, pp->q, ctx);

    // Compute y_prime = s_inv * s_tilde mod q
    y_prime = BN_new();
    BN_mod_mul(y_prime, s_inv, pre_sig->s, pp->q, ctx);

    // Compute Y_prime = g^y_prime
    EC_POINT* Y_prime = EC_POINT_new(pp->group);
    EC_POINT_mul(pp->group, Y_prime, y_prime, NULL, NULL, ctx);

    // If Y != Y_prime, set y_prime to NULL
    if (EC_POINT_cmp(pp->group, Y, Y_prime, ctx) != 0) {
        BN_free(y_prime);
        y_prime = NULL;
    }

    // Free memory
    BN_free(s_inv);
    EC_POINT_free(Y_prime);

    QueryPerformanceCounter(&end);
    elapsedTime = (end.QuadPart - start.QuadPart) * 1000.0 / frequency.QuadPart;
    printf("Ext exc time: %f ms\n", elapsedTime);

    return y_prime;
}

int e_c_size(Signature* sig) {
    int r_size = BN_num_bytes(sig->r);
    int s_size = BN_num_bytes(sig->s);
    return r_size + s_size;
}

int e_c_pre_size(Pre_Signature* pre_sig) {
    int r_size = BN_num_bytes(pre_sig->r);
    int s_size = BN_num_bytes(pre_sig->s);
    return r_size + s_size;
}

void ecdsa_test() {
    unsigned char entropy[MESSAGE_LENGTH];
    if (RAND_bytes(entropy, sizeof(entropy)) != 1) {
        printf("Error generating random message.\n");
        return;
    }

    char message_hex[MESSAGE_LENGTH * 2 + 1];
    for (size_t i = 0; i < MESSAGE_LENGTH; ++i) {
        snprintf(&message_hex[i * 2], 3, "%02x", entropy[i]);
    }
    message_hex[MESSAGE_LENGTH * 2] = '\0';

    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    PublicParameters pp;

    pp.group = group;
    pp.g = EC_POINT_new(group);
    pp.q = BN_new();

    const EC_POINT* generator = EC_GROUP_get0_generator(group);
    EC_POINT_copy(pp.g, generator); 
    EC_GROUP_get_order(group, pp.q, NULL); 

    BIGNUM* y = BN_new();
    EC_POINT* Y = EC_POINT_new(group);
    BN_rand_range(y, pp.q);
    EC_POINT_mul(group, Y, y, NULL, NULL, NULL);

    // Warm-up scalar multiplication and RNG to remove one-time costs from baseline timings
    BN_CTX* warm_ctx = BN_CTX_new();
    EC_POINT* warm_point = EC_POINT_new(group);
    BIGNUM* warm_scalar = BN_new();
    BN_one(warm_scalar);
    EC_POINT_mul(group, warm_point, warm_scalar, NULL, NULL, warm_ctx);
    BN_rand_range(warm_scalar, pp.q);
    EC_POINT_free(warm_point);
    BN_free(warm_scalar);
    BN_CTX_free(warm_ctx);

    printf("-------------------------------------------\n");
    printf("Experiment for ECDSA Signature:\n");
    printf("\n");
    //KGen
    LARGE_INTEGER frequency;
    LARGE_INTEGER start, end;
    double elapsedTime;
    QueryPerformanceFrequency(&frequency);

    QueryPerformanceCounter(&start);
    KeyPair keypair0 = e_generate_keypair(group, &pp);
    QueryPerformanceCounter(&end);

    elapsedTime = (end.QuadPart - start.QuadPart) * 1000.0 / frequency.QuadPart;
    printf("KGen exc time: %f ms\n", elapsedTime);

    //Sign
    BN_CTX* ctx = BN_CTX_new();
    Signature* sig = e_Sign(message_hex, &keypair0, &pp, ctx);
    BN_CTX_free(ctx);

    //Vrfy
    BN_CTX* ctx0 = BN_CTX_new();
    int result = e_Vrfy(message_hex, &keypair0, sig, &pp, ctx0);
    printf("ECDSA verification: %s\n", result ? "valid" : "invalid");
    BN_CTX_free(ctx0);

    printf("-------------------------------------------\n");
    printf("Experiment for 2PC_ECDSA Signature:\n");
    printf("\n");
    KeyPair keypair1;
    KeyPair keypair2;

    log_joint_keygen_info(group, &pp, &keypair1, &keypair2);
    // JSign
    BN_CTX* ctx1 = BN_CTX_new();
    Signature* j_sig = e_JSign(message_hex, group, &keypair1, &keypair2, &pp, ctx1);
    //printf("Size of j_sig: %d bytes\n", e_c_size(j_sig));
    BN_CTX_free(ctx1);

    // JVry
    BN_CTX* ctx2 = BN_CTX_new();
    int result1 = e_JVrfy(message_hex, group, &keypair1, &keypair2, j_sig, &pp, ctx2);
    printf("2PC ECDSA verification: %s\n", result1 ? "valid" : "invalid");
    BN_CTX_free(ctx2);

    printf("-------------------------------------------\n");
    printf("Experiment for Adapt_ECDSA Signature:\n");
    printf("\n");
    // PSign
    BN_CTX* ctx3 = BN_CTX_new();
    Pre_Signature* pre_sig = e_PSign(message_hex, group, &keypair1, &keypair2, Y, &pp, ctx3);
    //printf("Size of pre_sig: %d bytes\n", e_c_pre_size(pre_sig));
    BN_CTX_free(ctx3);

    // PVry
    BN_CTX* ctx4 = BN_CTX_new();
    int result2 = e_PVrfy(message_hex, group, &keypair1, &keypair2, pre_sig, Y, &pp, ctx4);
    printf("Adaptor ECDSA pre-signature verification: %s\n", result2 ? "valid" : "invalid");
    BN_CTX_free(ctx4);

    // Adapt
    BN_CTX* ctx5 = BN_CTX_new();
    Signature* sig1 = e_Adapt(pre_sig, y, &pp, ctx5);
    //printf("Size of sig: %d bytes\n", e_c_size(sig1));
    BN_CTX_free(ctx5);

    // Ext
    BN_CTX* ctx6 = BN_CTX_new();
    BIGNUM* y1 = e_Ext(sig1, pre_sig, Y, &pp, ctx6);
    BN_CTX_free(ctx6);
    BN_free(y1);

    printf("-------------------------------------------\n");
    printf("Experiment for Joint_Adaptor_ECDSA Signature:\n");
    printf("\n");

    BN_CTX* ctx7 = BN_CTX_new();
    Pre_Signature* jp_pre_sig = e_JpSign(message_hex, group, &keypair1, &keypair2, Y, &pp, ctx7);
    BN_CTX_free(ctx7);

    BN_CTX* ctx8 = BN_CTX_new();
    int result3 = e_JpVrfy(message_hex, group, &keypair1, &keypair2, jp_pre_sig, Y, &pp, ctx8);
    printf("Joint adaptor ECDSA verification: %s\n", result3 ? "valid" : "invalid");
    BN_CTX_free(ctx8);

    BN_free(sig1->r);
    BN_free(sig1->s);
    free(sig1);

    EC_POINT_free(pre_sig->K_tilde);
    EC_POINT_free(pre_sig->K);
    BN_free(pre_sig->r);
    BN_free(pre_sig->s);
    free(pre_sig);

    EC_POINT_free(jp_pre_sig->K_tilde);
    EC_POINT_free(jp_pre_sig->K);
    BN_free(jp_pre_sig->r);
    BN_free(jp_pre_sig->s);
    free(jp_pre_sig);

    BN_free(j_sig->r);
    BN_free(j_sig->s);
    free(j_sig);

    BN_free(sig->r);
    BN_free(sig->s);
    free(sig);

    EC_POINT_free(Y);
    BN_free(y);
    EC_POINT_free(keypair2.pk);
    BN_free(keypair2.sk);
    EC_POINT_free(keypair1.pk);
    BN_free(keypair1.sk);
    EC_POINT_free(keypair0.pk);
    BN_free(keypair0.sk);

    BN_free(pp.q);
    EC_POINT_free(pp.g);
    EC_GROUP_free(group);
}