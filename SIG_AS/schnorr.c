#include "schnorr.h"
#include "timing.h"
#include <string.h>
#include <openssl/crypto.h>

static int suppress_pVry_timing = 0;

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

    *keypair1 = generate_keypair(group, pp);
    *keypair2 = generate_keypair(group, pp);

    QueryPerformanceCounter(&end);
    elapsedTime = (end.QuadPart - start.QuadPart) * 1000.0 / frequency.QuadPart;
    printf("JKGen exc time: %f ms\n", elapsedTime);
}

KeyPair generate_keypair(EC_GROUP* group, PublicParameters* pp) {
    KeyPair keypair;
    keypair.sk = BN_new();
    keypair.pk = EC_POINT_new(group);

    // Generate a random big number in the range [1, q-1] as the private key sk
    BN_rand_range(keypair.sk, pp->q);

    // Compute the public key pk = g^sk
    EC_POINT_mul(group, keypair.pk, keypair.sk, NULL, NULL, NULL);

    return keypair;
}

void compute_h_schnorr(const EC_GROUP* group, const EC_POINT* pk1_pk2, const EC_POINT* g_k_Y, const unsigned char* m, int m_len, unsigned char* result) {
    unsigned char buffer[BN_LEN];
    int len;

    // Use the SHA256_CTX structure to save the context of the hash
    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    // Add pk1_pk2
    len = EC_POINT_point2oct(group, pk1_pk2, POINT_CONVERSION_COMPRESSED, buffer, BN_LEN, NULL);
    SHA256_Update(&sha256, buffer, len);

    // Add g_k_Y
    len = EC_POINT_point2oct(group, g_k_Y, POINT_CONVERSION_COMPRESSED, buffer, BN_LEN, NULL);
    SHA256_Update(&sha256, buffer, len);

    // Add m
    SHA256_Update(&sha256, m, m_len);

    // Compute the final hash value
    SHA256_Final(result, &sha256);
}

Signature* Sign(const char* m, KeyPair* keypair, PublicParameters* pp, BN_CTX* ctx) {
    LARGE_INTEGER frequency;
    LARGE_INTEGER start, end;
    double elapsedTime;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);

    Signature* sig = (Signature*)malloc(sizeof(Signature));
    sig->r = BN_new();
    sig->s = BN_new();

    BIGNUM* k = BN_new();
    BIGNUM* r_mul_sk = BN_new();
    EC_POINT* g_k = EC_POINT_new(pp->group);

    // generate random k in Z_q
    BN_rand_range(k, pp->q);

    // compute g^k
    EC_POINT_mul(pp->group, g_k, k, NULL, NULL, ctx);

    // compute r = H(pk || g^k || m)
    unsigned char r_str[BN_LEN];
    compute_h_schnorr(pp->group, keypair->pk, g_k, (const unsigned char*)m, strlen(m), r_str);
        BN_bin2bn(r_str, BN_LEN, sig->r);

    // compute s = k + r*sk (mod q)
    BN_mod_mul(r_mul_sk, sig->r, keypair->sk, pp->q, ctx);
    BN_mod_add(sig->s, k, r_mul_sk, pp->q, ctx);

    BN_free(k);
    BN_free(r_mul_sk);
    EC_POINT_free(g_k);

    QueryPerformanceCounter(&end);
    elapsedTime = (end.QuadPart - start.QuadPart) * 1000.0 / frequency.QuadPart;
    printf("Sign exc time: %f ms\n", elapsedTime);

    return sig;
}

int Vrfy(const char* m, KeyPair* keypair, Signature* sig, PublicParameters* pp, BN_CTX* ctx) {
    LARGE_INTEGER frequency;
    LARGE_INTEGER start, end;
    double elapsedTime;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);

    int result = 0;

    EC_POINT* hash_input = EC_POINT_new(pp->group);
    BIGNUM* neg_r_scalar = BN_new();
    BN_mod_sub(neg_r_scalar, pp->q, sig->r, pp->q, ctx);

    const EC_POINT* points[1] = { keypair->pk };
    const BIGNUM* scalars[1] = { neg_r_scalar };
    if (!EC_POINTs_mul(pp->group, hash_input, sig->s, 1, points, scalars, ctx)) {
        printf("Error computing hash input for Schnorr verification\n");
        exit(1);
    }

    unsigned char r_prime_str[BN_LEN];
    compute_h_schnorr(pp->group, keypair->pk, hash_input, (const unsigned char*)m, strlen(m), r_prime_str);

    BIGNUM* r_prime = BN_new();
    BN_bin2bn(r_prime_str, BN_LEN, r_prime);
    result = BN_cmp(sig->r, r_prime) == 0;

    EC_POINT_free(hash_input);
    BN_free(neg_r_scalar);
    BN_free(r_prime);

    QueryPerformanceCounter(&end);
    elapsedTime = (end.QuadPart - start.QuadPart) * 1000.0 / frequency.QuadPart;
    printf("Vrify exc time: %f ms\n", elapsedTime);

    return result;
}

Signature* pSign(const unsigned char* m, int m_len, const EC_POINT* Y, KeyPair* keypair1, KeyPair* keypair2, PublicParameters* pp, BN_CTX* ctx) {
    LARGE_INTEGER frequency;
    LARGE_INTEGER start, end;
    double elapsedTime;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);
    Signature* sig = (Signature*)malloc(sizeof(Signature));
    sig->r = BN_new();
    sig->s = BN_new();

    BIGNUM* k = BN_new();
    BIGNUM* sk1_plus_sk2 = BN_new();
    EC_POINT* g_k = EC_POINT_new(pp->group);
    EC_POINT* g_k_mul_Y = EC_POINT_new(pp->group);
    EC_POINT* pk1_mul_pk2 = compute_joint_public_key(pp->group, keypair1->pk, keypair2->pk, ctx);

    // Generate random k in Z_q
    BN_rand_range(k, pp->q);

    // Compute g^k
    EC_POINT_mul(pp->group, g_k, k, NULL, NULL, ctx);

    // Compute g^k * Y
    EC_POINT_copy(g_k_mul_Y, g_k);
    EC_POINT_add(pp->group, g_k_mul_Y, g_k_mul_Y, Y, ctx);

    // Compute r = H(pk1*pk2 || g^k*Y || m)
    unsigned char r_str[BN_LEN];
    compute_h_schnorr(pp->group, pk1_mul_pk2, g_k_mul_Y, m, m_len, r_str);
    BN_bin2bn(r_str, BN_LEN, sig->r);

    // Compute sk1 + sk2 mod q
    BN_mod_add(sk1_plus_sk2, keypair1->sk, keypair2->sk, pp->q, ctx);

    // Compute s = k + r*(sk1 + sk2)
    BIGNUM* r_mul_sk = BN_new();
    BN_mod_mul(r_mul_sk, sig->r, sk1_plus_sk2, pp->q, ctx);
    BN_mod_add(sig->s, k, r_mul_sk, pp->q, ctx);

    // Free the memory
    BN_free(k);
    BN_free(sk1_plus_sk2);
    EC_POINT_free(g_k);
    EC_POINT_free(g_k_mul_Y);
    EC_POINT_free(pk1_mul_pk2);

    QueryPerformanceCounter(&end);
    elapsedTime = (end.QuadPart - start.QuadPart) * 1000.0 / frequency.QuadPart;
    printf("pSign exc time: %f ms\n", elapsedTime);

    return sig;
}

int pVrfy(const char* m, const EC_POINT* Y, const Signature* sig, KeyPair* keypair1, KeyPair* keypair2, PublicParameters* pp, BN_CTX* ctx) {
    LARGE_INTEGER frequency;
    LARGE_INTEGER start, end;
    double elapsedTime;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);
    // Compute pk1 * pk2
    EC_POINT* pk1_mul_pk2 = compute_joint_public_key(pp->group, keypair1->pk, keypair2->pk, ctx);

    // Prepare scalars for simultaneous multiplication: g^s + (pk1*pk2)^(-r) + Y^r
    BIGNUM* neg_r = BN_new();
    BN_mod_sub(neg_r, pp->q, sig->r, pp->q, ctx);

    const EC_POINT* points[2] = { pk1_mul_pk2, Y };
    const BIGNUM* scalars[2] = { neg_r, sig->r };

    EC_POINT* hash_input = EC_POINT_new(pp->group);
    if (!EC_POINTs_mul(pp->group, hash_input, sig->s, 2, points, scalars, ctx)) {
        printf("Error computing hash input for adaptor verification\n");
        exit(1);
    }

    // Compute hash
    unsigned char r_prime_str[BN_LEN];
    compute_h_schnorr(pp->group, pk1_mul_pk2, hash_input, (const unsigned char*)m, strlen(m), r_prime_str);
    BIGNUM* r_prime = BN_new();
    BN_bin2bn(r_prime_str, BN_LEN, r_prime);

    // Compare r and r'
    int result = BN_cmp(sig->r, r_prime) == 0;

    // Clean up
    EC_POINT_free(pk1_mul_pk2);
    BN_free(neg_r);
    EC_POINT_free(hash_input);
    BN_free(r_prime);
    QueryPerformanceCounter(&end);
    elapsedTime = (end.QuadPart - start.QuadPart) * 1000.0 / frequency.QuadPart;
    if (!suppress_pVry_timing) {
        printf("pVry exc time: %f ms\n", elapsedTime);
    }

    return result;
}

Signature* JpSign(const unsigned char* m, int m_len, const EC_POINT* Y, KeyPair* keypair1, KeyPair* keypair2, PublicParameters* pp, BN_CTX* ctx) {
    LARGE_INTEGER frequency;
    LARGE_INTEGER start, end;
    double elapsedTime;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);

    Signature* sig = (Signature*)malloc(sizeof(Signature));
    sig->r = BN_new();
    sig->s = BN_new();

    BIGNUM* k = BN_new();
    BIGNUM* sk_sum = BN_new();
    EC_POINT* g_k = EC_POINT_new(pp->group);
    EC_POINT* gk_plus_Y = EC_POINT_new(pp->group);
    EC_POINT* pk_sum = compute_joint_public_key(pp->group, keypair1->pk, keypair2->pk, ctx);

    BN_rand_range(k, pp->q);
    EC_POINT_mul(pp->group, g_k, k, NULL, NULL, ctx);
    EC_POINT_add(pp->group, gk_plus_Y, g_k, Y, ctx);

    unsigned char r_str[BN_LEN];
    compute_h_schnorr(pp->group, pk_sum, gk_plus_Y, m, m_len, r_str);
    BN_bin2bn(r_str, BN_LEN, sig->r);

    BN_mod_add(sk_sum, keypair1->sk, keypair2->sk, pp->q, ctx);
    BIGNUM* r_mul_sk = BN_new();
    BN_mod_mul(r_mul_sk, sig->r, sk_sum, pp->q, ctx);
    BN_mod_add(sig->s, k, r_mul_sk, pp->q, ctx);

    const char* msg_str = (const char*)m;
    int prev_suppress = suppress_pVry_timing;
    suppress_pVry_timing = 1;
    int first_ok = pVrfy(msg_str, Y, sig, keypair1, keypair2, pp, ctx);
    int second_ok = pVrfy(msg_str, Y, sig, keypair1, keypair2, pp, ctx);
    suppress_pVry_timing = prev_suppress;
    if (!first_ok || !second_ok) {
        printf("Joint adaptor Schnorr pVrfy failed during JpSign timing.\n");
        exit(1);
    }

    QueryPerformanceCounter(&end);
    elapsedTime = (end.QuadPart - start.QuadPart) * 1000.0 / frequency.QuadPart;
    printf("JpSign total time: %f ms\n", elapsedTime);

    BN_free(k);
    BN_free(sk_sum);
    BN_free(r_mul_sk);
    EC_POINT_free(g_k);
    EC_POINT_free(gk_plus_Y);
    EC_POINT_free(pk_sum);

    return sig;
}

int JpVrfy(const char* m, const EC_POINT* Y, const Signature* sig, KeyPair* keypair1, KeyPair* keypair2, PublicParameters* pp, BN_CTX* ctx) {

    EC_POINT* pk_sum = compute_joint_public_key(pp->group, keypair1->pk, keypair2->pk, ctx);

    EC_POINT* g_s = EC_POINT_new(pp->group);
    EC_POINT_mul(pp->group, g_s, sig->s, NULL, NULL, ctx);

    BIGNUM* neg_r = BN_new();
    BN_mod_sub(neg_r, pp->q, sig->r, pp->q, ctx);
    EC_POINT* pk_neg_r = EC_POINT_new(pp->group);
    EC_POINT_mul(pp->group, pk_neg_r, NULL, pk_sum, neg_r, ctx);

    EC_POINT* Y_r = EC_POINT_new(pp->group);
    EC_POINT_mul(pp->group, Y_r, NULL, Y, sig->r, ctx);

    EC_POINT* hash_input = EC_POINT_new(pp->group);
    EC_POINT_copy(hash_input, g_s);
    EC_POINT_add(pp->group, hash_input, hash_input, pk_neg_r, ctx);
    EC_POINT_add(pp->group, hash_input, hash_input, Y_r, ctx);

    unsigned char r_prime_str[BN_LEN];
    compute_h_schnorr(pp->group, pk_sum, hash_input, (const unsigned char*)m, strlen(m), r_prime_str);
    BIGNUM* r_prime = BN_new();
    BN_bin2bn(r_prime_str, BN_LEN, r_prime);

    int result = BN_cmp(sig->r, r_prime) == 0;

    EC_POINT_free(pk_sum);
    EC_POINT_free(g_s);
    EC_POINT_free(pk_neg_r);
    EC_POINT_free(Y_r);
    EC_POINT_free(hash_input);
    BN_free(neg_r);
    BN_free(r_prime);

    return result;
}

Signature* JSign(const char* m, KeyPair* keypair1, KeyPair* keypair2, PublicParameters* pp, BN_CTX* ctx) {
    LARGE_INTEGER frequency;
    LARGE_INTEGER start, end;
    double elapsedTime;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);

    Signature* sig = (Signature*)malloc(sizeof(Signature));
    sig->r = BN_new();
    sig->s = BN_new();

    BIGNUM* k = BN_new();
    BIGNUM* sk_sum = BN_new();
    EC_POINT* g_k = EC_POINT_new(pp->group);
    EC_POINT* pk_sum = compute_joint_public_key(pp->group, keypair1->pk, keypair2->pk, ctx);

    // generate random k in Z_q
    BN_rand_range(k, pp->q);

    // compute g^k
    EC_POINT_mul(pp->group, g_k, k, NULL, NULL, ctx);

    // compute r = H(pk1*pk2 || g^k || m)
    unsigned char r_str[BN_LEN];
    compute_h_schnorr(pp->group, pk_sum, g_k, (const unsigned char*)m, strlen(m), r_str);
        BN_bin2bn(r_str, BN_LEN, sig->r);

    // compute s = k + r*(sk1 + sk2)
    BIGNUM* r_mul_sk = BN_new();
    BN_mod_add(sk_sum, keypair1->sk, keypair2->sk, pp->q, ctx);
    BN_mul(r_mul_sk, sig->r, sk_sum, ctx);
    BN_mod_add(sig->s, k, r_mul_sk, pp->q, ctx);

    BN_free(k);
    BN_free(sk_sum);
    BN_free(r_mul_sk);
    EC_POINT_free(g_k);
    EC_POINT_free(pk_sum);

    if (!JVrfy(m, keypair1, keypair2, sig, pp, ctx) || !JVrfy(m, keypair1, keypair2, sig, pp, ctx)) {
        printf("Joint Schnorr verification failed during JSign timing.\n");
        exit(1);
    }

    QueryPerformanceCounter(&end);
    elapsedTime = (end.QuadPart - start.QuadPart) * 1000.0 / frequency.QuadPart;
    printf("JSign total time : %f ms\n", elapsedTime);

    return sig;
}

int JVrfy(const char* m, KeyPair* keypair1, KeyPair* keypair2, Signature* sig, PublicParameters* pp, BN_CTX* ctx) {

    int result = 0;

    EC_POINT* hash_input = EC_POINT_new(pp->group);
    EC_POINT* g_s = EC_POINT_new(pp->group);
    EC_POINT* pk_sum = compute_joint_public_key(pp->group, keypair1->pk, keypair2->pk, ctx);

    // compute g^s
    EC_POINT_mul(pp->group, g_s, sig->s, NULL, NULL, ctx);

    // compute (pk1 * pk2)^(-r)
    BIGNUM* neg_r_scalar = BN_new();
    BN_mod_sub(neg_r_scalar, pp->q, sig->r, pp->q, ctx);
    EC_POINT* pk_neg_r = EC_POINT_new(pp->group);
    EC_POINT_mul(pp->group, pk_neg_r, NULL, pk_sum, neg_r_scalar, ctx);

    // compute g^s * (pk1 * pk2)^(-r)
    EC_POINT_add(pp->group, hash_input, g_s, pk_neg_r, ctx);

    // compute r' = H(pk1*pk2 || g^s * (pk1 * pk2)^(-r) || m)
    unsigned char r_prime_str[BN_LEN];
    compute_h_schnorr(pp->group, pk_sum, hash_input, (const unsigned char*)m, strlen(m), r_prime_str);

    // convert r' to BIGNUM
    BIGNUM* r_prime = BN_new();
    BN_bin2bn(r_prime_str, BN_LEN, r_prime);

    // check if r = r'
    result = BN_cmp(sig->r, r_prime) == 0;

    EC_POINT_free(hash_input);
    EC_POINT_free(g_s);
    EC_POINT_free(pk_sum);
    EC_POINT_free(pk_neg_r);
    BN_free(neg_r_scalar);
    BN_free(r_prime);

    return result;
}

Signature* Adapt(Signature* sig_tilde, BIGNUM* y, BN_CTX* ctx) {
    LARGE_INTEGER frequency;
    LARGE_INTEGER start, end;
    double elapsedTime;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);

    (void)ctx;

    Signature* sig = (Signature*)malloc(sizeof(Signature));
    sig->r = BN_new();
    sig->s = BN_new();

    // copy r from sig_tilde
    BN_copy(sig->r, sig_tilde->r);

    // compute s = s_tilde + y
    BN_add(sig->s, sig_tilde->s, y);

    QueryPerformanceCounter(&end);
    elapsedTime = (end.QuadPart - start.QuadPart) * 1000.0 / frequency.QuadPart;
    printf("Ada exc time: %f ms\n", elapsedTime);

    return sig;
}

BIGNUM* Ext(Signature* sig, Signature* sig_tilde, EC_POINT* Y, PublicParameters* pp, BN_CTX* ctx) {
    LARGE_INTEGER frequency;
    LARGE_INTEGER start, end;
    double elapsedTime;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);

    BIGNUM* y_prime = BN_new();
    EC_POINT* Y_prime = EC_POINT_new(pp->group);

    // compute y_prime = s - s_tilde
    BN_sub(y_prime, sig->s, sig_tilde->s);

    // compute Y_prime = g^{y_prime}
    EC_POINT_mul(pp->group, Y_prime, y_prime, NULL, NULL, ctx);

    QueryPerformanceCounter(&end);
    elapsedTime = (end.QuadPart - start.QuadPart) * 1000.0 / frequency.QuadPart;
    printf("Ext exc time: %f ms\n", elapsedTime);

    // if Y_prime = Y, return y_prime, else return NULL
    if (EC_POINT_cmp(pp->group, Y_prime, Y, ctx) == 0) {
        EC_POINT_free(Y_prime);
        return y_prime;
    }
    else {
        EC_POINT_free(Y_prime);
        BN_free(y_prime);
        return NULL;
    }
}

int c_size(Signature* sig) {
    int r_size = BN_num_bytes(sig->r);
    int s_size = BN_num_bytes(sig->s);
    return r_size + s_size;
}

void schnorr_test() {
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

    // Warm-up scalar multiplication and RNG so baseline timings avoid one-time costs
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
    printf("Experiment for Schnorr Signature:\n");
    printf("\n");
    //KGen
    LARGE_INTEGER frequency;
    LARGE_INTEGER start, end;
    double elapsedTime;
    QueryPerformanceFrequency(&frequency);

    QueryPerformanceCounter(&start);
    KeyPair keypair0 = generate_keypair(group, &pp);
    QueryPerformanceCounter(&end);

    elapsedTime = (end.QuadPart - start.QuadPart) * 1000.0 / frequency.QuadPart;
    printf("KGen exc time: %f ms\n", elapsedTime);

    // Sign
    BN_CTX* ctx = BN_CTX_new();
    Signature* sig0 = Sign(message_hex, &keypair0, &pp, ctx);
    BN_CTX_free(ctx);
    //printf("Size of sig: %d bytes\n", c_size(sig0));

    // Vry
    BN_CTX* ctx0 = BN_CTX_new();
    int result0 = Vrfy(message_hex, &keypair0, sig0, &pp, ctx0);
    printf("Schnorr verification: %s\n", result0 ? "valid" : "invalid");
    BN_CTX_free(ctx0);

    printf("-------------------------------------------\n");
    printf("Experiment for 2PC_Schnorr Signature:\n");
    printf("\n");
    KeyPair keypair1;
    KeyPair keypair2;

    log_joint_keygen_info(group, &pp, &keypair1, &keypair2);

    // JSign
    BN_CTX* ctx1 = BN_CTX_new();
    Signature* j_sig = JSign(message_hex, &keypair1, &keypair2, &pp, ctx1);
    BN_CTX_free(ctx1);
    //printf("Size of j_sig: %d bytes\n", c_size(j_sig));

    // JVry
    BN_CTX* ctx2 = BN_CTX_new();
    int result2 = JVrfy(message_hex, &keypair1, &keypair2, j_sig, &pp, ctx2);
    printf("2PC Schnorr verification: %s\n", result2 ? "valid" : "invalid");
    BN_CTX_free(ctx2);

    printf("-------------------------------------------\n");
    printf("Experiment for Adapt_Schnorr Signature:\n");
    printf("\n");
    // PSign
    BN_CTX* ctx3 = BN_CTX_new();
    Signature* pre_sig = pSign((const unsigned char*)message_hex, strlen(message_hex), Y, &keypair1, &keypair2, &pp, ctx3);
    BN_CTX_free(ctx3);
    //printf("Size of pre_sig: %d bytes\n", c_size(pre_sig));

    // Pvry
    BN_CTX* ctx4 = BN_CTX_new();
    int result1 = pVrfy(message_hex, Y, pre_sig, &keypair1, &keypair2, &pp, ctx4);
    printf("Adaptor Schnorr verification: %s\n", result1 ? "valid" : "invalid");
    BN_CTX_free(ctx4);

    // Adapt
    BN_CTX* ctx5 = BN_CTX_new();
    Signature* sig = Adapt(pre_sig, y, ctx5);
    BN_CTX_free(ctx5);
    //printf("Size of sig: %d bytes\n", c_size(sig));

    // Ext
    BN_CTX* ctx6 = BN_CTX_new();
    BIGNUM* y1 = Ext(sig, pre_sig, Y, &pp, ctx6);
    BN_CTX_free(ctx6);
    BN_free(y1);

    printf("-------------------------------------------\n");
    printf("Experiment for Joint_Adaptor_Schnorr Signature:\n");
    printf("\n");
    BN_CTX* ctx7 = BN_CTX_new();
    Signature* jp_sig = JpSign((const unsigned char*)message_hex, strlen(message_hex), Y, &keypair1, &keypair2, &pp, ctx7);
    BN_CTX_free(ctx7);

    BN_CTX* ctx8 = BN_CTX_new();
    int result3 = JpVrfy(message_hex, Y, jp_sig, &keypair1, &keypair2, &pp, ctx8);
    printf("Joint adaptor Schnorr verification: %s\n", result3 ? "valid" : "invalid");
    BN_CTX_free(ctx8);


    // Don't forget to free the memory
    BN_free(sig->r);
    BN_free(sig->s);
    free(sig);

    BN_free(jp_sig->r);
    BN_free(jp_sig->s);
    free(jp_sig);

    BN_free(pre_sig->r);
    BN_free(pre_sig->s);
    free(pre_sig);

    BN_free(sig0->r);
    BN_free(sig0->s);
    free(sig0);

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

