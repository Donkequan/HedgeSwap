#ifndef ECDSA_H
#define ECDSA_H

#ifndef OPENSSL_API_COMPAT
#define OPENSSL_API_COMPAT 0x10100000L
#endif

#include <openssl/ec.h>
#include <openssl/objects.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define MESSAGE_LENGTH 32
#define MSG_LEN 250

// Public parameters for ECDSA
typedef struct {
    EC_GROUP* group;
    EC_POINT* g;
    BIGNUM* q;
} PublicParameters;

// Keypair for ECDSA
typedef struct {
    BIGNUM* sk;  // private key
    EC_POINT* pk;  // public key
} KeyPair;

// Signature for ECDSA
typedef struct {
    BIGNUM* r;
    BIGNUM* s;
} Signature;

// Pre-signature for ECDSA
typedef struct {
    BIGNUM* r;
    BIGNUM* s;
    EC_POINT* K_tilde; // g^k
    EC_POINT* K;       // Y^k
} Pre_Signature;

// Function declarations for ECDSA operations
KeyPair e_generate_keypair(EC_GROUP* group, PublicParameters* pp);

Signature* e_Sign(const char* m, KeyPair* keypair, PublicParameters* pp, BN_CTX* ctx);

int e_Vrfy(const char* m, KeyPair* keypair, Signature* sig, PublicParameters* pp, BN_CTX* ctx);

Signature* e_JSign(const char* m, EC_GROUP* group, KeyPair* keypair1, KeyPair* keypair2, PublicParameters* pp, BN_CTX* ctx);

int e_JVrfy(const char* m, EC_GROUP* group, KeyPair* keypair1, KeyPair* keypair2, Signature* sig, PublicParameters* pp, BN_CTX* ctx);

Pre_Signature* e_PSign(const char* m, EC_GROUP* group, KeyPair* keypair1, KeyPair* keypair2, const EC_POINT* Y, PublicParameters* pp, BN_CTX* ctx);

int e_PVrfy(const char* m, EC_GROUP* group, KeyPair* keypair1, KeyPair* keypair2, Pre_Signature* pre_sig, const EC_POINT* Y, PublicParameters* pp, BN_CTX* ctx);

Pre_Signature* e_JpSign(const char* m, EC_GROUP* group, KeyPair* keypair1, KeyPair* keypair2, const EC_POINT* Y, PublicParameters* pp, BN_CTX* ctx);

int e_JpVrfy(const char* m, EC_GROUP* group, KeyPair* keypair1, KeyPair* keypair2, Pre_Signature* pre_sig, const EC_POINT* Y, PublicParameters* pp, BN_CTX* ctx);

Signature* e_Adapt(Pre_Signature* pre_sig, BIGNUM* y, PublicParameters* pp, BN_CTX* ctx);

BIGNUM* e_Ext(Signature* sig, Pre_Signature* pre_sig, EC_POINT* Y, PublicParameters* pp, BN_CTX* ctx);

void ecdsa_test();

#endif  // ECDSA_H
