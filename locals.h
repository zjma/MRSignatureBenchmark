#ifndef __LOCALS_H__
#define __LOCALS_H__

#include <openssl/bn.h>

extern char *_Q[2];
extern char *_P[2];
extern char *_G[2];

#define CURVE160 NID_secp160r2
#define CURVE192 NID_secp192k1
#define CURVE224 NID_secp224k1
#define CURVE256 NID_secp256k1
#define CURVE384 NID_secp384r1
#define CURVE521 NID_secp521r1

void *Omega_new_inner();
void Omega_free_inner(void* inner);
char *Omega_get_name();
int Omega_genkey(void* inner, int sec_size);
int Omega_sign_offline(void *inner);
int Omega_sign_online(void *inner, char *msg);
int Omega_vrfy(void *inner);

void *AO_new_inner();
void AO_free_inner(void* inner);
char *AO_get_name();
int AO_genkey(void* inner, int sec_size);
int AO_sign_offline(void *inner);
int AO_sign_online(void *inner, char *msg);
int AO_vrfy(void *inner);

void *PV_new_inner();
void PV_free_inner(void* inner);
char *PV_get_name();
int PV_genkey(void* inner, int sec_size);
int PV_sign_offline(void *inner);
int PV_sign_online(void *inner, char *msg);
int PV_vrfy(void *inner);


int BN2LenBin(BIGNUM *bn, char *buf, int len);

int DoSHA256(const char *msg, int msglen, char *dst);

int DoAES256CBC_fixIV(char *key,
        const char *ptxt, int plen,
        char *ctxt, int *clen);

int DoAES256CBC_DEC_fixIV(char *key,
        const char *ctxt, int clen,
        char *ptxt, int *plen);

int VHash(const char *msg, int msglen, char *dst, int dstlen);

int BinXor(const char *s0, const char *s1, char *d, int len);

int AES128CBC_fixIV_cipher_len(int bytelen_plain);

size_t bitlen2bytelen(size_t bitlen);

void hexdump(char *where, size_t howmany);

int InitCrypt();

int CleanCrypt();

#define max(a,b) ((a>b)?a:b)

extern BN_CTX *bnctx;

#endif
