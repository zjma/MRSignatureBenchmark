#ifndef __LOCALS_H__
#define __LOCALS_H__

#include <openssl/bn.h>

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

int DoAES256CBC(char *key,
        const char *ptxt, int plen,
        char *ctxt, int *clen);

int VHash(const char *msg, int msglen, char *dst, int dstlen);

int InitCrypt();

int CleanCrypt();

#endif
