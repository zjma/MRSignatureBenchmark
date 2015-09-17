#include <openssl/bn.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "locals.h"

typedef struct OmegaInner OmegaInner;
struct OmegaInner
{
    /* Scheme info */
    int bytelen_rec;
    int bytelen_red;

    /* Key info */
    BIGNUM *g;
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *w;//sk
    BIGNUM *h;//pk
    int bitlen_p;
    int bitlen_q;
    int bytelen_p;
    int bytelen_q;

    /* Signing vars */
    BIGNUM *r;
    BIGNUM *a;
    char *a_bytes;
    char *h0;
    char *h1;
    BIGNUM *e0;
    BIGNUM *e0w;
    BIGNUM *re0w;
    
    char *d1;
    BIGNUM *e1;
    BIGNUM *e1w;
    BIGNUM *z;
    char *z_bytes;
    
    BIGNUM *v_e0;
    BIGNUM *v_e1;
    BIGNUM *gz;
    BIGNUM *e0e1;
    BIGNUM *he0e1;
    BIGNUM *v_a;
    char *v_a_bytes;
    char *v_h0;
    char *v_h1;
    char *v_m;

    BN_CTX *bnctx;
};


void *Omega_new_inner(int sec_size, int bitlen_rec, int bitlen_red)
{
    int sizei = 0;
    BIGNUM *rbn;

    OmegaInner *ret = calloc(1, sizeof(OmegaInner));
    if (ret == NULL) return NULL;
    
    /* Remeber params */
    ret->bytelen_rec = bitlen_rec/8;
    ret->bytelen_red = bitlen_red/8;

    switch (sec_size)
    {
        case 1024:
            ret->bitlen_p = 1024;
            ret->bitlen_q = 160;
            ret->bytelen_p = 128;
            ret->bytelen_q = 20;
            sizei = 0;
            break;
        case 2048:
            ret->bitlen_p = 2048;
            ret->bitlen_q = 256;
            ret->bytelen_p = 256;
            ret->bytelen_q = 32;
            sizei = 1;
            break;
        default:
            assert(0);
    }
    
    int r;

   /* Init vars */
    int flag = 0;
    if ((ret->g = BN_new()) == NULL) flag = 1;
    if ((ret->p = BN_new()) == NULL) flag = 1;
    if ((ret->q = BN_new()) == NULL) flag = 1;
    if ((ret->w = BN_new()) == NULL) flag = 1;
    if ((ret->h = BN_new()) == NULL) flag = 1;

    if ((ret->r = BN_new()) == NULL) flag = 1;
    if ((ret->a = BN_new()) == NULL) flag = 1;
    if ((ret->a_bytes = malloc(ret->bytelen_p+1)) == NULL) flag = 1;
    if ((ret->h0 = malloc(ret->bytelen_red)) == NULL) flag = 1;
    if ((ret->h1 = malloc(ret->bytelen_rec)) == NULL) flag = 1;

    if ((ret->e0 = BN_new()) == NULL) flag = 1;
    if ((ret->e0w = BN_new()) == NULL) flag = 1;
    if ((ret->re0w = BN_new()) == NULL) flag = 1;
    
    if ((ret->d1 = malloc(ret->bytelen_rec)) == NULL) flag = 1;
    if ((ret->e1 = BN_new()) == NULL) flag = 1;
    if ((ret->e1w = BN_new()) == NULL) flag = 1;
    if ((ret->z = BN_new()) == NULL) flag = 1;
    if ((ret->z_bytes = malloc(ret->bytelen_q)) == NULL) flag = 1;
    
    if ((ret->v_e0 = BN_new()) == NULL) flag = 1;
    if ((ret->v_e1 = BN_new()) == NULL) flag = 1;
    if ((ret->gz = BN_new()) == NULL) flag = 1;
    if ((ret->e0e1 = BN_new()) == NULL) flag = 1;
    if ((ret->he0e1 = BN_new()) == NULL) flag = 1;
    if ((ret->v_a = BN_new()) == NULL) flag = 1;
    if ((ret->v_a_bytes = malloc(ret->bytelen_p)) == NULL) flag = 1;
    if ((ret->v_h0 = malloc(ret->bytelen_red)) == NULL) flag = 1;
    if ((ret->v_h1 = malloc(ret->bytelen_rec)) == NULL) flag = 1;
    if ((ret->v_m = malloc(ret->bytelen_rec)) == NULL) flag = 1;

    if ((ret->bnctx = BN_CTX_new()) == NULL) flag = 1;
    if (flag == 1) goto err;

    /* Generate key pairs */
    rbn = BN_bin2bn(_P[sizei], ret->bytelen_p, ret->p);
    assert(rbn != NULL);
    rbn = BN_bin2bn(_G[sizei], ret->bytelen_p, ret->g);
    assert(rbn != NULL);
    rbn = BN_bin2bn(_Q[sizei], ret->bytelen_q, ret->q);
    assert(rbn != NULL);
    r = BN_rand_range(ret->w, ret->q);
    assert(r==1);
    r = BN_mod_exp(ret->h, ret->g, ret->w, ret->p, ret->bnctx);
    assert(r==1);
    
    return ret;
err:
    BN_free(ret->g);
    BN_free(ret->p);
    BN_free(ret->q);
    BN_free(ret->w);
    BN_free(ret->h);

    BN_free(ret->r);
    BN_free(ret->a);
    free(ret->a_bytes);
    free(ret->h0);
    free(ret->h1);
    
    BN_free(ret->e0);
    BN_free(ret->e0w);
    BN_free(ret->re0w);
    
    free(ret->d1);
    BN_free(ret->e1);
    BN_free(ret->e1w);
    BN_free(ret->z);
    free(ret->z_bytes);
    
    BN_free(ret->gz);
    BN_free(ret->e0e1);
    BN_free(ret->he0e1);
    BN_free(ret->v_a);
    free(ret->v_a_bytes);
    free(ret->v_h0);
    free(ret->v_h1);
    free(ret->v_m);

    BN_CTX_free(ret->bnctx);

    return NULL;
}


void Omega_free_inner(void* inner)
{
    assert(inner!=NULL);
    OmegaInner *self = (OmegaInner*)inner;
    
    BN_free(self->g);
    BN_free(self->p);
    BN_free(self->q);
    BN_free(self->w);
    BN_free(self->h);

    BN_free(self->r);
    BN_free(self->a);
    free(self->a_bytes);
    free(self->h0);
    free(self->h1);

    BN_free(self->e0);
    BN_free(self->e0w);
    BN_free(self->re0w);
    
    free(self->d1);
    BN_free(self->e1);
    BN_free(self->e1w);
    BN_free(self->z);
    free(self->z_bytes);
    
    BN_free(self->v_e0);
    BN_free(self->v_e1);
    BN_free(self->gz);
    BN_free(self->e0e1);
    BN_free(self->he0e1);
    BN_free(self->v_a);
    free(self->v_a_bytes);
    free(self->v_h0);
    free(self->v_h1);
    free(self->v_m);

    BN_CTX_free(self->bnctx);
    
    free(self);
    
    return;
}


char *Omega_get_name()
{
    return "OMEGA";
}


int Omega_sign_offline(void *inner)
{
    assert(inner!=NULL);
    OmegaInner *self = (OmegaInner*)inner;
    
    int ret;
    BIGNUM *rbn;

    /* Pick r */
    ret = BN_rand_range(self->r, self->q);
    assert(ret==1);
    
    /* Compute a:=g^r mod p */
    ret = BN_mod_exp(self->a, self->g, self->r, self->p, self->bnctx);
    assert(ret==1);
    
    /* Convert a into bytes */
    int bytelen_a = BN_num_bytes(self->a);
    assert(bytelen_a <= self->bytelen_p);

    BN2LenBin(self->a, self->a_bytes, self->bytelen_p);
    
    /* Compute h0 = H0(a) = H(a||0x00) */
    self->a_bytes[self->bytelen_p] = 0x00;
    ret = VHash(self->a_bytes, self->bytelen_p+1,
            self->h0, self->bytelen_red);
    assert(ret==0);

    /* Compute h1 = H1(a) = H(a||0x01) */
    self->a_bytes[self->bytelen_p] = 0x01;
    ret = VHash(self->a_bytes, self->bytelen_p+1,
            self->h1, self->bytelen_rec);
    assert(ret==0);
    
    /* Convert h0(bytes) to e0*/
    rbn = BN_bin2bn(self->h0, self->bytelen_q, self->e0);
    assert(rbn!=NULL);

    /* Compute re0w = r-e0*w */
    ret = BN_mod_mul(self->e0w, self->e0, self->w, self->q, self->bnctx);
    assert(ret==1);

    ret = BN_mod_sub(self->re0w, self->r, self->e0w, self->q, self->bnctx);
    assert(ret==1);

    return 0;
}


int Omega_sign_online(void *inner, char *msg)
{
    assert(inner!=NULL);
    OmegaInner *self = (OmegaInner*)inner;
    
    int ret;
    /* compute d1 = h1 xor m */
    int i;
    for (i=0; i<self->bytelen_rec; i++)
        self->d1[i] = self->h1[i]^msg[i];
    
    /* Convert d1 to e1 */
    BIGNUM *rbn = BN_bin2bn(self->d1, self->bytelen_q, self->e1);
    assert(rbn!=NULL);
    
    /* Compute z=re0w - e1*w */
    ret = BN_mod_mul(self->e1w, self->e1, self->w, self->q, self->bnctx);
    assert(ret==1);
    ret = BN_mod_sub(self->z, self->re0w, self->e1w, self->q, self->bnctx);
    assert(ret==1);
    
    /*Convert z to z_bytes */
    ret = BN2LenBin(self->z, self->z_bytes, self->bytelen_q);
    assert(ret==0);
    
    return 0;
}

int Omega_vrfy(void *inner)
{
    assert(inner!=NULL);
    OmegaInner *self = (OmegaInner*)inner;
    
    int ret;
    BIGNUM *rbn;

    /* Derive e0~,e1~ from d0, d1 */
    rbn = BN_bin2bn(self->h0, self->bytelen_q, self->v_e0);
    assert(rbn!=NULL);
    rbn = BN_bin2bn(self->d1, self->bytelen_q, self->v_e1);
    assert(rbn!=NULL);
    
    assert(BN_cmp(self->v_e0, self->e0)==0);
    assert(BN_cmp(self->v_e1, self->e1)==0);


    /* Compute a~=g^z*h^(e0+e1) */
    ret = BN_mod_exp(self->gz, self->g, self->z, self->p, self->bnctx);
    assert(ret==1);
    ret = BN_mod_add(self->e0e1, self->e0, self->e1, self->q, self->bnctx);
    assert(ret==1);
    ret = BN_mod_exp(self->he0e1, self->h, self->e0e1, self->p, self->bnctx);
    assert(ret==1);
    ret = BN_mod_mul(self->v_a, self->gz, self->he0e1, self->p, self->bnctx);
    assert(ret==1);
    
    assert(BN_cmp(self->v_a, self->a)==0);

    /* Convert a~ to a~_bytes */
    BN2LenBin(self->v_a, self->v_a_bytes, self->bytelen_p);
    
    {
        int i;
        for (i=0; i<self->bytelen_p; i++)
            assert(self->v_a_bytes[i]==self->a_bytes[i]);
    }

    /* Compute h0~=H(a~bytes||00) */
    self->v_a_bytes[self->bytelen_p] = 0x00;
    VHash(self->v_a_bytes, self->bytelen_p+1, self->v_h0, self->bytelen_red);

    /* Check h0~==h0 */
    int i;
    int flag = 0;
    for (i=0; i<self->bytelen_red; i++)
        flag |= (self->h0[i] != self->v_h0[i]);
    assert(flag == 0);
    
    /* Compute h1~=H(a~bytes||01) */
    self->v_a_bytes[self->bytelen_p] = 0x01;
    VHash(self->v_a_bytes, self->bytelen_p+1, self->v_h1, self->bytelen_rec);

    /* Copmute m = h1~ xor d1*/
    for (i=0; i<self->bytelen_rec; i++)
        self->v_m[i] = self->v_h1[i]^self->d1[i];
    
    return 0;
}

