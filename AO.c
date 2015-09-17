#include <openssl/bn.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "locals.h"

typedef struct AOInner AOInner;
struct AOInner
{
    /* Scheme info */
    int bytelen_rec;
    int bytelen_red;
    int bytelen_recred;
    int bytelen_a_ex;

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
    char *am_bytes;
    
    char *n;
    char *e_bytes;
    BIGNUM *e;
    BIGNUM *ew;
    BIGNUM *z;
    char *z_bytes;
    
    char *v_e_bytes;
    BIGNUM *v_e;
    BIGNUM *v_e1;
    BIGNUM *gz;
    BIGNUM *he;
    BIGNUM *v_a;
    char *v_am_bytes;
    char *v_mh2;
    char *v_h1;

    BN_CTX *bnctx;
};


void *AO_new_inner(int sec_size, int bitlen_rec, int bitlen_red)
{
    int sizei = 0;
    BIGNUM *rbn;

    AOInner *ret = calloc(1, sizeof(AOInner));
    if (ret == NULL) return NULL;
    
    /* Remeber params */
    ret->bytelen_rec = bitlen_rec/8;
    ret->bytelen_red = bitlen_red/8;
    ret->bytelen_recred = ret->bytelen_red+ret->bytelen_rec;
    ret->bytelen_a_ex = (ret->bytelen_rec > ret->bytelen_red) ? ret->bytelen_rec : ret->bytelen_red;

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
    if ((ret->am_bytes = malloc(ret->bytelen_p+ret->bytelen_rec)) == NULL) flag = 1;

    if ((ret->n = malloc(ret->bytelen_rec+ret->bytelen_red)) == NULL) flag = 1;
    if ((ret->e_bytes = malloc(ret->bytelen_q)) == NULL) flag = 1;
    if ((ret->e = BN_new()) == NULL) flag = 1;
    if ((ret->ew = BN_new()) == NULL) flag = 1;
    if ((ret->z = BN_new()) == NULL) flag = 1;
    if ((ret->z_bytes = malloc(ret->bytelen_q)) == NULL) flag = 1;
    
    if ((ret->v_e_bytes = malloc(ret->bytelen_q)) == NULL) flag = 1;
    if ((ret->v_e = BN_new()) == NULL) flag = 1;
    if ((ret->v_e1 = BN_new()) == NULL) flag = 1;
    if ((ret->gz = BN_new()) == NULL) flag = 1;
    if ((ret->he = BN_new()) == NULL) flag = 1;
    if ((ret->v_a = BN_new()) == NULL) flag = 1;
    if ((ret->v_am_bytes = malloc(ret->bytelen_p+ret->bytelen_a_ex)) == NULL) flag = 1;
    if ((ret->v_mh2 = malloc(ret->bytelen_rec)) == NULL) flag = 1;
    if ((ret->v_h1 = malloc(ret->bytelen_red)) == NULL) flag = 1;

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
    free(ret->am_bytes);

    free(ret->n);
    free(ret->e_bytes);
    BN_free(ret->e);
    BN_free(ret->ew);
    BN_free(ret->z);
    free(ret->z_bytes);
    
    free(ret->v_e_bytes);
    BN_free(ret->v_e);
    BN_free(ret->gz);
    BN_free(ret->he);
    BN_free(ret->v_a);
    free(ret->v_am_bytes);
    free(ret->v_mh2);
    free(ret->v_h1);

    BN_CTX_free(ret->bnctx);

    return NULL;
}


void AO_free_inner(void* inner)
{
    assert(inner!=NULL);
    AOInner *self = (AOInner*)inner;
    
    BN_free(self->g);
    BN_free(self->p);
    BN_free(self->q);
    BN_free(self->w);
    BN_free(self->h);

    BN_free(self->r);
    BN_free(self->a);
    free(self->am_bytes);

    free(self->n);
    free(self->e_bytes);
    BN_free(self->e);
    BN_free(self->ew);
    BN_free(self->z);
    free(self->z_bytes);
    
    free(self->v_e_bytes);
    BN_free(self->v_e);
    BN_free(self->gz);
    BN_free(self->he);
    BN_free(self->v_a);
    free(self->v_am_bytes);
    free(self->v_mh2);
    free(self->v_h1);

    BN_CTX_free(self->bnctx);
    
    free(self);
    
    return;
}


char *AO_get_name()
{
    return "AO";
}


int AO_sign_offline(void *inner)
{
    assert(inner!=NULL);
    AOInner *self = (AOInner*)inner;
    
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
    BN_bn2bin(self->a, &self->am_bytes[self->bytelen_p]);
    BN2LenBin(self->a, self->am_bytes, self->bytelen_p);
    
    return 0;
}


int AO_sign_online(void *inner, char *msg)
{
    assert(inner!=NULL);
    AOInner *self = (AOInner*)inner;
    
    int ret;
    
    /* h1 := H1(a_bytes||msg) */
    memcpy(&self->am_bytes[self->bytelen_p], msg, self->bytelen_rec);
    VHash(self->am_bytes, self->bytelen_p+self->bytelen_rec, self->n, self->bytelen_red);
    /* h2 := H2(a_bytes||h1) xor msg*/
    memcpy(&self->am_bytes[self->bytelen_p], self->n, self->bytelen_red);
    VHash(self->am_bytes, self->bytelen_p+self->bytelen_red, &self->n[self->bytelen_red], self->bytelen_rec);
    {
        int i;
        for (i=0; i<self->bytelen_rec; i++)
            self->n[self->bytelen_red+i]^=msg[i];
    }

    /* n  := h1||h2
     * Already done. */
    
    /* e_bytes := H(n) */
    ret = VHash(self->n, self->bytelen_rec+self->bytelen_red, self->e_bytes, self->bytelen_q);
    assert(ret==0);

    /* e := int(e_bytes) */
    BN_bin2bn(self->e_bytes, self->bytelen_q, self->e);
    
    /* Compute z = r-e*w */
    ret = BN_mod_mul(self->ew, self->e, self->w, self->q, self->bnctx);
    assert(ret==1);

    ret = BN_mod_sub(self->z, self->r, self->ew, self->q, self->bnctx);
    assert(ret==1);
    
    /*Convert z to z_bytes */
    ret = BN2LenBin(self->z, self->z_bytes, self->bytelen_q);
    assert(ret==0);
    
    return 0;
}

int AO_vrfy(void *inner)
{
    assert(inner!=NULL);
    AOInner *self = (AOInner*)inner;
    
    int ret;
    BIGNUM *rbn;
    
    /* e_bytes~ := H(n) */
    VHash(self->n, self->bytelen_rec+self->bytelen_red, self->v_e_bytes, self->bytelen_q);

    /* e~ := int(e_bytes) */
    rbn = BN_bin2bn(self->v_e_bytes, self->bytelen_q, self->v_e);
    assert(rbn!=NULL);

    /* a~ := g^z * h^e~ */
    ret = BN_mod_exp(self->gz, self->g, self->z, self->p, self->bnctx);
    assert(ret==1);
    ret = BN_mod_exp(self->he, self->h, self->v_e, self->p, self->bnctx);
    assert(ret==1);
    ret = BN_mod_mul(self->v_a, self->gz, self->he, self->p, self->bnctx);
    assert(ret==1);

    /* a_bytes~ := bytes(a~) */
    BN2LenBin(self->v_a, self->v_am_bytes, self->bytelen_p);

    /* h2m~ := H2(a_bytes~ || h1~) */
    memcpy(&self->v_am_bytes[self->bytelen_p], self->n, self->bytelen_red);
    VHash(self->v_am_bytes, self->bytelen_p+self->bytelen_red, self->v_mh2, self->bytelen_rec);
    
    /* msg~ := mh2~ xor h2 */
    BinXor(self->v_mh2, &self->n[self->bytelen_red], self->v_mh2, self->bytelen_rec);

    /* h1~ := H1(a_bytes~||msg~) */
    memcpy(&self->v_am_bytes[self->bytelen_p], self->v_mh2, self->bytelen_rec);
    VHash(self->v_am_bytes, self->bytelen_p+self->bytelen_rec, self->v_h1, self->bytelen_red);

    /* Check if h1~ == h1 */
    ret = memcmp(self->v_h1, self->n, self->bytelen_red);
    assert(ret==0);

    return 0;
}

