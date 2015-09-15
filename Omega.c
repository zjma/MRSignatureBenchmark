#include <openssl/bn.h>
#include <assert.h>

#include "defaults.h"

typedef struct OmegaInner OmegaInner;
struct OmegaInner
{
    BIGNUM *g;
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *w;//sk
    BIGNUM *h;//pk
    BIGNUM *d0;
    BIGNUM *h1;
    BIGNUM *d1;
    BIGNUM *rd0w;
    BIGNUM *z;
    
    BN_CTX *bnctx;
};


void *Omega_new_inner()
{
    OmegaInner *ret = calloc(1, sizeof(OmegaInner));
    if (ret == NULL) return NULL;
    int flag = 0;
    if ((ret->g = BN_new()) == NULL) flag = 1;
    if ((ret->p = BN_new()) == NULL) flag = 1;
    if ((ret->q = BN_new()) == NULL) flag = 1;
    if ((ret->w = BN_new()) == NULL) flag = 1;
    if ((ret->h = BN_new()) == NULL) flag = 1;
    if ((ret->bnctx = BN_CTX_new()) == NULL) flag = 1;
    if ((ret->rd0w = BN_new()) == NULL) flag = 1;
    if ((ret->d0 = BN_new()) == NULL) flag = 1;
    if ((ret->h1 = BN_new()) == NULL) flag = 1;
    if ((ret->d1 = BN_new()) == NULL) flag = 1;
    if ((ret->z = BN_new()) == NULL) flag = 1;

    if (flag == 1) goto err;
    return ret;
err:
    BN_free(ret->g);
    BN_free(ret->p);
    BN_free(ret->q);
    BN_free(ret->w);
    BN_free(ret->h);
    BN_free(ret->rd0w);
    BN_free(ret->d0);
    BN_free(ret->h1);
    BN_free(ret->d1);
    BN_free(ret->z);
    BN_CTX_free(ret->bnctx);
    return NULL;
}


void Omega_free_inner(void* inner)
{
    assert(inner!=NULL);
    OmegaInner *self = (OmegaInner*)inner;
    return;
}


char *Omega_get_name()
{
    return "OMEGA";
}


int Omega_genkey(void* inner, int sec_size)
{
    assert(inner!=NULL);
    OmegaInner *self = (OmegaInner*)inner;
    
    int ret;

    assert(sec_size == 1024);

    self->p = BN_bin2bn(_P0, 128, NULL);
    assert(self->p != NULL);

    self->g = BN_bin2bn(_G0, 128, NULL);
    assert(self->g != NULL);
    
    self->q = BN_bin2bn(_Q0, 20, NULL);
    assert(self->q != NULL);
    
    self->w = BN_new();
    assert(self->w != NULL);
    
    self->h = BN_new();
    assert(self->h != NULL);
    
    self->bnctx = BN_CTX_new();
    assert(self->bnctx != NULL);

    ret = BN_rand_range(self->w, self->q);
    assert(ret==1);
    
    ret = BN_mod_exp(self->h, self->g, self->w, self->p, self->bnctx);
    assert(ret==1);

    return 0;
}


int Omega_sign_offline(void *inner)
{
    assert(inner!=NULL);
    OmegaInner *self = (OmegaInner*)inner;
    
    int ret;
    BIGNUM *r = BN_new();
    BIGNUM *a = BN_new();
    BIGNUM *d0 = BN_new();
    

    assert(r!=NULL);

    ret = BN_rand_range(r, self->q);
    assert(ret==1);

    ret = BN_mod_exp(a, self->g, r, self->p, self->bnctx);
    assert(ret==1);

    
    return 0;
}


int Omega_sign_online(void *inner, char *msg, int len)
{
    assert(inner!=NULL);
    OmegaInner *self = (OmegaInner*)inner;
    return 0;
}

int Omega_vrfy(void *inner)
{
    assert(inner!=NULL);
    OmegaInner *self = (OmegaInner*)inner;
    return 0;
}

