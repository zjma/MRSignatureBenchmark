#include <openssl/bn.h>
#include <openssl/evp.h>
#include <stdlib.h>
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
    
    BN_free(self->g);
    BN_free(self->p);
    BN_free(self->q);
    BN_free(self->w);
    BN_free(self->h);
    BN_free(self->rd0w);
    BN_free(self->d0);
    BN_free(self->h1);
    BN_free(self->d1);
    BN_free(self->z);
    BN_CTX_free(self->bnctx);
    
    free(self);
    
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
    BIGNUM *rbn;
    
    assert(sec_size == 1024);

    rbn = BN_bin2bn(_P0, 128, self->p);
    assert(rbn != NULL);

    rbn = BN_bin2bn(_G0, 128, self->g);
    assert(rbn != NULL);
    
    rbn = BN_bin2bn(_Q0, 20, self->q);
    assert(rbn != NULL);
    
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
    
    /* Pick r */
    ret = BN_rand_range(self->r, self->q);
    assert(ret==1);
    
    /* Compute a:=g^r mod p */
    ret = BN_mod_exp(self->a, self->g, self->r, self->p, self->bnctx);
    assert(ret==1);
    
    /* Convert a into bytes */
    self->a_bytes_len = BN_num_bytes(self->a);
    BN_bn2bin(self->a, self->a_bytes);
    
    /* Compute d0 = SHA256(a||0x00) */
    self->a[self->a_bytes_len] = 0x00;
    EVP_MD_CTX mdctx;
    EVP_MD_CTX_init(&mdctx);
    EVP_DigestInit_ex(&mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(&mdctx, self->a_bytes, self->a_bytes_len);
    EVP_DigestFinal_ex(&mdctx, self->d0, &self->d0_len);
    EVP_MD_CTX_cleanup(&mdctx);

    /* Compute h1 = SHA256(a||0x01) */
    self->a[self->a_bytes_len] = 0x01;
    EVP_MD_CTX mdctx2;
    EVP_MD_CTX_init(&mdctx2);
    EVP_DigestInit_ex(&mdctx2, EVP_sha256(), NULL);
    EVP_DigestUpdate(&mdctx2, self->a_bytes, self->a_bytes_len);
    EVP_DigestFinal_ex(&mdctx2, self->h1, &self->h1_len);
    EVP_MD_CTX_cleanup(&mdctx2);
    
    /* Compute rd0w = r-d0*w */
    ret = BN_mod_mul(self->d0w, self->d0, self->w, self->q, self->ctx);
    assert(ret==1);
    ret = BN_mod_sub(self->rd0w, self->r, self->d0w, self->q, self->ctx);
    assert(ret==1);

    return 0;
}


int Omega_sign_online(void *inner, char *msg, int msglen)
{
    assert(inner!=NULL);
    OmegaInner *self = (OmegaInner*)inner;
    
    int ret;
    
    /* compute d1 = h1 xor m */
    int i;
    for (i=0; i<msglen; i++)
        self->d1_bytes[i] = self->h1[i]^msg[i];
    
    /* Convert d1 to BIGMUN */
    BIGNUM *rbn = BN_bin2bn(self->d1_bytes, msglen, self->d1);
    assert(rbn!=NULL);
    
    /* Compute z=rd0w - d1*w */
    ret = BN_mod_mul(self->d1w, self->d1, self->w, self->q, self->ctx);
    assert(ret==1);
    ret = BN_mod_sub(self->z, self->rd0w, self->d1w, self->q, self->ctx);
    assert(ret==1);
    
    /*Convert z to z_bytes */
    self->z_bytes_len = BN_num_bytes(self->z);
    BN_bn2bin(self->z, self->z_bytes);
    
    return 0;
}

int Omega_vrfy(void *inner)
{
    assert(inner!=NULL);
    OmegaInner *self = (OmegaInner*)inner;
    
    int ret;
    
    /* Compute a~=g^z*h^(d0+d1) */
    ret = BN_mod_exp(self->gz, self->g, self->z, self->p, self->bnctx);
    assert(ret==1);
    ret = BN_mod_add(self->d0pd1, self->d0, self->d1, self->p);
    assert(ret==1);
    ret = BN_mod_exp(self->hd0d1, self->h, self->d0pd1, self->p, self->bnctx);
    assert(ret==1);
    ret = BN_mod_mul(self->v_a, self->gz, self->hd0d1, self->q, self->bnctx);
    assert(ret==1);

    /* Convert a~ to a~_bytes */
    int va_size = BN_num_bytes(a);
    ret = BN_bn2bin(self->v_a, self->v_a_bytes+(self->m_in_bytes-va_size));
    memset(self->v_a_bytes, 0, self->m_in_bytes-va_size);
    
    /* Compute d0~=H(a~bytes||00) */
    self->v_a_bytes[self->m_in_bytes] = 0x00;
    EVP_MD_CTX mdctx;
    EVP_MD_CTX_init(&mdctx);
    EVP_DigestInit_ex(&mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(&mdctx, self->v_a_bytes, self->m_in_bytes+1);
    EVP_DigestFinal_ex(&mdctx, self->v_d0, &self->v_d0_len);
    EVP_MD_CTX_cleanup(&mdctx);
    
    /* Check d0~==d0 */
    int i;
    imt flag = 0;
    for (i=0; i<n_in_bytes; i++)
    {
        if (self->d0[i] == self->v_d0[i]) flag = 1;
    }
    assert(flag == 0);
    
    /* Compute h1~=H(a~bytes||01) */
    self->v_a_bytes[self->m_in_bytes] = 0x01;
    EVP_MD_CTX mdctx2;
    EVP_MD_CTX_init(&mdctx2);
    EVP_DigestInit_ex(&mdctx2, EVP_sha256(), NULL);
    EVP_DigestUpdate(&mdctx2, self->v_a_bytes, self->m_in_bytes+1);
    EVP_DigestFinal_ex(&mdctx2, self->v_h1, &self->v_h1_len);
    EVP_MD_CTX_cleanup(&mdctx2);
    
    /* Copmute m = h1~ xor d1~*/
    for (i=0; i<self->v_d1_size; i++)
        self->m[i] = self->v_h1[i]^self->d1_bytes[i];
    
    
    return 0;
}

