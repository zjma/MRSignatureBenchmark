#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/crypto.h>

#include "scheme.h"
#include "locals.h"

typedef struct ECOMG_KeyPair ECOMG_KeyPair;
struct ECOMG_KeyPair
{
    EC_KEY*         eckey;
    const EC_GROUP* group;
    BIGNUM*         group_order;
    const BIGNUM*   w;  //private key
    const EC_POINT* h;  //public key
    int             bytelen_go;
    int             bytelen_point;
};


typedef struct ECOMG_SignSess ECOMG_SignSess;
struct ECOMG_SignSess
{
    BIGNUM *r;
    EC_POINT *a;
    char *a_bytes;
    //char *redun;
    char *tmpkey;
    BIGNUM *e0;
    BIGNUM *e0w;
    BIGNUM *re0w;

    char *covered;
    char *d1mclr;
    char *e1_bytes;
    BIGNUM *e1;
    BIGNUM *e1w;
    BIGNUM *z;

    BN_CTX *bnctx;
};


typedef struct ECOMG_VrfySess ECOMG_VrfySess;
struct ECOMG_VrfySess
{
    BIGNUM *e0;
    char *mclrcov;
    char *e1_bytes;
    BIGNUM *e1;
    BIGNUM *e0e1;
    BIGNUM *z;
    EC_POINT *a;
    char *a_bytes;
    char *redun;
    char *tmpkey;
    char *m_rec;
    int bytelen_rec;
    BN_CTX *bnctx;
};


typedef struct ECOMG_Sig ECOMG_Sig;
struct ECOMG_Sig
{
    int bytelen_clr;
    int bytelen_covered;
    int bytelen_red;
    int bytelen_z;
    char *m_clr;
    char *n;
    char *redun;
    char *z_bytes;
};


void *ECOMG_keypair_new(int sec);
void ECOMG_keypair_free(void *obj);
int ECOMG_keypair_gen(int sec, void *obj);
const char *ECOMG_get_name();
void *ECOMG_signsess_new(void *keyobj, int bitlen_clr, int bitlen_rec, int bitlen_red);
void ECOMG_signsess_free(void* obj);
void *ECOMG_vrfysess_new(void *keyobj, int bitlen_clr, int bitlen_rec, int bitlen_red);
void ECOMG_vrfysess_free(void* obj);
void *ECOMG_signature_new(void *keyobj, int bitlen_clr, int bitlen_rec, int bitlen_red);
void ECOMG_signature_free(void* obj);
int ECOMG_get_sig_len(int clr, int rec, int red, void *obj);
int ECOMG_sig_encode(int clr, int rec, int red, void *obj, char *buf);
int ECOMG_sign_offline(int clr, int rec, int red, void *keyobj, void *sessobj, void *sigobj);
int ECOMG_sign_online(int clr, int rec, int red, void *keyobj, void *sessobj, void *sigobj, const char *msg, int msglen);
int ECOMG_vrfy_offline(int clr, int rec, int red, void *keyobj, void *sessobj);
int ECOMG_vrfy_online(int clr, int rec, int red, void *keyobj, void *sessobj, void *sigobj);

void *ECOMG_keypair_new(int sec)
{
    BIGNUM *w = NULL;
    BIGNUM *group_order = NULL;
    EC_POINT *h = NULL;
    EC_KEY *eckey = NULL;

    ECOMG_KeyPair *ret = NULL;

    ret = malloc(sizeof(ECOMG_KeyPair));
    if (ret == NULL) goto err;

    switch(sec)
    {
        case 80:
            eckey = EC_KEY_new_by_curve_name(NID_secp160k1);
            break;
        case 128:
            eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
            break;
        case 256:
            eckey = EC_KEY_new_by_curve_name(NID_brainpoolP512r1);
            break;
        default:
            eckey = NULL;
    }
    if (eckey == NULL) goto err;

    group_order = BN_new();
    if (group_order == NULL) goto err;

    //w = BIGNUM_new();
    //if (w == NULL) goto err;


    //h = EC_POINT_new();

    ret->eckey = eckey;
    ret->group_order = group_order;
    ret->w = NULL;
    ret->h = NULL;
    ret->bytelen_go = 0;
    return ret;
err:
    free(ret);
    EC_KEY_free(eckey);
    BN_free(w);
    BN_free(group_order);
    EC_POINT_free(h);
    return NULL;
}


void ECOMG_keypair_free(void *obj)
{
    ECOMG_KeyPair *keypair = (ECOMG_KeyPair*)obj;
    EC_KEY_free(keypair->eckey);
    BN_free(keypair->group_order);
    free(keypair);
}


int ECOMG_keypair_gen(int sec, void *obj)
{
    int ret = 0;
    BN_CTX *bnctx = BN_CTX_new();
    if (bnctx == NULL)
    {
        ret = -1;
        goto final;
    }

    ECOMG_KeyPair *keypair = (ECOMG_KeyPair*)obj;
    ret = EC_KEY_generate_key(keypair->eckey);
    if (ret == 0)
    {
        ret = -1;
        goto final;
    }

    const EC_GROUP *grp = EC_KEY_get0_group(keypair->eckey);
    keypair->group = grp;
    EC_GROUP_get_order(grp, keypair->group_order, bnctx);
    keypair->w = EC_KEY_get0_private_key(keypair->eckey);
    keypair->h = EC_KEY_get0_public_key(keypair->eckey);
    keypair->bytelen_go = BN_num_bytes(keypair->group_order);
    keypair->bytelen_point = EC_POINT_point2oct(
            grp, keypair->h, POINT_CONVERSION_COMPRESSED, NULL, 0, bnctx);
    //printf("bytelen-point=%d\n", keypair->bytelen_point);
    ret = 0;

final:
    BN_CTX_free(bnctx);

    return ret;
}


const char *ECOMG_get_name()
{
    return "EC-Omega";
}


void *ECOMG_signsess_new(void *keyobj, int bitlen_clr, int bitlen_rec, int bitlen_red)
{
    ECOMG_KeyPair *keypair = (ECOMG_KeyPair*)keyobj;

    ECOMG_SignSess *sess = malloc(sizeof(ECOMG_SignSess));
    if (sess == NULL) return NULL;

    memset(sess, 0, sizeof(ECOMG_SignSess));

    void *flag = NULL;
    flag = sess->r = BN_new();if (flag == NULL) goto err;
    flag = sess->a = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
    flag = sess->a_bytes = malloc(keypair->bytelen_point+1);if (flag == NULL) goto err;

    int bytelen_red = (bitlen_red+7)/8;
    int bytelen_rec = (bitlen_rec+7)/8;
    int bytelen_clr = (bitlen_clr+7)/8;

    flag = sess->tmpkey = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
    flag = sess->e0 = BN_new();if (flag == NULL) goto err;
    flag = sess->e0w = BN_new();if (flag == NULL) goto err;
    flag = sess->re0w = BN_new();if (flag == NULL) goto err;

    int bytelen_d1 = AES128CBC_fixIV_cipher_len(bytelen_rec);
    flag = sess->covered = malloc(bytelen_d1);if (flag == NULL) goto err;
    flag = sess->d1mclr = malloc(bytelen_clr + bytelen_d1);if (flag == NULL) goto err;
    flag = sess->e1_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
    flag = sess->e1 = BN_new();if (flag == NULL) goto err;
    flag = sess->e1w = BN_new();if (flag == NULL) goto err;
    flag = sess->z = BN_new();if (flag == NULL) goto err;

    flag = sess->bnctx = BN_CTX_new();if (flag == NULL) goto err;
    return sess;
err:
    ECOMG_signsess_free(sess);
    return NULL;
}


void ECOMG_signsess_free(void* obj)
{
    if (obj == NULL) return;
    ECOMG_SignSess *sess = (ECOMG_SignSess*)obj;
    BN_free(sess->r);
    EC_POINT_free(sess->a);
    free(sess->a_bytes);
    //free(sess->redun);
    free(sess->tmpkey);
    BN_free(sess->e0);
    BN_free(sess->e0w);
    BN_free(sess->re0w);
    free(sess->covered);
    BN_free(sess->e1);
    BN_free(sess->e1w);
    BN_free(sess->z);
    BN_CTX_free(sess->bnctx);
    free(sess);
}


void *ECOMG_vrfysess_new(void *keyobj, int bitlen_clr, int bitlen_rec, int bitlen_red)
{
    ECOMG_KeyPair *keypair = (ECOMG_KeyPair*)keyobj;
    ECOMG_VrfySess *sess = malloc(sizeof(ECOMG_VrfySess));
    if (sess == NULL) return NULL;
    memset(sess, 0, sizeof(ECOMG_VrfySess));

    int bytelen_red = (bitlen_red+7)/8;
    int bytelen_clr = bitlen2bytelen(bitlen_clr);
    int bytelen_rec = bitlen2bytelen(bitlen_rec);
    int bytelen_covered = AES128CBC_fixIV_cipher_len(bytelen_rec);
    void *flag = NULL;
    flag = sess->e1_bytes = malloc(keypair->bytelen_go);if(flag==NULL) goto err;
    flag = sess->mclrcov = malloc(bytelen_clr+bytelen_covered);if(flag==NULL) goto err;
    flag = sess->e1 = BN_new();if(flag==NULL) goto err;
    flag = sess->e0 = BN_new();if(flag==NULL) goto err;
    flag = sess->e0e1 = BN_new();if(flag==NULL) goto err;
    flag = sess->z = BN_new();if(flag==NULL) goto err;
    flag = sess->a = EC_POINT_new(keypair->group);if    (flag==NULL) goto err;
    flag = sess->a_bytes = malloc(keypair->bytelen_point+1);if(flag==NULL) goto err;
    flag = sess->redun = malloc(bytelen_red);if(flag==NULL) goto err;
    flag = sess->tmpkey = malloc(keypair->bytelen_go);if(flag==NULL) goto err;
    flag = sess->m_rec = malloc(bytelen_rec);if(flag==NULL) goto err;
    flag = sess->bnctx = BN_CTX_new();if (flag==NULL) goto err;
    return sess;
err:
    ECOMG_vrfysess_free(sess);
    return NULL;
}


void ECOMG_vrfysess_free(void* obj)
{
    if (obj == NULL) return;
    ECOMG_VrfySess *sess = (ECOMG_VrfySess*)obj;
    free(sess->mclrcov);
    free(sess->e1_bytes);
    BN_free(sess->e0);
    BN_free(sess->e1);
    BN_free(sess->e0e1);
    BN_free(sess->z);
    EC_POINT_free(sess->a);
    free(sess->a_bytes);
    free(sess->redun);
    free(sess->tmpkey);
    free(sess->m_rec);
    free(sess);
}


void *ECOMG_signature_new(void *keyobj, int bitlen_clr, int bitlen_rec, int bitlen_red)
{
    ECOMG_KeyPair *keypair = (ECOMG_KeyPair*)keyobj;
    ECOMG_Sig *sig = malloc(sizeof(ECOMG_Sig));
    if (sig == NULL) return NULL;

    void *flag = NULL;
    int bytelen_red = (bitlen_red+7)/8;
    int bytelen_rec = (bitlen_rec+7)/8;
    int bytelen_covered = AES128CBC_fixIV_cipher_len(bytelen_rec);
    int bytelen_clr = (bitlen_clr+7)/8;
    int bytelen_z = keypair->bytelen_go;
    flag = sig->m_clr = malloc(bytelen_clr);if (flag==NULL) goto err;
    flag = sig->n = malloc(bytelen_covered);if (flag==NULL) goto err;
    flag = sig->redun = malloc(bytelen_red);if (flag==NULL) goto err;
    flag = sig->z_bytes = malloc(bytelen_z);if (flag==NULL) goto err;
    sig->bytelen_clr = bytelen_clr;
    sig->bytelen_covered = bytelen_covered;
    sig->bytelen_red = bytelen_red;
    sig->bytelen_z = bytelen_z;
    return sig;
err:
    ECOMG_signature_free(sig);
    return NULL;
}


void ECOMG_signature_free(void* obj)
{
    if (obj == NULL) return;
    ECOMG_Sig *sig = (ECOMG_Sig*)obj;
    free(sig->m_clr);
    free(sig->n);
    free(sig->redun);
    free(sig->z_bytes);
    free(sig);
}


/**
 * How we encode a signature in ec-omega:
 * len(m_clr) | len(covered) | len(red) | len(z) | m_clr | covered | red | z
 *      4byte        4byte        4byte      4byte
 * Lengths are in little-endian.
 */


int ECOMG_get_sig_len(int clr, int rec, int red, void *obj)
{
    ECOMG_Sig *sig = (ECOMG_Sig*)obj;
    int bytelen_clr = bitlen2bytelen(clr);
    int bytelen_red = bitlen2bytelen(red);
    int bytelen_rec = bitlen2bytelen(rec);
    return 16+bytelen_clr+bytelen_red+AES128CBC_fixIV_cipher_len(bytelen_rec)+sig->bytelen_z;
}


int ECOMG_sig_encode(int clr, int rec, int red, void *obj, char *buf)
{
    ECOMG_Sig *sig = (ECOMG_Sig*)obj;
    int bytelen_clr = bitlen2bytelen(clr);
    int bytelen_red = bitlen2bytelen(red);
    int bytelen_rec = bitlen2bytelen(rec);
    int bytelen_covered = AES128CBC_fixIV_cipher_len(bytelen_rec);
    int bytelen_z = sig->bytelen_z;

    char *c = buf;
    memcpy(c, &bytelen_clr, 4);c+=4;
    memcpy(c, &bytelen_covered, 4);c+=4;
    memcpy(c, &bytelen_red, 4);c+=4;
    memcpy(c, &bytelen_z, 4);c+=4;
    memcpy(c, sig->m_clr, bytelen_clr);c+=bytelen_clr;
    memcpy(c, sig->n, bytelen_covered);c+=bytelen_covered;
    memcpy(c, sig->redun, bytelen_red);c+=bytelen_red;
    memcpy(c, sig->z_bytes, bytelen_z);c+=bytelen_z;
    return 0;
}


int ECOMG_sign_offline(int clr, int rec, int red,
        void *keyobj, void *sessobj, void *sigobj)
{
    ECOMG_KeyPair *keys = (ECOMG_KeyPair*)keyobj;
    ECOMG_SignSess *sess = (ECOMG_SignSess*)sessobj;
    ECOMG_Sig *sig = (ECOMG_Sig*)sigobj;
    int ret;

    /* Pick r */
    ret = BN_rand_range(sess->r, keys->group_order);
    assert(ret==1);
    
    /* Compute a:=r*G mod p */
    ret = EC_POINT_mul(keys->group, sess->a, sess->r, NULL, NULL, sess->bnctx);
    assert(ret==1);

    /* Convert a into bytes */
    ret = EC_POINT_point2oct(keys->group,
            sess->a, POINT_CONVERSION_COMPRESSED,
            NULL, 0, sess->bnctx);
    assert(ret>=0);
    ret = EC_POINT_point2oct(keys->group,
            sess->a, POINT_CONVERSION_COMPRESSED,
            sess->a_bytes, ret, sess->bnctx);
    assert(ret>=0);
    int bytelen_a = ret;
    assert(bytelen_a == keys->bytelen_point);
    /* Compute redun = DDF(a) = H(a||0x00) */
    sess->a_bytes[bytelen_a] = 0x00;
    ret = VHash(sess->a_bytes, bytelen_a+1,
            sig->redun, bitlen2bytelen(red));
    assert(ret==0);

    /* Compute key = KDF(a) = H(a||0x01) */
    sess->a_bytes[bytelen_a] = 0x01;
    ret = VHash(sess->a_bytes, bytelen_a+1,
            sess->tmpkey, keys->bytelen_go);
    assert(ret==0);

    /* Convert redun to e0*/
    BIGNUM *rbn = BN_bin2bn(sig->redun, keys->bytelen_go, sess->e0);
    assert(rbn!=NULL);

    /* Compute re0w = r-e0*w */
    ret = BN_mod_mul(sess->e0w, sess->e0, keys->w,
            keys->group_order, sess->bnctx);
    assert(ret==1);

    ret = BN_mod_sub(sess->re0w, sess->r, sess->e0w,
            keys->group_order, sess->bnctx);
    assert(ret==1);

    return 0;
}


int ECOMG_sign_online(int clr, int rec, int red,
        void *keyobj, void *sessobj, void *sigobj, const char *msg, int msglen)
{
    
    ECOMG_KeyPair *keys = (ECOMG_KeyPair*)keyobj;
    ECOMG_SignSess *sess = (ECOMG_SignSess*)sessobj;
    ECOMG_Sig *sig = (ECOMG_Sig*)sigobj;
    int ret;
    int bytelen_rec = bitlen2bytelen(rec);
    int bytelen_covered = AES128CBC_fixIV_cipher_len(bytelen_rec);
    /* compute covered = Encrypt(tmpkey, m_rec) */
//    int i;
//    for (i=0; i<bytelen_rec; i++)
//        sess->covered[i] = sess->tmpkey[i]^msg[i];
    int clen;
    DoAES256CBC_fixIV(sess->tmpkey, msg, bytelen_rec, sess->covered, &clen);
    const char *m_clr = msg+bytelen_rec;
    int bytelen_clr = msglen - bytelen_rec;

    /* Compute e1_bytes = Hash(m_clr, covered) */
    memcpy(sess->d1mclr, m_clr, bytelen_clr);
    memcpy(sess->d1mclr+bytelen_clr, sess->covered, bytelen_covered);
    ret = VHash(sess->d1mclr, bytelen_clr+bytelen_covered, sess->e1_bytes, keys->bytelen_go);
    assert(ret==0);

    /* Convert e1_bytes to e1 */
    BIGNUM *rbn = BN_bin2bn(sess->e1_bytes, keys->bytelen_go, sess->e1);
    assert(rbn!=NULL);

    /* Compute z=re0w - e1*w */
    ret = BN_mod_mul(sess->e1w, sess->e1, keys->w, keys->group_order, sess->bnctx);
    assert(ret==1);
    ret = BN_mod_sub(sess->z, sess->re0w, sess->e1w, keys->group_order, sess->bnctx);
    assert(ret==1);

    BN_bn2bin(sess->z, sig->z_bytes);
    memcpy(sig->m_clr, m_clr, bytelen_clr);
    memcpy(sig->n, sess->covered, bytelen_covered);

    return 0;
}


int ECOMG_vrfy_offline(int clr, int rec, int red,
        void *keyobj, void *sessobj)
{
    return 0;
}

int ECOMG_vrfy_online(int clr, int rec, int red,
        void *keyobj, void *sessobj, void *sigobj)
{
    ECOMG_KeyPair *keys = (ECOMG_KeyPair*)keyobj;
    ECOMG_VrfySess *sess = (ECOMG_VrfySess*)sessobj;
    ECOMG_Sig *sig = (ECOMG_Sig*)sigobj;

    int ret;

    /* Derive e0 from redun. */
    BN_bin2bn(sig->redun, keys->bytelen_go, sess->e0);

    /* Derive e1 from H(m_clr||covered)*/
    memcpy(sess->mclrcov, sig->m_clr, sig->bytelen_clr);
    memcpy(sess->mclrcov+sig->bytelen_clr, sig->n, sig->bytelen_covered);
    VHash(sess->mclrcov, sig->bytelen_clr+sig->bytelen_covered,
            sess->e1_bytes, keys->bytelen_go);
    BN_bin2bn(sess->e1_bytes, keys->bytelen_go, sess->e1);

    /* Compute a=zG+(e0+e1)PK */
    BN_bin2bn(sig->z_bytes, sig->bytelen_z, sess->z);
    BN_mod_add(sess->e0e1, sess->e0, sess->e1, keys->group_order, sess->bnctx);
    EC_POINT_mul(keys->group, sess->a, sess->z, keys->h, sess->e0e1, sess->bnctx);

    /* Convert a to a_bytes */
    ret = EC_POINT_point2oct(keys->group,
            sess->a, POINT_CONVERSION_COMPRESSED,
            NULL, 0, sess->bnctx);
    assert(ret>=0);
    ret = EC_POINT_point2oct(keys->group,
            sess->a, POINT_CONVERSION_COMPRESSED,
            sess->a_bytes, ret, sess->bnctx);
    assert(ret>=0);
    int bytelen_a = ret;
    /* Compute redun=H(a_bytes||00) */
    sess->a_bytes[bytelen_a] = 0x00;
    ret = VHash(sess->a_bytes, bytelen_a+1,
            sess->redun, sig->bytelen_red);
    assert(ret==0);

    /* Check redun */
    {
        int i;
        for (i=0; i<sig->bytelen_red; i++)
            if (sig->redun[i] != sess->redun[i])
            {
                int j = 0;
                return -1;
            }
    }

    /* Compute tmpkey=H(a_bytes||01) */
    sess->a_bytes[bytelen_a] = 0x01;
    ret = VHash(sess->a_bytes, bytelen_a+1,
            sess->tmpkey, keys->bytelen_go);
    assert(ret==0);

    /* Compute m_rec = Decrypt(tmpkey, covered)*/
    //TODO
    return 0;
}


SchemeMethods ECOmegaMethods = 
{
    .mthd_keypair_new       = ECOMG_keypair_new,
    .mthd_keypair_free      = ECOMG_keypair_free,
    .mthd_keypair_gen       = ECOMG_keypair_gen,
    .mthd_get_name          = ECOMG_get_name,
    .mthd_signsess_new      = ECOMG_signsess_new,
    .mthd_signsess_free     = ECOMG_signsess_free,
    .mthd_vrfysess_new      = ECOMG_vrfysess_new,
    .mthd_vrfysess_free     = ECOMG_vrfysess_free,
    .mthd_signature_new     = ECOMG_signature_new,
    .mthd_signature_free    = ECOMG_signature_free,
    .mthd_get_sig_len       = ECOMG_get_sig_len,
    .mthd_sig_encode        = ECOMG_sig_encode,
    .mthd_sign_offline      = ECOMG_sign_offline,
    .mthd_sign_online       = ECOMG_sign_online,
    .mthd_vrfy_offline      = ECOMG_vrfy_offline,
    .mthd_vrfy_online       = ECOMG_vrfy_online
};


