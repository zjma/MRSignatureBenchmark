#include <time.h>
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


typedef struct ECAO_KeyPair ECAO_KeyPair;
struct ECAO_KeyPair
{
    EC_KEY*         eckey;
    const EC_GROUP* group;
    BIGNUM*         group_order;
    const BIGNUM*   sk;              // private key
    const EC_POINT* PK;              // public key
    int             bytelen_go;
    int             bytelen_point;
};


typedef struct ECAO_SignSess ECAO_SignSess;
struct ECAO_SignSess
{
    BIGNUM*         r;
    EC_POINT*       A;
    int             bytelen_A;
    unsigned char*  Abytes_n_rec;
    unsigned char*  Abytes_n_red;
    unsigned char*  hv2;
    unsigned char*  h2;
    unsigned char*  mclrcov;
    unsigned char*  e_bytes;
    BIGNUM*         e;
    BIGNUM*         ew;

};


typedef struct ECAO_VrfySess ECAO_VrfySess;
struct ECAO_VrfySess
{
    unsigned char*  mclrcov;
    unsigned char*  e_bytes;
    BIGNUM*         e;
    EC_POINT*       A;
    unsigned char*  A_bytes;
    unsigned char*  Abytes_n_red;
    unsigned char*  Abytes_n_rec;
    unsigned char*  hv2;
    unsigned char*  red;
};


typedef struct ECAO_Sig ECAO_Sig;
struct ECAO_Sig
{
    int             bytelen_clr;
    int             bytelen_covered;
    int             bytelen_z;
    unsigned char*  m_clr;
    unsigned char*  covered;
    BIGNUM*         z;
};


void *ECAO_keypair_new(int sec);
void ECAO_keypair_free(void *obj);
int ECAO_keypair_gen(int sec, void *obj);
const char *ECAO_get_name();
void *ECAO_signsess_new(void *keyobj, int bitlen_clr, int bitlen_rec, int bitlen_red);
void ECAO_signsess_free(void* obj);
void *ECAO_vrfysess_new(void *keyobj, int bitlen_clr, int bitlen_rec, int bitlen_red);
void ECAO_vrfysess_free(void* obj);
void *ECAO_signature_new(void *keyobj, int bitlen_clr, int bitlen_rec, int bitlen_red);
void ECAO_signature_free(void* obj);
int ECAO_get_sig_len(int clr, int rec, int red, void *obj);
int ECAO_sig_encode(int clr, int rec, int red, void *obj, unsigned char *buf);
int ECAO_sign_offline(int clr, int rec, int red, void *keyobj, void *sessobj, void *sigobj);
int ECAO_sign_online(int clr, int rec, int red, void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen);
int ECAO_vrfy_offline(int clr, int rec, int red, void *keyobj, void *sessobj);
int ECAO_vrfy_online(int clr, int rec, int red, void *keyobj, void *sessobj, void *sigobj);


void *ECAO_keypair_new(int sec)
{
    BIGNUM *w = NULL;
    BIGNUM *group_order = NULL;
    EC_POINT *h = NULL;
    EC_KEY *eckey = NULL;

    ECAO_KeyPair *ret = NULL;

    ret = malloc(sizeof(ECAO_KeyPair));
    if (ret == NULL) goto err;

    switch(sec)
    {
        case 160:
            eckey = EC_KEY_new_by_curve_name(CURVE160);
            break;
        case 192:
            eckey = EC_KEY_new_by_curve_name(CURVE192);
            break;
        case 224:
            eckey = EC_KEY_new_by_curve_name(CURVE224);
            break;
        case 256:
            eckey = EC_KEY_new_by_curve_name(CURVE256);
            break;
        case 384:
            eckey = EC_KEY_new_by_curve_name(CURVE384);
            break;
        case 521:
            eckey = EC_KEY_new_by_curve_name(CURVE521);
            break;
        default:
            eckey = NULL;
    }
    if (eckey == NULL) goto err;

    group_order = BN_new();
    if (group_order == NULL) goto err;

    ret->eckey = eckey;
    ret->group_order = group_order;
    ret->sk = NULL;
    ret->PK = NULL;
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


void ECAO_keypair_free(void *obj)
{
    ECAO_KeyPair *keypair = (ECAO_KeyPair*)obj;
    EC_KEY_free(keypair->eckey);
    BN_free(keypair->group_order);
    free(keypair);
}


int ECAO_keypair_gen(int sec, void *obj)
{
    int ret = 0;

    ECAO_KeyPair *keypair = (ECAO_KeyPair*)obj;
    ret = EC_KEY_generate_key(keypair->eckey);
    if (ret == 0)
    {
        ret = -1;
        goto final;
    }

    const EC_GROUP *grp = EC_KEY_get0_group(keypair->eckey);
    keypair->group = grp;
    EC_GROUP_get_order(grp, keypair->group_order, bnctx);
    keypair->sk = EC_KEY_get0_private_key(keypair->eckey);
    keypair->PK = EC_KEY_get0_public_key(keypair->eckey);
    keypair->bytelen_go = BN_num_bytes(keypair->group_order);
    keypair->bytelen_point = EC_POINT_point2oct(
            grp, keypair->PK, POINT_CONVERSION_COMPRESSED, NULL, 0, bnctx);
    ret = 0;

final:
    return ret;
}


const char *ECAO_get_name()
{
    return "ECAO-paper-version";
}


void *ECAO_signsess_new(void *keyobj, int bitlen_clr, int bitlen_rec, int bitlen_red)
{
    ECAO_KeyPair *keypair = (ECAO_KeyPair*)keyobj;

    ECAO_SignSess *sess = malloc(sizeof(ECAO_SignSess));
    if (sess == NULL) return NULL;
    int bytelen_red = (bitlen_red+7)/8;
    int bytelen_rec = (bitlen_rec+7)/8;
    int bytelen_clr = (bitlen_clr+7)/8;
    int bytelen_covered = bytelen_rec+bytelen_red;

    memset(sess, 0, sizeof(ECAO_SignSess));

    void *flag = NULL;
    flag = sess->r = BN_new();if (flag == NULL) goto err;
    flag = sess->A = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
    flag = sess->Abytes_n_rec = malloc(keypair->bytelen_point+bytelen_rec);if (flag == NULL) goto err;
    flag = sess->Abytes_n_red = malloc(keypair->bytelen_point+bytelen_red);if (flag == NULL) goto err;

    flag = sess->hv2 = malloc(bytelen_rec);if(flag==NULL) goto err;
    flag = sess->h2 = malloc(bytelen_rec);if(flag==NULL) goto err;
    flag = sess->mclrcov = malloc(bytelen_clr + bytelen_covered);if (flag == NULL) goto err;
    flag = sess->e_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
    flag = sess->e = BN_new();if (flag == NULL) goto err;
    flag = sess->ew = BN_new();if (flag == NULL) goto err;

    return sess;
err:
    ECAO_signsess_free(sess);
    return NULL;
}


void ECAO_signsess_free(void* obj)
{
    if (obj == NULL) return;
    ECAO_SignSess *sess = (ECAO_SignSess*)obj;
    BN_free(sess->r);
    EC_POINT_free(sess->A);
    free(sess->Abytes_n_rec);
    free(sess->Abytes_n_red);
    free(sess->hv2);
    free(sess->h2);
    free(sess->mclrcov);
    free(sess->e_bytes);
    BN_free(sess->e);
    BN_free(sess->ew);
    free(sess);
}


void *ECAO_vrfysess_new(void *keyobj, int bitlen_clr, int bitlen_rec, int bitlen_red)
{
    ECAO_KeyPair *keypair = (ECAO_KeyPair*)keyobj;
    ECAO_VrfySess *sess = malloc(sizeof(ECAO_VrfySess));
    if (sess == NULL) return NULL;
    memset(sess, 0, sizeof(ECAO_VrfySess));

    int bytelen_red = (bitlen_red+7)/8;
    int bytelen_clr = bitlen2bytelen(bitlen_clr);
    int bytelen_rec = bitlen2bytelen(bitlen_rec);
    int bytelen_covered = bytelen_red+bytelen_rec;
    int bytelen_tmpkey = bytelen_covered;
    void *flag = NULL;
    flag = sess->e_bytes = malloc(keypair->bytelen_go);if(flag==NULL) goto err;
    flag = sess->mclrcov = malloc(bytelen_clr+bytelen_covered);if(flag==NULL) goto err;
    flag = sess->e = BN_new();if(flag==NULL) goto err;
    flag = sess->A = EC_POINT_new(keypair->group);if    (flag==NULL) goto err;
    flag = sess->A_bytes = malloc(keypair->bytelen_point+1);if(flag==NULL) goto err;
    flag = sess->Abytes_n_rec = malloc(keypair->bytelen_point+bytelen_rec);if(flag==NULL) goto err;
    flag = sess->Abytes_n_red = malloc(keypair->bytelen_point+bytelen_red);if(flag==NULL) goto err;
    flag = sess->hv2 = malloc(bytelen_rec);if(flag==NULL) goto err;
    flag = sess->red = malloc(bytelen_red);if(flag==NULL) goto err;
    return sess;
err:
    ECAO_vrfysess_free(sess);
    return NULL;
}


void ECAO_vrfysess_free(void* obj)
{
    if (obj == NULL) return;
    ECAO_VrfySess *sess = (ECAO_VrfySess*)obj;
    free(sess->mclrcov);
    free(sess->e_bytes);
    BN_free(sess->e);
    EC_POINT_free(sess->A);
    free(sess->A_bytes);
    free(sess->Abytes_n_red);
    free(sess->Abytes_n_rec);
    free(sess->hv2);
    free(sess->red);
    free(sess);
}


void *ECAO_signature_new(void *keyobj, int bitlen_clr, int bitlen_rec, int bitlen_red)
{
    ECAO_KeyPair *keypair = (ECAO_KeyPair*)keyobj;
    ECAO_Sig *sig = malloc(sizeof(ECAO_Sig));
    if (sig == NULL) return NULL;

    void *flag = NULL;
    int bytelen_red = (bitlen_red+7)/8;
    int bytelen_rec = (bitlen_rec+7)/8;
    int bytelen_covered = bytelen_red+bytelen_rec;
    int bytelen_clr = (bitlen_clr+7)/8;
    flag = sig->m_clr = malloc(bytelen_clr);if (flag==NULL) goto err;
    flag = sig->covered = malloc(bytelen_covered);if (flag==NULL) goto err;
    flag = sig->z = BN_new();if (flag==NULL) goto err;
    sig->bytelen_clr = bytelen_clr;
    sig->bytelen_covered = bytelen_covered;
    return sig;
err:
    ECAO_signature_free(sig);
    return NULL;
}


void ECAO_signature_free(void* obj)
{
    if (obj == NULL) return;
    ECAO_Sig *sig = (ECAO_Sig*)obj;
    free(sig->m_clr);
    free(sig->covered);
    BN_free(sig->z);
    free(sig);
}


/**
 * How we encode a signature in ec-omega:
 * len(m_clr) | len(covered) | len(red) | len(z) | m_clr | covered | red | z
 *      4byte        4byte        4byte      4byte
 * Lengths are in little-endian.
 */


int ECAO_get_sig_len(int clr, int rec, int red, void *obj)
{
    ECAO_Sig *sig = (ECAO_Sig*)obj;
    int bytelen_clr = bitlen2bytelen(clr);
    int bytelen_red = bitlen2bytelen(red);
    int bytelen_rec = bitlen2bytelen(rec);
    return 16+bytelen_clr+2*bytelen_red+bytelen_rec+sig->bytelen_z;
}


int ECAO_sig_encode(int clr, int rec, int red, void *obj, unsigned char *buf)
{
    ECAO_Sig *sig = (ECAO_Sig*)obj;
    int bytelen_clr = bitlen2bytelen(clr);
    int bytelen_red = bitlen2bytelen(red);
    int bytelen_rec = bitlen2bytelen(rec);
    int bytelen_covered = bytelen_rec+bytelen_red;
    int bytelen_z = sig->bytelen_z;

    unsigned char *c = buf;
    memcpy(c, &bytelen_clr, 4);c+=4;
    memcpy(c, &bytelen_covered, 4);c+=4;
    memcpy(c, &bytelen_red, 4);c+=4;
    memcpy(c, &bytelen_z, 4);c+=4;
    memcpy(c, sig->m_clr, bytelen_clr);c+=bytelen_clr;
    memcpy(c, sig->covered, bytelen_covered);c+=bytelen_covered;
    return 0;
}


int ECAO_sign_offline(int clr, int rec, int red,
        void *keyobj, void *sessobj, void *sigobj)
{
    /* Rename objests. */
    ECAO_KeyPair *keys = (ECAO_KeyPair*)keyobj;
    ECAO_SignSess *sess = (ECAO_SignSess*)sessobj;
    ECAO_Sig *sig = (ECAO_Sig*)sigobj;
    int ret;

    /* Name some parameters. */
    int bytelen_rec = bitlen2bytelen(rec);
    int bytelen_red = bitlen2bytelen(red);
    int bytelen_tmpkey = bytelen_rec+bytelen_red;

    /* Pick r */
    ret = BN_rand_range(sess->r, keys->group_order);
    assert(ret==1);
    
    /* Compute A = rG */
    ret = EC_POINT_mul(keys->group, sess->A, sess->r, NULL, NULL, bnctx);
    assert(ret==1);

    /* Convert A into bytes */
    ret = EC_POINT_point2oct(keys->group,
            sess->A, POINT_CONVERSION_COMPRESSED,
            NULL, 0, bnctx);
    assert(ret>=0);
    ret = EC_POINT_point2oct(keys->group,
            sess->A, POINT_CONVERSION_COMPRESSED,
            sess->Abytes_n_rec, ret, bnctx);
    assert(ret>=0);
    sess->bytelen_A = ret;
    assert(sess->bytelen_A == keys->bytelen_point);

    memcpy(sess->Abytes_n_red, sess->Abytes_n_rec, sess->bytelen_A);

    return 0;
}


int ECAO_sign_online(int clr, int rec, int red,
        void *keyobj, void *sessobj, void *sigobj,
        const unsigned char *msg, int msglen)
{
    /* Rename objects. */
    ECAO_KeyPair *keys = (ECAO_KeyPair*)keyobj;
    ECAO_SignSess *sess = (ECAO_SignSess*)sessobj;
    ECAO_Sig *sig = (ECAO_Sig*)sigobj;
    int ret;

    /* Name some parameters. */
    int bytelen_rec = bitlen2bytelen(rec);
    int bytelen_red = bitlen2bytelen(red);
    int bytelen_covered = bytelen_rec+bytelen_red;
    const unsigned char *m_clr = msg+bytelen_rec;
    int bytelen_clr = msglen - bytelen_rec;
    const unsigned char *m_rec = msg;
    unsigned char *h2 = sig->covered+bytelen_red;

    /* Compute red = H1(Abytes||m_rec) */
    memcpy(sess->Abytes_n_rec+sess->bytelen_A, m_rec, bytelen_rec);
    PRG(sess->Abytes_n_rec, sess->bytelen_A+bytelen_rec,
            sig->covered, bytelen_red);

    /* Compute hv2 = H2(Abytes||red)*/
    memcpy(sess->Abytes_n_red+sess->bytelen_A, sig->covered, bytelen_red);
    PRG(sess->Abytes_n_red, sess->bytelen_A+bytelen_red,
            sess->hv2, bytelen_rec);

    /* h2 = hv2 XOR m_rec */
    BinXor(sess->hv2, m_rec, sess->h2, bytelen_rec);
    memcpy(sig->covered+bytelen_red, sess->h2, bytelen_rec);

    /* Compute e_bytes = H(m_clr||covered) */
    memcpy(sess->mclrcov, m_clr, bytelen_clr);
    memcpy(sess->mclrcov+bytelen_clr, sig->covered, bytelen_covered);
    PRG(sess->mclrcov, bytelen_clr+bytelen_covered, sess->e_bytes, keys->bytelen_go);

    /* Convert e_bytes to e */
    BN_bin2bn(sess->e_bytes, keys->bytelen_go, sess->e);

    /* Compute z=r-e*w */
    ret = BN_mod_mul(sess->ew, sess->e, keys->sk, keys->group_order, bnctx);
    assert(ret==1);
    ret = BN_mod_sub(sig->z, sess->r, sess->ew, keys->group_order, bnctx);
    assert(ret==1);

    memcpy(sig->m_clr, m_clr, bytelen_clr);

    return 0;
}


int ECAO_vrfy_offline(int clr, int rec, int red,
        void *keyobj, void *sessobj)
{
    return 0;
}

int ECAO_vrfy_online(int clr, int rec, int red,
        void *keyobj, void *sessobj, void *sigobj)
{
    /* Rename objects. */
    ECAO_KeyPair *keys = (ECAO_KeyPair*)keyobj;
    ECAO_VrfySess *sess = (ECAO_VrfySess*)sessobj;
    ECAO_Sig *sig = (ECAO_Sig*)sigobj;
    int ret;

    /* Name some parameters. */
    int bytelen_red = bitlen2bytelen(red);
    int bytelen_rec = bitlen2bytelen(rec);
    int bytelen_tmpkey = bytelen_red+bytelen_rec;
    unsigned char *m_rec = sess->Abytes_n_rec+keys->bytelen_point;

    /* Compute e = H(m_clr||covered)*/
    memcpy(sess->mclrcov, sig->m_clr, sig->bytelen_clr);
    memcpy(sess->mclrcov+sig->bytelen_clr, sig->covered, sig->bytelen_covered);
    PRG(sess->mclrcov, sig->bytelen_clr+sig->bytelen_covered,
            sess->e_bytes, keys->bytelen_go);
    BN_bin2bn(sess->e_bytes, keys->bytelen_go, sess->e);

    /* Compute a=z*G+e*PK */
    EC_POINT_mul(keys->group, sess->A, sig->z, keys->PK, sess->e, bnctx);

    /* Convert a to a_bytes */
    ret = EC_POINT_point2oct(keys->group,
            sess->A, POINT_CONVERSION_COMPRESSED,
            NULL, 0, bnctx);
    assert(ret>=0);
    ret = EC_POINT_point2oct(keys->group,
            sess->A, POINT_CONVERSION_COMPRESSED,
            sess->A_bytes, ret, bnctx);
    assert(ret>=0);
    int bytelen_A = ret;
    assert(bytelen_A==keys->bytelen_point);
    /* hv2 = H2(Abytes||red)*/
    memcpy(sess->Abytes_n_red, sess->A_bytes, bytelen_A);
    memcpy(sess->Abytes_n_red+bytelen_A, sig->covered, bytelen_red);
    PRG(sess->Abytes_n_red, bytelen_A+bytelen_red, sess->hv2, bytelen_rec);

    /* m_rec = hv2 XOR h2 */
    BinXor(sess->hv2, sig->covered+bytelen_red, m_rec, bytelen_rec);

    /* red = H1(Abytes||m_rec) */
    memcpy(sess->Abytes_n_rec, sess->A_bytes, bytelen_A);
    PRG(sess->Abytes_n_rec, bytelen_A+bytelen_rec, sess->red, bytelen_red);

    /* Check redun */
    ret = memcmp(sess->red, sig->covered, bytelen_red);
    if (ret != 0) return -1;

    return 0;
}


SchemeMethods ECAO_Methods =
{
    .mthd_keypair_new       = ECAO_keypair_new,
    .mthd_keypair_free      = ECAO_keypair_free,
    .mthd_keypair_gen       = ECAO_keypair_gen,
    .mthd_get_name          = ECAO_get_name,
    .mthd_signsess_new      = ECAO_signsess_new,
    .mthd_signsess_free     = ECAO_signsess_free,
    .mthd_vrfysess_new      = ECAO_vrfysess_new,
    .mthd_vrfysess_free     = ECAO_vrfysess_free,
    .mthd_signature_new     = ECAO_signature_new,
    .mthd_signature_free    = ECAO_signature_free,
    .mthd_get_sig_len       = ECAO_get_sig_len,
    .mthd_sig_encode        = ECAO_sig_encode,
    .mthd_sign_offline      = ECAO_sign_offline,
    .mthd_sign_online       = ECAO_sign_online,
    .mthd_vrfy_offline      = ECAO_vrfy_offline,
    .mthd_vrfy_online       = ECAO_vrfy_online
};


