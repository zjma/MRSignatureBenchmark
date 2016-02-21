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


typedef struct ECPV0_KeyPair ECPV0_KeyPair;
struct ECPV0_KeyPair
{
    EC_KEY*         eckey;
    const EC_GROUP* group;
    BIGNUM*         group_order;
    BN_RECP_CTX*    recp;
    const BIGNUM*   sk;              // private key
    const EC_POINT* PK;              // public key
    int             bytelen_go;
    int             bytelen_point;
};


typedef struct ECPV0_SignSess ECPV0_SignSess;
struct ECPV0_SignSess
{
    BIGNUM*         r;
    EC_POINT*       A;
    unsigned char*  A_bytes;
    unsigned char*  key;

    unsigned char*  recred;
    unsigned char*  mclrcov;
    unsigned char*  e_bytes;
    BIGNUM*         e;
    BIGNUM*         ew;

};


typedef struct ECPV0_VrfySess ECPV0_VrfySess;
struct ECPV0_VrfySess
{
    unsigned char*  mclrcov;
    unsigned char*  e_bytes;
    BIGNUM*         e;
    EC_POINT*       A;
    unsigned char*  A_bytes;
    unsigned char*  key;
    unsigned char*  recovered;
};


typedef struct ECPV0_Sig ECPV0_Sig;
struct ECPV0_Sig
{
    int             bytelen_clr;
    int             bytelen_covered;
    int             bytelen_z;
    unsigned char*  m_clr;
    unsigned char*  covered;
    unsigned char*  redun;
    BIGNUM*         z;
};


void *ECPV0_keypair_new(int sec);
void ECPV0_keypair_free(void *obj);
int ECPV0_keypair_gen(int sec, void *obj);
const char *ECPV0_get_name();
void *ECPV0_signsess_new(void *keyobj, int bitlen_clr, int bitlen_rec, int bitlen_red);
void ECPV0_signsess_free(void* obj);
void *ECPV0_vrfysess_new(void *keyobj, int bitlen_clr, int bitlen_rec, int bitlen_red);
void ECPV0_vrfysess_free(void* obj);
void *ECPV0_signature_new(void *keyobj, int bitlen_clr, int bitlen_rec, int bitlen_red);
void ECPV0_signature_free(void* obj);
int ECPV0_get_sig_len(int clr, int rec, int red, void *obj);
int ECPV0_sig_encode(int clr, int rec, int red, void *obj, unsigned char *buf);
int ECPV0_sign_offline(int clr, int rec, int red, void *keyobj, void *sessobj, void *sigobj);
int ECPV0_sign_online(int clr, int rec, int red, void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen);
int ECPV0_vrfy_offline(int clr, int rec, int red, void *keyobj, void *sessobj);
int ECPV0_vrfy_online(int clr, int rec, int red, void *keyobj, void *sessobj, void *sigobj);


void *ECPV0_keypair_new(int sec)
{
    BIGNUM *w = NULL;
    BIGNUM *group_order = NULL;
    BN_RECP_CTX *recp=NULL;
    EC_POINT *h = NULL;
    EC_KEY *eckey = NULL;

    ECPV0_KeyPair *ret = NULL;

    ret = malloc(sizeof(ECPV0_KeyPair));
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

    recp = BN_RECP_CTX_new();
    if (recp == NULL) goto err;

    ret->eckey = eckey;
    ret->group_order = group_order;
    ret->recp = recp;
    ret->sk = NULL;
    ret->PK = NULL;
    ret->bytelen_go = 0;
    return ret;
err:
    free(ret);
    EC_KEY_free(eckey);
    BN_free(w);
    BN_free(group_order);
    BN_RECP_CTX_free(recp);
    EC_POINT_free(h);
    return NULL;
}


void ECPV0_keypair_free(void *obj)
{
    ECPV0_KeyPair *keypair = (ECPV0_KeyPair*)obj;
    EC_KEY_free(keypair->eckey);
    BN_free(keypair->group_order);
    BN_RECP_CTX_free(keypair->recp);
    free(keypair);
}


int ECPV0_keypair_gen(int sec, void *obj)
{
    int ret = 0;

    ECPV0_KeyPair *keypair = (ECPV0_KeyPair*)obj;
    ret = EC_KEY_generate_key(keypair->eckey);
    if (ret == 0)
    {
        ret = -1;
        goto final;
    }

    const EC_GROUP *grp = EC_KEY_get0_group(keypair->eckey);
    keypair->group = grp;
    EC_GROUP_get_order(grp, keypair->group_order, bnctx);
    BN_RECP_CTX_set(keypair->recp, keypair->group_order, bnctx);
    keypair->sk = EC_KEY_get0_private_key(keypair->eckey);
    keypair->PK = EC_KEY_get0_public_key(keypair->eckey);
    keypair->bytelen_go = BN_num_bytes(keypair->group_order);
    keypair->bytelen_point = EC_POINT_point2oct(
            grp, keypair->PK, POINT_CONVERSION_COMPRESSED, NULL, 0, bnctx);
    ret = 0;

final:
    return ret;
}


const char *ECPV0_get_name()
{
    return "ECPV-xor";
}


void *ECPV0_signsess_new(void *keyobj, int bitlen_clr, int bitlen_rec, int bitlen_red)
{
    ECPV0_KeyPair *keypair = (ECPV0_KeyPair*)keyobj;

    ECPV0_SignSess *sess = malloc(sizeof(ECPV0_SignSess));
    if (sess == NULL) return NULL;

    memset(sess, 0, sizeof(ECPV0_SignSess));

    void *flag = NULL;
    flag = sess->r = BN_new();if (flag == NULL) goto err;
    flag = sess->A = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
    flag = sess->A_bytes = malloc(keypair->bytelen_point+1);if (flag == NULL) goto err;

    int bytelen_red = (bitlen_red+7)/8;
    int bytelen_rec = (bitlen_rec+7)/8;
    int bytelen_clr = (bitlen_clr+7)/8;
    int bytelen_covered = bytelen_rec+bytelen_red;
    int bytelen_tmpkey = bytelen_rec+bytelen_red;

    flag = sess->key = malloc(bytelen_tmpkey);if (flag == NULL) goto err;
    flag = sess->recred = malloc(bytelen_covered);if(flag==NULL) goto err;
    flag = sess->mclrcov = malloc(bytelen_clr + bytelen_covered);if (flag == NULL) goto err;
    flag = sess->e_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
    flag = sess->e = BN_new();if (flag == NULL) goto err;
    flag = sess->ew = BN_new();if (flag == NULL) goto err;

    return sess;
err:
    ECPV0_signsess_free(sess);
    return NULL;
}


void ECPV0_signsess_free(void* obj)
{
    if (obj == NULL) return;
    ECPV0_SignSess *sess = (ECPV0_SignSess*)obj;
    BN_free(sess->r);
    EC_POINT_free(sess->A);
    free(sess->A_bytes);
    free(sess->key);
    free(sess->recred);
    free(sess->mclrcov);
    free(sess->e_bytes);
    BN_free(sess->e);
    BN_free(sess->ew);
    free(sess);
}


void *ECPV0_vrfysess_new(void *keyobj, int bitlen_clr, int bitlen_rec, int bitlen_red)
{
    ECPV0_KeyPair *keypair = (ECPV0_KeyPair*)keyobj;
    ECPV0_VrfySess *sess = malloc(sizeof(ECPV0_VrfySess));
    if (sess == NULL) return NULL;
    memset(sess, 0, sizeof(ECPV0_VrfySess));

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
    flag = sess->key = malloc(bytelen_tmpkey);if(flag==NULL) goto err;
    flag = sess->recovered = malloc(bytelen_covered);if(flag==NULL) goto err;
    return sess;
err:
    ECPV0_vrfysess_free(sess);
    return NULL;
}


void ECPV0_vrfysess_free(void* obj)
{
    if (obj == NULL) return;
    ECPV0_VrfySess *sess = (ECPV0_VrfySess*)obj;
    free(sess->mclrcov);
    free(sess->e_bytes);
    BN_free(sess->e);
    EC_POINT_free(sess->A);
    free(sess->A_bytes);
    free(sess->key);
    free(sess->recovered);
    free(sess);
}


void *ECPV0_signature_new(void *keyobj, int bitlen_clr, int bitlen_rec, int bitlen_red)
{
    ECPV0_KeyPair *keypair = (ECPV0_KeyPair*)keyobj;
    ECPV0_Sig *sig = malloc(sizeof(ECPV0_Sig));
    if (sig == NULL) return NULL;

    void *flag = NULL;
    int bytelen_red = (bitlen_red+7)/8;
    int bytelen_rec = (bitlen_rec+7)/8;
    int bytelen_covered = bytelen_red+bytelen_rec;
    int bytelen_clr = (bitlen_clr+7)/8;
    flag = sig->m_clr = malloc(bytelen_clr);if (flag==NULL) goto err;
    flag = sig->covered = malloc(bytelen_covered);if (flag==NULL) goto err;
    flag = sig->z = BN_new();if (flag==NULL) goto err;
    flag = sig->redun = calloc(1,bytelen_red);if (flag==NULL) goto err;
    sig->bytelen_clr = bytelen_clr;
    sig->bytelen_covered = bytelen_covered;
    return sig;
err:
    ECPV0_signature_free(sig);
    return NULL;
}


void ECPV0_signature_free(void* obj)
{
    if (obj == NULL) return;
    ECPV0_Sig *sig = (ECPV0_Sig*)obj;
    free(sig->m_clr);
    free(sig->covered);
    BN_free(sig->z);
    free(sig->redun);
    free(sig);
}


/**
 * How we encode a signature in ec-omega:
 * len(m_clr) | len(covered) | len(red) | len(z) | m_clr | covered | red | z
 *      4byte        4byte        4byte      4byte
 * Lengths are in little-endian.
 */


int ECPV0_get_sig_len(int clr, int rec, int red, void *obj)
{
    ECPV0_Sig *sig = (ECPV0_Sig*)obj;
    int bytelen_clr = bitlen2bytelen(clr);
    int bytelen_red = bitlen2bytelen(red);
    int bytelen_rec = bitlen2bytelen(rec);
    return 16+bytelen_clr+2*bytelen_red+bytelen_rec+sig->bytelen_z;
}


int ECPV0_sig_encode(int clr, int rec, int red, void *obj, unsigned char *buf)
{
    ECPV0_Sig *sig = (ECPV0_Sig*)obj;
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


int ECPV0_sign_offline(int clr, int rec, int red,
        void *keyobj, void *sessobj, void *sigobj)
{
    /* Rename objests. */
    ECPV0_KeyPair *keys = (ECPV0_KeyPair*)keyobj;
    ECPV0_SignSess *sess = (ECPV0_SignSess*)sessobj;
    ECPV0_Sig *sig = (ECPV0_Sig*)sigobj;
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
            sess->A_bytes, ret, bnctx);
    assert(ret>=0);
    int bytelen_A = ret;
    assert(bytelen_A == keys->bytelen_point);

    /* Gen key */
    PRG(sess->A_bytes, bytelen_A, sess->key, bytelen_tmpkey);

    return 0;
}


int ECPV0_sign_online(int clr, int rec, int red,
        void *keyobj, void *sessobj, void *sigobj,
        const unsigned char *msg, int msglen)
{
    /* Rename objects. */
    ECPV0_KeyPair *keys = (ECPV0_KeyPair*)keyobj;
    ECPV0_SignSess *sess = (ECPV0_SignSess*)sessobj;
    ECPV0_Sig *sig = (ECPV0_Sig*)sigobj;
    int ret;

    /* Name some parameters. */
    int bytelen_rec = bitlen2bytelen(rec);
    int bytelen_red = bitlen2bytelen(red);
    int bytelen_covered = bytelen_rec+bytelen_red;
    const unsigned char *m_clr = msg+bytelen_rec;
    int bytelen_clr = msglen - bytelen_rec;
    const unsigned char *m_rec = msg;

    /* Compute covered = tmpkey XOR m_rec||m_red */
    memcpy(sess->recred, m_rec, bytelen_rec);
    memset(sess->recred+bytelen_rec, 0, bytelen_red);
    BinXor(sess->key, sess->recred, sig->covered, bytelen_covered);

    /* Compute e_bytes = Hash(m_clr, covered) */
    memcpy(sess->mclrcov, m_clr, bytelen_clr);
    memcpy(sess->mclrcov+bytelen_clr, sig->covered, bytelen_covered);
    ret = PRG(sess->mclrcov, bytelen_clr+bytelen_covered, sess->e_bytes, keys->bytelen_go);
    assert(ret==0);

    /* Convert e_bytes to e */
    BN_bin2bn(sess->e_bytes, keys->bytelen_go, sess->e);

    /* Compute z=r-e*w */
//    ret = BN_mod_mul(sess->ew, sess->e, keys->sk, keys->group_order, bnctx);
    ret = BN_mod_mul_reciprocal(sess->ew, sess->e, keys->sk, keys->recp, bnctx);
    assert(ret==1);
    ret = BN_mod_sub(sig->z, sess->r, sess->ew, keys->group_order, bnctx);
    assert(ret==1);

    memcpy(sig->m_clr, m_clr, bytelen_clr);

    return 0;
}


int ECPV0_vrfy_offline(int clr, int rec, int red,
        void *keyobj, void *sessobj)
{
    return 0;
}

int ECPV0_vrfy_online(int clr, int rec, int red,
        void *keyobj, void *sessobj, void *sigobj)
{
    /* Rename objects. */
    ECPV0_KeyPair *keys = (ECPV0_KeyPair*)keyobj;
    ECPV0_VrfySess *sess = (ECPV0_VrfySess*)sessobj;
    ECPV0_Sig *sig = (ECPV0_Sig*)sigobj;
    int ret;

    /* Name some parameters. */
    int bytelen_red = bitlen2bytelen(red);
    int bytelen_rec = bitlen2bytelen(rec);
    int bytelen_tmpkey = bytelen_red+bytelen_rec;

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
    int bytelen_a = ret;

    /* Gen materials for tmpkey. */
    PRG(sess->A_bytes, bytelen_a, sess->key, bytelen_tmpkey);

    /* Compute m_rec||m_red = tmpkey XOR covered*/
    BinXor(sess->key, sig->covered, sess->recovered, bytelen_tmpkey);

    /* Check redun */
    ret = memcmp(sess->recovered+bytelen_rec, sig->redun, bytelen_red);
    if (ret != 0) return -1;

    return 0;
}


SchemeMethods ECPV0_Methods =
{
    .mthd_keypair_new       = ECPV0_keypair_new,
    .mthd_keypair_free      = ECPV0_keypair_free,
    .mthd_keypair_gen       = ECPV0_keypair_gen,
    .mthd_get_name          = ECPV0_get_name,
    .mthd_signsess_new      = ECPV0_signsess_new,
    .mthd_signsess_free     = ECPV0_signsess_free,
    .mthd_vrfysess_new      = ECPV0_vrfysess_new,
    .mthd_vrfysess_free     = ECPV0_vrfysess_free,
    .mthd_signature_new     = ECPV0_signature_new,
    .mthd_signature_free    = ECPV0_signature_free,
    .mthd_get_sig_len       = ECPV0_get_sig_len,
    .mthd_sig_encode        = ECPV0_sig_encode,
    .mthd_sign_offline      = ECPV0_sign_offline,
    .mthd_sign_online       = ECPV0_sign_online,
    .mthd_vrfy_offline      = ECPV0_vrfy_offline,
    .mthd_vrfy_online       = ECPV0_vrfy_online
};


