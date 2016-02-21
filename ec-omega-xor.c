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


typedef struct ECOMG1_KeyPair ECOMG1_KeyPair;
struct ECOMG1_KeyPair
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


typedef struct ECOMG1_SignSess ECOMG1_SignSess;
struct ECOMG1_SignSess
{
    BIGNUM*         r;
    EC_POINT*       A;
    unsigned char*  A_bytes;
    unsigned char*  red_n_key;
    BIGNUM*         e0;
    BIGNUM*         e0w;
    BIGNUM*         re0w;

    unsigned char*  mclrcov;
    unsigned char*  e1_bytes;
    BIGNUM*         e1;
    BIGNUM*         e1w;

};


typedef struct ECOMG1_VrfySess ECOMG1_VrfySess;
struct ECOMG1_VrfySess
{
    BIGNUM*         e0;
    unsigned char*  mclrcov;
    unsigned char*  e1_bytes;
    BIGNUM*         e1;
    BIGNUM*         e0e1;
    EC_POINT*       A;
    unsigned char*  A_bytes;
    unsigned char*  red_n_key;
    unsigned char*  m_rec;
    int             bytelen_rec;
};


typedef struct ECOMG1_Sig ECOMG1_Sig;
struct ECOMG1_Sig
{
    int             bytelen_clr;
    int             bytelen_covered;
    int             bytelen_red;
    int             bytelen_z;
    unsigned char*  m_clr;
    unsigned char*  covered;
    unsigned char*  redun;
    BIGNUM*         z;
};


void *ECOMG1_keypair_new(int sec);
void ECOMG1_keypair_free(void *obj);
int ECOMG1_keypair_gen(int sec, void *obj);
const char *ECOMG1_get_name();
void *ECOMG1_signsess_new(void *keyobj, int bitlen_clr, int bitlen_rec, int bitlen_red);
void ECOMG1_signsess_free(void* obj);
void *ECOMG1_vrfysess_new(void *keyobj, int bitlen_clr, int bitlen_rec, int bitlen_red);
void ECOMG1_vrfysess_free(void* obj);
void *ECOMG1_signature_new(void *keyobj, int bitlen_clr, int bitlen_rec, int bitlen_red);
void ECOMG1_signature_free(void* obj);
int ECOMG1_get_sig_len(int clr, int rec, int red, void *obj);
int ECOMG1_sig_encode(int clr, int rec, int red, void *obj, unsigned char *buf);
int ECOMG1_sign_offline(int clr, int rec, int red, void *keyobj, void *sessobj, void *sigobj);
int ECOMG1_sign_online(int clr, int rec, int red, void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen);
int ECOMG1_vrfy_offline(int clr, int rec, int red, void *keyobj, void *sessobj);
int ECOMG1_vrfy_online(int clr, int rec, int red, void *keyobj, void *sessobj, void *sigobj);


void *ECOMG1_keypair_new(int sec)
{
    BIGNUM *w = NULL;
    BIGNUM *group_order = NULL;
    BN_RECP_CTX *recp=NULL;
    EC_POINT *h = NULL;
    EC_KEY *eckey = NULL;

    ECOMG1_KeyPair *ret = NULL;

    ret = malloc(sizeof(ECOMG1_KeyPair));
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


void ECOMG1_keypair_free(void *obj)
{
    ECOMG1_KeyPair *keypair = (ECOMG1_KeyPair*)obj;
    EC_KEY_free(keypair->eckey);
    BN_free(keypair->group_order);
    BN_RECP_CTX_free(keypair->recp);
    free(keypair);
}


int ECOMG1_keypair_gen(int sec, void *obj)
{
    int ret = 0;

    ECOMG1_KeyPair *keypair = (ECOMG1_KeyPair*)obj;
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


const char *ECOMG1_get_name()
{
    return "ECOMG-xor";
}


void *ECOMG1_signsess_new(void *keyobj, int bitlen_clr, int bitlen_rec, int bitlen_red)
{
    ECOMG1_KeyPair *keypair = (ECOMG1_KeyPair*)keyobj;

    ECOMG1_SignSess *sess = malloc(sizeof(ECOMG1_SignSess));
    if (sess == NULL) return NULL;

    memset(sess, 0, sizeof(ECOMG1_SignSess));

    void *flag = NULL;
    flag = sess->r = BN_new();if (flag == NULL) goto err;
    flag = sess->A = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
    flag = sess->A_bytes = malloc(keypair->bytelen_point+1);if (flag == NULL) goto err;

    int bytelen_red = (bitlen_red+7)/8;
    int bytelen_rec = (bitlen_rec+7)/8;
    int bytelen_covered = bytelen_rec;
    int bytelen_clr = (bitlen_clr+7)/8;
    int bytelen_tmpkey = bytelen_rec;

    flag = sess->red_n_key = malloc(bytelen_red+bytelen_tmpkey);if (flag == NULL) goto err;
    flag = sess->e0 = BN_new();if (flag == NULL) goto err;
    flag = sess->e0w = BN_new();if (flag == NULL) goto err;
    flag = sess->re0w = BN_new();if (flag == NULL) goto err;

    flag = sess->mclrcov = malloc(bytelen_clr + bytelen_covered);if (flag == NULL) goto err;
    flag = sess->e1_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
    flag = sess->e1 = BN_new();if (flag == NULL) goto err;
    flag = sess->e1w = BN_new();if (flag == NULL) goto err;

    return sess;
err:
    ECOMG1_signsess_free(sess);
    return NULL;
}


void ECOMG1_signsess_free(void* obj)
{
    if (obj == NULL) return;
    ECOMG1_SignSess *sess = (ECOMG1_SignSess*)obj;
    BN_free(sess->r);
    EC_POINT_free(sess->A);
    free(sess->A_bytes);
    free(sess->red_n_key);
    BN_free(sess->e0);
    BN_free(sess->e0w);
    BN_free(sess->re0w);
    free(sess->mclrcov);
    free(sess->e1_bytes);
    BN_free(sess->e1);
    BN_free(sess->e1w);
    free(sess);
}


void *ECOMG1_vrfysess_new(void *keyobj, int bitlen_clr, int bitlen_rec, int bitlen_red)
{
    ECOMG1_KeyPair *keypair = (ECOMG1_KeyPair*)keyobj;
    ECOMG1_VrfySess *sess = malloc(sizeof(ECOMG1_VrfySess));
    if (sess == NULL) return NULL;
    memset(sess, 0, sizeof(ECOMG1_VrfySess));

    int bytelen_red = (bitlen_red+7)/8;
    int bytelen_clr = bitlen2bytelen(bitlen_clr);
    int bytelen_rec = bitlen2bytelen(bitlen_rec);
    int bytelen_covered = bytelen_rec;
    int bytelen_tmpkey = bytelen_rec+bytelen_clr;
    void *flag = NULL;
    flag = sess->e1_bytes = malloc(keypair->bytelen_go);if(flag==NULL) goto err;
    flag = sess->mclrcov = malloc(bytelen_clr+bytelen_covered);if(flag==NULL) goto err;
    flag = sess->e1 = BN_new();if(flag==NULL) goto err;
    flag = sess->e0 = BN_new();if(flag==NULL) goto err;
    flag = sess->e0e1 = BN_new();if(flag==NULL) goto err;
    flag = sess->A = EC_POINT_new(keypair->group);if    (flag==NULL) goto err;
    flag = sess->A_bytes = malloc(keypair->bytelen_point+1);if(flag==NULL) goto err;
    flag = sess->red_n_key = malloc(bytelen_red+bytelen_tmpkey);if(flag==NULL) goto err;
    flag = sess->m_rec = malloc(bytelen_rec);if(flag==NULL) goto err;
    return sess;
err:
    ECOMG1_vrfysess_free(sess);
    return NULL;
}


void ECOMG1_vrfysess_free(void* obj)
{
    if (obj == NULL) return;
    ECOMG1_VrfySess *sess = (ECOMG1_VrfySess*)obj;
    free(sess->mclrcov);
    free(sess->e1_bytes);
    BN_free(sess->e0);
    BN_free(sess->e1);
    BN_free(sess->e0e1);
    EC_POINT_free(sess->A);
    free(sess->A_bytes);
    free(sess->red_n_key);
    free(sess->m_rec);
    free(sess);
}


void *ECOMG1_signature_new(void *keyobj, int bitlen_clr, int bitlen_rec, int bitlen_red)
{
    ECOMG1_KeyPair *keypair = (ECOMG1_KeyPair*)keyobj;
    ECOMG1_Sig *sig = malloc(sizeof(ECOMG1_Sig));
    if (sig == NULL) return NULL;

    void *flag = NULL;
    int bytelen_red = (bitlen_red+7)/8;
    int bytelen_rec = (bitlen_rec+7)/8;
    int bytelen_covered = bytelen_rec;
    int bytelen_clr = (bitlen_clr+7)/8;
    int bytelen_z = BN_bn2mpi(keypair->sk, NULL);
    flag = sig->m_clr = malloc(bytelen_clr);if (flag==NULL) goto err;
    flag = sig->covered = malloc(bytelen_covered);if (flag==NULL) goto err;
    flag = sig->redun = malloc(bytelen_red);if (flag==NULL) goto err;
    flag = sig->z = BN_new();if (flag==NULL) goto err;
    sig->bytelen_clr = bytelen_clr;
    sig->bytelen_covered = bytelen_covered;
    sig->bytelen_red = bytelen_red;
    return sig;
err:
    ECOMG1_signature_free(sig);
    return NULL;
}


void ECOMG1_signature_free(void* obj)
{
    if (obj == NULL) return;
    ECOMG1_Sig *sig = (ECOMG1_Sig*)obj;
    free(sig->m_clr);
    free(sig->covered);
    free(sig->redun);
    BN_free(sig->z);
    free(sig);
}


/**
 * How we encode a signature in ec-omega:
 * len(m_clr) | len(covered) | len(red) | len(z) | m_clr | covered | red | z
 *      4byte        4byte        4byte      4byte
 * Lengths are in little-endian.
 */


int ECOMG1_get_sig_len(int clr, int rec, int red, void *obj)
{
    ECOMG1_Sig *sig = (ECOMG1_Sig*)obj;
    int bytelen_clr = bitlen2bytelen(clr);
    int bytelen_red = bitlen2bytelen(red);
    int bytelen_rec = bitlen2bytelen(rec);
    return 16+bytelen_clr+bytelen_red+bytelen_rec+sig->bytelen_z;
}


int ECOMG1_sig_encode(int clr, int rec, int red, void *obj, unsigned char *buf)
{
    ECOMG1_Sig *sig = (ECOMG1_Sig*)obj;
    int bytelen_clr = bitlen2bytelen(clr);
    int bytelen_red = bitlen2bytelen(red);
    int bytelen_rec = bitlen2bytelen(rec);
    int bytelen_covered = bytelen_rec;
    int bytelen_z = sig->bytelen_z;

    unsigned char *c = buf;
    memcpy(c, &bytelen_clr, 4);c+=4;
    memcpy(c, &bytelen_covered, 4);c+=4;
    memcpy(c, &bytelen_red, 4);c+=4;
    memcpy(c, &bytelen_z, 4);c+=4;
    memcpy(c, sig->m_clr, bytelen_clr);c+=bytelen_clr;
    memcpy(c, sig->covered, bytelen_covered);c+=bytelen_covered;
    memcpy(c, sig->redun, bytelen_red);c+=bytelen_red;
    return 0;
}


int ECOMG1_sign_offline(int clr, int rec, int red,
        void *keyobj, void *sessobj, void *sigobj)
{
    /* Rename objests. */
    ECOMG1_KeyPair *keys = (ECOMG1_KeyPair*)keyobj;
    ECOMG1_SignSess *sess = (ECOMG1_SignSess*)sessobj;
    ECOMG1_Sig *sig = (ECOMG1_Sig*)sigobj;
    int ret;

    /* Name some parameters. */
    int bytelen_red = bitlen2bytelen(red);
    int bytelen_rec = bitlen2bytelen(rec);
    int bytelen_tmpkey = bytelen_rec;

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

    /* Gen materials for redun and key */
    PRG(sess->A_bytes, bytelen_A, sess->red_n_key, bytelen_red+bytelen_tmpkey);

    /* Get redun = DDF(a) from materials */
    memcpy(sig->redun, sess->red_n_key, bytelen_red);

    /* Convert redun to e0*/
    BN_bin2bn(sig->redun, bytelen_red, sess->e0);

    /* Compute re0w = r-e0*w */
//    ret = BN_mod_mul(sess->e0w, sess->e0, keys->sk,
//            keys->group_order, bnctx);
    ret = BN_mod_mul_reciprocal(sess->e0w, sess->e0, keys->sk,
            keys->recp, bnctx);
    assert(ret==1);

    ret = BN_mod_sub(sess->re0w, sess->r, sess->e0w,
            keys->group_order, bnctx);
    assert(ret==1);

    return 0;
}


int ECOMG1_sign_online(int clr, int rec, int red,
        void *keyobj, void *sessobj, void *sigobj,
        const unsigned char *msg, int msglen)
{
    /* Rename objects. */
    ECOMG1_KeyPair *keys = (ECOMG1_KeyPair*)keyobj;
    ECOMG1_SignSess *sess = (ECOMG1_SignSess*)sessobj;
    ECOMG1_Sig *sig = (ECOMG1_Sig*)sigobj;
    int ret;

    /* Name some parameters. */
    int bytelen_rec = bitlen2bytelen(rec);
    int bytelen_covered = bytelen_rec;
    int bytelen_red = bitlen2bytelen(red);
    int bytelen_clr = msglen - bytelen_rec;
    const unsigned char *m_clr = msg;
    const unsigned char *m_rec = msg+bytelen_clr;
    unsigned char *tmpkey = sess->red_n_key+bytelen_red;

    /* Compute covered = tmpkey XOR m_rec) */
    BinXor(tmpkey, m_rec, sig->covered, bytelen_rec);

    /* Compute e1_bytes = Hash(m_clr, covered) */
    memcpy(sess->mclrcov, m_clr, bytelen_clr);
    memcpy(sess->mclrcov+bytelen_clr, sig->covered, bytelen_covered);
    ret = PRG(sess->mclrcov, bytelen_clr+bytelen_covered, sess->e1_bytes, keys->bytelen_go);
    assert(ret==0);

    /* Convert e1_bytes to e1 */
    BN_bin2bn(sess->e1_bytes, keys->bytelen_go, sess->e1);

    /* Compute z=re0w - e1*w */
//    ret = BN_mod_mul(sess->e1w, sess->e1, keys->sk, keys->group_order, bnctx);
    ret = BN_mod_mul_reciprocal(sess->e1w, sess->e1, keys->sk, keys->recp, bnctx);
    assert(ret==1);
    ret = BN_mod_sub(sig->z, sess->re0w, sess->e1w, keys->group_order, bnctx);
    assert(ret==1);

    memcpy(sig->m_clr, m_clr, bytelen_clr);

    return 0;
}


int ECOMG1_vrfy_offline(int clr, int rec, int red,
        void *keyobj, void *sessobj)
{
    return 0;
}

int ECOMG1_vrfy_online(int clr, int rec, int red,
        void *keyobj, void *sessobj, void *sigobj)
{
    /* Rename objects. */
    ECOMG1_KeyPair *keys = (ECOMG1_KeyPair*)keyobj;
    ECOMG1_VrfySess *sess = (ECOMG1_VrfySess*)sessobj;
    ECOMG1_Sig *sig = (ECOMG1_Sig*)sigobj;
    int ret;

    /* Name some parameters. */
    int bytelen_red = sig->bytelen_red;
    int bytelen_tmpkey = sig->bytelen_covered;

    /* Derive e0 from redun. */
    BN_bin2bn(sig->redun, sig->bytelen_red, sess->e0);

    /* Derive e1 from H(m_clr||covered)*/
    memcpy(sess->mclrcov, sig->m_clr, sig->bytelen_clr);
    memcpy(sess->mclrcov+sig->bytelen_clr, sig->covered, sig->bytelen_covered);
    PRG(sess->mclrcov, sig->bytelen_clr+sig->bytelen_covered,
            sess->e1_bytes, keys->bytelen_go);
    BN_bin2bn(sess->e1_bytes, keys->bytelen_go, sess->e1);

    /* Compute a=zG+(e0+e1)PK */
    BN_mod_add(sess->e0e1, sess->e0, sess->e1, keys->group_order, bnctx);
    EC_POINT_mul(keys->group, sess->A, sig->z, keys->PK, sess->e0e1, bnctx);

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

    /* Gen materials for red and tmpkey. */
    PRG(sess->A_bytes, bytelen_a, sess->red_n_key, bytelen_red+bytelen_tmpkey);

    /* Get redun=H(a_bytes) from materials */
    // Nothing to do.

    /* Check redun */
    ret = memcmp(sess->red_n_key, sig->redun, bytelen_red);
    assert(ret==0);//if (ret != 0) return -1;

    /* Get tmpkey=H(a_bytes) from materials. */
    unsigned char* tmpkey = sess->red_n_key+bytelen_red;

    /* Compute m_rec = tmpkey XOR covered)*/
    //TODO

    return 0;
}


SchemeMethods ECOMG1_Methods =
{
    .mthd_keypair_new       = ECOMG1_keypair_new,
    .mthd_keypair_free      = ECOMG1_keypair_free,
    .mthd_keypair_gen       = ECOMG1_keypair_gen,
    .mthd_get_name          = ECOMG1_get_name,
    .mthd_signsess_new      = ECOMG1_signsess_new,
    .mthd_signsess_free     = ECOMG1_signsess_free,
    .mthd_vrfysess_new      = ECOMG1_vrfysess_new,
    .mthd_vrfysess_free     = ECOMG1_vrfysess_free,
    .mthd_signature_new     = ECOMG1_signature_new,
    .mthd_signature_free    = ECOMG1_signature_free,
    .mthd_get_sig_len       = ECOMG1_get_sig_len,
    .mthd_sig_encode        = ECOMG1_sig_encode,
    .mthd_sign_offline      = ECOMG1_sign_offline,
    .mthd_sign_online       = ECOMG1_sign_online,
    .mthd_vrfy_offline      = ECOMG1_vrfy_offline,
    .mthd_vrfy_online       = ECOMG1_vrfy_online
};


