#include <stddef.h>
#include <stdlib.h>
#include <assert.h>

#include "scheme.h"


struct Scheme
{
    SchemeMethods*  imp;
};


struct KeyPair
{
    Scheme* sch;
    int     sec;
    void*   obj;
};


struct SignSession
{
    Scheme* sch;
    int     bitlen_clr;
    int     bitlen_rec;
    int     bitlen_red;
    void*   obj;
};


struct VrfySession
{
    Scheme* sch;
    int     bitlen_clr;
    int     bitlen_rec;
    int     bitlen_red;
    void*   obj;
};


struct Signature
{
    Scheme*     sch;
    int     bitlen_clr;
    int     bitlen_rec;
    int     bitlen_red;
    void*       obj;
};


Scheme *Scheme_new(SchemeMethods *methods)
{
    if (methods == NULL) return NULL;

    Scheme *ret = malloc(sizeof(Scheme));
    ret->imp = methods;
    return ret;
err:
    Scheme_free(ret);
    return NULL;
}


KeyPair *KeyPair_new(Scheme *sch, int sec)
{
    if (sch == NULL) return NULL;
    KeyPair *ret = (KeyPair*)malloc(sizeof(KeyPair));
    void *obj = sch->imp->mthd_keypair_new(sec);
    if (obj == NULL) goto err;
    ret->sch = sch;
    ret->sec = sec;
    ret->obj = obj;
    return ret;
err:
    KeyPair_free(ret);
    return NULL;
}


void KeyPair_free(KeyPair *keypair)
{
    if (keypair == NULL) return;
    keypair->sch->imp->mthd_keypair_free(keypair->obj);
    free(keypair);
}


int KeyPair_gen(KeyPair *keypair)
{
    if (keypair == NULL) return -1;
    int sec = keypair->sec;
    void *obj = keypair->obj;
    return keypair->sch->imp->mthd_keypair_gen(sec, obj);
}


SignSession *SignSession_new(KeyPair *keypair, Scheme *sch,
        int bitlen_clr, int bitlen_rec, int bitlen_red)
{
    if (keypair == NULL) return NULL;
    if (sch == NULL) return NULL;
    SignSession *ret = (SignSession*)malloc(sizeof(SignSession));
    ret->sch = sch;
    ret->bitlen_clr = bitlen_clr;
    ret->bitlen_rec = bitlen_rec;
    ret->bitlen_red = bitlen_red;
    void *obj = sch->imp->mthd_signsess_new(keypair->obj, bitlen_clr, bitlen_rec, bitlen_red);
    if (obj == NULL) goto err;
    ret->obj = obj;
    return ret;
err:
    SignSession_free(ret);
    return NULL;
}


void SignSession_free(SignSession *sess)
{
    if (sess == NULL) return;
    sess->sch->imp->mthd_signsess_free(sess->obj);
    free(sess);
}


VrfySession *VrfySession_new(KeyPair *keypair, Scheme *sch,
        int bitlen_clr, int bitlen_rec, int bitlen_red)
{
    if (sch == NULL) return NULL;
    VrfySession *ret = (VrfySession*)malloc(sizeof(VrfySession));
    ret->sch = sch;
    ret->bitlen_clr = bitlen_clr;
    ret->bitlen_rec = bitlen_rec;
    ret->bitlen_red = bitlen_red;
    void *keyobj = keypair->obj;
    void *obj = sch->imp->mthd_vrfysess_new(keyobj, bitlen_clr, bitlen_rec, bitlen_red);
    if (obj == NULL) goto err;
    ret->obj = obj;
    return ret;

err:
    VrfySession_free(ret);
    return NULL;
}


void VrfySession_free(VrfySession *sess)
{
    if (sess == NULL) return;
    sess->sch->imp->mthd_vrfysess_free(sess->obj);
    free(sess);
}


Signature *Signature_new(KeyPair *keypair, Scheme *sch,
        int bitlen_clr, int bitlen_rec, int bitlen_red)
{
    if (sch == NULL) return NULL;
    Signature *ret = (Signature*)malloc(sizeof(Signature));
    ret->sch = sch;
    ret->bitlen_clr = bitlen_clr;
    ret->bitlen_rec = bitlen_rec;
    ret->bitlen_red = bitlen_red;
    void *keyobj = keypair->obj;
    void *obj = sch->imp->mthd_signature_new(keyobj,
            bitlen_clr, bitlen_rec, bitlen_red);
    if (obj == NULL) goto err;
    ret->obj = obj;
    return ret;
err:
    Signature_free(ret);
    return NULL;
}


void Signature_free(Signature *sig)
{
    if (sig == NULL) return;
    sig->sch->imp->mthd_signature_free(sig->obj);
    free(sig);
}


int Signature_get_length(Signature *sig)
{
    if (sig == NULL) return -1;
    return sig->sch->imp->mthd_get_sig_len(
            sig->bitlen_clr,
            sig->bitlen_rec,
            sig->bitlen_red,
            sig->obj);
}


int Signature_encode(Signature *sig, unsigned char *buf)
{
    if (sig == NULL) return -1;
    if (buf == NULL) return -1;
    return sig->sch->imp->mthd_sig_encode(
            sig->bitlen_clr,
            sig->bitlen_rec,
            sig->bitlen_red,
            sig->obj,
            buf);
}


void Scheme_free(Scheme *sch)
{
    if (sch == NULL) return;
    free(sch);
}


const unsigned char *Scheme_get_name(Scheme *sch)
{
    return sch->imp->mthd_get_name();
}


int Scheme_sign_offline(Scheme *sch, KeyPair *keypair,
        SignSession *sess, Signature *sig)
{
    if (sch == NULL) return -1;
    if (keypair == NULL) return -1;
    if (sess == NULL) return -1;
    if (sig == NULL) return -1;
    return sch->imp->mthd_sign_offline(
            sess->bitlen_clr,
            sess->bitlen_rec,
            sess->bitlen_red,
            keypair->obj, sess->obj, sig->obj);
}


int Scheme_sign_online(Scheme *sch, KeyPair *keypair,
        SignSession *sess, Signature *sig,
        const unsigned char *msg, int msglen)
{
    if (sch == NULL) return -1;
    if (keypair == NULL) return -1;
    if (sess == NULL) return -1;
    if (sig == NULL) return -1;
    if (msg == NULL) return -1;
    return sch->imp->mthd_sign_online(
            sess->bitlen_clr,
            sess->bitlen_rec,
            sess->bitlen_red,
            keypair->obj, sess->obj, sig->obj, msg, msglen);
}


int Scheme_vrfy_offline(Scheme *sch, KeyPair *keypair, VrfySession *sess)
{
    if (sch == NULL) return -1;
    if (keypair == NULL) return -1;
    if (sess == NULL) return -1;
    return sch->imp->mthd_vrfy_offline(
            sess->bitlen_clr,
            sess->bitlen_rec,
            sess->bitlen_red,
            keypair->obj,
            sess->obj);
}


int Scheme_vrfy_online(Scheme *sch, KeyPair *keypair, VrfySession *sess,
        Signature *sig)
{
    if (sch == NULL) return -1;
    if (keypair == NULL) return -1;
    if (sess == NULL) return -1;
    if (sig == NULL) return -1;
    return sch->imp->mthd_vrfy_online(
            sess->bitlen_clr,
            sess->bitlen_rec,
            sess->bitlen_red,
            keypair->obj,
            sess->obj,
            sig->obj);
}
