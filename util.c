#include <openssl/evp.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>


static char AESKEY[32];
static char *IV = "0123456789abcdef";
static char tmpbuf[1024];

static EVP_MD_CTX *hasher;
static EVP_CIPHER_CTX *crypter;

int InitCrypt()
{
    crypter = EVP_CIPHER_CTX_new();
    hasher = EVP_MD_CTX_create();
    assert(crypter!=NULL);
    assert(hasher!=NULL);
}

int CleanCrypt()
{
    EVP_MD_CTX_cleanup(hasher);
    EVP_MD_CTX_destroy(hasher);

    EVP_CIPHER_CTX_free(crypter);
}

int DoSHA256(const char *msg, int msglen, char *dst)
{
    int r;

    EVP_DigestInit_ex(hasher, EVP_sha256(), NULL);
    EVP_DigestUpdate(hasher, msg, msglen);
    EVP_DigestFinal_ex(hasher, dst, &r);
    assert(r==32);
    return 0;
}

int DoAES256CBC(char *key,
        const char *ptxt, int plen,
        char *ctxt, int *clen)
{
    int len = 0;
    EVP_EncryptInit_ex(crypter, EVP_aes_256_cbc(), NULL, key, IV);
    EVP_EncryptUpdate(crypter, ctxt, &len, ptxt, plen);
    *clen = len;
    EVP_EncryptFinal_ex(crypter, ctxt+len, &len);
    *clen += len;
    return 0;
}

int VHash(const char *msg, int msglen,
        char *dst, int dstlen)
{
    int buflen;
    assert(dstlen <= msglen);

    /* key:= SHA256(msg)*/
    int ret;

    ret = DoSHA256(msg, msglen, AESKEY);
    assert(ret==0);
    
    /* Encrypt msg to tmpbuf */
    DoAES256CBC(AESKEY, msg, dstlen, tmpbuf, &buflen);
    assert(buflen >= dstlen);

    /* Resize tmpbuf to dst */
    memcpy(dst, tmpbuf, dstlen);

    return 0;
}


int BN2LenBin(BIGNUM *bn, char *buf, int len)
{
    int bytelen_bn = BN_num_bytes(bn);
    assert(bytelen_bn <= len);
    BN_bn2bin(bn, &buf[len-bytelen_bn]);
    memset(buf, 0, len-bytelen_bn);
    return 0;
}
