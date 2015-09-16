#include <openssl/evp.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

int DoSHA256(EVP_MD_CTX *hasher, const char *msg, int msglen, char *dst)
{
    int r;

    EVP_DigestInit_ex(hasher, EVP_sha256(), NULL);
    EVP_DigestUpdate(hasher, msg, msglen);
    EVP_DigestFinal_ex(hasher, dst, &r);
    assert(r==32);
    return 0;
}


int VHash(const char *msg, int msglen, char *dst, int dstlen)
{
    //TODO
    memset(dst, 0, dstlen);
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
