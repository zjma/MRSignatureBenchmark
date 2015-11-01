#ifndef __SCHEME_H__
#define __SCHEME_H__


typedef struct SchemeMethods SchemeMethods;
struct SchemeMethods
{
    void *(*new_inner)(int sec_size, int rec_len, int red_len);
    void (*free_inner)(void* inner);
    char *(*get_name)();
    int (*sign_offline)(void *inner);
    int (*sign_online)(void *inner, char *msg);
    int (*vrfy)(void *inner);
};


/* All the scheme methods for Scheme_new() */
extern SchemeMethods OmegaMethods;
extern SchemeMethods AOMethods;
extern SchemeMethods PVMethods;
extern SchemeMethods ECOmegaMethods;
extern SchemeMethods ECAOMethods;
extern SchemeMethods ECPVMethods;


typedef struct Scheme Scheme;
typedef struct KeyPair KeyPair;
typedef struct SignSession SignSession;
typedef struct Signature Signature;


/**
 * Allocate for scheme.
 *
 * \param methods   Which scheme? Use pre-defined SchemeMethods here.
 *
 * \return  The pointer if succeeded, or NULL if failed.
 */
Scheme *Scheme_new(SchemeMethods *methods);


/**
 * Generate a key pair.
 *
 * \param sch   A scheme object.
 * \param sec   Security parameter.
 *
 * \return  A KeyPair object if OK, or NULL if error.
 */
KeyPair *Scheme_gen_keypair(Scheme *sch, int sec);


/**
 *
 */
SignSession *Scheme_new_session(Scheme *sch, int bitlen_clr, int bitlen_rec, int bitlen_red);


Signature *Scheme_new_signature(Scheme *sch, int bitlen_clr, int bitlen_rec, int bitlen_red);


/**
 * Get printable name of the scheme.
 *
 * \param sch   A scheme object.
 *
 * \return  A read-only string.
 */
char *Scheme_get_name(Scheme *sch);


/**
 * Run offline phase.
 *
 * \param sch       A Scheme object.
 * \param keypair   Key-pair used to sign.
 * \param sess      Context for this signing session.
 * \param sig       Offline part of signature (if exists) goes here.
 *
 * \return  0(OK), or -1(failed).
 */
int Scheme_sign_offline(Scheme *sch, KeyPair *keypair, SignSession *sess, Signature *sig);


/**
 * Run online phase.
 *
 * \param sch       A Scheme object.
 * \param keypair   Key-pair used to sign.
 * \param sess      Context for this signing session.
 * \param sig       Online part of signature (if exists) goes here.
 *
 * \return  0(OK), or -1(failed).
 */
int Scheme_sign_offline(Scheme *sch, KeyPair *keypair, SignSession *sess, Signature *sig);


/**
 * Verify a signature.
 *
 * \param sch       A scheme object.
 * \param keypair   A key-pair used to verify the signature.
 * \param sig       A signature to be verified.
 *
 * \return  0(accept), or 1(reject), or <0(error).
 */
int Scheme_verify(Scheme *sch, KeyPair *keypair, Signature *sig);

#endif
