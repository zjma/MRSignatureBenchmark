#ifndef __SCHEME_H__
#define __SCHEME_H__


typedef struct SchemeMethods SchemeMethods;
struct SchemeMethods
{
    void *(*mthd_keypair_new)(int sec);
    void (*mthd_keypair_free)(void *obj);
    int (*mthd_keypair_gen)(int sec, void *obj);
    const char *(*mthd_get_name)();
    void *(*mthd_signsess_new)(void *keyobj, int bitlen_clr, int bitlen_rec, int bitlen_red);
    void (*mthd_signsess_free)(void* obj);
    void *(*mthd_vrfysess_new)(void *keyobj, int bitlen_clr, int bitlen_rec, int bitlen_red);
    void (*mthd_vrfysess_free)(void* obj);
    void *(*mthd_signature_new)(void *keyobj, int bitlen_clr, int bitlen_rec, int bitlen_red);
    void (*mthd_signature_free)(void* obj);
    int (*mthd_get_sig_len)(int clr, int rec, int red, void *obj);
    int (*mthd_sig_encode)(int clr, int rec, int red, void *obj, unsigned char *buf);
    int (*mthd_sign_offline)(int clr, int rec, int red,
        void *keyobj, void *sessobj, void *sigobj);
    int (*mthd_sign_online)(int clr, int rec, int red,
        void *keyobj, void *sessobj, void *sigobj,
        const unsigned char *msg, int msglen);
    int (*mthd_vrfy_offline)(int clr, int rec, int red,
        void *keyobj, void *sessobj);
    int (*mthd_vrfy_online)(int clr, int rec, int red,
        void *keyobj, void *sessobj, void *sigobj);
};


/* All the scheme methods for Scheme_new() */
extern SchemeMethods OmegaMethods;
extern SchemeMethods AOMethods;
extern SchemeMethods PVMethods;
extern SchemeMethods ECOMG2_Methods;
extern SchemeMethods ECOMG1_Methods;
extern SchemeMethods ECOMG0_Methods;
extern SchemeMethods ECAO_Methods;
extern SchemeMethods ECPV1_Methods;
extern SchemeMethods ECPV0_Methods;


/* A structure to hold a scheme. */
typedef struct Scheme Scheme;


/* A structure to hold key materials. */
typedef struct KeyPair KeyPair;


/**
 * A structure to hold intermediate values used in a signing session.
 * It is opaque, since the processes differ from scheme to scheme.
 */
typedef struct SignSession SignSession;


/**
 * A structure to hold intermediate values used in a signing session.
 * It is opaque, since the processes differ from scheme to scheme.
 */
typedef struct VrfySession VrfySession;


/**
 * A structure to hold signature.
 * It is opaque since signature format differ from scheme to scheme.
 */
typedef struct Signature Signature;


/**
 * Allocate for scheme.
 *
 * \param methods   Which scheme? Use pre-defined SchemeMethods here.
 *
 * \return  The pointer if succeeded, or NULL if failed.
 *
 * \note    Remember to free it with Scheme_free().
 */
Scheme *Scheme_new(SchemeMethods *methods);


/**
 * Free a scheme.
 *
 * \param sch   Scheme object to free.
 */
void Scheme_free(Scheme *sch);


/**
 * Allocate for a key pair.
 *
 * \param sch   A scheme object.
 * \param sec   Security parameter.
 *
 * \return  An empty KeyPair object if OK, or NULL if error.
 *
 * \note    Remember to free it with KeyPair_free().
 */
KeyPair *KeyPair_new(Scheme *sch, int sec);


/**
 * Generate a key pair.
 *
 * \param keypair   A KeyPair object.
 *
 * \return  0(OK), or <0(error).
 */
int KeyPair_gen(KeyPair *keypair);


/**
 * Free a key pair.
 *
 * \param keypair   Keypair to free.
 */
void KeyPair_free(KeyPair *keypair);


/**
 * Allocate for a context used to generate a signature.
 *
 * \param keypair       A KeyPair object.
 * \param sch           A scheme object.
 * \param bitlen_clr    Length (in bit) of plain part of message.
 * \param bitlen_rec    Length (in bit) of recoverable part of message.
 * \param bitlen_red    Length (in bit) of additional redundancy.
 *
 * \return  A context object if OK, or NULL if error.
 *
 * \note    Once allocated, a SignSession object
 *          can be used for many more times,
 *          as long as it works with unchanged parameters.
 *
 * \note    Remember to free it by calling SignSession_free().
 */
SignSession *SignSession_new(KeyPair *keypair, Scheme *sch,
        int bitlen_clr, int bitlen_rec, int bitlen_red);


/**
 * Free a session context object.
 *
 * \param sess  object to free.
 */
void SignSession_free(SignSession *sess);


/**
 * Allocate for a context used to generate a signature.
 *
 * \param keypair       A KeyPair object.
 * \param sch           A scheme object.
 * \param bitlen_clr    Length (in bit) of plain part of message.
 * \param bitlen_rec    Length (in bit) of recoverable part of message.
 * \param bitlen_red    Length (in bit) of additional redundancy.
 *
 * \return  A context object if OK, or NULL if error.
 *
 * \note    Once allocated, a SignSession object
 *          can be used for many more times,
 *          as long as it works with unchanged parameters.
 *
 * \note    Remember to free it by calling SignSession_free().
 */
VrfySession *VrfySession_new(KeyPair *keypair, Scheme *sch,
        int bitlen_clr, int bitlen_rec, int bitlen_red);


/**
 * Free a session context object.
 *
 * \param sess  object to free.
 */
void VrfySession_free(VrfySession *sess);


/**
 * Allocate for a signature structure used to store a signature.
 *
 * \param keypair       A KeyPair object.
 * \param sch           A scheme object.
 * \param bitlen_clr    Length (in bit) of plain part of message.
 * \param bitlen_rec    Length (in bit) of recoverable part of message.
 * \param bitlen_red    Length (in bit) of additional redundancy.
 *
 * \return  A signature object if OK, or NULL if error.
 */
Signature *Signature_new(KeyPair *keypair, Scheme *sch,
        int bitlen_clr, int bitlen_rec, int bitlen_red);


/**
 * Get how many bytes are needed to encode this signature.
 *
 * Use this to prepare a buffer long enough, then call Signature_encode().
 *
 * \param sig   Signature object.
 *
 * \return  >=0 indicating the length , or <0 if error.
 */
int Signature_get_length(Signature *sig);


/**
 * Encode a signature to bytes.
 *
 * \param sig   Signature object to encode.
 * \param buf   Encoded signature goes here. Make sure it's long enough.
 *
 * \return  0(OK), or <0(error).
 */
int Signature_encode(Signature *sig, unsigned char *buf);


/**
 * Free a signature object.
 *
 * \param sig   object to free.
 */
void Signature_free(Signature *sig);


/**
 * Get printable name of the scheme.
 *
 * \param sch   A scheme object.
 *
 * \return  A read-only string.
 */
const unsigned char *Scheme_get_name(Scheme *sch);


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
int Scheme_sign_offline(Scheme *sch, KeyPair *keypair,
        SignSession *sess, Signature *sig);


/**
 * Run online phase.
 *
 * \param sch       A Scheme object.
 * \param keypair   Key-pair used to sign.
 * \param sess      Context for this signing session.
 * \param sig       Online part of signature (if exists) goes here.
 * \param msg       Message to be signed.
 * \param msglen    Length of message. Ensure it's larger than bitlen_rec.
 *
 * \return  0(OK), or -1(failed).
 */
int Scheme_sign_online(Scheme *sch, KeyPair *keypair,
        SignSession *sess, Signature *sig,
        const unsigned char *msg, int msglen);


/**
 * Run offline phase of verification.
 *
 * \param sch       A scheme object.
 * \param keypair   A key-pair used to verify the signature.
 * \param sess      Context for this verifying session.
 *
 * \return  0(accept), or 1(reject), or <0(error).
 */
int Scheme_vrfy_offline(Scheme *sch, KeyPair *keypair, VrfySession *sess);


/**
 * Run online phase of verification.
 *
 * \param sch       A scheme object.
 * \param keypair   A key-pair used to verify the signature.
 * \param sess      Context for this verifying session.
 * \param sig       A signature to be verified.
 *
 * \return  0(accept), or 1(reject), or <0(error).
 */
int Scheme_verify_online(Scheme *sch, KeyPair *keypair, VrfySession *sess,
        Signature *sig);


#endif
