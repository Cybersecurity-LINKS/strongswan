#ifdef VC_AUTH
#include <utils/utils/object.h>
#include "vc.h"
#include <credentials/vcs/verifiable_credential.h>
#include "did_iota.h"

#include <asn1/oid.h>
#include <asn1/asn1.h>
#include <asn1/asn1_parser.h>

Wallet *w = NULL;
typedef struct private_vc_t private_vc_t;

/*
*   Private data of vc_t object.
*/

struct private_vc_t {

    /**
	 * VC Public interface.
	 */
	vc_t public;

    //Wallet *w;
    Did *did;
    Vc *vc_oe;

    /**
	 * Reference counter
	 */
	refcount_t ref;
};

METHOD(verifiable_credential_t, get_type, verifiable_credential_type_t,
	private_vc_t *this)
{
	return VC_DATA_MODEL_2_0;
}

METHOD(verifiable_credential_t, get_encoding, bool,
	private_vc_t *this, cred_encoding_type_t type, chunk_t *encoding)
{
	/* This is the code used in cert->get_type, let's do it a little different */
    /* if (type == VC_ASN1_DER)
	{
		*encoding = chunk_clone(this->encoding);
		return TRUE;
	}

	return lib->encoding->encode(lib->encoding, type, NULL, encoding,
						CRED_PART_X509_ASN1_DER, this->encoding, CRED_PART_END); */
    if (type == VC_ASN1_DER)
    {   
        char *jwt;
        jwt = get_vc(this->vc_oe);
        encoding->ptr = jwt;
        encoding->len = strlen(jwt);

        printf("jwt in get encoding is %s\n\n", encoding->ptr);
        printf("jwt len in get encoding is %d\n\n", encoding->len);
        /* Maybe I should encode it in DER format */
        return TRUE;
    }

    return false;
}

/* METHOD(verifiable_credential_t, wallet_setup, bool, private_vc_t *this, const char *stronghold_path, const char *password) {
    this->w = setup("ciao", "ciao");

    if(this->w != NULL)
        return TRUE;
    return FALSE;
} */

METHOD(verifiable_credential_t, get_ref, verifiable_credential_t*,
	private_vc_t *this)
{
	ref_get(&this->ref);
	return &this->public.vc;
}

METHOD(verifiable_credential_t, destroy, void,
	private_vc_t *this)
{
	if (ref_put(&this->ref))
	{
		lib->encoding->clear_cache(lib->encoding, this);
		/* memwipe(this->s, HASH_SIZE_SHA512);
		chunk_clear(&this->key);
		chunk_free(&this->pubkey);
		free(this); */

        /* free(w);
        free(did);
        free(vc_oe); */
        free(this);
	}
}

/**
 * See header.
 */
vc_t *vc_load(verifiable_credential_type_t type, va_list args)
{
    private_vc_t *this;
    chunk_t jwt = chunk_empty;
    bool vc_vrfy = false;

    while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_BLOB_ASN1_DER:
				jwt = va_arg(args, chunk_t);
				continue;
            case BUILD_VC_VERIFY:
                jwt = va_arg(args, chunk_t);
                vc_vrfy = true;
                continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}

    INIT(this,
        .public = {
            .vc = {
                .get_type = _get_type,
                .get_encoding = _get_encoding,
                .equals = verifiable_credential_equals,
                .get_ref = _get_ref,
                .destroy = _destroy,
            },
        }, 
        .ref = 1,
    );

    if(jwt.ptr == NULL)
        return NULL;
    printf("This is the content of jwt.ptr: %s\n\n", jwt.ptr);
    
    char oid[20];
    char vc[2000];
    if(sscanf((char *)jwt.ptr, "%s %s", oid, vc) == EOF)
        return NULL;

    printf("This is the content of vc[2000]: %s\n\n", vc);
    if (w == NULL)
	{
		w = setup("./test-stuff/server.stronghold", "server");
		if (w == NULL)
			return NULL;
	}

    if(vc_vrfy) {
        Did *did;
        chunk_t data = chunk_empty;
        const char *did_jwt = NULL;
        did = vc_verify(w, vc);
        if (!did)
            return NULL;
        did_jwt = get_did(did);
        data.ptr = (u_char *)did_jwt;
        data.len = strlen(did_jwt);
        if(!lib->creds->create(lib->creds, CRED_DECENTRALIZED_IDENTIFIER, DID_IOTA, 
							BUILD_BLOB_ASN1_DER, data, BUILD_END))
            return NULL;
    }

    this->vc_oe = set_vc(vc);
    if (this->vc_oe != NULL) 
    {
        printf("This is the loaded vc: %s\n\n", get_vc(this->vc_oe));
        return &this->public; 
    }

    return NULL;
}

#endif