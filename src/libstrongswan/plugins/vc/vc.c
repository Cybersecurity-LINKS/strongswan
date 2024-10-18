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
    //Did *did;
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
    bool success = TRUE;
	char *vc_jwt;

    switch(type)
    {   
        case VC_PEM:
		{
			chunk_t der_encoding;
			vc_jwt = get_vc(this->vc_oe);
			encoding->ptr = vc_jwt;
			encoding->len = strlen(vc_jwt);
			der_encoding = *encoding;

			/* fprintf(stderr, "vc_jwt in get encoding is %s\n\n", encoding->ptr);
			fprintf(stderr, "vc_jwt len in get encoding is %d\n\n", encoding->len); */

			success = lib->encoding->encode(lib->encoding, VC_PEM, NULL, 
								encoding, CRED_PART_VC_ASN1_DER, der_encoding, CRED_PART_END);
			chunk_clear(&der_encoding);
			return success;
		}
        case VC_ASN1_DER:
        {   
            vc_jwt = get_vc(this->vc_oe);
            if(!vc_jwt)
                success = FALSE;
            encoding->ptr = vc_jwt;
            encoding->len = strlen(vc_jwt);
            return success;
        }
        default:
            return FALSE;
    }
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
vc_t *vc_gen(verifiable_credential_type_t type, va_list args)
{   
    private_vc_t *this;
    chunk_t did_doc = chunk_empty;
    Did *did;

    while (TRUE)
    {
        switch (va_arg(args, builder_part_t))
        {   
            case BUILD_VC_CREATE:
                did_doc = va_arg(args, chunk_t);
                continue;
            case BUILD_END:
                break;
            default:
                NULL;
        }
        break;
    }

    if(did_doc.ptr == NULL)
        return NULL;
    
    char oid[20] = {'\0'};
	char fragment[100] = {'\0'};
	char privkey[300] = {'\0'};
	char did_document[1000] = {'\0'};

    if (w == NULL)
	{
		w = setup("./test-stuff/server.stronghold", "server");
		if (w == NULL)
			return NULL;
	}

    if(sscanf((char *)did_doc.ptr, "%s%s%s%s", oid, fragment, privkey, did_document) == EOF)
        return NULL;

    /* fprintf(stderr, "This is the content of oid[20]: %s\n\n", oid);
	fprintf(stderr, "This is the content of fragment[100]: %s\n\n", fragment);
	fprintf(stderr, "This is the content of privkey[100]: %s\n\n", privkey);
	fprintf(stderr, "This is the content of did_document[1000]: %s\n\n", did_document); */
    did = set_did(did_document, fragment, privkey);
    if (!did)
        return NULL;

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

    this->vc_oe = vc_create(w, did, "leonardo"); 
    if(!this->vc_oe)
        return NULL;

    //fprintf(stderr, "This the VC just created: %s\n\n", get_vc(this->vc_oe));

    return this ? &this->public : NULL;

    return NULL;
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