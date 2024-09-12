#ifdef VC_AUTH
#include "identity.h"
#include <utils/utils/object.h>
#include "./vc.h"

#include <asn1/oid.h>
#include <asn1/asn1.h>
#include <asn1/asn1_parser.h>


typedef struct private_vc_t private_vc_t;

/*
*   Private data of vc_t object.
*/

struct private_vc_t {

    /**
	 * VC Public interface.
	 */
	vc_t public;

    Wallet *w;
    Did *did;
    Vc *vc_oe;

    /**
	 * Reference counter
	 */
	refcount_t ref;
};

METHOD(verifiable_credential_t, wallet_setup, bool, private_vc_t *this, const char *stronghold_path, const char *password) {
    this->w = setup("ciao", "ciao");

    if(this->w != NULL)
        return TRUE;
    return FALSE;
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

    while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_BLOB_ASN1_DER:
				jwt = va_arg(args, chunk_t);
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
                .wallet_setup = _wallet_setup,
                .equals = verifiable_credential_equals,
                .destroy = _destroy,
            },
        }, 
        .ref = 1,
    );

    if(jwt.ptr == NULL)
        return NULL;
    
    /* this->w = setup("./test-stuff/server.stronghold", "server");
    if(this->w == NULL)
        return NULL; */

    this->vc_oe = set_vc(jwt.ptr);
    if (this->vc_oe != NULL)
        printf("This is the loaded vc: %s\n", get_vc(this->vc_oe));
        return &this->public;
    

    return NULL;
}

#endif