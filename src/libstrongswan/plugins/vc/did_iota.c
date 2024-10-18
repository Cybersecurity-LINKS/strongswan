#ifdef VC_AUTH
#include "did_iota.h"
#include <utils/utils/object.h>
#include <credentials/dids/decentralized_identifier.h>

#include <asn1/oid.h>
#include <asn1/asn1.h>
#include <asn1/asn1_parser.h>

#define DID_SIGSIZE 187

extern Wallet *w; 
typedef struct private_did_iota_t private_did_iota_t;

/*
*   Private data of did_iota_t object.
*/

struct private_did_iota_t {

    /**
	 * DID IOTA Public interface.
	 */
	did_iota_t public;

	//Wallet *w;
    Did *did_oe;
    /**
	 * Reference counter
	 */
	refcount_t ref;
};

METHOD(decentralized_identifier_t, get_type, decentralized_identifier_type_t,
	private_did_iota_t *this)
{
	return DID_IOTA;
}

METHOD(decentralized_identifier_t, get_encoding, bool,
	private_did_iota_t *this, cred_encoding_type_t type, chunk_t *encoding)
{
	bool success = TRUE;
	char *did_doc;

    switch(type)
    {   
		case DID_PEM:
		{
			chunk_t der_encoding;
			did_doc = get_did(this->did_oe);
			encoding->ptr = did_doc;
			encoding->len = strlen(did_doc);
			der_encoding = *encoding;

			//fprintf(stderr, "did_doc in get encoding is %s\n\n", encoding->ptr);
			//fprintf(stderr, "did_doc len in get encoding is %d\n\n", encoding->len);

			success = lib->encoding->encode(lib->encoding, DID_PEM, NULL, 
								encoding, CRED_PART_DID_ASN1_DER, der_encoding, CRED_PART_END);
			chunk_clear(&der_encoding);
			return success;
		}
		case DID_ASN1_DER:
		{
			did_doc = get_did(this->did_oe);
			if(!did_doc)
				success = FALSE;
			encoding->ptr = did_doc;
			encoding->len = strlen(did_doc);
			return success;	
		}
		default:
			return FALSE;
    }
}

METHOD(decentralized_identifier_t, sign, bool,
	private_did_iota_t *this, chunk_t data, chunk_t *signature)
{	
	printf("This is the DID Document in sign: %s\n\n", get_did(this->did_oe));
	if(w == NULL){
		printf("w is null\n\n");
	}
	if(this->did_oe == NULL){
		printf("did_oe is null\n\n");
	}
	signature->ptr = did_sign(w, this->did_oe, data.ptr, data.len);

	if(signature->ptr == NULL)
		return false;

	signature->len = 187;

	return true;
}

METHOD(decentralized_identifier_t, verify, bool,
	private_did_iota_t *this, chunk_t data, chunk_t signature)
{	
	rvalue_t res;
	printf("data.len in did_iota verify is: %d\n\n", data.len);
	printf("signature.len in did_iota verify is: %d\n\n", signature.len); 
	res = did_verify(this->did_oe, data.ptr, data.len, signature.ptr, signature.len);
	if(res.code == 1)
		return true;
	return false;
}

METHOD(decentralized_identifier_t, get_ref, decentralized_identifier_t*,
	private_did_iota_t *this)
{
	ref_get(&this->ref);
	return &this->public.did;
}

/* METHOD(decentralized_identifier_t, get_internal_did, Did*,
	private_did_iota_t *this)
{
	return this->did_oe;
}
 */
/* METHOD(decentralized_identifier_t, get_internal_wallet, Wallet*,
	private_did_iota_t *this)
{
	return w;
} */

METHOD(decentralized_identifier_t, destroy, void,
	private_did_iota_t *this)
{
	if (ref_put(&this->ref))
	{
		lib->encoding->clear_cache(lib->encoding, this);
		/* memwipe(this->s, HASH_SIZE_SHA512);
		chunk_clear(&this->key);
		chunk_free(&this->pubkey);
		free(this); */

        /* free(w);
        free(this->did_oe);
        free(vc_oe); */
        free(this);
	}
}

/**
 * See header.
 */
did_iota_t *did_iota_gen(decentralized_identifier_type_t type, va_list args)
{	
	private_did_iota_t *this;
	Did *did;
	char *did_doc = NULL;

	while (TRUE)
    {
        switch (va_arg(args, builder_part_t))
        {
            case BUILD_END:
                break;
            default:
                NULL;
        }
        break;
    }

	if (w == NULL)
	{
		w = setup("./test-stuff/server.stronghold", "server");
		if (w == NULL)
			return NULL;
	}

	did = did_create(w);
	if (!did)
		return NULL;

	did_doc = get_did(did);
	if(!did_doc)
		return NULL;
	//fprintf(stderr, "this is the did_doc in did_iota_gen: %s\n\n", did_doc);

	INIT(this,
        .public = {
            .did = {
                .get_type = _get_type,
				.get_encoding = _get_encoding,
				.sign = _sign,
				.verify = _verify,
				.equals = decentralized_identifier_equals,
				.get_ref = _get_ref,
				.destroy = _destroy,
            },
        }, 
        .ref = 1,
		.did_oe = did,
    ); 

	return this ? &this->public : NULL;
}

/**
 * See header.
 */
did_iota_t *did_iota_load(decentralized_identifier_type_t type, va_list args)
{
    private_did_iota_t *this;
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
            .did = {
                .get_type = _get_type,
				.get_encoding = _get_encoding,
				.sign = _sign,
				.verify = _verify,
				.equals = decentralized_identifier_equals,
				.get_ref = _get_ref,
				/* .get_internal_did = _get_internal_did,
				.get_internal_wallet = _get_internal_wallet, */
				.destroy = _destroy,
            },
        }, 
        .ref = 1,
    );

	if(jwt.ptr == NULL)
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

	if(sscanf((char *)jwt.ptr, "%s%s%s%s", oid, fragment, privkey, did_document) == EOF)
        return NULL;

	printf("This is the content of the decoded did_document.pem: %s\n\n", jwt.ptr);
	
	printf("This is the content of oid[20]: %s\n\n", oid);
	printf("This is the content of fragment[100]: %s\n\n", fragment);
	printf("This is the content of privkey[100]: %s\n\n", privkey);
	printf("This is the content of did_document[1000]: %s\n\n", did_document);
	

	this->did_oe = set_did(did_document, fragment, privkey);
	if (this->did_oe != NULL)
	{
		printf("This is the load DID Document: %s\n", get_did(this->did_oe));
		return &this->public;
	}

	return NULL;
}
#endif