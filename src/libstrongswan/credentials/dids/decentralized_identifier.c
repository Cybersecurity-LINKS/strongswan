#ifdef VC_AUTH
#include "decentralized_identifier.h"

ENUM(did_type_names, DID_IOTA, DID_IOTA,
	"IOTA",
);

/**
 * See header.
 */
bool decentralized_identifier_equals(decentralized_identifier_t *did, decentralized_identifier_t *other)
{
	/* cred_encoding_type_t type;
	chunk_t a, b;

	if (this == other)
	{
		return TRUE;
	}

	for (type = 0; type < CRED_ENCODING_MAX; type++)
	{
		if (this->get_fingerprint(this, type, &a) &&
			other->get_fingerprint(other, type, &b))
		{
			return chunk_equals(a, b);
		}
	} */
	return TRUE;
}

/**
 * Described in header
 */
bool did_matches(decentralized_identifier_t *did, decentralized_identifier_type_t type,
						 identification_t *id)
{
	if (type != did->get_type(did))
	{
		return FALSE;
	}

	return TRUE;
}

#endif