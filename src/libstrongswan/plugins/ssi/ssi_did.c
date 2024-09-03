#include "ssi_did.h"

/**
 * See header.
 */
ssi_did_t *ssi_did_load(key_type_t type,
									va_list args)
{
    //chunk_t key = chunk_empty;

	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_EDDSA_PRIV_ASN1_DER:
				//key = va_arg(args, chunk_t);
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}

    return NULL;
}