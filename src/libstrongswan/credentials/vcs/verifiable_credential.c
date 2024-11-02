/*
 * Copyright 2024 Fondazione LINKS.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#ifdef VC_AUTH
#include "verifiable_credential.h"

ENUM(vc_type_names, VC_ANY, VC_DATA_MODEL_2_0,
	"ANY",
	"DM20",
);


/**
 * See header.
 */
bool verifiable_credential_equals(verifiable_credential_t *vc, verifiable_credential_t *other)
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
bool vc_matches(verifiable_credential_t *vc, verifiable_credential_type_t type,
						 identification_t *id)
{
	if (type != VC_ANY && type != vc->get_type(vc))
	{
		return FALSE;
	}

	return TRUE;
}
#endif