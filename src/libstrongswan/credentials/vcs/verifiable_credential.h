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
#ifndef VERIFIABLE_CREDENTIAL_H_
#define VERIFIABLE_CREDENTIAL_H_

#include <utils/identification.h>
#include <credentials/cred_encoding.h>

typedef struct verifiable_credential_t verifiable_credential_t;
typedef enum verifiable_credential_type_t verifiable_credential_type_t; 

enum verifiable_credential_type_t {
    /** vc type wildcard */
    VC_ANY              = 9,
    /** DATA MODEL 2.0 */
    VC_DATA_MODEL_2_0   = 10,
};

/**
 * Enum names for key_type_t
 */
extern enum_name_t *vc_type_names;

/*
* An abstract VC
*/

struct verifiable_credential_t {

    /**
	 * Get the type of the verifiable credential.
	 *
	 * @return			verifiable credential type
	 */
	verifiable_credential_type_t (*get_type)(verifiable_credential_t *this);

    /**
	 * Get the verifiable credential in an encoded form as a chunk.
	 *
	 * @param type		type of the encoding, one of VC_*
	 * @param encoding	encoding of the vc, allocated
	 * @return			TRUE if encoding supported
	 */
	bool (*get_encoding)(verifiable_credential_t *this, cred_encoding_type_t type,
						 chunk_t *encoding);

    /**
	 * Verifies a signature against a chunk of data with the public key of the DID Document.
	 *
	 * @param data		data to check signature against
 	 * @param signature	signature to check
	 * @return			TRUE if signature matches
	 */
	bool (*verify)(verifiable_credential_t *this, chunk_t data, chunk_t signature);

    /**
	 * Check if two verifiable credentials are equal.
	 *
	 * @param other		other verifiable credential
	 * @return			TRUE, if equality
	 */
	bool (*equals) (verifiable_credential_t *this, verifiable_credential_t *other);

	/**
	 * Get a new reference to the vc.
	 *
	 * @return			this, with an increased refcount
	 */
	verifiable_credential_t* (*get_ref)(verifiable_credential_t *this);

    /**
	 * Decrease refcount, destroy verifiable_credential if no more references.
	 */
	void (*destroy)(verifiable_credential_t *this);
};

/**
 * Generic verifiable credentials equals() implementation, usable by implementers.
 *
 * @param vc		    verifiable credential to check
 * @param other			verifiable credential to compare
 * @return				TRUE if this is equal to other
 */
bool verifiable_credential_equals(verifiable_credential_t *vc, verifiable_credential_t *other);

/**
 * Check if the given VC matches the given type and identity,
 * all of which are optional.
 *
 *
 * @param vc			verifiable credential
 * @param type			vc type to match, or VC_ANY
 * @param id			identity to match, or NULL
 */
bool vc_matches(verifiable_credential_t *vc, verifiable_credential_type_t type,
						 identification_t *id);

#endif
#endif