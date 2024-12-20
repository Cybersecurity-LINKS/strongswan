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
#ifndef DECENTRALIZED_IDENTIFIER_H_
#define DECENTRALIZED_IDENTIFIER_H_

#include <utils/identification.h>
#include <credentials/cred_encoding.h>

typedef struct decentralized_identifier_t decentralized_identifier_t;
typedef enum decentralized_identifier_type_t decentralized_identifier_type_t;

/**
 * Type of DID, namely DID Method, starts from 50 
 */ 
enum decentralized_identifier_type_t {
	/** IOTA */
	DID_IOTA = 50,
}; 

/**
 * Enum names for key_type_t
 */
extern enum_name_t *did_type_names;

/** 
 * DID Signature scheme for signature creation
 */ 

enum did_signature_scheme_t {
	/** Unknown signature scheme */
	SIGN_DID_UNKNOWN,
	/* EdDSA on Curve 25519 */
	SIGN_DID_ED25519,
};

/*
* An abstract DID
*/
struct decentralized_identifier_t {
    
    /**
	 * Get the DID method (type).
	 *
	 * @return			type of the DID
	 */
	decentralized_identifier_type_t (*get_type)(decentralized_identifier_t *this);

	/**
	 * Get the decentralized identifier in an encoded form as a chunk.
	 *
	 * @param type		type of the encoding, one of DID_*
	 * @param encoding	encoding of the did, allocated
	 * @return			TRUE if encoding supported
	 */
	bool (*get_encoding)(decentralized_identifier_t *this, cred_encoding_type_t type,
						 chunk_t *encoding);
	
	/**
	 * Create a signature over a chunk of data.
	 *
	 * @param data		chunk of data to sign
	 * @param signature	where to allocate created signature
	 * @return			TRUE if signature created
	 */
	bool (*sign)(decentralized_identifier_t *this, chunk_t data, chunk_t *signature);

	/**
	 * Verifies a signature against a chunk of data.
	 *
	 * @param data		data to check signature against
 	 * @param signature	signature to check
	 * @return			TRUE if signature matches
	 */
	bool (*verify)(decentralized_identifier_t *this, chunk_t data, chunk_t signature);

	/**
	 * Check if two decentralized identifiers are equal.
	 *
	 * @param other		other decentralized identifier
	 * @return			TRUE, if equality
	 */
	bool (*equals) (decentralized_identifier_t *this, decentralized_identifier_t *other);

	/**
	 * Get a new reference to the decentralized identifier.
	 *
	 * @return			this, with an increased refcount
	 */
	decentralized_identifier_t* (*get_ref)(decentralized_identifier_t *this);

	/**
	 * Get a reference to the internal DID  
	 * 
	 * @return 			Did from the DID library
	 */
	/* Did* (*get_internal_did)(decentralized_identifier_t *this);
 */
	/**
	 * Get a reference to the Wallet to do cryptographic operations with the DID  
	 * 
	 * @return 			Wallet from the DID library
	 */
	/* Wallet* (*get_internal_wallet)(decentralized_identifier_t *this); */

    /**
	 * Decrease refcount, destroy decentralized identifier if no more references.
	 */
	void (*destroy)(decentralized_identifier_t *this);
};

/**
 * Generic decentralized identifier equals() implementation, usable by implementers.
 *
 * @param did		    decentralized identifier to check
 * @param other			decentralized identifier to compare
 * @return				TRUE if this is equal to other
 */
bool decentralized_identifier_equals(decentralized_identifier_t *did, decentralized_identifier_t *other);

/**
 * Check if the given DID matches the given type and identity,
 * all of which are optional.
 *
 *
 * @param did			decentralized identifier
 * @param type			did type to match
 * @param id			identity to match, or NULL
 */
bool did_matches(decentralized_identifier_t *did, decentralized_identifier_type_t type,
						 identification_t *id);

#endif
#endif