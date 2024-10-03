#ifdef VC_AUTH
#ifndef DECENTRALIZED_IDENTIFIER_H_
#define DECENTRALIZED_IDENTIFIER_H_

#include <utils/identification.h>

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

/*
* An abstract DID
*/
struct decentralized_identifier_t {
    
    /**
	 * Get the DID method (type).
	 *
	 * @return			type of the DIDI
	 */
	decentralized_identifier_type_t (*get_type)(decentralized_identifier_type_t *this);

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
#endif
#endif