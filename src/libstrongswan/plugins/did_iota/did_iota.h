#ifdef VC_AUTH
#ifndef DID_IOTA_H
#define DID_IOTA_H

#include <credentials/dids/decentralized_identifier.h>

typedef struct did_iota_t did_iota_t;

/**
 *  decentralized_identifier_t implementation of IOTA DID Method.
 */
struct did_iota_t {
    
    /**
     * Implements the decentralized_identifier_t
     */
    decentralized_identifier_t did;    
};

/**
 * Load a DID
 * 
 * @param type		type of the decentralized identifier, must be IOTA
 * @param args		builder_part_t argument list
 * @return 			loaded DID, NULL on failure 
 */

did_iota_t *did_load(decentralized_identifier_type_t type, va_list args);

#endif
#endif