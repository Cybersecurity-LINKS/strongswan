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
#ifndef DID_IOTA_H
#define DID_IOTA_H

#include <credentials/dids/decentralized_identifier.h>
#include "identity.h"

extern Wallet *w; 

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
 * Generate a IOTA DID Document
 * 
 * @param type		type of the decentralized identifier, must be IOTA
 * @param args		builder_part_t argument list
 * @return 			generated DID, NULL on failure 
 */

did_iota_t *did_iota_gen(decentralized_identifier_type_t type, va_list args);

/**
 * Load a DID
 * 
 * @param type		type of the decentralized identifier, must be IOTA
 * @param args		builder_part_t argument list
 * @return 			loaded DID, NULL on failure 
 */

did_iota_t *did_iota_load(decentralized_identifier_type_t type, va_list args);

#endif
#endif