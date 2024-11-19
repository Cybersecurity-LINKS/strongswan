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
#ifndef VC_H
#define VC_H

#include <credentials/vcs/verifiable_credential.h>

typedef struct vc_t vc_t;

/**
 *  implementation of VC.
 */
struct vc_t {
    
    /**
     * Implements the verifiable_credential_t
     */
    verifiable_credential_t vc;    
};

/**
 * Generate a VC
 * 
 * @param type		type of the verifiable credential, must be DATA MODEL 2.0
 * @param args		builder_part_t argument list
 * @return 			Generated VC, NULL on failure 
 */

vc_t *vc_iota_gen(verifiable_credential_type_t type, va_list args);

/**
 * Load a VC
 * 
 * @param type		type of the verifiable credential, must be DATA MODEL 2.0
 * @param args		builder_part_t argument list
 * @return 			loaded VC, NULL on failure 
 */

vc_t *vc_iota_load(verifiable_credential_type_t type, va_list args);

#endif
#endif
