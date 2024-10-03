#ifdef VC_AUTH
#ifndef VC_H
#define VC_H

//#include "identity.h"
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
 * Load a VC
 * 
 * @param type		type of the verifiable credential, must be DATA MODEL 2.0
 * @param args		builder_part_t argument list
 * @return 			loaded VC, NULL on failure 
 */

vc_t *vc_load(verifiable_credential_type_t type, va_list args);

#endif
#endif
