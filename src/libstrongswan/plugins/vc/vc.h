#ifndef VC_H
#define VC_H

#include "identity.h"
#include <credentials/vcs/verifiable_credential.h>

typedef struct vc_t vc_t;

/**
 *  implementation of Ed25519 signature algorithm.
 */
struct vc_t {

    Vc *vc;    
};

vc_t *vc_load(verifiable_credential_type_t type, va_list args);

#endif
