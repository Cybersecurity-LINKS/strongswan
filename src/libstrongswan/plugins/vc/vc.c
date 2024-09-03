#include "identity.h"
#include <utils/utils/object.h>
#include "vc.h"

typedef struct private_vc_t private_vc_t;

/*
*   Private data of vc_t object.
*/

struct private_vc_t {

    Wallet *w;
    Did *did;
};

/* METHOD(verifiable_credential_t, setup, int, private_vc_t *this, const char *stronghold_path, const char *password) {
    struct Wallet *w = w_setup("ciao", "ciao");
    return 1;
} */

/**
 * See header.
 */
vc_t *vc_load(verifiable_credential_type_t type, va_list args)
{
    //private_vc_t *this;
    return NULL;
}