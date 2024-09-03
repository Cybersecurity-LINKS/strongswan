#ifndef VERIFIABLE_CREDENTIAL_H_
#define VERIFIABLE_CREDENTIAL_H_

#include <utils/identification.h>

typedef struct verifiable_credential_t verifiable_credential_t;

/*
* An abstract VC
*/

typedef enum verifiable_credential_type_t verifiable_credential_type_t; 

enum verifiable_credential_type_t {
    /** vc type wildcard */
    VC_ANY              = 0,
    /** DATA MODEL 2.0 */
    VC_DATA_MODEL_2_0   = 1,
};

/**
 * Enum names for key_type_t
 */
extern enum_name_t *vc_type_names;

struct verifiable_credential_t {

    int (*setup)(const char *stronghold_path, const char *password);
    //Did *(*did_create)(const Wallet *wallet);
};

#endif