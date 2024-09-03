#ifndef SSI_DID_H
#define SSI_DID_H

#include <credentials/builder.h>
#include <credentials/keys/private_key.h>

typedef struct ssi_did_t ssi_did_t;

/*
* implementation of DID
*/
struct ssi_did_t {

    /**
	 * Implements private_key_t interface
	 */
	private_key_t key;
};

/**
 * Load a DID Document.
 *
 * @param type		type of the key, must be KEY_DID
 * @param args		builder_part_t argument list
 * @return 			loaded key, NULL on failure
 */
ssi_did_t *ssi_did_load(key_type_t type,
									va_list args);

#endif