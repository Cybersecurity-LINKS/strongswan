#ifndef SSI_VC_H
#define SSI_VC_H

typedef struct ssi_vc_t ssi_vc_t;

/*
* implementation of VC
*/

#include <credentials/keys/public_key.h>


struct ssi_vc {
    /**
	 * Implements the public_key_t interface
	 */
    public_key_t vc;
};

/**
 * Load a VC.
 *
 * @param type		type of the key, must be KEY_VC
 * @param args		builder_part_t argument list
 * @return 			loaded key, NULL on failure
 */
ssi_vc *ssi_vc_load(key_type_t type,
							    va_list args);



#endif