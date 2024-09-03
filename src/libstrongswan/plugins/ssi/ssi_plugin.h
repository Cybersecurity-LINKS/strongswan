#ifndef SSI_PLUGIN_H_
#define SSI_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct ssi_plugin_t ssi_plugin_t;

/**
 * Plugin providing SSI implementation
 */
struct ssi_plugin_t {

	/**
	 * implements plugin interface
	 */
	plugin_t plugin;
};


#endif /** SSI_PLUGIN_H_ @}*/