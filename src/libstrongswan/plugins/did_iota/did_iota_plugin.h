#ifdef VC_AUTH
#ifndef DID_IOTA_PLUGIN_H
#define DID_IOTA_PLUGIN_H

#include <plugins/plugin.h>
#include <plugins/plugin_feature.h>


typedef struct did_iota_plugin_t did_iota_plugin_t;

/**
 * Plugin providing IOTA DID Method implementation
 */
struct did_iota_plugin_t {

	/**
	 * implements plugin interface
	 */
	plugin_t plugin;
};

#endif /** DID_IOTA_PLUGIN_H_ @}*/
#endif