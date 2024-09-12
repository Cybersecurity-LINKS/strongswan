#ifdef VC_AUTH
#ifndef VC_PLUGIN_H_
#define VC_PLUGIN_H_

#include <plugins/plugin.h>
#include <plugins/plugin_feature.h>


typedef struct vc_plugin_t vc_plugin_t;

/**
 * Plugin providing VC implementation
 */
struct vc_plugin_t {

	/**
	 * implements plugin interface
	 */
	plugin_t plugin;
};


#endif /** VC_PLUGIN_H_ @}*/
#endif