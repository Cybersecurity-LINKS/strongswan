#ifdef VC_AUTH
#include "vc_plugin.h"
#include "vc.h"
#include "did_iota.h"

#include <library.h>

typedef struct private_vc_plugin_t private_vc_plugin_t;

/**
 * private data of vc_plugin
 */
struct private_vc_plugin_t {
    /**
     * public functions
     */
    vc_plugin_t public;
};

METHOD(plugin_t, get_name, char*,
	private_vc_plugin_t *this)
    {
        return "vc";
    }

METHOD(plugin_t, get_features, int,
	private_vc_plugin_t *this, plugin_feature_t *features[])
{   
    static plugin_feature_t f[] = {
        PLUGIN_REGISTER(VC, vc_load, FALSE),
            PLUGIN_PROVIDE(VC, VC_DATA_MODEL_2_0),
        PLUGIN_REGISTER(VC, vc_gen, FALSE),
            PLUGIN_PROVIDE(VC, VC_DATA_MODEL_2_0),
        PLUGIN_REGISTER(DID, did_iota_gen, FALSE),
            PLUGIN_PROVIDE(DID, DID_IOTA),
        PLUGIN_REGISTER(DID, did_iota_load, FALSE),
            PLUGIN_PROVIDE(DID, DID_IOTA),
    };

    *features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_vc_plugin_t *this)
{
    free(this);
}

/*
 * see header file
 */
plugin_t *vc_plugin_create()
{
    private_vc_plugin_t *this;

    INIT(this,
        .public = {
            .plugin = {
                .get_name = _get_name,
                .get_features = _get_features,
                .destroy = _destroy,
            },
        },
    );

    return &this->public.plugin;
}
#endif