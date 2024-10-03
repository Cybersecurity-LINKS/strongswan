#ifdef VC_AUTH
#include "did_iota_plugin.h"
#include "did_iota.h"

typedef struct private_did_iota_plugin_t private_did_iota_plugin_t;

/**
 * private data of did_iota_plugin
 */
struct private_did_iota_plugin_t {
    /**
     * public functions
     */
    did_iota_plugin_t public;
};

METHOD(plugin_t, get_name, char*,
	private_did_iota_plugin_t *this)
    {
        return "did-iota";
    }

METHOD(plugin_t, get_features, int,
	private_did_iota_plugin_t *this, plugin_feature_t *features[])
{   
    static plugin_feature_t f[] = {
        PLUGIN_REGISTER(DID, did_load, FALSE),
            PLUGIN_PROVIDE(DID, DID_IOTA),
    };

    *features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_did_iota_plugin_t *this)
{
    free(this);
}

/*
 * see header file
 */
plugin_t *did_iota_plugin_create()
{
    private_did_iota_plugin_t *this;

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