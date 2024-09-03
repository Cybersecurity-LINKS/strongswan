#include "ssi_plugin.h"

#include <library.h>

typedef struct private_ssi_plugin_t private_ssi_plugin_t;

/**
 * private data of ssi_plugin
 */
struct private_ssi_plugin_t {
    /**
     * public functions
     */
    ssi_plugin_t public;
};

METHOD(plugin_t, get_name, char*,
	private_ssi_plugin_t *this)
    {
        return "ssi";
    }

METHOD(plugin_t, get_features, int,
	private_ssi_plugin_t *this, plugin_feature_t *features[])
{   
    static plugin_feature_t f[] = {};

    *features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_ssi_plugin_t *this)
{
    free(this);
}

/*
 * see header file
 */
plugin_t *ssi_plugin_create()
{
    private_ssi_plugin_t *this;

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