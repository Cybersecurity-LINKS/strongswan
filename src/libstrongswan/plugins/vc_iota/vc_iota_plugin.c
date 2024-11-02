/*
 * Copyright 2024 Fondazione LINKS.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#ifdef VC_AUTH
#include "vc_iota_plugin.h"
#include "vc_iota.h"
#include "did_iota.h"

#include <library.h>

Wallet *w = NULL;
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

    /* Everytime the plugin is loaded the wallet setup occurs, 
     * this may be annoying during pki --gen when not generating
     * VCs, but for now it is the most convenient position. 
     */
    w = setup("./test-stuff/server.stronghold", "server");
	if (w == NULL)
		return NULL;
    
    return &this->public.plugin;
}
#endif