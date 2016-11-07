/*
 * Copyright (C) 2013 Tobias Brunner
 * Hochschule fuer Technik Rapperswil
 *
 * Copyright (C) 2010 Martin Willi
 * Copyright (C) 2010 revosec AG
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

#include "pipe_plugin.h"

#include <daemon.h>
#include <plugins/plugin_feature.h>

#include "pipe_provider.h"

typedef struct private_pipe_plugin_t private_pipe_plugin_t;

/**
 * private data of pipe plugin
 */
struct private_pipe_plugin_t {

	/**
	 * implements plugin interface
	 */
	pipe_plugin_t public;

	/**
	 * Attribute provider
	 */
	pipe_provider_t *provider;
};

METHOD(plugin_t, get_name, char*,
	private_pipe_plugin_t *this)
{
	return "pipe";
}

/**
 * Register listener
 */
static bool plugin_cb(private_pipe_plugin_t *this,
					  plugin_feature_t *feature, bool reg, void *cb_data)
{
	if (reg)
	{
		this->provider = pipe_provider_create();
		charon->attributes->add_provider(charon->attributes, &this->provider->provider);
	}
	else
	{
		charon->attributes->remove_provider(charon->attributes, &this->provider->provider);
		this->provider->destroy(this->provider);
	}
	return TRUE;
}

METHOD(plugin_t, get_features, int,
	private_pipe_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_CALLBACK((plugin_feature_callback_t)plugin_cb, NULL),
			PLUGIN_PROVIDE(CUSTOM, "pipe")
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_pipe_plugin_t *this)
{
	free(this);
}

/**
 * Plugin constructor.
 */
plugin_t *pipe_plugin_create()
{
	private_pipe_plugin_t *this;

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
