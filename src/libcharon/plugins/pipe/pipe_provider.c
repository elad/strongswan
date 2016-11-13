/*
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

#include "pipe_provider.h"
#include "pipe_impl.h"

#include <library.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <credentials/certificates/x509.h>

#define	RECV_BUFSIZE	(1024)

typedef struct private_pipe_provider_t private_pipe_provider_t;

/**
 * Private data of an pipe_provider_t object.
 */
struct private_pipe_provider_t {
	/**
	 * Public pipe_provider_t interface.
	 */
	pipe_provider_t public;

	/**
	 * Unix domain socket path
	 */
	char *path;
};

/**
 * Entry for an added attribute
 */
typedef struct {
	configuration_attribute_type_t type;
	chunk_t data;
} attribute_entry_t;

METHOD(attribute_provider_t, acquire_address, host_t*,
	private_pipe_provider_t *this, linked_list_t *pools,
	ike_sa_t *ike_sa, host_t *requested)
{
	enumerator_t *enumerator;
	char *pool;
	host_t *vip = NULL;

	enumerator = pools->create_enumerator(pools);
	while (enumerator->enumerate(enumerator, &pool))
	{
		if (!streq(pool, "pipe"))
		{
			continue;
		}

		vip = acquire(this->path, ike_sa, requested);
		if (vip != NULL)
		{
			break;
		}

		break;
	}
	enumerator->destroy(enumerator);
	return vip;
}

METHOD(attribute_provider_t, release_address, bool,
	private_pipe_provider_t *this, linked_list_t *pools,
	host_t *address, ike_sa_t *ike_sa)
{
	enumerator_t *enumerator;
	bool found = FALSE;
	char *pool;

	enumerator = pools->create_enumerator(pools);
	while (enumerator->enumerate(enumerator, &pool))
	{
		if (!streq(pool, "pipe"))
		{
			continue;
		}

		int rv = release(this->path, ike_sa, address);
		if (rv != -1)
		{
			found = TRUE;
			break;
		}
	}
	enumerator->destroy(enumerator);
	return found;
}

METHOD(attribute_provider_t, create_attribute_enumerator, enumerator_t*,
	private_pipe_provider_t *this, linked_list_t *pools, ike_sa_t *ike_sa,
	linked_list_t *vips)
{
	return attr(this->path, ike_sa);
}

METHOD(pipe_provider_t, destroy, void, private_pipe_provider_t *this)
{
	free(this);
}

/**
 * See header
 */
pipe_provider_t *pipe_provider_create()
{
	private_pipe_provider_t *this;

	INIT(this,
		.public = {
			.provider = {
				.acquire_address = _acquire_address,
				.release_address = _release_address,
				.create_attribute_enumerator = _create_attribute_enumerator,
			},
			.destroy = _destroy,
		},
		.path = lib->settings->get_str(lib->settings, "%s.plugins.pipe.path", NULL, lib->ns),
	);

	if (this->path == NULL)
	{
		DBG1(DBG_CFG, "invalid Unix domain socket path");
		destroy(this);
		return NULL;
	}

	return &this->public;
}
