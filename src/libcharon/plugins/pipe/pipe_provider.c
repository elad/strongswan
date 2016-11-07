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

#include <library.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

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

static char *send_and_receive(private_pipe_provider_t *this, char *msg)
{
	int sock, len;
	struct sockaddr_un sun;
	char *res;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock == -1)
	{
		DBG1(DBG_NET, "could not create Unix domain socket: %s", strerror(errno));
		return NULL;
	}

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strcpy(sun.sun_path, this->path);
	len = strlen(sun.sun_path) + sizeof(sun.sun_family);
	if (connect(sock, (struct sockaddr *)&sun, len) == -1)
	{
		DBG1(DBG_NET, "could not connect to Unix domain socket at %s: %s", this->path, strerror(errno));
		return NULL;
	}

	if (send(sock, msg, strlen(msg), 0) == -1)
	{
		DBG1(DBG_NET, "could not communicate with Unix domain socket at %s: %s", this->path, strerror(errno));
		return NULL;
	}

	close(sock);

	asprintf(&res, "RESPONSE");

	return res;
}

static host_t *acquire(private_pipe_provider_t *this, ike_sa_t *ike_sa, host_t *requested)
{
	char *proto = NULL;
	char *msg = NULL;
	char *res = NULL;

	switch (requested->get_family(requested)) {
		case AF_INET:
			proto = "IPv4";
			break;
		case AF_INET6:
			proto = "IPv6";
			break;
		default:
			return NULL;
	}

	if (asprintf(&msg, "ACQUIRE %Y %s\n", ike_sa->get_other_eap_id(ike_sa), proto) == -1)
	{
		DBG1(DBG_ENC, "could not create message for Unix domain socket: %s", strerror(errno));
		return NULL;
	}

	res = send_and_receive(this, msg);
	free(msg);
	if (res == NULL)
	{
		DBG1(DBG_NET, "could not communicate over Unix domain socket");
		return NULL;
	}

	free(res);

	return host_create_from_string("2a0a:4b00:1234::3", 0);
}

METHOD(attribute_provider_t, acquire_address, host_t*,
	private_pipe_provider_t *this, linked_list_t *pools,
	ike_sa_t *ike_sa, host_t *requested)
{
	enumerator_t *enumerator;
	char *pool;
	host_t *vip = NULL;
	identification_t *id = ike_sa->get_other_eap_id(ike_sa);

	enumerator = pools->create_enumerator(pools);
	while (enumerator->enumerate(enumerator, &pool))
	{
		if (!streq(pool, "pipe"))
		{
			continue;
		}

		vip = acquire(this, ike_sa, requested);
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
	//identification_t *id;
	bool found = FALSE;
	char *pool;

	DBG1(DBG_CFG, "pipe: release: enter");

	//id = ike_sa->get_other_eap_id(ike_sa);
	enumerator = pools->create_enumerator(pools);
	while (enumerator->enumerate(enumerator, &pool))
	{
		if (!streq(pool, "pipe"))
		{
			continue;
		}
		DBG1(DBG_CFG, "pipe: release: communicate");
		/* TODO: socket comm */
		if (TRUE/* TODO: address acquired from pipe */)
		{
			/* TODO: socket comm */
			found = TRUE;
			break;
		}
	}
	enumerator->destroy(enumerator);
	DBG1(DBG_CFG, "pipe: release: leave");
	return found;
}

static linked_list_t *get_attr(private_pipe_provider_t *this, ike_sa_t *ike_sa)
{
	char *msg = NULL;
	char *res = NULL;
	char *tmp = NULL;

	if (asprintf(&msg, "ATTR %Y\n", ike_sa->get_other_eap_id(ike_sa)) == -1)
	{
		DBG1(DBG_ENC, "could not create message for Unix domain socket: %s", strerror(errno));
		return NULL;
	}

	res = send_and_receive(this, msg);
	free(msg);
	if (res == NULL)
	{
		DBG1(DBG_NET, "could not communicate over Unix domain socket");
		return NULL;
	}

	free(res);

	linked_list_t *attributes = linked_list_create();

	host_t *dns = host_create_from_string("2a0a:4b00:1234::1", 0);
	attribute_entry_t *entry;
	INIT(entry,
		.type = INTERNAL_IP6_DNS,
		.data = dns->get_address(dns),
	);
	attributes->insert_last(attributes, entry);

	return attributes;
}

METHOD(attribute_provider_t, create_attribute_enumerator, enumerator_t*,
	private_pipe_provider_t *this, linked_list_t *pools, ike_sa_t *ike_sa,
	linked_list_t *vips)
{

	linked_list_t *attributes = get_attr(this, ike_sa);
	return attributes ? attributes->create_enumerator(attributes) : NULL;
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
		DBG1(DBG_CFG, "configured Unix domain socket path invalid");
		destroy(this);
		return NULL;
	}

	return &this->public;
}
