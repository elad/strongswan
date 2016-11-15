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

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <credentials/certificates/x509.h>

#define	RECV_BUFSIZE	(1024)

/**
 * Entry for an added attribute
 */
typedef struct {
	configuration_attribute_type_t type;
	chunk_t data;
} attribute_entry_t;

static int send_and_receive(char *path, char *msg, char **res)
{
	int sock, len;
	struct sockaddr_un sun;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock == -1)
	{
		DBG1(DBG_NET, "pipe: send_and_receive: socket failed: %s", strerror(errno));
		return -1;
	}

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strcpy(sun.sun_path, path);
	len = strlen(sun.sun_path) + sizeof(sun.sun_family);
	if (connect(sock, (struct sockaddr *)&sun, len) == -1)
	{
		DBG1(DBG_NET, "pipe: send_and_receive: connect failed: %s", strerror(errno));
		(void)close(sock);
		return -1;
	}

	if (send(sock, msg, strlen(msg), 0) == -1)
	{
		DBG1(DBG_NET, "pipe: send_and_receive: send failed: %s", strerror(errno));
		(void)close(sock);
		return -1;
	}

	*res = calloc(1, RECV_BUFSIZE);
	if (*res == NULL)
	{
		DBG1(DBG_ENC, "pipe: send_and_receive: calloc failed: %s", strerror(errno));
		(void)close(sock);
		return -1;
	}

	if (recv(sock, *res, RECV_BUFSIZE, 0) == -1)
	{
		DBG1(DBG_NET, "pipe: send_and_receive: recv failed: %s", strerror(errno));
		free(*res);
		(void)close(sock);
		return -1;
	}

	if (close(sock) == -1)
	{
		DBG1(DBG_NET, "pipe: send_and_receive: close failed: %s", strerror(errno));
	}

	if (strcmp(*res, "ERROR") == 0)
	{
		free(*res);
		*res = NULL;
		return -1;
	}

	return 0;
}

static const char *get_proto(host_t *host)
{
	int af = host->get_family(host);
	switch (af) {
		case AF_INET:
			return "IPv4";
		case AF_INET6:
			return "IPv6";
		default:
			DBG1(DBG_ENC, "pipe: get_proto: unknown protocol family: %d", af);
			return NULL;
	}
}

static x509_t *get_x509(ike_sa_t *ike_sa)
{
	x509_t *x509 = NULL;
	enumerator_t *cfgs = ike_sa->create_auth_cfg_enumerator(ike_sa, FALSE);
	auth_cfg_t *auth;
	while (cfgs->enumerate(cfgs, &auth))
	{
		enumerator_t *items = auth->create_enumerator(auth);
		certificate_t *cert;
		auth_rule_t type;
		while (items->enumerate(items, &type, &cert))
		{
			if (type == AUTH_RULE_SUBJECT_CERT && cert->get_type(cert) == CERT_X509)
			{
				x509 = (x509_t*)cert;
				break;
			}
		}
		items->destroy(items);
	}
	cfgs->destroy(cfgs);
	if (!x509)
	{
		DBG1(DBG_ENC, "pipe: get_x509: could not find subject x509 certificate");
	}
	return x509;
}

/* From http://stackoverflow.com/a/10347773 */
static int ends_with(const char *str, const char *suffix)
{
  int str_len = strlen(str);
  int suffix_len = strlen(suffix);
  return (str_len >= suffix_len) && !strcmp(str + (str_len-suffix_len), suffix);
}

static identification_t *get_san(x509_t *x509)
{
	enumerator_t *sans;
	identification_t *id;
	sans = x509->create_subjectAltName_enumerator(x509);
	while (sans->enumerate(sans, &id))
	{
		if (id->get_type(id) == ID_FQDN)
		{
			char *str;
			if (asprintf(&str, "%Y", id) == -1)
			{
				DBG1(DBG_ENC, "pipe: get_san: asprintf failed: %s", strerror(errno));
				sans->destroy(sans);
				return NULL;
			}
			bool match = ends_with(str, ".nsof");
			free(str);
			if (match)
			{
				sans->destroy(sans);
				return id;
			}
		}
	}
	sans->destroy(sans);

	return NULL;
}

host_t *acquire(char *path, ike_sa_t *ike_sa, host_t *requested)
{
	char *msg = NULL;
	char *res = NULL;

	const char *proto = get_proto(requested);
	if (!proto)
	{
		return NULL;
	}

	x509_t *x509 = get_x509(ike_sa);
	if (!x509)
	{
		return NULL;
	}
	identification_t *san = get_san(x509);
	chunk_t serial = chunk_skip_zero(x509->get_serial(x509));
	int rv = asprintf(&msg, "ACQUIRE %s %Y %#B\n", proto, san, &serial);
	free(serial.ptr);
	if (rv == -1)
	{
		DBG1(DBG_ENC, "pipe: acquire: asprintf failed: %s", strerror(errno));
		return NULL;
	}

	rv = send_and_receive(path, msg, &res);
	free(msg);
	if (rv == -1)
	{
		DBG1(DBG_NET, "pipe: acquire: send_and_receive failed");
		return NULL;
	}

	host_t *host = host_create_from_string(res, 0);
	free(res);

	return host;
}

int release(char *path, ike_sa_t *ike_sa, host_t *address)
{
	char *msg = NULL;
	char *res = NULL;

	const char *proto = get_proto(address);
	if (!proto)
	{
		return -1;
	}

	x509_t *x509 = get_x509(ike_sa);
	if (!x509)
	{
		return NULL;
	}
	identification_t *san = get_san(x509);
	if (asprintf(&msg, "RELEASE %s %Y %H\n", proto, san, address) == -1)
	{
		DBG1(DBG_ENC, "pipe: release: asprintf failed: %s", strerror(errno));
		return -1;
	}

	int rv = send_and_receive(path, msg, &res);
	free(msg);
	if (rv == -1)
	{
		DBG1(DBG_NET, "pipe: release: send_and_receive failed");
		return -1;
	}

	free(res);

	return 0;
}

static bool attribute_filter(void *null, attribute_entry_t **entry, configuration_attribute_type_t *type, void **dummy, chunk_t *data)
{
	*type = (*entry)->type;
	*data = (*entry)->data;
	return TRUE;
}

enumerator_t *attr(char *path, ike_sa_t *ike_sa)
{
	char *msg = NULL;
	char *res = NULL;
	int rv;

	x509_t *x509 = get_x509(ike_sa);
	if (!x509)
	{
		return NULL;
	}
	identification_t *san = get_san(x509);
	if (asprintf(&msg, "ATTR %Y\n", san) == -1)
	{
		DBG1(DBG_ENC, "pipe: attr: asprintf failed: %s", strerror(errno));
		return NULL;
	}

	rv = send_and_receive(path, msg, &res);
	free(msg);
	if (rv == -1)
	{
		DBG1(DBG_NET, "pipe: attr: send_and_receive failed");
		return NULL;
	}

	linked_list_t *attributes = linked_list_create();
	enumerator_t *enumerator = enumerator_create_token(res, " ", " ");
	char *token;
	bool is_type = TRUE;
	configuration_attribute_type_t type = 0;
	while (enumerator->enumerate(enumerator, &token))
	{
		bool skip = FALSE;

		if (is_type) {
			if (strcmp(token, "DNS4") == 0) {
				type = INTERNAL_IP4_DNS;
			} else if (strcmp(token, "DNS6") == 0) {
				type = INTERNAL_IP6_DNS;
			} else {
				DBG1(DBG_ENC, "pipe: attr: unknown attribute type: %s", token);
				skip = TRUE;
			}
		} else {
			chunk_t data;
			switch (type) {
				case INTERNAL_IP4_DNS:
				case INTERNAL_IP6_DNS:
					{
					host_t *host = host_create_from_string(token, 0);
					data = host->get_address(host);
					break;
					}
				default:
					DBG1(DBG_ENC, "pipe: attr: skipping setting data for unknown attribute");
					skip = true;
					break;
			}

			if (!skip) {
				attribute_entry_t *entry;
				INIT(entry,
					.type = type,
					.data = chunk_clone(data),
				);
				attributes->insert_last(attributes, entry);
			}
		}
		is_type = !is_type;
	}
	enumerator->destroy(enumerator);
	free(res);

	return enumerator_create_filter(attributes->create_enumerator(attributes), (void *)attribute_filter, NULL, NULL);
}

