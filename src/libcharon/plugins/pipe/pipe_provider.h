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

/**
 * @defgroup pipe_provider pipe_provider
 * @{ @ingroup pipe
 */

#ifndef PIPE_PROVIDER_H_
#define PIPE_PROVIDER_H_

typedef struct pipe_provider_t pipe_provider_t;

#include <attributes/attribute_provider.h>

/**
 * DHCP based attribute provider.
 */
struct pipe_provider_t {

	/**
	 * Implements attribute_provier_t interface.
	 */
	attribute_provider_t provider;

	/**
	 * Destroy a pipe_provider_t.
	 */
	void (*destroy)(pipe_provider_t *this);
};

/**
 * Create a pipe_provider instance.
 *
 * @param socket		socket to use for DHCP communication
 * @return				provider instance
 */
pipe_provider_t *pipe_provider_create();

#endif /** PIPE_PROVIDER_H_ @}*/
