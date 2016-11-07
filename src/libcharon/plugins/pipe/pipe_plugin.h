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
 * @defgroup dhcp dhcp
 * @ingroup cplugins
 *
 * @defgroup dhcp_plugin dhcp_plugin
 * @{ @ingroup dhcp
 */

#ifndef PIPE_PLUGIN_H_
#define PIPE_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct pipe_plugin_t pipe_plugin_t;

/**
 * DHCP based attribute provider plugin.
 */
struct pipe_plugin_t {

	/**
	 * implements plugin interface
	 */
	plugin_t plugin;
};

#endif /** PIPE_PLUGIN_H_ @}*/
