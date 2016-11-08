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

#ifndef PIPE_IMPL_H_
#define PIPE_IMPL_H_

host_t *acquire(char *, ike_sa_t *, host_t *);
int release(char *, ike_sa_t *, host_t *);
linked_list_t *attr(char *, ike_sa_t *);

#endif /** PIPE_IMPL_H_ @}*/
