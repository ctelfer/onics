/*
 * ONICS
 * Copyright 2016
 * Christopher Adam Telfer
 *
 * prload.c -- Code loading external protocol libraries
 *
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "onics_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <cat/cat.h>
#include <cat/emalloc.h>
#include <cat/err.h>
#include <cat/stduse.h>
#include "prid.h"
#include "protoparse.h"
#include "ns.h"
#include "prload.h"
#include "util.h"

int register_protocol(struct oproto *opr)
{
	if (opr->ops == NULL || opr->ns == NULL)
		return -1;
	if (pp_register(opr->prid, opr->ops) < 0)
		return -1;
	if (ns_add_elem(NULL, (struct ns_elem *)opr->ns) < 0) {
		pp_unregister(opr->prid);
		return -1;
	}
	if (opr->etype != 0) {
		if (e2p_map_add(opr->etype, opr->prid) < 0) {
			ns_rem_elem((struct ns_elem *)opr->ns);
			pp_unregister(opr->prid);
			return -1;
		}
	}
	return 0;
}


void unregister_protocol(struct oproto *opr)
{
	if (opr->etype != 0)
		e2p_map_del(opr->etype);
	ns_rem_elem((struct ns_elem *)opr->ns);
	pp_unregister(opr->prid);
}


#if ONICS_DLSYM_SUPPORT

#define ONICS_PROTO_DIR ONICS_INSTALL_PREFIX "/lib/onics/protocols"


struct oproto_library {
	const char *path;
	void *handle;
	int (*load)(void);
	void (*unload)(void);
};


static struct clist *oprliblist = NULL;


static void load_prlib(const char *path)
{
	struct oproto_library *lib;

	abort_unless(path != NULL);

	if (oprliblist == NULL)
		oprliblist = cl_new(NULL, 1);

	lib = ecalloc(sizeof(*lib), 1);

	lib->path = path;

	lib->handle = dlopen(path, RTLD_LAZY);
	if (lib->handle == NULL)
		err("%s\n", dlerror());

	lib->load = dlsym(lib->handle, "load");
	if (lib->load == NULL)
		err("%s\n", dlerror());

	lib->unload = dlsym(lib->handle, "unload");
	if (lib->unload == NULL)
		err("%s\n", dlerror());

	if ((*lib->load)() < 0)
		errsys("Error loading %s: ");

	cl_push(oprliblist, lib);
}


void load_external_protocols()
{
	DIR *dir;
	struct dirent *ent;
	char *path;
	
	dir = opendir(ONICS_PROTO_DIR);
	if (dir == NULL)
		return;
	while ((ent = readdir(dir)) != NULL) {
		if (ent->d_type != DT_REG)
			continue;
		path = str_cat_a(ONICS_PROTO_DIR"/", ent->d_name);
		load_prlib(path);
	}
	closedir(dir);
}


void unload_external_protocols()
{
	struct oproto_library *lib;
	if (oprliblist == NULL)
		return;
	while ((lib = cl_pop(oprliblist)) != NULL) {
		(*lib->unload)();
		dlclose(lib->handle);
		free(lib);
	}
}


#else /* ONICS_DLSYM_SUPPORT */

void load_external_protocols()
{
}

void unload_external_protocols()
{
}

#endif /* ONICS_DLSYM_SUPPORT */
