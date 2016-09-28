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

#if ONICS_DLSYM_SUPPORT

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
#include "prlib.h"
#include "util.h"

#define ONICS_PROTO_DIR ONICS_INSTALL_PREFIX "/lib/onics/protocols"

static struct clist *prliblist = NULL;
static struct clist *dynliblist = NULL;


static const char *libname(struct prlib *lib)
{
	return (lib->name == NULL) ? "Unknown" : lib->name;
}


static void register_proto(struct prlib *lib, const char *path)
{
	int rv;
	if (lib->name == NULL || lib->pp_ops == NULL || lib->ns == NULL)
		err("Error parsing %s protocol in library %s\n",
		    libname(lib), path);
	rv = pp_register(lib->prid, lib->pp_ops);
	if (rv < 0)
		errsys("Could not register %s in %s to prid %u: ",
		       libname(lib), path, lib->prid);
	rv = ns_add_elem(NULL, (struct ns_elem *)lib->ns);
	if (rv < 0)
		err("%s in %s has a name conflict\n", libname(lib), path);
	if (lib->etype != 0) {
		rv = e2p_map_add(lib->etype, lib->prid);
		if (rv < 0)
			err("%s in %s can't map PRID %u to ethertype 0x%04x\n",
			    libname(lib), path, lib->prid, lib->etype);
	}
	cl_push(prliblist, lib);
}


static void load_prlib(const char *path)
{
	void *dlh;
	struct prlib *lib;

	if (prliblist == NULL)
		prliblist = cl_new(NULL, 1);
	if (dynliblist == NULL)
		dynliblist = cl_new(NULL, 1);

	dlh = dlopen(path, RTLD_LAZY);
	if (dlh == NULL)
		err("%s\n", dlerror());

	lib = dlsym(dlh, "_prlibs");
	if (lib == NULL)
		err("%s\n", dlerror());

	while (lib->prid != PRID_NONE) {
		register_proto(lib, path);
		++lib;
	}

	cl_push(dynliblist, dlh);
}


void register_extern_proto()
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
		free(path);
	}
	closedir(dir);
}


void unregister_extern_proto()
{
	struct prlib *lib;
	void *dlh;
	if (prliblist == NULL)
		return;
	while ((lib = cl_pop(prliblist)) != NULL) {
		pp_unregister(lib->prid);
		ns_rem_elem((struct ns_elem *)lib->ns);
	}
	while ((dlh = cl_pop(dynliblist)) != NULL)
		dlclose(dlh);
}


#else /* ONICS_DLSYM_SUPPORT */

void register_extern_proto()
{
}

void unregister_extern_proto()
{
}

#endif /* ONICS_DLSYM_SUPPORT */
