/*
 * mapping.c
 *
 * Copyright (C) 2006  Insigma Co., Ltd
 *
 * This software has been developed while working on the Linux Unified Kernel
 * project (http://www.longene.org) in the Insigma Research Institute,  
 * which is a subdivision of Insigma Co., Ltd (http://www.insigma.com.cn).
 * 
 * The project is sponsored by Insigma Co., Ltd.
 *
 * The authors can be reached at linux@insigma.com.cn.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of  the GNU General  Public License as published by the
 * Free Software Foundation; either version 2 of the  License, or (at your
 * option) any later version.
 *
 * Revision History:
 *   Dec 2008 - Created.
 */
 
/*
 * mapping.c:
 * Refered to Wine code
 */
#include "section.h"
#include "handle.h"
#include "pefile.h"

#ifdef CONFIG_UNIFIED_KERNEL
struct uk_file;

struct mapping
{
	struct object   obj;             /* object header */
	file_pos_t      size;            /* mapping size */
	int             protect;         /* protection flags */
	struct uk_file *file;            /* file mapped */
	int             header_size;     /* size of headers (for PE image mapping) */
	void           *base;            /* default base addr (for PE image mapping) */
	struct uk_file *shared_file;     /* temp file for shared PE mapping */
	struct list_head     shared_entry;    /* entry in global shared PE mappings list */
};

static void mapping_dump(struct object *obj, int verbose);
static struct object_type *mapping_get_type(struct object *obj);
static struct fd *mapping_get_fd(struct object *obj);
static unsigned int mapping_map_access(struct object *obj, unsigned int access);
static void mapping_destroy(struct object *obj);

static const struct object_ops mapping_ops =
{
	sizeof(struct mapping),      /* size */
	mapping_dump,                /* dump */
	mapping_get_type,            /* get_type */
	mapping_get_fd,              /* get_fd */
	mapping_map_access,          /* map_access */
	no_lookup_name,              /* lookup_name */
	no_open_file,                /* open_file */
	fd_close_handle,             /* close_handle */
	mapping_destroy,             /* destroy */

	NULL,                      /* signaled */
	NULL,                      /* satisfied */
	no_signal,                 /* signal */
	default_get_sd,            /* get_sd */
	default_set_sd             /* set_sd */
};

static struct list_head shared_list = LIST_INIT(shared_list);

#define ROUND_SIZE(size)  (((size) + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1))

extern int is_same_file(void *file1, void *file2);
extern struct uk_file *create_temp_file(int access);
extern struct file *get_file_unix_file(struct uk_file *file);
extern struct uk_file *get_file_obj(struct w32process *process, obj_handle_t handle, unsigned int access);
extern int objattr_is_valid(const struct object_attributes *attrib, int size);
extern void objattr_get_name(const struct object_attributes *objattr, struct unicode_str *name);
extern obj_handle_t alloc_handle_no_access_check(struct w32process *process, void *ptr, unsigned int access, unsigned int attr);
extern HANDLE base_dir_handle;
struct object_type *get_object_type(const struct unicode_str *name);

/* find the shared PE mapping for a given mapping */
static struct uk_file *get_shared_file(struct mapping *mapping)
{
	struct mapping *ptr;

	LIST_FOR_EACH_ENTRY(ptr, &shared_list, struct mapping, shared_entry)
		if (is_same_file(ptr->file, mapping->file))
			return (struct uk_file *)grab_object(ptr->shared_file);
	return NULL;
}

/* return the size of the memory mapping and file range of a given section */
static inline void get_section_sizes(const IMAGE_SECTION_HEADER *sec, size_t *map_size,
					off_t *file_start, size_t *file_size)
{
	static const unsigned int sector_align = 0x1ff;

	if (!sec->Misc.VirtualSize)
		*map_size = ROUND_SIZE(sec->SizeOfRawData);
	else
		*map_size = ROUND_SIZE(sec->Misc.VirtualSize);

	*file_start = sec->PointerToRawData & ~sector_align;
	*file_size = (sec->SizeOfRawData + (sec->PointerToRawData & sector_align) + sector_align) & ~sector_align;
	if (*file_size > *map_size)
		*file_size = *map_size;
}

/* allocate and fill the temp file for a shared PE image mapping */
static int build_shared_mapping(struct mapping *mapping, struct file *filp,
					IMAGE_SECTION_HEADER *sec, unsigned int nb_sec)
{
	unsigned int i;
	file_pos_t total_size;
	size_t file_size, map_size, max_size;
	off_t shared_pos, read_pos, write_pos;
	char *buffer = NULL;
	struct file *shared_filp;
	long toread;

	/* compute the total size of the shared mapping */

	total_size = max_size = 0;
	for (i = 0; i < nb_sec; i++) {
		if ((sec[i].Characteristics & IMAGE_SCN_MEM_SHARED) &&
				(sec[i].Characteristics & IMAGE_SCN_MEM_WRITE)) {
			get_section_sizes(&sec[i], &map_size, &read_pos, &file_size);
			if (file_size > max_size)
				max_size = file_size;
			total_size += map_size;
		}
	}
	if (!total_size)
		return 1;  /* nothing to do */

	if ((mapping->shared_file = get_shared_file(mapping)))
		return 1;

	/* create a temp file for the mapping */
	if (!(mapping->shared_file = create_temp_file(FILE_GENERIC_READ|FILE_GENERIC_WRITE)))
		return 0;
	if (!grow_file(mapping->shared_file, total_size))
		goto error;
	if (!(shared_filp = get_file_unix_file(mapping->shared_file)))
		goto error;

	if (!(buffer = malloc(max_size)))
		goto error;

	/* copy the shared sections data into the temp file */
	shared_pos = 0;
	for (i = 0; i < nb_sec; i++) {
		if (!(sec[i].Characteristics & IMAGE_SCN_MEM_SHARED))
			continue;
		if (!(sec[i].Characteristics & IMAGE_SCN_MEM_WRITE))
			continue;
		get_section_sizes(&sec[i], &map_size, &read_pos, &file_size);
		write_pos = shared_pos;
		shared_pos += map_size;
		if (!sec[i].PointerToRawData || !file_size)
			continue;
		toread = file_size;
		while (toread) {
			long res = filp_pread(filp, buffer + file_size - toread, toread, read_pos);
			if (!res && toread < 0x200) { /* partial sector at EOF is not an error */
				file_size -= toread;
				break;
			}
			if (res <= 0)
				goto error;
			toread -= res;
			read_pos += res;
		}
		if (filp_pwrite(shared_filp, buffer, file_size, write_pos) != file_size)
			goto error;
	}
	free(buffer);
	return 1;

error:
	release_object(mapping->shared_file);
	mapping->shared_file = NULL;
	free(buffer);
	return 0;
}

/* retrieve the mapping parameters for an executable (PE) image */
static int get_image_params(struct mapping *mapping)
{
	IMAGE_DOS_HEADER dos;
	IMAGE_NT_HEADERS nt;
	IMAGE_SECTION_HEADER *sec = NULL;
	struct file *filp;
	off_t pos;
	int size, toread;

	/* load the headers */
	if (!(filp = get_file_unix_file(mapping->file)))
		goto error;
	if (filp_pread(filp, (char *)&dos, sizeof(dos), 0) != sizeof(dos))
		goto error;
	if (dos.e_magic != IMAGE_DOS_SIGNATURE)
		goto error;
	pos = dos.e_lfanew;

	if (filp_pread(filp, (char *)&nt.Signature, sizeof(nt.Signature), pos) != sizeof(nt.Signature))
		goto error;
	pos += sizeof(nt.Signature);
	if (nt.Signature != IMAGE_NT_SIGNATURE)
		goto error;
	if (filp_pread(filp, (char *)&nt.FileHeader, sizeof(nt.FileHeader), pos) != sizeof(nt.FileHeader))
		goto error;
	pos += sizeof(nt.FileHeader);
	/* zero out Optional header in the case it's not present or partial */
	memset(&nt.OptionalHeader, 0, sizeof(nt.OptionalHeader));
	toread = min((WORD)sizeof(nt.OptionalHeader), nt.FileHeader.SizeOfOptionalHeader);
	if (filp_pread(filp, (char *)&nt.OptionalHeader, toread, pos) != toread)
		goto error;
	pos += nt.FileHeader.SizeOfOptionalHeader;

	/* load the section headers */

	size = sizeof(*sec) * nt.FileHeader.NumberOfSections;
	if (!(sec = malloc(size)))
		goto error;
	if (filp_pread(filp, (char *)sec, size, pos) != size)
		goto error;

	if (!build_shared_mapping(mapping, filp, sec, nt.FileHeader.NumberOfSections))
		goto error;

	if (mapping->shared_file)
		list_add_head(&shared_list, &mapping->shared_entry);

	mapping->size        = ROUND_SIZE(nt.OptionalHeader.SizeOfImage);
	mapping->base        = (void *)nt.OptionalHeader.ImageBase;
	mapping->header_size = max((unsigned int)(pos + size), nt.OptionalHeader.SizeOfHeaders);
	mapping->protect     = VPROT_IMAGE;

	/* sanity check */
	if (pos + size > mapping->size)
		goto error;

	free(sec);
	return 1;

error:
	free(sec);
	set_error(STATUS_INVALID_FILE_FOR_SECTION);
	return 0;
}

static struct object *create_mapping(HANDLE root, const struct unicode_str *name,
					unsigned int attr, file_pos_t size, int protect,
					obj_handle_t handle, const struct security_descriptor *sd)
{
	struct mapping *mapping;
	int access = 0;

	if (!(mapping = create_named_object_dir(root, name, attr, &mapping_ops)))
		return NULL;
	if (get_error() == STATUS_OBJECT_NAME_EXISTS)
		return &mapping->obj;  /* Nothing else to do */

	INIT_DISP_HEADER(&mapping->obj.header, MAPPING, sizeof(struct mapping) / sizeof(ULONG), 0);
	mapping->header_size = 0;
	mapping->base        = NULL;
	mapping->shared_file = NULL;

	if (protect & VPROT_READ)
		access |= FILE_READ_DATA;
	if (protect & VPROT_WRITE)
		access |= FILE_WRITE_DATA;

	if (handle) {
		if (!(mapping->file = get_file_obj(get_current_w32process(), handle, access)))
			goto error;
		if (protect & VPROT_IMAGE) {
			if (!get_image_params(mapping))
				goto error;
			return &mapping->obj;
		}
		if (!size) {
			size = get_file_size(get_file_unix_file(mapping->file));
			if (!size) {
				set_error(STATUS_MAPPED_FILE_SIZE_ZERO);
				goto error;
			}
		}
		else {
			if (!grow_file(mapping->file, size))
				goto error;
		}
	}
	else { /* Anonymous mapping (no associated file) */
		if (!size || (protect & VPROT_IMAGE)) {
			set_error(STATUS_INVALID_PARAMETER);
			mapping->file = NULL;
			goto error;
		}
		if (!(mapping->file = create_temp_file(access)))
			goto error;
		if (!grow_file(mapping->file, size))
			goto error;
	}
	mapping->size    = ROUND_SIZE(size);
	mapping->protect = protect;
	return &mapping->obj;

error:
	release_object(mapping);
	return NULL;
}

static void mapping_dump(struct object *obj, int verbose)
{
}

static struct object_type *mapping_get_type(struct object *obj)
{
	static const WCHAR name[] = {'S','e','c','t','i','o','n'};
	static const struct unicode_str str = {name, sizeof(name)};
	return get_object_type(&str);
}

static struct fd *mapping_get_fd(struct object *obj)
{
	struct mapping *mapping = (struct mapping *)obj;
	return get_obj_fd((struct object *)mapping->file);
}

static unsigned int mapping_map_access(struct object *obj, unsigned int access)
{
	if (access & GENERIC_READ)
		access |= STANDARD_RIGHTS_READ | SECTION_QUERY | SECTION_MAP_READ;
	if (access & GENERIC_WRITE)
		access |= STANDARD_RIGHTS_WRITE | SECTION_MAP_WRITE;
	if (access & GENERIC_EXECUTE)
		access |= STANDARD_RIGHTS_EXECUTE | SECTION_MAP_EXECUTE;
	if (access & GENERIC_ALL)
		access |= SECTION_ALL_ACCESS;
	return access & ~(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL);
}

static void mapping_destroy(struct object *obj)
{
	struct mapping *mapping = (struct mapping *)obj;

	if (mapping->file)
		release_object(mapping->file);
	if (mapping->shared_file) {
		release_object(mapping->shared_file);
		list_remove(&mapping->shared_entry);
	}
}

/* create a file mapping */
DECL_HANDLER(create_mapping)
{
	struct object *obj;
	struct unicode_str name;
	struct directory *root = NULL;
	struct object_attributes *objattr = get_req_data();
	const struct security_descriptor *sd;

	ktrace("\n");
	reply->handle = 0;

	if (!objattr_is_valid(objattr, get_req_data_size()))
		return;

	sd = objattr->sd_len ? (const struct security_descriptor *)(objattr + 1) : NULL;
	objattr_get_name(objattr, &name);

	if (objattr->rootdir)
		objattr->rootdir = base_dir_handle;
	if ((obj = create_mapping(objattr->rootdir, &name, req->attributes, req->size, req->protect, req->file_handle, sd))) {
		if (get_error() == STATUS_OBJECT_NAME_EXISTS)
			reply->handle = alloc_handle(get_current_w32process(), obj, req->access, req->attributes);
		else
			reply->handle = alloc_handle_no_access_check(get_current_w32process(), obj, req->access, req->attributes);
		release_object(obj);
	}

	if (root)
		release_object(root);
}

/* open a handle to a mapping */
DECL_HANDLER(open_mapping)
{
	struct unicode_str name;
	struct directory *root = NULL;
	struct mapping *mapping;

	ktrace("\n");
	get_req_unicode_str(&name);

	if ((mapping = open_object_dir(req->rootdir ? base_dir_handle : NULL, &name, req->attributes, &mapping_ops))) {
		reply->handle = alloc_handle(get_current_w32process(), &mapping->obj, req->access, req->attributes);
		release_object(mapping);
	}

	if (root)
		release_object(root);
}

/* get a mapping information */
DECL_HANDLER(get_mapping_info)
{
	struct mapping *mapping;
	struct fd *fd;

	ktrace("\n");
	if ((mapping = (struct mapping *)get_wine_handle_obj(get_current_w32process(), req->handle,
					0, &mapping_ops))) {
		reply->size        = mapping->size;
		reply->protect     = mapping->protect;
		reply->header_size = mapping->header_size;
		reply->base        = mapping->base;
		reply->shared_file = 0;
		if ((fd = get_obj_fd(&mapping->obj))) {
			if (!is_fd_removable(fd))
				reply->mapping = alloc_handle(get_current_w32process(), mapping, 0, 0);
			release_object(fd);
		}
		if (mapping->shared_file) {
			if (!(reply->shared_file = alloc_handle(get_current_w32process(), mapping->shared_file,
							GENERIC_READ|GENERIC_WRITE, 0))) {
				if (reply->mapping) close_handle(get_current_eprocess(), reply->mapping);
			}
		}
		release_object(mapping);
	}
}
#endif /* CONFIG_UNIFIED_KERNEL */
