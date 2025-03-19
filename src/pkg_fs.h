
#ifndef _PKG_FS_H_
#define _PKG_FS_H_

#include <psp2/types.h>

#ifdef __cplusplus
extern "C" {
#endif


#define PKG_VFS_FLAG_HAS_ENTIRE_HASH (1 << 0)
#define PKG_VFS_FLAG_HAS_HEADER_HASH (1 << 1)
#define PKG_VFS_FLAG_HAS_DIRENT_HASH (1 << 2)

typedef struct _PackageVfsHeader { // size is 0x80-bytes
	char magic[8];
	SceUInt32 version;
	SceUInt32 flags;
	SceOff    pkg_length;
	SceUInt32 pkg_dirs;
	SceUInt32 pkg_files;
	SceOff    root_entry;
	SceOff    root_nentry;
	SceUInt32 padding_0x30;
	SceUInt32 padding_0x34;
	SceUInt32 padding_0x38;
	SceUInt32 padding_0x3C;

	SceUInt8 pkg_hash[0x20];
	SceUInt8 pkg_header_hash[0x20];
} PackageVfsHeader;

typedef struct _PackageVfsDirEnt { // size is 0x80-bytes
	SceUInt32 flags;
	SceUInt32 flags_2;
	SceOff padding_0x08;
	SceOff data_offset;
	SceOff data_length;
	char name[0x40];
	SceUInt8 hash[0x20];
} PackageVfsDirEnt;

#define PKG_FS_FLAG_ISDIR (1 << 0)

int _sceKernelMountPackage(const char *assign_name, const char *pkg_path, const char *pkg_vfs_path);
int _sceKernelUmountPackage(const char *assign_name, int flags);

int sceKernelMountPackageForUser(const char *assign_name, const char *pkg_path, const char *pkg_vfs_path);
int sceKernelUmountPackageForUser(const char *assign_name, int flags);


#ifdef __cplusplus
}
#endif

#endif /* _PKG_FS_H_ */
