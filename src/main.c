
#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/cpu.h>
#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/kernel/debug.h>
#include <psp2kern/kernel/utils.h>
#include <psp2kern/kernel/ssmgr.h>
#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/iofilemgr.h>
#include <psp2kern/pfsmgr.h>
#include <psp2kern/power.h>
#include <psp2kern/vfs.h>
#include <psp2kern/pfsmgr.h>
#include <psp2/kernel/error.h>
#include <taihen.h>
#include "pkg_fs.h"
#include "npdrm.h"


#define SCE_ERROR_ERRNO_ENOENT (0x80010002)
#define SCE_ERROR_ERRNO_ENOMEM (0x8001000C)
#define SCE_ERROR_ERRNO_EUNSUP (0x80010030)

static const SceUInt8 pkg_ps3_key[] = {0x2E, 0x7B, 0x71, 0xD7, 0xC9, 0xC9, 0xA1, 0x4E, 0xA3, 0x22, 0x1F, 0x18, 0x88, 0x28, 0xB8, 0xF8};
static const SceUInt8 pkg_psp_key[] = {0x07, 0xF2, 0xC6, 0x82, 0x90, 0xB5, 0x0D, 0x2C, 0x33, 0x81, 0x8D, 0x70, 0x9B, 0x60, 0xE6, 0x2B};
static const SceUInt8 pkg_vita_2[]  = {0xE3, 0x1A, 0x70, 0xC9, 0xCE, 0x1D, 0xD7, 0x2B, 0xF3, 0xC0, 0x62, 0x29, 0x63, 0xF2, 0xEC, 0xCB};
static const SceUInt8 pkg_vita_3[]  = {0x42, 0x3A, 0xCA, 0x3A, 0x2B, 0xD5, 0x64, 0x9F, 0x96, 0x86, 0xAB, 0xAD, 0x6F, 0xD8, 0x80, 0x1F};
static const SceUInt8 pkg_vita_4[]  = {0xAF, 0x07, 0xFD, 0x59, 0x65, 0x25, 0x27, 0xBA, 0xF1, 0x33, 0x89, 0x66, 0x8B, 0x17, 0xD9, 0xEA};

int npdrm_package_decrypt(const void *src, void *dst, SceSize length, SceOff offset, const void *key, const void *iv){

	int res;
	uint8_t _iv[0x10];
	SceOff _len2 = offset / 16;

	uint8_t off[0x10];
	memset(off, 0, sizeof(off));
	off[0xF] = (_len2 >> 0) & 0xFF;
	off[0xE] = (_len2 >> 8) & 0xFF;
	off[0xD] = (_len2 >> 16) & 0xFF;
	off[0xC] = (_len2 >> 24) & 0xFF;

	uint32_t carry = 0;
	for(int k=0;k<0x10;k++){
		uint32_t t = (uint32_t)(((SceUInt8 *)iv)[0xF - k] + (uint32_t)off[0xF - k] + carry);
		_iv[k] = t & 0xFF;
		carry = (t >> 8) & 1;
	}

	res = ksceSblDmac5AesCtrDec(src, dst, length, key, 128, _iv, 1);
	if(res < 0){
		return res;
	}

	return SCE_OK;;
}

int DecodePathElem(void *a1, const char *path, SceSize *child_index, SceSize *pResultSize, char *dst, SceSize dst_size){

	*child_index = 0;

	if(dst_size == 0){
		return -1;
	}

	while(path[*child_index] == '/'){
		*child_index += 1;
	}

	const char *fname = &(path[*child_index]);

	while(*fname != 0 && *fname != '/'){

		if((dst_size - 1) == *pResultSize){
			break;
		}

		dst[*pResultSize] = toupper(*fname);
		*pResultSize += 1;
		fname += 1;
	}

	if((dst_size - 1) != *pResultSize){
		dst[*pResultSize] = 0;
	}

	return SCE_OK;
}

int _sceVfsOpDecodePathElem(void *pMount, const char *path, const char **dst_path, const char **child, char *dst, SceSize dst_size, SceSize *pResultSize){

	int res;
	SceUInt32 index;

	*pResultSize = 0;
	index = 0;

	res = DecodePathElem(pMount, path, &index, pResultSize, dst, dst_size);
	if(res == SCE_OK){
		*dst_path = path + index;
		*child    = path + index + *pResultSize;
	}

	return res;
}

typedef struct _pkg_fs_context {
	char *pkg_path;
	SceUID pkg_fd;
	SceVfsFile *pkg_vfs_file;
	SceUID pkg_vfs_fd;
	char assign_name[0x10];
	SceIoStat stat;
	SceOff enc_data_offset;
	SceUInt8 key[0x10];
	SceUInt8 iv[0x10];
} pkg_fs_context;

typedef struct _pkg_fs_fd {
	SceOff offset;
	SceOff length;
} pkg_fs_fd;

typedef struct _pkg_fs_file {
	SceOff length;
} pkg_fs_file;

typedef struct _pkg_fs_io_fd {
	void *buffer;
	void *buffer_aigned;
	SceSize buffer_size;
} pkg_fs_io_fd;

int pkg_init_npdrm_package(pkg_fs_context *ctx){

	void *pkg_hdr_raw = ksceKernelAllocHeapMemory(SCE_KERNEL_HEAP_ID, 0x8000);

	int res = ksceIoPread(ctx->pkg_fd, pkg_hdr_raw, 0x8000, 0LL);
	if(res < 0){
		return res;
	}

	ScePackageHeader *pkg_hdr = (ScePackageHeader *)pkg_hdr_raw;

	ctx->enc_data_offset = __builtin_bswap64(pkg_hdr->data_offset);

	if(__builtin_bswap16(pkg_hdr->type) != 2){
		memcpy(ctx->key, pkg_ps3_key, sizeof(ctx->key));
		memcpy(ctx->iv, pkg_hdr->riv, sizeof(ctx->iv));
	}else{
		ScePackageExtHeader *ext_hdr = (ScePackageExtHeader *)&(pkg_hdr[1]);

		SceAesContext aes_ctx;
		SceUInt8 body_key[0x10];

		switch(__builtin_bswap32(ext_hdr->pkg_key_id) & 7){
		case 1:
			memcpy(body_key, pkg_psp_key, 0x10);
			break;
		case 2:
			ksceAesInit1(&aes_ctx, 0x80, 0x80, pkg_vita_2);
			ksceAesEncrypt1(&aes_ctx, pkg_hdr->riv, body_key);
			break;
		case 3:
			ksceAesInit1(&aes_ctx, 0x80, 0x80, pkg_vita_3);
			ksceAesEncrypt1(&aes_ctx, pkg_hdr->riv, body_key);
			break;
		case 4:
			ksceAesInit1(&aes_ctx, 0x80, 0x80, pkg_vita_4);
			ksceAesEncrypt1(&aes_ctx, pkg_hdr->riv, body_key);
			break;
		default:
			memset(body_key, 0, 0x10);
			break;
		}

		memcpy(ctx->key, body_key, sizeof(ctx->key));
		memcpy(ctx->iv, pkg_hdr->riv, sizeof(ctx->iv));
	}

	ksceKernelFreeHeapMemory(SCE_KERNEL_HEAP_ID, pkg_hdr_raw);

	return SCE_OK;
}

int pkg_read(SceVfsVnode *vp, SceVfsFile *file, void *buf, SceSize nbyte, SceOff position, SceSize *result){

	int res;
	SceSize total_read = 0;

	SceVfsMount *mnt = vp->core.mnt;
	pkg_fs_context *ctx = (pkg_fs_context *)(mnt->data);
	pkg_fs_fd *pFd = (pkg_fs_fd *)(vp->core.node_data);
	pkg_fs_io_fd *pFd2 = (pkg_fs_io_fd *)(file->fd);

	if((position + nbyte) >= vp->core.size){
		nbyte = vp->core.size - position;
	}

	if((position & (pFd2->buffer_size - 1)) != 0 || 1){
		SceUInt32 read_offset = position & (pFd2->buffer_size - 1);
		SceSize read_byte = pFd2->buffer_size - read_offset;

		res = ksceIoPread(ctx->pkg_fd, pFd2->buffer_aigned, pFd2->buffer_size, ctx->enc_data_offset + pFd->offset + (position & ~(pFd2->buffer_size - 1)));
		if(res < 0){
			return res;
		}

		res = npdrm_package_decrypt(pFd2->buffer_aigned, pFd2->buffer_aigned, pFd2->buffer_size, pFd->offset + (position & ~(pFd2->buffer_size - 1)), ctx->key, ctx->iv);
		if(res < 0){
			return res;
		}

		if(read_byte > nbyte){
			read_byte = nbyte;
		}

		memcpy(buf, (void *)((uintptr_t)(pFd2->buffer_aigned) + read_offset), read_byte);

		total_read += read_byte;
	}

	if((nbyte - total_read) != 0){
		SCE_KERNEL_ASSERT((position & (pFd2->buffer_size - 1)) == 0);

		void *_bufp = (void *)((uintptr_t)buf + total_read);

		res = ksceIoPread(ctx->pkg_fd, _bufp, nbyte - total_read, ctx->enc_data_offset + pFd->offset + position + total_read);
		if(res < 0){
			return res;
		}

		res = npdrm_package_decrypt(_bufp, _bufp, nbyte - total_read, pFd->offset + position + total_read, ctx->key, ctx->iv);
		if(res < 0){
			return res;
		}

		total_read = nbyte;
	}

	*result = total_read;

	return SCE_OK;
}

int vfs_init(SceVfsOpInitArgs *argp){
	return SCE_OK;
}

int vfs_fini(SceVfsOpFiniArgs *argp){
	return SCE_OK;
}

int vfs_mount_func(SceVfsOpMountArgs *argp){

	int res;
	pkg_fs_context *ctx = (pkg_fs_context *)(argp->mnt->data);

	vfsLockVnode(argp->mnt->mnt_vnode);

	argp->mnt->mnt_vnode->core.state = SCE_VNODE_STATE_ACTIVE;

	do {
		res = vfsAllocateFile(argp->mnt->mnt_vnode, &(ctx->pkg_vfs_file), argp->dev_file_path->name);
		if(res < 0){
			ksceKernelPrintf("vfsAllocateFile 0x%X\n", res);
			break;
		}

		/*
		* Required SCE_O_NOBUF or 0x10000000 for avoid Kernel DABT within pkg mounted and pfs mounted on system reboot/susppend.
		*/
		ctx->pkg_vfs_fd = res;
		ctx->pkg_vfs_file->flags = SCE_O_RDONLY | 0x10000000;

		do {
			res = ksceVopGetstat(argp->mnt->mnt_vnode, argp->dev_file_path, &(ctx->stat));
			if(res < 0){
				ksceKernelPrintf("sceVopGetstat 0x%X\n", res);
				break;
			}

			res = ksceVopOpen(argp->mnt->mnt_vnode, argp->dev_file_path, SCE_O_RDONLY | 0x10000000, ctx->pkg_vfs_file);
			if(res < 0){
				ksceKernelPrintf("sceVopOpen 0x%X\n", res);
				break;
			}

			do {
				res = ksceIoOpen(ctx->pkg_path, SCE_O_RDONLY | SCE_O_NOBUF, 0);
				if(res < 0){
					break;
				}

				ctx->pkg_fd = res;

				do {
					res = pkg_init_npdrm_package(ctx);
					if(res < 0){
						break;
					}

					vfsUnlockVnode(argp->mnt->mnt_vnode);
					return SCE_OK;
				} while(0);
				ksceIoClose(ctx->pkg_fd);
				ctx->pkg_fd = -1;
			} while(0);
			ksceVopClose(argp->mnt->mnt_vnode, ctx->pkg_vfs_file);
		} while(0);
		vfsFreeFile(argp->mnt->mnt_vnode, ctx->pkg_vfs_fd);
		ctx->pkg_vfs_fd = -1;
		ctx->pkg_vfs_file = NULL;
	} while(0);

	vfsUnlockVnode(argp->mnt->mnt_vnode);

	return res;
}

int vfs_umount_func(SceVfsOpUmountArgs *argp){

	pkg_fs_context *ctx = (pkg_fs_context *)(argp->mnt->data);

	ksceKernelFreeHeapMemory(SCE_KERNEL_HEAP_ID, ctx->pkg_path);

	if(ctx->pkg_fd >= 0){
		ksceIoClose(ctx->pkg_fd);
		ctx->pkg_fd = -1;
	}

	if(ctx->pkg_vfs_fd >= 0){
		vfsLockVnode(argp->mnt->mnt_vnode);
		ksceVopClose(argp->mnt->mnt_vnode, ctx->pkg_vfs_file);
		vfsFreeFile(argp->mnt->mnt_vnode, ctx->pkg_vfs_fd);
		vfsUnlockVnode(argp->mnt->mnt_vnode);
		ctx->pkg_vfs_fd = -1;
		ctx->pkg_vfs_file = NULL;
	}

	ksceKernelFreeHeapMemory(SCE_KERNEL_HEAP_ID, argp->mnt->mnt_data);

	return SCE_OK;
}

int vfs_set_root(SceVfsOpSetRootArgs *argp){

	if(argp == NULL || argp->mnt == NULL){
		return SCE_KERNEL_ERROR_INVALID_ARGUMENT;
	}

	int res;
	pkg_fs_fd *pFd;
	SceSize read_byte = 0;
	PackageVfsHeader hdr;

	pFd = ksceKernelAllocHeapMemory(SCE_KERNEL_HEAP_ID, sizeof(*pFd));
	if(pFd == NULL){
		return SCE_ERROR_ERRNO_ENOMEM;
	}

	do {
		pkg_fs_context *ctx = (pkg_fs_context *)(argp->mnt->data);

		vfsLockVnode(argp->mnt->mnt_vnode);
		res = ksceVopRead(argp->mnt->mnt_vnode, ctx->pkg_vfs_file, &hdr, sizeof(hdr), &read_byte);
		vfsUnlockVnode(argp->mnt->mnt_vnode);
		if(res < 0){
			ksceKernelPrintf("sceVopRead 0x%X\n", res);
			break;
		}

		pFd->offset = hdr.root_entry;
		pFd->length = hdr.root_nentry;

		SceVfsVnode *vp = argp->vp;
		vp->core.dd          = NULL;
		vp->core.type        = SCE_VNODE_TYPE_ROOTDIR;
		vp->core.state       = SCE_VNODE_STATE_ACTIVE;
		vp->core.mnt         = argp->mnt;
		vp->core.acl_data[0] = 0;
		vp->core.acl_data[1] = 0;
		vp->core.size        = 0;
		vp->core.node_data   = pFd;

		return SCE_OK;
	} while(0);
	ksceKernelFreeHeapMemory(SCE_KERNEL_HEAP_ID, pFd);

	return res;
}

int vfs_devctl(SceVfsOpDevctlArg *argp){

	if(argp->cmd == 0x3001 && argp->buf_len == sizeof(SceIoDevInfo)){

		pkg_fs_context *ctx = (pkg_fs_context *)(argp->mnt->data);

		((SceIoDevInfo *)(argp->buf))->max_size  = ctx->stat.st_size;
		((SceIoDevInfo *)(argp->buf))->free_size = ctx->stat.st_size;
		((SceIoDevInfo *)(argp->buf))->cluster_size = 0;
		((SceIoDevInfo *)(argp->buf))->unk = NULL;

		return SCE_OK;
	}

	ksceKernelPrintf("%s: unknown cmd (0x%X)\n", __FUNCTION__, argp->cmd);

	return SCE_ERROR_ERRNO_EUNSUP;
}

int vfs_decode_path_elem(SceVfsOpDecodePathElemArgs *argp){
	return _sceVfsOpDecodePathElem(argp->mnt, argp->path, argp->path2, argp->path3, argp->buf, argp->buf_len, argp->decode_len);
}

int pkg_impl_open(SceVopOpenArgs *argp){

	if((argp->flags & (SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC)) != 0){
		return SCE_ERROR_ERRNO_EUNSUP;
	}

	int res;
	pkg_fs_io_fd *pFd;

	pFd = ksceKernelAllocHeapMemory(SCE_KERNEL_HEAP_ID, sizeof(*pFd));
	if(pFd == NULL){
		return SCE_ERROR_ERRNO_ENOMEM;
	}

	do {
		pFd->buffer_size = 0x100;
		pFd->buffer = ksceKernelAllocHeapMemory(SCE_KERNEL_HEAP_ID, pFd->buffer_size + 0x3F);
		if(pFd->buffer == NULL){
			res = SCE_ERROR_ERRNO_ENOMEM;
			break;
		}

		pFd->buffer_aigned = (void *)(((uintptr_t)pFd->buffer + 0x3F) & ~0x3F);

		argp->file->fd = (SceUInt32)pFd;

		return SCE_OK;
	} while(0);
	ksceKernelFreeHeapMemory(SCE_KERNEL_HEAP_ID, pFd);

	return res;
}

int pkg_impl_close(SceVopCloseArgs *argp){

	pkg_fs_io_fd *pFd = (pkg_fs_io_fd *)(argp->file->fd);
	ksceKernelFreeHeapMemory(SCE_KERNEL_HEAP_ID, pFd->buffer);
	ksceKernelFreeHeapMemory(SCE_KERNEL_HEAP_ID, pFd);
	argp->file->fd = 0;

	return SCE_OK;
}

int pkg_impl_lookup(SceVopLookupArgs *argp){

	pkg_fs_fd *pFd = (pkg_fs_fd *)(argp->dvp->core.node_data);

	if(argp->path->name_length >= 0x40){
		return SCE_ERROR_ERRNO_ENOENT;
	}

	for(int i=0;i<(int)pFd->length;i++){

		SceVfsMount *mnt = argp->dvp->core.mnt;
		pkg_fs_context *ctx = (pkg_fs_context *)(mnt->data);

		PackageVfsDirEnt vfs_ent;
		SceSize read_byte = 0;
		vfsLockVnode(mnt->mnt_vnode);
		ksceVopPread(mnt->mnt_vnode, ctx->pkg_vfs_file, &vfs_ent, sizeof(vfs_ent), pFd->offset + ((SceOff)sizeof(PackageVfsDirEnt) * i), &read_byte);
		vfsUnlockVnode(mnt->mnt_vnode);

		char name1[0x40];
		char name2[0x40];

		strncpy(name1, vfs_ent.name, 0x3F);
		name1[0x3F] = 0;
		strncpy(name2, argp->path->name, 0x3F);
		name2[0x3F] = 0;

		for(int i=0;i<0x40;i++){
			name1[i] = toupper(name1[i]);
			name2[i] = toupper(name2[i]);
		}

		if(strcmp(name1, name2) == 0){

			SceVfsVnode *vp;
			vfsGetNewVnode(mnt, argp->dvp->core.ops, 0, &vp);

			vfsLockVnode(vp);

			pkg_fs_fd *pNewFd;
			pNewFd = ksceKernelAllocHeapMemory(SCE_KERNEL_HEAP_ID, sizeof(*pNewFd));
			pNewFd->offset = vfs_ent.data_offset;
			pNewFd->length = vfs_ent.data_length;

			vp->core.dd          = argp->dvp;
			vp->core.type        = ((vfs_ent.flags & PKG_FS_FLAG_ISDIR) != 0) ? SCE_VNODE_TYPE_DIR : SCE_VNODE_TYPE_REG;
			vp->core.state       = SCE_VNODE_STATE_ACTIVE;
			vp->core.mnt         = mnt;
			vp->core.acl_data[0] = 0;
			vp->core.acl_data[1] = 0;
			vp->core.size        = ((vfs_ent.flags & PKG_FS_FLAG_ISDIR) != 0) ? 0LL : vfs_ent.data_length;
			vp->core.node_data   = pNewFd;

			// vfsUnlockVnode(vp);

			*(argp->vpp) = vp;

			return SCE_OK;
		}
	}

	return SCE_ERROR_ERRNO_ENOENT;
}

SceSSize pkg_impl_read(SceVopReadArgs *argp){

	SceSize total_read;

	int res = pkg_read(argp->vp, argp->file, argp->buf, argp->nbyte, argp->file->position, &total_read);
	if(res != SCE_OK){
		return res;
	}

	argp->file->position += total_read;

	return total_read;
}

SceOff pkg_impl_lseek(SceVopLseekArgs *argp){

	SceOff curr_pos = argp->file->position;

	switch(argp->whence){
	case SCE_SEEK_SET:
		if(argp->offset < 0LL || argp->offset > argp->vp->core.size){
			return 0xFFFFFFFF00000000 | SCE_KERNEL_ERROR_INVALID_ARGUMENT;
		}

		curr_pos = argp->offset;
		break;
	case SCE_SEEK_CUR:
		if((curr_pos + argp->offset) < 0LL || (curr_pos + argp->offset) > argp->vp->core.size){
			return 0xFFFFFFFF00000000 | SCE_KERNEL_ERROR_INVALID_ARGUMENT;
		}

		curr_pos += argp->offset;
		break;
	case SCE_SEEK_END:
		if(argp->offset < 0LL || argp->offset > argp->vp->core.size){
			return 0xFFFFFFFF00000000 | SCE_KERNEL_ERROR_INVALID_ARGUMENT;
		}

		curr_pos = argp->vp->core.size - argp->offset;
		break;
	default:
		return 0xFFFFFFFF00000000 | SCE_KERNEL_ERROR_INVALID_ARGUMENT;
	}

	argp->file->position = curr_pos;

	return curr_pos;
}

int pkg_impl_ioctl(SceVopIoctlArgs *argp){
	return SCE_ERROR_ERRNO_EUNSUP;
}

int pkg_impl_dopen(SceVopDopenAgrs *argp){

	pkg_fs_file *pFile;

	pFile = ksceKernelAllocHeapMemory(SCE_KERNEL_HEAP_ID, sizeof(*pFile));
	pFile->length = 0LL;

	argp->file->fd = (SceUInt32)pFile;

	return SCE_OK;
}

int pkg_impl_dclose(SceVopDcloseArgs *argp){

	pkg_fs_file *pFile = (pkg_fs_file *)(argp->file->fd);
	ksceKernelFreeHeapMemory(SCE_KERNEL_HEAP_ID, pFile);
	argp->file->fd = 0;

	return SCE_OK;
}

int pkg_impl_dread(SceVopDreadArgs *argp){

	pkg_fs_file *pFile = (pkg_fs_file *)(argp->file->fd);
	pkg_fs_fd *pFd = (pkg_fs_fd *)(argp->vp->core.node_data);

	if(pFile->length >= pFd->length){
		return 0;
	}


	SceVfsMount *mnt = argp->vp->core.mnt;
	pkg_fs_context *ctx = (pkg_fs_context *)(mnt->data);

	PackageVfsDirEnt vfs_ent;
	SceSize read_byte = 0;
	vfsLockVnode(mnt->mnt_vnode);
	ksceVopPread(mnt->mnt_vnode, ctx->pkg_vfs_file, &vfs_ent, sizeof(vfs_ent), pFd->offset + ((SceOff)sizeof(PackageVfsDirEnt) * pFile->length), &read_byte);
	vfsUnlockVnode(mnt->mnt_vnode);

	strncpy(argp->dir->d_name, vfs_ent.name, sizeof(argp->dir->d_name) - 1);
	argp->dir->d_name[sizeof(argp->dir->d_name) - 1] = 0;

	argp->dir->d_private = NULL;

	memcpy(&(argp->dir->d_stat), &(ctx->stat), sizeof(SceIoStat));
	argp->dir->d_stat.st_mode = SCE_S_IRUSR | SCE_S_IWUSR | SCE_S_IRSYS | SCE_S_IWSYS;
	argp->dir->d_stat.st_mode |= ((vfs_ent.flags & PKG_FS_FLAG_ISDIR) != 0) ? SCE_S_IFDIR : SCE_S_IFREG;
	argp->dir->d_stat.st_attr = ((vfs_ent.flags & PKG_FS_FLAG_ISDIR) != 0) ? SCE_SO_IFDIR : SCE_SO_IFREG;
	argp->dir->d_stat.st_size = ((vfs_ent.flags & PKG_FS_FLAG_ISDIR) != 0) ? 0LL : vfs_ent.data_length;

	argp->dir->dummy = 0;

	pFile->length++;

	return 1;
}

int pkg_impl_getstat(SceVopGetstatArgs *argp){

	SceVfsMount *mnt = argp->vp->core.mnt;
	pkg_fs_context *ctx = (pkg_fs_context *)(mnt->data);

	memcpy(argp->stat, &(ctx->stat), sizeof(SceIoStat));

	argp->stat->st_mode = SCE_S_IRUSR | SCE_S_IWUSR | SCE_S_IRSYS | SCE_S_IWSYS;
	argp->stat->st_mode |= ((argp->vp->core.type & SCE_VNODE_TYPE_DIR) != 0) ? SCE_S_IFDIR : SCE_S_IFREG;
	argp->stat->st_attr = ((argp->vp->core.type & SCE_VNODE_TYPE_DIR) != 0) ? SCE_SO_IFDIR : SCE_SO_IFREG;

	pkg_fs_fd *pFd = (pkg_fs_fd *)argp->vp->core.node_data;
	argp->stat->st_size = ((argp->vp->core.type & SCE_VNODE_TYPE_DIR) != 0) ? 0LL : pFd->length;

	return SCE_OK;
}

SceSSize pkg_impl_pread(SceVopPreadArgs *argp){

	SceSize total_read;

	int res = pkg_read(argp->vp, argp->file, argp->buf, argp->nbyte, argp->offset, &total_read);
	if(res != SCE_OK){
		return res;
	}

	return total_read;
}

int pkg_impl_inactive(SceVopInactiveArgs *argp){
	ksceKernelFreeHeapMemory(SCE_KERNEL_HEAP_ID, argp->vp->core.node_data);
	argp->vp->core.node_data = NULL;
	return SCE_OK;
}

int pkg_impl_sync(SceVopSyncArgs *argp){
	return SCE_OK;
}

int pkg_impl_fgetstat(SceVopFgetstatArgs *argp){

	SceVfsMount *mnt = argp->vp->core.mnt;
	pkg_fs_context *ctx = (pkg_fs_context *)(mnt->data);

	memcpy(argp->stat, &(ctx->stat), sizeof(SceIoStat));

	argp->stat->st_mode = SCE_S_IRUSR | SCE_S_IWUSR | SCE_S_IRSYS | SCE_S_IWSYS;
	argp->stat->st_mode |= ((argp->vp->core.type & SCE_VNODE_TYPE_DIR) != 0) ? SCE_S_IFDIR : SCE_S_IFREG;
	argp->stat->st_attr = ((argp->vp->core.type & SCE_VNODE_TYPE_DIR) != 0) ? SCE_SO_IFDIR : SCE_SO_IFREG;

	pkg_fs_fd *pFd = (pkg_fs_fd *)argp->vp->core.node_data;
	argp->stat->st_size = ((argp->vp->core.type & SCE_VNODE_TYPE_DIR) != 0) ? 0LL : pFd->length;

	return SCE_OK;
}

int pkg_impl_cleanup(SceVopCleanupArgs *argp){

	pkg_fs_io_fd *pFd = (pkg_fs_io_fd *)(argp->file->fd);
	ksceKernelFreeHeapMemory(SCE_KERNEL_HEAP_ID, pFd->buffer);
	ksceKernelFreeHeapMemory(SCE_KERNEL_HEAP_ID, pFd);
	argp->file->fd = 0;

	return SCE_OK;
}

int _sceKernelMountPackage(const char *assign_name, const char *pkg_path, const char *pkg_vfs_path){

	int res;
	pkg_fs_context *ctx;
	SceVfsMountData *pMountData;

	ctx = ksceKernelAllocHeapMemory(SCE_KERNEL_HEAP_ID, sizeof(*ctx));
	if(ctx == NULL){
		return -1;
	}

	memset(ctx, 0, sizeof(*ctx));

	ctx->pkg_fd = -1;
	ctx->pkg_vfs_file = NULL;
	ctx->pkg_vfs_fd = -1;
	strncpy(ctx->assign_name, assign_name, sizeof(ctx->assign_name) - 1);

	do {
		size_t pkg_path_len = strlen(pkg_path);
		ctx->pkg_path = ksceKernelAllocHeapMemory(SCE_KERNEL_HEAP_ID, pkg_path_len + 1);
		if(ctx->pkg_path == NULL){
			res = -1;
			break;
		}

		memcpy(ctx->pkg_path, pkg_path, pkg_path_len);
		ctx->pkg_path[pkg_path_len] = 0;

		do {
			pMountData = ksceKernelAllocHeapMemory(SCE_KERNEL_HEAP_ID, sizeof(*pMountData));
			if(pMountData == NULL){
				res = -1;
				break;
			}

			pMountData->assign_name           = ctx->assign_name;
			pMountData->fs_name               = "pkg_fs";
			pMountData->blockdev_name         = pkg_vfs_path;
			pMountData->blockdev_name_no_part = NULL;
			pMountData->mnt_id                = 0;

			do {
				SceVfsMountParam _vfs_mount_devkit_test = {
					.root_path     = "/pkg", // Cannot duplicates for other root_path of vfs with SCE_VFS_MOUNT_TYPE_FSROOT.
					.blockdev_name = pkg_vfs_path,
					.fs_type       = SCE_VFS_FS_TYPE_FS,
					.opt           = 0x100, // 0x100:disable ScePfsFacadeForKernel callback
					.mnt_flags     = SCE_VFS_MOUNT_FLAG_NOBUF | SCE_VFS_MOUNT_FLAG_RDONLY | SCE_VFS_MOUNT_TYPE_FSROOT,
					.vfs_name      = "pkg_fs",
					.data          = ctx,
					.misc          = pMountData,
					.vops          = NULL
				};

				res = vfsMount(&_vfs_mount_devkit_test);
				if(res < 0){
					break;
				}

				return SCE_OK;
			} while(0);
			ksceKernelFreeHeapMemory(SCE_KERNEL_HEAP_ID, pMountData);
		} while(0);
		ksceKernelFreeHeapMemory(SCE_KERNEL_HEAP_ID, ctx->pkg_path);
	} while(0);
	ksceKernelFreeHeapMemory(SCE_KERNEL_HEAP_ID, ctx);

	return res;
}

int _sceKernelUmountPackage(const char *assign_name, int flags){

	int res;
	SceVfsUmountParam param;

	param.assign_name = assign_name;
	param.flag = flags;

	res = vfsUmount(&param);
	if(res < 0){
		return res;
	}

	return SCE_OK;
}

int sceKernelMountPackageForUser(const char *assign_name, const char *pkg_path, const char *pkg_vfs_path){

	int res;
	char *_assign_name;
	char *_pkg_path;
	char *_pkg_vfs_path;
	SceUInt32 state;

	ENTER_SYSCALL(state);

	do {
		_assign_name = ksceKernelAllocHeapMemory(SCE_KERNEL_HEAP_ID, 0x400);
		if(_assign_name == NULL){
			res = SCE_ERROR_ERRNO_ENOMEM;
			break;
		}

		do {
			res = ksceKernelStrncpyFromUser(_assign_name, assign_name, 0x400);
			if(res < 0){
				break;
			}

			if(res == 0x400){
				break;
			}

			_pkg_path = ksceKernelAllocHeapMemory(SCE_KERNEL_HEAP_ID, 0x400);
			if(_pkg_path == NULL){
				res = SCE_ERROR_ERRNO_ENOMEM;
				break;
			}

			do {
				res = ksceKernelStrncpyFromUser(_pkg_path, pkg_path, 0x400);
				if(res < 0){
					break;
				}

				if(res == 0x400){
					break;
				}

				_pkg_vfs_path = ksceKernelAllocHeapMemory(SCE_KERNEL_HEAP_ID, 0x400);
				if(_pkg_vfs_path == NULL){
					res = SCE_ERROR_ERRNO_ENOMEM;
					break;
				}

				do {
					res = ksceKernelStrncpyFromUser(_pkg_vfs_path, pkg_vfs_path, 0x400);
					if(res < 0){
						break;
					}

					if(res == 0x400){
						break;
					}

					res = _sceKernelMountPackage(_assign_name, _pkg_path, _pkg_vfs_path);
				} while(0);
				ksceKernelFreeHeapMemory(SCE_KERNEL_HEAP_ID, _pkg_vfs_path);
			} while(0);
			ksceKernelFreeHeapMemory(SCE_KERNEL_HEAP_ID, _pkg_path);
		} while(0);
		ksceKernelFreeHeapMemory(SCE_KERNEL_HEAP_ID, _assign_name);
	} while(0);

	EXIT_SYSCALL(state);

	return res;
}

int sceKernelUmountPackageForUser(const char *assign_name, int flags){

	int res;
	char *_assign_name;
	SceUInt32 state;

	ENTER_SYSCALL(state);

	do {
		_assign_name = ksceKernelAllocHeapMemory(SCE_KERNEL_HEAP_ID, 0x400);
		if(_assign_name == NULL){
			res = SCE_ERROR_ERRNO_ENOMEM;
			break;
		}

		do {
			res = ksceKernelStrncpyFromUser(_assign_name, assign_name, 0x400);
			if(res < 0){
				break;
			}

			if(res == 0x400){
				break;
			}

			res = _sceKernelUmountPackage(_assign_name, flags);
		} while(0);
		ksceKernelFreeHeapMemory(SCE_KERNEL_HEAP_ID, _assign_name);
	} while(0);

	EXIT_SYSCALL(state);

	return res;
}

const SceVfsOpTable vfs_table_test = {
	.vfs_mount            = vfs_mount_func,
	.vfs_umount           = vfs_umount_func,
	.vfs_set_root         = vfs_set_root,
	.vfs_get_root         = NULL,
	.reserved             = {NULL, NULL},
	.vfs_sync             = NULL,
	.reserved2            = NULL,
	.vfs_init             = vfs_init,
	.vfs_fini             = vfs_fini,
	.reserved3            = NULL,
	.vfs_devctl           = vfs_devctl,
	.vfs_decode_path_elem = vfs_decode_path_elem
};

const SceVopTable vop_table_test = {
	.vop_open           = pkg_impl_open,
	.vop_create         = NULL,
	.vop_close          = pkg_impl_close,
	.vop_lookup         = pkg_impl_lookup,
	.vop_read           = pkg_impl_read,
	.vop_write          = NULL,
	.vop_lseek          = pkg_impl_lseek,
	.vop_ioctl          = pkg_impl_ioctl,
	.vop_remove         = NULL,
	.vop_mkdir          = NULL,
	.vop_rmdir          = NULL,
	.vop_dopen          = pkg_impl_dopen,
	.vop_dclose         = pkg_impl_dclose,
	.vop_dread          = pkg_impl_dread,
	.vop_getstat        = pkg_impl_getstat,
	.vop_chstat         = NULL,
	.vop_rename         = NULL,
	.reserved           = NULL,
	.vop_pread          = pkg_impl_pread,
	.vop_pwrite         = NULL,
	.vop_inactive       = pkg_impl_inactive,
	.vop_link           = NULL,
	.vop_unlink         = NULL,
	.vop_sync           = pkg_impl_sync,
	.vop_fgetstat       = pkg_impl_fgetstat,
	.vop_fchstat        = NULL,
	.vop_whiteout       = NULL,
	.vop_cleanup        = pkg_impl_cleanup,
	.vop_verofill       = NULL
};

SceVfsInfo vfs_add;

void _start() __attribute__ ((weak, alias("module_start")));
int module_start(SceSize args, void *argp){

	int res;

	vfs_add.vfs_ops      = &vfs_table_test;
	vfs_add.vfs_name     = "pkg_fs";
	vfs_add.vfs_name_len = __builtin_strlen("pkg_fs");
	vfs_add.ref_count    = 0;
	vfs_add.type         = SCE_VFS_TYPE_FS;
	vfs_add.default_vops = &vop_table_test;
	vfs_add.vfs_data     = NULL;

	res = ksceVfsAddVfs(&vfs_add);
	if(res < 0){
		ksceKernelPrintf("%s=0x%X\n", "sceVfsAddVfs", res);
		return SCE_KERNEL_START_FAILED;
	}

	return SCE_KERNEL_START_SUCCESS;
}
