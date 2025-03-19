
#ifndef _NPDRM_PACKAGE_H_
#define _NPDRM_PACKAGE_H_

#include <psp2/types.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef struct _ScePackageHeader {
	SceUInt32 magic;
	SceUInt16 flags;
	SceUInt16 type;
	SceUInt32 metadata_offset;
	SceUInt32 metadata_count;

	// 0x10
	SceUInt32 metadata_size;
	SceUInt32 item_count;
	SceUInt64 total_size;

	// 0x20
	SceUInt64 data_offset;
	SceUInt64 data_size;

	// 0x30
	char contentid[0x30];

	// 0x60
	SceUInt8 digest[0x10];

	// 0x70
	SceUInt8 riv[0x10];

	SceUInt8 cmac_hash[0x10];
	SceUInt8 signature[0x28];
	SceUInt8 hdr_hash[8];
} ScePackageHeader;

typedef struct _ScePackageExtHeader {
	SceUInt32 magic;                             // 0x7F657874 (".ext")
	SceUInt32 unknown_1;                         // Maybe version. Always 1.
	SceUInt32 ext_hdr_size;                      // Extended header size. ex: 0x40
	SceUInt32 ext_data_size;                     // ex: 0x180

	SceUInt32 main_and_ext_headers_hmac_offset;  // ex: 0x100
	SceUInt32 metadata_header_hmac_offset;       // ex: 0x360, 0x390, 0x490 
	SceUInt64 tail_offset;                       // Tail size seems to be always 0x1A0

	SceUInt32 padding1;
	SceUInt32 pkg_key_id;                        // Id of the AES key used for decryption. PSP = 0x1, PS Vita = 0xC0000002, PSM = 0xC0000004
	SceUInt32 full_header_hmac_offset;           // ex: none (old pkg): 0, 0x930
	SceUInt8 padding2[0x14];
} ScePackageExtHeader;

typedef struct _ScePackageItemInfo { // size is 0x20-bytes
	SceSize file_name_offset;
	SceSize file_name_len;
	SceOff data_offset;
	SceOff data_size;
	SceUInt32 flags;
	SceUInt32 padding;
} ScePackageItemInfo;



#ifdef __cplusplus
}
#endif

#endif /* _NPDRM_PACKAGE_H_ */
