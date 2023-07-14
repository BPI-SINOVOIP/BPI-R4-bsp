/*
 * Copyright (c) 2022, Mediatek Inc. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MTK_SECURE_DATA_H
#define MTK_SECURE_DATA_H

#include <common/runtime_svc.h>
#include <lib/mmio.h>

#define TEMP_NS_SHMEM_BASE			(BL32_LIMIT)
#define TEMP_NS_SHMEM_SIZE			(0x1000)

#define MTK_SECURE_DATA_K_ROOTFS		"k-rootfs"
#define MTK_SECURE_DATA_K_DERIVED		"k-dev-specific-derived"
#define MTK_SECURE_DATA_FIT_SECRET		"fit-secret"

#define MTK_SECURE_DATA_KEY_LEN			32
#define MTK_SECURE_DATA_FIT_SECRET_LEN		32
#define MTK_SECURE_DATA_MAX_DATA_LEN		160
#define MTK_SECURE_DATA_CBC_CIPHER_LEN		48
#define MTK_SECURE_DATA_GCM_CIPHER_LEN		32
#define MTK_SECURE_DATA_CBC_IV_LEN		16
#define MTK_SECURE_DATA_GCM_IV_LEN		12
#define MTK_SECURE_DATA_SALT_LEN		16
#define MTK_SECURE_DATA_TAG_LEN			16

#define MTK_SECURE_DATA_SUCC		        U(0)
#define MTK_SECURE_DATA_ERR_WRONG_SRC		U(1)
#define MTK_SECURE_DATA_ERR_INVAL		U(2)
#define MTK_SECURE_DATA_ERR_MAP			U(3)
#define MTK_SECURE_DATA_ERR_DERIVED		U(4)
#define MTK_SECURE_DATA_ERR_DEC			U(5)
#define MTK_SECURE_DATA_ERR_VERIFY		U(6)
#define MTK_SECURE_DATA_ERR_MULTI_EXEC		U(7)
#define MTK_SECURE_DATA_ERR_KEY_UNK		U(8)
#define MTK_SECURE_DATA_ERR_ENC			U(9)
#define MTK_SECURE_DATA_ERR_EFUSE		U(10)
#define MTK_SECURE_DATA_ERR_UNMAP		U(32)

enum mtk_secure_data_key_id {
	MTK_SECURE_DATA_ROOTFS_KEY_ID = 0,
	MTK_SECURE_DATA_DERIVED_KEY_ID,
	__MTK_SECURE_DATA_MAX_KEY_ID,
};
#define MTK_SECURE_DATA_MAX_KEY_ID (__MTK_SECURE_DATA_MAX_KEY_ID - 1)

/*
 * secure data decryption descriptor
 * describes how each secure data be decrypted
 *
 * @cipher_name:	secure data cipher name
 * @out:		buffer to place plain text
 * @out_len:		plain text length
 */
struct secure_data_dec_desc {
	const char	*cipher_name;
	uint8_t		*out;
	unsigned int	out_len;
};

struct k_temp_cipher_node {
	uint8_t		salt[MTK_SECURE_DATA_SALT_LEN];
	uint8_t		iv[MTK_SECURE_DATA_CBC_IV_LEN];
	const uint8_t	cipher[MTK_SECURE_DATA_CBC_CIPHER_LEN];
};

struct	data_cipher_node {
	const uint8_t	iv[MTK_SECURE_DATA_GCM_IV_LEN];
	const uint8_t	tag[MTK_SECURE_DATA_TAG_LEN];
	const uint8_t	cipher[MTK_SECURE_DATA_GCM_CIPHER_LEN];
};

struct secure_data_node {
	struct k_temp_cipher_node	k_temp;
	struct data_cipher_node		data;
};

#if MTK_SECURE_DATA
uint64_t mtk_secure_data_get_shm_config(uintptr_t *paddr, size_t *size);

uint64_t mtk_secure_data_proc_data(void);

uint64_t mtk_secure_data_get_key(const uint32_t key_id, void *buf);

uint64_t mtk_secure_data_encrypt(u_register_t x1, u_register_t x2,
				 u_register_t x3, u_register_t x4,
				 void *buf);
#else
uint64_t mtk_secure_data_get_shm_config(uintptr_t *paddr, size_t *size)
{
	return 0;
}

uint64_t mtk_secure_data_proc_data(void)
{
	return 0;
}

uint64_t mtk_secure_data_get_key(const uint32_t key_id, void *buf)
{
	return 0;
}

uint64_t mtk_secure_data_encrypt(u_register_t x1, u_register_t x2,
				 u_register_t x3, u_register_t x4,
				 void *buf)
{
	return 0;
}
#endif
#endif /* MTK_SECURE_DATA_H */
