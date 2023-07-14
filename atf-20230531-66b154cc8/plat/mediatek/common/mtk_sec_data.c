/*
 * Copyright (c) 2022, MediaTek Inc. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-CLause
 */
#include <common/debug.h>
#include <common/runtime_svc.h>
#include <lib/xlat_tables/xlat_tables_v2.h>
#include <platform_def.h>
#include <mbedtls/aes.h>
#include <mbedtls/md.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/gcm.h>
#include <mbedtls/platform_util.h>
#include <mtk_sec_data.h>
#include <mtk_efuse.h>
#include <mtk_crypto.h>

static uint8_t k_rootfs[MTK_SECURE_DATA_KEY_LEN];
static uint8_t fit_secret[MTK_SECURE_DATA_FIT_SECRET_LEN];

static uint32_t salt_1[] = {
	0x06BACD1D, 0xC8567BB4, 0x91D9D66B, 0x3691228B,
	0xDBC09405, 0x29B8E672, 0xE1AED3C6, 0xDE2A20FD,
};

static const uintptr_t shm_paddr = TEMP_NS_SHMEM_BASE;
static const size_t shm_size = TEMP_NS_SHMEM_SIZE;

/* make sure out_len < MTK_SECURE_DATA_MAX_CIPHER_LEN */
static const struct secure_data_dec_desc sd_dec_descs[] = {
	[0] = {
		.cipher_name = MTK_SECURE_DATA_FIT_SECRET,
		.out = fit_secret,
		.out_len = sizeof(fit_secret)
	},
	[1] = {
		.cipher_name = MTK_SECURE_DATA_K_ROOTFS,
		.out = k_rootfs,
		.out_len = sizeof(k_rootfs)
	}
};

uint64_t mtk_secure_data_get_shm_config(uintptr_t *paddr, size_t *size)
{
	if (!paddr || !size)
		return MTK_SECURE_DATA_ERR_INVAL;

	*paddr = shm_paddr;
	*size = shm_size;

	return MTK_SECURE_DATA_SUCC;
}

/*
 * hkdf_derive_key
 * @key:		key input keying material
 * @key_len:		length of keying material in bytes
 * @salt:		salt value
 * @salt_len:		length of salt in bytes
 * @info		info value
 * @info_len		length of info in bytes
 * @out:		output
 * @out_len:		length of output material in bytes
 *
 * Derive key using HKDF.
 *
 * returns:
 *	0: on success
 *	MTK_SECURE_DATA_ERR_INVAL: invalid arguments
 *	MTK_SECURE_DATA_ERR_DERIVED: key derivation failed
 */
static uint64_t hkdf_derive_key(const uint8_t *key, size_t key_len,
				const uint8_t *salt, size_t salt_len,
				const uint8_t *info, size_t info_len,
				uint8_t *out, size_t out_len)
{
	int ret = 0;
	const mbedtls_md_info_t *md_info = NULL;

	if (!key || !key_len || !out || !out_len)
		return MTK_SECURE_DATA_ERR_INVAL;

	md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	if (!md_info) {
		INFO("Get md_info type failed\n");
		return MTK_SECURE_DATA_ERR_DERIVED;
	}

	ret = mbedtls_hkdf(md_info, salt, salt_len, key, key_len,
			   info, info_len, out, out_len);
	if (ret)
		INFO("Key derivation function failed: %d\n", ret);

	return (ret) ? MTK_SECURE_DATA_ERR_DERIVED : 0;
}

static uint64_t aes_cbc_decrypt(const uint8_t *cipher, size_t cipher_len,
				const uint8_t *key, size_t key_len,
				uint8_t *iv, uint8_t *out)
{
	int ret = 0;
	size_t len = 0;
	size_t olen = 0;
	mbedtls_cipher_context_t aes_ctx = {0};
	const mbedtls_cipher_info_t *info = NULL;

	if (!cipher || !cipher_len || !key || !key_len || !iv || !out)
		return MTK_SECURE_DATA_ERR_INVAL;

	info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CBC);
	if (!info) {
		INFO("Get cipher info failed\n");
		return MTK_SECURE_DATA_ERR_DEC;
	}

	mbedtls_cipher_init(&aes_ctx);

	ret = mbedtls_cipher_setup(&aes_ctx, info);
	if (ret) {
		INFO("Cipher setup failed: %d\n", ret);
		goto aes_cbc_decrypt_err;
	}

	ret = mbedtls_cipher_setkey(&aes_ctx, key, key_len << 3, MBEDTLS_DECRYPT);
	if (ret) {
		INFO("Cipher set key failed: %d\n", ret);
		goto aes_cbc_decrypt_err;
	}

	ret = mbedtls_cipher_set_iv(&aes_ctx, iv, 16);
	if (ret) {
		INFO("Cipher set iv failed: %d\n", ret);
		goto aes_cbc_decrypt_err;
	}

	ret = mbedtls_cipher_update(&aes_ctx, cipher, cipher_len, out, &len);
	if (ret) {
		INFO("Cipher update failed: %d\n", ret);
		goto aes_cbc_decrypt_err;
	}
	olen += len;

	ret = mbedtls_cipher_finish(&aes_ctx, out, &len);
	if (ret)
		INFO("Cipher finish failed: %d\n", ret);
	olen += len;

aes_cbc_decrypt_err:
	mbedtls_cipher_free(&aes_ctx);

	return (ret) ? MTK_SECURE_DATA_ERR_DEC : 0;
}

/*
 * aes_gcm_decrypt
 * @cipher:		cipher value
 * @cipher_len:		length of cipher in bytes
 * @key:		key value
 * @key_len:		length of key in bytes
 * @iv:			iv value
 * @iv_len:		length of iv in bytes
 * @tag:		gcm tag
 * @tag_len:		length of gcm tag in bytes
 * @aad:		additional authentication data
 * @aad_len:		length of aad in bytes
 * @out:		output buffer
 *
 * Decrypt secure data using AES-GCM-256
 *
 * returns:
 *	0: on success
 *	MTK_SECURE_DATA_ERR_INVAL: invalid arguments
 *	MTK_SECURE_DATA_ERR_DEC: decryption failed
 */
static uint64_t aes_gcm_decrypt(const uint8_t *cipher, size_t cipher_len,
				const uint8_t *key, size_t key_len,
				const uint8_t *iv, size_t iv_len,
				const uint8_t *tag, size_t tag_len,
				const uint8_t *aad, size_t aad_len,
				uint8_t *out)
{
	int ret = 0;
	mbedtls_gcm_context gcm_ctx = {0};

	if (!cipher || !cipher_len || !key || !key_len || !iv || !iv_len
	    || !tag || !tag_len || !aad || !aad_len || !out)
		return MTK_SECURE_DATA_ERR_INVAL;

	mbedtls_gcm_init(&gcm_ctx);

	ret = mbedtls_gcm_setkey(&gcm_ctx, MBEDTLS_CIPHER_ID_AES,
				 key, (key_len << 3));
	if (ret) {
		INFO("Setting key failed: %d\n", ret);
		goto aes_gcm_decrypt_err;
	}

	ret = mbedtls_gcm_auth_decrypt(&gcm_ctx, cipher_len, iv, iv_len,
				       aad, aad_len, tag, tag_len, cipher, out);
	if (ret)
		INFO("Decryption failed: %d\n", ret);

aes_gcm_decrypt_err:
	mbedtls_gcm_free(&gcm_ctx);

	return (ret) ? MTK_SECURE_DATA_ERR_DEC : 0;
}

static uint64_t decrypt_k_roe(uintptr_t cipher, uint8_t *k_roe)
{
	uint64_t ret = 0;

	if (!cipher || !k_roe)
		return MTK_SECURE_DATA_ERR_INVAL;

	memcpy(k_roe, (void *)cipher, MTK_SECURE_DATA_KEY_LEN);

	ret = sej_decrypt(k_roe, k_roe, MTK_SECURE_DATA_KEY_LEN);
	if (ret) {
		INFO("Decrypt k-roe failed\n");
		ret = MTK_SECURE_DATA_ERR_DEC;
	}

	return ret;
}

/*
 * decrypt_k_temp
 *
 * @node:		cipher node including salt, iv, cipher
 * @desc: decryption descriptor, specifing cipher_name, out buffer
 * @k_roe:		key used for key derivation
 * @k_temp:		k-temp buffer
 *
 * Use HKDF to derive key from roe-key, and decrypt k-tempx
 *
 * returns:
 *	0: on success
 *	MTK_SECURE_DATA_ERR_INVAL: invalid arguments
 *	MTK_SECURE_DATA_ERR_DERIVED: key derivation failed
 *	MTK_SECURE_DATA_ERR_DEC: decryption failed
 */
static uint64_t decrypt_k_temp(struct k_temp_cipher_node *node,
			       const struct secure_data_dec_desc *desc,
			       uint8_t *k_roe, uint8_t *k_temp)
{
	uint64_t ret = 0;
	uint8_t key[MTK_SECURE_DATA_KEY_LEN] = {0};

	if (!node || !desc || !k_roe || !k_temp || !desc->cipher_name ||
	    !strlen(desc->cipher_name))
		return MTK_SECURE_DATA_ERR_INVAL;

	ret = hkdf_derive_key(k_roe, MTK_SECURE_DATA_KEY_LEN,
			      node->salt, MTK_SECURE_DATA_SALT_LEN,
			      /* use cipher name as info */
			      (uint8_t *)desc->cipher_name,
			      strlen(desc->cipher_name),
			      key, MTK_SECURE_DATA_KEY_LEN);
	if (ret) {
		INFO("Derive key for %s failed\n", desc->cipher_name);
		goto decrypt_k_temp_err;
	}

	ret = aes_cbc_decrypt(node->cipher, MTK_SECURE_DATA_CBC_CIPHER_LEN,
			      key, MTK_SECURE_DATA_KEY_LEN, node->iv, k_temp);
	if (ret)
		INFO("Decrypt %s failed\n", desc->cipher_name);

decrypt_k_temp_err:
	mbedtls_platform_zeroize(key, sizeof(key));

	return ret;
}

/*
 * decrypt_secure_data
 * @sd_node: secure_data_node, including cipher nodes for k_temp, data
 * @desc: decryption descriptor, specifing cipher_name, out buffer
 * @k-roe; roe-key buffer
 *
 * Derive decryption key using roe key to decrypt k-temp, then use k-temp
 * to decrypt secure data.
 *
 * returns:
 *	0: on success
 *	MTK_SECURE_DATA_ERR_INVAL: invalid arguments
 *	MTK_SECURE_DATA_ERR_DEC: decryption failed
 *	MTK_SECURE_DATA_ERR_DERIVED: key derivation failed
 */
static uint64_t decrypt_secure_data(struct secure_data_node *sd_node,
				    const struct secure_data_dec_desc *desc,
				    uint8_t *k_roe)
{
	uint64_t ret = 0;
	struct data_cipher_node *node = NULL;
	uint8_t k_temp[MTK_SECURE_DATA_CBC_CIPHER_LEN + 16] = {0};

	if (!sd_node || !desc || !k_roe)
		return MTK_SECURE_DATA_ERR_INVAL;

	ret = decrypt_k_temp(&sd_node->k_temp, desc, k_roe, k_temp);
	if (ret)
		goto decrypt_secure_data_err;

	node = &sd_node->data;

	ret = aes_gcm_decrypt(node->cipher, desc->out_len,
			      k_temp, MTK_SECURE_DATA_KEY_LEN,
			      node->iv, MTK_SECURE_DATA_GCM_IV_LEN,
			      node->tag, MTK_SECURE_DATA_TAG_LEN,
			      /* use k-tempx cipher node as aad */
			      (uint8_t *)&sd_node->k_temp, sizeof(sd_node->k_temp),
			      desc->out);
	if (ret && desc->cipher_name)
		INFO("Decrypt %s failed\n", desc->cipher_name);

decrypt_secure_data_err:
	mbedtls_platform_zeroize(k_temp, sizeof(k_temp));

	return ret;
}

/*
 * verify_fit_secret
 * @signature_hash: ptr point to signature hash
 *
 * verify if hash decrypted from fit_secret is same as FIT
 * signature hash.

 * returns:
 *	0: on success
 *	MTK_SECURE_DATA_ERR_VERIFY: on failure
 */
static uint64_t verify_fit_secret(uintptr_t signature_hash)
{
	uint8_t hash[MTK_SECURE_DATA_FIT_SECRET_LEN];

	if (!signature_hash)
		return MTK_SECURE_DATA_ERR_INVAL;

	memcpy(hash, (void *)signature_hash, MTK_SECURE_DATA_FIT_SECRET_LEN);

	if (memcmp(fit_secret, hash, MTK_SECURE_DATA_FIT_SECRET_LEN)) {
		INFO("Verify FIT-secret failed\n");
		return MTK_SECURE_DATA_ERR_VERIFY;
	}

	return 0;
}

static uint64_t get_hw_unique_key(uint8_t *hw_key, size_t *key_len)
{
	uint32_t ret = 0;
	int i = 0;
	size_t len = 0;
	uint32_t huid_field = 0;
	uint8_t huid[MTK_EFUSE_MAX_HUID_LEN] = {0};

	if (!hw_key || !key_len)
		return MTK_SECURE_DATA_ERR_INVAL;

	*key_len = 0;

	for (i = 0, len = 0; i < 2; i++, len += sizeof(huid_field)) {
		ret = mtk_efuse_read(MTK_EFUSE_FIELD_HUID0 + i,
				     (uint8_t *)&huid_field,
				     sizeof(huid_field));
		if (ret) {
			INFO("mtk_efuse_read failed: %d\n", ret);
			ret = MTK_SECURE_DATA_ERR_EFUSE;
			goto get_hw_unique_key_err;
		}

		memcpy(huid + len, (uint8_t *)&huid_field, sizeof(huid_field));
	}

	*key_len = MTK_EFUSE_MAX_HUID_LEN;

	ret = sej_encrypt(huid, hw_key, MTK_EFUSE_MAX_HUID_LEN);
	if (ret)
		ret = MTK_SECURE_DATA_ERR_ENC;

get_hw_unique_key_err:
	mbedtls_platform_zeroize(huid, sizeof(huid));

	return ret;
}

/*
 * derive_key_from_hw_key
 * @k_derived: derived key buffer
 *
 * derive_key_from_hw_key derives key from hw_key
 *
 * returns:
 *	0: on success
 *	MTK_SECURE_DATA_ERR_ENC: encrypt data failed
 *	MTK_EFUSE_ERROR_CODE_OFFSET: read efuse field HUID failed
 *	MTK_SECURE_DATA_ERR_DERIVED: derive key failed
 */
static uint64_t derive_key_from_hw_key(uint8_t *k_derived)
{
	uint64_t ret = 0;
	size_t len = 0;
	uint8_t hw_key[MTK_SECURE_DATA_KEY_LEN] __attribute__((aligned(16))) = {0};

	if (!k_derived)
		return MTK_SECURE_DATA_ERR_INVAL;

	ret = get_hw_unique_key(hw_key, &len);
	if (ret) {
		INFO("Get hw key failed\n");
		goto derive_key_from_hw_key_err;
	}

	ret = hkdf_derive_key(hw_key, len,
			      /* use const. salt_1 */
			      (uint8_t *)salt_1, sizeof(salt_1),
			      /* use k-derived str as info */
			      (uint8_t *)MTK_SECURE_DATA_K_DERIVED,
			      strlen(MTK_SECURE_DATA_K_DERIVED),
			      k_derived, MTK_SECURE_DATA_KEY_LEN);
	if (ret) {
		INFO("Derive key from hw key failed\n");
		goto derive_key_from_hw_key_err;
	}

	mbedtls_platform_zeroize(hw_key, sizeof(hw_key));

	return 0;

derive_key_from_hw_key_err:
	mbedtls_platform_zeroize(k_derived, MTK_SECURE_DATA_KEY_LEN);

	mbedtls_platform_zeroize(hw_key, sizeof(hw_key));

	return ret;
}

/*
 * proc_secure_data
 * @shm_vaddr: virtual shared memory address
 * Decrypt secure data, verify fit-secret.
 *
 * For now, we assume secure data is in following format:
 * for each node is fixed size, MTK_SECURE_DATA_MAX_DATA_LEN.
 * Low address	------------------------------------------------------
 *		| roe-key.enc                                        |
 *		------------------------------------------------------
 *		| salt | iv | k-temp2.enc | iv | tag | fit-secret    |
 *		------------------------------------------------------
 *		| salt | iv | k-temp1.enc | iv | tag | k-rootfs.enc  |
 *		------------------------------------------------------
 *		| fit-signature's hash   |                           |
 * High address	------------------------------------------------------
 *
 * returns:
 *	0: on success
 *	MTK_SECURE_DATA_ERR_DERIVED: key derivation failed
 *	MTK_SECURE_DATA_ERR_DEC: decryption failed
 *	MTK_SECURE_DATA_ERR_VERIFY: verifying fit-secret failed
 */
static uint64_t proc_secure_data(uintptr_t shm_vaddr)
{
	uint64_t ret = 0;
	int i = 0;
	uintptr_t p = 0;
	uintptr_t hash_p = 0;
	struct secure_data_node sd_node = {0};
	uint8_t k_roe[MTK_SECURE_DATA_KEY_LEN] __attribute__((aligned(16))) = {0};

	if (!shm_vaddr)
		return MTK_SECURE_DATA_ERR_INVAL;

	ret = decrypt_k_roe(shm_vaddr, k_roe);
	if (ret)
		goto proc_secure_data_err;

	p = shm_vaddr + MTK_SECURE_DATA_MAX_DATA_LEN;
	hash_p = p + ARRAY_SIZE(sd_dec_descs) * MTK_SECURE_DATA_MAX_DATA_LEN;

	for (i = 0; i < ARRAY_SIZE(sd_dec_descs); i++) {
		memcpy(&sd_node, (void *)p, sizeof(sd_node));

		ret = decrypt_secure_data(&sd_node, &sd_dec_descs[i], k_roe);
		if (ret)
			goto proc_secure_data_err;

		if (!strncmp(sd_dec_descs[i].cipher_name,
			     MTK_SECURE_DATA_FIT_SECRET,
			     strlen(MTK_SECURE_DATA_FIT_SECRET))) {
			ret = verify_fit_secret(hash_p);
			if (ret)
				goto proc_secure_data_err;
		}

		p += MTK_SECURE_DATA_MAX_DATA_LEN;
	}

	mbedtls_platform_zeroize(k_roe, sizeof(k_roe));

	return 0;

proc_secure_data_err:
	for (i = 0; i < ARRAY_SIZE(sd_dec_descs); i++) {
		mbedtls_platform_zeroize(sd_dec_descs[i].out,
					 sd_dec_descs[i].out_len);
	}

	mbedtls_platform_zeroize(k_roe, sizeof(k_roe));

	return ret;
}

/*
 * mtk_secure_data_proc_data
 *
 * mtk_secure_data_proc_data maps shared memory region as read-only
 * non-secure memory, prepares crypto libraries, extracts secure data
 * nodes from shared memory region, processes secure data.
 *
 * returns:
 *	0: on success
 *	>0: on failure
 */
uint64_t mtk_secure_data_proc_data(void)
{
	uint64_t ret = 0;
	int mmap_status = 0;
	static bool proc_data_exec;
	uintptr_t shm_vaddr = 0;

	if (proc_data_exec)
		return MTK_SECURE_DATA_ERR_MULTI_EXEC;
	proc_data_exec = true;

	mmap_status = mmap_add_dynamic_region_alloc_va(shm_paddr & TABLE_ADDR_MASK,
						       &shm_vaddr,
						       shm_size,
						       MT_MEMORY | MT_RO | MT_NS);
	if (mmap_status) {
		INFO("Mapping region failed: %d\n", mmap_status);
		return MTK_SECURE_DATA_ERR_MAP;
	}

	ret = proc_secure_data(shm_vaddr);

	mmap_status = mmap_remove_dynamic_region(shm_vaddr, shm_size);
	if (mmap_status) {
		INFO("Unmapping region failed: %d\n", mmap_status);
		ret |= MTK_SECURE_DATA_ERR_UNMAP;
	}

	return ret;
}

uint64_t mtk_secure_data_get_key(const uint32_t key_id, void *buf)
{
	uint64_t ret = 0;
	void *key = NULL;
	uint8_t k_derived[MTK_SECURE_DATA_KEY_LEN] = {0};

	if (key_id > MTK_SECURE_DATA_MAX_KEY_ID || !buf)
		return MTK_SECURE_DATA_ERR_INVAL;

	switch (key_id) {
	case MTK_SECURE_DATA_ROOTFS_KEY_ID:
		key = k_rootfs;
		break;
	case MTK_SECURE_DATA_DERIVED_KEY_ID:
		ret = derive_key_from_hw_key(k_derived);
		if (ret)
			return ret;
		key = k_derived;
		break;
	default:
		key = NULL;
		break;
	}

	if (!key)
		return MTK_SECURE_DATA_ERR_KEY_UNK;

	memcpy(buf, key, MTK_SECURE_DATA_KEY_LEN);
	mbedtls_platform_zeroize(key, MTK_SECURE_DATA_KEY_LEN);

	return 0;
}

#ifdef MTK_PREPARE_SECURE_DATA
uint64_t mtk_secure_data_encrypt(u_register_t x1, u_register_t x2,
				 u_register_t x3, u_register_t x4,
				 void *buf)
{
	uint32_t ret = 0;
	uint8_t in[MTK_SECURE_DATA_KEY_LEN];
	uint8_t out[MTK_SECURE_DATA_KEY_LEN] __attribute__((aligned(16))) = {0};

	if (!buf)
		return MTK_SECURE_DATA_ERR_INVAL;

	*(u_register_t *)in = x1;
	*((u_register_t *)in + 1) = x2;
	*((u_register_t *)in + 2) = x3;
	*((u_register_t *)in + 3) = x4;

	ret = sej_encrypt(in, out, MTK_SECURE_DATA_KEY_LEN);
	if (ret) {
		ret = MTK_SECURE_DATA_ERR_ENC;
		goto mtk_secure_data_encrypt_err;
	}

	memcpy(buf, out, MTK_SECURE_DATA_KEY_LEN);

mtk_secure_data_encrypt_err:
	mbedtls_platform_zeroize(in, MTK_SECURE_DATA_KEY_LEN);

	return ret;
}
#else
uint64_t mtk_secure_data_encrypt(u_register_t x1, u_register_t x2,
				 u_register_t x3, u_register_t x4,
				 void *buf)
{
	return 0;
}
#endif
