/*
 * Copyright (c) 2019, MediaTek Inc. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PLAT_SIP_CALLS_H
#define PLAT_SIP_CALLS_H

/*******************************************************************************
 * Plat SiP function constants
 ******************************************************************************/
#define MTK_PLAT_SIP_NUM_CALLS		13

#define MTK_SIP_PWR_ON_MTCMOS		0x82000402
#define MTK_SIP_PWR_OFF_MTCMOS		0x82000403
#define MTK_SIP_PWR_MTCMOS_SUPPORT	0x82000404

/*
 *  MTK_SIP_EFUSE_GET_LEN - get data length of efuse field
 *
 *  parameters
 *  @x1:	efuse field
 *
 *  return
 *  @r0:	status
 *  @r1:	data length
 */
#define MTK_SIP_EFUSE_GET_LEN		0xC2000501

/*
 *  MTK_SIP_EFUSE_SEND_DATA - send data to efuse buffer
 *
 *  parameters
 *  @x1:	data offset, 0 ~ 24 bytes
 *  @x2:	data length, 0 ~ 8 bytes
 *  @x3:	data, bytes 0 to 3
 *  @x4:	data, bytes 4 to 7
 *
 *  return
 *  @r0:	status
 *  @r1:	data length
 */
#define MTK_SIP_EFUSE_SEND_DATA		0xC2000502

/*
 *  MTK_SIP_EFUSE_GET_DATA - get data from efuse buffer
 *
 *  parameters
 *  @x1:	data offset, 0 ~ 24 bytes
 *  @x2:	data length, 0 ~ 8 bytes
 *
 *  return
 *  @r0:	status
 *  @r1:	data length
 *  @r2:	data, bytes 0 to 3
 *  @r3:	data, bytes 4 to 7
 */
#define MTK_SIP_EFUSE_GET_DATA		0xC2000503

/*
 *  MTK_SIP_EFUSE_WRITE - write efuse field
 *
 *  parameters
 *  @x1:	efuse field
 *
 *  return
 *  @r0:	status
 */
#define MTK_SIP_EFUSE_WRITE		0xC2000504

/*
 *  MTK_SIP_EFUSE_READ - read efuse field
 *
 *  parameters
 *  @x1:	efuse field
 *
 *  return
 *  @r0:	status
 */
#define MTK_SIP_EFUSE_READ		0xC2000505

/*
 *  MTK_SIP_EFUSE_DISABLE - disable efuse field
 *
 *  parameters
 *  @x1:	efuse field
 *
 *  return
 *  @r0:	status
 */
#define MTK_SIP_EFUSE_DISABLE		0xC2000506

/*
 * MTK_SIP_SECURE_DATA_GET_SHM_CONFIG
 *
 * parameters
 *
 * return
 * @r0:		status
 * @r1:		shm addr
 * @r2:		shm size
 */
#define MTK_SIP_SECURE_DATA_GET_SHM_CONFIG 0xC2000520

/*
 * MTK_SIP_SECURE_DATA_PROC_DATA
 *
 * parameters
 *
 * return
 * @r0:		status
 */
#define MTK_SIP_SECURE_DATA_PROC_DATA	0xC2000521

/*
 * MTK_SIP_SECURE_DATA_GET_KEY
 *
 * parameters
 * @x1:		key identifier
 *
 * return
 * @r0:		key[63:0]
 * @r1:		key[127:64]
 * @r2:		key[191:128]
 * @r3:		key[255:192]
 */
#define MTK_SIP_SECURE_DATA_GET_KEY	0xC2000522

/*
 * MTK_SIP_SECURE_DATA_ENC - encrypt data using SEJ
 *
 * parameters
 * @x1:		data[63:0]
 * @x2:		data[127:64]
 * @x3:		data[191:128]
 * @x4:		data[255:192]
 *
 * return
 * @r0:		data_enc[63:0]
 * @r1:		data_enc[127:64]
 * @r2:		data_enc[191:128]
 * @r3:		data_enc[255:192]
 */
#define MTK_SIP_SECURE_DATA_ENC		0xC2000523
#endif /* PLAT_SIP_CALLS_H */
