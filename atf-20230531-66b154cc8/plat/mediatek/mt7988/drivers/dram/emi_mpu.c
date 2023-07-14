/*
 * Copyright (c) 2020, ARM Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <common/debug.h>
#include <lib/mmio.h>
#include <emi_mpu.h>
#include <mt7988_def.h>

#ifdef FWDL
#include <wo.h>
#endif

static unsigned int region_id;

/*
 * emi_mpu_set_region_protection: protect a region.
 * @start: start address of the region
 * @end: end address of the region
 * @access_permission: EMI MPU access permission
 * Return 0 for success, otherwise negative status code.
 */
static int _emi_mpu_set_protection(
	unsigned long start, unsigned long end,
	unsigned int apc)
{
	unsigned int dgroup;
	unsigned int region;

	region = (start >> 24) & 0xFF;
	start &= 0x00FFFFFF;
	dgroup = (end >> 24) & 0xFF;
	end &= 0x00FFFFFF;

	if  ((region >= EMI_MPU_REGION_NUM) || (dgroup > EMI_MPU_DGROUP_NUM)) {
		WARN("Region:%u or dgroup:%u is wrong!\n", region, dgroup);
		return -1;
	}

	apc &= 0x80FFFFFF;

	if ((start >= DRAM_OFFSET) && (end >= start)) {
		start -= DRAM_OFFSET;
		end -= DRAM_OFFSET;
	} else {
		WARN("start:0x%lx or end:0x%lx address is wrong!\n",
		     start, end);
		return -2;
	}

	mmio_write_32(EMI_MPU_SA(region), start);
	mmio_write_32(EMI_MPU_EA(region), end);
	mmio_write_32(EMI_MPU_APC(region, dgroup), apc);

	return 0;
}

void dump_emi_mpu_regions(void)
{
	unsigned long apc[EMI_MPU_DGROUP_NUM], sa, ea;

	int region, i;

	/* only dump 4 regions */
	for (region = 0; region < 4; ++region) {
		for (i = 0; i < EMI_MPU_DGROUP_NUM; ++i)
			apc[i] = mmio_read_32(EMI_MPU_APC(region, i));
		sa = mmio_read_32(EMI_MPU_SA(region));
		ea = mmio_read_32(EMI_MPU_EA(region));

		INFO("[MPU](Region%d)sa:0x%04lx, ea:0x%04lx\n",
		     region, sa, ea);
		INFO("[MPU](Region%d)apc0:0x%08lx, apc1:0x%08lx\n",
		     region, apc[0], apc[1]);
	}
}

int emi_mpu_set_protection(struct emi_region_info_t *region_info)
{
	unsigned long start, end;
	int i;
	int ret;

	if (region_info->region >= EMI_MPU_REGION_NUM)
		return -1;

	start = (unsigned long)(region_info->start >> EMI_MPU_ALIGN_BITS) |
		(region_info->region << 24);

	for (i = EMI_MPU_DGROUP_NUM - 1; i >= 0; i--) {
		end = (unsigned long)(region_info->end >> EMI_MPU_ALIGN_BITS) |
			(i << 24);
		ret = _emi_mpu_set_protection(start, end, region_info->apc[i]);
		if (ret)
			return ret;
	}

	return 0;
}

#ifdef FWDL
void emi_mpu_wo_init(void)
{
	struct emi_region_info_t region_info;
	int ret;

	/* WO cpu protect address */
	region_info.start = WO_CPU_EMI_BASE;
	region_info.end = (WO_CPU_EMI_BASE + WO_CPU_EMI_SIZE) - 1;
	region_info.region = region_id++;
	SET_ACCESS_PERMISSION(region_info.apc, 1,
			      FORBID, FORBID, FORBID, FORBID,
			      FORBID, FORBID, FORBID, FORBID,
			      FORBID, FORBID, FORBID, FORBID,
			      FORBID, FORBID, NO_PROT, SEC_RW);
	ret = emi_mpu_set_protection(&region_info);
	if (ret)
		panic();

	/* WO data protect address */
	region_info.start = WO_DATA_EMI_BASE;
	region_info.end = (WO_DATA_EMI_BASE + WO_DATA_EMI_SIZE) - 1;
	region_info.region = region_id++;
	SET_ACCESS_PERMISSION(region_info.apc, 1,
			      FORBID, FORBID, FORBID, FORBID,
			      FORBID, FORBID, FORBID, FORBID,
			      FORBID, FORBID, FORBID, FORBID,
			      FORBID, FORBID, NO_PROT, SEC_RW);
	ret = emi_mpu_set_protection(&region_info);
	if (ret)
		panic();
}
#endif

void emi_mpu_init(void)
{
	struct emi_region_info_t region_info;
	int ret;

	/* TZRAM protect address(320KB) */
	region_info.start = TZRAM_BASE;
	region_info.end = (TZRAM_BASE + TZRAM_SIZE + TZRAM2_SIZE) - 1;
	region_info.region = region_id++;
	SET_ACCESS_PERMISSION(region_info.apc, 1,
			      FORBID, FORBID, FORBID, FORBID,
			      FORBID, FORBID, FORBID, FORBID,
			      FORBID, FORBID, FORBID, FORBID,
			      FORBID, FORBID, FORBID, SEC_RW);
	ret = emi_mpu_set_protection(&region_info);
	if (ret)
		panic();

	dump_emi_mpu_regions();
}
