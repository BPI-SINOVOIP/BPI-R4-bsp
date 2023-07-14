/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2022, MediaTek Inc. All rights reserved.
 *
 * Author: Sam Shih <sam.shih@mediatek.com>
 */

#include <assert.h>
#include <common/debug.h>
#include <cpuxgpt.h>
#include <lib/mmio.h>
#include <initcall.h>
#include <emi.h>
#include <mt7988_gpio.h>
#include <pll.h>
#ifdef EIP197_SUPPORT
#include <eip197_init.h>
#endif
#ifdef I2C_SUPPORT
#include <mt_i2c.h>
#include "mt6682a.h"
#endif

#define CHN_EMI_TESTB 0x10236048
#define EMI_TESTB     0x102190e8
#define GDU_REG_18    0x11c40048
#define GBE_TOP_REG   0x11d1020c
#define   I2P5G_MDIO  BIT(22)
#define PGD_REG_9     0x11d40024
#define PGD_REG_33    0x11d40084

#define HANG_FREE_PROT_INFRA_AO	0x1000310c

static int mtk_wdt_init(int data)
{
	unsigned int tmp;

	tmp = mmio_read_32(0x1001c00c);
	if (!tmp) {
		NOTICE("WDT: Cold boot\n");
	} else {
		NOTICE("WDT: Reboot status is 0x%x:\n", tmp);
		if (tmp & WDT_REASON_HW_RST)
			NOTICE("     Watchdog timeout\n");
		if (tmp & WDT_REASON_SW_RST)
			NOTICE("     Software reset (reboot)\n");
		if (tmp & WDT_REASON_SECURE_RST)
			NOTICE("     Secure reset\n");
		if (tmp & WDT_REASON_THERMAL_RST)
			NOTICE("     Thermal-triggered reset\n");
		if (tmp & WDT_REASON_SPM_RST)
			NOTICE("     SPM-trigger reset\n");
		if (tmp & WDT_REASON_SPM_THERMAL_RST)
			NOTICE("     SPM-thermal-triggered reset\n");
	}

	if (data) {
		NOTICE("WDT: enabled by default\n");
	} else {
		NOTICE("WDT: disabled\n");
		mmio_write_32(0x1001c000, 0x22000000);
	}

	return 0;
}

#ifndef MT7988_FPGA
static int bl2_pinmux_init(int data)
{
	mtk_pin_init();
	mt7988_set_default_pinmux();

	return 0;
}

static int bl2_pll_init(int data)
{
#ifndef USING_BL2PLL
	mtk_pll_init(data);
	eth_2p5g_phy_mtcmos_ctrl(true);
#endif

	return 0;
}

static int bl2_pll_post_init(int data)
{
	plat_mt_cpuxgpt_pll_update_sync();

	return 0;
}

static int mtk_disable_GDU(int data)
{
	INFO("PGD: disable GDU\n");
	mmio_write_32(GDU_REG_18, 0x1); //mask analog output

	return 0;
}

static int mtk_disable_PGD(int data)
{
	INFO("PGD: disable PGD\n");
	mmio_write_32(PGD_REG_33, 0xFFF); //mask analog output
	mmio_write_32(PGD_REG_9, 0x40); //DA_PWRGD_ENB analog power down

	return 0;
}
#endif

static int mtk_wed_init(int data)
{
	uint32_t val;

	INFO("WED: setup initial setting\n");
	/* EMI_TESTB: BYTE32_WRAP_EN */
	val = mmio_read_32(EMI_TESTB);
	mmio_write_32(EMI_TESTB, val | 0x20);
	/* EMI_TESTB: CHN_EMI_TESTB */
	val = mmio_read_32(CHN_EMI_TESTB);
	mmio_write_32(CHN_EMI_TESTB, val | 0x20);

	return 0;
}

static int init_infra_ao(int data)
{
	mmio_write_32(HANG_FREE_PROT_INFRA_AO, 0x0);

	return 0;
}

static int mtk_i2p5g_phy_init(int data)
{
	/* For internal 2.5Gphy,
	 * set bit 22 to use internal MDIO, and
	 * clear bit 22 to use external MDIO.
	 */
	mmio_setbits_32(GBE_TOP_REG, I2P5G_MDIO);

	return 0;
}

#ifdef I2C_SUPPORT
#ifndef MT7988_FPGA
static int bl2_i2c_init(int data)
{
	mtk_i2c_init();
	mt6682a_init();
#ifdef CPU_USE_FULL_SPEED
	mt6682a_set_voltage(REGULATOR_BUCK3, 900000, 900000);
#endif

	return 0;
}
#else
static int bl2_i2c_init(int data)
{
	mtk_i2c_init();
	return 0;
}
#endif
#endif


static int mtk_pcie_init(int data)
{
	uint32_t efuse, intr, cktx_pt0, cktx_pt1, cktx_pt2, cktx_pt3, val;

	/* PCIe SRAM PD  0:power on, 1:power off
	 * 0x10003030 bit[11:0]  port0 SRAM PD
	 * 0x10003030 bit[23:12] port1 SRAM PD
	 * 0x10003034 bit[11:0]  port2 SRAM PD
	 * 0x10003034 bit[23:12] port3 SRAM PD*/
	mmio_write_32(0x10003030, 0x00000000);
	mmio_write_32(0x10003034, 0x00000000);

	/* Switch PCIe MSI group1 to AP */
	mmio_write_32(0x10209000, 0x00000007);

	/* Adjust EQ preset P10 coefficient */
	mmio_write_32(0x11e48038, 0x000f2100);
	mmio_write_32(0x11e48138, 0x000f2100);
	mmio_write_32(0x11e58038, 0x000f2100);
	mmio_write_32(0x11e58138, 0x000f2100);
	mmio_write_32(0x11e68038, 0x000f2100);
	mmio_write_32(0x11e78038, 0x000f2100);

	/* CKM efuse load */
	efuse = mmio_read_32(0x11f508c4);
	intr = (efuse & GENMASK(25, 20)) >> 4;
	cktx_pt0 = (efuse & GENMASK(19, 15)) >> 15;
	cktx_pt1 = (efuse & GENMASK(14, 10)) >> 10;
	cktx_pt2 = (efuse & GENMASK(9, 5)) << 11;
	cktx_pt3 = efuse & GENMASK(4, 0);
	/* BIAS_INTR_CTRL:  EFUSE[25:20] to 0x11f10000[21:16] */
	val = mmio_read_32(0x11f10000);
	val = (val & ~GENMASK(21, 16)) | intr;
	mmio_write_32(0x11f10000, val);
	/* PT0_CKTX_IMPSEL: EFUSE[19:15] to 0x11f10004[4:0] */
	val = mmio_read_32(0x11f10004);
	val = (val & ~GENMASK(4, 0)) | cktx_pt0;
	mmio_write_32(0x11f10004, val);
	/* PT1_CKTX_IMPSEL: EFUSE[14:10] to 0x11f10018[4:0] */
	/* PT2_CKTX_IMPSEL: EFUSE[9:5]   to 0x11f10018[20:16] */
	val = mmio_read_32(0x11f10018);
	val = (val & ~GENMASK(4, 0)) | cktx_pt1;
	val = (val & ~GENMASK(20, 16)) | cktx_pt2;
	mmio_write_32(0x11f10018, val);
	/* PT3_CKTX_IMPSEL: EFUSE[4:0]   to 0x11f1001c[4:0] */
	val = mmio_read_32(0x11f1001c);
	val = (val & ~GENMASK(4, 0)) | cktx_pt3;
	mmio_write_32(0x11f1001c, val);

	return 0;
}

#ifdef EIP197_SUPPORT
static int bl2_eip197_init(int data)
{
	printf("EIP197: setup initial setting\n");
	eip197_init();

	return 0;
}
#endif

static int bl2_memory_init(int data)
{
	mtk_mem_init();

	return 0;
}

const struct initcall_entry init_sequence[] = {
	{ .name = "mtk_wdt_init", .func = mtk_wdt_init, .data = 0 },
#ifndef MT7988_FPGA
	{ .name = "mtk_disable_PGD", .func = mtk_disable_PGD },
	{ .name = "mtk_disable_GDU", .func = mtk_disable_GDU },
	{ .name = "bl2_pinmux_init", .func = bl2_pinmux_init },
#endif
#ifdef I2C_SUPPORT
	{ .name = "bl2_i2c_init", .func = bl2_i2c_init },
#endif
#ifndef MT7988_FPGA
	{ .name = "bl2_pll_init", .func = bl2_pll_init, .data = 0 },
	{ .name = "bl2_pll_post_init", .func = bl2_pll_post_init },
#endif
	{ .name = "init_infra_ao", .func = init_infra_ao },
	{ .name = "mtk_pcie_init", .func = mtk_pcie_init },
#ifdef EIP197_SUPPORT
	{ .name = "bl2_eip197_init", .func = bl2_eip197_init },
#endif
	{ .name = "bl2_memory_init", .func = bl2_memory_init },
	{ .name = "mtk_wed_init", .func = mtk_wed_init },
	{ .name = "mtk_i2p5g_phy_init", .func = mtk_i2p5g_phy_init },
	{ NULL },
};

int initcall_run_list(void)
{
	const struct initcall_entry *entry;
	int ret;

	INFO("initcall: run init_sequence at %p\n", init_sequence);
	for (entry = init_sequence; entry->name; entry++) {
		if (entry->func) {
			INFO("initcall: %p (%s) (data=%d)\n", entry->func,
			     entry->name, entry->data);
			ret = entry->func(entry->data);
			if (ret) {
				ERROR("initcall failed at %p (%s) (err=%d)\n",
				      entry->func, entry->name, ret);

				return ret;
			}
		}
	}

	return 0;
}
