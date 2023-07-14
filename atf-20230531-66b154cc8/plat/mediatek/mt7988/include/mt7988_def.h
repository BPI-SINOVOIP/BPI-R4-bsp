/*
 * Copyright (c) 2021, MediaTek Inc. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MT7988_DEF_H
#define MT7988_DEF_H

#include "reg_base.h"

/* Special value used to verify platform parameters from BL2 to BL3-1 */
#define MT_BL31_PLAT_PARAM_VAL 0x0f1e2d3c4b5a6978ULL

/* CPU */
#define PRIMARY_CPU 0

/* MMU */
#define MTK_DEV_BASE		0x00000000
#define MTK_DEV_SIZE		0x20000000

/* GICv3 */
#define PLAT_ARM_GICD_BASE GIC_BASE
#define PLAT_ARM_GICR_BASE (GIC_BASE + 0x80000)

/* Int pol ctl */
#define SEC_POL_CTL_EN0 (MCUCFG_BASE + 0x0a00)
#define INT_POL_CTL0	(MCUCFG_BASE + 0x0a80)

/* Watchdog */
#define MTK_WDT_BASE	       CKSYS_TOPRGU_BASE
#define MTK_WDT_RESTART	       (MTK_WDT_BASE + 0x8)
#define MTK_WDT_STA		(MTK_WDT_BASE + 0xc)
#define MTK_WDT_SWRST	       (MTK_WDT_BASE + 0x14)
#define MTK_WDT_MODE_EXTEN     0x0004
#define MTK_WDT_MODE_IRQ       0x0008
#define MTK_WDT_MODE_DUAL_MODE 0x0040
#define MTK_WDT_SWRST_KEY      0x1209
#define MTK_WDT_MODE_KEY       0x22000000
#define MTK_WDT_RESTART_KEY    0x1971
#define MTK_WDT_MODE_ENABLE    0x0001

#define WDT_REASON_HW_RST		BIT(31)
#define WDT_REASON_SW_RST		BIT(30)
#define WDT_REASON_SECURE_RST		BIT(28)
#define WDT_REASON_THERMAL_RST		BIT(16)
#define WDT_REASON_SPM_RST		BIT(1)
#define WDT_REASON_SPM_THERMAL_RST	BIT(0)

/* MPU */
#define EMI_MPU_SA0			(EMI_MPU_APB_BASE + 0x100)
#define EMI_MPU_EA0			(EMI_MPU_APB_BASE + 0x200)
#define EMI_MPU_APC0			(EMI_MPU_APB_BASE + 0x300)
#define EMI_MPU_SA(region)		(EMI_MPU_SA0 + (region) * 4)
#define EMI_MPU_EA(region)		(EMI_MPU_EA0 + (region) * 4)
#define EMI_MPU_APC(region, dgroup)	(EMI_MPU_APC0 + (region) * 4 + \
					 (dgroup) * 0x100)

/* UART */
#define UART_BASE     UART0_BASE
#define UART_BAUDRATE 115200
#ifdef MT7988_FPGA
#define UART_CLOCK 12000000
#else
#define UART_CLOCK 40000000
#endif

/* TIMER */
#ifdef MT7988_FPGA
/* In FPGA design, the GPT clock rate is a half of FPGA XTAL */
#define MTK_GPT_CLOCK_RATE	12000000 / 2
/* In FPGA design, the systimer clock rate is equal to FPGA XTAL */
#define ARM_TIMER_CLOCK_RATE_0	12000000 / 1
#define ARM_TIMER_CLOCK_RATE_1	ARM_TIMER_CLOCK_RATE_0
#else
/* In ASIC design, the GPT clock rate is a half of 40M ASIC XTAL */
#define MTK_GPT_CLOCK_RATE	40000000 / 2
/*
 * In ASIC design, the systimer clock rate is a half of CK_TOP_INFRA_F26M_SEL
 * CK_TOP_INFRA_26M_SEL default clock rate is a half of 40M ASIC XTAL, but after
 * PLL initial code, the clock rate of CK_TOP_INFRA_26M_SEL become 26M
 */
#define ARM_TIMER_CLOCK_RATE_0	40000000 / 2 / 2
#define ARM_TIMER_CLOCK_RATE_1	26000000 / 2
#endif

/* TOP_CLOCK*/
#define CLK_CFG_3_SET	      (CKSYS_CKCTRL_BASE + 0x034)
#define CLK_SPI_SEL_S	      (0)
#define CLK_NFI1X_SEL_S	      (16)
#define CLK_SPINFI_BCLK_SEL_S (24)

#define CLK_CFG_3_CLR		 (CKSYS_CKCTRL_BASE + 0x038)
#define CLK_SPI_SEL_MASK	 GENMASK(2, 0)
#define CLK_NFI1X_SEL_MASK	 GENMASK(18, 16)
#define CLK_SPINFI_BCLK_SEL_MASK GENMASK(26, 24)

#define CLK_CFG_UPDATE	 (CKSYS_CKCTRL_BASE + 0x1c0)
#define NFI1X_CK_UPDATE	 (1U << 14)
#define SPINFI_CK_UPDATE (1U << 15)
#define SPI_CK_UPDATE	 (1U << 12)

#ifndef __ASSEMBLER__
enum CLK_NFI1X_RATE {
	CLK_NFI1X_40MHz = 0,
	CLK_NFI1X_180MHz,
	CLK_NFI1X_156MHz,
	CLK_NFI1X_133MHz,
	CLK_NFI1X_104MHz,
	CLK_NFI1X_90MHz,
	CLK_NFI1X_78MHz,
	CLK_NFI1X_52MHz
};

enum CLK_SPINFI_RATE {
	CLK_SPINFI_20MHz = 0,
	CLK_SPINFI_40MHz,
	CLK_SPINFI_125MHz,
	CLK_SPINFI_104MHz,
	CLK_SPINFI_90MHz,
	CLK_SPINFI_78MHz,
	CLK_SPINFI_60MHz,
	CLK_SPINFI_52MHz
};

enum CLK_SPIM_RATE {
	CLK_SPIM_40MHz = 0,
	CLK_SPIM_208MHz,
	CLK_SPIM_180MHz,
	CLK_SPIM_156MHz,
	CLK_SPIM_133MHz,
	CLK_SPIM_125MHz,
	CLK_SPIM_104MHz,
	CLK_SPIM_76MHz
};
#endif

/* FIQ platform related define */
#define MT_IRQ_SEC_SGI_0 8
#define MT_IRQ_SEC_SGI_1 9
#define MT_IRQ_SEC_SGI_2 10
#define MT_IRQ_SEC_SGI_3 11
#define MT_IRQ_SEC_SGI_4 12
#define MT_IRQ_SEC_SGI_5 13
#define MT_IRQ_SEC_SGI_6 14
#define MT_IRQ_SEC_SGI_7 15

/* Define maximum page size for NAND devices */
#define PLATFORM_MTD_MAX_PAGE_SIZE 0x1000

#endif /* MT7988_DEF_H */
