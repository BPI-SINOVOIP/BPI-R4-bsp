#
# Copyright (c) 2022, MediaTek Inc. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

BOOT_DEVICE_LIST	:=	ram
BOOT_DEVICE_LIST	+=	snand
BOOT_DEVICE_LIST	+=	spim-nand
BOOT_DEVICE_LIST	+=	nor
BOOT_DEVICE_LIST	+=	emmc
BOOT_DEVICE_LIST	+=	sdmmc

ifdef BOOT_DEVICE
#
# boot from ram
#
ifeq ($(BOOT_DEVICE),ram)
BL2_SOURCES		+=	drivers/io/io_memmap.c			\
				${MTK_PLAT_SOC}/bl2_boot_ram.c
DTS_NAME		:=	mt7988

ifeq ($(RAM_BOOT_DEBUGGER_HOOK), 1)
CPPFLAGS		+=	-DRAM_BOOT_DEBUGGER_HOOK
endif
ifeq ($(RAM_BOOT_UART_DL), 1)
BL2_SOURCES		+=	${MTK_PLAT}/common/uart_dl.c
CPPFLAGS		+=	-DRAM_BOOT_UART_DL
endif

else
#
# boot from flash
#
ifeq ($(BOOT_DEVICE),snand)
include ${MTK_PLAT}/common/drivers/snfi/mtk-snand.mk
BROM_HEADER_TYPE	:=	snand
NAND_TYPE		?=	hsm20:2k+64
BL2_SOURCES		+=	${MTK_SNAND_SOURCES}			\
				${MTK_PLAT_SOC}/bl2_boot_snand.c
PLAT_INCLUDES		+=	-I${MTK_PLAT}/common/drivers/snfi
CPPFLAGS		+=	-DMTK_MEM_POOL_BASE=0x40100000		\
				-DPRIVATE_MTK_SNAND_HEADER
DTS_NAME		:=	mt7988
endif
ifeq ($(BOOT_DEVICE),spim-nand)
CPPFLAGS		+=	-DMTK_SPIM_NAND
BROM_HEADER_TYPE	:=	spim-nand
NAND_TYPE		?=	spim:2k+64
BL2_SOURCES		+=	drivers/mtd/nand/core.c			\
				drivers/mtd/nand/spi_nand.c		\
				drivers/mtd/spi-mem/spi_mem.c		\
				${MTK_PLAT_SOC}/bl2_boot_spim_nand.c	\
				${MTK_PLAT}/common/mempool.c
PLAT_INCLUDES		+=	-Iinclude/lib/libfdt
CPPFLAGS		+=	-DMTK_MEM_POOL_BASE=0x40100000
DTS_NAME		:=	mt7988-spi0
endif
ifeq ($(BOOT_DEVICE),nor)
CPPFLAGS		+=	-DMTK_SPIM_NOR
BROM_HEADER_TYPE	:=	nor
BL2_SOURCES		+=	drivers/mtd/nor/spi_nor.c			\
				drivers/mtd/spi-mem/spi_mem.c			\
				${MTK_PLAT_SOC}/bl2_boot_spim_nor.c		\
				${MTK_PLAT}/common/mempool.c
PLAT_INCLUDES		+=	-Iinclude/lib/libfdt
CPPFLAGS		+=	-DMTK_MEM_POOL_BASE=0x40100000
DTS_NAME		:=	mt7988-spi2
endif
ifeq ($(BOOT_DEVICE),emmc)
BL2_SOURCES		+=	drivers/mmc/mmc.c				\
				drivers/partition/partition.c			\
				drivers/partition/gpt.c				\
				${MTK_PLAT}/common/drivers/mmc/mtk-sd.c		\
				${MTK_PLAT_SOC}/bl2_boot_mmc.c
BROM_HEADER_TYPE	:=	emmc
CPPFLAGS		+=	-DMSDC_INDEX=0
DTS_NAME		:=	mt7988
endif
ifeq ($(BOOT_DEVICE),sdmmc)
BL2_SOURCES		+=	drivers/mmc/mmc.c				\
				drivers/partition/partition.c			\
				drivers/partition/gpt.c				\
				${MTK_PLAT}/common/drivers/mmc/mtk-sd.c		\
				${MTK_PLAT_SOC}/bl2_boot_mmc.c
BROM_HEADER_TYPE	:=	sdmmc
CPPFLAGS		+=	-DMSDC_INDEX=1
DTS_NAME		:=	mt7988
DEVICE_HEADER_OFFSET	?=	0x4400
endif
ifeq ($(BROM_HEADER_TYPE),)
$(error BOOT_DEVICE has invalid value. Please re-check.)
endif
endif
else
$(error You must specify the boot device by provide BOOT_DEVICE= to \
	make parameter. Avaliable values: $(BOOT_DEVICE_LIST))
endif
