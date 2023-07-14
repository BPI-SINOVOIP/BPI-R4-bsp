#
# Copyright (c) 2022, MediaTek Inc. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

MTK_PLAT		:=	plat/mediatek
MTK_PLAT_SOC		:=	${MTK_PLAT}/${PLAT}

# Whether to enble extra feature
I2C_SUPPORT		:= 	1
EIP197_SUPPORT		:= 	0
ENABLE_JTAG		?=	0

include lib/xlat_tables_v2/xlat_tables.mk
include lib/libfdt/libfdt.mk
include lib/xz/xz.mk
include make_helpers/dep.mk

BL2_CPU_SOURCES		:=	lib/cpus/aarch64/cortex_a73.S

PLAT_INCLUDES		:=	-Iinclude/plat/arm/common/			\
				-Iinclude/plat/arm/common/aarch64/		\
				-I${MTK_PLAT}/common/				\
				-I${MTK_PLAT}/common/drivers/gpt/		\
				-I${MTK_PLAT}/common/drivers/spi/		\
				-I${MTK_PLAT}/common/drivers/efuse		\
				-I${MTK_PLAT}/common/drivers/efuse/include	\
				-I${MTK_PLAT}/common/drivers/uart/		\
				-I${MTK_PLAT_SOC}/include/			\
				-I${MTK_PLAT_SOC}/drivers/efuse/include		\
				-I${MTK_PLAT_SOC}/drivers/gpio/			\
				-I${MTK_PLAT_SOC}/drivers/pll/			\
				-I${MTK_PLAT_SOC}/drivers/spi/			\
				-I${MTK_PLAT_SOC}/drivers/spmc/			\
				-I${MTK_PLAT_SOC}/drivers/timer/		\
				-I${MTK_PLAT_SOC}/drivers/trng/			\
				-I${MTK_PLAT_SOC}/drivers/dram/			\
				-I${MTK_PLAT_SOC}/drivers/devapc/

PLAT_BL_COMMON_SOURCES	:=	${XLAT_TABLES_LIB_SRCS}
CPPFLAGS		+=	-DPLAT_XLAT_TABLES_DYNAMIC

FDT_SOURCES		+=	fdts/${DTS_NAME}.dts

BL2_SOURCES		:=	$(BL2_CPU_SOURCES)				\
				common/desc_image_load.c			\
				common/image_decompress.c			\
				drivers/io/io_storage.c				\
				drivers/io/io_block.c				\
				drivers/io/io_fip.c				\
				drivers/delay_timer/delay_timer.c		\
				drivers/delay_timer/generic_delay_timer.c	\
				drivers/gpio/gpio.c				\
				$(XZ_SOURCES)					\
				${MTK_PLAT}/common/mtk_plat_common.c		\
				${MTK_PLAT}/common/drivers/gpt/mt_gpt.c		\
				${MTK_PLAT}/common/drivers/efuse/mtk_efuse.c	\
				${MTK_PLAT}/common/drivers/spi/mtk_spi.c	\
				${MTK_PLAT}/common/drivers/uart/aarch64/hsuart.S\
				${MTK_PLAT_SOC}/aarch64/plat_helpers.S		\
				${MTK_PLAT_SOC}/aarch64/platform_common.c	\
				${MTK_PLAT_SOC}/bl2_plat_setup.c		\
				${MTK_PLAT_SOC}/dtb.S				\
				${MTK_PLAT_SOC}/initcall.c			\
				${MTK_PLAT_SOC}/drivers/gpio/mt7988_gpio.c	\
				${MTK_PLAT_SOC}/drivers/pll/pll.c		\
				${MTK_PLAT_SOC}/drivers/spi/boot_spi.c		\
				${MTK_PLAT_SOC}/drivers/timer/cpuxgpt.c

# Include dram driver files
include ${MTK_PLAT_SOC}/drivers/dram/dram.mk

CPPFLAGS		+=	-DDTB_PATH=\"${BUILD_PLAT}/fdts/${DTS_NAME}.dtb\"

ifeq ($(FPGA), 1)
CPPFLAGS		+=	-DMT7988_FPGA
CPPFLAGS		+=	-DFPGA
endif

# IF BL33 is AARCH64, need to add this define
CPPFLAGS                +=      -DKERNEL_IS_DEFAULT_64BIT

ifeq ($(I2C_SUPPORT), 1)
include ${MTK_PLAT}/common/drivers/i2c/i2c.mk
override I2C_GPIO_SDA_PIN	:=	16
override I2C_GPIO_SCL_PIN	:=	15
PLAT_INCLUDES		+=	-I${MTK_PLAT_SOC}/drivers/pmic/
BL2_SOURCES		+=	${MTK_PLAT_SOC}/drivers/pmic/mt6682a.c
endif

ifeq ($(EIP197_SUPPORT), 1)
PLAT_INCLUDES		+=	-I${MTK_PLAT_SOC}/drivers/eip197/
BL2_SOURCES		+=	${MTK_PLAT_SOC}/drivers/eip197/eip197_init.c
CPPFLAGS		+=	-DEIP197_SUPPORT
endif

ifeq ($(ENABLE_JTAG), 1)
CPPFLAGS		+=	-DENABLE_JTAG
endif

ifeq ($(BL2_CPU_FULL_SPEED), 1)
CPPFLAGS		+=	-DCPU_USE_FULL_SPEED
endif

# Include GICv3 driver files
include drivers/arm/gic/v3/gicv3.mk

BL31_SOURCES		+=	drivers/arm/cci/cci.c				\
				${GICV3_SOURCES}				\
				drivers/delay_timer/delay_timer.c		\
				drivers/delay_timer/generic_delay_timer.c	\
				lib/cpus/aarch64/aem_generic.S			\
				lib/cpus/aarch64/cortex_a73.S			\
				plat/common/plat_gicv3.c			\
				${MTK_PLAT}/common/drivers/uart/aarch64/hsuart.S\
				${MTK_PLAT}/common/mtk_plat_common.c		\
				${MTK_PLAT}/common/drivers/gpt/mt_gpt.c		\
				${MTK_PLAT}/common/drivers/efuse/mtk_efuse.c	\
				${MTK_PLAT}/common/mtk_sip_svc.c		\
				${MTK_PLAT_SOC}/aarch64/plat_helpers.S		\
				${MTK_PLAT_SOC}/aarch64/platform_common.c	\
				${MTK_PLAT_SOC}/bl31_plat_setup.c		\
				${MTK_PLAT_SOC}/plat_mt_gic.c			\
				${MTK_PLAT_SOC}/plat_pm.c			\
				${MTK_PLAT_SOC}/plat_sip_calls.c		\
				${MTK_PLAT_SOC}/plat_topology.c			\
				${MTK_PLAT_SOC}/drivers/spmc/mtspmc.c		\
				${MTK_PLAT_SOC}/drivers/timer/cpuxgpt.c		\
				${MTK_PLAT_SOC}/drivers/trng/rng.c		\
				${MTK_PLAT_SOC}/drivers/dram/emi_mpu.c		\
				${MTK_PLAT_SOC}/drivers/devapc/devapc.c

include ${MTK_PLAT_SOC}/drivers/fwdl/fwdl.mk

ifeq ($(MT7988_FPGA_USE_BROM_SRAM),1)
BL2_BASE		:=	0x101000
else
BL2_BASE		:=	0x201000
endif
CPPFLAGS		+=	-DBL2_BASE=$(BL2_BASE)

ERRATA_A73_852427	:=	1
ERRATA_A73_855423	:=	1

# indicate the reset vector address can be programmed
PROGRAMMABLE_RESET_ADDRESS	:=	1

$(eval $(call add_define,MTK_SIP_SET_AUTHORIZED_SECURE_REG_ENABLE))

# Do not enable SVE
ENABLE_SVE_FOR_NS		:=	0
MULTI_CONSOLE_API		:=	1

RESET_TO_BL2			:=	1

#
# Bromimage related build macros
#

DOIMAGEPATH		:=      tools/mediatek/bromimage
DOIMAGETOOL		:=      ${DOIMAGEPATH}/bromimage

#
# Boot device related build macros
#

include ${MTK_PLAT_SOC}/image.mk

#
# NMBM related build macros
#

ifneq ($(filter snand spim-nand,$(BROM_HEADER_TYPE)),)
ifeq ($(NMBM),1)
include lib/nmbm/nmbm.mk
BL2_SOURCES		+=	${NMBM_SOURCES}
CPPFLAGS		+=	-DNMBM=1
ifneq ($(NMBM_MAX_RATIO),)
CPPFLAGS		+=	-DNMBM_MAX_RATIO=$(NMBM_MAX_RATIO)
endif
ifneq ($(NMBM_MAX_RESERVED_BLOCKS),)
CPPFLAGS		+=	-DNMBM_MAX_RESERVED_BLOCKS=$(NMBM_MAX_RESERVED_BLOCKS)
endif
ifneq ($(NMBM_DEFAULT_LOG_LEVEL),)
CPPFLAGS		+=	-DNMBM_DEFAULT_LOG_LEVEL=$(NMBM_DEFAULT_LOG_LEVEL)
endif
endif
endif # END OF NMBM

# BL2PL for BL2 compression
ifeq ($(BL2_COMPRESS),1)
BL2PL_SOURCES		+=	${MTK_PLAT_SOC}/bl2pl/bl2pl_plat_setup.c	\
				${MTK_PLAT_SOC}/bl2pl/serial.c			\
				${MTK_PLAT_SOC}/bl2pl/timer.c			\
				${MTK_PLAT_SOC}/drivers/pll/pll.c

BL2PL_CPPFLAGS		+=	-DXZ_SIMPLE_PRINT_ERROR
BL2_CPPFLAGS		+=	-DUSING_BL2PL
endif # END OF BL2_COMPRESS

#
# Trusted board related build macros
#

ifneq (${TRUSTED_BOARD_BOOT},0)
include drivers/auth/mbedtls/mbedtls_crypto.mk
include drivers/auth/mbedtls/mbedtls_x509.mk
ifeq ($(MBEDTLS_DIR),)
$(error You must specify MBEDTLS_DIR when TRUSTED_BOARD_BOOT enabled)
endif
CPPFLAGS		+=	-DMTK_EFUSE_FIELD_NORMAL
AUTH_SOURCES		:=	drivers/auth/auth_mod.c				\
				drivers/auth/crypto_mod.c			\
				drivers/auth/img_parser_mod.c			\
				drivers/auth/tbbr/tbbr_cot_bl2.c		\
				drivers/auth/tbbr/tbbr_cot_common.c
BL2_SOURCES		+=	${AUTH_SOURCES}					\
				${MTK_PLAT_SOC}/mtk_tbbr.c			\
				${MTK_PLAT_SOC}/mtk_rotpk.S
ROT_KEY			:=	$(BUILD_PLAT)/rot_key.pem
ROTPK_HASH		:=	$(BUILD_PLAT)/rotpk_sha256.bin

$(eval $(call add_define_val,ROTPK_HASH,'"$(ROTPK_HASH)"'))
$(BUILD_PLAT)/bl1/mtk_rotpk.o: $(ROTPK_HASH)
$(BUILD_PLAT)/bl2/mtk_rotpk.o: $(ROTPK_HASH)

certificates: $(ROT_KEY)
$(ROT_KEY): | $(BUILD_PLAT)
	@echo "  OPENSSL $@"
	$(Q)openssl genrsa 2048 > $@ 2>/dev/null

$(ROTPK_HASH): $(ROT_KEY)
	@echo "  OPENSSL $@"
	$(Q)openssl rsa -in $< -pubout -outform DER 2>/dev/null |\
	openssl dgst -sha256 -binary > $@ 2>/dev/null
endif


#
# Read/Write efuse related build macros
#

HAVE_EFUSE_SRC_FILE	:=	$(shell test -f ${MTK_PLAT}/common/drivers/efuse/src/efuse_cmd.c && echo yes)
ifeq ($(HAVE_EFUSE_SRC_FILE),yes)
PLAT_INCLUDES		+=	-I${MTK_PLAT}/common/drivers/efuse/src
BL31_SOURCES		+=	${MTK_PLAT}/common/drivers/efuse/src/efuse_cmd.c
else
PREBUILT_LIBS		+=	${MTK_PLAT_SOC}/drivers/efuse/release/efuse_cmd.o
endif


#
# Anti-rollback related build macros
#

DOVERSIONPATH		:=	tools/mediatek/ar-tool
DOVERSIONTOOL		:=	${DOVERSIONPATH}/ar-tool
AUTO_AR_VER		:=	${MTK_PLAT_SOC}/auto_ar_ver.c
AUTO_AR_CONF		:=	${MTK_PLAT_SOC}/auto_ar_conf.mk
ifeq ($(ANTI_ROLLBACK),1)
ifneq ($(TRUSTED_BOARD_BOOT),1)
$(error You must enable TRUSTED_BOARD_BOOT when ANTI_ROLLBACK enabled)
endif
ifeq ($(ANTI_ROLLBACK_TABLE),)
$(error You must specify ANTI_ROLLBACK_TABLE when ANTI_ROLLBACK enabled)
endif

BL2_SOURCES		+=	${AUTO_AR_VER}					\
				${MTK_PLAT}/common/mtk_ar.c
CPPFLAGS		+=	-DMTK_ANTI_ROLLBACK

ar_tool: $(DOVERSIONTOOL) $(AUTO_AR_VER) $(AUTO_AR_CONF)
	$(eval $(shell sed -n 1p $(AUTO_AR_CONF)))
	$(eval $(call CERT_REMOVE_CMD_OPT,0,--tfw-nvctr))
	$(eval $(call CERT_REMOVE_CMD_OPT,0,--ntfw-nvctr))
	$(eval $(call CERT_ADD_CMD_OPT,$(BL_AR_VER),--tfw-nvctr))
	$(eval $(call CERT_ADD_CMD_OPT,$(BL_AR_VER),--ntfw-nvctr))
	@echo "BL_AR_VER = $(BL_AR_VER)"

$(AUTO_AR_VER): $(DOVERSIONTOOL)
	$(Q)$(DOVERSIONTOOL) bl_ar_table create_ar_ver $(ANTI_ROLLBACK_TABLE) $(AUTO_AR_VER)

$(AUTO_AR_CONF): $(DOVERSIONTOOL)
	$(Q)$(DOVERSIONTOOL) bl_ar_table create_ar_conf $(ANTI_ROLLBACK_TABLE) $(AUTO_AR_CONF)

$(DOVERSIONTOOL):
	$(Q)$(MAKE) --no-print-directory -C $(DOVERSIONPATH)
else
ar_tool:
	@echo "Warning: anti-rollback function has been turn-off"
endif


# Build dtb before embedding to BL2

${BUILD_PLAT}/bl2/dtb.o: ${BUILD_PLAT}/fdts/${DTS_NAME}.dtb

# Make sure make command parameter reflects on .o files immediately
$(call GEN_DEP_RULES,bl2,emicfg bl2_boot_ram bl2_boot_snand bl2_boot_spim_nand mtk_efuse initcall mt7988_gpio)
$(call MAKE_DEP,bl2,emicfg,DRAM_USE_COMB DRAM_USE_DDR4 DRAM_SIZE_LIMIT DRAM_DEBUG_LOG)
$(call MAKE_DEP,bl2,initcall,BL2_COMPRESS I2C_SUPPORT EIP197_SUPPORT)
$(call MAKE_DEP,bl2,bl2_boot_ram,RAM_BOOT_DEBUGGER_HOOK RAM_BOOT_UART_DL)
$(call MAKE_DEP,bl2,bl2_boot_snand,NMBM NMBM_MAX_RATIO NMBM_MAX_RESERVED_BLOCKS NMBM_DEFAULT_LOG_LEVEL)
$(call MAKE_DEP,bl2,bl2_boot_spim_nand,NMBM NMBM_MAX_RATIO NMBM_MAX_RESERVED_BLOCKS NMBM_DEFAULT_LOG_LEVEL)
$(call MAKE_DEP,bl2,mtk_efuse,ANTI_ROLLBACK TRUSTED_BOARD_BOOT)
$(call MAKE_DEP,bl2,mt7988_gpio,ENABLE_JTAG)

$(call GEN_DEP_RULES,bl31,mtk_efuse plat_sip_calls)
$(call MAKE_DEP,bl31,mtk_efuse,ANTI_ROLLBACK TRUSTED_BOARD_BOOT)
$(call MAKE_DEP,bl31,plat_sip_calls,FWDL)

# BL2 compress
ifeq ($(BL2_COMPRESS),1)
BL2PLIMAGEPATH		:= tools/bl2plimage
BL2PLIMAGETOOL		:= ${BL2PLIMAGEPATH}/bl2plimage

$(BL2PLIMAGETOOL):
	$(Q)$(MAKE) --no-print-directory -C $(BL2PLIMAGEPATH)

$(BUILD_PLAT)/bl2-sfx.bin: $(BUILD_PLAT)/bl2pl.bin $(BUILD_PLAT)/bl2.bin.xz.plimg
	$(Q)cat $^ > $@

$(BUILD_PLAT)/bl2.bin.xz.plimg: $(BUILD_PLAT)/bl2.bin.xz $(BL2PLIMAGETOOL)
	$(Q)$(BL2PLIMAGETOOL) -a $(BL2_BASE) $(BUILD_PLAT)/bl2.bin.xz $@

$(BUILD_PLAT)/bl2.bin.xz: $(BUILD_PLAT)/bl2.bin
	$(ECHO) "  XZ      $@"
	$(Q)xz -e -k -9 -C crc32 $< --stdout > $@

.PHONY: $(BUILD_PLAT)/bl2.xz.plimg

BL2_IMG_PAYLOAD := $(BUILD_PLAT)/bl2-sfx.bin
else
BL2_IMG_PAYLOAD := $(BUILD_PLAT)/bl2.bin
endif # END OF BL2_COMPRESS

# FIP compress
ifeq ($(FIP_COMPRESS),1)
BL31_PRE_TOOL_FILTER	:= XZ
BL32_PRE_TOOL_FILTER	:= XZ
BL33_PRE_TOOL_FILTER	:= XZ
endif

OPTEE_TZRAM_SIZE := 0x10000
ifneq ($(BL32),)
ifeq ($(TRUSTED_BOARD_BOOT),1)
CPPFLAGS += -DNEED_BL32
OPTEE_TZRAM_SIZE := 0xfb0000
endif
endif
CPPFLAGS += -DOPTEE_TZRAM_SIZE=$(OPTEE_TZRAM_SIZE)

ifeq ($(BOOT_DEVICE),ram)
bl2: $(BL2_IMG_PAYLOAD)
else
bl2: $(BUILD_PLAT)/bl2.img
endif

ifneq ($(BROM_SIGN_KEY),)
$(BUILD_PLAT)/bl2.img: $(BROM_SIGN_KEY)
endif

MTK_SIP_KERNEL_BOOT_ENABLE := 1
$(eval $(call add_define,MTK_SIP_KERNEL_BOOT_ENABLE))

$(BUILD_PLAT)/bl2.img: $(BL2_IMG_PAYLOAD) $(DOIMAGETOOL)
	-$(Q)rm -f $@.signkeyhash
	$(Q)$(DOIMAGETOOL) -c mt7986 -f $(BROM_HEADER_TYPE) -a $(BL2_BASE) -d -e	\
		$(if $(BROM_SIGN_KEY), -s sha256+rsa-pss -k $(BROM_SIGN_KEY))	\
		$(if $(BROM_SIGN_KEY), -p $@.signkeyhash)			\
		$(if $(DEVICE_HEADER_OFFSET), -o $(DEVICE_HEADER_OFFSET))	\
		$(if $(BL_AR_VER), -r $(BL_AR_VER))				\
		$(if $(NAND_TYPE), -n $(NAND_TYPE))				\
		$(BL2_IMG_PAYLOAD) $@

$(DOIMAGETOOL): FORCE
	$(Q)$(MAKE) --no-print-directory -C $(DOIMAGEPATH)

.PHONY: $(BUILD_PLAT)/bl2.img $(AUTO_AR_TABLE) $(AUTO_AR_CONF)
