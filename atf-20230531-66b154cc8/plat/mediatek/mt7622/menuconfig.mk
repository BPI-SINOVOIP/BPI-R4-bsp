#
# Copyright (c) 2022, MediaTek Inc. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause

NAMESPACE := MT7622

ifeq (${CONFIG_${NAMESPACE}_DRAM_DDR3},y)
MAKE_ARGS += DRAM_USE_DDR4=0
endif

ifeq (${CONFIG_${NAMESPACE}_DRAM_DDR3_FLYBY},y)
MAKE_ARGS += DDR3_FLYBY=1
endif

