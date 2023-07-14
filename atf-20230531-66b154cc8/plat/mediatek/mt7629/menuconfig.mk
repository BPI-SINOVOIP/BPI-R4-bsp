#
# Copyright (c) 2022, MediaTek Inc. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause

NAMESPACE := MT7629

ifeq (${CONFIG_${NAMESPACE}_DRAM_DDR3},y)
MAKE_ARGS += DRAM_USE_DDR4=0
endif
