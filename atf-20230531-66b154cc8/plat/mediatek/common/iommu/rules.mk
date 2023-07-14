#
# Copyright (c) 2022, MediaTek Inc. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

LOCAL_DIR := $(call GET_LOCAL_DIR)

MODULE := mtk_iommu

LOCAL_SRCS-y := ${LOCAL_DIR}/mtk_iommu_smc.c
LOCAL_SRCS-y += ${LOCAL_DIR}/${MTK_SOC}/mtk_iommu_plat.c

PLAT_INCLUDES += -I${LOCAL_DIR}
PLAT_INCLUDES += -I${LOCAL_DIR}/${MTK_SOC}

$(eval $(call MAKE_MODULE,$(MODULE),$(LOCAL_SRCS-y),$(MTK_BL)))
