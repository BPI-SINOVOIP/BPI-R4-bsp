#
# Copyright (c) 2022, MediaTek Inc. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#

LOCAL_DIR := $(call GET_LOCAL_DIR)

MODULE := pm

LOCAL_SRCS-y := ${LOCAL_DIR}/mtk_pm.c

$(eval $(call MAKE_MODULE,$(MODULE),$(LOCAL_SRCS-y),$(MTK_BL)))

SUB_RULES-$(CONFIG_MTK_PM_SUPPORT) := $(LOCAL_DIR)/armv${CONFIG_MTK_PM_ARCH}
$(eval $(call INCLUDE_MAKEFILE,$(SUB_RULES-y)))
