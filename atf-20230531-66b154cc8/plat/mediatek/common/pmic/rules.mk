#
# Copyright (c) 2022, MediaTek Inc. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

LOCAL_DIR := $(call GET_LOCAL_DIR)

MODULE := pmic

LOCAL_SRCS-y += ${LOCAL_DIR}/pmic.c

PLAT_INCLUDES += -I${LOCAL_DIR}/

$(eval $(call MAKE_MODULE,$(MODULE),$(LOCAL_SRCS-y),$(MTK_BL)))
