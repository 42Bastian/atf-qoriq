#
# Copyright 2018 NXP
# Copyright (C) 2019 MicroSys Electronics GmbH
#
# SPDX-License-Identifier: BSD-3-Clause
#
# Author Ruchika Gupta <ruchika.gupta@nxp.com>

# board-specific build parameters (sd, flexspi_nor, emmc)
BOOT_MODE	?= 	sd
BOARD		:=	mpxls1028
BOARD_PATH	:=	${PLAT_SOC_PATH}/mpxls1028
POVDD_ENABLE	:=	no

 # DDR Compilation Configs
NUM_OF_DDRC	:=	1
DDRC_NUM_DIMM	:=	1
DDRC_NUM_CS	:=	1
CONFIG_DDR_NODIMM	:=	1
DDR_ECC_EN	:=	yes
CONFIG_STATIC_DDR := 0

# On-board flash
FLASH_TYPE	:=	MT25QU128A
XSPI_FLASH_SZ	:=	0x1000000

 # Platform specific features.
WARM_BOOT	:=	no

 # Adding Platform files build files
BL2_SOURCES	+=	${BOARD_PATH}/ddr_init.c\
			${BOARD_PATH}/platform.c

SUPPORTED_BOOT_MODE	:=	flexspi_nor	\
				sd		\
				emmc

# Adding platform board build info
include plat/nxp/common/plat_make_helper/plat_common_def.mk

 # Adding SoC build info
include plat/nxp/soc-ls1028a/soc.mk

CFLAGS += -DCONFIG_MPXLS1028_MEM_4G -DCONFIG_TARGET_MPXLS1028
