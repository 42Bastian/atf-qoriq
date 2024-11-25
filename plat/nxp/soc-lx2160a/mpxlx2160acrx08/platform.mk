#
# Copyright 2018 NXP
# Copyright (C) 2021 MicroSys Electronics GmbH
#
# SPDX-License-Identifier: BSD-3-Clause
#
# Author Ruchika Gupta <ruchika.gupta@nxp.com>
#	Pankaj Gupta <pankaj.gupta@nxp.com>
#       Kei Thomsen <thomsen@microsys.de>
#	Sriraman Ravi <sriraman.ravi@microsys.de>

# board-specific build parameters (sd or flexspi_nor)
BOOT_MODE	:= 	flexspi_nor
BOARD		:=	mpxlx2160a
BOARD_PATH	:=	${PLAT_SOC_PATH}/mpxlx2160a
POVDD_ENABLE	:=	no
NXP_COINED_BB	:=	no

 # DDR Compilation Configs
NUM_OF_DDRC	:=	2
DDRC_NUM_DIMM	:=	2
CONFIG_DDR_NODIMM:=	1
DDRC_NUM_CS	:=	4
DDR_ECC_EN	:=	yes
 #enable address decoding feature
DDR_ADDR_DEC	:=	no	# not for MPX-LX2160
APPLY_MAX_CDD	:=	no	# not for MPX-LX2160, we specifiy the value

DDR_PHY_DEBUG	:=	no	# yes for debuging

 # On-Board Flash Details
FLASH_TYPE	:=	MT35XU512A
XSPI_FLASH_SZ	:=	0x10000000
NXP_XSPI_NOR_UNIT_SIZE		:=	0x20000
BL2_BIN_XSPI_NOR_END_ADDRESS	:=	0x100000
# CONFIG_FSPI_ERASE_4K is required to erase 4K sector sizes. This
# config is enabled for future use cases.
FSPI_ERASE_4K	:= 1

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
include plat/nxp/soc-lx2160a/soc.mk

$(eval $(call add_define_val,PHY_TRAINING_REGS_ON_FLASH,'${BL2_BIN_XSPI_NOR_END_ADDRESS} - ${NXP_XSPI_NOR_UNIT_SIZE}'))

CFLAGS += -DCONFIG_MPXLX2160_MEM_16G -DCONFIG_TARGET_MPXLX2160
