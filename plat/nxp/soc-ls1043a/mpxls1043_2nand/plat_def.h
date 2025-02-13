/*
 * Copyright 2018-2021 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PLAT_DEF_H
#define PLAT_DEF_H

#include <arch.h>
#include <cortex_a72.h>
#include <policy.h>
/*
 * Required without TBBR.
 * To include the defines for DDR PHY Images.
 */
#include <tbbr_img_def.h>

#include "soc.h"

#define NXP_SPD_EEPROM0		0x51

#define NXP_SYSCLK_FREQ		100000000
#define NXP_DDRCLK_FREQ		100000000

/* UART related definition */
#define NXP_CONSOLE_ADDR	NXP_UART_ADDR
#define NXP_CONSOLE_BAUDRATE	115200

#define MEM_2G 0x080000000
#define MEM_4G 0x100000000
#define MEM_8G 0x200000000

#define PLAT_DEF_DRAM0_SIZE MEM_2G  /* == NXP_DRAM0_SIZE */

/* Size of cacheable stacks */
#if defined(IMAGE_BL2)
#if defined(TRUSTED_BOARD_BOOT)
#define PLATFORM_STACK_SIZE	0x2000
#else
#define PLATFORM_STACK_SIZE	0x1000
#endif
#elif defined(IMAGE_BL31)
#define PLATFORM_STACK_SIZE	0x1000
#endif

/* SD block buffer */
#define NXP_SD_BLOCK_BUF_SIZE	(0x00100000)
#define NXP_SD_BLOCK_BUF_ADDR	ULL(0x80000000)

#define BL2_LIMIT		(NXP_OCRAM_ADDR + NXP_OCRAM_SIZE)

#define FIRMWARE_WELCOME_STR_LS_BL2  "Welcome to MPX-LS1043 BL2 Phase\n"
#define FIRMWARE_WELCOME_STR_LS_BL31 "Welcome to MPX-LS1043 BL31 Phase\n"

/* IO defines as needed by IO driver framework */
#define MAX_IO_DEVICES		3
#define MAX_IO_BLOCK_DEVICES	1
#define MAX_IO_HANDLES		4

/*
 * FIP image defines - Offset at which FIP Image would be present
 * Image would include Bl31 , Bl33 and Bl32 (optional)
 */
#ifdef POLICY_FUSE_PROVISION
#define MAX_FIP_DEVICES		2
#endif

#ifndef MAX_FIP_DEVICES
#define MAX_FIP_DEVICES		1
#endif

/*
 * ID of the secure physical generic timer interrupt used by the BL32.
 */
#define BL32_IRQ_SEC_PHY_TIMER	29

/*
 * Define properties of Group 1 Secure and Group 0 interrupts as per GICv3
 * terminology. On a GICv2 system or mode, the lists will be merged and treated
 * as Group 0 interrupts.
 */
#define PLAT_LS_G1S_IRQ_PROPS(grp) \
	INTR_PROP_DESC(BL32_IRQ_SEC_PHY_TIMER, GIC_HIGHEST_SEC_PRIORITY, grp, \
			GIC_INTR_CFG_LEVEL)

#define PLAT_LS_G0_IRQ_PROPS(grp)

#endif /* PLAT_DEF_H */
