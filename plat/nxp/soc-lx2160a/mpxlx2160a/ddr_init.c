/*
 * Copyright 2018 NXP
 * Copyright (C) 2020 MicroSys Electronics GmbH
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Author York Sun <york.sun@nxp.com>
 * Kei Thomsen <thomsen@microsys.de>
 */

#include <platform_def.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <common/debug.h>
#include <errno.h>
#include <utils.h>
#include <string.h>
#include <ddr.h>
#include <lib/utils.h>
#include <load_img.h>

#include "plat_common.h"
#include <platform_def.h>

// Define for 64GB soldered down
// #define CONFIG_TARGET_MPXLX2160_64GB 1

#if defined(CONFIG_DDR_NODIMM)
/*
 * Code to bypass reading SPD.
 * DDR model number:
 * Micron D9XQH		popts->output_driver_impedance = 1;
		popts->vref_phy = U(0x60);		// 75%
		popts->odt = U(40);			// 40 Ohm
		popts->phy_tx_impedance = U(30);	// 30-40 Ohm
		popts->phy_atx_impedance = U(20);	// 20-30 Ohm

 * MT40A1G16RC-062E IT
 * 16Gbit * (8 + 2) * 2 = 32GByte + ECC
 */
struct dimm_params ddr_raw_timing = {
    .n_ranks = U(2),
#ifdef CONFIG_TARGET_MPXLX2160_64GB
    .rank_density = U(MEM_16G),
    .capacity = U(MEM_32G),
    .bank_group_bits = U(2),		// (BG0/1) for 64GB Board !!!
    .device_width = U(8),		// 16Gbit RAMs are dual die with 2 x8
#else
    .rank_density = U(MEM_8G),
    .capacity = U(MEM_16G),
    .bank_group_bits = U(1),		// (BG0) for 32GB Board !!!
    .device_width = U(16),		// 16Gbit RAMs are single die with real x16
#endif
    .primary_sdram_width = U(64),
    .ec_sdram_width = U(8),
    .package_3ds = U(0),
    .die_density = U(0x6),
    .rdimm = U(0),
    .mirrored_dimm = U(0),		// Mirror on SODIMM. See phy.c line 834 msg_blk->addr_mirror = 0x08
    .n_row_addr = U(17),
    .n_col_addr = U(10),
    .bank_addr_bits = U(0),		// (BA[1:0]) (UNUSED)
    .edc_config = U(2),			// 0 no ECC/CRC, 1 for CRC (unsupported), 2 for ECC
    .burst_lengths_bitmask = U(0x0c),	// (UNUSED)
    .tckmin_x_ps = U(625),		// -062E = 625psec
    .tckmax_ps = U(1600),
    .caslat_x = U(0x17FFFC00),		// KeiT from 0x00FFFC00 to 0x17FFFC00 from SO-SIMM SPD
					// Use the Timing for 2400 Speed Bin and not for the chip type (-062E)
    .taa_ps = 13320,			//-062E is 13.75nsec. (at 2400MT this is 13.32nsec)
    .trcd_ps = 13320,
    .trp_ps = 13320,
    .tras_ps = 32000,			// 32000
    .trc_ps = 32000+13320,              // tRAS + tRP => 45.329nsec
    .twr_ps = 15000,
    .trfc1_ps = 350000,			// was 550000 before. 16 and 32 are 350nsec
    .trfc2_ps = 260000,
    .trfc4_ps = 160000,
#ifdef CONFIG_TARGET_MPXLX2160_64GB_Test	// _Test because not sure if this can work
    .tfaw_ps = 21000,			// Page size 1KB (x8) = 21nsec
    .trrds_ps = 3300,			// Page size 1KB (x8) = 5.3nsec
    .trrdl_ps = 4900,			// Page size 1KB (x8) = 6.4nsec
#else
    .tfaw_ps = 30000,			// Page size 2KB (x16) = 30nsec
    .trrds_ps = 5300,			// Page size 2KB (x16) = 5.3nsec
    .trrdl_ps = 6400,			// Page size 2KB (x16) = 6.4nsec
#endif
    .tccdl_ps = 5000,
    .refresh_rate_ps = U(3900000),	// Refresh rate for up to 95C
    .dq_mapping[0] = 0x01,
    .dq_mapping[1] = 0x21,
    .dq_mapping[2] = 0x01,
    .dq_mapping[3] = 0x21,
    .dq_mapping[4] = 0x01,
    .dq_mapping[5] = 0x21,
    .dq_mapping[6] = 0x01,
    .dq_mapping[7] = 0x21,
    .dq_mapping[8] = 0x01,
    .dq_mapping[9] = 0x21,
    .dq_mapping[10] = 0x01,
    .dq_mapping[11] = 0x21,
    .dq_mapping[12] = 0x01,
    .dq_mapping[13] = 0x21,
    .dq_mapping[14] = 0x01,
    .dq_mapping[15] = 0x21,
    .dq_mapping[16] = 0x01,
    .dq_mapping[17] = 0x21,
    .dq_mapping_ors = 0,
};

int ddr_get_ddr_params(struct dimm_params *pdimm,
			    struct ddr_conf *conf)
{
	static const char dimm_model[] = "Fixed DDR on board";

	memcpy(pdimm, &ddr_raw_timing, sizeof(struct dimm_params));
	memcpy(pdimm->mpart, dimm_model, sizeof(dimm_model) - 1);

	conf->dimm_in_use[0] = pdimm->n_ranks;	/* Ranks on DIMM */
	conf->dimm_in_use[1] = 0;		/* Ranks on SODIMM. 0 until SPD is valid */

	/* valid DIMM mask, change accordingly, together with dimm_on_ctlr. */
	/* 0x1 == DDRC0, 0x04 == DDRC1, 0x05 == DDRC0+1 */
	return 0x5;
}
#endif	/* CONFIG_DDR_NODIMM */

#define DDR_ODT_NONE 0x10	// Flag that this CS is not used

// ODT setup to Ohm
const int odt_table[8] =
{ 1000, 60, 120, 40, 240, 48, 80, 34 };

const int odt_wr_table[5] =
{ 1000, 120, 240, 1000, 80 };

int calc_vref_percent(int Ron, int ODT)
{
	int Vddq = 1200;
	int Vlow = (Vddq * Ron) / (ODT + Ron);
	int Vmid = ((Vddq - Vlow) / 2) + Vlow;
	int percent = (Vmid * 10000) / Vddq;
	INFO("Ron = %d Ohm. ODT = %d Ohm. Vlow = %d mV, Vmid = %d mV -> %d Percent\n",Ron,ODT,Vlow,Vmid,percent/100);
	return percent;
}

// Calculate the Vrefdq start value by Ron and ODT
int calc_vrefdq(int Ron, int ODT)
{
	int percent = calc_vref_percent(Ron, ODT);
	int value = 0;
	// Range 1 60% - 92.50% in 0.65% Steps
	if (percent >= 6000) {
		if (percent > 9250) return 0x32;
		percent -= 6000;
		value = (percent / 65) + 1;
	}
	INFO(" Vrefdq Value = 0x%02x\n",value);
	return value;
}

// Calculate the Vrefdq start value by Ron and ODT
int calc_vrefphy(int Ron, int ODT)
{
	int value = (128 * calc_vref_percent(Ron, ODT)) / 10000;
	INFO(" Vrefphy Value = 0x%02x\n",value);
	return value;
}


int ddr_board_options(struct ddr_info *priv)
{
	struct memctl_opt *popts = &priv->opt;
	const struct ddr_conf *conf = &priv->conf;
	int i;

	/*
	 * Various other phy parameters are also defined in this file
	 * such as:
	 * PHY Data bus driver impedance: value is defined in popts->tx_impedance
	 * 	If not defined default is 28 ohm
	 * 	Valid values (in ohm): 000001 - 480.0, 240.0, 160.0, 120.0,
	 * 	96.0, 80.0, 68.6, 60.0, 53.3, 48.0, 43.6, 40.0, 36.9, 34.3,
	 * 	32.0, 30.0, 28.2
	 * PHY C/A bus driver impedance: value is defined in popts->atx_impedance
	 * 	If not defined default is 30 ohm
	 * 	Valid values (in ohm): 120.0, 60.0, 40.0, 30.0, 24.0, 20.0 Ohm
	 * PHY ODT: value is defined in popts->odt
	 * 	If not defined default is 60 ohm
	 * 	Valid values (in ohm): 000001 - 480.0, 240.0, 160.0, 120.0,
	 * 	96.0, 80.0, 68.6, 60.0, 53.3, 48.0, 43.6, 40.0, 36.9, 34.3,
	 * 	32.0, 30.0, 28.2
	 * PHY Vref: value is defined in popts->vref_phy
	 *	if not defined default value is 0x61
	 *	Value programmed in register is calculated as:
	 *	(input_value * 1000 - 345 * 128 + 320) / (5 * 128);
	 *
	 * Above mentioned settings are set in the below code, user can change
	 * according to their board/DRAM configuration needs.
	 */
	popts->vref_phy = 0;
	popts->vref_dimm = 0;
	popts->rtt_park = U(80);
	popts->otf_burst_chop_en = 0;		/* Override burst chop for update_burst_length() */
	popts->burst_length = U(DDR_BL8);
	/* Auto Precharge Enable:
	 * the memory Performance is about 9% faster, if multiple Cores are working all over they
	 * memory. But it is 8% slower with linear memory access.
	 * As we have 16 Cores, which are all working something somewhere without prediction,
	 * it is better to have Auto-Precharge-Enabled (set bstopre = 0)
	 */
	popts->bstopre = U(0);			/* auto precharge */
	popts->addr_hash = 0;			/* Must be 0 (OFF) for mixed configuration */

	// ddr.c/cal_odt did a generic setup, we have our own impression
	popts->rtt_override = 0;	// Dont override the odt_rtt_norm and odt_rtt_rw
	popts->rtt_override_value = DDR4_RTT_80_OHM;
	popts->rtt_wr_override_value = DDR4_RTT_WR_240_OHM;

	popts->twot_en = U(1);
	popts->threet_en = U(0);

	// Preset all CS
	switch (conf->dimm_in_use[1]) {
	case 0:
		// Only the soldered RAMs are used
		NOTICE("Soldered DRAM in use\n");
// Hiermit geht beim 32GB separate CS, als auch Interleaved CS0+1
// Bei beiden DDRC gleichzeitig muss CS0+1 Interleaved sein, sonst vertauschen die DDRC bei
// der höheren Adresse ein Adress-dreher auf dem höchsten Bit.
		// Fast gut für 64GB. Sehr gut für 32GB (31.5.22)
		popts->rtt_park = U(48);

		popts->cs_odt[0].odt_rtt_norm = DDR4_RTT_48_OHM;
		popts->cs_odt[0].odt_rtt_wr = DDR4_RTT_WR_120_OHM;

		popts->cs_odt[0].odt_rd_cfg = DDR_ODT_CS;
		popts->cs_odt[0].odt_wr_cfg = DDR_ODT_CS;

		popts->cs_odt[1].odt_rd_cfg = DDR_ODT_CS;
		popts->cs_odt[1].odt_wr_cfg = DDR_ODT_CS;

		// CS2/3 not used. Setup as NONE
		popts->cs_odt[2].odt_rd_cfg = DDR_ODT_NONE;
		popts->cs_odt[2].odt_wr_cfg = DDR_ODT_NONE;

		popts->cs_odt[3].odt_rd_cfg = DDR_ODT_NONE;
		popts->cs_odt[3].odt_wr_cfg = DDR_ODT_NONE;

		popts->output_driver_impedance = 1;	// 0 = 34 Ohm, 1 = 48 Ohm
		// popts->vref_phy = U(0x60);		// 83%
		popts->odt = U(60);			// 40 Ohm
		popts->phy_tx_impedance = U(32);	// 30-40 Ohm
		popts->phy_atx_impedance = U(24);	// 20-30 Ohm

		popts->addr_hash = 1;			// ON for single RAM type configuration
		// uncomment for 1T and CL=16, 18 or 20 -> Gear Down Mode
		// popts->twot_en = U(0);
		// popts->caslat_override = 1;
		// popts->caslat_override_value = 18;
		break;
	case 1:
		// Soldered RAMs + SODIMMs assembled
		NOTICE("Soldered DRAM + SODIMM in use (1 of 2 CS)\n");
		printf("!!! WARNING !!! SODIMM with Rank 1 is not working yet!!!\n");
		popts->cs_odt[0].odt_rtt_norm = DDR4_RTT_60_OHM;
		popts->cs_odt[0].odt_rtt_wr = DDR4_RTT_WR_120_OHM;

		popts->cs_odt[0].odt_rd_cfg = DDR_ODT_ALL_OTHER_CS;
		popts->cs_odt[0].odt_wr_cfg = DDR_ODT_CS_AND_OTHER_DIMM;

		popts->cs_odt[1].odt_rd_cfg = DDR_ODT_OTHER_CS_ONSAMEDIMM;
		popts->cs_odt[1].odt_wr_cfg = DDR_ODT_CS;

		popts->cs_odt[2].odt_rd_cfg = DDR_ODT_OTHER_DIMM;
		popts->cs_odt[2].odt_wr_cfg = DDR_ODT_CS_AND_OTHER_DIMM;

		// CS3 not used
		popts->cs_odt[3].odt_rd_cfg = DDR_ODT_NONE;
		popts->cs_odt[3].odt_wr_cfg = DDR_ODT_NONE;

		popts->output_driver_impedance = 0;
		popts->vref_phy = U(0x60);		// 75%
		popts->odt = U(60);			// 40 Ohm
		popts->phy_tx_impedance = U(40);	// 40 Ohm
		popts->phy_atx_impedance = U(40);	// 40 Ohm
		break;

	case 2:
		// Fehlerfrei bei 32 + 2x32GB 2400MT (31.5.22)
		// Schlecht bei 64 + 2x32GB (31.5.22)
		// Soldered RAMs + SODIMMs assembled
		NOTICE("Soldered DRAM + SODIMM in use (all CS) 96GB\n");
		/* odt_rtt_norm and odt_rtt_wr are only used from
		 * cs_odt[0] as the controller is not using UNQ_MRS_EN
		 */
		popts->rtt_park = U(120);
		// Funktioniert gut und nur mit CS0+CS1 und CS2+CS3
		popts->cs_odt[0].odt_rtt_norm = DDR4_RTT_80_OHM;
		popts->cs_odt[0].odt_rtt_wr = DDR4_RTT_WR_240_OHM;

		// CS0 is doing the Termination for access to the other DIMM pair (CS2+3)
		popts->cs_odt[0].odt_rd_cfg = DDR_ODT_CS_AND_OTHER_DIMM;
		popts->cs_odt[0].odt_wr_cfg = DDR_ODT_CS_AND_OTHER_DIMM;

		// CS1 is only doing the Termination for itself
		popts->cs_odt[1].odt_rd_cfg = DDR_ODT_CS;
		popts->cs_odt[1].odt_wr_cfg = DDR_ODT_CS;

		// CS2 is doing the Termination for access to the other DIMM pair (CS0+1)
		popts->cs_odt[2].odt_rd_cfg = DDR_ODT_CS_AND_OTHER_DIMM;
		popts->cs_odt[2].odt_wr_cfg = DDR_ODT_CS_AND_OTHER_DIMM;

		// CS3 is only doing the Termination for itself
		popts->cs_odt[3].odt_rd_cfg = DDR_ODT_CS;
		popts->cs_odt[3].odt_wr_cfg = DDR_ODT_CS;

		popts->output_driver_impedance = 1;
//		popts->vref_dimm = U(0x1C);		// Vmid 933mV
//		popts->vref_phy = U(0x70);		// Vmid 1050mV
		popts->odt = U(60);			// 60 Ohm
		popts->phy_tx_impedance = U(30);	// 28 Ohm
		popts->phy_atx_impedance = U(24);	// 30 Ohm
		break;
	default:
		break;
	}
	/* All CS are getting the samt rtt_norm and rtt_wr anyway.
	 * Make sure this is set, if later versions will do it
	 * different.
	 */
	for (i = 1; i < 4; i++) {
		popts->cs_odt[i].odt_rtt_norm =
			popts->cs_odt[0].odt_rtt_norm;
		popts->cs_odt[i].odt_rtt_wr =
			popts->cs_odt[0].odt_rtt_wr;
		popts->cs_odt[i].auto_precharge = 0;
	}

	if (popts->vref_dimm == 0) {
		// Set the Vrefdq start value based on the settings made
		int odt_wr = odt_wr_table[popts->cs_odt[0].odt_rtt_wr];
		int one_div_odt = 0;	// 1/odt -> 100000/odt for integer
		int odt;

		for (i = 0; i < 2; i++) {
			switch (popts->cs_odt[i].odt_wr_cfg) {
				case DDR_ODT_NONE:
					break;
				case DDR_ODT_ALL:
					// Write is setting the ODT_WR
					one_div_odt += 100000 / odt_wr;
					break;
				case DDR_ODT_CS:
				case DDR_ODT_CS_AND_OTHER_DIMM:
					if (i == 0)
						// Write is setting the ODT_WR
						one_div_odt += 100000 / odt_wr;
					else
						// Otherwise we have RTT_park active
						one_div_odt += 100000 / popts->rtt_park;
					break;
				default:
					// Otherwise we have RTT_park active
					one_div_odt += 100000 / popts->rtt_park;
					break;
			}
		}
		for ( ; i < 4; i++) {
			if (popts->cs_odt[i].odt_wr_cfg != DDR_ODT_NONE) {
				one_div_odt += 100000 / popts->rtt_park;
			}
		}
		odt = 100000 / one_div_odt;

		popts->vref_dimm = calc_vrefdq(popts->phy_tx_impedance, odt);
	}

	if (popts->vref_phy == 0) {
		int odt_rd = odt_table[popts->cs_odt[0].odt_rtt_norm];
		int ron = popts->output_driver_impedance ? 48 : 34;	// 48 or 34 Ohm
		int one_div_odt = 0;	// 1/odt -> 100000/odt for integer
		int odt;

		one_div_odt = 100000 / popts->odt;
		for (i = 0; i < 4; i++) {
			switch (popts->cs_odt[i].odt_rd_cfg) {
				case DDR_ODT_NONE:
					break;
				case DDR_ODT_CS:
					// only for cs0
					if (i == 0) {
						one_div_odt += 100000 / odt_rd;
					} else {
						// Otherwise we have RTT_park active
						one_div_odt += 100000 / popts->rtt_park;
					}
					break;
				case DDR_ODT_ALL:
					// on every
					one_div_odt += 100000 / odt_rd;
					break;
				case DDR_ODT_ALL_OTHER_CS:
				case DDR_ODT_CS_AND_OTHER_DIMM:
					if (i == 0) {
						one_div_odt += 100000 / odt_rd;
					} else {
						// Otherwise we have RTT_park active
						one_div_odt += 100000 / popts->rtt_park;
					}
					break;
				case DDR_ODT_OTHER_DIMM:
					// other dimm
					if (i >= 2) {
						one_div_odt += 100000 / odt_rd;
					} else {
						// Otherwise we have RTT_park active
						one_div_odt += 100000 / popts->rtt_park;
					}
					break;
				case DDR_ODT_SAME_DIMM:
					// same dimm
					if (i <= 1) {
						one_div_odt += 100000 / odt_rd;
					} else {
						// Otherwise we have RTT_park active
						one_div_odt += 100000 / popts->rtt_park;
					}
					break;
				default:
					// Otherwise we have RTT_park active
					one_div_odt += 100000 / popts->rtt_park;
					break;
			}
		}
		odt = 100000 / one_div_odt;
		popts->vref_phy = calc_vrefphy(ron, odt);
	}
	// Timing when changing CS
	popts->trwt_override = U(1);
#if 0	// Super Slow Timing for Tests
	popts->trwt = U(0xf);
	popts->twrt = U(0x7);
	popts->trrt = U(0x7);
	popts->twwt = U(0x7);
	NOTICE("Slow RW-WR-RR-WW Timing\n");
#elif 0
	popts->trwt = U(0x5);
	popts->twrt = U(0x3);
	popts->trrt = U(0x3);
	popts->twwt = U(0x3);
	NOTICE("Medium RW-WR-RR-WW Timing\n");
#elif 1	// Regular timing
	popts->trwt = U(0x3);
	popts->twrt = U(0x2);
	popts->trrt = U(0x4);
	popts->twwt = U(0x5);
	NOTICE("Regular RW-WR-RR-WW Timing\n");
#else
	popts->trwt = U(0x1);
	popts->twrt = U(0x1);
	popts->trrt = U(0x1);
	popts->twwt = U(0x1);
	NOTICE("Fastes RW-WR-RR-WW Timing\n");
#endif

	INFO("MPX-LX2160 Board Values set. Previous odt_* values are overwritten. DRAM Clock %lu\n",priv->clk);

	return 0;
}

#ifdef NXP_WARM_BOOT
long long init_ddr(uint32_t wrm_bt_flg)
#else
long long init_ddr(void)
#endif
{
	int spd_addr[] = { 0x51, 0x51, 0x53, 0x53 };
	struct ddr_info info;
	struct sysinfo sys;
	long long dram_size;

	zeromem(&sys, sizeof(sys));
	get_clocks(&sys);
	INFO("platform clock %lu\n", sys.freq_platform);
	INFO("DDR PLL1 %lu\n", sys.freq_ddr_pll0);
	INFO("DDR PLL2 %lu\n", sys.freq_ddr_pll1);

	zeromem(&info, sizeof(info));

	/* Set two DDRC. Unused DDRC will be removed automatically. */
	info.num_ctlrs = NUM_OF_DDRC;
	info.spd_addr = spd_addr;
	info.ddr[0] = (void *)NXP_DDR_ADDR;
	info.ddr[1] = (void *)NXP_DDR2_ADDR;
	info.phy[0] = (void *)NXP_DDR_PHY1_ADDR;
	info.phy[1] = (void *)NXP_DDR_PHY2_ADDR;
	info.clk = get_ddr_freq(&sys, 0);
	INFO("DDR CLK %lu\n",info.clk);
	info.img_loadr = load_img;
	info.phy_gen2_fw_img_buf = PHY_GEN2_FW_IMAGE_BUFFER;
	if (info.clk == 0) {
		info.clk = get_ddr_freq(&sys, 1);
	}
	info.dimm_on_ctlr = DDRC_NUM_DIMM;

	info.warm_boot_flag = DDR_WRM_BOOT_NT_SUPPORTED;
#ifdef NXP_WARM_BOOT
	if (wrm_bt_flg) {
		info.warm_boot_flag = DDR_WARM_BOOT;
	} else if (wrm_bt_flg == 0x0) {
		info.warm_boot_flag = DDR_COLD_BOOT;
	}
#endif

	dram_size = dram_init(&info
#if defined(NXP_HAS_CCN504) || defined(NXP_HAS_CCN508)
		    , NXP_CCN_HN_F_0_ADDR
#endif
		    );

	if (dram_size < 0)
		ERROR("DDR init failed.\n");

	return dram_size;
}
