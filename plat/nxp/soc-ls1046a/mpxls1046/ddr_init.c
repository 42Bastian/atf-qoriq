/*
 * Copyright 2018-2020 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

/*
 * Copyright (C) 2020 MicroSys Electronics GmbH
 * Author: Kay Potthoff <kay.potthoff@microsys.de>
 *
 */

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <common/debug.h>
#include <ddr.h>
#include <errata.h>
#include <lib/utils.h>

#include "plat_common.h"
#include <platform_def.h>

#if defined(CONFIG_COMELS1046A_MEM_4G)
static const struct rc_timing rce[] = {
    {2100, 0x4, 0x4},
    {}
};

static const struct board_timing udimm[] = {
    {0x1f, rce, 0x00020203, 0x03030302},
};
#else
static const struct rc_timing rce[] = {
    {1600, 0x9, 0xA},
    {2100, 0x9, 0xA},
    {}
};

static const struct board_timing udimm[] = {
    {0x1f, rce, 0xfffefefc, 0xfafaf9fc},
};
#endif

int ddr_board_options(struct ddr_info *priv)
{
    int ret;
    struct memctl_opt *popts = &priv->opt;

    ret = cal_board_params(priv, udimm, ARRAY_SIZE(udimm));
    if (ret)
        return ret;

    /*
     * Write leveling override
     */
    popts->wrlvl_override = 1;
    popts->wrlvl_sample = 0xf;

    /*
     * Rtt and Rtt_WR override
     */
    popts->rtt_override = 0;

    popts->ddr_cdr1 = DDR_CDR1_DHC_EN | DDR_CDR1_ODT(DDR_CDR_ODT_60ohm);
    popts->ddr_cdr2 =
        DDR_CDR2_ODT(DDR_CDR_ODT_60ohm) | DDR_CDR2_VREF_TRAIN_EN |
        DDR_CDR2_VREF_RANGE_2;

    /* optimize cpo for erratum A-009942 */
    popts->cpo_sample = 0x4b;

    return 0;
}

struct dimm_params ddr_raw_timing = {
    .n_ranks = 1,
#if defined(CONFIG_MPXLS1046_MEM_8G)
	.rank_density = MEM_8G,
	.capacity = MEM_8G,
#elif defined(CONFIG_MPXLS1046_MEM_4G) || defined(CONFIG_COMELS1046A_MEM_4G)
    .rank_density = MEM_4G,
    .capacity = MEM_4G,
#else
    .rank_density = MEM_2G,
    .capacity = MEM_2G,
#endif
    .primary_sdram_width = 64,
    .ec_sdram_width = 8,
    .rdimm = 0,
    .mirrored_dimm = 0,

#if defined(CONFIG_MPXLS1046_MEM_8G)
	.n_row_addr = 17,
#elif defined(CONFIG_MPXLS1046_MEM_4G) || defined(CONFIG_COMELS1046A_MEM_4G)
	.n_row_addr = 16,
#endif

#if defined(CONFIG_MPXLS1046_MEM_4G) || defined(CONFIG_COMELS1046A_MEM_4G) || defined(CONFIG_MPXLS1046_MEM_8G)
    .n_col_addr = 10,
    .bank_addr_bits = 0,
    .bank_group_bits = 1,
    .edc_config = 2,
    .burst_lengths_bitmask = 0x0c,

    .tckmin_x_ps = 937,
    .tckmax_ps = 1070,
    .caslat_x = 0x000DFA00,
    .taa_ps = 14060,
    .trcd_ps = 14060,
    .trp_ps = 14060,
    .tras_ps = 33000,
    .trc_ps = 47060,
    .twr_ps = 15000,
    .trfc1_ps = 350000,
    .trfc2_ps = 260000,
    .trfc4_ps = 160000,
    .tfaw_ps = 30000,
    .trrds_ps = 5300,
    .trrdl_ps = 6400,
    .tccdl_ps = 5355,
    .refresh_rate_ps = 3900000,
#else
    .n_row_addr = 15,
    .n_col_addr = 10,
    .bank_addr_bits = 0,
    .bank_group_bits = 1,
    .edc_config = 2,
    .burst_lengths_bitmask = 0x0c,

    .tckmin_x_ps = 1250,
    .tckmax_ps = 1499,
    .caslat_x = 0x000DFA00,
    .taa_ps = 13750,
    .trcd_ps = 13750,
    .trp_ps = 13750,
    .tras_ps = 35000,
    .trc_ps = 48750,
    .twr_ps = 15000,
    .trfc1_ps = 260000,
    .trfc2_ps = 160000,
    .trfc4_ps = 110000,
    .tfaw_ps = 35000,
    .trrds_ps = 6000,
    .trrdl_ps = 7500,
    .tccdl_ps = 6250,
    .refresh_rate_ps = 3900000,
#endif

#if defined(CONFIG_COMELS1046A_MEM_4G)
                             // SPD byte:
    .dq_mapping[0] = 0x0c,   // 60
    .dq_mapping[1] = 0x2b,   // 61
    .dq_mapping[2] = 0x0c,   // 62
    .dq_mapping[3] = 0x2c,   // 63
    .dq_mapping[4] = 0x0c,   // 64
    .dq_mapping[5] = 0x36,   // 65
    .dq_mapping[6] = 0x0c,   // 66
    .dq_mapping[7] = 0x36,   // 67
    .dq_mapping[8] = 0x0c,   // 68
    .dq_mapping[9] = 0x2b,   // 69
    .dq_mapping[10] = 0x15,  // 70
    .dq_mapping[11] = 0x2c,  // 71
    .dq_mapping[12] = 0x16,  // 72
    .dq_mapping[13] = 0x36,  // 73
    .dq_mapping[14] = 0x16,  // 74
    .dq_mapping[15] = 0x2c,  // 75
    .dq_mapping[16] = 0x16,  // 76
    .dq_mapping[17] = 0x2c,  // 77
    .dq_mapping_ors = 0,
#else
    .dq_mapping[0] = 0x07,
    .dq_mapping[1] = 0x2B,
    .dq_mapping[2] = 0x0B,
    .dq_mapping[3] = 0x36,
    .dq_mapping[4] = 0x0C,
    .dq_mapping[5] = 0x2C,
    .dq_mapping[6] = 0x0C,
    .dq_mapping[7] = 0x35,
    .dq_mapping[8] = 0x0B,
    .dq_mapping[9] = 0x2B,
    .dq_mapping[10] = 0x17,
    .dq_mapping[11] = 0x2C,
    .dq_mapping[12] = 0x09,
    .dq_mapping[13] = 0x2C,
    .dq_mapping[14] = 0x15,
    .dq_mapping[15] = 0x36,
    .dq_mapping[16] = 0x02,
    .dq_mapping[17] = 0x21,
    .dq_mapping_ors = 0,
#endif

    .rc = 0x1f,
};

int ddr_get_ddr_params(struct dimm_params *pdimm, struct ddr_conf *conf)
{
    static const char dimm_model[] = "Fixed DDR on board";

    conf->dimm_in_use[0] = 1;
    memcpy(pdimm, &ddr_raw_timing, sizeof(struct dimm_params));
    memcpy(pdimm->mpart, dimm_model, sizeof(dimm_model) - 1);

    return 1;
}

long long init_ddr(void)
{
    struct ddr_info info;
    struct sysinfo sys;
    long long dram_size;

    zeromem(&sys, sizeof(sys));
    get_clocks(&sys);
    debug("platform clock %lu\n", sys.freq_platform);
    debug("DDR PLL1 %lu\n", sys.freq_ddr_pll0);

    zeromem(&info, sizeof(struct ddr_info));
    info.num_ctlrs = 1;
    info.dimm_on_ctlr = 1;
    info.clk = get_ddr_freq(&sys, 0);
    info.ddr[0] = (void *)NXP_DDR_ADDR;

    dram_size = dram_init(&info);

    if (dram_size < 0)
        ERROR("DDR init failed.\n");

    erratum_a008850_post();

    return dram_size;
}
