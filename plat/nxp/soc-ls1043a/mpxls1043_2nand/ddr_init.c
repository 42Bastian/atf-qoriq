/*
 * Copyright 2018 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Author York Sun <york.sun@nxp.com>
 */

/*
 * Copyright (C) 2020 MicroSys Electronics GmbH
 * Author: Kay Potthoff <kay.potthoff@microsys.de>
 * Co-Author: Sriraman Ravi <sriraman.ravi@microsys.de>
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
#include <lib/utils.h>
#include <lib/utils_def.h>
#include <errata.h>

#include "plat_common.h"
#include <platform_def.h>

#ifdef CONFIG_STATIC_DDR
const struct ddr_cfg_regs static_1600 = {
    .cs[0].config = 0x80040412,
    .cs[0].bnds = 0x0000007F,
    .sdram_cfg[0] = 0xE50C0004,
    .sdram_cfg[1] = 0x00401110,
    .timing_cfg[0] = 0x91550018,
    .timing_cfg[1] = 0xBCB40C52,
    .timing_cfg[2] = 0x0048C11C,
    .timing_cfg[3] = 0x01111000,
    .timing_cfg[4] = 0x00000002,
    .timing_cfg[5] = 0x03401400,
    .timing_cfg[7] = 0x23300000,
    .timing_cfg[8] = 0x02116600,
    .sdram_mode[0] = 0x03010210,
    .sdram_mode[9] = 0x04000000,
    .sdram_mode[8] = 0x00000500,
    .sdram_mode[2] = 0x00010210,
    .sdram_mode[10] = 0x00000400,
    .sdram_mode[11] = 0x04000000,
    .sdram_mode[4] = 0x00010210,
    .sdram_mode[12] = 0x00000400,
    .sdram_mode[13] = 0x04000000,
    .sdram_mode[6] = 0x00010210,
    .sdram_mode[14] = 0x00000400,
    .sdram_mode[15] = 0x04000000,
    .interval = 0x0C30030C,
    .zq_cntl = 0x8A090705,
    .clk_cntl = 0x02400000,
    .cdr[0] = 0x80080000,
    .cdr[1] = 0x0000A180,
    .wrlvl_cntl[0] = 0x8675F605,
    .wrlvl_cntl[1] = 0x07070800,
    .wrlvl_cntl[2] = 0x00000008,
};

long long board_static_ddr(struct ddr_info *priv)
{
    memcpy(&priv->ddr_reg, &static_1600, sizeof(static_1600));

    return 0x80000000;
}

#else
static const struct rc_timing rcz[] = {
    {1600, 0x9, 0x5},
    {}
};

static const struct board_timing ram[] = {
    {0x1f, rcz, 0x020202fb, 0xfafafb03},
};

int ddr_board_options(struct ddr_info *priv)
{
    int ret;
    struct memctl_opt *popts = &priv->opt;

    ret = cal_board_params(priv, ram, ARRAY_SIZE(ram));
    if (ret)
        return ret;

    /* force DDR bus width to 32 bits */

    popts->otf_burst_chop_en = 0;
    popts->burst_length = DDR_BL8;

    /*
     * Factors to consider for half-strength driver enable:
     *    - number of DIMMs installed
     */
    popts->half_strength_drive_en = 0;
    /*
     * Write leveling override
     */
    popts->wrlvl_override = 1;
    popts->wrlvl_sample = 0xf;

    /*
     * Rtt and Rtt_WR override
     */
    popts->rtt_override = 0;

    popts->twot_en = 0;         /* disable 2T timing */
    /* optimize cpo for erratum A-009942 */
    popts->cpo_sample = 0x46;

    popts->ddr_cdr1 = DDR_CDR1_DHC_EN | DDR_CDR1_ODT(DDR_CDR_ODT_60ohm);
    popts->ddr_cdr2 = DDR_CDR2_ODT(DDR_CDR_ODT_60ohm) | DDR_CDR2_VREF_OVRD(70); /* Vref = 70% */

    return 0;
}

/* DDR model number: MT40A512M8HX-093E */
struct dimm_params ddr_raw_timing = {
    .n_ranks = 1,
    .rank_density = MEM_2G,
    .capacity = MEM_2G,
    .primary_sdram_width = 32,
    .ec_sdram_width = 4,
    .rdimm = 0,
    .mirrored_dimm = 0,
    .n_row_addr = 16,
    .n_col_addr = 10,
    .bank_addr_bits = 0,
    .bank_group_bits = 1,
    .edc_config = 2,
    .burst_lengths_bitmask = 0x0c,

    .tckmin_x_ps = 1250,
    .tckmax_ps = 1499,
    .caslat_x = 0x2edf,
    .taa_ps = 13750,
    .trcd_ps = 13750,
    .trp_ps = 13750,
    .tras_ps = 35000,
    .trc_ps = 48750,
    .twr_ps = 15000,
    .trfc1_ps = 350000,
    .trfc2_ps = 260000,
    .trfc4_ps = 160000,
    .tfaw_ps = 35000,
    .trrds_ps = 6000,
    .trrdl_ps = 7500,
    .tccdl_ps = 6250,
    .refresh_rate_ps = 3900000,
    .dq_mapping[0] = 0x0B,
    .dq_mapping[1] = 0x2B,
    .dq_mapping[2] = 0x0C,
    .dq_mapping[3] = 0x35,
    .dq_mapping[4] = 0x0C,
    .dq_mapping[5] = 0x2C,
    .dq_mapping[6] = 0x0B,
    .dq_mapping[7] = 0x36,
    .dq_mapping[8] = 0x07,
    .dq_mapping[9] = 0x0,
    .dq_mapping[10] = 0x0,
    .dq_mapping[11] = 0x0,
    .dq_mapping[12] = 0x0,
    .dq_mapping[13] = 0x0,
    .dq_mapping[14] = 0x0,
    .dq_mapping[15] = 0x0,
    .dq_mapping[16] = 0x0,
    .dq_mapping[17] = 0x0,
    .dq_mapping_ors = 0,
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
#endif

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

    return dram_size;
}
