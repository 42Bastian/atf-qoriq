/*
 * Copyright 2021 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
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

#ifdef CONFIG_STATIC_DDR
#error No static value defined
#endif

static const struct rc_timing rce[] = {
    {2100, 0xA, 0xB},
    {}
};

static const struct board_timing udimm[] = {
    {0x04, rce, 0xfffefefc, 0xfafafafc},
};

int ddr_board_options(struct ddr_info *priv)
{
    int ret;
    struct memctl_opt *popts = &priv->opt;

    if (popts->rdimm) {
        debug("RDIMM parameters not set.\n");
        return -EINVAL;
    }

    ret = cal_board_params(priv, udimm, ARRAY_SIZE(udimm));
    if (ret)
        return ret;

    popts->half_strength_drive_en = 0;
    popts->wrlvl_override = 1;
    popts->wrlvl_sample = 0xf;
    popts->addr_hash = 1;
    popts->cpo_sample = 0x4b;
    popts->ddr_cdr1 = DDR_CDR1_DHC_EN | DDR_CDR1_ODT(DDR_CDR_ODT_60ohm);
    popts->ddr_cdr2 =
        DDR_CDR2_ODT(DDR_CDR_ODT_60ohm) | DDR_CDR2_VREF_TRAIN_EN |
        DDR_CDR2_VREF_RANGE_2;

    return 0;
}

/* DDR model number: MT40A512M8HX-093E */
struct dimm_params ddr_raw_timing = {
    .n_ranks = 1,
    /* DDR model number: MT40A512M16HX-093E */
    .rank_density = MEM_4G,
    .capacity = MEM_4G,
    .primary_sdram_width = 64,
    .ec_sdram_width = 8,
    .rdimm = 0,
    .mirrored_dimm = 0,
    .n_row_addr = 16,
    .n_col_addr = 10,
    .bank_addr_bits = 0,
    .bank_group_bits = 1,
    .edc_config = 2,
    .burst_lengths_bitmask = 0x0c,

    .tckmin_x_ps = 625,
    .tckmax_ps = 1500,
    .caslat_x = 0x01FFFC00,
    .taa_ps = 13750,
    .trcd_ps = 13750,
    .trp_ps = 13750,
    .tras_ps = 32000,
    .trc_ps = 45750,
    .twr_ps = 15000,
    .trfc1_ps = 350000,
    .trfc2_ps = 260000,
    .trfc4_ps = 160000,
    .tfaw_ps = 30000,
    .trrds_ps = 5300,
    .trrdl_ps = 6400,
    .tccdl_ps = 5000,
    .refresh_rate_ps = 3900000,
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
    .rc = 0x04,
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

//    erratum_a008850_post();

    return dram_size;
}
