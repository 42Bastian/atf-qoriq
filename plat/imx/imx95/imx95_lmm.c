#include <drivers/arm/css/scmi.h>
#include <imx_sip_svc.h>
#include <scmi_imx9.h>
#include <common/runtime_svc.h>

extern void *imx95_scmi_handle;

int imx_lmm_handler(uint32_t smc_fid, u_register_t x1, u_register_t x2,
		    u_register_t x3, void *handle)
{
	int ret;

	switch (x1) {
	case IMX_SIP_LMM_BOOT:
		ret = scmi_lmm_boot(imx95_scmi_handle, x2);
		if (ret)
			return ret;
		break;
	case IMX_SIP_LMM_SHUTDOWN:
		ret = scmi_lmm_shutdown(imx95_scmi_handle, x2,
					IMX9_SCMI_LMM_SHUTDOWN_FLAG_GRACEFUL);
		if (ret)
			return ret;
		break;
	default:
		return SMC_UNK;
	}

	return 0;
}
