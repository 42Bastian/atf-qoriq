/*
 * Copyright (c) 2013-2021, ARM Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */


/*******************************************************************************
 * This is the Secure Payload Dispatcher (SPD). The dispatcher is meant to be a
 * plug-in component to the Secure Monitor, registered as a runtime service. The
 * SPD is expected to be a functional extension of the Secure Payload (SP) that
 * executes in Secure EL1. The Secure Monitor will delegate all SMCs targeting
 * the Trusted OS/Applications range to the dispatcher. The SPD will either
 * handle the request locally or delegate it to the Secure Payload. It is also
 * responsible for initialising and maintaining communication with the SP.
 ******************************************************************************/
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>

#include <arch_helpers.h>
#include <bl31/bl31.h>
#include <bl31/ehf.h>
#include <bl32/tsp/tsp.h>
#include <common/bl_common.h>
#include <common/debug.h>
#include <common/runtime_svc.h>
#include <lib/el3_runtime/context_mgmt.h>
#include <plat/common/platform.h>
#include <tools_share/uuid.h>

#define TSPD_ROUTE_IRQ_TO_EL3 1
#define TSPD_ROUTE_FIQ_TO_EL3 1

static int s_idle = 0;
static int ns_idle = 1;

#include "tspd_private.h"

/*******************************************************************************
 * Address of the entrypoint vector table in the Secure Payload. It is
 * initialised once on the primary core after a cold boot.
 ******************************************************************************/
tsp_vectors_t *tsp_vectors;

/*******************************************************************************
 * Array to keep track of per-cpu Secure Payload state
 ******************************************************************************/
tsp_context_t tspd_sp_context[TSPD_CORE_COUNT];


/* TSP UID */
DEFINE_SVC_UUID2(tsp_uuid,
                 0xa056305b, 0x9132, 0x7b42, 0x98, 0x11,
                 0x71, 0x68, 0xca, 0x50, 0xf3, 0xfa);

int32_t tspd_init(void);

static uint64_t switch_to_nonsecure()
{
   cpu_context_t *ns_cpu_context;
   /*
    * Restore non-secure state.
    */
   ns_cpu_context = cm_get_context(NON_SECURE);
   cm_el1_sysregs_context_restore(NON_SECURE);
   cm_set_next_eret_context(NON_SECURE);
   SMC_RET0(ns_cpu_context);
}

static uint64_t switch_to_secure()
{
   cpu_context_t *ns_cpu_context;
   /*
    * Restore non-secure state.
    */
   ns_cpu_context = cm_get_context(SECURE);
   cm_el1_sysregs_context_restore(SECURE);
   cm_set_next_eret_context(SECURE);
   SMC_RET0(ns_cpu_context);
}


static uint64_t tspd_sel1_interrupt_handler(uint32_t id,
					    uint32_t flags,
					    void *handle,
					    void *cookie)
{
  /* Check the security state when the exception was generated */
  if (get_interrupt_src_ss(flags) == NON_SECURE) {
    /* Save the non-secure context before entering the TSP */
    cm_el1_sysregs_context_save(NON_SECURE);
    s_idle = 0;
  } else {
    panic();
  }
  return switch_to_secure();
}

#if TSP_NS_INTR_ASYNC_PREEMPT
/*******************************************************************************
 * This function is the handler registered for Non secure interrupts by the
 * TSPD. It validates the interrupt and upon success arranges entry into the
 * normal world for handling the interrupt.
 ******************************************************************************/
static uint64_t tspd_ns_interrupt_handler(uint32_t id,
                                          uint32_t flags,
                                          void *handle,
                                          void *cookie)
{
  /* Check the security state when the exception was generated */

  if (get_interrupt_src_ss(flags) == SECURE) {
    cm_el1_sysregs_context_save(SECURE);
    ns_idle = 0;

  } else {
    panic();
  }
  return switch_to_nonsecure();
}
#endif

/*******************************************************************************
 * Secure Payload Dispatcher setup. The SPD finds out the SP entrypoint and type
 * (aarch32/aarch64) if not already known and initialises the context for entry
 * into the SP for its initialisation.
 ******************************************************************************/
static int32_t tspd_setup(void)
{
  entry_point_info_t *tsp_ep_info;
  uint32_t linear_id;

  linear_id = plat_my_core_pos();

  /*
   * Get information about the Secure Payload (BL32) image. Its
   * absence is a critical failure.  TODO: Add support to
   * conditionally include the SPD service
   */
  tsp_ep_info = bl31_plat_get_next_image_ep_info(SECURE);
  if (!tsp_ep_info) {
    WARN("No TSP provided by BL2 boot loader, Booting device"
         " without TSP initialization. SMC`s destined for TSP"
         " will return SMC_UNK\n");
    return 1;
  }

  /*
   * If there's no valid entry point for SP, we return a non-zero value
   * signalling failure initializing the service. We bail out without
   * registering any handlers
   */
  if (!tsp_ep_info->pc)
    return 1;

  /*
   * We could inspect the SP image and determine its execution
   * state i.e whether AArch32 or AArch64. Assuming it's AArch64
   * for the time being.
   */
  tspd_init_tsp_ep_state(tsp_ep_info,
                         TSP_AARCH64,
                         tsp_ep_info->pc,
                         &tspd_sp_context[linear_id]);

#if TSP_INIT_ASYNC
  bl31_set_next_image_type(SECURE);
#else
  /*
   * All TSPD initialization done. Now register our init function with
   * BL31 for deferred invocation
   */
  bl31_register_bl32_init(&tspd_init);
#endif
  return 0;
}

/*******************************************************************************
 * This function passes control to the Secure Payload image (BL32) for the first
 * time on the primary cpu after a cold boot. It assumes that a valid secure
 * context has already been created by tspd_setup() which can be directly used.
 * It also assumes that a valid non-secure context has been initialised by PSCI
 * so it does not need to save and restore any non-secure state. This function
 * performs a synchronous entry into the Secure payload. The SP passes control
 * back to this routine through a SMC.
 ******************************************************************************/
int32_t tspd_init(void)
{
  uint32_t linear_id = plat_my_core_pos();
  tsp_context_t *tsp_ctx = &tspd_sp_context[linear_id];
  entry_point_info_t *tsp_entry_point;
  uint64_t rc;

  /*
   * Get information about the Secure Payload (BL32) image. Its
   * absence is a critical failure.
   */
  tsp_entry_point = bl31_plat_get_next_image_ep_info(SECURE);
  assert(tsp_entry_point);

  cm_init_my_context(tsp_entry_point);

  /*
   * Arrange for an entry into the test secure payload. It will be
   * returned via TSP_ENTRY_DONE case
   */
  rc = tspd_synchronous_sp_entry(tsp_ctx);
  assert(rc != 0);

  return rc;
}


/*******************************************************************************
 * This function is responsible for handling all SMCs in the Trusted OS/App
 * range from the non-secure state as defined in the SMC Calling Convention
 * Document. It is also responsible for communicating with the Secure payload
 * to delegate work and return results back to the non-secure state. Lastly it
 * will also return any information that the secure payload needs to do the
 * work assigned to it.
 ******************************************************************************/


static uintptr_t tspd_smc_handler(uint32_t smc_fid,
                                  u_register_t x1,
                                  u_register_t x2,
                                  u_register_t x3,
                                  u_register_t x4,
                                  void *cookie,
                                  void *handle,
                                  u_register_t flags)
{
  cpu_context_t *ns_cpu_context;
  uint32_t linear_id = plat_my_core_pos(), ns;
  tsp_context_t *tsp_ctx = &tspd_sp_context[linear_id];
  uint64_t rc;
#if TSP_INIT_ASYNC
  entry_point_info_t *next_image_info;
#endif
//->        tf_log(LOG_MARKER_ERROR "x1 %ld\n",x1);

  /* Determine which security state this SMC originated from */
  ns = is_caller_non_secure(flags);

  switch (smc_fid) {

  case TSP_S_IDLE:
    if (ns)
      SMC_RET1(handle, SMC_UNK);

    cm_el1_sysregs_context_save(SECURE);
    s_idle = 1;
    if ( ns_idle == 0 ){
      return switch_to_nonsecure();
    } else {
      goto system_idle;
    }
    break;


  case TSP_NS_IDLE:
    if (!ns)
      SMC_RET1(handle, SMC_UNK);

    cm_el1_sysregs_context_save(NON_SECURE);
    ns_idle = 1;
    if ( s_idle == 0 ){

      return switch_to_secure();
    } else {
    system_idle:
      u_register_t isr;
      do{
//->        __asm__ __volatile__ (" wfi");
        __asm__ __volatile__ (" mrs %0,ISR_EL1":"=r"(isr));
        if ( isr & 0x40 ){
//->          NOTICE("FIQ\n");
          return switch_to_secure();
        } else if ( isr & 0x80 ){
//->          NOTICE("IRQ\n");
          return switch_to_nonsecure();
        }
      } while ( 1 );
      panic();
    }
    break;

/*
     * This function ID is used only by the SP to indicate it has
     * finished initialising itself after a cold boot
     */
  case TSP_ENTRY_DONE:
    if (ns)
      SMC_RET1(handle, SMC_UNK);

    /*
     * Stash the SP entry points information. This is done
     * only once on the primary cpu
     */
    assert(tsp_vectors == NULL);
    tsp_vectors = (tsp_vectors_t *) x1;

    if (tsp_vectors) {
      set_tsp_pstate(tsp_ctx->state, TSP_PSTATE_ON);

      /*
       * TSP has been successfully initialized. Register power
       * management hooks with PSCI
       */
      psci_register_spd_pm_hook(&tspd_pm);


      cm_el1_sysregs_context_save(SECURE);
      /*
       * Register an interrupt handler for S-EL1 interrupts
       * when generated during code executing in the
       * non-secure state.
       */
      flags = 0;
      set_interrupt_rm_flag(flags, NON_SECURE);
      rc = register_interrupt_type_handler(INTR_TYPE_S_EL1,
                                           tspd_sel1_interrupt_handler,
                                           flags);
      if (rc)
        panic();

      /*
       * Register an interrupt handler for NS interrupts when
       * generated during code executing in secure state are
       * routed to EL3.
       */
      flags = 0;
      set_interrupt_rm_flag(flags, SECURE);

      rc = register_interrupt_type_handler(INTR_TYPE_NS,
                                           tspd_ns_interrupt_handler,
                                           flags);
      if (rc)
        panic();
    }

#if TSP_INIT_ASYNC
    s_idle = 1;
    ns_idle = 0;
    /* Save the Secure EL1 system register context */
    cm_el1_sysregs_context_save(SECURE);

    /* Program EL3 registers to enable entry into the next EL */
    next_image_info = bl31_plat_get_next_image_ep_info(NON_SECURE);
    assert(next_image_info);
    assert(NON_SECURE ==
           GET_SECURITY_STATE(next_image_info->h.attr));

    cm_init_my_context(next_image_info);
    cm_prepare_el3_exit(NON_SECURE);
    SMC_RET0(cm_get_context(NON_SECURE));
#else
    /*
     * SP reports completion. The SPD must have initiated
     * the original request through a synchronous entry
     * into the SP. Jump back to the original C runtime
     * context.
     */
    tspd_synchronous_sp_exit(tsp_ctx, x1);
    break;
#endif
    /*
     * This function ID is used only by the SP to indicate it has finished
     * aborting a preempted Yielding SMC Call.
     */
  case TSP_ABORT_DONE:

    /*
     * These function IDs are used only by the SP to indicate it has
     * finished:
     * 1. turning itself on in response to an earlier psci
     *    cpu_on request
     * 2. resuming itself after an earlier psci cpu_suspend
     *    request.
     */
  case TSP_ON_DONE:
  case TSP_RESUME_DONE:

    /*
     * These function IDs are used only by the SP to indicate it has
     * finished:
     * 1. suspending itself after an earlier psci cpu_suspend
     *    request.
     * 2. turning itself off in response to an earlier psci
     *    cpu_off request.
     */
  case TSP_OFF_DONE:
  case TSP_SUSPEND_DONE:
  case TSP_SYSTEM_OFF_DONE:
  case TSP_SYSTEM_RESET_DONE:
    if (ns)
      SMC_RET1(handle, SMC_UNK);

    /*
     * SP reports completion. The SPD must have initiated the
     * original request through a synchronous entry into the SP.
     * Jump back to the original C runtime context, and pass x1 as
     * return value to the caller
     */
    tspd_synchronous_sp_exit(tsp_ctx, x1);
    break;

    /*
     * Request from non-secure client to perform an
     * arithmetic operation or response from secure
     * payload to an earlier request.
     */
  case TSP_FAST_FID(TSP_ADD):
  case TSP_FAST_FID(TSP_SUB):
  case TSP_FAST_FID(TSP_MUL):
  case TSP_FAST_FID(TSP_DIV):

  case TSP_YIELD_FID(TSP_ADD):
  case TSP_YIELD_FID(TSP_SUB):
  case TSP_YIELD_FID(TSP_MUL):
  case TSP_YIELD_FID(TSP_DIV):
    if (ns) {
      /*
       * This is a fresh request from the non-secure client.
       * The parameters are in x1 and x2. Figure out which
       * registers need to be preserved, save the non-secure
       * state and send the request to the secure payload.
       */
      assert(handle == cm_get_context(NON_SECURE));

      /* Check if we are already preempted */
      if (get_yield_smc_active_flag(tsp_ctx->state))
        SMC_RET1(handle, SMC_UNK);

      cm_el1_sysregs_context_save(NON_SECURE);

      /* Save x1 and x2 for use by TSP_GET_ARGS call below */
      store_tsp_args(tsp_ctx, x1, x2);

      /*
       * We are done stashing the non-secure context. Ask the
       * secure payload to do the work now.
       */

      /*
       * Verify if there is a valid context to use, copy the
       * operation type and parameters to the secure context
       * and jump to the fast smc entry point in the secure
       * payload. Entry into S-EL1 will take place upon exit
       * from this function.
       */
      assert(&tsp_ctx->cpu_ctx == cm_get_context(SECURE));

      /* Set appropriate entry for SMC.
       * We expect the TSP to manage the PSTATE.I and PSTATE.F
       * flags as appropriate.
       */
      if (GET_SMC_TYPE(smc_fid) == SMC_TYPE_FAST) {
        cm_set_elr_el3(SECURE, (uint64_t)
                       &tsp_vectors->fast_smc_entry);
      } else {
        set_yield_smc_active_flag(tsp_ctx->state);
        cm_set_elr_el3(SECURE, (uint64_t)
                       &tsp_vectors->yield_smc_entry);
#if TSP_NS_INTR_ASYNC_PREEMPT
        /*
         * Enable the routing of NS interrupts to EL3
         * during processing of a Yielding SMC Call on
         * this core.
         */
        enable_intr_rm_local(INTR_TYPE_NS, SECURE);
#endif

#if EL3_EXCEPTION_HANDLING
        /*
         * With EL3 exception handling, while an SMC is
         * being processed, Non-secure interrupts can't
         * preempt Secure execution. However, for
         * yielding SMCs, we want preemption to happen;
         * so explicitly allow NS preemption in this
         * case, and supply the preemption return code
         * for TSP.
         */
        ehf_allow_ns_preemption(TSP_PREEMPTED);
#endif
      }

      cm_el1_sysregs_context_restore(SECURE);
      cm_set_next_eret_context(SECURE);
      SMC_RET3(&tsp_ctx->cpu_ctx, smc_fid, x1, x2);
    } else {
      /*
       * This is the result from the secure client of an
       * earlier request. The results are in x1-x3. Copy it
       * into the non-secure context, save the secure state
       * and return to the non-secure state.
       */
      assert(handle == cm_get_context(SECURE));
      cm_el1_sysregs_context_save(SECURE);

      /* Get a reference to the non-secure context */
      ns_cpu_context = cm_get_context(NON_SECURE);
      assert(ns_cpu_context);

      /* Restore non-secure state */
      cm_el1_sysregs_context_restore(NON_SECURE);
      cm_set_next_eret_context(NON_SECURE);
      if (GET_SMC_TYPE(smc_fid) == SMC_TYPE_YIELD) {
        clr_yield_smc_active_flag(tsp_ctx->state);
#if TSP_NS_INTR_ASYNC_PREEMPT
        /*
         * Disable the routing of NS interrupts to EL3
         * after processing of a Yielding SMC Call on
         * this core is finished.
         */
        disable_intr_rm_local(INTR_TYPE_NS, SECURE);
#endif
      }

      SMC_RET3(ns_cpu_context, x1, x2, x3);
    }
    assert(0); /* Unreachable */

    /*
     * Request from the non-secure world to abort a preempted Yielding SMC
     * Call.
     */
  case TSP_FID_ABORT:
    /* ABORT should only be invoked by normal world */
    if (!ns) {
      assert(0);
      break;
    }

    assert(handle == cm_get_context(NON_SECURE));
    cm_el1_sysregs_context_save(NON_SECURE);

    /* Abort the preempted SMC request */
    if (!tspd_abort_preempted_smc(tsp_ctx)) {
      /*
       * If there was no preempted SMC to abort, return
       * SMC_UNK.
       *
       * Restoring the NON_SECURE context is not necessary as
       * the synchronous entry did not take place if the
       * return code of tspd_abort_preempted_smc is zero.
       */
      cm_set_next_eret_context(NON_SECURE);
      break;
    }

    cm_el1_sysregs_context_restore(NON_SECURE);
    cm_set_next_eret_context(NON_SECURE);
    SMC_RET1(handle, SMC_OK);

    /*
     * Request from non secure world to resume the preempted
     * Yielding SMC Call.
     */
  case TSP_FID_RESUME:
    /* RESUME should be invoked only by normal world */
    if (!ns) {
      assert(0);
      break;
    }

    /*
     * This is a resume request from the non-secure client.
     * save the non-secure state and send the request to
     * the secure payload.
     */
    assert(handle == cm_get_context(NON_SECURE));

    /* Check if we are already preempted before resume */
    if (!get_yield_smc_active_flag(tsp_ctx->state))
      SMC_RET1(handle, SMC_UNK);

    cm_el1_sysregs_context_save(NON_SECURE);

    /*
     * We are done stashing the non-secure context. Ask the
     * secure payload to do the work now.
     */
#if TSP_NS_INTR_ASYNC_PREEMPT
    /*
     * Enable the routing of NS interrupts to EL3 during resumption
     * of a Yielding SMC Call on this core.
     */
    enable_intr_rm_local(INTR_TYPE_NS, SECURE);
#endif

#if EL3_EXCEPTION_HANDLING
    /*
     * Allow the resumed yielding SMC processing to be preempted by
     * Non-secure interrupts. Also, supply the preemption return
     * code for TSP.
     */
    ehf_allow_ns_preemption(TSP_PREEMPTED);
#endif

    /* We just need to return to the preempted point in
     * TSP and the execution will resume as normal.
     */
    cm_el1_sysregs_context_restore(SECURE);
    cm_set_next_eret_context(SECURE);
    SMC_RET0(&tsp_ctx->cpu_ctx);

    /*
     * This is a request from the secure payload for more arguments
     * for an ongoing arithmetic operation requested by the
     * non-secure world. Simply return the arguments from the non-
     * secure client in the original call.
     */
  case TSP_GET_ARGS:
    if (ns)
      SMC_RET1(handle, SMC_UNK);

    get_tsp_args(tsp_ctx, x1, x2);
    SMC_RET2(handle, x1, x2);

  case TOS_CALL_COUNT:
    /*
     * Return the number of service function IDs implemented to
     * provide service to non-secure
     */
    SMC_RET1(handle, TSP_NUM_FID);

  case TOS_UID:
    /* Return TSP UID to the caller */
    SMC_UUID_RET(handle, tsp_uuid);

  case TOS_CALL_VERSION:
    /* Return the version of current implementation */
    SMC_RET2(handle, TSP_VERSION_MAJOR, TSP_VERSION_MINOR);

  default:
    break;
  }

  SMC_RET1(handle, SMC_UNK);
}

/* Define a SPD runtime service descriptor for fast SMC calls */
DECLARE_RT_SVC(
  tspd_fast,

  OEN_TOS_START,
  OEN_TOS_END,
  SMC_TYPE_FAST,
  tspd_setup,
  tspd_smc_handler
  );

/* Define a SPD runtime service descriptor for Yielding SMC Calls */
DECLARE_RT_SVC(
  tspd_std,

  OEN_TOS_START,
  OEN_TOS_END,
  SMC_TYPE_YIELD,
  NULL,
  tspd_smc_handler
  );
