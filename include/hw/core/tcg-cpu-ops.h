/*
 * TCG CPU-specific operations
 *
 * Copyright 2021 SUSE LLC
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef TCG_CPU_OPS_H
#define TCG_CPU_OPS_H

#include "hw/core/cpu.h"

struct TCGCPUOps {
    /**
     * @initialize: Initalize TCG state
     *
     * Called when the first CPU is realized.
     */
    void (*initialize)(void);
    /**
     * @synchronize_from_tb: Synchronize state from a TCG #TranslationBlock
     *
     * This is called when we abandon execution of a TB before starting it,
     * and must set all parts of the CPU state which the previous TB in the
     * chain may not have updated.
     * By default, when this is NULL, a call is made to @set_pc(tb->pc).
     *
     * If more state needs to be restored, the target must implement a
     * function to restore all the state, and register it here.
     */
    void (*synchronize_from_tb)(CPUState *cpu, const TranslationBlock *tb);
    /** @cpu_exec_enter: Callback for cpu_exec preparation */
    void (*cpu_exec_enter)(CPUState *cpu);
    /** @cpu_exec_exit: Callback for cpu_exec cleanup */
    void (*cpu_exec_exit)(CPUState *cpu);
    /**
     * @tlb_fill: Handle a softmmu tlb miss or user-only address fault
     *
     * For system mode, if the access is valid, call tlb_set_page
     * and return true; if the access is invalid, and probe is
     * true, return false; otherwise raise an exception and do
     * not return.  For user-only mode, always raise an exception
     * and do not return.
     */
    unsigned long (*tlb_fill_pgtables)(CPUState *cpu, vaddr addr, int size,
                              int mmu_idx, unsigned long *cr3, unsigned long *pud,
                                       unsigned long *pmd, unsigned long *pte,
                                       unsigned int *page_size, unsigned long *entry);
    bool (*tlb_fill)(CPUState *cpu, vaddr address, int size,
                     MMUAccessType access_type, int mmu_idx,
                     bool probe, uintptr_t retaddr);
    /** @debug_excp_handler: Callback for handling debug exceptions */
    void (*debug_excp_handler)(CPUState *cpu);

#ifdef NEED_CPU_H
#if defined(CONFIG_USER_ONLY) && defined(TARGET_I386)
    /**
     * @fake_user_interrupt: Callback for 'fake exception' handling.
     *
     * Simulate 'fake exception' which will be handled outside the
     * cpu execution loop (hack for x86 user mode).
     */
    void (*fake_user_interrupt)(CPUState *cpu);
#else
    /**
     * @do_interrupt: Callback for interrupt handling.
     */
    void (*do_interrupt)(CPUState *cpu);
#endif /* !CONFIG_USER_ONLY || !TARGET_I386 */
#ifdef CONFIG_SOFTMMU
    /** @cpu_exec_interrupt: Callback for processing interrupts in cpu_exec */
    bool (*cpu_exec_interrupt)(CPUState *cpu, int interrupt_request);
    /**
     * @do_transaction_failed: Callback for handling failed memory transactions
     * (ie bus faults or external aborts; not MMU faults)
     */
    void (*do_transaction_failed)(CPUState *cpu, hwaddr physaddr, vaddr addr,
                                  unsigned size, MMUAccessType access_type,
                                  int mmu_idx, MemTxAttrs attrs,
                                  MemTxResult response, uintptr_t retaddr);
    /**
     * @do_unaligned_access: Callback for unaligned access handling
     * The callback must exit via raising an exception.
     */
    void (*do_unaligned_access)(CPUState *cpu, vaddr addr,
                                MMUAccessType access_type,
                                int mmu_idx, uintptr_t retaddr) QEMU_NORETURN;

    /**
     * @adjust_watchpoint_address: hack for cpu_check_watchpoint used by ARM
     */
    vaddr (*adjust_watchpoint_address)(CPUState *cpu, vaddr addr, int len);

    /**
     * @debug_check_watchpoint: return true if the architectural
     * watchpoint whose address has matched should really fire, used by ARM
     */
    bool (*debug_check_watchpoint)(CPUState *cpu, CPUWatchpoint *wp);

    /**
     * @debug_check_breakpoint: return true if the architectural
     * breakpoint whose PC has matched should really fire.
     */
    bool (*debug_check_breakpoint)(CPUState *cpu);

    /**
     * @io_recompile_replay_branch: Callback for cpu_io_recompile.
     *
     * The cpu has been stopped, and cpu_restore_state_from_tb has been
     * called.  If the faulting instruction is in a delay slot, and the
     * target architecture requires re-execution of the branch, then
     * adjust the cpu state as required and return true.
     */
    bool (*io_recompile_replay_branch)(CPUState *cpu,
                                       const TranslationBlock *tb);
#endif /* CONFIG_SOFTMMU */
#endif /* NEED_CPU_H */

};

#endif /* TCG_CPU_OPS_H */
