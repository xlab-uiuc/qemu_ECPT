/*
 *  x86 exception helpers - sysemu code
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/log.h"
#include "tcg/helper-tcg.h"

#include "excp_helper.h"
#include "ECPT_hash.h"
#include "ECPT.h"
#include "fpt.h"


#include "build/x86_64-softmmu-config-target.h"
#include "tcg/sysemu/MemRecord.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

#ifdef TARGET_X86_64_ECPT
#include "ECPT_utils.h"
#endif 

#define QEMU_LOG_TRANSLATE(gdb, MASK, FMT, ...)   \
    do {                                                \
        if (likely(!gdb)) {       \
            qemu_log_mask(MASK, FMT, ## __VA_ARGS__);              \
        }                                               \
    } while (0)

int get_pg_mode(CPUX86State *env)
{
    int pg_mode = 0;
    if (env->cr[0] & CR0_WP_MASK) {
        pg_mode |= PG_MODE_WP;
    }
    if (env->cr[4] & CR4_PAE_MASK) {
        pg_mode |= PG_MODE_PAE;
    }
    if (env->cr[4] & CR4_PSE_MASK) {
        pg_mode |= PG_MODE_PSE;
    }
    if (env->cr[4] & CR4_PKE_MASK) {
        pg_mode |= PG_MODE_PKE;
    }
    if (env->cr[4] & CR4_PKS_MASK) {
        pg_mode |= PG_MODE_PKS;
    }
    if (env->cr[4] & CR4_SMEP_MASK) {
        pg_mode |= PG_MODE_SMEP;
    }
    if (env->cr[4] & CR4_LA57_MASK) {
        pg_mode |= PG_MODE_LA57;
    }
    if (env->hflags & HF_LMA_MASK) {
        pg_mode |= PG_MODE_LMA;
    }
    if (env->efer & MSR_EFER_NXE) {
        pg_mode |= PG_MODE_NXE;
    }
    return pg_mode;
}

#define PG_ERROR_OK (-1)

typedef hwaddr (*MMUTranslateFunc)(CPUState *cs, hwaddr gphys, MMUAccessType access_type,
				int *prot);

#define GET_HPHYS(cs, gpa, access_type, prot)  \
	(get_hphys_func ? get_hphys_func(cs, gpa, access_type, prot) : gpa)

#ifdef TARGET_X86_64_ECPT


static uint64_t gen_hash(uint64_t vpn, uint64_t size) {
    uint64_t hash = hash_wrapper(vpn);
    hash = hash % size;
    if (hash > size) {
        printf("Hash value %lu, size %lu\n", hash, size);
        assert(1 == 0 && "Hash value is larger than index\n");
    }

    return hash;
}

/**
     *  crc_64_multi_hash applies hash for n times, where n is the way number
     *  For example,
     *  For way 0: hash = crc64_be(VA)
     *  For way 1: hash = crc64_be(crc64_be(VA))
     *  For way 2: hash = crc64_be(crc64_be(crc64_be(VA)))
     */
// static uint64_t crc_64_multi_hash(uint64_t vpn, uint64_t size, int n) {
//     uint64_t hash = 0, i = 0;
//     // hash = crc64_be(0, &vpn, 5);
//     // for (i = 0; i < n; i++) {
//     //     hash = crc64_be(hash, &vpn, 5);
//     // }

//     hash = crc64_be(0, &vpn, 5); /* at most we need five of them */ 
//     for (i = 0; i < n; i++) {
//         hash = crc64_be(0, &hash, 5);
//     }
//     return hash;
// }

#define SIZE_PRIME 98317

struct hash_combinator {
	uint64_t vpn;
	uint64_t size;
	uint32_t way;
} __attribute__((__packed__));

uint64_t gen_hash64(uint64_t vpn, uint64_t size, uint32_t way) 
{
#ifdef TARGET_X86_64_ECPT_CRC64
    // uint64_t hash = crc_64_multi_hash(vpn, size, way);
    uint64_t hash = ecpt_crc64_hash(vpn, way);
#endif 

#ifdef TARGET_X86_64_ECPT_MURMUR64
    struct hash_combinator hash_combo = { .vpn = vpn,
					      .size = size * SIZE_PRIME,
					      .way = way };
	uint64_t hash =
		MurmurHash64(&hash_combo, sizeof(struct hash_combinator), 0);
#endif 

    hash = hash % size;

    if (hash > size) {
        printf("Hash value %lu, size %lu\n", hash, size);
        assert(1 == 0 && "Hash value is larger than index\n");
    }

    return hash;
}

void load_helper(CPUState *cs, void * entry, hwaddr addr, int size) {
	int32_t loaded = 0;
	int32_t needed = size;
	
	void * ptr = (void *) entry;

	while(loaded < needed) {
		if (needed - loaded >= 8) {
			uint64_t * quad_ptr = (uint64_t *) ptr;
			*quad_ptr = x86_ldq_phys(cs, addr);

			ptr += 8;
			loaded += 8;
			addr += 8;
		} else if (needed - loaded >= 4) {
			uint32_t * long_ptr = (uint32_t *) ptr;
			*long_ptr = x86_ldl_phys(cs, addr);

			ptr += 4;
			loaded += 4;
			addr += 4;
		} else if (needed - loaded >= 2) {
			uint16_t * word_ptr = (uint16_t *) ptr;
			*word_ptr = x86_lduw_phys(cs, addr);

			ptr += 2;
			loaded += 2;
			addr += 2;
		} else {
			uint8_t * word_ptr = (uint8_t *) ptr;
			*word_ptr = x86_ldub_phys(cs, addr);

			ptr += 1;
			loaded += 1;
			addr += 1;
		}
	}
}

static inline hwaddr get_pte_addr(hwaddr entry_addr, ecpt_entry_t * entry_p, uint64_t * pte_p) {
    return entry_addr + (uint64_t) (((void *) pte_p) - ((void *) entry_p));
}


static void fill_ways_range(int way_start, int way_end, int * possible_ways, int cur_pos, int * n_ways)
{
    int i;
    for (i = way_start; i < way_end; i++) {
        possible_ways[cur_pos] = i;
        cur_pos++;
    }
    *n_ways = cur_pos;
}

static inline void fill_all_kernel_ways(int * possible_ways, int * n_ways)
{
    fill_ways_range(0, ECPT_KERNEL_WAY, possible_ways, 0, n_ways);
}

static inline void fill_all_user_ways(int * possible_ways, int * n_ways)
{
    fill_ways_range(ECPT_KERNEL_WAY, ECPT_TOTAL_WAY, possible_ways, 0, n_ways);
}

static inline void fill_all_ways(int * possible_ways, int * n_ways)
{
    fill_ways_range(0, ECPT_TOTAL_WAY, possible_ways, 0, n_ways);
}

static uint32_t relative_way_to_absolute_way(int relative_way, bool is_kernel, enum Granularity gran)
{
    if (is_kernel) {
        if (gran == page_4KB) {
            return ECPT_4K_WAY_START + relative_way;
        } else if (gran == page_2MB) {
            return ECPT_2M_WAY_START + relative_way;
        } else if (gran == page_1GB) {
            return ECPT_1G_WAY_START + relative_way;
        } else {
            assert(0);
        }
    } else {
        if (gran == page_4KB) {
            return ECPT_4K_USER_WAY_START + relative_way;
        } else if (gran == page_2MB) {
            return ECPT_2M_USER_WAY_START + relative_way;
        } else if (gran == page_1GB) {
            return ECPT_1G_USER_WAY_START + relative_way;
        } else {
            assert(0);
        }
    }
    return 0; 
}

typedef struct hit_info {
    bool pud_hit;
    bool pmd_hit;
} hit_info_t;

static inline void fill_4K_ways_range(bool is_kernel, int * possible_ways, int * n_ways)
{
    if (is_kernel) {
        fill_ways_range(ECPT_4K_WAY_START, ECPT_4K_WAY_END, possible_ways, *n_ways, n_ways);
    } else {
        fill_ways_range(ECPT_4K_USER_WAY_START, ECPT_4K_USER_WAY_END, possible_ways, *n_ways, n_ways);
    } 
}

static inline void fill_2M_ways_range(bool is_kernel, int * possible_ways, int * n_ways)
{
    if (is_kernel) {
        fill_ways_range(ECPT_2M_WAY_START, ECPT_2M_WAY_END, possible_ways, *n_ways, n_ways);
    } else {
        fill_ways_range(ECPT_2M_USER_WAY_START, ECPT_2M_USER_WAY_END, possible_ways, *n_ways, n_ways);
    } 
}

static inline hit_info_t cwc_fill_finish_helper(hit_info_t hit_res, hwaddr addr, cwt_header_t pud_cwc_res, cwt_header_t pmd_cwc_res, int *possible_ways, int *n_ways)
{

    QEMU_LOG_TRANSLATE(
            0, CPU_LOG_MMU,
            "CWC LOAD: addr=%lx"
            " pud_hit=%d (p1G=%d, p2M=%d, p4K=%d, rel_way=%d), pmd_hit=%d (p2M=%d, p4K=%d, rel_way=%d)\n",
                addr, hit_res.pud_hit,
                pud_cwc_res.present_1GB, pud_cwc_res.present_2MB,
                pud_cwc_res.present_4KB, pud_cwc_res.way_in_ecpt,
                hit_res.pmd_hit,
                pmd_cwc_res.present_2MB, pmd_cwc_res.present_4KB, pmd_cwc_res.way_in_ecpt);
        
    QEMU_LOG_TRANSLATE(0, CPU_LOG_MMU, "CWC LOAD: ways=[ ");
    
    for (int i = 0; i < *n_ways; i++) {
        QEMU_LOG_TRANSLATE(0, CPU_LOG_MMU, "%d ", possible_ways[i]);
    }
    
    QEMU_LOG_TRANSLATE(0, CPU_LOG_MMU, "]\n");

    return hit_res;
}

static hit_info_t fill_from_cwc(CPUState *cs, hwaddr addr, int *possible_ways, int *n_ways)
{
    cwt_header_t pud_cwc_res = {}, pmd_cwc_res = {};
    bool pud_hit = cwc_lookup(&cwc_pud, addr, CWT_1GB, &pud_cwc_res);
    
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;
    bool is_kernel = is_kernel_addr(env, addr);

    hit_info_t hit_res = {};
    hit_res.pud_hit = pud_hit;

    if (pud_hit) {
        if (pud_cwc_res.present_1GB) {
            uint32_t abs_way = relative_way_to_absolute_way(pud_cwc_res.way_in_ecpt, is_kernel, page_1GB);
            fill_ways_range(abs_way, abs_way + 1, possible_ways, 0, n_ways);
            return cwc_fill_finish_helper(hit_res, addr, pud_cwc_res, pmd_cwc_res, possible_ways, n_ways);
        } 
        
        /* PUD 4K only */
        if (!!pud_cwc_res.present_4KB && !pud_cwc_res.present_2MB) {
            fill_4K_ways_range(is_kernel, possible_ways, n_ways);
            return cwc_fill_finish_helper(hit_res, addr, pud_cwc_res, pmd_cwc_res, possible_ways, n_ways);
        }
        
    } 

    bool pmd_hit = cwc_lookup(&cwc_pmd, addr, CWT_2MB, &pmd_cwc_res);
    hit_res.pmd_hit = pmd_hit;

    if (pmd_hit) {
        if (pmd_cwc_res.present_2MB) {
            uint32_t abs_way = relative_way_to_absolute_way(pmd_cwc_res.way_in_ecpt, is_kernel, page_2MB);
            fill_ways_range(abs_way, abs_way + 1, possible_ways, 0, n_ways);
        }
        
        if (pmd_cwc_res.present_4KB) {
            fill_4K_ways_range(is_kernel, possible_ways, n_ways);
        }
    } else {
        if (pud_hit && pud_cwc_res.present_2MB) {
            fill_2M_ways_range(is_kernel, possible_ways, n_ways);
        }

        if (pud_hit && pud_cwc_res.present_4KB) {
            fill_4K_ways_range(is_kernel, possible_ways, n_ways);
        }
    }

    return cwc_fill_finish_helper(hit_res, addr, pud_cwc_res, pmd_cwc_res, possible_ways, n_ways);
}

static void fix_cwc_from_cwt(CPUState *cs, hwaddr addr, hit_info_t hit_res)
{
    fetch_from_cwt(cs, &cwc_pud, addr, CWT_1GB, hit_res.pud_hit);
    fetch_from_cwt(cs, &cwc_pmd, addr, CWT_2MB, hit_res.pmd_hit);
    /* TODO: add pmd */
}

/* consume addr and CWC to get which way in ECPT to query 
    possible_ways will be filled. n_ways indicate its size.
    start and end indicate the range of ways to be filled.
*/
static bool __get_ECPT_full_ways(CPUState *cs, hwaddr addr, int * possible_ways, int * n_ways, hit_info_t hit_res, bool refill_cwc)
{
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;

    if (is_kernel_addr(env, addr)) {
        
        if (*n_ways < ECPT_KERNEL_WAY) {
            /* CWC fails to cover all ways*/
            /* TODO: optimize this by only querying the remaining ways  */
            fill_all_kernel_ways(possible_ways, n_ways);
            if (refill_cwc) {
                fix_cwc_from_cwt(cs, addr, hit_res); 
            }
            
        } else {
            /* cannot query more ways. Things not in page table */
            return false;                                                                                 
        }
    } else {
        if (*n_ways < ECPT_USER_WAY) {
            /* CWC fails to cover all ways*/
            /* TODO: optimize this by only querying the remaining ways */
            fill_all_user_ways(possible_ways, n_ways); 
            if (refill_cwc) {
                fix_cwc_from_cwt(cs, addr, hit_res);
            }
        } else {
            /* cannot query more ways. Things not in page table */
            return false;   
        }
    }

    return true;
}

static inline bool get_ECPT_full_ways_with_refill(CPUState *cs, hwaddr addr, int * possible_ways, int * n_ways, hit_info_t hit_res) {
    return __get_ECPT_full_ways(cs, addr, possible_ways, n_ways, hit_res, true);
}

/* used in simulation mode, get all ECPT info */
static inline bool get_ECPT_full_ways_no_refill(CPUState *cs, hwaddr addr, int * possible_ways, int * n_ways, hit_info_t hit_res) {
    return __get_ECPT_full_ways(cs, addr, possible_ways, n_ways, hit_res, false);
}

static uint64_t * entry_to_pte_pointer(ecpt_entry_t * entry, hwaddr addr, enum Granularity gran) {
    uint64_t * pte_pointer = NULL;
    
    if (gran == page_4KB) {
        pte_pointer = pte_offset_from_ecpt_entry(entry, addr);
    } else if (gran == page_2MB) {
        pte_pointer = pmd_offset_from_ecpt_entry(entry, addr);
    } else if (gran == page_1GB) {
        pte_pointer = pud_offset_from_ecpt_entry(entry, addr);
    } else {
        assert(0);
    }
    return pte_pointer;
}

static int get_paddr_from_pte(uint64_t pte, hwaddr vaddr, enum Granularity gran, hwaddr * paddr) {
    uint64_t page_offset = 0;

    if (gran == page_4KB) {
        page_offset = ADDR_TO_OFFSET_4KB(vaddr);
        
    } else if (gran == page_2MB) {
        page_offset = ADDR_TO_OFFSET_2MB(vaddr);
        if (PTE_TO_PADDR(pte) != PTE_TO_PADDR_2MB(pte)) {
            warn_report("PTE wrong format pte=%lx\n", pte);
            return -1;
        }

    } else {
        /* gran == page_1GB */
        page_offset = ADDR_TO_OFFSET_1GB(vaddr);
        if (PTE_TO_PADDR(pte) != PTE_TO_PADDR_1GB(pte)) {
            warn_report("PTE wrong format pte=%lx\n", pte);
            return -1;
        }
    }
    
    *paddr = PTE_TO_PADDR(pte);
    *paddr += page_offset;

    return 0;
}

static bool duplicated_pte_tolerable(hwaddr vaddr, uint64_t old_pte,
                                     enum Granularity old_gran,
                                     uint64_t new_pte,
                                     enum Granularity new_gran) {
    hwaddr old_paddr = 0, new_paddr = 0;
    int res = 0;

    /* no duplication at all. unlikely this is true */
    if (ecpt_pte_is_empty(old_pte) || ecpt_pte_is_empty(new_pte)) {
        return true;
    }

    res = get_paddr_from_pte(old_pte, vaddr, old_gran, &old_paddr);
    if (res) {
        return false;
    }

    res = get_paddr_from_pte(new_pte, vaddr, new_gran, &new_paddr);
    if (res) {
        return false;
    }

    /* not tolerable if addr is different */
    if (old_paddr != new_paddr) {
        return false;
    }

    return true;
}

static uint64_t get_rehash_ptr(CPUX86State *env, int way)
{
    if (way < 0 || way > ECPT_TOTAL_WAY) {
        warn_report("get_rehash_ptr: Invalid way %d\n", way);
        return 0;
    }
    return env->ecpt_rehash_msr[way];
}

static inline void record_ecpt_leaf(MemRecord * rec, int w, hwaddr entry_addr)
{
    if (rec) {
        if (w < ECPT_KERNEL_WAY) {
            rec->leaves[w] = entry_addr;
        } else {
            rec->leaves[w - ECPT_KERNEL_WAY] = entry_addr;
        }
    }
}

static inline void record_cwt_visit(CPUState *cs, uint64_t vaddr, MemRecord * rec)
{
    cwt_entry_t matched_entries[CWT_TOTAL_N_WAY] = {0};
	uint32_t n_matched_entries = 0;

    if (rec) {
        n_matched_entries = cwt_lookup(cs, vaddr, CWT_2MB, &matched_entries[0], rec);
        if (n_matched_entries != 1) {
            warn_report("CWT entry not found for vaddr=%lx gran=%d\n", vaddr, CWT_2MB);
        }

        n_matched_entries = cwt_lookup(cs, vaddr, CWT_1GB, &matched_entries[0], rec);
        if (n_matched_entries != 1) {
            warn_report("CWT entry not found for vaddr=%lx gran=%d\n", vaddr, CWT_1GB);
        }
    }
}

static int mmu_translate_ECPT(CPUState *cs, hwaddr addr, MMUTranslateFunc get_hphys_func,
                         int is_write1, int mmu_idx, int pg_mode, int gdb,
                         hwaddr *xlat, int *page_size, int *prot, MemRecord * rec)
{
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;

    int error_code = 0;
    int is_dirty;
    int is_write = is_write1 & 1;
    int is_user = (mmu_idx == MMU_USER_IDX);
    uint64_t rsvd_mask = PG_ADDRESS_MASK & ~MAKE_64BIT_MASK(0, cpu->phys_bits);
    uint32_t page_offset;
    uint32_t pkr;
    hwaddr paddr;
    bool tolerable = false;
    /**
     * TODO: support more granularity
     */
    
    QEMU_LOG_TRANSLATE(gdb, CPU_LOG_MMU, "ECPT Translate: addr=%" VADDR_PRIx " eip=%lx w=%d mmu=%d\n",
           addr, env->eip, is_write1, mmu_idx);

    /**
     * TODO: 
     *  unclear meaning of a20_mask
     */
    int32_t a20_mask = x86_get_a20_mask(env);

    /**
     * @brief 
     * cr3 structure for now:
     *      51-12 bits base address for hash page table
     *      11-0 bits #of entries the hash page table can contain
     *      size of the page table obtained by 
     * 
     */
    int w, idx = 0;
    
    /* These are results from accessing all translation ways */
    uint64_t pte = 0;
    hwaddr entry_found_addr = 0, pte_addr = 0;
	int way_found = -1;
    enum Granularity gran_found;

	ecpt_entry_t entry;

    int possible_ways[ECPT_TOTAL_WAY];
    int n_ways = 0;
    bool new_way_filled = false;
    hit_info_t hit_res = {};

    // get_ECPT_ways(cs, addr, possible_ways, &n_ways);
    if (rec == NULL ) {
        /* run mode */
        hit_res = fill_from_cwc(cs, addr, possible_ways, &n_ways);
    } else {
        /* simulation mode */
        get_ECPT_full_ways_no_refill(cs, addr, possible_ways, &n_ways, hit_res);
        record_cwt_visit(cs, addr, rec);
    }
    
retry:

    pte = 0;
    entry_found_addr = 0; pte_addr = 0;
    way_found = -1;
    gran_found = page_4KB;
    for (idx = 0; idx < n_ways; idx++) 
    {
        uint64_t rehash_ptr = 0, rehash_way = 0, rehash_cr = 0, rehash_size = 0,
                 rehash_hash = 0;
        ecpt_entry_t * ecpt_base;
        uint64_t vpn = 0, size = 0, hash = 0, cr = 0 ;
        hwaddr entry_addr = 0;
        enum Granularity gran = page_4KB;

        w = possible_ways[idx];

        /* go through all the ways to search for matching tag  */
        /* In real hardware, this should be done in parallel */
        if (w < ECPT_4K_WAY) {
            gran = page_4KB;
            vpn = VADDR_TO_PAGE_NUM_4KB(addr); 
        } else if (w < ECPT_4K_WAY + ECPT_2M_WAY) {
            gran = page_2MB;
			vpn = VADDR_TO_PAGE_NUM_2MB(addr);
        } else if (w < ECPT_4K_WAY + ECPT_2M_WAY + ECPT_1G_WAY) {
            gran = page_1GB;
			vpn = VADDR_TO_PAGE_NUM_1GB(addr);
        } else if (w < ECPT_KERNEL_WAY + ECPT_4K_USER_WAY) {
            gran = page_4KB;
            vpn = VADDR_TO_PAGE_NUM_4KB(addr);  
        } else if (w < ECPT_KERNEL_WAY + ECPT_4K_USER_WAY + ECPT_2M_USER_WAY) {
            gran = page_2MB;
			vpn = VADDR_TO_PAGE_NUM_2MB(addr);
        } else if (w < ECPT_KERNEL_WAY + ECPT_4K_USER_WAY + ECPT_2M_USER_WAY + ECPT_1G_USER_WAY) {
            gran = page_1GB;
			vpn = VADDR_TO_PAGE_NUM_1GB(addr);
        } else {
            assert(0);
        }

		// cr = env->cr[way_to_crN[w]];
        cr = env->ecpt_msr[w];
		size = GET_HPT_SIZE(cr);

        if (!size) {
            /**
             *  this way is being constructed lazily,
             *      so we don't bother checking this way 
             */ 
            continue;
        }

		hash = gen_hash64(vpn, size, w);
		// QEMU_LOG_TRANSLATE(gdb, CPU_LOG_MMU, "    Translate: w=%d ECPT_TOTAL_WAY=%d hash=0x%lx vpn =0x%lx size=0x%lx\n",w, ECPT_TOTAL_WAY, hash, vpn, size);

        // rehash_ptr = GET_HPT_REHASH_PTR(cr);
        rehash_ptr = get_rehash_ptr(env, w);

        if (hash < rehash_ptr) {
            /* not supported for resizing now */
            rehash_way = find_rehash_way(w);
            // rehash_cr = env->cr[way_to_crN[rehash_way]];
            rehash_cr = env->ecpt_msr[rehash_way];
            rehash_size = GET_HPT_SIZE(rehash_cr);

            /* we use the original way's hash function now */
            /* TODO: change the hash function with size as seed */
            rehash_hash = gen_hash64(vpn, rehash_size, w);

            // qemu_log("    Translate: Elastic addr=%lx w=%d hash=0x%lx rehash_way=%ld rehash_hash=0x%lx vpn =0x%lx rehash_size=0x%lx \n",
            //     addr, w, hash, rehash_way, rehash_hash, vpn, rehash_size);

            // QEMU_LOG_TRANSLATE(gdb, CPU_LOG_MMU, "    Translate: Elastic rehash_way=%ld rehash_hash=0x%lx vpn =0x%lx rehash_size=0x%lx\n",
                // rehash_way, rehash_hash, vpn, rehash_size);

            ecpt_base = (ecpt_entry_t * ) GET_HPT_BASE(rehash_cr);
            entry_addr = (uint64_t) &ecpt_base[rehash_hash];

        } else {
            /* stay with current hash table */
            ecpt_base = (ecpt_entry_t * ) GET_HPT_BASE(cr);
            entry_addr = (uint64_t) &ecpt_base[hash];
        }
        
        // QEMU_LOG_TRANSLATE(gdb, CPU_LOG_MMU, "    Translate: load from 0x%016lx base at 0x%016lx\n", entry_addr, (uint64_t) ecpt_base);

         /* do nothing for now, cuz nested paging is not enabled */
        entry_addr = GET_HPHYS(cs, entry_addr, MMU_DATA_STORE, NULL);
        
        load_helper(cs, (void *) &entry, entry_addr, sizeof(ecpt_entry_t));
        record_ecpt_leaf(rec, w, entry_addr);
        // PRINT_ECPT_ENTRY((&entry));

        if (ecpt_entry_match_vpn(&entry, vpn)) {
            /* found */
            uint64_t * pte_pointer = entry_to_pte_pointer(&entry, addr, gran);
            
            if (!ecpt_pte_is_empty(*pte_pointer)) {
                /* either found pte or pte_pointer has to be empty */
                if (!(ecpt_pte_is_empty(pte))) {
                    tolerable = duplicated_pte_tolerable(addr, pte, gran_found, *pte_pointer, gran);
                    warn_report("Duplicated entry! pc=%lx addr=%lx way_found=%x entry_found_addr=%lx pte_addr=%lx pte=%lx"
                                " *pte_pointer=%lx cur_way=%x cur_entry_addr=%lx tolerable=%d\n",
                                env->eip, addr, way_found, entry_found_addr, pte_addr, pte,
                                *pte_pointer, w, entry_addr, tolerable);
                    
                    if (!tolerable) {
                        assert(0);
                    }

                    /* if tolerable  */
                    if (gran > gran_found) {
                        /* if the new entry has larger granularity, we use it to resolve duplication*/
                        /* fall through */
                    } else {
                        /* if the new entry has larger granularity, we don't pick it */
                        continue;
                    }
                }

                /* assign current  */
                /* we found a real matched entry */
                pte = *pte_pointer;

                if (gran == page_4KB) {
                    *page_size = PAGE_SIZE_4KB;
                } else if (gran == page_2MB) {
                    *page_size = PAGE_SIZE_2MB;
                } else if (gran == page_1GB) {
                    *page_size = PAGE_SIZE_1GB;
                } else {
                    assert(0);
                }

                way_found = w;
                entry_found_addr = entry_addr;
                pte_addr = get_pte_addr(entry_addr, &entry, pte_pointer);
                gran_found = gran;
            }
        }

	}

    if (entry_found_addr != 0) {

        QEMU_LOG_TRANSLATE(gdb, CPU_LOG_MMU, "ECPT Translate: load from entry at 0x%016lx pte at 0x%016lx pte=0x%016lx way=%d\n", 
            entry_found_addr, pte_addr, pte, way_found);

        if (way_found >= ECPT_TOTAL_WAY) {
            QEMU_LOG_TRANSLATE(gdb, CPU_LOG_MMU, "    ECPT Translate: Elastic load from entry at 0x%016lx pte at 0x%016lx pte=0x%016lx rehash_way=%d\n",
                entry_found_addr, pte_addr, pte, way_found);
        }

        if (rec) {
            if (way_found < ECPT_KERNEL_WAY) {
                rec->selected_ecpt_way = way_found;
            } else {
                rec->selected_ecpt_way = way_found - ECPT_KERNEL_WAY;
            }
        }

    } else {
        pte = 0;
        entry_found_addr = 0;
        pte_addr = 0;
        way_found = -1;

        /* Try to fix it with new ways */
        new_way_filled = get_ECPT_full_ways_with_refill(cs, addr, possible_ways, &n_ways, hit_res);
        if (new_way_filled){
            goto retry;
        }
        /* fall through This will lead to a page fault */
    }

    uint64_t ptep = PG_NX_MASK | PG_USER_MASK | PG_RW_MASK;
    ptep &= pte;
    
    if (!(pte & PG_PRESENT_MASK)) {
		QEMU_LOG_TRANSLATE(gdb, CPU_LOG_MMU, "    fault triggered. Page not Present!\n");
        goto do_fault;
    }
    
    /**
     * don't need these two symbols here since, we go to the following code if we are arriving at the leaf of the page table
     * 
     */
// do_check_protect:
    rsvd_mask |= (*page_size - 1) & PG_ADDRESS_MASK & ~PG_PSE_PAT_MASK;
// do_check_protect_pse36:
    if (pte & rsvd_mask) {
        goto do_fault_rsvd;
    }
    // ptep ^= PG_NX_MASK;

    /* can the page can be put in the TLB?  prot will tell us */
    if (is_user && !(ptep & PG_USER_MASK)) {
        QEMU_LOG_TRANSLATE(gdb, CPU_LOG_MMU, "    Checking prot is_user=%x !(ptep & PG_USER_MASK)=%x\n", is_user, !(ptep & PG_USER_MASK));
        goto do_fault_protect;
    }

    *prot = 0;
    if (mmu_idx != MMU_KSMAP_IDX || !(ptep & PG_USER_MASK)) {
        *prot |= PAGE_READ;
        if ((ptep & PG_RW_MASK) || !(is_user || (pg_mode & PG_MODE_WP))) {
            *prot |= PAGE_WRITE;
        }
    }
    if (!(ptep & PG_NX_MASK) &&
        (mmu_idx == MMU_USER_IDX ||
         !((pg_mode & PG_MODE_SMEP) && (ptep & PG_USER_MASK)))) {
        *prot |= PAGE_EXEC;
    }

    if (!(env->hflags & HF_LMA_MASK)) {
        pkr = 0;
    } else if (ptep & PG_USER_MASK) {
        pkr = pg_mode & PG_MODE_PKE ? env->pkru : 0;
    } else {
        pkr = pg_mode & PG_MODE_PKS ? env->pkrs : 0;
    }
    if (pkr) {
        uint32_t pk = (pte & PG_PKRU_MASK) >> PG_PKRU_BIT;
        uint32_t pkr_ad = (pkr >> pk * 2) & 1;
        uint32_t pkr_wd = (pkr >> pk * 2) & 2;
        uint32_t pkr_prot = PAGE_READ | PAGE_WRITE | PAGE_EXEC;

        if (pkr_ad) {
            pkr_prot &= ~(PAGE_READ | PAGE_WRITE);
        } else if (pkr_wd && (is_user || (pg_mode & PG_MODE_WP))) {
            pkr_prot &= ~PAGE_WRITE;
        }

        *prot &= pkr_prot;
        if ((pkr_prot & (1 << is_write1)) == 0) {
            assert(is_write1 != 2);
            error_code |= PG_ERROR_PK_MASK;
            goto do_fault_protect;
        }
    }

    if ((*prot & (1 << is_write1)) == 0) {
        QEMU_LOG_TRANSLATE(gdb, CPU_LOG_MMU, "    Checking prot *prot=%x \n", *prot);
        goto do_fault_protect;
    }

    /* yes, it can! */
    is_dirty = is_write && !(pte & PG_DIRTY_MASK);
    if (!(pte & PG_ACCESSED_MASK) || is_dirty) {
        pte |= PG_ACCESSED_MASK;
        if (is_dirty) {
            pte |= PG_DIRTY_MASK;
        }
        // hwaddr pte_addr = get_pte_addr(entry_addr, addr);
        QEMU_LOG_TRANSLATE(gdb, CPU_LOG_MMU, "    update dirty at %lx pte=%lx!\n", pte_addr, pte );
        x86_stl_phys_notdirty(cs, pte_addr, pte);
    }

    if (!(pte & PG_DIRTY_MASK)) {
        /* only set write access if already dirty... otherwise wait
           for dirty access */
        assert(!is_write);
        *prot &= ~PAGE_WRITE;
    }

    pte = pte & a20_mask;

    /* align to page_size */
    // pte &= PG_ADDRESS_MASK & ~(*page_size - 1);
    if (gran_found == page_4KB) {
        page_offset = ADDR_TO_OFFSET_4KB(addr);
        
    } else if (gran_found == page_2MB) {
        page_offset = ADDR_TO_OFFSET_2MB(addr);
        if (PTE_TO_PADDR(pte) != PTE_TO_PADDR_2MB(pte)) {
            goto do_fault_rsvd;
        }

    } else {
        /* gran == page_1GB */
        page_offset = ADDR_TO_OFFSET_1GB(addr);
        if (PTE_TO_PADDR(pte) != PTE_TO_PADDR_1GB(pte)) {
            goto do_fault_rsvd;
        }
    }
    
    paddr = PTE_TO_PADDR(pte);
    if (rec) {
        rec->pte = pte;
    }
    paddr += page_offset;
    // pte = pte & PG_ADDRESS_MASK;
    *xlat = GET_HPHYS(cs, paddr, is_write1, prot);
    if (rec) {
        rec->paddr = *xlat;
    }
    return PG_ERROR_OK;

 do_fault_rsvd:
    error_code |= PG_ERROR_RSVD_MASK;
 do_fault_protect:
    error_code |= PG_ERROR_P_MASK;
 do_fault:
    error_code |= (is_write << PG_ERROR_W_BIT);
    if (is_user)
        error_code |= PG_ERROR_U_MASK;
    if (is_write1 == 2 &&
        (((pg_mode & PG_MODE_NXE) && (pg_mode & PG_MODE_PAE)) ||
         (pg_mode & PG_MODE_SMEP)))
        error_code |= PG_ERROR_I_D_MASK;
    return error_code;
}


static int mmu_translate_2M_basic(CPUState *cs, hwaddr addr, MMUTranslateFunc get_hphys_func,
                         uint64_t cr3, int is_write1, int mmu_idx, int pg_mode, int gdb,
                         hwaddr *xlat, int *page_size, int *prot)
{
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;

    int error_code = 0;
    int is_dirty;
    int is_write = is_write1 & 1;
    int is_user = (mmu_idx == MMU_USER_IDX);
    uint64_t rsvd_mask = PG_ADDRESS_MASK & ~MAKE_64BIT_MASK(0, cpu->phys_bits);
    uint32_t page_offset;
    uint32_t pkr;
    hwaddr  paddr;
    // QEMU_LOG_TRANSLATE(gdb, CPU_LOG_MMU, "2M_basic Translate: addr=%" VADDR_PRIx " w=%d mmu=%d cr3=0x%016lx\n",
        //    addr, is_write1, mmu_idx, cr3);
    // printf("Translate: addr=%" VADDR_PRIx " w=%d mmu=%d cr3=0x%16lx\n",
        //    addr, is_write1, mmu_idx, cr3);

    /**
     * TODO: 
     *  unclear meaning of a20_mask
     */
    int32_t a20_mask = x86_get_a20_mask(env);

    /**
     * @brief 
     * cr3 structure for now:
     *      51-12 bits base address for hash page table
     *      11-0 bits #of entries the hash page table can contain
     *      size of the page table obtained by 
     * 
     *  TODO:
     *      translation only for 2MB right now
     */
    uint64_t size = GET_HPT_SIZE_OLD(cr3);
    uint64_t hash = gen_hash(VADDR_TO_PAGE_NUM_NO_CLUSTER_2MB(addr) , size);
    
    hwaddr pte_addr = GET_HPT_BASE(cr3)                /* page table base */
                            + (hash << 3);           /*  offset; */
	// QEMU_LOG_TRANSLATE(gdb, CPU_LOG_MMU, "    Translate: load from 0x%016lx\n", pte_addr);
    pte_addr = GET_HPHYS(cs, pte_addr, MMU_DATA_STORE, NULL);
    uint64_t pte = x86_ldq_phys(cs, pte_addr);


    QEMU_LOG_TRANSLATE(gdb, CPU_LOG_MMU, "2M_basic Translate: load from 0x%016lx pte=0x%016lx\n", pte_addr, pte);

    uint64_t ptep = PG_NX_MASK | PG_USER_MASK | PG_RW_MASK;
    ptep &= pte;
    *page_size = PAGE_SIZE_2MB;
    /*  */
    if (!(pte & PG_PRESENT_MASK)) {
		QEMU_LOG_TRANSLATE(gdb, CPU_LOG_MMU, "    fault triggered. Page not Present!\n");
        goto do_fault;
    }

/* TODO: fix legacy from paging's protection check */
    /**
     * don't need these two symbols here since, we go to the following code if we are arriving at the leaf of the page table
     * 
     */
// do_check_protect:
    rsvd_mask |= (*page_size - 1) & PG_ADDRESS_MASK & ~PG_PSE_PAT_MASK;
// do_check_protect_pse36:
    if (pte & rsvd_mask) {
        goto do_fault_rsvd;
    }
    // ptep ^= PG_NX_MASK;

    /* can the page can be put in the TLB?  prot will tell us */
    if (is_user && !(ptep & PG_USER_MASK)) {
        goto do_fault_protect;
    }

    *prot = 0;
    if (mmu_idx != MMU_KSMAP_IDX || !(ptep & PG_USER_MASK)) {
        *prot |= PAGE_READ;
        if ((ptep & PG_RW_MASK) || !(is_user || (pg_mode & PG_MODE_WP))) {
            *prot |= PAGE_WRITE;
        }
    }
    if (!(ptep & PG_NX_MASK) &&
        (mmu_idx == MMU_USER_IDX ||
         !((pg_mode & PG_MODE_SMEP) && (ptep & PG_USER_MASK)))) {
        *prot |= PAGE_EXEC;
    }

    if (!(env->hflags & HF_LMA_MASK)) {
        pkr = 0;
    } else if (ptep & PG_USER_MASK) {
        pkr = pg_mode & PG_MODE_PKE ? env->pkru : 0;
    } else {
        pkr = pg_mode & PG_MODE_PKS ? env->pkrs : 0;
    }
    if (pkr) {
        uint32_t pk = (pte & PG_PKRU_MASK) >> PG_PKRU_BIT;
        uint32_t pkr_ad = (pkr >> pk * 2) & 1;
        uint32_t pkr_wd = (pkr >> pk * 2) & 2;
        uint32_t pkr_prot = PAGE_READ | PAGE_WRITE | PAGE_EXEC;

        if (pkr_ad) {
            pkr_prot &= ~(PAGE_READ | PAGE_WRITE);
        } else if (pkr_wd && (is_user || (pg_mode & PG_MODE_WP))) {
            pkr_prot &= ~PAGE_WRITE;
        }

        *prot &= pkr_prot;
        if ((pkr_prot & (1 << is_write1)) == 0) {
            assert(is_write1 != 2);
            error_code |= PG_ERROR_PK_MASK;
            goto do_fault_protect;
        }
    }

    if ((*prot & (1 << is_write1)) == 0) {
        goto do_fault_protect;
    }

    /* yes, it can! */
    is_dirty = is_write && !(pte & PG_DIRTY_MASK);
    if (!(pte & PG_ACCESSED_MASK) || is_dirty) {
        pte |= PG_ACCESSED_MASK;
        if (is_dirty) {
            pte |= PG_DIRTY_MASK;
        }
        x86_stl_phys_notdirty(cs, pte_addr, pte);
    }

    if (!(pte & PG_DIRTY_MASK)) {
        /* only set write access if already dirty... otherwise wait
           for dirty access */
        assert(!is_write);
        *prot &= ~PAGE_WRITE;
    }

    pte = pte & a20_mask;

    /* align to page_size */
    // pte &= PG_ADDRESS_MASK & ~(*page_size - 1);
    page_offset = ADDR_TO_OFFSET_2MB(addr);
    // pte = SHIFT_TO_ADDR_2MB(ADDR_REMOVE_OFFSET_SHIFT_2MB(pte));
    // pte = pte & PG_ADDRESS_MASK;
    if (PTE_TO_PADDR(pte) != PTE_TO_PADDR_2MB(pte)) {
        goto do_fault_rsvd;
    }

    paddr = PTE_TO_PADDR(pte);
    paddr += page_offset;
    *xlat = GET_HPHYS(cs, paddr, is_write1, prot);
    return PG_ERROR_OK;

 do_fault_rsvd:
    error_code |= PG_ERROR_RSVD_MASK;
 do_fault_protect:
    error_code |= PG_ERROR_P_MASK;
 do_fault:
    error_code |= (is_write << PG_ERROR_W_BIT);
    if (is_user)
        error_code |= PG_ERROR_U_MASK;
    if (is_write1 == 2 &&
        (((pg_mode & PG_MODE_NXE) && (pg_mode & PG_MODE_PAE)) ||
         (pg_mode & PG_MODE_SMEP)))
        error_code |= PG_ERROR_I_D_MASK;
    return error_code;
}

static int mmu_translate(CPUState *cs, hwaddr addr, MMUTranslateFunc get_hphys_func,
                         uint64_t cr3, int is_write1, int mmu_idx, int pg_mode, int gdb,
                         hwaddr *xlat, int *page_size, int *prot) {

    // X86CPU *cpu = X86_CPU(cs);
    // CPUX86State *env = &cpu->env;

    // int after_transition = !!(env->cr[4] & CR4_ECPT_MASK);
    int after_transition = !!(cr3 & CR3_TRANSITION_BIT);

    if (after_transition) {
        return mmu_translate_ECPT(cs, addr, get_hphys_func, is_write1, mmu_idx, pg_mode, gdb, xlat, page_size, prot, NULL);
    } else {
        return mmu_translate_2M_basic(cs, addr, get_hphys_func, cr3, is_write1, mmu_idx, pg_mode, gdb, xlat, page_size, prot);
    }
}

// TODO: change this to the corresponding ECTP version
// schai. I believe this can reuse the mmu_translate_ECPT function 
__attribute__((unused))
static unsigned long mmu_translate_pgtables(CPUState *cs, hwaddr addr, MMUTranslateFunc get_hphys_func,
                                            uint64_t cr3,int mmu_idx, int pg_mode,
                                            unsigned long *pgd, unsigned long *pud, unsigned long *pmd,
                                            unsigned long *pte_table, unsigned int *size, unsigned long *entry) {
    return 0;
                                            }

#else

#define RADIX_LEVEL 4

struct radix_trans_info {
    uint64_t vaddr;
    uint64_t PTEs[RADIX_LEVEL];
    uint64_t paddr;
    uint64_t page_size;
};
#ifdef TARGET_X86_64_FPT
__attribute__((unused))
#endif
static void print_radix_info(struct radix_trans_info * info) {
    QEMU_LOG_TRANSLATE(0, CPU_LOG_MMU, "Radix Translate: vaddr=%lx PTE0=%lx PTE1=%lx PTE2=%lx PTE3=%lx paddr=%lx page_size=%lx\n", 
        info->vaddr, info->PTEs[0], info->PTEs[1], info->PTEs[2], info->PTEs[3], info->paddr, info->page_size);
}
#ifdef TARGET_X86_64_FPT
__attribute__((unused))
#endif
/* This is used for address translation dumping */
static unsigned long mmu_translate_pgtables(CPUState *cs, hwaddr addr, MMUTranslateFunc get_hphys_func,
                                            uint64_t cr3,int mmu_idx, int pg_mode,
                                            unsigned long *pgd, unsigned long *pud, unsigned long *pmd,
                                            unsigned long *pte_table, unsigned int *size, unsigned long *entry) {
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;
    target_ulong pde_addr, pte_addr;
    unsigned long pte;
    uint32_t page_offset;
    int page_size;
    int32_t a20_mask;
    unsigned long physaddr = ~(unsigned long) 0;

    a20_mask = x86_get_a20_mask(env);

    if (pg_mode & PG_MODE_PAE) {
        uint64_t pde, pdpe;
        target_ulong pdpe_addr;

        /* IA-32e mode only */
        if (env->hflags & HF_LMA_MASK) {
            bool la57 = pg_mode & PG_MODE_LA57;
            uint64_t pml5e;
            uint64_t pml4e_addr, pml4e;

           if(!la57) {
               pml5e = cr3;
           } else {
               printf("BUG: LA57 is on\n");
               exit(1);
           }

           pml4e_addr = ((pml5e & PG_ADDRESS_MASK) + (((addr >> 39) & 0x1ff) << 3)) &a20_mask;
           pml4e_addr = GET_HPHYS(cs, pml4e_addr, MMU_DATA_STORE, NULL);
           *pgd = pml4e_addr;
           pml4e = x86_ldq_phys(cs, pml4e_addr);
           pdpe_addr = ((pml4e & PG_ADDRESS_MASK) + (((addr >> 30) & 0x1ff) << 3)) & a20_mask;
           pdpe_addr = GET_HPHYS(cs, pdpe_addr, MMU_DATA_STORE, NULL);
           *pud = pdpe_addr;
           pdpe = x86_ldq_phys(cs, pdpe_addr);
           if (pdpe & PG_PSE_MASK) {
               /* 1 GB page */
               page_size = 1024 * 1024 * 1024;
               *size = page_size;
               pte = pdpe;
               *pmd = 0u;
               *pte_table = 0u;
               *entry = pdpe;
               goto calculate_phys;
           }
           pde_addr = ((pdpe & PG_ADDRESS_MASK) + (((addr >> 21) & 0x1ff) << 3)) & a20_mask;
           pde_addr = GET_HPHYS(cs, pde_addr, MMU_DATA_STORE, NULL);
           *pmd = pde_addr;
           pde = x86_ldq_phys(cs, pde_addr);
           if (pde & PG_PSE_MASK) {
               /* 2 MB page */
               page_size = 2048 * 1024;
               *size = page_size;
               pte = pde;
               *pte_table = 0u;
               *entry = pde;
               goto calculate_phys;
           }
           /* 4 KB page */
           pte_addr = ((pde & PG_ADDRESS_MASK) + (((addr >> 12) & 0x1ff) << 3)) & a20_mask;
           pte_addr = GET_HPHYS(cs, pte_addr, MMU_DATA_STORE, NULL);
           *pte_table = pte_addr;
           pte = x86_ldq_phys(cs, pte_addr);
           page_size = 4096;
           *size = page_size;
           *entry = pte;
           goto calculate_phys;
        } else {
            return physaddr;
        }
    } else {
        return physaddr;
    }

calculate_phys:
    pte = pte & a20_mask;
    /* align to page_size */
    pte &= PG_ADDRESS_MASK & ~(page_size - 1);
    page_offset = addr & (page_size - 1);
    physaddr = GET_HPHYS(cs, pte + page_offset, MMU_DATA_LOAD, NULL);

    return physaddr;
}


#ifdef TARGET_X86_64_FPT
__attribute__((unused))
#endif
static int mmu_translate_radix(CPUState *cs, hwaddr addr, MMUTranslateFunc get_hphys_func,
                         uint64_t cr3, int is_write1, int mmu_idx, int pg_mode, int gdb,
                         hwaddr *xlat, int *page_size, int *prot)
{
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;
    uint64_t ptep, pte;
    int32_t a20_mask;
    target_ulong pde_addr, pte_addr;
    int error_code = 0;
    int is_dirty, is_write, is_user;
    uint64_t rsvd_mask = PG_ADDRESS_MASK & ~MAKE_64BIT_MASK(0, cpu->phys_bits);
    uint32_t page_offset;
    uint32_t pkr;

    is_user = (mmu_idx == MMU_USER_IDX);
    is_write = is_write1 & 1;
    a20_mask = x86_get_a20_mask(env);


#ifdef TARGET_X86_64_RADIX_DUMP_TRANS_ADDR
    struct radix_trans_info walk_info;
    memset(&walk_info, 0, sizeof(struct radix_trans_info));
    walk_info.vaddr = addr;
    // QEMU_LOG_TRANSLATE(gdb, CPU_LOG_MMU, "Radix Translate: addr=%" VADDR_PRIx " w=%d mmu=%d\n", addr, is_write1, mmu_idx);
#endif

    if (!(pg_mode & PG_MODE_NXE)) {
        rsvd_mask |= PG_NX_MASK;
    }

    if (pg_mode & PG_MODE_PAE) {
        uint64_t pde, pdpe;
        target_ulong pdpe_addr;

#ifdef TARGET_X86_64
        if (env->hflags & HF_LMA_MASK) {
            bool la57 = pg_mode & PG_MODE_LA57;
            uint64_t pml5e_addr, pml5e;
            uint64_t pml4e_addr, pml4e;
            int32_t sext;

            /* test virtual address sign extension */
            sext = la57 ? (int64_t)addr >> 56 : (int64_t)addr >> 47;
            if (get_hphys_func && sext != 0 && sext != -1) {
                env->error_code = 0;
                cs->exception_index = EXCP0D_GPF;
                return 1;
            }

            if (la57) {
                pml5e_addr = ((cr3 & ~0xfff) +
                        (((addr >> 48) & 0x1ff) << 3)) & a20_mask;
                pml5e_addr = GET_HPHYS(cs, pml5e_addr, MMU_DATA_STORE, NULL);

// #ifdef TARGET_X86_64_RADIX_DUMP_TRANS_ADDR
//                 // QEMU_LOG_TRANSLATE(gdb, CPU_LOG_MMU, "PML5E: addr=%" VADDR_PRIx "\n", pml5e_addr);
// #endif
                pml5e = x86_ldq_phys(cs, pml5e_addr);
                if (!(pml5e & PG_PRESENT_MASK)) {
                    goto do_fault;
                }
                if (pml5e & (rsvd_mask | PG_PSE_MASK)) {
                    goto do_fault_rsvd;
                }
                if (!(pml5e & PG_ACCESSED_MASK)) {
                    pml5e |= PG_ACCESSED_MASK;
                    x86_stl_phys_notdirty(cs, pml5e_addr, pml5e);
                }
                ptep = pml5e ^ PG_NX_MASK;
            } else {
                pml5e = cr3;
                ptep = PG_NX_MASK | PG_USER_MASK | PG_RW_MASK;
            }

            pml4e_addr = ((pml5e & PG_ADDRESS_MASK) +
                    (((addr >> 39) & 0x1ff) << 3)) & a20_mask;
            pml4e_addr = GET_HPHYS(cs, pml4e_addr, MMU_DATA_STORE, NULL);

#ifdef TARGET_X86_64_RADIX_DUMP_TRANS_ADDR
            walk_info.PTEs[0] = pml4e_addr;
            // QEMU_LOG_TRANSLATE(gdb, CPU_LOG_MMU, "PML4E: addr=%" VADDR_PRIx "\n", pml4e_addr);
#endif
            pml4e = x86_ldq_phys(cs, pml4e_addr);
            if (!(pml4e & PG_PRESENT_MASK)) {
                goto do_fault;
            }
            if (pml4e & (rsvd_mask | PG_PSE_MASK)) {
                goto do_fault_rsvd;
            }
            if (!(pml4e & PG_ACCESSED_MASK)) {
                pml4e |= PG_ACCESSED_MASK;
                x86_stl_phys_notdirty(cs, pml4e_addr, pml4e);
            }
            ptep &= pml4e ^ PG_NX_MASK;
            pdpe_addr = ((pml4e & PG_ADDRESS_MASK) + (((addr >> 30) & 0x1ff) << 3)) &
                a20_mask;
            pdpe_addr = GET_HPHYS(cs, pdpe_addr, MMU_DATA_STORE, NULL);
            pdpe = x86_ldq_phys(cs, pdpe_addr);
            if (!(pdpe & PG_PRESENT_MASK)) {
                goto do_fault;
            }
            if (pdpe & rsvd_mask) {
                goto do_fault_rsvd;
            }
            ptep &= pdpe ^ PG_NX_MASK;
            if (!(pdpe & PG_ACCESSED_MASK)) {
                pdpe |= PG_ACCESSED_MASK;
                x86_stl_phys_notdirty(cs, pdpe_addr, pdpe);
            }
            if (pdpe & PG_PSE_MASK) {
                /* 1 GB page */
                *page_size = 1024 * 1024 * 1024;
                pte_addr = pdpe_addr;
                pte = pdpe;
                goto do_check_protect;
            }
        } else
#endif
        {
            /* XXX: load them when cr3 is loaded ? */
            pdpe_addr = ((cr3 & ~0x1f) + ((addr >> 27) & 0x18)) &
                a20_mask;
            pdpe_addr = GET_HPHYS(cs, pdpe_addr, MMU_DATA_STORE, NULL);
            pdpe = x86_ldq_phys(cs, pdpe_addr);
            if (!(pdpe & PG_PRESENT_MASK)) {
                goto do_fault;
            }
            rsvd_mask |= PG_HI_USER_MASK;
            if (pdpe & (rsvd_mask | PG_NX_MASK)) {
                goto do_fault_rsvd;
            }
            ptep = PG_NX_MASK | PG_USER_MASK | PG_RW_MASK;
        }

#ifdef TARGET_X86_64_RADIX_DUMP_TRANS_ADDR
        walk_info.PTEs[1] = pdpe_addr;
        // QEMU_LOG_TRANSLATE(gdb, CPU_LOG_MMU, "PDPE: addr=%" VADDR_PRIx "\n", pdpe_addr);
#endif
        pde_addr = ((pdpe & PG_ADDRESS_MASK) + (((addr >> 21) & 0x1ff) << 3)) &
            a20_mask;
        pde_addr = GET_HPHYS(cs, pde_addr, MMU_DATA_STORE, NULL);

#ifdef TARGET_X86_64_RADIX_DUMP_TRANS_ADDR
        walk_info.PTEs[2] = pde_addr;
        // QEMU_LOG_TRANSLATE(gdb, CPU_LOG_MMU, "PDE: addr=%" VADDR_PRIx "\n", pde_addr);
#endif
        pde = x86_ldq_phys(cs, pde_addr);

        if (!(pde & PG_PRESENT_MASK)) {
            goto do_fault;
        }
        if (pde & rsvd_mask) {
            goto do_fault_rsvd;
        }
        ptep &= pde ^ PG_NX_MASK;
        if (pde & PG_PSE_MASK) {
            /* 2 MB page */
            *page_size = 2048 * 1024;
            pte_addr = pde_addr;
            pte = pde;
            goto do_check_protect;
        }
        /* 4 KB page */
        if (!(pde & PG_ACCESSED_MASK)) {
            pde |= PG_ACCESSED_MASK;
            x86_stl_phys_notdirty(cs, pde_addr, pde);
        }
        pte_addr = ((pde & PG_ADDRESS_MASK) + (((addr >> 12) & 0x1ff) << 3)) &
            a20_mask;
        pte_addr = GET_HPHYS(cs, pte_addr, MMU_DATA_STORE, NULL);
        
#ifdef TARGET_X86_64_RADIX_DUMP_TRANS_ADDR
        walk_info.PTEs[3] = pte_addr;
        QEMU_LOG_TRANSLATE(gdb, CPU_LOG_MMU, "PTE: addr=%" VADDR_PRIx "\n", pdpe_addr);
#endif
        pte = x86_ldq_phys(cs, pte_addr);


        if (!(pte & PG_PRESENT_MASK)) {
            goto do_fault;
        }
        if (pte & rsvd_mask) {
            goto do_fault_rsvd;
        }
        /* combine pde and pte nx, user and rw protections */

        /* pte[63] -> if page non executable */
        /* ptep[63] -> if page executable */
        /* A page is executable only if ALL of its parent page entries has NX bit as 0 */
        /* the logic is reversed here to simplify the AND logic */

        ptep &= pte ^ PG_NX_MASK;
        
        
        *page_size = 4096;
    } else {
        uint32_t pde;

        /* page directory entry */
        pde_addr = ((cr3 & ~0xfff) + ((addr >> 20) & 0xffc)) &
            a20_mask;
        pde_addr = GET_HPHYS(cs, pde_addr, MMU_DATA_STORE, NULL);
        pde = x86_ldl_phys(cs, pde_addr);
        if (!(pde & PG_PRESENT_MASK)) {
            goto do_fault;
        }
        ptep = pde | PG_NX_MASK;

        /* if PSE bit is set, then we use a 4MB page */
        if ((pde & PG_PSE_MASK) && (pg_mode & PG_MODE_PSE)) {
            *page_size = 4096 * 1024;
            pte_addr = pde_addr;

            /* Bits 20-13 provide bits 39-32 of the address, bit 21 is reserved.
             * Leave bits 20-13 in place for setting accessed/dirty bits below.
             */
            pte = pde | ((pde & 0x1fe000LL) << (32 - 13));
            rsvd_mask = 0x200000;
            goto do_check_protect_pse36;
        }

        if (!(pde & PG_ACCESSED_MASK)) {
            pde |= PG_ACCESSED_MASK;
            x86_stl_phys_notdirty(cs, pde_addr, pde);
        }

        /* page directory entry */
        pte_addr = ((pde & ~0xfff) + ((addr >> 10) & 0xffc)) &
            a20_mask;
        pte_addr = GET_HPHYS(cs, pte_addr, MMU_DATA_STORE, NULL);
        pte = x86_ldl_phys(cs, pte_addr);
        if (!(pte & PG_PRESENT_MASK)) {
            goto do_fault;
        }
        /* combine pde and pte user and rw protections */
        ptep &= pte | PG_NX_MASK;
        *page_size = 4096;
        rsvd_mask = 0;
    }

do_check_protect:
    rsvd_mask |= (*page_size - 1) & PG_ADDRESS_MASK & ~PG_PSE_PAT_MASK;
do_check_protect_pse36:
    if (pte & rsvd_mask) {
        goto do_fault_rsvd;
    }
    ptep ^= PG_NX_MASK;

    /* can the page can be put in the TLB?  prot will tell us */
    if (is_user && !(ptep & PG_USER_MASK)) {
        goto do_fault_protect;
    }

    *prot = 0;
    if (mmu_idx != MMU_KSMAP_IDX || !(ptep & PG_USER_MASK)) {
        *prot |= PAGE_READ;
        if ((ptep & PG_RW_MASK) || !(is_user || (pg_mode & PG_MODE_WP))) {
            *prot |= PAGE_WRITE;
        }
    }
    if (!(ptep & PG_NX_MASK) &&
        (mmu_idx == MMU_USER_IDX ||
         !((pg_mode & PG_MODE_SMEP) && (ptep & PG_USER_MASK)))) {
        *prot |= PAGE_EXEC;
    }

    if (!(env->hflags & HF_LMA_MASK)) {
        pkr = 0;
    } else if (ptep & PG_USER_MASK) {
        pkr = pg_mode & PG_MODE_PKE ? env->pkru : 0;
    } else {
        pkr = pg_mode & PG_MODE_PKS ? env->pkrs : 0;
    }
    if (pkr) {
        uint32_t pk = (pte & PG_PKRU_MASK) >> PG_PKRU_BIT;
        uint32_t pkr_ad = (pkr >> pk * 2) & 1;
        uint32_t pkr_wd = (pkr >> pk * 2) & 2;
        uint32_t pkr_prot = PAGE_READ | PAGE_WRITE | PAGE_EXEC;

        if (pkr_ad) {
            pkr_prot &= ~(PAGE_READ | PAGE_WRITE);
        } else if (pkr_wd && (is_user || (pg_mode & PG_MODE_WP))) {
            pkr_prot &= ~PAGE_WRITE;
        }

        *prot &= pkr_prot;
        if ((pkr_prot & (1 << is_write1)) == 0) {
            assert(is_write1 != 2);
            error_code |= PG_ERROR_PK_MASK;
            goto do_fault_protect;
        }
    }

    if ((*prot & (1 << is_write1)) == 0) {
        goto do_fault_protect;
    }

    /* yes, it can! */
    is_dirty = is_write && !(pte & PG_DIRTY_MASK);
    if (!(pte & PG_ACCESSED_MASK) || is_dirty) {
        pte |= PG_ACCESSED_MASK;
        if (is_dirty) {
            pte |= PG_DIRTY_MASK;
        }
        x86_stl_phys_notdirty(cs, pte_addr, pte);
    }

    if (!(pte & PG_DIRTY_MASK)) {
        /* only set write access if already dirty... otherwise wait
           for dirty access */
        assert(!is_write);
        *prot &= ~PAGE_WRITE;
    }

    pte = pte & a20_mask;

    /* align to page_size */
    pte &= PG_ADDRESS_MASK & ~(*page_size - 1);
    page_offset = addr & (*page_size - 1);
    *xlat = GET_HPHYS(cs, pte + page_offset, is_write1, prot);
#ifdef TARGET_X86_64_RADIX_DUMP_TRANS_ADDR
    walk_info.paddr = *xlat;
    walk_info.page_size = *page_size;
    print_radix_info(&walk_info);
#endif
    return PG_ERROR_OK;

 do_fault_rsvd:
    error_code |= PG_ERROR_RSVD_MASK;
 do_fault_protect:
    error_code |= PG_ERROR_P_MASK;
 do_fault:
    error_code |= (is_write << PG_ERROR_W_BIT);
    if (is_user)
        error_code |= PG_ERROR_U_MASK;
    if (is_write1 == 2 &&
        (((pg_mode & PG_MODE_NXE) && (pg_mode & PG_MODE_PAE)) ||
         (pg_mode & PG_MODE_SMEP)))
        error_code |= PG_ERROR_I_D_MASK;

#ifdef TARGET_X86_64_RADIX_DUMP_TRANS_ADDR
    walk_info.paddr = *xlat;
    print_radix_info(&walk_info);
#endif
    return error_code;
}

#ifdef TARGET_X86_64_FPT

static inline unsigned long acquire_pgtable_index(unsigned long address,
						  uint32_t shift,
						  uint32_t ptrs_per_entry)
{
	return (address >> shift) & (ptrs_per_entry - 1);
}


static inline uint64_t get_pdpe_addr_flat(uint64_t parent, uint64_t addr, int32_t a20_mask) {
    uint64_t index = acquire_pgtable_index(addr, PAGE_SHIFT_1GB, 512 * 512);
    return ((parent & PG_ADDRESS_MASK) + (index << 3)) & a20_mask;
}

static inline uint64_t get_pde_addr_flat(uint64_t parent, uint64_t addr, int32_t a20_mask) {
    uint64_t index = acquire_pgtable_index(addr, PAGE_SHIFT_2MB, 512 * 512);
    return ((parent & PG_ADDRESS_MASK) + (index << 3)) & a20_mask;
}

static inline uint64_t get_pte_addr_flat(uint64_t parent, uint64_t addr, int32_t a20_mask) {
    uint64_t index = acquire_pgtable_index(addr, PAGE_SHIFT_4KB, 512 * 512);
    return ((parent & PG_ADDRESS_MASK) + (index << 3)) & a20_mask;
}


static void print_radix_record(MemRecord * record)
{
    // QEMU_LOG_TRANSLATE(0, CPU_LOG_MMU, "Radix Translate: vaddr=%lx PTE0=%lx PTE1=%lx PTE2=%lx PTE3=%lx paddr=%lx\n", 
    //     record->vaddr, record->leaves[0], record->leaves[1], record->leaves[2], record->leaves[3], record->paddr);

    // printf( "Radix Translate: vaddr=%lx PTE0=%lx PTE1=%lx PTE2=%lx PTE3=%lx pte=%lx paddr=%lx\n", 
        // record->vaddr, record->leaves[0], record->leaves[1], record->leaves[2], record->leaves[3], record->pte, record->paddr);
}


static int mmu_translate_fpt(CPUState *cs, hwaddr addr, MMUTranslateFunc get_hphys_func,
                         uint64_t cr3, int is_write1, int mmu_idx, int pg_mode, int gdb,
                         hwaddr *xlat, int *page_size, int *prot, MemRecord * rec)
{
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;
    uint64_t ptep, pte;
    int32_t a20_mask;
    target_ulong pde_addr, pte_addr;
    int error_code = 0;
    int is_dirty, is_write, is_user;
    uint64_t rsvd_mask = PG_ADDRESS_MASK & ~MAKE_64BIT_MASK(0, cpu->phys_bits);
    uint32_t page_offset;
    uint32_t pkr;

    is_user = (mmu_idx == MMU_USER_IDX);
    is_write = is_write1 & 1;
    a20_mask = x86_get_a20_mask(env);

    __attribute__((unused)) int level_folded = 0;
    if (rec != NULL) {
        /* TODO: remove after finish debugging */
        rec->vaddr = addr;
    }

    if (!(pg_mode & PG_MODE_NXE)) {
        rsvd_mask |= PG_NX_MASK;
    }

    if (pg_mode & PG_MODE_PAE) {
        uint64_t pde, pdpe;
        target_ulong pdpe_addr;

#ifdef TARGET_X86_64
        if (env->hflags & HF_LMA_MASK) {
            bool la57 = pg_mode & PG_MODE_LA57;
            uint64_t pml5e_addr, pml5e;
            uint64_t pml4e_addr, pml4e;
            int32_t sext;

            /* test virtual address sign extension */
            sext = la57 ? (int64_t)addr >> 56 : (int64_t)addr >> 47;
            if (get_hphys_func && sext != 0 && sext != -1) {
                env->error_code = 0;
                cs->exception_index = EXCP0D_GPF;
                return 1;
            }

            if (la57) {
                pml5e_addr = ((cr3 & ~0xfff) +
                        (((addr >> 48) & 0x1ff) << 3)) & a20_mask;
                pml5e_addr = GET_HPHYS(cs, pml5e_addr, MMU_DATA_STORE, NULL);

                pml5e = x86_ldq_phys(cs, pml5e_addr);
                if (!(pml5e & PG_PRESENT_MASK)) {
                    goto do_fault;
                }
                if (pml5e & (rsvd_mask | PG_PSE_MASK)) {
                    goto do_fault_rsvd;
                }
                if (!(pml5e & PG_ACCESSED_MASK)) {
                    pml5e |= PG_ACCESSED_MASK;
                    x86_stl_phys_notdirty(cs, pml5e_addr, pml5e);
                }
                ptep = pml5e ^ PG_NX_MASK;
            } else {
                pml5e = cr3;
                ptep = PG_NX_MASK | PG_USER_MASK | PG_RW_MASK;
            }
            // printf("pml5e=%016lx\n", pml5e);
            if (L4_L3_IS_FOLDED(pml5e)) {
                
                level_folded = 1;
                pdpe_addr = get_pdpe_addr_flat(pml5e, addr, a20_mask);
                QEMU_LOG_TRANSLATE(gdb, CPU_LOG_MMU, "FPT Translate (L4+L3 folded): addr=%016lx pml5e_addr=%016lx pml5e=%016lx pdpe_addr=%016lx\n",
                    addr, pml5e_addr, pml5e, pdpe_addr);
                goto pdpe_addr_ready;
            }

            pml4e_addr = ((pml5e & PG_ADDRESS_MASK) +
                    (((addr >> 39) & 0x1ff) << 3)) & a20_mask;
            pml4e_addr = GET_HPHYS(cs, pml4e_addr, MMU_DATA_STORE, NULL);
            
            if (rec != NULL) {
                rec->leaves[0] = pml4e_addr;
            }
            // record.leaves[0] = pml4e_addr;

            pml4e = x86_ldq_phys(cs, pml4e_addr);
            if (!(pml4e & PG_PRESENT_MASK)) {
                goto do_fault;
            }
            if (pml4e & (rsvd_mask | PG_PSE_MASK)) {
                goto do_fault_rsvd;
            }
            if (!(pml4e & PG_ACCESSED_MASK)) {
                pml4e |= PG_ACCESSED_MASK;
                x86_stl_phys_notdirty(cs, pml4e_addr, pml4e);
            }
            ptep &= pml4e ^ PG_NX_MASK;


            if (NEXT_LEVEL_IS_FOLDED(pml4e)) {
                QEMU_LOG_TRANSLATE(gdb, CPU_LOG_MMU, "FPT Translate (L3+L2 folded): addr=%016lx pdpe_addr=%016lx pdpe=%016lx\n",
                    addr, pml4e_addr, pml4e);
                
                level_folded = 2;
                pde_addr = get_pde_addr_flat(pml4e, addr, a20_mask);
                goto pde_addr_ready;
            }

            pdpe_addr = ((pml4e & PG_ADDRESS_MASK) + (((addr >> 30) & 0x1ff) << 3)) &
                a20_mask;

pdpe_addr_ready:
            pdpe_addr = GET_HPHYS(cs, pdpe_addr, MMU_DATA_STORE, NULL);
            if (rec != NULL) {
                rec->leaves[1] = pdpe_addr;
            }
            // record.leaves[1] = pdpe_addr;

            pdpe = x86_ldq_phys(cs, pdpe_addr);
            if (!(pdpe & PG_PRESENT_MASK)) {
                goto do_fault;
            }
            if (pdpe & rsvd_mask) {
                goto do_fault_rsvd;
            }
            ptep &= pdpe ^ PG_NX_MASK;
            if (!(pdpe & PG_ACCESSED_MASK)) {
                pdpe |= PG_ACCESSED_MASK;
                x86_stl_phys_notdirty(cs, pdpe_addr, pdpe);
            }
            if (pdpe & PG_PSE_MASK) {
                /* 1 GB page */
                *page_size = 1024 * 1024 * 1024;
                pte_addr = pdpe_addr;
                pte = pdpe;
                goto do_check_protect;
            }
        } else
#endif
        {
            /* XXX: load them when cr3 is loaded ? */
            pdpe_addr = ((cr3 & ~0x1f) + ((addr >> 27) & 0x18)) &
                a20_mask;
            pdpe_addr = GET_HPHYS(cs, pdpe_addr, MMU_DATA_STORE, NULL);
            pdpe = x86_ldq_phys(cs, pdpe_addr);
            if (!(pdpe & PG_PRESENT_MASK)) {
                goto do_fault;
            }
            rsvd_mask |= PG_HI_USER_MASK;
            if (pdpe & (rsvd_mask | PG_NX_MASK)) {
                goto do_fault_rsvd;
            }
            ptep = PG_NX_MASK | PG_USER_MASK | PG_RW_MASK;
        }

        if (NEXT_LEVEL_IS_FOLDED(pdpe)) {
            level_folded = 3;
            pte_addr = get_pte_addr_flat(pdpe, addr, a20_mask);
            QEMU_LOG_TRANSLATE(gdb, CPU_LOG_MMU, "FPT Translate (L2+L1 folded): addr=%lx pdpe_addr=%lx pdpe=%lx pte_addr=%lx\n",
                addr, pdpe_addr, pdpe, pte_addr);
            goto pte_addr_ready;
        }

        pde_addr = ((pdpe & PG_ADDRESS_MASK) + (((addr >> 21) & 0x1ff) << 3)) &
            a20_mask;

pde_addr_ready:
        pde_addr = GET_HPHYS(cs, pde_addr, MMU_DATA_STORE, NULL);
        if (rec != NULL) {
            rec->leaves[2] = pde_addr;
        }    
        pde = x86_ldq_phys(cs, pde_addr);

        if (!(pde & PG_PRESENT_MASK)) {
            goto do_fault;
        }
        if (pde & rsvd_mask) {
            goto do_fault_rsvd;
        }
        ptep &= pde ^ PG_NX_MASK;
        if (pde & PG_PSE_MASK) {
            /* 2 MB page */
            *page_size = 2048 * 1024;
            pte_addr = pde_addr;
            pte = pde;
            goto do_check_protect;
        }
        /* 4 KB page */
        if (!(pde & PG_ACCESSED_MASK)) {
            pde |= PG_ACCESSED_MASK;
            x86_stl_phys_notdirty(cs, pde_addr, pde);
        }
        pte_addr = ((pde & PG_ADDRESS_MASK) + (((addr >> 12) & 0x1ff) << 3)) &
            a20_mask;
        
pte_addr_ready:        
        pte_addr = GET_HPHYS(cs, pte_addr, MMU_DATA_STORE, NULL);
        if (rec != NULL) {
            rec->leaves[3] = pte_addr;
        }
        pte = x86_ldq_phys(cs, pte_addr);


        if (!(pte & PG_PRESENT_MASK)) {
            goto do_fault;
        }
        if (pte & rsvd_mask) {
            goto do_fault_rsvd;
        }
        /* combine pde and pte nx, user and rw protections */

        /* pte[63] -> if page non executable */
        /* ptep[63] -> if page executable */
        /* A page is executable only if ALL of its parent page entries has NX bit as 0 */
        /* the logic is reversed here to simplify the AND logic */

        ptep &= pte ^ PG_NX_MASK;
        
        
        *page_size = 4096;
    } else {
        uint32_t pde;

        /* page directory entry */
        pde_addr = ((cr3 & ~0xfff) + ((addr >> 20) & 0xffc)) &
            a20_mask;
        pde_addr = GET_HPHYS(cs, pde_addr, MMU_DATA_STORE, NULL);
        pde = x86_ldl_phys(cs, pde_addr);
        if (!(pde & PG_PRESENT_MASK)) {
            goto do_fault;
        }
        ptep = pde | PG_NX_MASK;

        /* if PSE bit is set, then we use a 4MB page */
        if ((pde & PG_PSE_MASK) && (pg_mode & PG_MODE_PSE)) {
            *page_size = 4096 * 1024;
            pte_addr = pde_addr;

            /* Bits 20-13 provide bits 39-32 of the address, bit 21 is reserved.
             * Leave bits 20-13 in place for setting accessed/dirty bits below.
             */
            pte = pde | ((pde & 0x1fe000LL) << (32 - 13));
            rsvd_mask = 0x200000;
            goto do_check_protect_pse36;
        }

        if (!(pde & PG_ACCESSED_MASK)) {
            pde |= PG_ACCESSED_MASK;
            x86_stl_phys_notdirty(cs, pde_addr, pde);
        }

        /* page directory entry */
        pte_addr = ((pde & ~0xfff) + ((addr >> 10) & 0xffc)) &
            a20_mask;
        pte_addr = GET_HPHYS(cs, pte_addr, MMU_DATA_STORE, NULL);
        pte = x86_ldl_phys(cs, pte_addr);
        if (!(pte & PG_PRESENT_MASK)) {
            goto do_fault;
        }
        /* combine pde and pte user and rw protections */
        ptep &= pte | PG_NX_MASK;
        *page_size = 4096;
        rsvd_mask = 0;
    }

do_check_protect:
    rsvd_mask |= (*page_size - 1) & PG_ADDRESS_MASK & ~PG_PSE_PAT_MASK;
do_check_protect_pse36:
    if (pte & rsvd_mask) {
        goto do_fault_rsvd;
    }
    ptep ^= PG_NX_MASK;

    /* can the page can be put in the TLB?  prot will tell us */
    if (is_user && !(ptep & PG_USER_MASK)) {
        goto do_fault_protect;
    }

    *prot = 0;
    if (mmu_idx != MMU_KSMAP_IDX || !(ptep & PG_USER_MASK)) {
        *prot |= PAGE_READ;
        if ((ptep & PG_RW_MASK) || !(is_user || (pg_mode & PG_MODE_WP))) {
            *prot |= PAGE_WRITE;
        }
    }
    if (!(ptep & PG_NX_MASK) &&
        (mmu_idx == MMU_USER_IDX ||
         !((pg_mode & PG_MODE_SMEP) && (ptep & PG_USER_MASK)))) {
        *prot |= PAGE_EXEC;
    }

    if (!(env->hflags & HF_LMA_MASK)) {
        pkr = 0;
    } else if (ptep & PG_USER_MASK) {
        pkr = pg_mode & PG_MODE_PKE ? env->pkru : 0;
    } else {
        pkr = pg_mode & PG_MODE_PKS ? env->pkrs : 0;
    }
    if (pkr) {
        uint32_t pk = (pte & PG_PKRU_MASK) >> PG_PKRU_BIT;
        uint32_t pkr_ad = (pkr >> pk * 2) & 1;
        uint32_t pkr_wd = (pkr >> pk * 2) & 2;
        uint32_t pkr_prot = PAGE_READ | PAGE_WRITE | PAGE_EXEC;

        if (pkr_ad) {
            pkr_prot &= ~(PAGE_READ | PAGE_WRITE);
        } else if (pkr_wd && (is_user || (pg_mode & PG_MODE_WP))) {
            pkr_prot &= ~PAGE_WRITE;
        }

        *prot &= pkr_prot;
        if ((pkr_prot & (1 << is_write1)) == 0) {
            assert(is_write1 != 2);
            error_code |= PG_ERROR_PK_MASK;
            goto do_fault_protect;
        }
    }

    if ((*prot & (1 << is_write1)) == 0) {
        goto do_fault_protect;
    }

    /* yes, it can! */
    is_dirty = is_write && !(pte & PG_DIRTY_MASK);
    if (!(pte & PG_ACCESSED_MASK) || is_dirty) {
        pte |= PG_ACCESSED_MASK;
        if (is_dirty) {
            pte |= PG_DIRTY_MASK;
        }
        x86_stl_phys_notdirty(cs, pte_addr, pte);
    }

    if (!(pte & PG_DIRTY_MASK)) {
        /* only set write access if already dirty... otherwise wait
           for dirty access */
        assert(!is_write);
        *prot &= ~PAGE_WRITE;
    }

    pte = pte & a20_mask;

    /* align to page_size */
    pte &= PG_ADDRESS_MASK & ~(*page_size - 1);
    page_offset = addr & (*page_size - 1);
    *xlat = GET_HPHYS(cs, pte + page_offset, is_write1, prot);

    // record.paddr = *xlat;
    // record.pte = pte;
    if (rec != NULL) {
        rec->paddr = *xlat;
        rec->pte = pte;
    }

    if (level_folded && rec != NULL) {
        print_radix_record(rec);
    }

    return PG_ERROR_OK;

 do_fault_rsvd:
    error_code |= PG_ERROR_RSVD_MASK;
 do_fault_protect:
    error_code |= PG_ERROR_P_MASK;
 do_fault:
    error_code |= (is_write << PG_ERROR_W_BIT);
    if (is_user)
        error_code |= PG_ERROR_U_MASK;
    if (is_write1 == 2 &&
        (((pg_mode & PG_MODE_NXE) && (pg_mode & PG_MODE_PAE)) ||
         (pg_mode & PG_MODE_SMEP)))
        error_code |= PG_ERROR_I_D_MASK;
    // if (level_folded) {
    //     print_radix_record(&record);
    // }
    return error_code;
}


#endif

static int mmu_translate(CPUState *cs, hwaddr addr, MMUTranslateFunc get_hphys_func,
                         uint64_t cr3, int is_write1, int mmu_idx, int pg_mode, int gdb,
                         hwaddr *xlat, int *page_size, int *prot) {

#ifdef TARGET_X86_64_FPT
    // MemRecord record = {0};                 
    // return mmu_translate_fpt(cs, addr, get_hphys_func, cr3, is_write1, mmu_idx, pg_mode, gdb, xlat, page_size, prot, &record);

    return mmu_translate_fpt(cs, addr, get_hphys_func, cr3, is_write1, mmu_idx, pg_mode, gdb, xlat, page_size, prot, NULL);
#else 
    return mmu_translate_radix(cs, addr, get_hphys_func, cr3, is_write1, mmu_idx, pg_mode, gdb, xlat, page_size, prot);
#endif

}


#endif

hwaddr get_hphys(CPUState *cs, hwaddr gphys, MMUAccessType access_type,
                        int *prot)
{
    CPUX86State *env = &X86_CPU(cs)->env;
    uint64_t exit_info_1;
    int page_size;
    int next_prot;
    hwaddr hphys;

	// qemu_log_mask(CPU_LOG_MMU, "\tNested Paging turned on=%d\n",
    //        (env->hflags2 & HF2_NPT_MASK));
	/* nested paging not turned on for now */


    if (likely(!(env->hflags2 & HF2_NPT_MASK))) {
        return gphys;
    }

    exit_info_1 = mmu_translate(cs, gphys, NULL, env->nested_cr3, 
                               access_type, MMU_USER_IDX, env->nested_pg_mode, 0 /* gdb */, 
                               &hphys, &page_size, &next_prot);
    if (exit_info_1 == PG_ERROR_OK) {
        if (prot) {
            *prot &= next_prot;
        }
        return hphys;
    }

    x86_stq_phys(cs, env->vm_vmcb + offsetof(struct vmcb, control.exit_info_2),
                 gphys);
    if (prot) {
        exit_info_1 |= SVM_NPTEXIT_GPA;
    } else { /* page table access */
        exit_info_1 |= SVM_NPTEXIT_GPT;
    }
    cpu_vmexit(env, SVM_EXIT_NPF, exit_info_1, env->retaddr);
}

/* return value:
 * -1 = cannot handle fault
 * 0  = nothing more to do
 * 1  = generate PF fault
 */
static int handle_mmu_fault(CPUState *cs, vaddr addr, int size,
                            int is_write1, int mmu_idx)
{
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;
    int error_code = PG_ERROR_OK;
    int pg_mode, prot, page_size;
    hwaddr paddr;
    hwaddr vaddr;

#if defined(DEBUG_MMU)
    printf("MMU fault: addr=%" VADDR_PRIx " w=%d mmu=%d eip=" TARGET_FMT_lx "\n",
           addr, is_write1, mmu_idx, env->eip);
#endif
    qemu_log_mask(CPU_LOG_MMU, "MMU fault: addr=%" VADDR_PRIx " w=%d mmu=%d eip=" TARGET_FMT_lx "\n",
           addr, is_write1, mmu_idx, env->eip);
    // printf("MMU fault: addr=%" VADDR_PRIx " w=%d mmu=%d eip=" TARGET_FMT_lx "\n",
        //    addr, is_write1, mmu_idx, env->eip);

    if (!(env->cr[0] & CR0_PG_MASK)) {
        paddr = addr;
#ifdef TARGET_X86_64
        if (!(env->hflags & HF_LMA_MASK)) {
            /* Without long mode we can only address 32bits in real mode */
            paddr = (uint32_t)paddr;
        }
#endif
        prot = PAGE_READ | PAGE_WRITE | PAGE_EXEC;
        page_size = 4096;
    } else {
        pg_mode = get_pg_mode(env);
        error_code = mmu_translate(cs, addr, get_hphys, env->cr[3], is_write1,
                                   mmu_idx, pg_mode, 0 /* gdb */, 
                                   &paddr, &page_size, &prot);
        qemu_log_mask(CPU_LOG_MMU, "Translation Result: paddr=%" VADDR_PRIx " page_size=0x%x prot=0x%x err=%x\n",
           paddr, page_size, prot, error_code);
        // printf("Translation Result: paddr=%" VADDR_PRIx " page_size=%d prot=0x%x\n",
        //    paddr, page_size, prot);
    }

    if (error_code == PG_ERROR_OK) {
        /* Even if 4MB pages, we map only one 4KB page in the cache to
           avoid filling it too fast */
        vaddr = addr & TARGET_PAGE_MASK;
        paddr &= TARGET_PAGE_MASK;

        assert(prot & (1 << is_write1));
        tlb_set_page_with_attrs(cs, vaddr, paddr, cpu_get_mem_attrs(env),
                                prot, mmu_idx, page_size);
        return 0;
    } else {
        if (env->intercept_exceptions & (1 << EXCP0E_PAGE)) {
            /* cr2 is not modified in case of exceptions */
            x86_stq_phys(cs,
                     env->vm_vmcb + offsetof(struct vmcb, control.exit_info_2),
                     addr);
        } else {
            env->cr[2] = addr;
        }
        env->error_code = error_code;
        cs->exception_index = EXCP0E_PAGE;
        return 1;
    }
}

unsigned long x86_tlb_fill_pgtables(CPUState *cs, vaddr addr, int size,
                              int mmu_idx, void * trans_info) {

    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;
    int pg_mode;
    hwaddr paddr;
    MemRecord * rec = (MemRecord *) trans_info;
    

    if (!(env->cr[0] & CR0_PG_MASK)) {
        paddr = addr;
        if (!(env->hflags & HF_LMA_MASK)) {
            /* Without long mode we can only address 32bits in real mode */
            paddr = (uint32_t)paddr;
        }
    } else {
        pg_mode = get_pg_mode(env);
#ifdef TARGET_X86_64_ECPT
    int prot;
    /**
     * NOTE: we set mmu_idx to MMU_KNOSMAP_IDX, which indicates privelege level of kernel access.
     *  This is a hack to bypass warning message of fail to page table when dumping translation info in mmu_translate_ECPT.
     *  What would happen is that at page fault time, we somehow get an incorrect mmu_idx (MMU_USER_IDX) but to access
     *  a kernel address space (cpu_entry area). 
     * 
     * Example:
     *  ECPT Translate: addr=fffffe0000000ec0 eip=40159e w=0 mmu=1
     *  ECPT Translate: load from entry at 0x0000000002c88040 pte at 0x0000000002c88040 pte=0x8000000004290161 way=0
     *  Checking prot is_user=1 !(ptep & PG_USER_MASK)=1
     * 
     * The page table query result here is correct, but protection check fails;
     * as a result, we get incorrect paddr info which is recorded after the protection check.
     * 
     * Ideally, we should fix the mmu_idx fed here in translate_guest_virtual function (cputlb.c),
     * but it seems like already have the correct cpu_mmu_idx function, so it seems more like a issue within 
     * the QEMU plugin system. 
     * The radix translation dump doesn't have this problem, because the implemented mmu_translate_pgtables function
     * never checks user access or kernel access.
     * 
     * Our hack can serve as a temporary solution because address translation dump is to simulate performance;
     * permissino correctness checks are properly checked at runtime (handle_mmu_fault) which has the correct mmu_idx.
     */
    mmu_idx = MMU_KNOSMAP_IDX;
    int page_size = 0;
    int error_code =
        mmu_translate_ECPT(cs, addr, get_hphys, MMU_DATA_LOAD, mmu_idx, pg_mode,
                           0, &paddr, &page_size, &prot, rec);
    
    if (error_code != PG_ERROR_OK) {
        warn_report("ECPT fill pgtable failure: addr=%lx eip=%lx error_code=%d paddr=%lx page_size=%x prot=%x\n",
                    addr, env->eip, error_code, paddr, page_size, prot);
    }
    return paddr;
#elif defined TARGET_X86_64_FPT
    int prot;
    /**
     * NOTE: we set mmu_idx to MMU_KNOSMAP_IDX, which indicates privelege level of kernel access.
     *  This is a hack to bypass warning message of fail to page table when dumping translation info in mmu_translate_fpt.
     *  What would happen is that at page fault time, we somehow get an incorrect mmu_idx (MMU_USER_IDX) but to access
     *  a kernel address space (cpu_entry area). 
     * 
     * Example:
     *  FPT Translate: addr=fffffe0000000ec0 eip=40159e w=0 mmu=1
     *  FPT Translate: load from entry at 0x0000000002c88040 pte at 0x0000000002c88040 pte=0x8000000004290161 way=0
     *  Checking prot is_user=1 !(ptep & PG_USER_MASK)=1
     * 
     * The page table query result here is correct, but protection check fails;
     * as a result, we get incorrect paddr info which is recorded after the protection check.
     * 
     * Ideally, we should fix the mmu_idx fed here in translate_guest_virtual function (cputlb.c),
     * but it seems like already have the correct cpu_mmu_idx function, so it seems more like a issue within 
     * the QEMU plugin system. 
     * The radix translation dump doesn't have this problem, because the implemented mmu_translate_pgtables function
     * never checks user access or kernel access.
     * 
     * Our hack can serve as a temporary solution because address translation dump is to simulate performance;
     * permissino correctness checks are properly checked at runtime (handle_mmu_fault) which has the correct mmu_idx.
     */
    mmu_idx = MMU_KNOSMAP_IDX;
    int page_size = 0;
    int error_code =
        mmu_translate_fpt(cs, addr, get_hphys, env->cr[3], MMU_DATA_LOAD,
                          mmu_idx, pg_mode, 0 /* gdb */, &paddr, &page_size,
                          &prot, rec);
    
    if (error_code != PG_ERROR_OK) {
        warn_report("FPT fill pgtable failure: addr=%lx", addr);
    }

    return paddr;

#else
    /* radix */
    unsigned int page_size = 0;
    paddr = mmu_translate_pgtables(cs, addr, get_hphys, env->cr[3],
                                       mmu_idx, pg_mode,
                                       &rec->leaves[0], &rec->leaves[1], &rec->leaves[2], &rec->leaves[3], &page_size, &rec->pte);
#endif
    }

    return paddr;
}

bool x86_cpu_tlb_fill(CPUState *cs, vaddr addr, int size,
                      MMUAccessType access_type, int mmu_idx,
                      bool probe, uintptr_t retaddr)
{
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;

    env->retaddr = retaddr;
    if (handle_mmu_fault(cs, addr, size, access_type, mmu_idx)) {
        /* FIXME: On error in get_hphys we have already jumped out.  */
        g_assert(!probe);
        raise_exception_err_ra(env, cs->exception_index,
                               env->error_code, retaddr);
    }
    return true;
}

int mmu_translate_wrapper(CPUState *cs, hwaddr addr, MMUTranslateFunc get_hphys_func,
                         uint64_t cr3, int is_write1, int mmu_idx, int pg_mode,
                         hwaddr *xlat, int *page_size, int *prot) {
    return mmu_translate(cs, addr, get_hphys_func, cr3, is_write1, mmu_idx, pg_mode, 1 /* gdb */, xlat, page_size, prot);
}
