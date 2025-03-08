#ifndef MEM_RECORD_H
#define MEM_RECORD_H

#include "x86_64-softmmu-config-target.h"

#ifdef TARGET_X86_64_ECPT
#define PAGE_TABLE_LEAVES 6
#define CWT_LEAVES 4
#endif

#ifndef PAGE_TABLE_LEAVES
#define PAGE_TABLE_LEAVES 4
#endif

typedef struct MemRecord
{
	uint8_t header;
	uint8_t access_rw;
	uint16_t access_cpu;
	uint32_t access_sz;
	uint64_t vaddr;
	uint64_t paddr;
	uint64_t pte;
	uint64_t leaves[PAGE_TABLE_LEAVES];
    /* 64 bytes if ECPT not defined */ 
#ifdef TARGET_X86_64_ECPT
    uint64_t cwt_leaves[CWT_LEAVES];
    uint16_t selected_ecpt_way;
    uint8_t pmd_cwt_header;
    uint8_t pud_cwt_header;
    /* 120 bytes if ECPT defined */
#elif defined (TARGET_X86_64_FPT)
	
#endif
} MemRecord;

#endif /* MEM_RECORD_H */