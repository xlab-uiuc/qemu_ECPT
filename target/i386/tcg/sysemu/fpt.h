#ifndef FPT_H
#define FPT_H

#include "qemu/osdep.h"

#define CR3_L4_L3_FOLDED_SHIFT (63)
#define CR3_L4_L3_FOLDED_BIT (1ULL << CR3_L4_L3_FOLDED_SHIFT)
#define L4_L3_IS_FOLDED(pte) (pte & CR3_L4_L3_FOLDED_BIT)

#define NEXT_LEVEL_FOLDED_BIT 58
#define NEXT_LEVEL_FOLDED_MASK (1ULL << NEXT_LEVEL_FOLDED_BIT)
#define NEXT_LEVEL_IS_FOLDED(pte) (pte & NEXT_LEVEL_FOLDED_MASK)


#define PAGE_SHIFT_4KB (12)
#define PAGE_SHIFT_2MB (21)
#define PAGE_SHIFT_1GB (30)
#define PAGE_SHIFT_512GB (39)



#endif /* FPT_H */