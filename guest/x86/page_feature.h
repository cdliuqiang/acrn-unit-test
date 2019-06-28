#ifndef _PAGE_FEATURE_H_
#define _PAGE_FEATURE_H_

typedef struct fxsave_st{
	u32 num_fxsave;
}fxsave_st;

#define PASS 0
#define MSR_EFER_ME		(1 << 8)
#define EDX_PAT			(1 << 16)
#ifdef __x86_64__
#define uint64_t unsigned long
#else
#define uint64_t unsigned long long
#endif
#endif

typedef enum page_control_bit{
	PAGE_P_FLAG = 0,
	PAGE_WRITE_READ_FLAG = 1,
	PAGE_USER_SUPER_FLAG = 2,
	PAGE_PWT_FLAG = 3,
	PAGE_PCM_FLAG = 4,
	PAGE_PS_FLAG = 7,
}page_control_bit;

typedef enum page_level{
	PAGE_PTE = 1,
	PAGE_PDE,
	PAGE_PDPTE,
	PAGE_PML4,
}page_level;

