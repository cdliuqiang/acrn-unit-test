#include "libcflat.h"
#include "desc.h"
#include "processor.h"
#include "page_feature.h"
#include "vm.h"
#include "vmalloc.h"
#include "alloc_page.h"
#include "alloc_phys.h"
#include "ioram.h"
#include "alloc.h"

#define INVPCIDE_CHECK 0
#define WRITE_PROTECT 1 // user-mode address write

static void write_cr0_bybit(u32 bit, u32 bitvalue)
{
	u32 cr0 = read_cr0();
	if (bitvalue) {
		write_cr0(cr0 | (1 << bit));
	} else {
		write_cr0(cr0 & ~(1 << bit));
	}
}

static void write_cr4_bybit(u32 bit, u32 bitvalue)
{
	u32 cr0 = read_cr4();
	if (bitvalue) {
		write_cr4(cr0 | (1 << bit));
	} else {
		write_cr4(cr0 & ~(1 << bit));
	}
}

static void write_cr4_osxsave(u32 bitvalue)
{
	u32 cr4;

	cr4 = read_cr4();
	if (bitvalue) {
		write_cr4(cr4 | (1 << 18));
	} else {
		write_cr4(cr4 & ~(1 << 18));
	}
}

#if INVPCIDE_CHECK
struct page_invpcid_desc {
    unsigned long pcid : 12;
    unsigned long rsv  : 52;
    unsigned long addr : 64;
};

static int page_invpcid_checking(unsigned long type, void *desc)
{
    asm volatile (ASM_TRY("1f")
                  ".byte 0x66,0x0f,0x38,0x82,0x18 \n\t" /* invpcid (%rax), %rbx */
                  "1:" : : "a" (desc), "b" (type));
    return exception_vector();
}

static void invpcid_disabled_test(void)
{
    struct page_invpcid_desc desc;

    /* try executing invpcid, #UD expected */
    if (page_invpcid_checking(2, &desc) == UD_VECTOR)
    	printf("\n test invpcid #UD\n");
}

#endif

void mem_cache_type_set(u64 cache_type)
{
	u64 ia32_pat_test;

	ia32_pat_test = rdmsr(MSR_IA32_CR_PAT_TEST);
	printf("ia32_pat_test 0x%lx \n", ia32_pat_test);
	
	wrmsr(MSR_IA32_CR_PAT_TEST, cache_type);
	
	ia32_pat_test = rdmsr(MSR_IA32_CR_PAT_TEST);
	printf("ia32_pat_test 0x%lx \n", ia32_pat_test);
	
	if(ia32_pat_test != cache_type)
		printf("set pat type error set=0x%lx, get=0x%lx\n",
			cache_type, ia32_pat_test);
	else
		printf("set pat type sucess type=0x%lx\n", cache_type);
}

static inline void clear_eflags_ac(void) 
{
    asm volatile ("clac" : : : "memory");
}

static inline void set_eflags_ac(void) 
{
    asm volatile ("stac" : : : "memory");
}

static int write_protect_checking(u32 *p, u32 value)
{
	asm volatile(ASM_TRY("1f")
		     "mov %[value], (%[p])\n\t" /* xsetbv */
		     "1:"
		     : : [value]"r" (value), [p]"r"(p));
	return exception_vector();
}

static void clear_pflag()
{
	ulong cr3 = read_cr3();
	u32 *linear_addr = NULL;

	linear_addr = (u32 *)malloc(sizeof(u32));
	printf("\n linear_addr:%p\n", linear_addr);
	*linear_addr = 0x23456;

	pteval_t *pml4 = (pgd_t *)cr3;
	u32 pml4_offset = PGDIR_OFFSET((uintptr_t)linear_addr, 4);   //  1
	printf("\n pde_offset:%x-\n", pml4_offset);
	printf("\n 11--pde[pde-offset]:%lx \n", pml4[pml4_offset]);
	pml4[pml4_offset] = pml4[pml4_offset] & ~(1 << 1);

	asm volatile ("invlpg %0\n\t"
		      "nop\n\t" : : "m"(*linear_addr): "memory");
	*linear_addr = 0x456;

	free(linear_addr);
	linear_addr = NULL;
}
static void test_paging(void)
{

	u64 ia32_efer;
	ulong cr3 = read_cr3();
	ulong cr4 = read_cr4();
	ulong cr0 = read_cr0();
	u32 *linear_addr = NULL;
	ia32_efer = rdmsr(X86_IA32_EFER);

	printf("\n--cr0:0x%lx---cr4:0x%lx----ia32_efer:0x%lx---cr3:0x%lx\n",
	       cr0, cr4, ia32_efer, cr3);

#if INVPCIDE_CHECK
	if (!(cpuid(7).b & (1 << 10))) {
		invpcid_disabled_test();
	}
#elif WRITE_PROTECT
#define CR0WP_CR4SMAP_00 1
#define CR0WP_CR4SMAP_01 2
#define CR0WP_CR4SMAP_10 3
#define CR0WP_CR4SMAP_11 4
	u32 condition = CR0WP_CR4SMAP_10;

	linear_addr = (u32 *)malloc(sizeof(u32));
	printf("\n linear_addr:%p\n", linear_addr);
	*linear_addr = 0x23456;
	phys_addr_t *phy_addr;
	phy_addr = (virt_to_pte_phys((pgd_t *)cr3 , linear_addr));
	printf("\n 11--phy_addr:%p\n", phy_addr);
	printf("\n phy_addr_vlaue:%lx \n", *phy_addr);

	pteval_t *pml4 = cr3;
	u32 pml4_offset = PGDIR_OFFSET((uintptr_t)linear_addr, 4);   //  1
	u32 pdpte_offset = PGDIR_OFFSET((uintptr_t)linear_addr, 3); // 0x45
	printf("\n pde_offset:%x---pte_offset:%x\n", pml4_offset, pdpte_offset);
	printf("\n 11--pde[pde-offset]:%lx \n", pml4[pml4_offset]);
	pml4[pml4_offset] = pml4[pml4_offset] & ~(1 << 1);
	printf("\n 22---pde[pde-offset]:%lx \n", pml4[pml4_offset]);

	switch (condition) {
	case CR0WP_CR4SMAP_00:
		write_cr0(cr0 & ~X86_CR0_WP);
		write_cr4(cr4 & ~X86_CR4_SMAP);
		asm volatile ("invlpg %0\n\t"
			      "nop\n\t" : : "m"(*linear_addr): "memory");
		*linear_addr = 0x12;
		break;
	case CR0WP_CR4SMAP_01:
		write_cr0(cr0 & ~X86_CR0_WP);
		write_cr4(cr4 | X86_CR4_SMAP);
		set_eflags_ac();
		asm volatile ("invlpg %0\n\t"
			      "nop\n\t" : : "m"(*linear_addr): "memory");
		*linear_addr = 0x13;
		printf("\n write from user page with SMAP=1, AC=1, WP=0, PTE.U=1 && PTE.W=0\n");

		clear_eflags_ac();
		asm volatile ("invlpg %0\n\t"
			      "nop\n\t" : : "m"(*linear_addr): "memory");
		*linear_addr = 0x14;
		set_eflags_ac();
		printf("\n write from user page with SMAP=1, AC=0, WP=0, PTE.U=1 && PTE.W=0 \n");

		break;
	case CR0WP_CR4SMAP_10:
		write_cr0(cr0 | X86_CR0_WP);
		write_cr4(cr4 & ~X86_CR4_SMAP);
		asm volatile ("invlpg %0\n\t"
			      "nop\n\t" : : "m"(*linear_addr): "memory");

		//*linear_addr = 0x12;
		u32 result = write_protect_checking(linear_addr, 0x15);
		printf("\n result:%lx\n", result);
		//if ( == PF_VECTOR) {
		//	printf("\n write from user page with SMAP=0, AC=1, WP=1, PTE.U=1 && PTE.W=0 \n");
		//}
		break;

	default:
		break;
	}
	printf("\n 22----value:%x \n", *linear_addr);
	printf("\n cr0:%lx--cr4:%lx-\n", read_cr0(), read_cr4());
#elif 1
	write_cr4(cr4 | X86_CR4_PKE);
	printf("\n cr4:%lx\n", read_cr4());
#else
	linear_addr = (u32 *)malloc(4);
	if (linear_addr != NULL) {
		printf("\n -----linear_addr:%p\n", linear_addr);
	}
	*linear_addr = 0x23456;

	u32 *phy_addr = NULL;
	printf("\n set phy\n");
	phy_addr = (u32 *)virt_to_pte_phys((phys_addr_t *)cr3 , linear_addr);
	printf("\n 1111--phy_addr:%p\n", phy_addr);
	printf("\n phy_addr_vlaue:%lx \n", *phy_addr);

	free(linear_addr);
#endif
}

int main(void)
{
	setup_idt();
	setup_vm();
	phys_alloc_show();
	test_paging();

	return report_summary();
}

