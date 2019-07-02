/*
 * Test for x86 cache and memory cache control
 *
 * 
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 */
#include "libcflat.h"
#include "desc.h"
#include "processor.h"
#include "alloc.h"
#include "alloc_phys.h"
#include "vmalloc.h"
#include "alloc_page.h"
#include "asm/io.h"
#include "asm/spinlock.h"

#define USE_DEBUG
#ifdef  USE_DEBUG
//#define debug_print printf
#define debug_print(fmt, args...) printf("[%s:%s] line=%d "fmt"\r\n",__FILE__, __func__, __LINE__,  ##args)
//#define DEBUG_ERR(fmt, args...) printf("\033[47;31m[%s:%d]\033[0m   "fmt" \r\n", __func__, __LINE__,  ##args)
//#define DEBUG_INFO(fmt, args...) printf("\033[33m[%s:%d]\033[0m  "fmt"  \r\n", __func__, __LINE__, ##args)
#else
#define debug_print()
//#define DEBUG_ERR(fmt, ...)
//#define DEBUG_INFO(fmt, ...)
#endif

#define CR0_BIT_NW		29
#define CR0_BIT_CD		30
#define CR0_BIT_PG		31

#define CR3_BIT_PWT		3
#define CR3_BIT_PCD		4

#define CR4_BIT_PAE		5
#define CR4_BIT_PGE		7

#define MSR_IA32_CR_PAT_TEST			0x00000277
#define IA32_MISC_ENABLE				0x000001A0
#define IA32_MTRR_DEF_TYPE				0x000002FF
#define IA32_MTRRCAP_MSR				0x000000FE
#define IA32_SMRR_PHYSBASE_MSR			0x000001F2
#define IA32_SMRR_PHYSMASK_MSR			0x000001F3

#define IA32_MTRR_PHYSBASE0			0x00000200
#define IA32_MTRR_PHYSMASK0			0x00000201
#define IA32_MTRR_PHYSBASE1			0x00000202
#define IA32_MTRR_PHYSMASK1			0x00000203
#define IA32_MTRR_PHYSBASE2			0x00000204
#define IA32_MTRR_PHYSMASK2			0x00000205
#define IA32_MTRR_PHYSBASE3			0x00000206
#define IA32_MTRR_PHYSMASK3			0x00000207
#define IA32_MTRR_PHYSBASE4			0x00000208
#define IA32_MTRR_PHYSMASK4			0x00000209
#define IA32_MTRR_PHYSBASE5			0x0000020A
#define IA32_MTRR_PHYSMASK5			0x0000020B
#define IA32_MTRR_PHYSBASE6			0x0000020C
#define IA32_MTRR_PHYSMASK6			0x0000020D
#define IA32_MTRR_PHYSBASE7			0x0000020E
#define IA32_MTRR_PHYSMASK7			0x0000020F
#define IA32_MTRR_PHYBASE(i)	(IA32_MTRR_PHYSBASE0+i*2)
#define IA32_MTRR_PHYMASK(i)	(IA32_MTRR_PHYSMASK0+i*2)

extern void pt_memory_type_set(u64 type);

static long target;
static volatile int ud;
static volatile int isize;

u64 ia32_pat_test;

//default PAT entry value 0007040600070406
u64 cache_type_UC = 0x0;
u64 cache_type_WB = 0x0606060606060600;
u64 cache_type_WC = 0x0101010101010100;
u64 cache_type_WT = 0x0404040404040400;
u64 cache_type_WP = 0x0505050505050500;

u64 test_value = 0x1122334455667788;

u64 cache_line_size=64;

#define PT_PWT_MASK		(1ull << 3)
#define PT_PCD_MASK		(1ull << 4)
#define PT_PAT_MASK		(1ull << 7)

#if 0
u64 cache_l1_size=0x2000;	//64K
u64 cache_l2_size=0x20000;	//1M
u64 cache_l3_size=0x200000;	//16M
u64 cache_over_l3_size=0x1000000;	//128M
u64 cache_over_l3_size2=0x1000000;	//128M/8
#else
u64 cache_l1_size=0x1000;	//32K/8
u64 cache_l2_size=0x8000;	//256K/8
u64 cache_l3_size=0x100000;	//8M/8
u64 cache_over_l3_size=0x200000;	//16sM/8
u64 cache_over_l3_size2=0x400000;	//32M/8
#endif

u64 * cache_test_array=NULL;

unsigned long long rdtsc_test(void)
{
	long long r;

#ifdef __x86_64__
	unsigned a, d;
        asm volatile("mfence" ::: "memory");
	asm volatile ("rdtsc" : "=a"(a), "=d"(d));
	r = a | ((long long)d << 32);
#else
	asm volatile ("rdtsc" : "=A"(r));
#endif
        asm volatile("mfence" ::: "memory");
	return r;
}

static inline void maccess(u64 *p) 
{
  //asm volatile("mfence" ::: "memory");
  asm volatile("movq (%0), %%rax\n" : : "c"(p) : "rax");
  //asm volatile("mfence" ::: "memory");
}

static void wraccess(unsigned long address, unsigned long value)
{
	asm volatile("mov %[value], (%[address])"
		     : 
		     : [value]"r"(value), [address]"r"(address)
		     : "memory");
	//asm volatile("mfence" ::: "memory");
}

void cache_test_wbinvd()
{
	asm volatile ("wbinvd\n" : : : "memory");
}

void cache_test_mfence_wbinvd()
{
	asm volatile("mfence" ::: "memory");
	asm volatile ("   wbinvd\n" : : : "memory");
	asm volatile("mfence" ::: "memory");
}

void cache_test_invd()
{
	asm volatile ("invd\n" : : : "memory");
}

void cache_test_mfence_invd()
{
	asm volatile("mfence" ::: "memory");
	asm volatile ("invd\n" : : : "memory");
	asm volatile("mfence" ::: "memory");
}


u64 disorder_access(u64 index, u64 size)
{
    int i=0;
	u64 *p;
	u64 t[2] = {0};
	u64 disorder_index = 0;

	t[0] = rdtsc_test();
	disorder_index = (index*(t[0]&0xffff))%size;
	p=&cache_test_array[disorder_index];
	
	t[0] = rdtsc_test();
	maccess(p);
	t[1] = rdtsc_test();

	i = t[1]-t[0];
	return i;
}

void disorder_access_size(u64 size)
{
	int i;
	u64 ts_delta = 0;
	u64 ts_delta_all = 0;

	i=size;
	while(i){
		ts_delta = disorder_access(i, size);
		ts_delta_all = ts_delta_all + ts_delta;
		i--;
	}
	printf("%ld\n", ts_delta_all);
}

void disorder_access_size_time(u64 size, int time)
{
	int i=0;

	for(i=0; i<time; i++){
		disorder_access_size(size);
	}
}

void write_cr0_bybit(u32 bit, u32 bitvalue)
{
	u32 cr0 = read_cr0();
	if (bitvalue) {
		write_cr0(cr0 | (1 << bit));
	} else {
		write_cr0(cr0 & ~(1 << bit));
	}
}
/*
static void write_cr4_bybit(u32 bit, u32 bitvalue)
{
	u32 cr0 = read_cr4();
	if (bitvalue) {
		write_cr4(cr0 | (1 << bit));
	} else {
		write_cr4(cr0 & ~(1 << bit));
	}
}
*/

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

#if 1
void set_page_control_bit(void *gva,
	page_level level, page_control_bit bit, u32 value)
{
	if (gva == NULL) {
		printf("this address is NULL!\n");
		return;
	}

	ulong cr3 = read_cr3();
#ifdef __x86_64__
	u32 pdpte_offset = PGDIR_OFFSET((uintptr_t)gva, PAGE_PDPTE);
	u32 pml4_offset = PGDIR_OFFSET((uintptr_t)gva, PAGE_PML4);
	u32 pd_offset = PGDIR_OFFSET((uintptr_t)gva, PAGE_PDE);
	u32 pt_offset = PGDIR_OFFSET((uintptr_t)gva, PAGE_PTE);
	pteval_t *pml4 = (pteval_t *)cr3;

	pteval_t *pdpte = (pteval_t *)(pml4[pml4_offset] & PAGE_MASK);
	pteval_t *pd = (pteval_t *)(pdpte[pdpte_offset] & PAGE_MASK);
	pteval_t *pt = (pteval_t *)(pd[pd_offset] & PAGE_MASK);

	switch (level) {
	case PAGE_PML4:
		if (value) {
			pml4[pml4_offset] |= (1 << bit);
		} else {
			pml4[pml4_offset] &= ~(1 << bit);
		}
		break;
	case PAGE_PDPTE:
		if (value) {
			pdpte[pdpte_offset] |= (1 << bit);
		} else {
			pdpte[pdpte_offset] &= ~(1 << bit);
		}
		break;
	case PAGE_PDE:
		if (value) {
			pd[pd_offset] |= (1 << bit);
		} else {
			pd[pd_offset] &= ~(1 << bit);
		}
		break;
	case PAGE_PTE:
		if (value) {
			pt[pt_offset] |= (1 << bit);
		} else {
			pt[pt_offset] &= ~(1 << bit);
		}
		break;
	}
#if 1
	if (value) {
		pml4[pml4_offset] |= (1 << bit);
		pdpte[pdpte_offset] |= (1 << bit);
		pd[pd_offset] |= (1 << bit);
		pt[pt_offset] |= (1 << bit);
	}
#endif
	//printf("\n pte:%016x\n", pt[pt_offset]);
#else
	u32 pde_offset = PGDIR_OFFSET((uintptr_t)gva, PAGE_PDE);
	u32 pte_offset = PGDIR_OFFSET((uintptr_t)gva, PAGE_PTE);
	pteval_t *pde = (pgd_t *)cr3;

	u32 *pte = pde[pde_offset] & PAGE_MASK;

	if (level == PAGE_PDE) {
		if (value) {
			pde[pde_offset] |= (1 << bit);
		} else {
			pde[pde_offset] &= ~(1 << bit);
		}
	} else {
		if (value) {
			pte[pte_offset] |= (1 << bit);
		} else {
			pte[pte_offset] &= ~(1 << bit);
		}
	}
#endif
	asm volatile("invlpg %0\n\t"
			"nop\n\t" : : "m"(*((uintptr_t*)gva)): "memory");
}
#else
static void set_page_control_bit(void *gva,
	page_level level, page_control_bit bit, u32 value)
{
	if (gva == NULL || level > PAGE_PDE) {
		printf("this address is NULL or this is not 2 level page\n");
		return;
	}

	u32 pde_offset = PGDIR_OFFSET((uintptr_t)gva, PAGE_PDE);
	u32 pte_offset = PGDIR_OFFSET((uintptr_t)gva, PAGE_PTE);
	ulong cr3 = read_cr3();
	pteval_t *pde = (pgd_t *)cr3;

	u32 *pte = pde[pde_offset] & ~(0xfff);

	if (level == PAGE_PDE) {
		if (value) {
			pde[pde_offset] |= (1 << bit);
		} else {
			pde[pde_offset] &= ~(1 << bit);
		}
	} else {
		if (value) {
			pte[pte_offset] |= (1 << bit);
		} else {
			pte[pte_offset] &= ~(1 << bit);
		}
	}
	asm volatile("invlpg %0\n\t"
			"nop\n\t" : : "m"(*gva): "memory");

}
#endif
void disable_MTRR()
{
	u64 msr_value;

	msr_value = rdmsr(IA32_MTRR_DEF_TYPE);
	msr_value = msr_value&(~(1<<11));
	wrmsr(IA32_MTRR_DEF_TYPE,msr_value);
	debug_print("IA32_MTRR_DEF_TYPE 0x%lx set=0x%lx\n",
		rdmsr(IA32_MTRR_DEF_TYPE), msr_value);
}
void enable_MTRR()
{
	u64 msr_value;

	msr_value = rdmsr(IA32_MTRR_DEF_TYPE);
	msr_value = msr_value|(1<<11);
	wrmsr(IA32_MTRR_DEF_TYPE,msr_value);
	debug_print("IA32_MTRR_DEF_TYPE 0x%lx set=0x%lx\n",
		rdmsr(IA32_MTRR_DEF_TYPE), msr_value);
}

void flush_tlb()
{
	u32 cr3;
	cr3 = read_cr3();
	write_cr3(cr3);
}

void mem_cache_reflush_cache()
{
	
	u32 cr4;
	//write_cr4_bybit(CR4_BIT_PGE, 1);
	//cr4  = read_cr4();
	//debug_print("cr4.PGE=%d cr4.PAE=%d\n", cr4&(1<<CR4_BIT_PGE)?1:0, cr4&(1<<CR4_BIT_PAE)?1:0);

	//disable interrupts;
	irq_disable();

	//Save current value of CR4;
	cr4 = read_cr4();

	//disable and flush caches;
	write_cr0_bybit(CR0_BIT_CD, 1);
	write_cr0_bybit(CR0_BIT_NW, 0);
	cache_test_wbinvd();

	//flush TLBs;
	flush_tlb();

	//disable MTRRs;
	disable_MTRR();

	//flush caches and TLBs
	cache_test_wbinvd();
	flush_tlb();

	//enable MTRRs;
	enable_MTRR();

	//enable caches
	write_cr0_bybit(CR0_BIT_CD, 0);
	write_cr0_bybit(CR0_BIT_NW, 0);

	//restore value of CR4;
	write_cr4(cr4);

	//enable interrupts;
	irq_enable();
}

void mem_cache_test_set_type(u64 cache_type)
{
/*
	u64 ia32_pat_test;

	ia32_pat_test = rdmsr(MSR_IA32_CR_PAT_TEST);
	debug_print("ia32_pat_test 0x%lx \n",ia32_pat_test);
	
	//wrmsr(MSR_IA32_CR_PAT_TEST,(ia32_pat_test&(~0xFF0000))|(cache_type<<16));
	wrmsr(MSR_IA32_CR_PAT_TEST,cache_type);
	
	ia32_pat_test = rdmsr(MSR_IA32_CR_PAT_TEST);
	debug_print("ia32_pat_test 0x%lx \n",ia32_pat_test);
	
	if(ia32_pat_test != cache_type)
		debug_print("set pat type error set=0x%lx, get=0x%lx\n", cache_type, ia32_pat_test);
	else
		debug_print("set pat type sucess type=0x%lx get=0x%lx\n", cache_type, ia32_pat_test);

	asm volatile("mfence" ::: "memory");
	asm volatile ("   wbinvd\n" : : : "memory");
	asm volatile("mfence" ::: "memory");	

	mem_cache_reflush_cache();
*/
	//not free
	//if(cache_test_array != NULL)
	//	free(cache_test_array);

	pt_memory_type_set(cache_type);
	
	cache_test_array = (u64 *)malloc(cache_over_l3_size2*8);
	if(cache_test_array==NULL){
		debug_print("malloc error\n");
		return;
	}
	debug_print("cache_test_array=%p\n", cache_test_array);
	
	//flush caches and TLBs
	cache_test_wbinvd();
	flush_tlb();
}

void mem_cache_test_set_type_all(u64 cache_type)
{
	u64 ia32_pat_test;

	wrmsr(MSR_IA32_CR_PAT_TEST,cache_type);
	
	ia32_pat_test = rdmsr(MSR_IA32_CR_PAT_TEST);
	debug_print("ia32_pat_test 0x%lx \n",ia32_pat_test);
	
	if(ia32_pat_test != cache_type)
		debug_print("set pat type all error set=0x%lx, get=0x%lx\n", cache_type, ia32_pat_test);
	else
		debug_print("set pat type all sucess type=0x%lx\n", cache_type);

	cache_test_mfence_wbinvd();

	mem_cache_reflush_cache();
}


void mem_cache_test_read(u64 size)
{
	u64 index;
	u64 t[2] = {0};

	t[0] = rdtsc_test();
	for(index=0; index<size; index++){
		maccess(&cache_test_array[index]);
	}
	t[1] = rdtsc_test();
	printf("%ld\n", (t[1]-t[0]));
	asm volatile("mfence" ::: "memory");
}

void mem_cache_test_read_time_invd(u64 size, int time)
{
	debug_print("read cache cache_test_size 0x%lx %ld\n",size, size*8);

	while(time--){
		mem_cache_test_read(size);
	}
	
	cache_test_mfence_wbinvd();
}

void mem_cache_test_write(u64 size)
{
	u64 index;
	u64 t[2] = {0};
	u64 tt = rdtsc_test();
	u64 t_total=0;
	
	for(index=0; index<size; index++){
		tt += index;
		t[0] = rdtsc_test();
		wraccess((unsigned long )&cache_test_array[index],tt);
		t[1] = rdtsc_test();
		t_total += t[1] - t[0];
	}
	
	printf("%ld\n", t_total);
	asm volatile("mfence" ::: "memory");
}

void mem_cache_test_write_time_invd(u64 size, int time)
{
	debug_print("write cache cache_test_size 0x%lx %ld\n",size, size*8);

	while(time--){
		mem_cache_test_write(size);
	}
	
	cache_test_mfence_wbinvd();
}


void mem_cache_test_read_all(int time)
{
	debug_print("read ----------------------\n");
	//Cache size L1
	mem_cache_test_read_time_invd(cache_l1_size, time);
	//Cache size L2
	mem_cache_test_read_time_invd(cache_l2_size, time);
	//Cache size L3
	mem_cache_test_read_time_invd(cache_l3_size, time);
	//Cache size over L3
	mem_cache_test_read_time_invd(cache_over_l3_size, time);
	//Cache size over L3 2
	//mem_cache_test_read_time_invd(cache_over_l3_size2, time);
}

static void * mem_copy(void *dst, void *src, u64 size)
{
	asm volatile("mfence" ::: "memory");
	asm volatile("mov %0, %%rsi \n\t"
		     "mov %1, %%rdi \n\t"
		     "rep/movsq \n\t"
		     : : "m"(src), "m"(dst), "c"(size): "memory");
	return dst;
}

void test_cache_mem_copy_latency(void *dst, void *src, u64 size)
{
	u64 t[2] = {0};

	t[0] = rdtsc_test();
	asm volatile("mfence" ::: "memory");
	mem_copy(dst, src, size);
	asm volatile("mfence" ::: "memory");
	t[1] = rdtsc_test();
	
	printf("%ld\n", (t[1]-t[0]));
}

static void *vm_memalign_type_wc(size_t alignment, size_t size)
{
	void *mem, *p;
	unsigned pages;

	assert(alignment <= PAGE_SIZE);
	size = (size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
	pages = size / PAGE_SIZE;
	mem = p = alloc_vpages(pages);
	while (pages--) {
		phys_addr_t pa = virt_to_phys(alloc_page());
		/*used PAT entry 1 */
		install_page(phys_to_virt(read_cr3()), pa|PT_PWT_MASK, p);
		p += PAGE_SIZE;
	}
	return mem;
}

static void *vm_memalign_type_uc(size_t alignment, size_t size)
{
	void *mem, *p;
	unsigned pages;

	assert(alignment <= PAGE_SIZE);
	size = (size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
	pages = size / PAGE_SIZE;
	mem = p = alloc_vpages(pages);
	while (pages--) {
		phys_addr_t pa = virt_to_phys(alloc_page());
		/*used PAT entry 2 */
		install_page(phys_to_virt(read_cr3()), pa|PT_PCD_MASK, p);
		p += PAGE_SIZE;
	}
	return mem;
}

static void vm_free_type(void *mem, size_t size)
{
	while (size) {
		free_page(phys_to_virt(virt_to_pte_phys(phys_to_virt(read_cr3()), mem)));
		mem += PAGE_SIZE;
		size -= PAGE_SIZE;
	}
}

struct alloc_ops vmalloc_ops_wc = {
	.memalign = vm_memalign_type_wc,
	.free = vm_free_type,
	.align_min = PAGE_SIZE,
};

struct alloc_ops vmalloc_ops_uc = {
	.memalign = vm_memalign_type_uc,
	.free = vm_free_type,
	.align_min = PAGE_SIZE,
};

#include "vm.h"
static void setup_mmu_range_tmp(pgd_t *cr3, phys_addr_t start, size_t len)
{
	u64 max = (u64)len + (u64)start;
	u64 phys = start;

	//while (phys + LARGE_PAGE_SIZE <= max) {
	//	install_large_page(cr3, phys, (void *)(ulong)phys);
	//	phys += LARGE_PAGE_SIZE;
	//}
	install_pages(cr3, phys, max - phys, (void *)(ulong)phys);
}

void mem_cache_test_write_all(int time)
{
	debug_print("write ----------------------\n");
	//Cache size L1
	mem_cache_test_write_time_invd(cache_l1_size, time);
	//Cache size L2
	mem_cache_test_write_time_invd(cache_l2_size, time);
	//Cache size L3
	mem_cache_test_write_time_invd(cache_l3_size, time);
	//Cache size over L3
	mem_cache_test_write_time_invd(cache_over_l3_size, time);
	//Cache size over L3 2
	//mem_cache_test_write_time_invd(cache_over_l3_size2, time);

}
void test_cache_type_uc(int time)
{
	u64 type=cache_type_UC;
	debug_print("************uc*************** 0x%lx 0x%lx\n", cache_type_UC, type);
	//program MSR
	mem_cache_test_set_type(PT_MEMORY_TYPE_MASK4);

	mem_cache_test_write_all(time);
	mem_cache_test_read_all(time);
}

void test_cache_type_wb(int time)
{
	debug_print("************wb***************\n");
	//program MSR
	mem_cache_test_set_type(PT_MEMORY_TYPE_MASK0);

	mem_cache_test_write_all(time);
	mem_cache_test_read_all(time);
}

void test_cache_type_wc(int time)
{
	debug_print("************wc***************\n");
	//program MSR
	mem_cache_test_set_type(PT_MEMORY_TYPE_MASK3);
	
	mem_cache_test_write_all(time);
	mem_cache_test_read_all(time);
}

void test_cache_type_wt(int time)
{
	debug_print("************wt***************\n");
	//program MSR
	mem_cache_test_set_type(PT_MEMORY_TYPE_MASK2);

	mem_cache_test_write_all(time);
	mem_cache_test_read_all(time);
}

void test_cache_type_wp(int time)
{
	debug_print("************wp***************\n");
	//program MSR
	mem_cache_test_set_type(PT_MEMORY_TYPE_MASK1);

	mem_cache_test_write_all(time);
	mem_cache_test_read_all(time);
}

void test_cache_type_wt_wp()
{
	//int j;
	//u64 i;
	//u64 ts_delta = 0;
	//u64 ts_delta_all = 0;
	u64 cache_size = cache_l1_size;
	debug_print("************wt_wp***************\n");
	mem_cache_test_set_type(PT_MEMORY_TYPE_MASK2);

	debug_print("wt read cache_test_size %lx\n",cache_size);
	cache_test_wbinvd();
	mem_cache_test_read(cache_size);
	mem_cache_test_write(cache_size);
	
	disorder_access_size(cache_size);
	disorder_access_size(cache_size);
	disorder_access_size(cache_size);


	////////////////////////////////
	mem_cache_test_set_type(PT_MEMORY_TYPE_MASK1);
	debug_print("wp read cache_test_size %lx\n",cache_size);
	cache_test_wbinvd();
	mem_cache_test_read(cache_size);
	mem_cache_test_write(cache_size);
	
	disorder_access_size(cache_size);
	disorder_access_size(cache_size);
	disorder_access_size(cache_size);
	
	cache_test_mfence_wbinvd();
}

#if 0
void test_cache_type_wc_uc(void)
{
	//u64 * p_dst_wc, *p_dst_uc;
	u64 t[2] = {0};
	struct alloc_ops *alloc_ops_tmp;
	
	debug_print("***********wc_uc****************\n");
	/*
	* src is WB
	*7-0  UC WC WP WB     UC WC WP WB
	*/
	//mem_cache_test_set_type_all(0x0001050600010606);
	mem_cache_test_write(cache_l3_size);
	mem_cache_test_read_time_invd(cache_l3_size, 3);
	
	/*dst is wc*/
	alloc_ops_tmp = alloc_ops;
	alloc_ops = &vmalloc_ops_type_2;
	//p_dst_wc = (u64 *)malloc(cache_l3_size*8);
	cache_test_array = (u64 *)malloc(cache_l3_size*8);
	//debug_print("p_dst_wc=%p\n", p_dst_wc);
	
	t[0] = rdtsc_test();
	asm volatile("mfence" ::: "memory");
	//mem_copy(p_dst_wc, cache_test_array, cache_l3_size);
	mem_cache_test_write(cache_l3_size);
	mem_cache_test_read_time_invd(cache_l3_size, 3);
	asm volatile("mfence" ::: "memory");
	t[1] = rdtsc_test();
	
	debug_print("wb to wc latency %ld\n", (t[1]-t[0]));
	//free(p_dst_wc);
	//p_dst_wc= NULL;
	
	asm volatile("mfence" ::: "memory");
	asm volatile ("   wbinvd\n" : : : "memory");
	asm volatile("mfence" ::: "memory");
	
	mem_cache_test_write(cache_l3_size);
	/*dst is uc*/
	alloc_ops = &vmalloc_ops_type_3;
	//p_dst_uc = (u64 *)malloc(cache_l3_size*8);
	mem_cache_test_write(cache_l3_size);
	cache_test_array = (u64 *)malloc(cache_l3_size*8);
	//debug_print("p_dst_uc=%p\n", p_dst_uc);
	
	t[0] = rdtsc_test();
	asm volatile("mfence" ::: "memory");
	//mem_copy(p_dst_uc, cache_test_array, cache_l3_size);
	mem_cache_test_read_time_invd(cache_l3_size, 3);
	asm volatile("mfence" ::: "memory");
	t[1] = rdtsc_test();
	
	debug_print("wb to uc latency %ld\n", (t[1]-t[0]));

	//free(p_dst_uc);
	//p_dst_uc = NULL;
	alloc_ops = alloc_ops_tmp;
}
#endif

void test_cache_type(void)
{
#if 1
	int i;
	test_cache_type_uc(3);
	test_cache_type_wb(3);
	test_cache_type_wc(3);
	test_cache_type_wt(3);
	test_cache_type_wp(3);
	for(i=0; i<1; i++)
	{
		test_cache_type_wt_wp(3);
		//test_cache_type_wc_uc();
	}
#endif
}

extern char edata;
int get_bit_range(u32 r, int start, int end)
{
	int mask=0;
	int i = end-start+1;
	r = r>>start;
	while(i--){
		mask = mask<<1;
		mask+=1;
	}
	return r&mask;
}

void test_register_get()
{
	u32 cr0;
	u32 cr2;
	u32 cr3;
	u32 cr4;
	struct cpuid id;
	u32 ia32_efer;

	cr0 = read_cr0();
	cr2 = read_cr2();
	cr3 = read_cr3();
	cr4 = read_cr4();
	debug_print("cr0=0x%x\n", cr0);
	debug_print("cr0.PG=%d cr0.CD=%d cr0.NW=%d\n", cr0&(1<<31)?1:0, cr0&(1<<30)?1:0, cr0&(1<<29)?1:0);
	debug_print("cr2=0x%x\n", cr2);
	debug_print("cr3=0x%x\n", cr3);
	debug_print("cr3.PCD=%d cr0.PWT=%d\n", cr3&(1<<4)?1:0, cr3&(1<<3)?1:0);
	debug_print("cr4=0x%x\n", cr4);
	debug_print("cr4.PGE=%d cr4.PAE=%d\n", cr4&(1<<7)?1:0, cr4&(1<<5)?1:0);
	
	id = cpuid_indexed(0x01, 0);
	debug_print("cpuid.1: a=0x%x, b=0x%x, c=0x%x, d=0x%x\n", id.a, id.b, id.c, id.d);

	id = cpuid_indexed(0x02, 0);
		debug_print("cpuid.2: a=0x%x, b=0x%x, c=0x%x, d=0x%x\n", id.a, id.b, id.c, id.d);
	
	ia32_efer = rdmsr(X86_IA32_EFER);
	debug_print("msr ia32_efer=0x%x LME=%d\n", ia32_efer, ia32_efer&(1<<8)?1:0);
	
	debug_print("mem cache control start malloc memory edata=0x%x %p\n", edata, &edata);
}

/*
* ID:140465
* Name:Cache control deterministic cache parameters
* When a vCPU attempts to read CPUID.4H, 
* ACRN hypervisor shall write the deterministic cache parameters 
* of the physical platform to guest * EAX, EBX, ECX and EDX, 
* in compliance with Table 3-8 Information Returned by CPUID Instruction, Vol. 2, SDM.
*/
void cache_test_case_cpuid4()
{
	struct cpuid id;

	for(int i=0; i<4; i++){
		id = cpuid_indexed(0x04, i);
		debug_print("cpuid.04.%d: a=0x%x, b=0x%x, c=0x%x, d=0x%x\n", i, id.a, id.b, id.c, id.d);
		debug_print("type=0x%x level=0x%x self_init=0x%x Fully Associative=0x%x ID_process=0x%x ID_core=0x%x\n", 
			get_bit_range(id.a, 0, 4), get_bit_range(id.a, 5, 7), get_bit_range(id.a, 8, 8),
			get_bit_range(id.a, 9, 9), get_bit_range(id.a, 14, 25), get_bit_range(id.a, 26, 31));
		debug_print("Line Size=0x%x partitions=0x%x Ways=0x%x\n", 
			get_bit_range(id.b, 0, 11), get_bit_range(id.b, 12, 21), get_bit_range(id.b, 22, 31));
		debug_print("Sets=0x%x  edx 0-3bit 0x%x 0x%x 0x%x\n",id.c, 
			get_bit_range(id.d, 0, 0), get_bit_range(id.d, 1, 1), get_bit_range(id.d, 2, 2));
	}

}

/*
* ID:143710
* Name:INVD instruction
* When a vCPU attempts to call instruction invd, 
* ACRN hypervisor shall guarantee that the vCPU receives a #GP(0).
*/
void cache_test_case_invd()
{
	debug_print("start invd\n");
	cache_test_mfence_invd();
	debug_print("end invd\n");
}

/*
* ID:139986
* Name:Cache control invalid cache operating mode configuration
* When a vCPU attempts to write guest CR0, 
* the new guest CR0.CD is 0H and the new guest CR0.NW is 1H, 
* ACRN hypervisor shall guarantee that the vCPU receives a #GP(0).
*/
void cache_test_case_CD_NW_control()
{
	u32 cr0;
	cr0 = read_cr0();
	debug_print("CR0 = 0x%x\n", cr0);

	cr0 = cr0& ~(1<<CR0_BIT_CD); // clean CD
	cr0 = cr0|(1<<CR0_BIT_NW);	//set NW

	debug_print("CR0 = 0x%x\n", cr0);
	write_cr0(cr0);
}

/*
* ID:139246	
* Name:Cache control L3 cache control
* ACRN hypervisor shall hide L3 cache control from any VM, 
* in compliance with Chapter 11.5.4, Vol. 3, SDM. 
*/
void cache_test_case_l3_control()
{
	u64 msr_value;
	
	msr_value = rdmsr(IA32_MISC_ENABLE);
	debug_print("IA32_MISC_ENABLE 0x%lx  set=0x%lx\n",msr_value, (msr_value|(1<<6)));
	
	wrmsr(IA32_MISC_ENABLE,(msr_value|(1<<6)));

	msr_value = rdmsr(IA32_MISC_ENABLE);
	debug_print("IA32_MISC_ENABLE 0x%lx \n",msr_value);
}

/*
* ID:139247	
* Name:Cache control CLFLUSH instruction
* ACRN hypervisor shall expose CLFLUSH instruction to any VM, 
* in compliance with Chapter 9.6, Vol. 3, SDM.
*/
void cache_test_case_clflush_001(void)
{
	struct cpuid cpuid1;
	int expected;

	target = 0x11223344;
	
	cpuid1 = cpuid(1);
	expected = cpuid1.d & (1U << 19); // CLFLUSH 
	asm volatile("clflush (%0)" : : "b" (&target));
	report("clflush (%s)", expected==1, expected?"present":"absent");
}

void cache_test_case_clflush_all_line(u64 size)
{
	int i;

	for(i=0; i<size; i++){
		asm volatile("clflush (%0)" : : "b" (&cache_test_array[i]));
	}
}

void cache_test_case_clflush_read(u64 size, int time)
{
	int i=0;

	for(i=0; i<time; i++){
		cache_test_case_clflush_all_line(size);
		mem_cache_test_read(size);
	}
}

void cache_test_case_clflush_disroder_read(u64 size, int time)
{
	int i=0;

	for(i=0; i<time; i++){
		cache_test_case_clflush_all_line(size);
		disorder_access_size(size);
	}
}

void cache_test_case_clflush_002(int time)
{
	//program MSR
	mem_cache_test_set_type(PT_MEMORY_TYPE_MASK0);

	debug_print("************ wb no clflush read***************\n");
	mem_cache_test_read_time_invd(cache_l3_size, time);
	
	debug_print("************ wb clflush read***************\n");
	cache_test_case_clflush_read(cache_l3_size, time);
}

void cache_test_case_clflush_003(int time)
{
	mem_cache_test_set_type(PT_MEMORY_TYPE_MASK0);
	
	debug_print("************ wb no clflush disorder read***************\n");
	disorder_access_size_time(cache_l3_size, time);

	debug_print("************ wb clflush disorder read***************\n");
	cache_test_case_clflush_disroder_read(cache_l3_size, time);
}

/*
* ID:139249	
* Name:Cache control CLFLUSHOPT instruction
* ACRN hypervisor shall expose CLFLUSHOPT instruction to any VM, 
* in compliance with CLFLUSHOPT, Vol. 2, SDM.
*/
void cache_test_case_clflushopt_001(void)
{
	struct cpuid cpuid7;
	int expected;

	target = 0x11223344;
	
	cpuid7 = cpuid(7);
	expected = cpuid7.b & (1U << 23); /* CLFLUSHOPT */
	/* clflushopt (%rbx): */
	asm volatile(".byte 0x66, 0x0f, 0xae, 0x3b" : : "b" (&target));
	report("clflushopt (%s)", expected==1, expected?"present":"absent");
}

void cache_test_case_clflushopt_all_line(u64 size)
{
	int i;

	for(i=0; i<size; i++){
		//asm volatile(".byte 0x66, 0x0f, 0xae, 0x3b" : : "b" (&cache_test_array[i]));
		asm volatile("clflushopt (%0)" : : "b" (&cache_test_array[i]));
	}
}

void cache_test_case_clflushopt_read(u64 size, int time)
{
	int i=0;

	for(i=0; i<time; i++){
		cache_test_case_clflushopt_all_line(size);
		mem_cache_test_read(size);
	}
}

void cache_test_case_clflushopt_disroder_read(u64 size, int time)
{
	int i=0;

	for(i=0; i<time; i++){
		cache_test_case_clflushopt_all_line(size);
		disorder_access_size(size);
	}
}

void cache_test_case_clflushopt_002(int time)
{
	//program MSR
	mem_cache_test_set_type(PT_MEMORY_TYPE_MASK0);

	debug_print("************ wb no clflushopt read***************\n");
	mem_cache_test_read_time_invd(cache_l3_size, time);

	debug_print("************ wb clflushopt read***************\n");
	cache_test_case_clflushopt_read(cache_l3_size, time);
}

void cache_test_case_clflushopt_003(int time)
{
	mem_cache_test_set_type(PT_MEMORY_TYPE_MASK0);
	
	debug_print("************ wb no clflushopt disorder read***************\n");
	disorder_access_size_time(cache_l3_size, time);

	debug_print("************ wb clflushopt disorder read***************\n");
	cache_test_case_clflushopt_disroder_read(cache_l3_size, time);
}

/*
* ID:139239
* Name:Cache control MTRR general support
* ACRN hypervisor shall hide MTTR general support from any VM, 
* in compliance with Chapter 11.11.1, Vol. 3, SDM.
*/
void cache_test_case_MTRR_general(void)
{
	struct cpuid id;
	u64 msr_value;
	
	id = cpuid(1);

	debug_print("cpuid.1: a=0x%x, b=0x%x, c=0x%x, d=0x%x\n", id.a, id.b, id.c, id.d);
	if(id.d&(1<<12)){
		//IA32_MTRR_DEF_TYPE MSR
		msr_value = rdmsr(IA32_MTRR_DEF_TYPE);
		debug_print("IA32_MTRR_DEF_TYPE 0x%lx \n",msr_value);
		if(msr_value & (1<<11)){
			debug_print("MTRR enable\n");

			//disable
			//msr_value = msr_value&(~(1<<11));
			//wrmsr(IA32_MTRR_DEF_TYPE,msr_value);
			//debug_print("IA32_MTRR_DEF_TYPE 0x%lx set=0x%lx\n",
			//rdmsr(IA32_MTRR_DEF_TYPE), msr_value);

			//enable
			//msr_value = msr_value|(1<<11);
			//wrmsr(IA32_MTRR_DEF_TYPE,msr_value);
			//debug_print("IA32_MTRR_DEF_TYPE 0x%lx set=0x%lx\n",
			//rdmsr(IA32_MTRR_DEF_TYPE), msr_value);
		}
		else{
			debug_print("MTRR disable\n");
		}
	}
	else{
		debug_print("MTRR not support\n");
	}

	msr_value = rdmsr(IA32_MTRR_DEF_TYPE);
	debug_print("IA32_MTRR_DEF_TYPE 0x%lx\n", msr_value);
	debug_print("MTRR default type =%d\n", (int)(msr_value&0xff));
	
}

/*
* ID:139240
* Name:Cache control MTRR fixed range registers
* ACRN hypervisor shall hide MTRR fixed range registers from any VM, 
* in compliance with Chapter 11.11.1, Vol. 3, SDM.
*/
void cache_test_case_MTRR_fixed(void)
{
	u64 msr_value;

	msr_value = rdmsr(IA32_MTRRCAP_MSR);
	debug_print("IA32_MTRRCAP_MSR 0x%lx \n",msr_value);
	if(msr_value & (1<<8)){
		debug_print("fixed MTRRs support\n");
	}
	
	msr_value = rdmsr(IA32_MTRR_DEF_TYPE);
	debug_print("IA32_MTRR_DEF_TYPE 0x%lx \n",msr_value);
	if(msr_value & (1<<10)){
		debug_print("fixed MTRRs enableds\n");
	}
}

/*
* ID:139241
* Name:Cache control MTRR write-combining memory type support
* ACRN hypervisor shall hide MTRR write-combining memory type support from any VM, 
* in compliance with Chapter 11.11.1, Vol. 3, SDM.
*/
void cache_test_case_MTRR_WC(void)
{
	u64 msr_value;

	msr_value = rdmsr(IA32_MTRRCAP_MSR);
	debug_print("IA32_MTRRCAP_MSR 0x%lx \n",msr_value);
	if(msr_value & (1<<10)){
		debug_print("WC support\n");
	}
}

/*
* ID:139242
* Name:Cache control system management range register
* ACRN hypervisor shall hide MTRR system management range register from any VM, 
* in compliance with Chapter 11.11.2.4, Vol. 3, SDM.
*/
void cache_test_case_MTRR_SMRR(void)
{
	u64 msr_value;

	msr_value = rdmsr(IA32_MTRRCAP_MSR);
	debug_print("IA32_MTRRCAP_MSR 0x%lx \n",msr_value);
	if(msr_value & (1<<11)){
		debug_print("SMRR support\n");
	}

	msr_value = rdmsr(IA32_SMRR_PHYSBASE_MSR);
	debug_print("IA32_SMRR_PHYSBASE_MSR 0x%lx \n",msr_value);
	debug_print("SMRR type=%d  base=0x%lx %ldM\n",
		(int)(msr_value&0xFF), (msr_value&0xFFFFFFFF)>>12, (msr_value&0xFFFFFFFF)>>20);

	msr_value = rdmsr(IA32_SMRR_PHYSMASK_MSR);
	debug_print("IA32_SMRR_PHYSMASK_MSR 0x%lx \n",msr_value);
	debug_print("SMRR valid=%d  mask=0x%lx size = %ldM\n",
		(int)(msr_value>>11)&0x1, (msr_value&0xFFFFFFFF)>>12, ~((msr_value)>>20)&0xFFFF);
}

/*
* ID:
* Name:Cache control variable range register
*  
* 
*/
void cache_test_case_MTRR_VR(void)
{
	int i=0, max;
	u64 msr_value;
	
	msr_value = rdmsr(IA32_MTRRCAP_MSR);
	debug_print("IA32_MTRRCAP_MSR 0x%lx \n",msr_value);
	debug_print("vnct=%d\n", (int)msr_value&0xFF);

	max = msr_value&0xFF;
	for(i=0; i<max; i++){

		msr_value = rdmsr(IA32_MTRR_PHYBASE(i));
		debug_print("IA32_SMRR_PHYSBASE_MSR 0x%x %d 0x%lx \n",
			IA32_MTRR_PHYBASE(i), i, msr_value);
		debug_print("SMRR type=%d  base=0x%lx %ldM\n",
			(int)(msr_value&0xFF), (msr_value&0xFFFFFFFF)>>12, (msr_value&0xFFFFFFFF)>>20);

		msr_value = rdmsr(IA32_MTRR_PHYMASK(i));
		debug_print("IA32_SMRR_PHYSMASK_MSR 0x%x %d 0x%lx \n",
			IA32_MTRR_PHYMASK(i), i, msr_value);
		debug_print("SMRR valid=%d  mask=0x%lx  size=%ldM\n\n",
			(int)(msr_value>>11)&0x1, (msr_value&0xFFFFFFFF)>>12, ~((msr_value)>>20)&0xFFFF);
	}
}


/*
* ID:139243
* Name:Cache control cache invalidation instructions
* ACRN hypervisor shall expose cache invalidation instructions to any VM, 
* in compliance with Chapter 11.5.5, Vol. 3, SDM
*/
void cache_test_case_invalidation_001(void)
{
	debug_print("start invd\n");
	cache_test_mfence_wbinvd();
	debug_print("end invd\n");
}

void cache_test_case_invalidation_read(u64 size, int time)
{
	int i=0;

	for(i=0; i<time; i++){
		cache_test_wbinvd();
		mem_cache_test_read(size);
	}
}

void cache_test_case_invalidation_disroder_read(u64 size, int time)
{
	int i=0;

	for(i=0; i<time; i++){
		cache_test_wbinvd();
		disorder_access_size(size);
	}
}

void cache_test_case_invalidation_002(int time)
{
	//program MSR
	mem_cache_test_set_type(PT_MEMORY_TYPE_MASK0);

	debug_print("************ wb no wbinvd read***************\n");
	mem_cache_test_read_time_invd(cache_l3_size, time);
	
	debug_print("************ wb wbinvd read***************\n");
	cache_test_case_invalidation_read(cache_l3_size, time);
}

void cache_test_case_invalidation_003(int time)
{
	mem_cache_test_set_type(PT_MEMORY_TYPE_MASK0);
	
	debug_print("************ wb no wbinvd disorder read***************\n");
	disorder_access_size_time(cache_l3_size, time);

	debug_print("************ wb wbinvd disorder read***************\n");
	cache_test_case_invalidation_disroder_read(cache_l3_size, time);
}

/*
* ID:139251
* Name:CLWB instruction
* ACRN hypervisor shall hide CLWB instruction from any VM, 
* in compliance with CLWB, Vol. 2, SDM.
*/
void cache_test_case_CLWB(void)
{
	struct cpuid cpuid7;
	cpuid7 = cpuid_indexed(7, 0);
	int expected;
	
	expected = cpuid7.b & (1U << 24); /* CLWB */
	/* clwb (%rbx): */
	//asm volatile(".byte 0x66, 0x0f, 0xae, 0x33" : : "b" (&target));   //GP
	asm volatile("clwb (%0)" : : "b"(&target));
	report("clwb (%s)", expected==1, expected ? "present" : "ABSENT");
}

/* PREFETCHW1  ?
* ID:141162
* Name:PREFETCHW instruction
* ACRN hypervisor shall expose PREFETCHW instruction to any VM, 
* in compliance with Chapter 5.1.16.1, Vol. 1, SDM.
*/
void cache_test_case_PREFETCHW(void)
{
	struct cpuid cpuid;
	cpuid = cpuid_indexed(0x80000001, 0);
	int expected;

	expected = cpuid.c & (1U << 8); /* PREFETCHW */
	/* clwb (%rbx): */
	//asm volatile(".byte " : : "b" (&target));   //GP
	asm volatile("prefetchw (%0)" : : "b"(&target));
	report("prefetchw (%s)", expected==1, expected ? "present" : "ABSENT");
}


/*
* ID:139245	
* Name: Cache control L1 data cache context mode	
* ACRN hypervisor shall hide L1 data cache context mode from any VM, 
* in compliance with Chapter 11.5.6, Vol. 3, SDM
*/
void cache_test_case_l1_control()
{
	struct cpuid id;
	u64 msr_value;

	id = cpuid_indexed(0x01, 0);
	debug_print("cpuid.1: a=0x%x, b=0x%x, c=0x%x, d=0x%x\n", id.a, id.b, id.c, id.d);

	if(id.c&(1<<10)){
		debug_print("not supports setting L1 data cache context mode\n");
	}
	
	msr_value = rdmsr(IA32_MISC_ENABLE);
	debug_print("IA32_MISC_ENABLE 0x%lx  set=0x%lx\n",msr_value, (msr_value|(1<<24)));
	
	wrmsr(IA32_MISC_ENABLE,(msr_value|(1<<24)));
	
	msr_value = rdmsr(IA32_MISC_ENABLE);
	debug_print("IA32_MISC_ENABLE 0x%lx \n",msr_value);
}

void cache_test_disable_paging()
{
	u32 cr0;
	cr0 = read_cr0();
	debug_print("CR0 = 0x%x\n", cr0);

	cr0 = cr0 | (1<<CR0_BIT_CD); // set CD
	//cr0 = cr0 | (1<<CR0_BIT_NW);	//set NW
	debug_print("CR0 = 0x%x\n", cr0);
	write_cr0(cr0);
	cr0 = read_cr0();
	debug_print("CR0 = 0x%x\n", cr0);
	
	//flush caches and TLBs
	cache_test_wbinvd();
	flush_tlb();
}

void cache_test_enable_paging()
{
	mem_cache_reflush_cache();
}
/*
* ID:139985
* Name: Cache control access to guest linear addresses in no-fill cache mode
* When a vCPU accesses a guest address range and the guest CR0.CD is 1H, 
* ACRN hypervisor shall guarantee that the access follows caching and read/write 
* policy of normal cache mode with effective memory type being UC.
*/
void cache_test_case_no_fill_cache(int time)
{
	debug_print("************no_fill_cache***************\n");

	cache_test_disable_paging();

	mem_cache_test_write_all(time);
	mem_cache_test_read_all(time);

	//reset 
	cache_test_enable_paging();
}

/*
* ID:139257
* Name: Cache control access to device-mapped guest linear addresses in normal cache mode
* When a vCPU accesses a guest address range, the guest CR0.CD is 0H, the guest 
* CR0.NW is 0H, the guest CR0.PG is 1H and the guest address range maps to device, 
* ACRN hypervisor shall guarantee that the access follows caching and read/write policy of 
* normal cache mode with effective memory type being UC.
*/
void cache_test_case_map_to_device_linear(int time)
{
	//unsigned int tmp;
	u64* regValue=0;

	debug_print("************map_to_device_linear***************\n");
	//tmp = visitPciDev(NULL);
	//regValue = (uintptr_t*)tmp;

	cache_test_array = regValue;
	mem_cache_test_write_time_invd((0x4FF0/8), time);
}


/*
* ID:143295
* Name: Cache control access to device-mapped guest physical addresses in normal cache mode
* When a vCPU accesses a guest address range, the guest CR0.CD is 0H, the guest CR0.
* NW is 0H, the guest CR0.PG is 0H and the guest address range maps to device, 
* ACRN hypervisor shall guarantee that the access follows caching and read/write policy 
* of normal cache mode with effective memory type being UC.
*/
void cache_test_case_map_to_device_physical(int time)
{
	debug_print("************map_to_device_physical***************\n");

	cache_test_disable_paging();
	
	cache_test_enable_paging();
}

/*
* ID:143294
* Name: Cache control access to empty-mapped guest linear addresses in normal cache mode
* When a vCPU accesses a guest address range, the guest CR0.CD is 0H, the guest 
* CR0.NW is 0H, the guest CR0.PG is 1H and the guest address range maps to none, 
* ACRN hypervisor shall guarantee that the access follows caching and read/write policy 
* of normal cache mode with effective memory type being UC.
*/
void cache_test_case_map_to_none_linear(int time)
{
	u64 * tmp = cache_test_array;
	debug_print("************map_to_none_linear***************\n");
	//struct alloc_ops *alloc_ops_tmp;
	
	//none_pate_init();
		
	//alloc_ops_tmp = alloc_ops;
	//alloc_ops = &vmalloc_ops_none;
	mem_cache_test_set_type(PT_MEMORY_TYPE_MASK4);	//UC
	setup_mmu_range_tmp(phys_to_virt(read_cr3()), 1ul<<36, (1ul << 30)); //64G-65G  map to none
	cache_test_array = (u64*) (1ul<<36);
	mem_cache_test_write_all(41);
	mem_cache_test_read_all(41);
	
	//alloc_ops = alloc_ops_tmp;
	cache_test_array = tmp;
}

/*
* ID:143296
* Name: Cache control access to empty-mapped guest physical addresses in normal cache mode
* When a vCPU accesses a guest address range, the guest CR0.CD is 0H, the guest 
* CR0.NW is 0H, the guest CR0.PG is 0H and the guest address range maps to none, 
* ACRN hypervisor shall guarantee that the access follows caching and read/write policy 
* of normal cache mode with effective memory type being UC.
*/
//32bit mode
void cache_test_case_map_to_none_physical(int time)
{
	u64 * tmp = cache_test_array;
	debug_print("************map_to_none_physical***************\n");

	cache_test_disable_paging();

	//setup_mmu_range_tmp(phys_to_virt(read_cr3()), 1ul<<36, (1ul << 30)); //64G-65G  map to none
	cache_test_array = (u64*) (1ul<<36);
	mem_cache_test_write_all(3);
	mem_cache_test_read_all(3);
	
	cache_test_enable_paging();

	cache_test_array = tmp;
}

/*
* ID:139984
* Name: Cache control access to memory-mapped guest physical addresses in normal cache mode
* When a vCPU accesses a guest address range, the guest CR0.CD is 0H, the guest 
* CR0.NW is 0H, the guest CR0.PG is 0H and the guest address range maps to memory, 
* ACRN hypervisor shall guarantee that the access follows caching and read/write policy 
* of normal cache mode with effective memory type being WB
*/
void cache_test_case_map_to_memory_linear(int time)
{
	debug_print("************map_to_memory_linear***************\n");

	mem_cache_test_write_all(time);
	mem_cache_test_read_all(time);
}

/*
* ID:139243
* Name:Cache control cache invalidation instructions[exception]
* ACRN hypervisor shall expose cache invalidation instructions to any VM, 
* in compliance with Chapter 11.5.5, Vol. 3, SDM
*/
static int do_at_ring3(void (*fn)(void), const char *arg)
{
	static unsigned char user_stack[4096];
	int ret;

	asm volatile ("mov %[user_ds], %%" R "dx\n\t"
		  "mov %%dx, %%ds\n\t"
		  "mov %%dx, %%es\n\t"
		  "mov %%dx, %%fs\n\t"
		  "mov %%dx, %%gs\n\t"
		  "mov %%" R "sp, %%" R "cx\n\t"
		  "push" W " %%" R "dx \n\t"
		  "lea %[user_stack_top], %%" R "dx \n\t"
		  "push" W " %%" R "dx \n\t"
		  "pushf" W "\n\t"
		  "push" W " %[user_cs] \n\t"
		  "push" W " $1f \n\t"
		  "iret" W "\n"
		  "1: \n\t"
		  "push %%" R "cx\n\t"   /* save kernel SP */

#ifndef __x86_64__
		  "push %[arg]\n\t"
#endif
		  "call *%[fn]\n\t"
#ifndef __x86_64__
		  "pop %%ecx\n\t"
#endif

		  "pop %%" R "cx\n\t"
		  "mov $1f, %%" R "dx\n\t"
		  "int %[kernel_entry_vector]\n\t"
		  ".section .text.entry \n\t"
		  "kernel_entry: \n\t"
		  "mov %%" R "cx, %%" R "sp \n\t"
		  "mov %[kernel_ds], %%cx\n\t"
		  "mov %%cx, %%ds\n\t"
		  "mov %%cx, %%es\n\t"
		  "mov %%cx, %%fs\n\t"
		  "mov %%cx, %%gs\n\t"
		  "jmp *%%" R "dx \n\t"
		  ".section .text\n\t"
		  "1:\n\t"
		  : [ret] "=&a" (ret)
		  : [user_ds] "i" (USER_DS),
		    [user_cs] "i" (USER_CS),
		    [user_stack_top]"m"(user_stack[sizeof user_stack]),
		    [fn]"r"(fn),
		    [arg]"D"(arg),
		    [kernel_ds]"i"(KERNEL_DS),
		    [kernel_entry_vector]"i"(0x20)
		  : "rcx", "rdx");
	return ret;
}

#ifdef __x86_64__
/*64bit mode ring 3   GP
* Hypervisor GP ok
*/
void cache_test_case_invalidation_exception_001(void)
{
	debug_print("\n");
	do_at_ring3(cache_test_wbinvd, "");
}

/*64bit mode LOCK prefix F0   UD
* Hypervisor UD ok
*/
void cache_test_case_invalidation_exception_002(void) 
{
	debug_print("\n");
	asm volatile(".byte 0xF0\n\t" "wbinvd\n\t" : :);
	//asm volatile(".byte 0xF0, 0x0F, 0x09" : :);
}
#elif defined(__i386__)
/*protected mode ring 3   GP*/
void cache_test_case_invalidation_exception_003(void)
{
	debug_print("\n");
	do_at_ring3(cache_test_wbinvd, "");
}

/*protected mode LOCK prefix F0   UD*/
void cache_test_case_invalidation_exception_004(void)
{
	debug_print("\n");
	asm volatile(".byte 0xF0\n\t" "wbinvd\n\t" : :);
}
#else
/*real mode LOCK prefix F0   UD*/
void cache_test_case_invalidation_exception_005(void)
{
	debug_print("\n");
	asm volatile(".byte 0xF0\n\t" "wbinvd\n\t" : :);
}
#endif
void wbinvd_exception_test()
{
#ifdef __x86_64__
	cache_test_case_invalidation_exception_001();//ok
	cache_test_case_invalidation_exception_002();//ok
#elif defined(__i386__)
	cache_test_case_invalidation_exception_003();
	cache_test_case_invalidation_exception_004();
#else
	cache_test_case_invalidation_exception_005();
#endif
}

#ifdef __x86_64__
/*64bit mode ring 3   GP
* Hypervisor GP ok
*/
void cache_test_case_invd_exception_001(void)
{
	debug_print("\n");
	do_at_ring3(cache_test_invd, "");
}

/*64bit mode LOCK prefix F0   UD
Hypervisor UD ok
*/
void cache_test_case_invd_exception_002(void)
{
	debug_print("\n");
	//asm volatile(".byte 0xF0, 0x0f, 0x08" : :);
	asm volatile(".byte 0xF0\n\t" "invd" : :);
}
#elif defined(__i386__)
/*protected mode ring 3   GP*/
void cache_test_case_invd_exception_003(void)
{
	debug_print("\n");
	do_at_ring3(cache_test_invd, "");
}

/*protected mode LOCK prefix F0   UD*/
void cache_test_case_invd_exception_004(void)
{
	debug_print("\n");
	//asm volatile(".byte 0xF0, 0x0f, 0x08" : :);
	asm volatile(".byte 0xF0\n\t" "invd" : :);
}
#else
/*real mode LOCK prefix F0   UD*/
void cache_test_case_invd_exception_005(void)
{
	debug_print("\n");
	//asm volatile(".byte 0xF0, 0x0f, 0x08" : :);
	asm volatile(".byte 0xF0\n\t" "invd" : :);
}
#endif

void invd_exception_test()
{
#ifdef __x86_64__
	cache_test_case_invd_exception_001();//ok
	cache_test_case_invd_exception_002();//ok
#elif defined(__i386__)
	cache_test_case_invd_exception_003();
	cache_test_case_invd_exception_004();
#else
	cache_test_case_invd_exception_005();
#endif
}


/*bit 63 set to 1
*/
void cache_test_case_clflush_all_line_non_canonical(u64 size)
{
	int i;
	unsigned long address;

	for(i=0; i<size; i++){
		address = (unsigned long)(&cache_test_array[i]);
		address = (address|(1UL<<63));
		printf("%lx\n", address);
		asm volatile("clflush (%0)" : : "b" (address));
	}
}

void cache_test_case_clflush_all_line_lock_prefix(u64 size)
{
	int i=0;

	for(i=0; i<size; i++){
		asm volatile(".byte 0xF0\n\t" "clflush (%0)" : : "b" (&cache_test_array[i]));
	}
}

#ifdef __x86_64__
/*64bit mode non-canonical   GP
* Hypervisor GP ok
*/
void cache_test_case_clflush_exception_001(void)
{
	debug_print("\n");
	mem_cache_test_read_time_invd(cache_l1_size, 1);
	cache_test_case_clflush_all_line_non_canonical(cache_l1_size);
}

/*64bit mode non-canonical   SS   SS segment
* fail  only GP
*/
void cache_test_case_clflush_exception_002(void)
{
	u64 ss_mem;
	u64 address=0;

	ss_mem = 0x1122334455667788;

	address = (unsigned long)(&ss_mem);
	address = (address|(1UL<<63));
	printf("%lx\n", address);

	//debug_print("%p %lx\n", &ss_mem, address);
	//asm volatile("movq %%rsp, %0\n" :"=m"(address) ::"memory");
	//asm volatile("movq %0,%%rsp\n": :"r"(address): "memory");
	//debug_print("%p %lx\n", &ss_mem, address);

	//asm volatile("clflush %%rsp" : : );
	asm volatile("clflush (%0)" : : "b" (address));
}

/*64bit mode page fault   PF
fail
*/
void cache_test_case_clflush_exception_003(void)
{
	u64 address=0;

	debug_print("\n");
	mem_cache_test_read_time_invd(cache_l1_size, 1);
	address = (u64)&cache_test_array;
	address = (((address) + (PAGE_SIZE-1)) & ~(PAGE_SIZE-1)); //page algin

	//set_page_control_bit((void *)address, PAGE_PTE, 0, 0);// not present
	cache_test_case_clflush_all_line(cache_l1_size);
}

/*64bit mode LOCK prefix   UD
* Hypervisor UD
*/
void cache_test_case_clflush_exception_004(void)
{
	debug_print("\n");
	mem_cache_test_read_time_invd(cache_l1_size, 1);
	cache_test_case_clflush_all_line_lock_prefix(cache_l1_size);
}

#elif defined(__i386__)
/*protected mode  For an illegal memory operand effective address in the CS, DS, ES, FS or GS segments   GP(0)*/
void cache_test_case_clflush_exception_005(void)
{
	debug_print("\n");
}

/*protected mode  For an illegal address in the SS segment SS(0)*/
void cache_test_case_clflush_exception_006(void)
{
	debug_print("\n");
}

/*protected mode page fault   PF*/
void cache_test_case_clflush_exception_007(void)
{
	u32 address=0;

	debug_print("\n");
	mem_cache_test_read_time_invd(cache_l1_size, 1);
	address = (u32)&cache_test_array;
	address = (((address) + (PAGE_SIZE-1)) & ~(PAGE_SIZE-1)); //page algin

	set_page_control_bit((void *)address, PAGE_PTE, 0, 0);// not present
	cache_test_case_clflush_all_line(cache_l1_size);
}

/*protected mode LOCK prefix   UD*/
void cache_test_case_clflush_exception_008(void)
{
	debug_print("\n");
	mem_cache_test_read_time_invd(cache_l1_size, 1);
	cache_test_case_clflush_all_line_lock_prefix(cache_l1_size);
}
#else
/*real mode If any part of the operand lies outside the effective address space from 0 to FFFFH. GP*/
void cache_test_case_clflush_exception_009(void)
{
	debug_print("\n");
}

/*real mode LOCK prefix   UD*/
void cache_test_case_clflush_exception_010(void)
{
	debug_print("\n");
	mem_cache_test_read_time_invd(cache_l1_size, 1);
	cache_test_case_clflush_all_line_lock_prefix(cache_l1_size);
}
#endif

void clflush_exception_test()
{
#ifdef __x86_64__
	cache_test_case_clflush_exception_001(); //ok
	cache_test_case_clflush_exception_002(); //fail
	cache_test_case_clflush_exception_003(); //fail
	cache_test_case_clflush_exception_004(); //ok
#elif defined(__i386__)
	cache_test_case_clflush_exception_005();
	cache_test_case_clflush_exception_006();
	cache_test_case_clflush_exception_007();
	cache_test_case_clflush_exception_008();
#else
	cache_test_case_clflush_exception_009();
	cache_test_case_clflush_exception_010();
#endif
}

/*bit 63 set to 1*/
void cache_test_case_clflushopt_all_line_non_canonical(u64 size)
{
	int i;
	unsigned long address;

	for(i=0; i<size; i++){
		address = (unsigned long)(&cache_test_array[i]);
		address = (address|(1UL<<63));
		printf("%lx\n", address);
		asm volatile("clflushopt (%0)" : : "b" (address));
	}
}

void cache_test_case_clflushopt_all_line_lock_prefix_F0(u64 size)
{
	int i=0;

	for(i=0; i<size; i++){
		asm volatile(".byte 0xF0\n\t" "clflushopt (%0)" : : "b" (&cache_test_array[i]));
	}
}

void cache_test_case_clflushopt_all_line_lock_prefix_F2(u64 size)
{
	int i=0;

	for(i=0; i<size; i++){
		asm volatile(".byte 0xF2\n\t" "clflushopt (%0)" : : "b" (&cache_test_array[i]));
	}
}

void cache_test_case_clflushopt_all_line_lock_prefix_F3(u64 size)
{
	int i=0;

	for(i=0; i<size; i++){
		asm volatile(".byte 0xF3\n\t" "clflushopt (%0)" : : "b" (&cache_test_array[i]));
	}
}

#ifdef __x86_64__
/*64bit mode non-canonical   GP
Hypervisor GP OK
*/
void cache_test_case_clflushopt_exception_001(void)
{
	debug_print("\n");
	mem_cache_test_read_time_invd(cache_l1_size, 1);
	cache_test_case_clflushopt_all_line_non_canonical(cache_l1_size);
}

/*64bit mode non-canonical   SS   SS segment
* fail
*/
void cache_test_case_clflushopt_exception_002(void)
{
	u64 ss_mem;
	unsigned long address;

	debug_print("\n");
	ss_mem = 0x1122334455667788;

	address = (unsigned long)(&ss_mem);
	address = (address|(1UL<<63));
	printf("%lx\n", address);

	asm volatile("clflushopt (%0)" : : "b" (address));
}

/*64bit mode page fault   PF
* fail
*/
void cache_test_case_clflushopt_exception_003(void)
{
	u64 address=0;

	debug_print("\n");
	mem_cache_test_read_time_invd(cache_l1_size, 1);
	address = (u64)&cache_test_array;
	address = (((address) + (PAGE_SIZE-1)) & ~(PAGE_SIZE-1)); //page algin

	set_page_control_bit((void *)address, PAGE_PTE, 0, 0);// not present
	cache_test_case_clflushopt_all_line(cache_l1_size);
}

/*64bit mode LOCK prefix F2  UD
Hypervisor UD ok
*/
void cache_test_case_clflushopt_exception_004(void)
{
	debug_print("\n");
	mem_cache_test_read_time_invd(cache_l1_size, 1);
	cache_test_case_clflushopt_all_line_lock_prefix_F2(cache_l1_size);
}

/*64bit mode LOCK prefix F3  UD
Hypervisor UD ok
*/
void cache_test_case_clflushopt_exception_005(void)
{
	debug_print("\n");
	mem_cache_test_read_time_invd(cache_l1_size, 1);
	cache_test_case_clflushopt_all_line_lock_prefix_F3(cache_l1_size);
}

/*64bit mode LOCK prefix  F0 UD
Hypervisor UD oks
*/
void cache_test_case_clflushopt_exception_014(void)
{
	debug_print("\n");
	mem_cache_test_read_time_invd(cache_l1_size, 1);
	cache_test_case_clflushopt_all_line_lock_prefix_F0(cache_l1_size);
}

#elif defined(__i386__)
/*protected mode  For an illegal memory operand effective address in the CS, DS, ES, FS or GS segments   GP(0)*/
void cache_test_case_clflushopt_exception_006(void)
{
	debug_print("\n");
}

/*protected mode  For an illegal address in the SS segment SS(0)*/
void cache_test_case_clflushopt_exception_007(void)
{
	debug_print("\n");
}

/*protected mode page fault   PF*/
void cache_test_case_clflushopt_exception_008(void)
{
	u32 address=0;

	debug_print("\n");
	mem_cache_test_read_time_invd(cache_l1_size, 1);
	address = (u32)&cache_test_array;
	address = (((address) + (PAGE_SIZE-1)) & ~(PAGE_SIZE-1)); //page algin

	set_page_control_bit((void *)address, PAGE_PTE, 0, 0);// not present
	cache_test_case_clflushopt_all_line(cache_l1_size);
}

/*protected mode LOCK prefix  F2 UD*/
void cache_test_case_clflushopt_exception_009(void)
{
	debug_print("\n");
	mem_cache_test_read_time_invd(cache_l1_size, 1);
	cache_test_case_clflushopt_all_line_lock_prefix_F2(cache_l1_size);
}

/*protected mode LOCK prefix  F3 UD*/
void cache_test_case_clflushopt_exception_010(void)
{
	debug_print("\n");
	mem_cache_test_read_time_invd(cache_l1_size, 1);
	cache_test_case_clflushopt_all_line_lock_prefix_F3(cache_l1_size);
}

/*protected mode LOCK prefix  F0 UD*/
void cache_test_case_clflushopt_exception_015(void)
{
	debug_print("\n");
	mem_cache_test_read_time_invd(cache_l1_size, 1);
	cache_test_case_clflushopt_all_line_lock_prefix_F0(cache_l1_size);
}

#else
/*real mode If any part of the operand lies outside the effective address space from 0 to FFFFH. GP*/
void cache_test_case_clflushopt_exception_011(void)
{
	debug_print("\n");
}

/*real mode LOCK prefix  F2 UD*/
void cache_test_case_clflushopt_exception_012(void)
{
	debug_print("\n");
	mem_cache_test_read_time_invd(cache_l1_size, 1);
	cache_test_case_clflushopt_all_line_lock_prefix_F2(cache_l1_size);
}

/*real mode LOCK prefix  F3 UD*/
void cache_test_case_clflushopt_exception_013(void)
{
	debug_print("\n");
	mem_cache_test_read_time_invd(cache_l1_size, 1);
	cache_test_case_clflushopt_all_line_lock_prefix_F3(cache_l1_size);
}

/*real mode LOCK prefix  F0 UD*/
void cache_test_case_clflushopt_exception_016(void)
{
	debug_print("\n");
	mem_cache_test_read_time_invd(cache_l1_size, 1);
	cache_test_case_clflushopt_all_line_lock_prefix_F0(cache_l1_size);
}

#endif


void clflushopt_exception_test()
{
#ifdef __x86_64__
	cache_test_case_clflushopt_exception_001();	//ok
	cache_test_case_clflushopt_exception_002();	//fail
	cache_test_case_clflushopt_exception_003();	//fail
	cache_test_case_clflushopt_exception_004();	//ok
	cache_test_case_clflushopt_exception_005();	//ok
	cache_test_case_clflushopt_exception_014();	//ok
#elif defined(__i386__)
	cache_test_case_clflushopt_exception_006();
	cache_test_case_clflushopt_exception_007();
	cache_test_case_clflushopt_exception_008();
	cache_test_case_clflushopt_exception_009();
	cache_test_case_clflushopt_exception_010();
	cache_test_case_clflushopt_exception_015();
#else
	cache_test_case_clflushopt_exception_011();
	cache_test_case_clflushopt_exception_012();
	cache_test_case_clflushopt_exception_013();
	cache_test_case_clflushopt_exception_016();
#endif
}

void exception_test()
{
	//wbinvd_exception_test();
	//invd_exception_test();
	//clflush_exception_test();
	clflushopt_exception_test();
}

#if 0
static void handle_ud(struct ex_regs *regs)
{
	ud = 1;
	regs->rip += isize;
}
#endif

#define CPUID_VENDORSTRING      0U
static uint64_t native_calibrate_tsc(void)
{
	struct cpuid id;
	uint64_t tsc_hz = 0UL;
	uint32_t cpuid_level;

	id = cpuid(CPUID_VENDORSTRING);
	cpuid_level= id.a;
	
	if (cpuid_level >= 0x15U) {
		uint32_t eax_denominator, ebx_numerator, ecx_hz;

		id = cpuid(0x15U);
		eax_denominator = id.a;
		ebx_numerator = id.b;
		ecx_hz= id.c;
		//reserved = id.d;

		if ((eax_denominator != 0U) && (ebx_numerator != 0U)) {
			tsc_hz = ((uint64_t) ecx_hz *
				ebx_numerator) / eax_denominator;
		}
	}

	if ((tsc_hz == 0UL) && (cpuid_level >= 0x16U)) {
		uint32_t eax_base_mhz;
		id = cpuid(0x16U);
		eax_base_mhz = id.a;
		//ebx_max_mhz = id.b;
		//ecx_bus_mhz= id.c;
		//edx = id.d;
		tsc_hz = (uint64_t) eax_base_mhz * 1000000U;
	}

	return tsc_hz;
}
#define min(x, y)	((x) < (y)) ? (x) : (y)
/* Write 1 byte to specified I/O port */
static inline void pio_write8(uint8_t value, uint16_t port)
{
	asm volatile ("outb %0,%1"::"a" (value), "dN"(port));
}
/* Read 1 byte from specified I/O port */
static inline uint8_t pio_read8(uint16_t port)
{
	uint8_t value;

	asm volatile ("inb %1,%0":"=a" (value):"dN"(port));
	return value;
}

static uint64_t pit_calibrate_tsc(uint32_t cal_ms_arg)
{
#define PIT_TICK_RATE	1193182U
#define PIT_TARGET	0x3FFFU
#define PIT_MAX_COUNT	0xFFFFU

	uint32_t cal_ms = cal_ms_arg;
	uint32_t initial_pit;
	uint16_t current_pit;
	uint32_t max_cal_ms;
	uint64_t current_tsc;
	uint8_t initial_pit_high, initial_pit_low;

	max_cal_ms = ((PIT_MAX_COUNT - PIT_TARGET) * 1000U) / PIT_TICK_RATE;
	cal_ms = min(cal_ms, max_cal_ms);

	/* Assume the 8254 delivers 18.2 ticks per second when 16 bits fully
	 * wrap.  This is about 1.193MHz or a clock period of 0.8384uSec
	 */
	initial_pit = (cal_ms * PIT_TICK_RATE) / 1000U;
	initial_pit += PIT_TARGET;
	initial_pit_high = (uint8_t)(initial_pit >> 8U);
	initial_pit_low = (uint8_t)initial_pit;

	/* Port 0x43 ==> Control word write; Data 0x30 ==> Select Counter 0,
	 * Read/Write least significant byte first, mode 0, 16 bits.
	 */

	pio_write8(0x30U, 0x43U);
	pio_write8(initial_pit_low, 0x40U);	/* Write LSB */
	pio_write8(initial_pit_high, 0x40U);		/* Write MSB */

	current_tsc = rdtsc();

	do {
		/* Port 0x43 ==> Control word write; 0x00 ==> Select
		 * Counter 0, Counter Latch Command, Mode 0; 16 bits
		 */
		pio_write8(0x00U, 0x43U);

		current_pit = (uint16_t)pio_read8(0x40U);	/* Read LSB */
		current_pit |= (uint16_t)pio_read8(0x40U) << 8U;	/* Read MSB */
		/* Let the counter count down to PIT_TARGET */
	} while (current_pit > PIT_TARGET);

	current_tsc = rdtsc() - current_tsc;

	return (current_tsc / cal_ms) * 1000U;
}

#define CAL_MS			10U
static uint32_t tsc_khz = 0U;
void calibrate_tsc(void)
{
	uint64_t tsc_hz;
	tsc_hz = native_calibrate_tsc();
	if (tsc_hz == 0U) {
		tsc_hz = pit_calibrate_tsc(CAL_MS);
	}
	tsc_khz = (uint32_t)(tsc_hz / 1000UL);
	printf("%s, ************ tsc_khz=0x%x\n", __func__, tsc_khz);
}

int main(int ac, char **av)
{
#if 1	//wbinvd invd ring3 need
	extern unsigned char kernel_entry;

	setup_idt();
	set_idt_entry(0x20, &kernel_entry, 3);
#endif
	//default PAT entry value 0007040600070406
	//mem_cache_test_set_type_all(0x0000000001040506);
	//setup_vm();
	//setup_idt();
	//smp_init();
	//setup_idt();
	//handle_exception(UD_VECTOR, handle_ud);
	//write_cr4_bybit(CR4_BIT_PGE, 0);
	//write_cr0_bybit(CR0_BIT_PG, 0);
	test_register_get();
	calibrate_tsc();

	cache_test_array = (u64 *)malloc(cache_over_l3_size2*8);
	if(cache_test_array==NULL){
		debug_print("malloc error\n");
		return -1;
	}
	debug_print("cache_test_array=%p\n", cache_test_array);
	
	//cache_test_case_cpuid4();
	//cache_test_case_invd();
	//cache_test_case_CD_NW_control();
	//cache_test_case_l3_control();
	//cache_test_case_clflush_001();
	//cache_test_case_clflush_002(41);
	//cache_test_case_clflush_003(41);
	
	//cache_test_case_clflushopt_001();
	//cache_test_case_clflushopt_002(41);
	//cache_test_case_clflushopt_003(41);
	//cache_test_case_l1_control();
	//cache_test_case_MTRR_general();
	//cache_test_case_MTRR_fixed();
	//cache_test_case_MTRR_WC();
	//cache_test_case_MTRR_SMRR();
	//cache_test_case_MTRR_VR();
	//cache_test_case_invalidation_001();
	//cache_test_case_invalidation_002(41);
	//cache_test_case_invalidation_003(41);
	//cache_test_case_CLWB();
	//cache_test_case_PREFETCHW();

	//alloc_ops = &vmalloc_ops_type_2;
	//phys_alloc_show();
	//memset(cache_test_array, 0, cache_over_l3_size2*8);

#ifdef __x86_64__
	//cache_test_case_no_fill_cache(3);
	//cache_test_case_map_to_device_linear(3);
	//cache_test_case_map_to_none_linear(3);	//blocking
	//cache_test_case_map_to_memory_linear(3);
#else
	//cache_test_case_map_to_device_physical(3);
	//cache_test_case_map_to_none_physical(3);
#endif
	exception_test();
	debug_print("mem cache control memory malloc success\n");
	//test_cache_type();

	//free(cache_test_array);
	//cache_test_array = NULL;

	return report_summary();
}
