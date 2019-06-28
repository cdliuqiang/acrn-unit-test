#include "libcflat.h"
#include "processor.h"
#include "xsave_feature.h"
#include "desc.h"
#include "desc.c"
#include "alloc.h"

//#include "xmmintrin.h"
//#include <x86intrin.h>

#define DS_SEL 0xFFFF


__attribute__((aligned(64))) struct xsave_st g_xsave_struct[XSAVE_AREA_SIZE]; 

int do_at_ring3(void (*fn)(void), const char *arg)
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

/*static int xgetbv_checking(u32 index, u64 *result)
{
    u32 eax, edx;

    asm volatile(ASM_TRY("1f")
            ".byte 0x0f,0x01,0xd0\n\t"
            "1:"
            : "=a" (eax), "=d" (edx)
            : "c" (index));
    *result = eax + ((u64)edx << 32);
    return exception_vector();
}*/

/*static int xsetbv_checking(u32 index, u64 value)
{
	u32 eax = value;
	u32 edx = value >> 32;

	asm volatile(ASM_TRY("1f")
		     "xsetbv\n\t" 
		     "1:"
		     : : "a" (eax), "d" (edx), "c" (index));
	return exception_vector();
}*/

/*
static int xsave_checking(struct xsave_st *xsave_array, u64 xcr0)
{
	u32 eax = xcr0;
	u32 edx = xcr0 >> 32;

	asm volatile(ASM_TRY("1f")
		     "xsave %[addr]\n\t" 
		     "1:"
		     : : [addr]"m"(xsave_array->num_xsave), "a"(eax), "d"(edx)
		     : "memory");
	
	return exception_vector();
}
*/
/*
static int xsaves_checking(struct xsave_st *xsave_array, u64 xcr0)
{
	u32 eax = xcr0;
	u32 edx = xcr0 >> 32;

	asm volatile(ASM_TRY("1f")
		     "xsaves %[addr]\n\t" 
		     "1:"
		     : : [addr]"m"(xsave_array->num_xsave), "a"(eax), "d"(edx)
		     : "memory");
	
	return exception_vector();
}
*/

/*static int xsavec_checking(struct xsave_st *xsave_array, u64 xcr0)
{
	u32 eax = xcr0;
	u32 edx = xcr0 >> 32;

	asm volatile(ASM_TRY("1f")
		     "xsavec %[addr]\n\t" 
		     "1:"
		     : : [addr]"m"(xsave_array->num_xsave), "a"(eax), "d"(edx)
		     : "memory");
	
	return exception_vector();
}*/

/*static int xsaveopt_checking(struct xsave_st *xsave_array, u64 xcr0)
{
	u32 eax = xcr0;
	u32 edx = xcr0 >> 32;

	asm volatile(ASM_TRY("1f")
		     "xsaveopt %[addr]\n\t" 
		     "1:"
		     : : [addr]"m"(xsave_array->num_xsave), "a"(eax), "d"(edx)
		     : "memory");
	
	return exception_vector();
}*/

/*static int rdmsr_checking(u32 MSR_ADDR, u64 *result)
{
	u32 eax;
	u32 edx;

	asm volatile(ASM_TRY("1f")
		     "rdmsr \n\t" 
		     "1:"
		     : "=a"(eax), "=d"(edx): "c"(MSR_ADDR));
	*result = eax + ((u64)edx << 32);
	return exception_vector();
}*/
/*
static int wrmsr_checking(u32 MSR_ADDR, u64 value)
{
	u32 edx = value >> 32;
	u32 eax = value;

	asm volatile(ASM_TRY("1f")
		     "wrmsr \n\t" 
		     "1:"
		     : : "c"(MSR_ADDR), "a"(eax), "d"(edx));
	return exception_vector();
}

static int xrstor_checking(struct xsave_st *xsave_array, u64 xcr0)
{
	u32 eax = xcr0;
	u32 edx = xcr0 >> 32;

	asm volatile(ASM_TRY("1f")
		     "xrstor %[addr]\n\t" 
		     "1:"
		     : : [addr]"m"(xsave_array->num_xsave), "a"(eax), "d"(edx)
		     : "memory");

	return exception_vector();
}

static int xrstors_checking(struct xsave_st *xsave_array, u64 xcr0)
{
	u32 eax = xcr0;
	u32 edx = xcr0 >> 32;

	asm volatile(ASM_TRY("1f")
		     "xrstors %[addr]\n\t" 
		     "1:"
		     : : [addr]"m"(xsave_array->num_xsave), "a"(eax), "d"(edx)
		     : "memory");

	return exception_vector();
}

static int write_cr4_checking(unsigned long val)
{
	asm volatile(ASM_TRY("1f")
	    "mov %0,%%cr4\n\t"
	    "1:": : "r" (val));
	return exception_vector();
}

static int write_cr4_osxsave(u32 bitvalue)
{
	u32 cr4;

	cr4 = read_cr4();
	if (bitvalue) {
		return write_cr4_checking(cr4 | X86_CR4_OSXSAVE);
	} else {
		return write_cr4_checking(cr4 & ~X86_CR4_OSXSAVE);
	}
}

static void write_cr0_ts(u32 bitvalue)
{
	u32 cr0 = read_cr0();
	if (bitvalue) {
		write_cr0(cr0 | X86_CR0_TS);
	} else {
		write_cr0(cr0 & ~X86_CR0_TS);
	}
}

static u32 get_cr4_osxsave(void)
{
	u32 cr4;

	cr4 = read_cr4();
	if (cr4 & X86_CR4_OSXSAVE) {
		return 1;
	} else {
		return 0;
	}
}

static int check_cpuid_1_ecx(unsigned int bit)
{
	return (cpuid(1).c & bit) != 0;
}

static uint64_t get_supported_xcr0(void)
{
	struct cpuid r;
	r = cpuid_indexed(0xd, 0);
	return r.a + ((u64)r.d << 32);
}

static uint64_t get_supported_ia32_xss(void)
{
	struct cpuid r;
	r = cpuid_indexed(0xd, 1);
	return r.c + ((u64)r.d << 32);
}
*/

/* 
 * 1)Every processor that supports the XSAVE feature set will set EAX[0]
 * (x87 state) and EAX[1] (SSE state).
 * 2)XCR0[0] is always 1. Executing the XSETBV instruction causes a general-protection fault (#GP) if ECX = 0 and EAX[0] is 0.
 */
 /*
static void test_case_000(void)
{
	uint64_t test_bits;
	u32 xcr0;
	u32 cr4;

	cr4 = read_cr4();
	if (write_cr4_checking(cr4 | X86_CR4_OSXSAVE) != PASS) {
		printf("\n set cr4.osxsave error! \n");
		return;
	}

	if (xgetbv_checking(XCR0_MASK, &test_bits) != PASS) {
		printf("\n get XCR0 error! \n");
		return;		
	}
	report("\t\t XCR0[0] has 1 value coming out of RESET.",
	       (test_bits & STATE_X87) == 1);
	report("\t\t XCR0[1] is 0 coming out of RESET",
	       (test_bits & STATE_SSE) == 0);
	report("\t\t XCR0[2] is 0 coming out of RESET",
	       (test_bits & STATE_AVX) == 0);
	report("\t\t XCR0[4:3] have value 00b coming out of RESET.",
	       (test_bits & (STATE_MPX_BNDREGS | STATE_MPX_BNDCSR)) == 0);
	report("\t\t XCR0[7:5] have value 000b coming out of RESET.",
	       (test_bits & STATE_AVX_512) == 0);
	report("\t\t XCR0[9] have value 0 coming out of RESET.",
	       (test_bits & STATE_PKRU) == 0);
	report("\t\t XCR0[8] is reserved.",
	       (test_bits & STATE_PT) == 0);
	report("\t\t XCR0[63:10] in XCR0 are all 0 coming out of RESET. and reserved",
	       (test_bits & XCR0_BIT10_BIT63) == 0);

	test_bits = test_bits & ~(STATE_X87);
	report("\t\t XCR0[0] is always 1. Executing the XSETBV instruction causes a general-protection fault (#GP) if ECX = 0 and EAX[0] is 0 --> GP exception",
	       xsetbv_checking(XCR0_MASK, test_bits) == GP_VECTOR);

	xcr0 = get_supported_xcr0();
	report("\t\t Every processor that supports the XSAVE feature set will set EAX[0] (x87 state) and EAX[1] (SSE state)",
	       (xcr0 & (STATE_X87 | STATE_SSE)) ==
	       (STATE_X87 | STATE_SSE));	
}
*/

/*Modify set_gdt_entry in 32 bit-mode to 64 bit-mode by steven-20190521*/
extern gdt_entry_t gdt64[];
void set_gdt64_entry(int sel, u32 base,  u32 limit, u8 access, u8 gran)
{
	int num = sel >> 3;

	/* Setup the descriptor base address */
	gdt64[num].base_low = (base & 0xFFFF);
	gdt64[num].base_middle = (base >> 16) & 0xFF;
	gdt64[num].base_high = (base >> 24) & 0xFF;

	/* Setup the descriptor limits */
	gdt64[num].limit_low = (limit & 0xFFFF);
	gdt64[num].granularity = ((limit >> 16) & 0x0F);

	/* Finally, set up the granularity and access flags */
	gdt64[num].granularity |= (gran & 0xF0);
	gdt64[num].access = access;
}

//write immedite to DS
void write_value_to_ds_offfset(void)
{
	asm volatile("mov $0xffffffff,%rax\n\r mov %ds:0xffffffff,%rax\n\r");
}

// load the GDT to 
void load_gdt_and_set_segment_rigster(void)
{
	asm volatile("lgdt gdt64_desc\n"
				"mov $0x10, %ax\n"
				"mov %ax, %ds\n"
				"mov %ax, %es\n"
				"mov %ax, %fs\n"
				"mov %ax, %gs\n"
				"mov %ax, %ss\n"
				);
}


static void test_dry_run_steven_DE(void)
{
	
	u16 *tmp_16 = (u16 *)malloc(sizeof(u16));
	u32 *tmp_32 = (u32 *)malloc(sizeof(u32));
	*tmp_16 = 0;
	*tmp_32 = 0;
	
	asm volatile("MOV %0, %%AX\n": :"m"(tmp_16));
	asm volatile("DIV %AX\n");
	//asm volatile("DIV (%[tmp_16])"::[tmp_16]"r"(tmp_16));
	//asm volatile("DIV %0\n" : :"m"(tmp_32):"memory");
	printf("Step1: Instruction: DIV, the divsor is 0\n");
}

static void test_dry_run_steven_LDS_UD_OprandNotMemroy(void)
{
	
	//u16 *tmp_16 = (u16 *)malloc(sizeof(u16));
	//u32 *tmp_32 = (u32 *)malloc(sizeof(u32));
	//*tmp_16 = 0;
	//*tmp_32 = 0;
	printf("Step1: Instruction: LDS, with the source oprand is not memory.\n");
	//asm volatile("LED %%EAX, %%EBX\n"); //Result: Compile error
	printf("Step2: Instruction: LDS, pass.\n");
}

static void test_dry_run_steven_JMP_UD(void)
{
	//u64 *data_add = (u64 *)0x00cf93000000ffff;
	u64 *data_add = (u64 *)0x000000000048e520;
	//u64 *data_add = (u64 *)test_dry_run_steven_JMP_UD;
	//u32 *data_add = (u32 *)0x930000ff;

	printf("Step1: UD: JMP with the absolute address in memory.\n");
	//asm volatile("jmp %[data_add]\n": :[data_add]"m"(data_add));
	asm volatile(".byte 0xea, 0x20, 0xe5, 0x48, 0xe8, 0x9d, 0xfe");
	//asm volatile(".byte 0xEA, 0x20, 0xe5, 0x48": : );
	//asm volatile(".byte 0xEA, 0xd8, 0xd8, 0x40": : );
	//asm volatile("ljmp %0,$0\n": :"m"(data_add));
	//asm volatile("ljmpl $0xc,$0\n": :"m"(data_add));
	//asm volatile("ljmpl (0x930000ff)\n");
	printf("Step2: Instruction: JMP, pass.\n");
}

static void test_dry_run_steven_CALL_UD(void)
{
	u64 *data_add = (u64 *)0x00cf93000000ffff;
	//u64 *data_add = (u64 *)0x000000000048e520;
	//u64 *data_add = (u64 *)test_dry_run_steven_JMP_UD;
	//u32 *data_add = (u32 *)0x930000ff;

	printf("Step1: UD: CALL with the absolute address in memory.\n");
	//asm volatile("CALL %[data_add]\n": :[data_add]"m"(data_add));
	asm volatile(".byte 0x9a, 0x20, 0xe5, 0x48, 0xe8, 0x9d, 0xfe");
	//asm volatile(".byte 0xea, 0x20, 0xe5, 0x48, 0xe8, 0x9d, 0xfe");
	//asm volatile(".byte 0xEA, 0x20, 0xe5, 0x48": : );
	printf("Step2: Instruction: CALL, pass.\n");
}



//Move to/from Control Registers
static void test_dry_run_steven_MOV2CR1_UD(void)
{
	//u64 *data_add = (u64 	*)0x00cf93000000ffff;
	//u64 *data_add = (u64 *)0x000000000048e520;
	u64 *data_add = (u64 *)test_dry_run_steven_JMP_UD;
	//u32 *data_add = (u32 *)0x930000ff;

	printf("Step1: UD: MOV2CR1.\n");
	asm volatile("mov %%cr1, %%" R "ax\n": : :);
	//asm volatile("mov %%" R "ax," "%0" :"=m"(ptr->rax)::"memory"); 
	//asm volatile(".byte 0xEA, 0x20, 0xe5, 0x48": : );
	//asm volatile(".byte 0xEA, 0xd8, 0xd8, 0x40": : );
	//asm volatile("ljmp %0,$0\n": :"m"(data_add));
	//asm volatile("ljmpl $0xc,$0\n": :"m"(data_add));
	//asm volatile("ljmpl (0x930000ff)\n");
	printf("Step2: Instruction: JMP, pass.\n");
}


static void AVX_AVX_expose_execution_environment_#PF_001_VPADDQ (void)
{
	//u64 *data_add = (u64 	*)0x00cf93000000ffff;
	//u64 *data_add = (u64 *)0x000000000048e520;
	u64 *data_add = (u64 *)test_dry_run_steven_JMP_UD;
	//u32 *data_add = (u32 *)0x930000ff;

	printf("Step1: UD: MOV2CR1.\n");
	asm volatile("mov %%cr1, %%" R "ax\n": : :);
	//asm volatile("mov %%" R "ax," "%0" :"=m"(ptr->rax)::"memory"); 
	//asm volatile(".byte 0xEA, 0x20, 0xe5, 0x48": : );
	//asm volatile(".byte 0xEA, 0xd8, 0xd8, 0x40": : );
	//asm volatile("ljmp %0,$0\n": :"m"(data_add));
	//asm volatile("ljmpl $0xc,$0\n": :"m"(data_add));
	//asm volatile("ljmpl (0x930000ff)\n");
	printf("Step2: Instruction: JMP, pass.\n");
}



static void test_dry_run_steven_GDT(void)
{
	//dry-run print CPUID
	//u32 xsave_area_size;
	//u64 ds_val=0x0;

#if 0
//CPUID_steven	
	printf("Step1: Get CPUID that is the processor defult-support\n");
	uint64_t supported_xcr0;
	supported_xcr0 = get_supported_xcr0();
	printf("The supported CPUID = %lu\nThe supported CPUID = 0x%lx\n", supported_xcr0, supported_xcr0);
#endif


#if 0
//_GDT_POP_instrution_generate_GP_steven
	printf("Step2: Set gdt64 limite\n ");
	set_gdt64_entry(DS_SEL, 0, 0xc000f, 0x93, 0);
	
	printf("Step3: load gdt to lgdtr\n ");
	load_gdt_and_set_segment_rigster();
	
	printf("Step4: mov immedite to the modified DS\n ");
	write_value_to_ds_offfset();
	
	printf("Step5: push %rax\n ");
	asm volatile("push %rax\n");
	
	//printf("Step5: pop to DS\n ");
	//asm volatile("pop %ds\n");

	printf("Step5: pop to SS\n ");
	//u32 char* ss_segment;
	asm volatile("tmpss:\n\r" ".quad 0,0\n" );
	asm volatile("mov tmpss, %sp\n");
	//asm volatile("mov 0x12345678, %ss\n");
	//asm volatile("pop %ss:0\n");
	printf("Step6: push %rax\n ");
	asm volatile("push %rax\n");
	
	//printf("Step6: read-ds:0xffffff.\n ");
	//asm volatile("mov %%ds:0xffffffff,%%rax\n"
	//	"mov %%rax, %0":"=m"(ds_val)::);
	//printf("ds= %x.\n ", ds_val);
	
	printf("Step6: Exception need to generated, Test end.\n ");
#endif

#if 0
// Address canonical generate #GP
	u64 data_add;
	data_add = (float *)0xffbffffffffff010;
	printf("\n --data_add:%lx\n", data_add);
	asm volatile("fld %0": : "m"( *(data_add)): "memory") 
#endif
//#if 0
// Address canonical generate #SS

	//set_gdt_entry(0x10, 0x0, 0xfffff, 0x13,0xc0 ); // 0 001 0011  p=clear
	
	//load_gdt_and_set_segmsent_rigster(REG_SS,index);

	//asm volatile("memoryss : \n" ".long 0\n");
	//asm volatile("mov $memoryss,%esp \n" "  push %ebx ");
	
	//u64 *data_add = (u64 *)0xffbffffffffff010;
	//u64 *data_add = (u64 *)0xfbff9b000000ffff; //20190604-new
	u64 *data_add = (u64 *)0xffbffffffffff010;


	//asm volatile("movq %%rsp, %0\n":"m"( :"r"(*data_add): "memory");
	//asm volatile("movq %0,%%rsp\n": :"r"(*data_add): "memory");
	asm volatile("mov %[data_add],%%rsp\n": :[data_add]"m"(data_add): "memory");
	//asm volatile("movq %%mm0,%rsp\n");

	//asm volatile("push %rbx\n");
	asm volatile(ASM_TRY("1f")
		    "pushq %%rbx\n\t"
		    "1:"
		    :
		    :
		    );
	
	//asm volatile("pop ($0xffbffffffffff010)");
	//asm volatile("fld %0": : "m"( *(data_add)): "memory");
	
	//asm volatile("pop %[data_add]\n": [data_add]"=m"(*data_add): : "memory");
	/*asm volatile(ASM_TRY("1f")
			    "pop %[data_add]\n"
			    "1:"
			    :[data_add]"=m"(*data_add)
			    :
			    :"memory"
			    );

	*/
	//asm volatile("push %[data_add]\n": :[data_add]"r"(*data_add): "memory");
	//asm volatile(".byte 0xff, 0x00" : :[data_add]"r"(*data_add): "memory");
	

	//printf("mov Inv address to esp,and execute push\n");
	//asm volatile("mov $0xffbffffffffff010,%rax \n"); 
	//asm volatile("mov %rax,%esp \n" "push %ebx ");
//#endi

#if 0
//AVX_UD_Exception
	u64 i = 0
	
	char *p = __attribute__ ((aligned (256)))malloc(32);
	asm volatile("VMOVAPS %ymm1, %0":"=m"(p)::"memory");
	printf("the *p val is %s\n", p);
#endif
	
#if 0
	/* lea Gv, M*/
	//asm volatile(ASM_TRY("1f")
	//"lea %%ecx, %%eax \n\t" 
	//"1:"
	//: : );
	u32 a = 10;
	printf("Run lea instruction\n");
	//asm volatile(".byte 0x66,0x67,0x8d,0xff" : : );
	asm volatile("lea %0, %%eax \n\t": :"val"(a));	
#endif
	
}


/*static void test_xsave(void)
{
	//test_case_040_steven();
	test_dry_run_steven_GDT();
	return;
	test_case_000();
}*/

/*static void test_no_xsave(void)
{
    unsigned long cr4;
    u64 xcr0;
    

    //report("Check CPUID.1.ECX.OSXSAVE - expect 0",
	//check_cpuid_1_ecx(CPUID_1_ECX_OSXSAVE) == 0);

    printf("Illegal instruction testing:\n");

    cr4 = read_cr4();
    //eport("Set OSXSAVE in CR4 - expect #GP",
	//write_cr4_checking(cr4 | X86_CR4_OSXSAVE) == GP_VECTOR);

    report("Execute xgetbv - expect #UD",
	xgetbv_checking(XCR0_MASK, &xcr0) == UD_VECTOR);

    report("Execute xsetbv - expect #UD",
	xsetbv_checking(XCR0_MASK, 0x3) == UD_VECTOR);
}*/

int main(void)
{
	extern unsigned char kernel_entry;
		
	setup_idt();
	set_idt_entry(0x20, &kernel_entry, 3);

	test_dry_run_steven_CALL_UD();

	//test_dry_run_steven_JMP_UD();
	//do_at_ring3(test_dry_run_steven_JMP_UD, "");
	//test_dry_run_steven_MOV2CR1_UD();
	//test_dry_run_steven_LDS_UD_OprandNotMemroy();
	//test_dry_run_steven_DE();
	//test_dry_run_steven_GDT();
	//do_at_ring3(test_dry_run_steven_GDT, "");
	
	/*if (check_cpuid_1_ecx(CPUID_1_ECX_XSAVE)) {
		printf("CPU has XSAVE feature\n");
		test_xsave();
	} else {
		printf("CPU don't has XSAVE feature\n");
		test_no_xsave();
	}
	*/
	return report_summary();
}

