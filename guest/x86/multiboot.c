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

extern u32 bp_esi;


/** Defines a single entry in an E820 memory map. */
struct e820_entry {
   /** The base address of the memory range. */
	uint64_t baseaddr;
   /** The length of the memory range. */
	uint64_t length;
   /** The type of memory region. */
	uint32_t type;
} __packed;

/* The real mode kernel header, refer to Documentation/x86/boot.txt */
struct _zeropage {
	uint8_t pad1[0x1e8];                    /* 0x000 */
	uint8_t e820_nentries;                  /* 0x1e8 */
	uint8_t pad2[0x8];                      /* 0x1e9 */

	struct	{
		uint8_t hdr_pad1[0x1f];         /* 0x1f1 */
		uint8_t loader_type;            /* 0x210 */
		uint8_t load_flags;             /* 0x211 */
		uint8_t hdr_pad2[0x2];          /* 0x212 */
		uint32_t code32_start;          /* 0x214 */
		uint32_t ramdisk_addr;          /* 0x218 */
		uint32_t ramdisk_size;          /* 0x21c */
		uint8_t hdr_pad3[0x8];          /* 0x220 */
		uint32_t bootargs_addr;         /* 0x228 */
		uint8_t hdr_pad4[0x3c];         /* 0x22c */
	} __attribute__((packed)) hdr;

	uint8_t pad3[0x68];                     /* 0x268 */
	struct e820_entry e820[0x80];           /* 0x2d0 */
	uint8_t pad4[0x330];                    /* 0xcd0 */
} __attribute__((packed));


int main(int ac, char **av)
{
	setup_vm();
	debug_print("esi=0x%x\n", bp_esi);

	 unsigned char mac[6]={0xFF, 0x3F, 0xFF, 0x20, 0xae, 0xbd};

	 
	debug_print("0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
		
	unsigned char * point = (unsigned char *)((intptr_t)bp_esi);
	debug_print("magic number =0x%x, 0x%x, addr=%p, %p\n", point[0x01FE], point[0x01FF], &point[0x01FE], &point[0x01FF]);
	debug_print("Magic signature =0x%x, 0x%x, 0x%x, 0x%x\n", point[0x0202], 
		point[0x0203], point[0x0204], point[0x0205]);
	
	struct _zeropage *zeropage = (struct _zeropage *)((intptr_t)bp_esi);

	debug_print("hdr_pad1:%s\n", zeropage->hdr.hdr_pad1);
	return report_summary();
}
