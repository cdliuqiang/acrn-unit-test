/*
 * Test for x86 cache and memory instructions
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

#define MP_BIOS_ADDR   (0x0F0000)

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

#pragma pack(1)
typedef struct{
   char   signature[4];
   uint32 address_point;
   uint8  length;
   uint8  spec_rev;
   uint8  check_sum;
   uint8  mp_byte1;
   uint8  mp_byte2;
   uint8  mp_reserv_byte[3];
}MP_FLOAT_POINTER;

typedef struct{
    char   signature[4];
    uint16 base_table_len;
    uint8  spec_rev;
    uint8  check_sum;
    char   oem_string[8];
    char   product_string[12];
    uint32 oem_table_pointer;
    uint16 oem_table_size;
    uint16 oem_entry_count;
    uint32 local_apic_map_addr;
    uint16 extend_table_len;
    uint8  extend_table_checksum;
    uint8  reserved;
}MP_CONFIG_TABLE_HEADER;

typedef enum{
   MP_ENTRY_PROCESSOR = 0,
   MP_ENTRY_BUS       = 1,
   MP_ENTRY_APIC      = 2,
   MP_ENTRY_IO_INT    = 3,
   MP_ENTRY_LOCAL_INT = 4
}MP_CONFIG_ENTRY_TYPE;

typedef struct{
   uint8  entry_type;
   uint8  local_apic_id;
   uint8  local_apic_ver;
   uint8  cpu_flags;
   uint32 cpu_signature;
   uint32 feature_flags;
   uint32 reserved1;
   uint32 reserved2;
}PROCESSOR_ENTRY;

typedef struct{
   uint8  entry_type;
   uint8  bus_id;
   char   bus_type_str[6];
}BUS_ENTRY;

typedef struct{
   uint8  entry_type;
   uint8  apic_id;
   uint8  apic_ver;
   uint8  apic_flags;
   uint32 mm_address;
}APIC_ENTRY;

typedef struct{
   uint8  entry_type;
   uint8  int_type;
   uint16 int_flags;
   uint8  source_bus_id;
   uint8  source_bus_irq;
   uint8  des_apic_id;
   uint8  des_apic_intin;
}IO_INT_ENTRY;

typedef struct{
   uint8  entry_type;
   uint8  int_type;
   uint16 local_int_flags;
   uint8  source_bus_id;
   uint8  source_bus_irq;
   uint8  des_apic_id;
   uint8  des_apic_intin;
}LOCAL_INT_ENTRY;
#pragma pack()


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


int get_zeropage(int ac, char **av)
{
	u32 bp_esi;
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


void print_mp_float_pointer_info( MP_FLOAT_POINTER *pointer )
{
   if( 0 == pointer )
   {
      debug_print( "invalid pointer\n" );
      return;
   }
   debug_print( "pinter address %p \n", pointer );
   debug_print( "signature: %c%c%c%c\n", pointer->signature[0], pointer->signature[1], pointer->signature[2], pointer->signature[3] );
   debug_print( "address_point: 0x%08x\n", pointer->address_point );
   debug_print( "length: %d \n", pointer->length );
   debug_print( "spec_rev: %d \n", pointer->spec_rev );
   debug_print( "check_sum: %d \n", pointer->check_sum );
   debug_print( "mp_byte1: %d \n", pointer->mp_byte1 );
   debug_print( "mp_byte2: %d \n", pointer->mp_byte2 );
   debug_print( "mp_reserv_byte: %d %d %d \n",  pointer->mp_reserv_byte[0], pointer->mp_reserv_byte[1], pointer->mp_reserv_byte[2] );
   uint32 i = 0;
   uint8 *p = (uint8 *)pointer;
   debug_print( "MP float pointer data: " );
   for( i=0; i<16; i++ )
   {
      debug_print( "%x ", *p++ );
   }
   debug_print( "\n" );
}

void print_mp_table_header_info( MP_CONFIG_TABLE_HEADER *header )
{
   uint32 i;
   if( 0 == header )
   {
       debug_print( "invalid pointer\n" );
       return;
   }
   debug_print( "header address %p \n", header );
   char *oem_str = header->oem_string;
   char *product_str = header->product_string;

   debug_print( "signature: %c%c%c%c\n", header->signature[0], header->signature[1], header->signature[2], header->signature[3] );
   debug_print( "base_table_len: %d\n", header->base_table_len );
   debug_print( "spec_rev: %d\n", header->spec_rev );
   debug_print( "check_sum: %d\n", header->check_sum );
   debug_print( "oem_string :" );
   for( i=0; i<8; i++ )
   {
       debug_print( "%c", *oem_str++ );
   }
   debug_print( "\n" );
   debug_print( "product_string :" );
   for( i=0; i<12; i++ )
   {
       debug_print( "%c", *product_str++ );
   }
   debug_print( "\n" );
   debug_print( "oem_table_pointer: 0x%08x\n", header->oem_table_pointer );
   debug_print( "oem_table_size: %d\n", header->oem_table_size );
   debug_print( "entry_count: %d\n", header->oem_entry_count );
   debug_print( "local_apic_map_addr: 0x%08x\n", header->local_apic_map_addr );
   debug_print( "extend_table_len: %d\n", header->extend_table_len );
   debug_print( "extend_table_checksum: %d\n", header->extend_table_checksum );
   debug_print( "reserved: %d\n", header->reserved );

   uint8 *p = (uint8 *)header;
   debug_print( "dump: " );
   for( i=0; i<sizeof(MP_CONFIG_TABLE_HEADER); i++ )
   {
      debug_print( "%x ", *p++ );
   }
   debug_print( "\n" );
}

void print_processor_entry_info( PROCESSOR_ENTRY *entry )
{
   if( 0 == entry )
   {
       debug_print( "invalid pointer\n" );
       return;
   }
   debug_print( "entry_type: %d \n", entry->entry_type );
   debug_print( "local_apic_id: 0x%x \n", entry->local_apic_id );
   debug_print( "local_apic_ver: 0x%x \n", entry->local_apic_ver );
   debug_print( "cpu_flags: 0x%x \n", entry->cpu_flags );
   debug_print( "cpu_signature: 0x%x\n", entry->cpu_signature );
   debug_print( "feature_flags: 0x%x\n", entry->feature_flags );
   debug_print( "reserved1: 0x%x\n", entry->reserved1 );
   debug_print( "reserved2: 0x%x\n", entry->reserved2 );

   uint32 i = 0;
   uint8 *p = (uint8 *)entry;
   debug_print( "dump: " );
   for( i=0; i<sizeof(PROCESSOR_ENTRY); i++ )
   {
      debug_print( "%x ", *p++ );
   }
   debug_print( "\n" );
}

void print_bus_entry_info( BUS_ENTRY *entry )
{
   uint32 i;
   char   *p;
   if( 0 == entry )
   {
       debug_print( "invalid pointer\n" );
       return;
   }
   debug_print( "entry_type: %d \n", entry->entry_type );
   debug_print( "bus_id: %d \n", entry->bus_id );
   debug_print( "bus_type_string:" );
   p = entry->bus_type_str;
   for( i=0; i<6; i++ )
   {
       debug_print( "%c", *p++ );
   }
   debug_print( "\n" );

   uint8 *pt = (uint8 *)entry;
   debug_print( "dump: " );
   for( i=0; i<sizeof(BUS_ENTRY); i++ )
   {
      debug_print( "%x ", *pt++ );
   }
   debug_print( "\n" );
}

void print_apic_entry_info( APIC_ENTRY *entry )
{
   if( 0 == entry )
   {
       debug_print( "invalid pointer\n" );
       return;
   }
   debug_print( "entry_type: %d \n", entry->entry_type );
   debug_print( "apic_id: %d \n", entry->apic_id );
   debug_print( "apic_ver: %d\n", entry->apic_ver );
   debug_print( "apic_flags: %d\n", entry->apic_flags );
   debug_print( "mm_address: 0x%08x\n", entry->mm_address );

   uint32 i = 0;
   uint8 *p = (uint8 *)entry;
   debug_print( "dump: " );
   for( i=0; i<sizeof(APIC_ENTRY); i++ )
   {
      debug_print( "%x ", *p++ );
   }
   debug_print( "\n" );
}

void print_io_int_entry_info( IO_INT_ENTRY *entry )
{
   if( 0 == entry )
   {
       debug_print( "invalid pointer\n" );
       return;
   }
   debug_print( "entry_type: %d \n", entry->entry_type );
   debug_print( "int_type: %d \n", entry->int_type );
   debug_print( "int_flags: %d\n", entry->int_flags );
   debug_print( "source_bus_id: %d\n", entry->source_bus_id );
   debug_print( "source_bus_irq: %d\n", entry->source_bus_irq );
   debug_print( "des_apic_id: %d\n", entry->des_apic_id );
   debug_print( "des_apic_intin: %d\n", entry->des_apic_intin );

   uint32 i = 0;
   uint8 *p = (uint8 *)entry;
   debug_print( "dump: " );
   for( i=0; i<sizeof(IO_INT_ENTRY); i++ )
   {
      debug_print( "%x ", *p++ );
   }
   debug_print( "\n" );
}

void print_local_int_entry_info( LOCAL_INT_ENTRY *entry )
{
   if( 0 == entry )
   {
       debug_print( "invalid pointer\n" );
       return;
   }
   debug_print( "entry_type: %d \n", entry->entry_type );
   debug_print( "int_type: %d \n", entry->int_type );
   debug_print( "local_int_flags: %d\n", entry->local_int_flags );
   debug_print( "source_bus_id: %d\n", entry->source_bus_id );
   debug_print( "source_bus_irq: %d\n", entry->source_bus_irq );
   debug_print( "des_apic_id: %d\n", entry->des_apic_id );
   debug_print( "des_apic_intin: %d\n", entry->des_apic_intin );

   uint32 i = 0;
   uint8 *p = (uint8 *)entry;
   debug_print( "dump: " );
   for( i=0; i<sizeof(LOCAL_INT_ENTRY); i++ )
   {
      debug_print( "%x ", *p++ );
   }
   debug_print( "\n" );
}

//static MP_FLOAT_POINTER mp_pointer;
int main(int ac, char **av)
{
   uint8 *point;
   uint8 entry_type;
   uint32 entry_count;
   setup_idt();
   debug_print( "---------------------MP_FLOAT_POINTER-------------------\n" );
   MP_FLOAT_POINTER *pPointer = (MP_FLOAT_POINTER *)MP_BIOS_ADDR;
   print_mp_float_pointer_info( pPointer );

   debug_print( "---------------------MP_CONFIG_TABLE_HEADER-------------------\n" );
   MP_CONFIG_TABLE_HEADER *header = (MP_CONFIG_TABLE_HEADER *)((long long)(pPointer->address_point));
   print_mp_table_header_info( header );

   debug_print( "---------------------MP_TABLE_ENTRY_LIST-------------------\n" );
   point = (uint8 *)header;
   point = point + sizeof(MP_CONFIG_TABLE_HEADER);
   entry_count = header->oem_entry_count;
   while(entry_count--)
   {
       entry_type = *point;
       debug_print( "/********************entry type %d********************/\n", entry_type );
       switch( entry_type )
       {
           case MP_ENTRY_PROCESSOR:
               print_processor_entry_info( (PROCESSOR_ENTRY *)point );
               point = point + sizeof(PROCESSOR_ENTRY);
               break;

           case MP_ENTRY_BUS:
               print_bus_entry_info( (BUS_ENTRY *)point );
               point = point + sizeof(BUS_ENTRY);
               break;

           case MP_ENTRY_APIC:
               print_apic_entry_info( (APIC_ENTRY *)point );
               point = point + sizeof(APIC_ENTRY);
               break;

           case MP_ENTRY_IO_INT:
               print_io_int_entry_info( (IO_INT_ENTRY *)point );
               point = point + sizeof(IO_INT_ENTRY);
               break;

           case MP_ENTRY_LOCAL_INT:
               print_local_int_entry_info( (LOCAL_INT_ENTRY *)point );
               point = point + sizeof(LOCAL_INT_ENTRY);
               break;

           default:
               debug_print( "unkown entry type: %d\n", entry_type );
               break;
       }
	}
   debug_print( "---------------------MP_TABLE_ENTRY_LIST_END-------------------\n" );
   return 0;
}
