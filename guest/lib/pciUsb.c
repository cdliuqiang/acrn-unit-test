/*
 *Copyright (C) 2019 Intel Corporation.All rigths reserved
 *Test mode:PCIe config space
 *Written by wangchunlin,06-12-2019
*/

#include "libcflat.h"
#include "processor.h"
#include "desc.h"
#include "./asm/io.h"
#include "pci.h"

#define PCIE_PRINT				1
#define PCI_USB_REMAP			0xDFF00000

/*PCI  I/O ports */
#define PCI_CONFIG_ADDR       0xCF8U
#define PCI_CONFIG_DATA       0xCFCU

#define OK                  0
#define ERROR               (-1)


/*
 *pci config space register
 */
#define	PCIR_DEVVENDOR	0x00
#define	PCIR_VENDOR	0x00
#define	PCIR_DEVICE	0x02
#define	PCIR_COMMAND	0x04
#define	PCIM_CMD_PORTEN		0x0001
#define	PCIM_CMD_MEMEN		0x0002
#define	PCIM_CMD_BUSMASTEREN	0x0004
#define	PCIM_CMD_SPECIALEN	0x0008
#define	PCIM_CMD_MWRICEN	0x0010
#define	PCIM_CMD_PERRESPEN	0x0040
#define	PCIM_CMD_SERRESPEN	0x0100
#define	PCIM_CMD_BACKTOBACK	0x0200
#define	PCIM_CMD_INTxDIS	0x0400
#define	PCIR_STATUS	0x06
#define	PCIM_STATUS_INTxSTATE	0x0008
#define	PCIM_STATUS_CAPPRESENT	0x0010
#define	PCIM_STATUS_66CAPABLE	0x0020
#define	PCIM_STATUS_BACKTOBACK	0x0080
#define	PCIM_STATUS_MDPERR	0x0100
#define	PCIM_STATUS_SEL_FAST	0x0000
#define	PCIM_STATUS_SEL_MEDIMUM	0x0200
#define	PCIM_STATUS_SEL_SLOW	0x0400
#define	PCIM_STATUS_SEL_MASK	0x0600
#define	PCIM_STATUS_STABORT	0x0800
#define	PCIM_STATUS_RTABORT	0x1000
#define	PCIM_STATUS_RMABORT	0x2000
#define	PCIM_STATUS_SERR	0x4000
#define	PCIM_STATUS_PERR	0x8000
#define	PCIR_REVID	0x08
#define	PCIR_PROGIF	0x09
#define	PCIR_SUBCLASS	0x0a
#define	PCIR_CLASS	0x0b
#define	PCIR_CACHELNSZ	0x0c
#define	PCIR_LATTIMER	0x0d
#define	PCIR_HDRTYPE	0x0e
#define	PCIM_HDRTYPE		0x7f
#define	PCIM_HDRTYPE_NORMAL	0x00
#define	PCIM_HDRTYPE_BRIDGE	0x01
#define	PCIM_HDRTYPE_CARDBUS	0x02
#define	PCIM_MFDEV		0x80
#define	PCIR_BIST	0x0f

#define	PCIR_BUS_NUM	0x18
#define  PCIR_REV		0x36


#define PCI_CFG_ENABLE        0x80000000U

#define	PCIM_BAR_SPACE		0x00000001
#define	PCIM_BAR_IO_SPACE	1
#define	PCIM_BAR_MEM_TYPE	0x00000006
#define	PCIM_BAR_MEM_32		0
#define	PCIM_BAR_MEM_1MB	2	/* Locate below 1MB in PCI <= 2.1 */
#define	PCIM_BAR_MEM_64		4

#define	PCICAP_ID	0x0

/* Capability Identification Numbers */

#define	PCIY_PMG	0x01	/* PCI Power Management */
#define	PCIY_AGP	0x02	/* AGP */
#define	PCIY_VPD	0x03	/* Vital Product Data */
#define	PCIY_SLOTID	0x04	/* Slot Identification */
#define	PCIY_MSI	0x05	/* Message Signaled Interrupts */
#define	PCIY_CHSWP	0x06	/* CompactPCI Hot Swap */
#define	PCIY_PCIX	0x07	/* PCI-X */
#define	PCIY_HT		0x08	/* HyperTransport */
#define	PCIY_VENDOR	0x09	/* Vendor Unique */
#define	PCIY_DEBUG	0x0a	/* Debug port */
#define	PCIY_CRES	0x0b	/* CompactPCI central resource control */
#define	PCIY_HOTPLUG	0x0c	/* PCI Hot-Plug */
#define	PCIY_SUBVENDOR	0x0d	/* PCI-PCI bridge subvendor ID */
#define	PCIY_AGP8X	0x0e	/* AGP 8x */
#define	PCIY_SECDEV	0x0f	/* Secure Device */
#define	PCIY_EXPRESS	0x10	/* PCI Express */
#define	PCIY_MSIX	0x11	/* MSI-X */
#define	PCIY_SATA	0x12	/* SATA */
#define	PCIY_PCIAF	0x13	/* PCI Advanced Features */
#define	PCIY_EA		0x14	/* PCI Extended Allocation */

#define	PCIR_BARS	0x10
#define	PCIR_BAR(x)		(PCIR_BARS + (x) * 4)

union pci_bdf {
	uint16_t value;
	struct {
		uint8_t f : 3; /* BITs 0-2 */
		uint8_t d : 5; /* BITs 3-7 */
		uint8_t b; /* BITs 8-15 */
	} bits;
};


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

/* Write 2 bytes to specified I/O port */
static inline void pio_write16(uint16_t value, uint16_t port)
{
	asm volatile ("outw %0,%1"::"a" (value), "dN"(port));
}

/* Read 2 bytes from specified I/O port */
static inline uint16_t pio_read16(uint16_t port)
{
	uint16_t value;

	asm volatile ("inw %1,%0":"=a" (value):"dN"(port));
	return value;
}

/* Write 4 bytes to specified I/O port */
static inline void pio_write32(uint32_t value, uint16_t port)
{
	asm volatile ("outl %0,%1"::"a" (value), "dN"(port));
}

/* Read 4 bytes from specified I/O port */
static inline uint32_t pio_read32(uint16_t port)
{
	uint32_t value;

	asm volatile ("inl %1,%0":"=a" (value):"dN"(port));
	return value;
}

static inline void pio_write(uint32_t v, uint16_t addr, size_t sz)
{
	if (sz == 1U) {
		pio_write8((uint8_t)v, addr);
	} else if (sz == 2U) {
		pio_write16((uint16_t)v, addr);
	} else {
		pio_write32(v, addr);
	}
}

static inline uint32_t pio_read(uint16_t addr, size_t sz)
{
	uint32_t ret;
	if (sz == 1U) {
		ret = pio_read8(addr);
	} else if (sz == 2U) {
		ret = pio_read16(addr);
	} else {
		ret = pio_read32(addr);
	}
	return ret;
}


static uint32_t pci_pdev_calc_address(union pci_bdf bdf, uint32_t offset)
{
	uint32_t addr = (uint32_t)bdf.value;

	addr <<= 8U;
	addr |= (offset | PCI_CFG_ENABLE);
	return addr;
}

static uint32_t pci_pdev_read_cfg(union pci_bdf bdf, uint32_t offset, uint32_t bytes)
{
	uint32_t addr;
	uint32_t val;

	addr = pci_pdev_calc_address(bdf, offset);

	#if 0
	spinlock_obtain(&pci_device_lock);
	#endif

	/* Write address to ADDRESS register */
	pio_write32(addr, (uint16_t)PCI_CONFIG_ADDR);

	/* Read result from DATA register */
	switch (bytes) {
	case 1U:
		val = (uint32_t)pio_read8((uint16_t)PCI_CONFIG_DATA + ((uint16_t)offset & 3U));
		break;
	case 2U:
		val = (uint32_t)pio_read16((uint16_t)PCI_CONFIG_DATA + ((uint16_t)offset & 2U));
		break;
	default:
		val = pio_read32((uint16_t)PCI_CONFIG_DATA);
		break;
	}

	#if 0
	spinlock_release(&pci_device_lock);
	#endif
	
	return val;
}

#if PCI_USB_REMAP
static void pci_pdev_write_cfg(union pci_bdf bdf, uint32_t offset, uint32_t bytes, uint32_t val)
{
	uint32_t addr;

	#if 0
	spinlock_obtain(&pci_device_lock);
	#endif
	
	addr = pci_pdev_calc_address(bdf, offset);

	/* Write address to ADDRESS register */
	pio_write32(addr, (uint16_t)PCI_CONFIG_ADDR);

	/* Write value to DATA register */
	switch (bytes) {
	case 1U:
		pio_write8((uint8_t)val, (uint16_t)PCI_CONFIG_DATA + ((uint16_t)offset & 3U));
		break;
	case 2U:
		pio_write16((uint16_t)val, (uint16_t)PCI_CONFIG_DATA + ((uint16_t)offset & 2U));
		break;
	default:
		pio_write32(val, (uint16_t)PCI_CONFIG_DATA);
		break;
	}

	#if 0
	spinlock_release(&pci_device_lock);
	#endif
}
#endif

/*
*function:designing visit to BAR of USB for Andy,get PCIe USB device BAR mem space
*param:void * pArg:output the BAR address to the pointer
*return : OK or ERROR(There is no device or bar)
*note:PCI_USB_REMAP define 0,use BIOS dispense BAR space,Otherwise, use the PCI_USB_REMAP defined space,EXP:0xDFF0_0000
*      The allocation of this space is very careful because we don't know how the BIOS is allocated. It's easy to overlap space.
*/
int visitPciDev(void * pArg)
{
	unsigned int regValue=0,regValueH=0;
	unsigned long long value;
	union pci_bdf bdfTmp;
	unsigned int val;
	unsigned int i,j;
	int ret=OK;
	
	bdfTmp.bits.b = (uint8_t)0;
	bdfTmp.bits.d = (uint8_t)0x14;
	bdfTmp.bits.f = (uint8_t)0;

#if PCIE_PRINT
	printf("\r\n[INFO] test device [%03x:%02x:%01x]...",bdfTmp.bits.b,bdfTmp.bits.d,bdfTmp.bits.f);
#endif

	val = pci_pdev_read_cfg(bdfTmp, PCIR_VENDOR, 4U);
	if ((val == 0xFFFFFFFFU) || (val == 0U) || (val == 0xFFFF0000U) || (val == 0xFFFFU)) {
		#if PCIE_PRINT
			printf("    failed");
		#endif
		ret = ERROR;
		goto __DONE__;
	}
	
#if PCI_USB_REMAP
{
		extern void setup_mmu_range();
		/*set page*/
		setup_mmu_range(phys_to_virt(read_cr3()), PCI_USB_REMAP, 0x100000);
}
#endif
		for(i=0 ; i<1 ; i++){
			#if PCI_USB_REMAP
				pci_pdev_write_cfg(bdfTmp,PCIR_BAR(i),4U,0xFFFFFFFF);
				regValue = pci_pdev_read_cfg(bdfTmp,PCIR_BAR(i),4U);
				#if PCIE_PRINT
					printf("\n\r    [INFO]:origin BAR%d register is 0x%08x",i,regValue);
				#endif

				pci_pdev_write_cfg(bdfTmp,PCIR_BAR(i),4U,PCI_USB_REMAP);
				pci_pdev_write_cfg(bdfTmp,PCIR_BAR(i+1),4U,0x00000000);
				#if PCIE_PRINT
					printf("\n\r    [INFO]:set BAR%d register is 0x%08x",i,PCI_USB_REMAP);
				#endif
			#endif

			regValueH = pci_pdev_read_cfg(bdfTmp,PCIR_BAR(i+1),4U);
			#if PCIE_PRINT
				printf("\n\r    [INFO]:set BAR%d register is 0x%08x",i+1,0x00000000);
			#endif
			regValue = pci_pdev_read_cfg(bdfTmp,PCIR_BAR(i),4U);
			#if PCIE_PRINT
				printf("    [INFO]:  BAR%d register is 0x%08x",i,regValue);
			#endif
			
			if(regValue){
				for(j=1 ; j<2 ; j++){
					printf("\r\n    [INFO]:ID @[0x%08x]=[0x%04x] ",((regValue & 0xFFFFFFF0)+j*2),*(unsigned short *)(long long)((regValue & 0xFFFFFFF0)+j*sizeof(short)));
				}printf("\r\n    [INFO]:CAP @[0x%08x]=[0x%08x] ",((regValue & 0xFFFFFFF0)+0x10),*(unsigned int *)(long long)((regValue & 0xFFFFFFF0)+0x10));
			}else{
				goto __DONE__;				
			}

			/*test rev register,whether is happen error*/
			*((unsigned int *)((long long)((regValue & 0xFFFFFFF0)+0x20)))= 0xAA55CC33;
			if(*((unsigned int *)((long long)((regValue & 0xFFFFFFF0)+0x20)))== 0xAA55CC33){
				printf("\r\n[INFO]:rev register @[0x%08x]=[0x%04x]  is write data",((regValue & 0xFFFFFFF0)+0x20),*((unsigned int *)((long long)((regValue & 0xFFFFFFF0)+0x20))));
			}else{
				printf("  \r\n[ERROR]: rev register R!=W");
			}
		}printf("\r\n");

__DONE__:
	value = regValueH;
	value = (value << 32) | (regValue & 0xFFFFFFF0);
	*((unsigned long long *)pArg)=value;
	printf("\r\n[INFO]:USB MEM @0x%llx\r\n",value);

	return ret;
}
#if 0
/*
 *Entery
 */
int main(int ac, char **av)
{

	printf("Enter %s/%s   %s  %s\r\n",__FILE__,__FUNCTION__,__DATE__,__TIME__);
	printf("This is PCIe USB device unit\r\n");
	
    setup_idt();

	visitPciDev((void * )0);
	
    report_summary();

	while(1);

	return OK;
}
#endif