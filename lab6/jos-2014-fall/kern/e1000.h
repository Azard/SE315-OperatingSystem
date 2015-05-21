#ifndef JOS_KERN_E1000_H
#define JOS_KERN_E1000_H

#include <kern/pci.h>

uint32_t *volatile e1000;

#define E1000_ADDR	KSTACKTOP 


// 82540EM Desktop ID
#define E1000_VENDOR_ID 0x8086
#define E1000_DEVICE_ID 0x100e

#define E1000_NTXDESC  64
#define E1000_NRCVDESC 128

#define E1000_TX_PKT_LEN  1518
#define E1000_RCV_PKT_LEN 2048


// Registers, divided by four for indexing purposes
#define E1000_STATUS (0x0008 / 4)

// TX Descriptors and Flags
#define E1000_TDBAL (0x3800 / 4) // Base Address Low
#define E1000_TDBAH (0x3804 / 4) // Base Address High
#define E1000_TDLEN (0x3808 / 4) // Length
#define E1000_TDH   (0x3810 / 4) // Head
#define E1000_TDT   (0x3818 / 4) // Tail

#define E1000_TDESC_CMD_RS (0x1 << 3) // Report Status
#define E1000_TDESC_CMD_EOP (0x1)     // End of Packet
#define E1000_TDESC_STATUS_DD (0x1)   // Descriptor Done

// Control Registers and Flags
#define E1000_TCTL  (0x0400 / 4)     // Transmit Control Register
#define E1000_TCTL_EN (0x1 << 1)     // Transmit Enable
#define E1000_TCTL_PSP (0x1 << 3)    // Pad Short Packets
#define E1000_TCTL_CT  (0x10 << 4)   // Collision Threshold
#define E1000_TCTL_COLD (0x40 << 12) // Collision Distance

#define E1000_TIPG  (0x0410 / 4)     // Transmit Inter-Packet Gap Register
#define E1000_TIPG_IPGT 0xA          // Transmit Time
#define E1000_TIPG_IPGR1 (0x4 << 10) // IPG Receive Time 1
#define E1000_TIPG_IPGR2 (0x6 << 20) // IPG Receive Time 2

// RCV Registers
#define E1000_FILTER_RAL (0x5400 / 4)      // Receive Address Low
#define E1000_FILTER_RAH (0x5404 / 4)      // Receive Address High
#define E1000_FILTER_RAH_VALID (0x1 << 31) // Address Valid

#define E1000_EERD (0x0014 / 4)    // EEPROM Read Register
#define E1000_EERD_START 0x1       // Start Read
#define E1000_EERD_DONE (0x1 << 4) // Read Finished
#define E1000_EERD_ADDR_SHIFT 8    // Address Shift
#define E1000_EERD_DATA_SHIFT 16   // Data Shift

#define E1000_MTA     (0x5200 / 4)
#define E1000_MTA_LEN 0x400

#define E1000_RDBAL (0x2800 / 4) // Receive Address Low
#define E1000_RDBAH (0x2804 / 4) // Receive Address High
#define E1000_RDLEN (0x2808 / 4) // Receive Length
#define E1000_RDH   (0x2810 / 4) // Receive Descriptor Head
#define E1000_RDT   (0x2818 / 4) // Receive Descriptor Tail
#define E1000_RAL	(0x05400 / 4)
#define E1000_RAH	(0x05404 / 4)

#define E1000_RCTL (0x100 / 4) // Receive Control Register
#define E1000_RCTL_EN (0x1 << 1) // Receiver Enabled
#define E1000_RCTL_LPE (0x1 << 5) // Long Packet Enable
#define E1000_RCTL_LBM (0x3 << 6) // Loopback Mode
#define E1000_RCTL_RDMTS (0x3 << 8) // Minimum Threshold Size
#define E1000_RCTL_MO (0x3 << 12)  // Multicast Offset
#define E1000_RCTL_BAM (0x1 << 15) // Broadcast Accept Mode
#define E1000_RCTL_BSIZE (0x3 << 16) // Buffer Size
#define E1000_RCTL_SECRC (0x1 << 26) // Strip Ethernet

#define E1000_RDESC_STATUS_DD 0x1         // Descriptor Done
#define E1000_RDESC_STATUS_EOP (0x1 << 1) // End of Packet

struct pci_func;

struct tx_desc
{
	uint64_t addr;
	uint16_t length;
	uint8_t cso;
	uint8_t cmd;
	uint8_t status;
	uint8_t css;
	uint16_t special;
} __attribute__((packed));

struct tx_pkt
{
	uint8_t pkt[E1000_TX_PKT_LEN];
};

struct rcv_desc
{
	uint64_t addr;
	uint16_t length;
	uint16_t chksum;
	uint8_t status;
	uint8_t errors;
	uint16_t special;
} __attribute__((packed));

struct rcv_pkt
{
	uint8_t pkt[E1000_RCV_PKT_LEN];
};

int e1000_attach(struct pci_func *pcif);
int e1000_transmit(uint8_t *data, uint32_t len);
int e1000_receive(uint8_t *data);

#endif	// JOS_KERN_E1000_H
