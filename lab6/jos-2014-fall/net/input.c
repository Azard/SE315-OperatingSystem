#include "ns.h"

extern union Nsipc nsipcbuf;

	void
input(envid_t ns_envid)
{
	binaryname = "ns_input";

	// LAB 6: Your code here:
	// 	- read a packet from the device driver
	//	- send it to the network server
	// Hint: When you IPC a page to the network server, it will be
	// reading from it for a while, so don't immediately receive
	// another packet in to the same physical page.
	const int Size = 2048;
	uint8_t buf[Size];
	uint32_t len;

	while (1)
	{
		while (sys_net_receive(buf, &len) < 0)
			sys_yield();

		cprintf("Length of received packet from network: %d\n", len);
		while (sys_page_alloc(0, &nsipcbuf, PTE_P|PTE_W|PTE_U) < 0)
			;
		nsipcbuf.pkt.jp_len = len;
		memmove(nsipcbuf.pkt.jp_data, buf, len);
		//cprintf("DEBUG\n");

		while(sys_ipc_try_send(ns_envid, NSREQ_INPUT, &nsipcbuf, PTE_P|PTE_W|PTE_U) < 0)
			;
	}
}
