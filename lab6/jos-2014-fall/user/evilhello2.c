// evil hello world -- kernel pointer passed to kernel
// kernel should destroy user environment in response

#include <inc/lib.h>
#include <inc/mmu.h>
#include <inc/x86.h>

char vaddr[PGSIZE];
struct Segdesc old;
struct Segdesc *gdt;
struct Segdesc *entry;

// Call this function with ring0 privilege
void evil()
{
	// Kernel memory access
	*(char*)0xf010000a = 0;

	// Out put something via outb
	outb(0x3f8, 'I');
	outb(0x3f8, 'N');
	outb(0x3f8, ' ');
	outb(0x3f8, 'R');
	outb(0x3f8, 'I');
	outb(0x3f8, 'N');
	outb(0x3f8, 'G');
	outb(0x3f8, '0');
	outb(0x3f8, '!');
	outb(0x3f8, '!');
	outb(0x3f8, '!');
	outb(0x3f8, '\n');
}

void call_fun_ptr()
{
	evil();  
	*entry = old;  
	asm volatile("popl %ebp");
	asm volatile("lret");	
}

static void
get_gdt(struct Pseudodesc* r_gdt)
{
	__asm __volatile("sgdt %0" :  "=m" (*r_gdt));
}

// Invoke a given function pointer with ring0 privilege, then return to ring3
void ring0_call(void (*fun_ptr)(void)) {
    // Here's some hints on how to achieve this.
    // 1. Store the GDT descripter to memory (sgdt instruction)
    // 2. Map GDT in user space (sys_map_kernel_page)
    // 3. Setup a CALLGATE in GDT (SETCALLGATE macro)
    // 4. Enter ring0 (lcall instruction)
    // 5. Call the function pointer
    // 6. Recover GDT entry modified in step 3 (if any)
    // 7. Leave ring0 (lret instruction)

    // Hint : use a wrapper function to call fun_ptr. Feel free
    //        to add any functions or global variables in this 
    //        file if necessary.

    // Lab3 : Your Code Here

    struct Pseudodesc r_gdt; 
	get_gdt(&r_gdt);

	int t = sys_map_kernel_page((void* )r_gdt.pd_base, (void* )vaddr);
	if (t < 0) {
		cprintf("ring0_call: sys_map_kernel_page failed, %e\n", t);
	}

	uint32_t base = (uint32_t)(PGNUM(vaddr) << PTXSHIFT);
	uint32_t index = GD_UD >> 3;
	uint32_t offset = PGOFF(r_gdt.pd_base);

	gdt = (struct Segdesc*)(base+offset); 
	entry = gdt + index; 
	old= *entry; 

	SETCALLGATE(*((struct Gatedesc*)entry), GD_KT, call_fun_ptr, 3);
	asm volatile("lcall $0x20, $0");
}

void
umain(int argc, char **argv)
{
    // call the evil function in ring0
	ring0_call(&evil);

	// call the evil function in ring3
	evil();
}

