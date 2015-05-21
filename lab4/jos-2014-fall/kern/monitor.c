// Simple command-line kernel monitor useful for
// controlling the kernel and exploring the system interactively.

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/x86.h>

#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/kdebug.h>
#include <kern/trap.h>
#include <kern/env.h>

#define CMDBUF_SIZE	80	// enough for one VGA text line


struct Command {
	const char *name;
	const char *desc;
	// return -1 to force monitor to exit
	int (*func)(int argc, char** argv, struct Trapframe* tf);
};

static struct Command commands[] = {
	{ "help", "Display this list of commands", mon_help },
	{ "time", "Display a commond runtime, usage: time [command]", mon_time},
	{ "kerninfo", "Display information about the kernel", mon_kerninfo },
	{ "backtrace", "Display function backtrace", mon_backtrace},
	{ "c", "Continue, use in debug", mon_debug_continue},
	{ "si", "Step by step, use in debug", mon_debug_step},
	{ "x", "Display memory, use in debug", mon_debug_display}
};
#define NCOMMANDS (sizeof(commands)/sizeof(commands[0]))

unsigned read_eip();

/***** Implementations of basic kernel monitor commands *****/

int
mon_help(int argc, char **argv, struct Trapframe *tf)
{
	int i;

	for (i = 0; i < NCOMMANDS; i++)
		cprintf("%s - %s\n", commands[i].name, commands[i].desc);
	return 0;
}

int
mon_time(int argc, char **argv, struct Trapframe *tf)
{
	uint32_t begin_low = 0;
	uint32_t begin_high = 0;
	uint32_t end_low = 0;
	uint32_t end_high = 0;
	int i;

	if (argc == 1) {
		cprintf("Please enter: time [command]\n");
		return 0;
	}
	for (i = 0; i < NCOMMANDS; i++) {
		if (strcmp(argv[1], commands[i].name) == 0)
			break;
		if (i == NCOMMANDS-1) {
			cprintf("Unknown command after time '%s'\n", argv[1]);
			return 0;
		}
	}
	argc--;
	argv++;

	__asm __volatile("rdtsc" : "=a" (begin_low), "=d" (begin_high));
	commands[i].func(argc, argv, tf);
	__asm __volatile("rdtsc" : "=a" (end_low), "=d" (end_high));
	
	uint64_t begin_total = ((uint64_t)begin_high << 32) | begin_low; 
	uint64_t end_total = ((uint64_t)end_high << 32) | end_low; 
	cprintf("%s cycles: %llu\n", argv[0], end_total-begin_total);
	return 0;
}

int
mon_kerninfo(int argc, char **argv, struct Trapframe *tf)
{
	extern char entry[], etext[], edata[], end[];

	cprintf("Special kernel symbols:\n");
	cprintf("  entry  %08x (virt)  %08x (phys)\n", entry, entry - KERNBASE);
	cprintf("  etext  %08x (virt)  %08x (phys)\n", etext, etext - KERNBASE);
	cprintf("  edata  %08x (virt)  %08x (phys)\n", edata, edata - KERNBASE);
	cprintf("  end    %08x (virt)  %08x (phys)\n", end, end - KERNBASE);
	cprintf("Kernel executable memory footprint: %dKB\n",
		(end-entry+1023)/1024);
	return 0;
}

// Lab1 only
// read the pointer to the retaddr on the stack
static uint32_t
read_pretaddr() {
    uint32_t pretaddr;
    __asm __volatile("leal 4(%%ebp), %0" : "=r" (pretaddr)); 
    return pretaddr;
}

void
do_overflow(void)
{
    cprintf("Overflow success\n");
}

void
start_overflow(void)
{
	// You should use a techique similar to buffer overflow
	// to invoke the do_overflow function and
	// the procedure must return normally.

    // And you must use the "cprintf" function with %n specifier
    // you augmented in the "Exercise 9" to do this job.

    // hint: You can use the read_pretaddr function to retrieve 
    //       the pointer to the function call return address;

    char str[256] = {};
    int nstr = 0;
    char *pret_addr;

	// Your code here.
	// replace 'ret to overflow_me' to 'ret to do_overflow' 
	pret_addr = (char*)read_pretaddr(); // get eip pointer
	int i = 0;
	for (;i < 256; i++) {
		str[i] = 'h';
		if (i%2)
			str[i] = 'a';
	}
	void (*do_overflow_t)();
	do_overflow_t = do_overflow;
	uint32_t ret_addr = (uint32_t)do_overflow_t+3; // ignore stack asm code
	
	uint32_t ret_byte_0 = ret_addr & 0xff;
	uint32_t ret_byte_1 = (ret_addr >> 8) & 0xff;
	uint32_t ret_byte_2 = (ret_addr >> 16) & 0xff;
	uint32_t ret_byte_3 = (ret_addr >> 24) & 0xff;
	str[ret_byte_0] = '\0';
	cprintf("%s%n\n", str, pret_addr);
	str[ret_byte_0] = 'h';
	str[ret_byte_1] = '\0';
	cprintf("%s%n\n", str, pret_addr+1);
	str[ret_byte_1] = 'h';
	str[ret_byte_2] = '\0';
	cprintf("%s%n\n", str, pret_addr+2);
	str[ret_byte_2] = 'h';
	str[ret_byte_3] = '\0';
	cprintf("%s%n\n", str, pret_addr+3);
}

void
overflow_me(void)
{
        start_overflow();
}

int
mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
	// Your code here.
	uint32_t ebp = read_ebp();
	uint32_t eip = read_eip();

	cprintf("Stack backtrace:\n");
	while(ebp != 0x0) {
		eip = *((uint32_t*)ebp + 1);
		cprintf("  eip %08x  ebp %08x  args %08x %08x %08x %08x %08x\n", eip, ebp, *((uint32_t*)ebp+2), *((uint32_t*)ebp+3), *((uint32_t*)ebp+4), *((uint32_t*)ebp+5), *((uint32_t*)ebp+6) );
		
		// debug info, zhe ge hai yao suan fen, WTF
		struct Eipdebuginfo info;
		if (debuginfo_eip(eip, &info) == 0) {
			char temp[info.eip_fn_namelen+1];
			temp[info.eip_fn_namelen] = '\0';
			int i = 0;
			for (i = 0; i < info.eip_fn_namelen; i++) {
				temp[i] = info.eip_fn_name[i];
			}
			cprintf("         %s:%d: %s+%x\n", info.eip_file, info.eip_line, temp, eip-info.eip_fn_addr);
		}
		// debug info end

		ebp = *((uint32_t*)ebp);
	}
	
	
    overflow_me();
    cprintf("Backtrace success\n");
	return 0;
}


/* use in debug(int3 interrupter) */
int
mon_debug_continue(int argc, char **argv, struct Trapframe *tf)
{
	uint32_t eflags;
	if (tf == NULL) {
		cprintf("No trapped environment\n");
		return 1;
	}
	eflags = tf->tf_eflags;
	eflags &= ~FL_TF;
	tf->tf_eflags = eflags;
	env_run(curenv);
	return 0;
}


int
mon_debug_step(int argc, char **argv, struct Trapframe *tf)
{
	uint32_t eflags;
	if (tf == NULL) {
		cprintf("No trapped environment\n");
		return 1;
	}
	eflags = tf->tf_eflags;
	eflags |= FL_TF;
	tf->tf_eflags = eflags;

	cprintf("tf_eip=0x%x\n", tf->tf_eip);
	env_run(curenv);
	return 0;
}


int
mon_debug_display(int argc, char **argv, struct Trapframe *tf)
{
	if (argc != 2) {
		cprintf("please enter x addr");
	}
	uint32_t get_addr;
	get_addr = strtol(argv[1], NULL, 16);
	
	uint32_t get_val;
    __asm __volatile("movl (%0), %0" : "=r" (get_val) : "r" (get_addr)); 
	
	cprintf("%d\n", get_val);
	return 0;
}


/***** Kernel monitor command interpreter *****/

#define WHITESPACE "\t\r\n "
#define MAXARGS 16

static int
runcmd(char *buf, struct Trapframe *tf)
{
	int argc;
	char *argv[MAXARGS];
	int i;

	// Parse the command buffer into whitespace-separated arguments
	argc = 0;
	argv[argc] = 0;
	while (1) {
		// gobble whitespace
		while (*buf && strchr(WHITESPACE, *buf))
			*buf++ = 0;
		if (*buf == 0)
			break;

		// save and scan past next arg
		if (argc == MAXARGS-1) {
			cprintf("Too many arguments (max %d)\n", MAXARGS);
			return 0;
		}
		argv[argc++] = buf;
		while (*buf && !strchr(WHITESPACE, *buf))
			buf++;
	}
	argv[argc] = 0;

	// Lookup and invoke the command
	if (argc == 0)
		return 0;
	for (i = 0; i < NCOMMANDS; i++) {
		if (strcmp(argv[0], commands[i].name) == 0)
			return commands[i].func(argc, argv, tf);
	}
	cprintf("Unknown command '%s'\n", argv[0]);
	return 0;
}

void
monitor(struct Trapframe *tf)
{
	char *buf;

	cprintf("Welcome to the JOS kernel monitor!\n");
	cprintf("Type 'help' for a list of commands.\n");

	if (tf != NULL)
		print_trapframe(tf);

	while (1) {
		buf = readline("K> ");
		if (buf != NULL)
			if (runcmd(buf, tf) < 0)
				break;
	}
}

// return EIP of caller.
// does not work if inlined.
// putting at the end of the file seems to prevent inlining.
unsigned
read_eip()
{
	uint32_t callerpc;
	__asm __volatile("movl 4(%%ebp), %0" : "=r" (callerpc));
	return callerpc;
}
