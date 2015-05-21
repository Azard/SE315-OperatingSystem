#include <inc/lib.h>
#include <inc/env.h>

void umain(int argc, char **argv)
{
	sys_env_set_priority(0, PRIORITY_MIDDLE);
	int i;
	int n = 3;
	for (i = 0; i < n; i++) {
		cprintf("[%08x] Middle Priority Process is Running\n", sys_getenvid());
	}
	return;
}
