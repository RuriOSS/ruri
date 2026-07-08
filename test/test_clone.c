// Test all unshare clone flags like CLONE_NEWNS, CLONE_NEWUTS, CLONE_NEWIPC, CLONE_NEWUSER, CLONE_NEWPID, CLONE_NEWNET, and CLONE_NEWCGROUP.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sched.h>
#include <errno.h>
static int child_func(void *arg)
{
	// Child process code
	printf("Child process running with PID: %d\n", getpid());
	return 0;
}
int main()
{
	struct clone_flags {
		unsigned int flag;
		const char *name;
	} flags[] = { { CLONE_NEWNS, "CLONE_NEWNS" }, { CLONE_NEWUTS, "CLONE_NEWUTS" }, { CLONE_NEWIPC, "CLONE_NEWIPC" }, { CLONE_NEWUSER, "CLONE_NEWUSER" }, { CLONE_NEWPID, "CLONE_NEWPID" }, { CLONE_NEWNET, "CLONE_NEWNET" }, { CLONE_NEWCGROUP, "CLONE_NEWCGROUP" }, { 0, "NONE" } };
	for (int i = 0; i < sizeof(flags) / sizeof(flags[0]); i++) {
		// clone() with the specified flag
		void *child_stack = malloc(1024 * 1024); // Allocate stack for child
		pid_t pid = clone(child_func, child_stack + 1024 * 1024, flags[i].flag | SIGCHLD, NULL);
		if (pid == -1) {
			printf("clone() failed for %s: %s\n", flags[i].name, strerror(errno));
		} else {
			printf("clone() succeeded for %s, child PID: %d\n", flags[i].name, pid);
			waitpid(pid, NULL, 0); // Wait for the child
		}
	}
	return 0;
}