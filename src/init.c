// SPDX-License-Identifier: MIT
/*
 *
 * This file is part of ruri, with ABSOLUTELY NO WARRANTY.
 *
 * MIT License
 *
 * Copyright (c) 2022-2024 Moe-hacker
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */
#include "include/ruri.h"

#ifndef DISABLE_SYSTEMD
/*
 * In systemd mode, ruri prepares the container environment and then execs
 * systemd directly so it becomes the real PID 1 inside the container.
 */

static void verify_pid1_environment(void)
{
	pid_t pid = getpid();
	if (pid != 1) {
		ruri_error("{red}systemd mode requires ruri to be PID 1 (current PID: %d)\n", pid);
	}

	struct stat self_mnt, init_mnt;
	if (stat("/proc/self/ns/mnt", &self_mnt) == 0 && stat("/proc/1/ns/mnt", &init_mnt) == 0) {
		if (self_mnt.st_ino == init_mnt.st_ino) {
			ruri_log("{yellow}Warning: ruri appears to be in the same mount namespace as init\n");
		}
	}

	ruri_log("{base}Verified: running as PID %d in container namespace\n", pid);
}

void ruri_init_systemd(struct RURI_CONTAINER *container)
{
	if (!container->systemd_mode) {
		return;
	}

	if (!container->enable_unshare) {
		ruri_error("{red}systemd mode requires --unshare option (PID namespace)\n");
	}

	if (getuid() != 0 && geteuid() != 0) {
		ruri_error("{red}systemd mode requires root privileges\n");
	}

	ruri_log("{base}systemd mode initialized\n");
}

void ruri_run_systemd_init(char *const command[])
{
	if (command == NULL || command[0] == NULL) {
		ruri_error("{red}No command specified for systemd mode\n");
	}

	if (access(command[0], X_OK) != 0) {
		ruri_error("{red}Init binary not found or not executable: %s\n", command[0]);
	}

	verify_pid1_environment();
	setenv("container", "ruri", 1);
	setenv("SYSTEMD_IGNORE_CHROOT", "1", 1);

	ruri_log("{base}Execing systemd as PID 1: %s\n", command[0]);
	execvp(command[0], command);
	ruri_error("{red}Failed to exec systemd: %s\n", strerror(errno));
}

#else // !DISABLE_SYSTEMD

void ruri_init_systemd(struct RURI_CONTAINER *container __attribute__((unused)))
{
	return;
}

void ruri_run_systemd_init(char *const command[] __attribute__((unused)))
{
	ruri_error("{red}systemd support is not enabled. Rebuild with --enable-systemd\n");
}

#endif // DISABLE_SYSTEMD
