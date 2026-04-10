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

#ifdef ENABLE_SYSTEMD
/*
 * This file provides init process functionality for systemd mode.
 * When running as PID 1 in a container, ruri needs to reap zombie processes
 * and forward signals to the systemd process.
 */

static volatile sig_atomic_t child_exited = 0;
static volatile sig_atomic_t signal_received = 0;
static pid_t systemd_pid = 0;

static void sigchld_handler(int sig __attribute__((unused)))
{
	child_exited = 1;
}

static void forward_signal(int sig)
{
	signal_received = sig;
	if (systemd_pid > 0) {
		kill(systemd_pid, sig);
	}
}

static void setup_signal_handlers(void)
{
	struct sigaction sa;

	// Setup SIGCHLD handler for zombie reaping
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sigchld_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;

#ifdef __ANDROID__
	// Bionic doesn't use sa_restorer
	sigaction(SIGCHLD, &sa, NULL);

	// Setup signal forwarding
	sa.sa_handler = forward_signal;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;

	sigaction(SIGHUP, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGQUIT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGUSR1, &sa, NULL);
	sigaction(SIGUSR2, &sa, NULL);
	sigaction(SIGPWR, &sa, NULL);
	sigaction(SIGWINCH, &sa, NULL);
#else
	sa.sa_restorer = NULL;
	sigaction(SIGCHLD, &sa, NULL);

	// Setup signal forwarding
	sa.sa_handler = forward_signal;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	sa.sa_restorer = NULL;

	sigaction(SIGHUP, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGQUIT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGUSR1, &sa, NULL);
	sigaction(SIGUSR2, &sa, NULL);
	sigaction(SIGPWR, &sa, NULL);
	sigaction(SIGWINCH, &sa, NULL);
#endif
}

static void reap_children(void)
{
	pid_t pid;
	int status;

	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
		if (pid == systemd_pid) {
			// Systemd exited
			if (WIFEXITED(status)) {
				ruri_log("{base}systemd exited with status %d\n", WEXITSTATUS(status));
				exit(WEXITSTATUS(status));
			} else if (WIFSIGNALED(status)) {
				ruri_log("{base}systemd killed by signal %d\n", WTERMSIG(status));
				exit(128 + WTERMSIG(status));
			}
		}
	}
}

static void run_systemd_as_init(char *const argv[])
{
	/*
	 * Fork and exec systemd as PID 1's child,
	 * then act as init by reaping zombies and forwarding signals.
	 */
	systemd_pid = fork();
	if (systemd_pid < 0) {
		ruri_error("{red}Failed to fork for systemd\n");
	}

	if (systemd_pid == 0) {
		// Child process: exec systemd
		// Reset signal handlers
		signal(SIGCHLD, SIG_DFL);
		signal(SIGHUP, SIG_DFL);
		signal(SIGINT, SIG_DFL);
		signal(SIGQUIT, SIG_DFL);
		signal(SIGTERM, SIG_DFL);
		signal(SIGUSR1, SIG_DFL);
		signal(SIGUSR2, SIG_DFL);
		signal(SIGPWR, SIG_DFL);
		signal(SIGWINCH, SIG_DFL);

		// Set default environment for systemd
		setenv("container", "ruri", 1);

		execvp(argv[0], argv);
		ruri_error("{red}Failed to exec systemd: %s\n", strerror(errno));
	}

	// Parent process: act as init
	setup_signal_handlers();

	// Main loop: wait for signals and reap children
	while (1) {
		// Check if any child exited
		if (child_exited) {
			child_exited = 0;
			reap_children();
		}

		// Wait for next signal
		pause();
	}
}

void ruri_init_systemd(struct RURI_CONTAINER *container)
{
	/*
	 * Initialize systemd mode.
	 * This should be called after chroot but before exec.
	 */
	if (!container->systemd_mode) {
		return;
	}

	// Only work in unshare mode (PID namespace)
	if (!container->enable_unshare) {
		ruri_error("{red}systemd mode requires --unshare option (PID namespace)\n");
	}

	// Ensure we're running as root in the container
	if (getuid() != 0 && geteuid() != 0) {
		ruri_error("{red}systemd mode requires root privileges\n");
	}
}

void ruri_run_systemd_init(char *const command[])
{
	/*
	 * Run systemd with ruri acting as init process.
	 * This function never returns (it calls exit when systemd exits).
	 */
	if (command == NULL || command[0] == NULL) {
		ruri_error("{red}No command specified for systemd mode\n");
	}

	// Check if the init binary exists
	if (access(command[0], X_OK) != 0) {
		ruri_error("{red}Init binary not found or not executable: %s\n", command[0]);
	}

	ruri_log("{base}Starting systemd as init process: %s\n", command[0]);
	run_systemd_as_init(command);
}

#else // !ENABLE_SYSTEMD

void ruri_init_systemd(struct RURI_CONTAINER *container __attribute__((unused)))
{
	// Stub when systemd support is disabled
	return;
}

void ruri_run_systemd_init(char *const command[] __attribute__((unused)))
{
	// Stub when systemd support is disabled
	ruri_error("{red}systemd support is not enabled. Rebuild with --enable-systemd\n");
}

#endif // ENABLE_SYSTEMD
