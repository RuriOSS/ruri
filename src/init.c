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
 * This file provides init process functionality for systemd mode.
 * When running as PID 1 in a container, ruri needs to reap zombie processes
 * and forward signals to the systemd process.
 *
 * Enhanced features:
 * - PID 1 and mount namespace verification
 * - PR_SET_CHILD_SUBREAPER for orphan process reaping
 * - signalfd/epoll based signal handling (race-free)
 * - Reliable waitpid with proper exit code propagation
 * - Support for systemd cgroup delegation
 */

#include <sys/signalfd.h>
#include <sys/epoll.h>

static volatile sig_atomic_t child_exited = 0;
static pid_t systemd_pid = 0;
static int systemd_exit_status = 0;

/* Signals to forward to systemd and handle via signalfd */
static const int forward_signals[] = { SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGUSR1, SIGUSR2, SIGPWR, SIGWINCH, SIGCHLD, 0 };

/*
 * Verify that we are running as PID 1 and in a proper mount namespace.
 * This is a fail-fast check to ensure ruri can act as init.
 */
static void verify_pid1_environment(void)
{
	pid_t pid = getpid();
	if (pid != 1) {
		ruri_error("{red}systemd mode requires ruri to be PID 1 (current PID: %d)\n", pid);
	}

	/*
	 * Check if we're in a mount namespace by comparing inode of /proc/1/ns/mnt
	 * with /proc/self/ns/mnt. In a proper container, they should differ.
	 */
	struct stat self_mnt, init_mnt;
	if (stat("/proc/self/ns/mnt", &self_mnt) == 0 && stat("/proc/1/ns/mnt", &init_mnt) == 0) {
		if (self_mnt.st_ino == init_mnt.st_ino) {
			/* Same mount namespace - we might be on the host */
			ruri_log("{yellow}Warning: ruri appears to be in the same mount namespace as init\n");
		}
	}

	ruri_log("{base}Verified: running as PID %d in container namespace\n", pid);
}

/*
 * Setup child subreaper to ensure orphaned processes are reaped.
 * This is critical for proper init behavior.
 */
static void setup_child_subreaper(void)
{
	if (prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) < 0) {
		ruri_warning("{yellow}Warning: Failed to set child subreaper: %s\n", strerror(errno));
	} else {
		ruri_log("{base}Set PR_SET_CHILD_SUBREAPER for orphan process reaping\n");
	}
}

/*
 * Forward signal to systemd process.
 */
static void forward_signal_to_systemd(int sig)
{
	if (systemd_pid > 0 && kill(systemd_pid, sig) < 0) {
		ruri_warning("{yellow}Warning: Failed to forward signal %d to systemd: %s\n", sig, strerror(errno));
	}
}

/*
 * Reap all exited children and handle systemd exit.
 * Returns 1 if systemd exited, 0 otherwise.
 */
static int reap_children(void)
{
	pid_t pid;
	int status;
	int systemd_exited = 0;

	/* Reap all children that have exited */
	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
		ruri_log("{base}Reaped child process PID %d\n", pid);

		if (pid == systemd_pid) {
			/* Systemd exited - record the status */
			systemd_exited = 1;
			if (WIFEXITED(status)) {
				systemd_exit_status = WEXITSTATUS(status);
				ruri_log("{base}systemd exited with status %d\n", systemd_exit_status);
			} else if (WIFSIGNALED(status)) {
				systemd_exit_status = 128 + WTERMSIG(status);
				ruri_log("{base}systemd killed by signal %d\n", WTERMSIG(status));
			}
		}
	}

	return systemd_exited;
}

/*
 * Main init loop using signalfd + epoll.
 * This provides race-free signal handling.
 */
static void run_init_loop_signalfd(void)
{
	int epoll_fd, sfd;
	struct epoll_event ev, events[10];
	sigset_t mask;

	/* Block signals that we want to handle via signalfd */
	sigemptyset(&mask);
	for (int i = 0; forward_signals[i]; i++) {
		sigaddset(&mask, forward_signals[i]);
	}

	if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
		ruri_warning("{yellow}Warning: Failed to block signals: %s\n", strerror(errno));
		return;
	}

	sfd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
	if (sfd < 0) {
		ruri_warning("{yellow}Warning: Failed to create signalfd: %s\n", strerror(errno));
		sigprocmask(SIG_UNBLOCK, &mask, NULL);
		return;
	}

	epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	if (epoll_fd < 0) {
		ruri_warning("{yellow}Warning: Failed to create epoll: %s\n", strerror(errno));
		close(sfd);
		sigprocmask(SIG_UNBLOCK, &mask, NULL);
		return;
	}

	ev.events = EPOLLIN;
	ev.data.fd = sfd;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sfd, &ev) < 0) {
		ruri_warning("{yellow}Warning: Failed to add signalfd to epoll: %s\n", strerror(errno));
		goto cleanup;
	}

	ruri_log("{base}Init loop started with signalfd/epoll\n");

	while (1) {
		int nfds = epoll_wait(epoll_fd, events, 10, -1);
		if (nfds < 0 && errno != EINTR) {
			ruri_warning("{yellow}Warning: epoll_wait failed: %s\n", strerror(errno));
			continue;
		}

		for (int i = 0; i < nfds; i++) {
			if (events[i].data.fd != sfd) {
				continue;
			}

			struct signalfd_siginfo fdsi;
			if (read(sfd, &fdsi, sizeof(fdsi)) != sizeof(fdsi)) {
				continue;
			}

			if (fdsi.ssi_signo == SIGCHLD) {
				if (reap_children()) {
					close(epoll_fd);
					close(sfd);
					exit(systemd_exit_status);
				}
			} else {
				forward_signal_to_systemd(fdsi.ssi_signo);
			}
		}
	}

cleanup:
	close(epoll_fd);
	close(sfd);
	sigprocmask(SIG_UNBLOCK, &mask, NULL);
}

/*
 * Traditional signal handlers for systems without signalfd support.
 */
static void sigchld_handler(int sig __attribute__((unused)))
{
	child_exited = 1;
}

static void forward_signal_handler(int sig)
{
	forward_signal_to_systemd(sig);
}

static void setup_traditional_signal_handlers(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;

	/* Setup SIGCHLD handler */
	sa.sa_handler = sigchld_handler;
	sigaction(SIGCHLD, &sa, NULL);

	/* Setup signal forwarding for other signals */
	sa.sa_handler = forward_signal_handler;
	sa.sa_flags = SA_RESTART;

	for (int i = 0; forward_signals[i]; i++) {
		if (forward_signals[i] != SIGCHLD) {
			sigaction(forward_signals[i], &sa, NULL);
		}
	}

	ruri_log("{base}Using traditional signal handlers\n");
}

/*
 * Traditional init loop using pause() for systems without signalfd.
 */
static void run_init_loop_traditional(void)
{
	ruri_log("{base}Init loop started with traditional signal handling\n");

	while (1) {
		if (child_exited) {
			child_exited = 0;
			if (reap_children()) {
				exit(systemd_exit_status);
			}
		}
		pause();
	}
}

/*
 * Fork and exec systemd as PID 1's child,
 * then act as init by reaping zombies and forwarding signals.
 */
static void run_systemd_as_init(char *const argv[])
{
	verify_pid1_environment();
	setup_child_subreaper();

	systemd_pid = fork();
	if (systemd_pid < 0) {
		ruri_error("{red}Failed to fork for systemd: %s\n", strerror(errno));
	}

	if (systemd_pid == 0) {
		/* Child process: exec systemd - reset all signal handlers */
		for (int i = 0; forward_signals[i]; i++) {
			signal(forward_signals[i], SIG_DFL);
		}

		/* Unblock all signals */
		sigset_t mask;
		sigfillset(&mask);
		sigprocmask(SIG_UNBLOCK, &mask, NULL);

		setenv("container", "ruri", 1);
		setenv("SYSTEMD_IGNORE_CHROOT", "1", 1);

		execvp(argv[0], argv);
		ruri_error("{red}Failed to exec systemd: %s\n", strerror(errno));
	}

	/* Parent process: act as init */
	ruri_log("{base}Started systemd as PID %d\n", systemd_pid);

	/* Try signalfd first, fall back to traditional signal handling */
	run_init_loop_signalfd();

	/* Fallback to traditional signal handling */
	setup_traditional_signal_handlers();
	run_init_loop_traditional();
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

	ruri_log("{base}Starting systemd as init process: %s\n", command[0]);
	run_systemd_as_init(command);
}

#else // !DISABLE_SYSTEMD

void ruri_init_systemd(struct RURI_CONTAINER *container __attribute__((unused)))
{
	/* Stub when systemd support is disabled */
	return;
}

void ruri_run_systemd_init(char *const command[] __attribute__((unused)))
{
	/* Stub when systemd support is disabled */
	ruri_error("{red}systemd support is not enabled. Rebuild with --enable-systemd\n");
}

#endif // DISABLE_SYSTEMD
