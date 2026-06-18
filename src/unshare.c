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
 *
 */
#include "include/ruri.h"
/*
 * This file provides unshare container support for ruri.
 * The design is: unshare(2) or setns(2), then fork(2),
 * Then, we can just call ruri_run_container(), the next step have the same logic.
 *
 * For historical reason, unshare is not enabled by default in ruri.
 */
// For ruri_run_unshare_container().
static pid_t init_unshare_container(struct RURI_CONTAINER *_Nonnull container)
{
	/*
	 * Use unshare(2) to create new namespaces and fork(2) to join them.
	 * Return pid of forked process.
	 *
	 * NOTE: Network namespace is not fully supported.
	 * But, as it can be setuped in privileged environment before running container,
	 * I think it's not necessory to implement it in ruri.
	 */
	// unshare_pid in forked process is 0.
	pid_t unshare_pid = RURI_INIT_VALUE;
	// Create namespaces.
	int unshare_ret = 0;
	unshare_ret = unshare(CLONE_NEWNS);
	ruri_panic_on_error(unshare_ret, 0, "{red}Unshare container need at least mount ns support QwQ\n");
	unshare_ret = unshare(CLONE_NEWUTS);
	ruri_warn_on_error(unshare_ret, 0, !container->no_warnings, "{yellow}Warning: seems that uts namespace is not supported on this device QwQ{clear}\n");
	unshare_ret = unshare(CLONE_NEWIPC);
	ruri_warn_on_error(unshare_ret, 0, !container->no_warnings, "{yellow}Warning: seems that ipc namespace is not supported on this device QwQ{clear}\n");
	unshare_ret = unshare(CLONE_NEWPID);
	ruri_warn_on_error(unshare_ret, 0, !container->no_warnings, "{yellow}Warning: seems that pid namespace is not supported on this device QwQ{clear}\n");
	unshare_ret = unshare(CLONE_NEWCGROUP);
	ruri_warn_on_error(unshare_ret, 0, !container->no_warnings, "{yellow}Warning: seems that cgroup namespace is not supported on this device QwQ{clear}\n");
	if (unshare(CLONE_NEWTIME) == -1) {
		if (container->timens_realtime_offset != 0 || container->timens_monotonic_offset != 0) {
			ruri_error("{red}Failed to unshare time namespace, --timens-offset cannot be enabled QwQ\n");
		}
		ruri_warn_on_error(1, 0, !container->no_warnings, "{yellow}Warning: seems that time namespace is not supported on this device QwQ{clear}\n");
	}
	if (container->timens_monotonic_offset != 0) {
		int fd = open("/proc/self/timens_offsets", O_WRONLY | O_CLOEXEC);
		if (fd < 0) {
			ruri_error("{red}Error: failed to open /proc/self/timens_offsets QwQ\n");
		}
		char buf[1024] = { '\0' };
		sprintf(buf, _Generic((time_t)0, long: "monotonic %ld 0", long long: "monotonic %lld 0", default: "monotonic %ld 0"), container->timens_monotonic_offset);
		write(fd, buf, strlen(buf));
		close(fd);
	}
	if (container->timens_realtime_offset != 0) {
		int fd = open("/proc/self/timens_offsets", O_WRONLY | O_CLOEXEC);
		if (fd < 0) {
			ruri_error("{red}Error: failed to open /proc/self/timens_offsets QwQ\n");
		}
		char buf[1024] = { '\0' };
		sprintf(buf, _Generic((time_t)0, long: "boottime %ld 0", long long: "boottime %lld 0", default: "boottime %ld 0"), container->timens_realtime_offset);
		write(fd, buf, strlen(buf));
		close(fd);
	}
	unshare_ret = unshare(CLONE_FILES);
	ruri_warn_on_error(unshare_ret, 0, !container->no_warnings, "{yellow}Warning: seems that we could not unshare file descriptors with child process QwQ{clear}\n");
	unshare_ret = unshare(CLONE_FS);
	ruri_warn_on_error(unshare_ret, 0, !container->no_warnings, "{yellow}Warning: seems that we could not unshare filesystem information with child process QwQ{clear}\n");
	// Disable network.
	if (container->no_network) {
		if (unshare(CLONE_NEWNET) == -1) {
			ruri_error("{red}Failed to unshare network namespace, --no-network cannot be enabled QwQ\n");
		}
	}
	// before fork()
	int sync_pipe[2] = { -1, -1 };
	if (pipe2(sync_pipe, O_CLOEXEC) < 0) {
		ruri_error("{red}pipe2 sync failed, QwQ?\n");
	}
	// Fork itself into namespace.
	unshare_pid = fork();
	if (unshare_pid > 0) {
		// Store container info.
		if (container->use_rurienv) {
			container->ns_pid = unshare_pid;
			ruri_store_info(container);
		} else if (!container->no_warnings) {
			ruri_warning("{base}NS PID:{green} %d\n", unshare_pid);
		}
		ruri_pid_file_write(RURI_PID_FILE_PID, unshare_pid);
		// parent: close write end, wait for child sync signal first
		close(sync_pipe[1]);
		char ready = 0;
		ssize_t n = read(sync_pipe[0], &ready, 1);
		close(sync_pipe[0]);
		if (n < 0) {
			ruri_warn_on_error(1, 0, !container->no_warnings, "{yellow}sync pipe read failed{clear}\n");
		}
		int stat = 0;
		waitpid(unshare_pid, &stat, 0);
		// Write exit status to pid_fd.
		// Write exit status to pid_fd.
		if (WIFEXITED(stat)) {
			ruri_pid_file_write(RURI_PID_FILE_EXITED, WEXITSTATUS(stat));
		} else if (WIFSIGNALED(stat)) {
			ruri_pid_file_write(RURI_PID_FILE_SIGNALED, WTERMSIG(stat));
		} else {
			ruri_pid_file_write(RURI_PID_FILE_UNKNOWN, 0);
		}
		if (WIFEXITED(stat)) {
			exit(WEXITSTATUS(stat));
		}
		if (WIFSIGNALED(stat)) {
			exit(128 + WTERMSIG(stat));
		}
		exit(EXIT_FAILURE);
	} else if (unshare_pid == 0) {
		// child: close read end and notify parent we reached child path
		close(sync_pipe[0]);
		char ready = 1;
		(void)write(sync_pipe[1], &ready, 1);
		close(sync_pipe[1]);
	} else {
		// fork failed
		close(sync_pipe[0]);
		close(sync_pipe[1]);
		ruri_error("{red}Fork error, QwQ?\n");
	}
	return unshare_pid;
}
// For ruri_run_unshare_container().
static pid_t join_ns(struct RURI_CONTAINER *_Nonnull container)
{
	/*
	 * Use setns(2) to enter existing namespaces.
	 */
	pid_t unshare_pid = RURI_INIT_VALUE;
	// We only need 0(stdin), 1(stdout), 2(stderr), and pid_fd
	// So we close the other fds to avoid security issues.
	// NOTE: this might cause unknown issues.
	for (int i = 3; i <= 10; i++) {
		if (i == ruri_pid_file_fd(-1)) {
			continue;
		}
		close(i);
	}
	// Use setns(2) to enter existing namespaces.
	char cgroup_ns_file[PATH_MAX] = { '\0' };
	char ipc_ns_file[PATH_MAX] = { '\0' };
	char mount_ns_file[PATH_MAX] = { '\0' };
	char pid_ns_file[PATH_MAX] = { '\0' };
	char time_ns_file[PATH_MAX] = { '\0' };
	char uts_ns_file[PATH_MAX] = { '\0' };
	sprintf(cgroup_ns_file, "%s%d%s", "/proc/", container->ns_pid, "/ns/cgroup");
	sprintf(ipc_ns_file, "%s%d%s", "/proc/", container->ns_pid, "/ns/ipc");
	sprintf(mount_ns_file, "%s%d%s", "/proc/", container->ns_pid, "/ns/mnt");
	sprintf(pid_ns_file, "%s%d%s", "/proc/", container->ns_pid, "/ns/pid");
	sprintf(time_ns_file, "%s%d%s", "/proc/", container->ns_pid, "/ns/time");
	sprintf(uts_ns_file, "%s%d%s", "/proc/", container->ns_pid, "/ns/uts");
	// Enter namespaces via setns(2).
	int ns_fd = RURI_INIT_VALUE;
	ns_fd = open(pid_ns_file, O_RDONLY | O_CLOEXEC);
	if (ns_fd < 0) {
		ruri_warn_on_error(1, 0, !container->no_warnings, "{yellow}Warning: seems that pid namespace is not supported on this device QwQ{clear}\n");
	} else {
		if (setns(ns_fd, CLONE_NEWPID) == -1) {
			ruri_error("{red}Failed to setns pid namespace QwQ\n");
		}
		close(ns_fd);
	}
	ns_fd = open(time_ns_file, O_RDONLY | O_CLOEXEC);
	if (ns_fd < 0) {
		ruri_warn_on_error(1, 0, !container->no_warnings, "{yellow}Warning: seems that time namespace is not supported on this device QwQ{clear}\n");
	} else {
		if (setns(ns_fd, CLONE_NEWTIME) == -1) {
			ruri_error("{red}Failed to setns time namespace QwQ\n");
		}
		close(ns_fd);
	}
	ns_fd = open(uts_ns_file, O_RDONLY | O_CLOEXEC);
	if (ns_fd < 0) {
		ruri_warn_on_error(1, 0, !container->no_warnings, "{yellow}Warning: seems that uts namespace is not supported on this device QwQ{clear}\n");
	} else {
		if (setns(ns_fd, CLONE_NEWUTS) == -1) {
			ruri_error("{red}Failed to setns uts namespace QwQ\n");
		}
		close(ns_fd);
	}
	ns_fd = open(cgroup_ns_file, O_RDONLY | O_CLOEXEC);
	if (ns_fd < 0) {
		ruri_warn_on_error(1, 0, !container->no_warnings, "{yellow}Warning: seems that cgroup namespace is not supported on this device QwQ{clear}\n");
	} else {
		if (setns(ns_fd, CLONE_NEWCGROUP) == -1) {
			ruri_error("{red}Failed to setns cgroup namespace QwQ\n");
		}
		close(ns_fd);
	}
	ns_fd = open(ipc_ns_file, O_RDONLY | O_CLOEXEC);
	if (ns_fd < 0) {
		ruri_warn_on_error(1, 0, !container->no_warnings, "{yellow}Warning: seems that ipc namespace is not supported on this device QwQ{clear}\n");
	} else {
		if (setns(ns_fd, CLONE_NEWIPC) == -1) {
			ruri_error("{red}Failed to setns ipc namespace QwQ\n");
		}
		close(ns_fd);
	}
	// Disable network.
	if (container->no_network) {
		char net_ns_file[PATH_MAX] = { '\0' };
		sprintf(net_ns_file, "%s%d%s", "/proc/", container->ns_pid, "/ns/net");
		ns_fd = open(net_ns_file, O_RDONLY | O_CLOEXEC);
		if (ns_fd < 0) {
			ruri_error("{red}--no-network detected, but failed to open network namespace QwQ\n");
		}
		if (setns(ns_fd, CLONE_NEWNET) == -1) {
			ruri_error("{red}--no-network detected, but failed to setns network namespace QwQ\n");
		}
	} else {
		// Join net ns will be forced.
		// As I plan to add net ns support in rurima.
		char net_ns_file[PATH_MAX] = { '\0' };
		sprintf(net_ns_file, "%s%d%s", "/proc/", container->ns_pid, "/ns/net");
		ns_fd = open(net_ns_file, O_RDONLY | O_CLOEXEC);
		setns(ns_fd, CLONE_NEWNET);
	}
	ns_fd = open(mount_ns_file, O_RDONLY | O_CLOEXEC);
	if (ns_fd < 0) {
		ruri_error("{red}Unshare container need at least mount ns support QwQ\n");
	} else {
		if (setns(ns_fd, CLONE_NEWNS) == -1) {
			ruri_error("{red}Failed to setns mount namespace QwQ\n");
		}
		close(ns_fd);
	}
	// Close fds after fork().
	unshare(CLONE_FILES);
	// Fork itself into namespace.
	// This can fix `can't fork: out of memory` issue.
	unshare_pid = fork();
	// Fix `can't access tty` issue.
	if (unshare_pid > 0) {
		ruri_pid_file_write(RURI_PID_FILE_PID, unshare_pid);
		// Wait until current process exit.
		int stat = 0;
		waitpid(unshare_pid, &stat, 0);
		// Write exit status to pid_fd.
		if (WIFEXITED(stat)) {
			ruri_pid_file_write(RURI_PID_FILE_EXITED, WEXITSTATUS(stat));
		} else if (WIFSIGNALED(stat)) {
			ruri_pid_file_write(RURI_PID_FILE_SIGNALED, WTERMSIG(stat));
		} else {
			ruri_pid_file_write(RURI_PID_FILE_UNKNOWN, 0);
		}
		if (WIFEXITED(stat)) {
			exit(WEXITSTATUS(stat));
		}
		if (WIFSIGNALED(stat)) {
			exit(128 + WTERMSIG(stat));
		}
		exit(EXIT_FAILURE);
	}
	// Maybe this will never be run.
	else if (unshare_pid < 0) {
		ruri_error("{red}Fork error, QwQ?\n");
		return 1;
	}
	return unshare_pid;
}
static void setup_cgroup2(int container_id)
{
	mkdir("/sys/fs/cgroup/ruri", 0755);
	char cgroup_dir[PATH_MAX] = { '\0' };
	sprintf(cgroup_dir, "/sys/fs/cgroup/ruri/%d", container_id);
	if (mkdir(cgroup_dir, 0755) == -1) {
		ruri_error("{red}Failed to create cgroup directory QwQ\n");
	}
	FILE *cgroup_procs = fopen(strcat(cgroup_dir, "/cgroup.procs"), "we");
	if (!cgroup_procs) {
		ruri_error("{red}Failed to open cgroup.procs QwQ\n");
	}
	fprintf(cgroup_procs, "%d", getpid());
	fclose(cgroup_procs);
}
static void join_cgroup2(int container_id)
{
	char cgroup_dir[PATH_MAX] = { '\0' };
	sprintf(cgroup_dir, "/sys/fs/cgroup/ruri/%d/cgroup.procs", container_id);
	FILE *cgroup_procs = fopen(cgroup_dir, "we");
	if (!cgroup_procs) {
		ruri_error("{red}Failed to open cgroup.procs QwQ\n");
	}
	fprintf(cgroup_procs, "%d", getpid());
	fclose(cgroup_procs);
}
// Run unshare container.
void ruri_run_unshare_container(struct RURI_CONTAINER *_Nonnull container)
{
	/*
	 * We first read /.rurienv file to get container config.
	 * If container->ns_pid is not set, use unshare(2) to create new namespaces.
	 * If container->ns_pid is set, use setns(2) to enter existing namespaces.
	 */
	ruri_proc_mark(RURI_UNSHARE);
	ruri_check_container_dir(container->container_dir);
	pid_t unshare_pid = RURI_INIT_VALUE;
	// unshare(2) itself into new namespaces.
	if (container->use_rurienv) {
		container = ruri_read_info(container, container->container_dir);
	}
	if (container->ns_pid < 0) {
		if (container->is_health_check) {
			ruri_error("{red}Error: health check should not run before container is initialized QwQ\n");
		}
		if (!container->systemd_mode) {
			ruri_set_limit(container);
		} else {
			setup_cgroup2(container->container_id);
		}
		unshare_pid = init_unshare_container(container);
	} else {
		container->first_init = false;
		if (!container->systemd_mode) {
			ruri_set_limit(container);
		} else {
			join_cgroup2(container->container_id);
		}
		unshare_pid = join_ns(container);
	}
	ruri_log("{base}ns pid: %d\n", container->ns_pid);
	// Check if we have joined the container's namespaces.
	if (unshare_pid == 0) {
		ruri_run_chroot_container(container);
	}
}
