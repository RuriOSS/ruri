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
 * This file provides functions to show or kill processes in the container.
 * Note:
 * For unshare container without pid ns,
 * we can not recognize the pids in container by detecting /proc/pid/root,
 * but cgroup can be used for this.
 * And for unshare with pid ns, just kill pid 1 of the ns,
 * and all processes will be destroyed.
 */
static bool is_container_process(pid_t pid, const char *_Nonnull container_dir, int container_id);
static char *getpid_name(pid_t pid)
{
	/*
	 * Get the name of the process by pid.
	 * Warning: free() the return value after using it.
	 */
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s%d%s", "/proc/", pid, "/stat");
	char buf[8192];
	// Initialize to empty string to avoid returning an uninitialized value
	// if the expected format is not found in the file.
	char name_buf[PATH_MAX] = { '\0' };
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		return strdup(" ");
	}
	ssize_t bytes_read = read(fd, buf, sizeof(buf) - 1);
	if (bytes_read <= 0) {
		close(fd);
		return strdup(" ");
	}
	close(fd);
	buf[bytes_read] = '\0';
	int j = 0;
	for (unsigned long i = 0; i < (unsigned long)bytes_read; i++) {
		if (j == 1) {
			for (unsigned long k = 0; (k + i + 1 < (unsigned long)bytes_read) && buf[k + i + 1] != ')'; k++) {
				// Prevent writing past the end of name_buf.
				if (k >= sizeof(name_buf) - 1) {
					break;
				}
				name_buf[k] = buf[k + i + 1];
				name_buf[k + 1] = '\0';
			}
			break;
		}
		if (buf[i] == ' ') {
			j++;
		}
	}
	char *name = strdup(name_buf);
	return name;
}
static char *getpid_stat(pid_t pid)
{
	/*
	 * Get the status of the process by pid.
	 * Warning: free() the return value after using it.
	 */
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s%d%s", "/proc/", pid, "/stat");
	char buf[8192];
	// Initialize to empty string to avoid returning an uninitialized value
	// if the expected format is not found in the file.
	char stat_buf[PATH_MAX] = { '\0' };
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		return strdup(" ");
	}
	ssize_t bytes_read = read(fd, buf, sizeof(buf) - 1);
	if (bytes_read <= 0) {
		close(fd);
		return strdup(" ");
	}
	close(fd);
	buf[bytes_read] = '\0';
	int j = 0;
	for (unsigned long i = 0; i < (unsigned long)bytes_read; i++) {
		if (j == 2) {
			for (unsigned long k = 0; (k + i < (unsigned long)bytes_read) && buf[k + i] != ' '; k++) {
				// Prevent writing past the end of stat_buf.
				if (k >= sizeof(stat_buf) - 1) {
					break;
				}
				stat_buf[k] = buf[k + i];
				stat_buf[k + 1] = '\0';
			}
			break;
		}
		if (buf[i] == ' ') {
			j++;
		}
	}
	char *pid_status = strdup(stat_buf);
	return pid_status;
}
static void test_and_print_pid(pid_t pid, char *_Nonnull container_dir, int container_id)
{
	/*
	 * If pid is in the container, print it.
	 */
	if (is_container_process(pid, container_dir, container_id)) {
		char *name = getpid_name(pid);
		char *pid_status = getpid_stat(pid);
		if (name != NULL && pid_status != NULL) {
			printf("%d %s %s\n", pid, name, pid_status);
		}
		free(name);
		free(pid_status);
	}
}
static void container_ps__(char *_Nonnull container_dir, int container_id)
{
	/*
	 * Show the processes in the container.
	 * This is the core function of ruri_container_ps().
	 */
	DIR *proc_dir = opendir("/proc");
	if (proc_dir == NULL) {
		ruri_error("{red}Failed to open /proc QwQ\n");
	}
	struct dirent *file = NULL;
	int len = 0;
	while ((file = readdir(proc_dir)) != NULL) {
		if (file->d_type == DT_DIR) {
			len++;
		}
	}
	seekdir(proc_dir, 0);
	int *pids = malloc((len + 11) * sizeof(int));
	// For passing clang-tidy.
	memset(pids, 0, (len + 11) * sizeof(int));
	int i = 0;
	while ((file = readdir(proc_dir)) != NULL) {
		if (file->d_type == DT_DIR) {
			if (atoi(file->d_name) > 0) {
				pids[i] = atoi(file->d_name);
				pids[i + 1] = RURI_INIT_VALUE;
				i++;
			}
		}
	}
	for (int j = 0; j < len; j++) {
		if (pids[j] != RURI_INIT_VALUE) {
			ruri_log("{base}Checking pid: {cyan}%d\n", pids[j]);
			test_and_print_pid(pids[j], container_dir, container_id);
		} else {
			break;
		}
	}
	free(pids);
	closedir(proc_dir);
}
void ruri_container_ps(char *_Nonnull container_dir)
{
	/*
	 * Show the processes in the container.
	 * We check the root of each process, if it is the container directory, print the pid.
	 * if this is an unshare container, join the pid and mount namespace, so root is "/" now.
	 * if pid namespace is not supported, fallback to the behavior with common container.
	 */
	ruri_log("{base}Container directory: {cyan}%s\n", container_dir);
	if (geteuid() != 0) {
		ruri_warning("{yellow}Warning: Please run `ruri -P` with sudo.\n");
	}
	struct RURI_CONTAINER *container = ruri_read_info(NULL, container_dir);
	bool in_pid_ns = false;
	if (container->ns_pid > 0) {
		// We need to get the info of ns_pid before joining the namespace.
		char *name = getpid_name(container->ns_pid);
		char *pid_status = getpid_stat(container->ns_pid);
		free(name);
		free(pid_status);
	}
	container_ps__(container_dir, container->container_id);
	free(container);
	exit(EXIT_SUCCESS);
}
static bool is_container_process(pid_t pid, const char *_Nonnull container_dir, int container_id)
{
	/*
	 * Check if the process is in the container.
	 */
	if (container_dir == NULL) {
		ruri_warning("{base}Container directory is NULL, WHY??\n");
		return false;
	}
	if (ruri_pid_in_cgroup(pid, container_id)) {
		return true;
	}
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s%d%s", "/proc/", pid, "/root");
	char buf[PATH_MAX];
	buf[0] = '\0';
	realpath(path, buf);
	if (strcmp(buf, "/") == 0) {
		return false;
	}
	if (strcmp(buf, container_dir) == 0) {
		return true;
	}
	return false;
}
void ruri_kill_container(struct RURI_CONTAINER *_Nonnull container)
{
	/*
	 *
	 * Check all the processes in /proc,
	 * If the process is in the container, kill it.
	 * We check for /proc/pid/root to determine if the process is in the container.
	 * This function is called by ruri_umount_container().
	 */
	if (container->ns_pid > 0) {
		if (ruri_try_cgroup_kill(container) == 0) {
			ruri_log("{base}Killed container processes with cgroup v2\n");
		}
	}
	DIR *proc_dir = opendir("/proc");
	if (proc_dir == NULL) {
		ruri_error("{red}Failed to open /proc QwQ\n");
	}
	struct dirent *file = NULL;
	int len = 0;
	while ((file = readdir(proc_dir)) != NULL) {
		if (file->d_type == DT_DIR) {
			len++;
		}
	}
	seekdir(proc_dir, 0);
	int *pids = malloc((len + 11) * sizeof(int));
	// For passing clang-tidy.
	memset(pids, 0, (len + 11) * sizeof(int));
	int i = 0;
	while ((file = readdir(proc_dir)) != NULL) {
		if (file->d_type == DT_DIR) {
			if (atoi(file->d_name) > 0) {
				pids[i] = atoi(file->d_name);
				pids[i + 1] = RURI_INIT_VALUE;
				i++;
			}
		}
	}
	for (int j = 0; j < len; j++) {
		if (pids[j] != RURI_INIT_VALUE) {
			if (is_container_process(pids[j], container->container_dir, container->container_id)) {
				ruri_log("{base}Killing pid: {cyan}%d\n", pids[j]);
				kill(pids[j], SIGKILL);
			}
		} else {
			break;
		}
	}
	free(pids);
	closedir(proc_dir);
}
void ruri_stat(const char *pid_file)
{
	if (!pid_file) {
		cprintf("{red}Pid file is not specified, cannot show statistics\n{clear}");
		exit(114);
	}
	int pid_fd = open(pid_file, O_RDONLY | O_CLOEXEC);
	if (pid_fd < 0) {
		cprintf("{red}Failed to open pid file\n{clear}");
		exit(114);
	}
	char buf[256];
	ssize_t bytes_read = read(pid_fd, buf, sizeof(buf) - 1);
	if (bytes_read <= 0) {
		close(pid_fd);
		cprintf("{red}Failed to read pid file\n{clear}");
		exit(114);
	}
	buf[bytes_read] = '\0';
	if (strncmp(buf, "RURI_INIT_", 10) == 0) {
		// Get value after "RURI_INIT_"
		char *status = buf + 10;
		// Use strtoll() to convert the status to long long.
		char *endptr = NULL;
		long long status_code = strtoll(status, &endptr, 10);
		if (endptr == status || *endptr != '\n') {
			cprintf("{red}Invalid init time in pid file\n{clear}");
			exit(114);
		}
		if (status_code <= 0) {
			cprintf("{red}Invalid init time in pid file\n{clear}");
			exit(114);
		}
		struct timespec ts;
		clock_gettime(CLOCK_MONOTONIC, &ts);
		long long now_ns = (ts.tv_sec * 1000000000LL) + ts.tv_nsec;
		// Timeout 3s.
		if (now_ns - status_code > 3000000000LL) {
			cprintf("{yellow}Container is not running, last init time was %lld ns ago\n{clear}", now_ns - status_code);
			exit(114);
		} else {
			cprintf("{green}Container is initializing, init time was %lld ns ago\n{clear}", now_ns - status_code);
			exit(0);
		}
	}
	if (strncmp(buf, "RURI_PANIC_", 11) == 0) {
		cprintf("{red}Paniced\n{clear}");
		// Get reason.
		char *reason = buf + 11;
		if (strncmp(reason, "EXEC", 4) == 0) {
			cprintf("{red}Panic reason: execution failed\n{clear}");
		} else if (strncmp(reason, "INTERNAL", 8) == 0) {
			cprintf("{red}Panic reason: internal error\n{clear}");
		} else if (strncmp(reason, "TIMEOUT", 7) == 0) {
			cprintf("{red}Panic reason: timeout\n{clear}");
		} else {
			cprintf("{red}Panic reason: unknown\n{clear}");
		}
		exit(114);
	}
	if (strncmp(buf, "RURI_EXITED_", 12) == 0) {
		// Get value after "RURI_EXITED_"
		char *status = buf + 12;
		// Use strtol() to convert the status to long.
		char *endptr = NULL;
		long exit_code = strtol(status, &endptr, 10);
		if (endptr == status || *endptr != '\n') {
			cprintf("{red}Invalid exit code in pid file\n{clear}");
			exit(114);
		}
		if (exit_code == 0) {
			cprintf("{green}Exited normally with code 0\n{clear}");
		} else {
			cprintf("{yellow}Exited with code %ld\n{clear}", exit_code);
		}
		exit(114);
	}
	if (strncmp(buf, "RURI_SIGNALED_", 14) == 0) {
		// Get value after "RURI_SIGNALED_"
		char *status = buf + 14;
		// Use strtol() to convert the status to long.
		char *endptr = NULL;
		long signal_num = strtol(status, &endptr, 10);
		if (endptr == status || *endptr != '\n') {
			cprintf("{red}Invalid signal number in pid file\n{clear}");
			exit(114);
		}
		cprintf("{yellow}Killed by signal %ld\n{clear}", signal_num);
		exit(114);
	}
	if (strncmp(buf, "RURI_EXIT_UNKNOWN", 17) == 0) {
		cprintf("{yellow}Exited with unknown status\n{clear}");
		exit(114);
	}
	if (strncmp(buf, "RURI_WAIT_EXEC_", 15) == 0) {
		cprintf("{yellow}Waiting for SIGUSR1 signal before execvp(), pid: %s\n{clear}", buf + 15);
		exit(114);
	}
	// Use strtol() to convert all the buf.
	char *endptr = NULL;
	long pid = strtol(buf, &endptr, 10);
	if (endptr == buf || *endptr != '\n' || pid <= 0) {
		cprintf("{red}Invalid pid in pid file\n{clear}");
		exit(114);
	}
	// Test /proc/pid/stat to determine if the process is still running.
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "/proc/%ld/stat", pid);
	if (access(path, F_OK) == 0) {
		cprintf("{green}Running with pid %ld\n{clear}", pid);
		exit(0);
	} else {
		cprintf("{yellow}Pid %ld is not running\n{clear}", pid);
		exit(114);
	}
	exit(114);
}