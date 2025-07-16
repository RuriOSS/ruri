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
 * This file provides functions to show or kill all processes in the container.
 * Note:
 * For unshare container without pid ns,
 * we can not recognize the pids in container.
 * And for that with pid ns, just kill pid 1 of the ns,
 * and all processes will be destroyed.
 */
static char *getpid_name(pid_t pid)
{
	/*
	 * Get the name of the process by pid.
	 * Warning: free() the return value after using it.
	 */
	char path[PATH_MAX];
	sprintf(path, "%s%d%s", "/proc/", pid, "/stat");
	char buf[8192];
	char name_buf[PATH_MAX];
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	read(fd, buf, sizeof(buf));
	if (fd < 0) {
		return strdup(" ");
	}
	int j = 0;
	for (unsigned long i = 0; i < sizeof(buf); i++) {
		if (j == 1) {
			for (unsigned long k = 0; buf[k + i + 1] != ')'; k++) {
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
	sprintf(path, "%s%d%s", "/proc/", pid, "/stat");
	char buf[8192];
	char stat_buf[PATH_MAX];
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		return strdup(" ");
	}
	read(fd, buf, sizeof(buf));
	int j = 0;
	for (unsigned long i = 0; i < sizeof(buf); i++) {
		if (j == 2) {
			for (unsigned long k = 0; buf[k + i] != ' '; k++) {
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
static void test_and_print_pid(pid_t pid, char *_Nonnull container_dir, bool in_pid_ns)
{
	/*
	 * If /proc/pid/root is container_dir, print the pid.
	 */
	char path[PATH_MAX];
	sprintf(path, "%s%d%s", "/proc/", pid, "/root");
	char buf[PATH_MAX];
	realpath(path, buf);
	ruri_log("{base}Pid: {cyan}%d\n", pid);
	ruri_log("{base}Root: {cyan}%s\n", buf);
	if (strcmp(buf, container_dir) == 0) {
		char *name = getpid_name(pid);
		char *pid_status = getpid_stat(pid);
		if (name != NULL && pid_status != NULL) {
			if (in_pid_ns) {
				printf("--> %d %s %s\n", pid, name, pid_status);
			} else {
				printf("%d %s %s\n", pid, name, pid_status);
			}
		}
		free(name);
		free(pid_status);
	}
}
static void container_ps__(char *_Nonnull container_dir, bool in_pid_ns)
{
	/*
	 * Show the processes in the container.
	 * This is the core function of ruri_container_ps().
	 */
	DIR *proc_dir = opendir("/proc");
	struct dirent *file = NULL;
	int len = 0;
	while ((file = readdir(proc_dir)) != NULL) {
		if (file->d_type == DT_DIR) {
			len++;
		}
	}
	seekdir(proc_dir, 0);
	int pids[len + 11];
	// For passing clang-tidy.
	memset(pids, 0, sizeof(pids));
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
			test_and_print_pid(pids[j], container_dir, in_pid_ns);
		} else {
			break;
		}
	}
	closedir(proc_dir);
}
static int join_ns(pid_t ns_pid)
{
	/*
	 * Try to join the pid and mount namespace of the container.
	 * If failed, return -1.
	 */
	if (geteuid() != 0) {
		ruri_error("{red}Error: Please run `ruri -P` with sudo.\n");
	}
	char path[PATH_MAX];
	sprintf(path, "%s%d%s", "/proc/", ns_pid, "/ns/pid");
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		return -1;
	}
	setns(fd, 0);
	close(fd);
	ruri_log("{base}Joined pid namespace\n");
	sprintf(path, "%s%d%s", "/proc/", ns_pid, "/ns/mnt");
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		return -1;
	}
	setns(fd, 0);
	close(fd);
	chdir("/");
	ruri_log("{base}Joined mount namespace\n");
	return 0;
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
		if (join_ns(container->ns_pid) == 0) {
			printf("%d %s %s\n", container->ns_pid, name, pid_status);
			in_pid_ns = true;
			// If we successfully joined the namespace,
			// The root of the process is now "/".
			container_dir = "/";
		}
		free(name);
		free(pid_status);
	}
	container_ps__(container_dir, in_pid_ns);
	free(container);
	exit(EXIT_SUCCESS);
}
static bool is_container_process(pid_t pid, const char *_Nonnull container_dir)
{
	/*
	 * Check if the process is in the container.
	 */
	char path[PATH_MAX];
	sprintf(path, "%s%d%s", "/proc/", pid, "/root");
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
void ruri_kill_container(const char *_Nonnull container_dir)
{
	/*
	 *
	 * Check all the processes in /proc,
	 * If the process is in the container, kill it.
	 * We check for /proc/pid/root to determine if the process is in the container.
	 * This function is called by ruri_umount_container().
	 */
	DIR *proc_dir = opendir("/proc");
	struct dirent *file = NULL;
	int len = 0;
	while ((file = readdir(proc_dir)) != NULL) {
		if (file->d_type == DT_DIR) {
			len++;
		}
	}
	seekdir(proc_dir, 0);
	int pids[len + 11];
	// For passing clang-tidy.
	memset(pids, 0, sizeof(pids));
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
			if (is_container_process(pids[j], container_dir)) {
				ruri_log("{base}Killing pid: {cyan}%d\n", pids[j]);
				kill(pids[j], SIGKILL);
			}
		} else {
			break;
		}
	}
	closedir(proc_dir);
}