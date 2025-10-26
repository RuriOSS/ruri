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
 * This file provides functions to read and store .rurienv file.
 * ${container_dir}/.rurienv file is a file that stores the runtime info of the container.
 * It's used when running and umounting container.
 * As we cannot trust files in the container,
 * this file is immutable and bind-mount as readonly to itself.
 */
// Check if the running pid is ruri.
static bool is_ruri_pid(pid_t pid)
{
	/*
	 * We check if /proc/pid/ns/mnt is same of /proc/self/ns/mnt.
	 * If it is, we think the pid is not a ruri process,
	 * because ruri will unshare the mount namespace.
	 * If not, we think the pid is a ruri process.
	 */
	char pid_ns_mnt[PATH_MAX] = { '\0' };
	sprintf(pid_ns_mnt, "/proc/%d/ns/mnt", pid);
	char *pid_ns_mnt_realpath = malloc(PATH_MAX);
	ssize_t len = readlink(pid_ns_mnt, pid_ns_mnt_realpath, PATH_MAX);
	if (len <= 0) {
		free(pid_ns_mnt_realpath);
		return false;
	}
	pid_ns_mnt_realpath[len] = '\0';
	char *self_ns_mnt_realpath = malloc(PATH_MAX);
	len = readlink("/proc/self/ns/mnt", self_ns_mnt_realpath, PATH_MAX);
	if (len <= 0) {
		free(self_ns_mnt_realpath);
		free(pid_ns_mnt_realpath);
		return false;
	}
	self_ns_mnt_realpath[len] = '\0';
	if (strcmp(pid_ns_mnt_realpath, self_ns_mnt_realpath) == 0) {
		free(self_ns_mnt_realpath);
		free(pid_ns_mnt_realpath);
		return false;
	}
	free(self_ns_mnt_realpath);
	free(pid_ns_mnt_realpath);
	return true;
}
// Get ns_pid.
pid_t ruri_get_ns_pid(const char *_Nonnull container_dir)
{
	/*
	 * Read .rurienv,
	 * and get the ns_pid.
	 * If the ns_pid is a ruri process,
	 * return the ns_pid.
	 * If not, return RURI_INIT_VALUE.
	 * If .rurienv does not exist, return RURI_INIT_VALUE.
	 */
	char file[PATH_MAX] = { '\0' };
	sprintf(file, "%s/.rurienv", container_dir);
	int fd = open(file, O_RDONLY | O_CLOEXEC);
	// If .rurienv file does not exist.
	if (fd < 0) {
		return RURI_INIT_VALUE;
	}
	struct stat filestat;
	fstat(fd, &filestat);
	off_t size = filestat.st_size;
	if (size >= 65536) {
		ruri_error("{red}Config file is too large, it should be less than 65536 bytes.\n{clear}");
	}
	close(fd);
	// Read .rurienv file.
	char *buf = k2v_open_file(file, (size_t)size);
	pid_t ret = k2v_get_key(int, "ns_pid", buf);
	free(buf);
	if (ret <= 0) {
		return RURI_INIT_VALUE;
	}
	if (is_ruri_pid(ret)) {
		return ret;
	}
	return RURI_INIT_VALUE;
}
// Format container info as k2v.
static char *build_container_info(const struct RURI_CONTAINER *_Nonnull container)
{
	/*
	 * Format container runtime info to k2v format,
	 * and return the formatted config.
	 */
	char *ret = NULL;
	int len = 0;
// drop_caplist.
#ifndef DISABLE_LIBCAP
	char *drop_caplist[RURI_CAP_LAST_CAP + 1] = { NULL };
	char *cap_tmp = NULL;
	for (int i = 0; true; i++) {
		if (container->drop_caplist[i] == RURI_INIT_VALUE) {
			len = i;
			break;
		}
		cap_tmp = cap_to_name(container->drop_caplist[i]);
		if (cap_tmp == NULL) {
			drop_caplist[i] = malloc(114);
			sprintf(drop_caplist[i], "%d", container->drop_caplist[i]);
		} else {
			drop_caplist[i] = strdup(cap_tmp);
			cap_free(cap_tmp);
			cap_tmp = NULL;
		}
	}
	ret = k2v_add_comment(ret, "The capability to drop.");
	ret = k2v_add_config(char_array, ret, "drop_caplist", drop_caplist, len);
	// Make ASAN happy.
	for (int i = 0; i < len; i++) {
		free(drop_caplist[i]);
	}
#endif
	// no_new_privs.
	ret = k2v_add_comment(ret, "Set NO_NEW_PRIVS bit.");
	ret = k2v_add_config(bool, ret, "no_new_privs", container->no_new_privs);
	// enable_seccomp.
	ret = k2v_add_comment(ret, "Enable built-in seccomp profile.");
	ret = k2v_add_config(bool, ret, "enable_seccomp", container->enable_default_seccomp);
	// seccomp_denied_syscall.
	for (int i = 0; true; i++) {
		if (container->seccomp_denied_syscall[i] == NULL) {
			len = i;
			break;
		}
	}
	ret = k2v_add_comment(ret, "Denied syscalls, use seccomp.");
	ret = k2v_add_config(char_array, ret, "deny_syscall", container->seccomp_denied_syscall, len);
	ret = k2v_add_newline(ret);
	// ns_pid.
	ret = k2v_add_comment(ret, "PID owning unshare namespace.");
	ret = k2v_add_config(int, ret, "ns_pid", container->ns_pid);
	// container_id.
	ret = k2v_add_comment(ret, "Container ID.");
	ret = k2v_add_config(int, ret, "container_id", container->container_id);
	// work_dir.
	ret = k2v_add_comment(ret, "Work directory.");
	ret = k2v_add_config(char, ret, "work_dir", container->work_dir);
	// no_warnings.
	ret = k2v_add_comment(ret, "Do not show warnings.");
	ret = k2v_add_config(bool, ret, "no_warnings", container->no_warnings);
	// no_network.
	ret = k2v_add_comment(ret, "Disable network.");
	ret = k2v_add_config(bool, ret, "no_network", container->no_network);
	// rootless
	ret = k2v_add_comment(ret, "Run rootless container.");
	ret = k2v_add_config(bool, ret, "rootless", container->rootless);
	// user.
	ret = k2v_add_comment(ret, "User to run command in the container.");
	ret = k2v_add_config(char, ret, "user", container->user);
	// OOM score.
	ret = k2v_add_comment(ret, "OOM score.");
	ret = k2v_add_config(int, ret, "oom_score_adj", container->oom_score_adj);
	// extra_mountpoint.
	for (int i = 0; true; i++) {
		if (container->extra_mountpoint[i] == NULL) {
			len = i;
			break;
		}
	}
	ret = k2v_add_comment(ret, "Extra mountpoint.");
	ret = k2v_add_config(char_array, ret, "extra_mountpoint", container->extra_mountpoint, len);
	// extra_ro_mountpoint.
	for (int i = 0; true; i++) {
		if (container->extra_ro_mountpoint[i] == NULL) {
			len = i;
			break;
		}
	}
	ret = k2v_add_comment(ret, "Extra read-only mountpoint.");
	ret = k2v_add_config(char_array, ret, "extra_ro_mountpoint", container->extra_ro_mountpoint, len);
	// env.
	for (int i = 0; true; i++) {
		if (container->env[i] == NULL) {
			len = i;
			break;
		}
	}
	ret = k2v_add_comment(ret, "Environment variable.");
	ret = k2v_add_config(char_array, ret, "env", container->env, len);
	ruri_log("{base}Container config in /.rurienv:{cyan}\n%s", ret);
	ret = k2v_add_newline(ret);
	// skip_setgroups.
	ret = k2v_add_comment(ret, "Skip setgroups() call.");
	ret = k2v_add_config(bool, ret, "skip_setgroups", container->skip_setgroups);
	return ret;
}
// Store container info.
void ruri_store_info(const struct RURI_CONTAINER *_Nonnull container)
{
	/*
	 * Format the runtime info of container to k2v format.
	 * And store the info to container_dir/.rurienv .
	 *
	 * How to avoid security issue?
	 *
	 * The .rurienv file is set to be immutable, but the container
	 * will not have cap_linux_immutable by default,
	 * that means the file will always be read-only
	 * into the container. So even if ruri have memory overflow bugs,
	 * it can not be exploited by modifying the .rurienv file.
	 */
	// Format container info.
	char *info = build_container_info(container);
	char file[PATH_MAX] = { '\0' };
	sprintf(file, "%s/.rurienv", container->container_dir);
	// Umount the .rurienv file.
	umount2(file, MNT_DETACH | MNT_FORCE);
	int fd = open(file, O_RDONLY | O_CLOEXEC);
	// We know that it's not recommended to use bitwise operator on signed int.
	// But I found this code in man-doc:
	//
	//       int attr;
	//       fd = open("pathname", ...);
	//
	//       ioctl(fd, FS_IOC_GETFLAGS, &attr);  /* Place current flags
	//                                              in 'attr' */
	//       attr |= FS_NOATIME_FL;              /* Tweak returned bit mask */
	//       ioctl(fd, FS_IOC_SETFLAGS, &attr);  /* Update flags for inode
	//                                              referred to by 'fd' */
	// And FS_IMMUTABLE_FL (0x00000010) is also (int) by default.
	// So I leave the `attr` to int.
	int attr = 0;
	if (fd >= 0) {
		// Unset the immutable flag so that we can remove the file.
		ioctl(fd, FS_IOC_GETFLAGS, &attr);
		attr &= ~FS_IMMUTABLE_FL;
		ioctl(fd, FS_IOC_SETFLAGS, &attr);
		remove(file);
		close(fd);
	}
	// Creat .rurienv file and open it.
	fd = open(file, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, S_IWUSR | S_IRUSR);
	// Write info to .rurienv file.
	write(fd, info, strlen(info));
	// Set immutable flag on .rurienv file.
	attr = 0;
	ioctl(fd, FS_IOC_GETFLAGS, &attr);
	attr |= FS_IMMUTABLE_FL;
	ioctl(fd, FS_IOC_SETFLAGS, &attr);
	close(fd);
	// Mount the .rurienv file as read-only.
	mount(file, file, NULL, MS_BIND | MS_REC, NULL);
	mount(file, file, NULL, MS_REMOUNT | MS_RDONLY | MS_BIND, NULL);
	free(info);
}
// Read .rurienv file.
struct RURI_CONTAINER *ruri_read_info(struct RURI_CONTAINER *_Nullable container, const char *_Nonnull container_dir)
{
	/*
	 * Get runtime info of container.
	 * And return the container struct back.
	 * For ruri_umount_container() and ruri_container_ps(), it will accept a NULL struct,
	 * and return a struct with malloced memory.
	 */
	char file[PATH_MAX] = { '\0' };
	sprintf(file, "%s/.rurienv", container_dir);
	int fd = open(file, O_RDONLY | O_CLOEXEC);
	// If .rurienv file does not exist.
	if (fd < 0) {
		// Return a malloced struct for ruri_umount_container() and ruri_container_ps().
		if (container == NULL) {
			container = (struct RURI_CONTAINER *)malloc(sizeof(struct RURI_CONTAINER));
			ruri_init_config(container);
			container->extra_mountpoint[0] = NULL;
			container->extra_ro_mountpoint[0] = NULL;
			container->ns_pid = RURI_INIT_VALUE;
			container->rootless = false;
		}
		return container;
	}
	struct stat filestat;
	fstat(fd, &filestat);
	off_t size = filestat.st_size;
	if (size >= 65536) {
		ruri_error("{red}Config file is too large, it should be less than 65536 bytes.\n{clear}");
	}
	close(fd);
	// Read .rurienv file.
	char *buf = k2v_open_file(file, (size_t)size);
	ruri_log("{base}Container config in /.rurienv:{cyan}\n%s", buf);
	// We only need to get part of container info when container is NULL.
	if (container == NULL) {
		// For ruri_umount_container().
		container = (struct RURI_CONTAINER *)malloc(sizeof(struct RURI_CONTAINER));
		ruri_init_config(container);
		int mlen = k2v_get_key(char_array, "extra_mountpoint", buf, container->extra_mountpoint, RURI_MAX_MOUNTPOINTS);
		container->extra_mountpoint[mlen] = NULL;
		container->extra_mountpoint[mlen + 1] = NULL;
		mlen = k2v_get_key(char_array, "extra_ro_mountpoint", buf, container->extra_ro_mountpoint, RURI_MAX_MOUNTPOINTS);
		container->extra_ro_mountpoint[mlen] = NULL;
		container->extra_ro_mountpoint[mlen + 1] = NULL;
		// For ruri_container_ps() and ruri_umount_container().
		if (is_ruri_pid(k2v_get_key(int, "ns_pid", buf))) {
			container->ns_pid = k2v_get_key(int, "ns_pid", buf);
		} else {
			container->ns_pid = RURI_INIT_VALUE;
		}
		// Get rootless.
		container->rootless = k2v_get_key(bool, "rootless", buf);
		close(fd);
		free(buf);
		return container;
	}
	// Check if ns_pid is a ruri process.
	// If not, that means the container is not running.
	if ((container->enable_unshare || container->rootless) && !is_ruri_pid(k2v_get_key(int, "ns_pid", buf))) {
		ruri_log("{base}pid %d is not a ruri process.\n", k2v_get_key(int, "ns_pid", buf));
		free(buf);
		// Unset immutable flag of .rurienv.
		umount2(file, MNT_DETACH | MNT_FORCE);
		fd = open(file, O_RDONLY | O_CLOEXEC);
		if (fd < 0 && !container->no_warnings) {
			ruri_warning("{yellow}Open .rurienv failed{clear}\n");
		}
		int attr = 0;
		ioctl(fd, FS_IOC_GETFLAGS, &attr);
		attr &= ~FS_IMMUTABLE_FL;
		ioctl(fd, FS_IOC_SETFLAGS, &attr);
		remove(file);
		close(fd);
		remove(file);
		return container;
	}
	// Rootless container will only get ns_pid, work_dir and user.
	// Because these config are safe.
	if (container->rootless) {
		container->ns_pid = k2v_get_key(int, "ns_pid", buf);
		if (container->work_dir == NULL) {
			container->work_dir = k2v_get_key(char, "work_dir", buf);
		}
		if (container->user == NULL) {
			container->user = k2v_get_key(char, "user", buf);
		}
		free(buf);
		// Unset timens offsets because it's already set.
		container->timens_realtime_offset = 0;
		container->timens_monotonic_offset = 0;
		return container;
	}
	// Backup container config.
	struct RURI_CONTAINER *backup = (struct RURI_CONTAINER *)malloc(sizeof(struct RURI_CONTAINER));
	memcpy(backup, container, sizeof(struct RURI_CONTAINER));
#ifndef DISABLE_LIBCAP
	// Get capabilities to drop.
	char *drop_caplist[RURI_CAP_LAST_CAP + 1] = { NULL };
	int caplen = k2v_get_key(char_array, "drop_caplist", buf, drop_caplist, RURI_CAP_LAST_CAP);
	drop_caplist[caplen] = NULL;
	for (int i = 0; true; i++) {
		if (drop_caplist[i] == NULL) {
			container->drop_caplist[i] = RURI_INIT_VALUE;
			break;
		}
		if (atoi(drop_caplist[i]) > 0) {
			container->drop_caplist[i] = atoi(drop_caplist[i]);
		} else {
			if (ruri_cap_from_name(drop_caplist[i], &(container->drop_caplist[i])) < 0) {
				ruri_error("{red}Invalid capability:%s\n{clear}", drop_caplist[i]);
			}
		}
		free(drop_caplist[i]);
		container->drop_caplist[i + 1] = RURI_INIT_VALUE;
	}
#endif
	// Check if drop_caplist changed.
	if (memcmp(backup->drop_caplist, container->drop_caplist, sizeof(cap_value_t) * RURI_CAP_LAST_CAP) != 0) {
		if (!container->no_warnings) {
			ruri_warning("{yellow}.rurienv detected, drop_caplist changed{clear}\n");
		}
	}
	// Get no_new_privs.
	container->no_new_privs = k2v_get_key(bool, "no_new_privs", buf);
	// Check if no_new_privs changed.
	if (backup->no_new_privs != container->no_new_privs) {
		if (!container->no_warnings) {
			ruri_warning("{yellow}.rurienv detected, no_new_privs changed{clear}\n");
		}
	}
	// Get enable_seccomp.
	container->enable_default_seccomp = k2v_get_key(bool, "enable_seccomp", buf);
	// Check if enable_seccomp changed.
	if (backup->enable_default_seccomp != container->enable_default_seccomp) {
		if (!container->no_warnings) {
			ruri_warning("{yellow}.rurienv detected, enable_seccomp changed{clear}\n");
		}
	}
	// Get skip_setgroups.
	container->skip_setgroups = k2v_get_key(bool, "skip_setgroups", buf);
	// Check if skip_setgroups changed.
	if (backup->skip_setgroups != container->skip_setgroups) {
		if (!container->no_warnings) {
			ruri_warning("{yellow}.rurienv detected, skip_setgroups changed{clear}\n");
		}
	}
	// Get seccomp_denied_syscall.
	int seccomplen = k2v_get_key(char_array, "deny_syscall", buf, container->seccomp_denied_syscall, RURI_MAX_SECCOMP_DENIED_SYSCALL);
	container->seccomp_denied_syscall[seccomplen] = NULL;
	// Check if seccomp_denied_syscall changed.
	//
	// TODO
	//
	// Get ns_pid.
	container->ns_pid = k2v_get_key(int, "ns_pid", buf);
	ruri_log("{base}ns_pid: %d\n", container->ns_pid);
	// Get container_id.
	container->container_id = k2v_get_key(int, "container_id", buf);
	// Get work_dir.
	if (container->work_dir == NULL) {
		container->work_dir = k2v_get_key(char, "work_dir", buf);
	}
	// Get no_warnings.
	container->no_warnings = k2v_get_key(bool, "no_warnings", buf);
	// User.
	if (container->user == NULL) {
		container->user = k2v_get_key(char, "user", buf);
	}
	// Get no_network.
	container->no_network = k2v_get_key(bool, "no_network", buf);
	// Get oom_score_adj.
	container->oom_score_adj = k2v_get_key(int, "oom_score_adj", buf);
	// Get env.
	int envlen = k2v_get_key(char_array, "env", buf, container->env, RURI_MAX_ENVS);
	container->env[envlen] = NULL;
	container->env[envlen + 1] = NULL;
	// Qemu will only be set when initializing container.
	free(container->cross_arch);
	free(container->qemu_path);
	container->qemu_path = NULL;
	container->cross_arch = NULL;
	// Unset cgroup limits because it's already set.
	container->cpuset = NULL;
	container->memory = NULL;
	container->cpupercent = RURI_INIT_VALUE;
	// Unset timens offsets because it's already set.
	container->timens_realtime_offset = 0;
	container->timens_monotonic_offset = 0;
	free(buf);
	free(backup);
	return container;
}
