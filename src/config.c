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
 * This file provides config file support for ruri.
 * ruri_init_config() is also here.
 * Not very graceful, but it works.
 */
void ruri_init_config(struct RURI_CONTAINER *_Nonnull container)
{
	/*
	 * Initialize a RURI_CONTAINER struct.
	 * Set all values to default.
	 */
	container->container_dir = NULL;
	for (int i = 0; i < RURI_CAP_LAST_CAP + 1; i++) {
		container->drop_caplist[i] = RURI_INIT_VALUE;
	}
	cap_value_t nullcaplist[2] = { RURI_INIT_VALUE };
	ruri_build_caplist(container->drop_caplist, false, nullcaplist, nullcaplist);
	container->enable_default_seccomp = false;
	container->no_new_privs = false;
	container->no_warnings = false;
	container->enable_unshare = false;
	container->rootless = false;
	container->mount_host_runtime = false;
	container->command[0] = NULL;
	container->env[0] = NULL;
	container->extra_mountpoint[0] = NULL;
	container->extra_ro_mountpoint[0] = NULL;
	container->cross_arch = NULL;
	container->qemu_path = NULL;
	container->ns_pid = RURI_INIT_VALUE;
#ifndef DISABLE_RURIENV
	container->use_rurienv = true;
#else
	container->use_rurienv = false;
#endif
	container->ro_root = false;
	container->cpuset = NULL;
	container->memory = NULL;
	container->work_dir = NULL;
	container->just_chroot = false;
	container->rootfs_source = NULL;
	container->unmask_dirs = false;
	container->user = NULL;
	container->hostname = NULL;
	container->cpupercent = RURI_INIT_VALUE;
	container->use_kvm = false;
	container->char_devs[0] = NULL;
	container->hidepid = RURI_INIT_VALUE;
	container->timens_realtime_offset = 0;
	container->timens_monotonic_offset = 0;
	container->seccomp_denied_syscall[0] = NULL;
	container->oom_score_adj = 0;
	// Use the time now for container_id.
	time_t tm = time(NULL);
	// We need a int value for container_id, so use long%86400.
	// (86400 is the seconds of a day).
	container->container_id = (int)(tm % 86400);
	container->masked_path[0] = NULL;
	container->enable_tty_signals = false;
	container->skip_setgroups = false;
}
static int pmcrts(const char *s1, const char *s2)
{
	/*
	 *
	 * Compare two strings, but s2 is in the end of s1.
	 * Return the same value as strcmp() s2 and the end of s1.
	 * If s1 is shorter than s2, it will return -1.
	 *
	 */
	size_t len1 = strlen(s1);
	size_t len2 = strlen(s2);
	if (len1 < len2) {
		return -1; // s1 is shorter than s2
	}
	return strcmp(s2, s1 + len1 - len2);
}
char *ruri_container_info_to_k2v(const struct RURI_CONTAINER *_Nonnull container)
{
	/*
	 * Format container info to k2v format.
	 * return the config as string.
	 */
	// Add the shebang.
	char ruri_bin_path[PATH_MAX] = { '\0' };
	if (readlink("/proc/self/exe", ruri_bin_path, PATH_MAX) <= 0) {
		sprintf(ruri_bin_path, "%s", "/usr/bin/ruri");
	}
	char shebang[PATH_MAX + 16] = { '\0' };
	// Detect rurima.
	if (pmcrts(ruri_bin_path, "rurima") == 0) {
		sprintf(shebang, "#!%s ruri -c\n\n", ruri_bin_path);
	} else {
		sprintf(shebang, "#!%s -c\n\n", ruri_bin_path);
	}
	char *ret = strdup(shebang);
	// container_dir.
	ret = k2v_add_comment(ret, "The CONTAINER_DIR.");
	ret = k2v_add_comment(ret, "Should be an absolute path on host.");
	ret = k2v_add_comment(ret, "This can not be empty.");
	ret = k2v_add_config(char, ret, "container_dir", container->container_dir);
	ret = k2v_add_newline(ret);
	// user.
	ret = k2v_add_comment(ret, "The user to run command in the container.");
	ret = k2v_add_comment(ret, "Use username or uid is both valid.");
	ret = k2v_add_comment(ret, "Default is root, set it to empty to use default.");
	ret = k2v_add_config(char, ret, "user", container->user);
	ret = k2v_add_newline(ret);
	// drop_caplist.
	char *drop_caplist[RURI_CAP_LAST_CAP + 1] = { NULL };
	int len = 0;
#ifndef DISABLE_LIBCAP
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
#endif
	ret = k2v_add_comment(ret, "The capability to drop.");
	ret = k2v_add_comment(ret, "Format: \"capname1\",\"capname2\".");
	ret = k2v_add_comment(ret, "For example, [\"cap_sys_admin\",\"cap_sys_chroot\"] is valid.");
	ret = k2v_add_config(char_array, ret, "drop_caplist", drop_caplist, len);
	ret = k2v_add_newline(ret);
	// Make ASAN happy.
	for (int i = 0; i < len; i++) {
		free(drop_caplist[i]);
	}
	// no_new_privs.
	ret = k2v_add_comment(ret, "Set NO_NEW_PRIVS bit.");
	ret = k2v_add_comment(ret, "Default is false.");
	ret = k2v_add_config(bool, ret, "no_new_privs", container->no_new_privs);
	ret = k2v_add_newline(ret);
	// enable_unshare.
	ret = k2v_add_comment(ret, "Enable unshare feature.");
	ret = k2v_add_comment(ret, "Default is false.");
	ret = k2v_add_config(bool, ret, "enable_unshare", container->enable_unshare);
	ret = k2v_add_newline(ret);
	// rootless.
	ret = k2v_add_comment(ret, "Run rootless container.");
	ret = k2v_add_comment(ret, "Need user ns support.");
	ret = k2v_add_comment(ret, "Default is false.");
	ret = k2v_add_config(bool, ret, "rootless", container->rootless);
	ret = k2v_add_newline(ret);
	// no_warnings.
	ret = k2v_add_comment(ret, "Disable warnings.");
	ret = k2v_add_comment(ret, "Default is false.");
	ret = k2v_add_config(bool, ret, "no_warnings", container->no_warnings);
	ret = k2v_add_newline(ret);
	// cross_arch.
	ret = k2v_add_comment(ret, "The arch for running cross-arch container.");
	ret = k2v_add_comment(ret, "For example, x86_64.");
	ret = k2v_add_comment(ret, "Should also set qemu_path.");
	ret = k2v_add_comment(ret, "Set it to empty to disable.");
	ret = k2v_add_config(char, ret, "cross_arch", container->cross_arch);
	ret = k2v_add_newline(ret);
	// qemu_path.
	ret = k2v_add_comment(ret, "The path of qemu-user static binary.");
	ret = k2v_add_comment(ret, "For example, /usr/bin/qemu-x86_64-static.");
	ret = k2v_add_comment(ret, "Should also set cross_arch.");
	ret = k2v_add_comment(ret, "Set it to empty to disable.");
	ret = k2v_add_config(char, ret, "qemu_path", container->qemu_path);
	ret = k2v_add_newline(ret);
	// use_rurienv.
	ret = k2v_add_comment(ret, "Enable using .rurienv file.");
	ret = k2v_add_comment(ret, "Default is true.");
	ret = k2v_add_config(bool, ret, "use_rurienv", container->use_rurienv);
	ret = k2v_add_newline(ret);
	// enable_default_seccomp.
	ret = k2v_add_comment(ret, "Enable built-in seccomp profile.");
	ret = k2v_add_comment(ret, "Default is false.");
	ret = k2v_add_config(bool, ret, "enable_seccomp", container->enable_default_seccomp);
	ret = k2v_add_newline(ret);
	// hidepid.
	ret = k2v_add_comment(ret, "Hide pid in /proc.");
	ret = k2v_add_comment(ret, "Can be 1 or 2, set <=0 to use default.");
	ret = k2v_add_config(int, ret, "hidepid", container->hidepid);
	ret = k2v_add_newline(ret);
	// cpuset.
	ret = k2v_add_comment(ret, "Cgroup cpuset limit.");
	ret = k2v_add_comment(ret, "For example, 0-2 or 0 is valid.");
	ret = k2v_add_comment(ret, "Set it to empty to disable.");
	ret = k2v_add_config(char, ret, "cpuset", container->cpuset);
	ret = k2v_add_newline(ret);
	// cpupercent.
	ret = k2v_add_comment(ret, "Cgroup cpu limit.");
	ret = k2v_add_comment(ret, "The value is in percentage, set it <=0 to disable.");
	ret = k2v_add_config(int, ret, "cpupercent", container->cpupercent);
	ret = k2v_add_newline(ret);
	// memory.
	ret = k2v_add_comment(ret, "Cgroup memory limit.");
	ret = k2v_add_comment(ret, "For example, 1G or 1024M is valid.");
	ret = k2v_add_comment(ret, "Set it to empty to disable.");
	ret = k2v_add_config(char, ret, "memory", container->memory);
	ret = k2v_add_newline(ret);
	// just_chroot.
	ret = k2v_add_comment(ret, "Just chroot, do not create runtime dirs.");
	ret = k2v_add_comment(ret, "Default is false.");
	ret = k2v_add_config(bool, ret, "just_chroot", container->just_chroot);
	ret = k2v_add_newline(ret);
	// unmask_dirs.
	ret = k2v_add_comment(ret, "Unmask dirs in /proc and /sys.");
	ret = k2v_add_comment(ret, "Default is false.");
	ret = k2v_add_config(bool, ret, "unmask_dirs", container->unmask_dirs);
	ret = k2v_add_newline(ret);
	// mount_host_runtime.
	ret = k2v_add_comment(ret, "Mount runtime dirs from the host.");
	ret = k2v_add_comment(ret, "Default is false.");
	ret = k2v_add_config(bool, ret, "mount_host_runtime", container->mount_host_runtime);
	ret = k2v_add_newline(ret);
	// work_dir.
	ret = k2v_add_comment(ret, "Work directory.");
	ret = k2v_add_comment(ret, "Should be an absolute path in the container.");
	ret = k2v_add_comment(ret, "Default is / , set it to empty to use default.");
	ret = k2v_add_config(char, ret, "work_dir", container->work_dir);
	ret = k2v_add_newline(ret);
	// rootfs_source.
	ret = k2v_add_comment(ret, "Rootfs source, will be mount to / as first mountpoint.");
	ret = k2v_add_comment(ret, "Should be an absolute path in the host.");
	ret = k2v_add_comment(ret, "/path/to/rootfs.img or /dev/sda1 is valid.");
	ret = k2v_add_comment(ret, "Set it to empty to use container_dir as default.");
	ret = k2v_add_config(char, ret, "rootfs_source", container->rootfs_source);
	ret = k2v_add_newline(ret);
	// ro_root.
	ret = k2v_add_comment(ret, "Make / read-only.");
	ret = k2v_add_comment(ret, "Default is false.");
	ret = k2v_add_config(bool, ret, "ro_root", container->ro_root);
	ret = k2v_add_newline(ret);
	// no_network.
	ret = k2v_add_comment(ret, "Disable network.");
	ret = k2v_add_comment(ret, "This also need enable_unshare to be true.");
	ret = k2v_add_comment(ret, "Default is false.");
	ret = k2v_add_config(bool, ret, "no_network", container->no_network);
	ret = k2v_add_newline(ret);
	// Use kvm.
	ret = k2v_add_comment(ret, "Use kvm");
	ret = k2v_add_comment(ret, "Default is false.");
	ret = k2v_add_config(bool, ret, "use_kvm", container->use_kvm);
	// oom_score_adj.
	ret = k2v_add_comment(ret, "OOM score.");
	ret = k2v_add_comment(ret, "Default is 0.");
	ret = k2v_add_comment(ret, "Set it to 0 to disable.");
	ret = k2v_add_config(int, ret, "oom_score_adj", container->oom_score_adj);
	ret = k2v_add_newline(ret);
	// extra_mountpoint.
	for (int i = 0; true; i++) {
		if (container->extra_mountpoint[i] == NULL) {
			len = i;
			break;
		}
	}
	ret = k2v_add_comment(ret, "Extra mountpoint.");
	ret = k2v_add_comment(ret, "Format: \"source\",\"target\".");
	ret = k2v_add_comment(ret, "For example, [\"/tmp\",\"/tmp\",\"/var\",\"/var\"] is valid.");
	ret = k2v_add_comment(ret, "Set it to empty to disable.");
	ret = k2v_add_config(char_array, ret, "extra_mountpoint", container->extra_mountpoint, len);
	ret = k2v_add_newline(ret);
	// extra_ro_mountpoint.
	for (int i = 0; true; i++) {
		if (container->extra_ro_mountpoint[i] == NULL) {
			len = i;
			break;
		}
	}
	ret = k2v_add_comment(ret, "Extra read-only mountpoint.");
	ret = k2v_add_comment(ret, "Format: \"source\",\"target\".");
	ret = k2v_add_comment(ret, "For example, [\"/tmp\",\"/tmp\",\"/var\",\"/var\"] is valid.");
	ret = k2v_add_comment(ret, "Set it to empty to disable.");
	ret = k2v_add_config(char_array, ret, "extra_ro_mountpoint", container->extra_ro_mountpoint, len);
	ret = k2v_add_newline(ret);
	// env.
	for (int i = 0; true; i++) {
		if (container->env[i] == NULL) {
			len = i;
			break;
		}
	}
	ret = k2v_add_comment(ret, "Environment variable.");
	ret = k2v_add_comment(ret, "Format: \"key\",\"value\".");
	ret = k2v_add_comment(ret, "For example, [\"key1\",\"value1\",\"key2\",\"value2\"] is valid.");
	ret = k2v_add_comment(ret, "Set it to empty to disable.");
	ret = k2v_add_config(char_array, ret, "env", container->env, len);
	ret = k2v_add_newline(ret);
	// Char devices.
	for (int i = 0; true; i++) {
		if (container->char_devs[i] == NULL) {
			len = i;
			break;
		}
	}
	ret = k2v_add_comment(ret, "Extra char devices.");
	ret = k2v_add_comment(ret, "Format: \"device\",\"major\",\"minor\".");
	ret = k2v_add_comment(ret, "For example, [\"kvm\",\"10\",\"232\"] is valid.");
	ret = k2v_add_comment(ret, "Set it to empty to disable.");
	ret = k2v_add_config(char_array, ret, "char_devs", container->char_devs, len);
	ret = k2v_add_newline(ret);
	// command.
	for (int i = 0; true; i++) {
		if (container->command[i] == NULL) {
			len = i;
			break;
		}
	}
	ret = k2v_add_comment(ret, "Default command to run.");
	ret = k2v_add_comment(ret, "For example, [\"/bin/sh\",\"-c\",\"echo hello\"] is valid.");
	ret = k2v_add_comment(ret, "Set it to empty to use default (/bin/su - or /bin/sh).");
	ret = k2v_add_config(char_array, ret, "command", container->command, len);
	ret = k2v_add_newline(ret);
	// hostname.
	ret = k2v_add_comment(ret, "The hostname of the container.");
	ret = k2v_add_comment(ret, "This is only for unshare container.");
	ret = k2v_add_comment(ret, "Set it to empty to disable it.");
	ret = k2v_add_config(char, ret, "hostname", container->hostname);
	ret = k2v_add_newline(ret);
	// Time offset.
	ret = k2v_add_comment(ret, "Time offset for timens.");
	ret = k2v_add_comment(ret, "Default is 0.");
	ret = k2v_add_comment(ret, "Need unshare enabled.");
	ret = k2v_add_config(long, ret, "timens_monotonic_offset", container->timens_monotonic_offset);
	ret = k2v_add_config(long, ret, "timens_realtime_offset", container->timens_realtime_offset);
	ret = k2v_add_newline(ret);
	// seccomp_denied_syscall.
	for (int i = 0; true; i++) {
		if (container->seccomp_denied_syscall[i] == NULL) {
			len = i;
			break;
		}
	}
	ret = k2v_add_comment(ret, "Denied syscalls, use seccomp.");
	ret = k2v_add_comment(ret, "For example, [\"syscall1\",\"syscall2\"] is valid.");
	ret = k2v_add_comment(ret, "Set it to empty to disable.");
	ret = k2v_add_config(char_array, ret, "deny_syscall", container->seccomp_denied_syscall, len);
	ret = k2v_add_newline(ret);
	// masked_path.
	for (int i = 0; true; i++) {
		if (container->masked_path[i] == NULL) {
			len = i;
			break;
		}
	}
	ret = k2v_add_comment(ret, "Masked path, will be masked with ro tmpfs or /dev/null.");
	ret = k2v_add_comment(ret, "Format: \"path\".");
	ret = k2v_add_comment(ret, "For example, [\"/sys/class\",\"/etc/ssl\"] is valid.");
	ret = k2v_add_comment(ret, "Set it to empty to disable.");
	ret = k2v_add_config(char_array, ret, "masked_path", container->masked_path, len);
	ret = k2v_add_newline(ret);
	// enable_tty_signals.
	ret = k2v_add_comment(ret, "Enable TTY signals in the container.");
	ret = k2v_add_config(bool, ret, "enable_tty_signals", container->enable_tty_signals);
	ret = k2v_add_newline(ret);
	// skip_setgroups.
	ret = k2v_add_comment(ret, "Skip setgroups() call.");
	ret = k2v_add_config(bool, ret, "skip_setgroups", container->skip_setgroups);
	return ret;
}
void ruri_read_config(struct RURI_CONTAINER *_Nonnull container, const char *_Nonnull path)
{
	/*
	 * Read k2v format config file,
	 * and set container config.
	 */
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		ruri_error("{red}No such file or directory:%s\n{clear}", path);
	}
	struct stat filestat;
	fstat(fd, &filestat);
	off_t size = filestat.st_size;
	if (size >= 65536) {
		ruri_error("{red}Config file is too large, it should be less than 65536 bytes.\n{clear}");
	}
	close(fd);
	char *buf = k2v_open_file(path, (size_t)size);
	// Check if config is valid.
	char *key_list[] = { "timens_realtime_offset", "timens_monotonic_offset", "hidepid", "char_devs", "use_kvm", "no_network", "container_dir", "user", "drop_caplist", "no_new_privs", "enable_seccomp", "rootless", "no_warnings", "cross_arch", "qemu_path", "use_rurienv", "cpuset", "memory", "cpupercent", "just_chroot", "unmask_dirs", "mount_host_runtime", "work_dir", "rootfs_source", "ro_root", "extra_mountpoint", "extra_ro_mountpoint", "env", "command", "hostname", NULL };
	for (int i = 0; key_list[i] != NULL; i++) {
		if (!have_key(key_list[i], buf)) {
			ruri_error("{red}Invalid config file, there is no key:%s\nHint:\n You can try to use `ruri -C config` to fix the config file{clear}", key_list[i]);
		}
	}
#ifndef DISABLE_LIBCAP
	// Get drop_caplist.
	char *drop_caplist[RURI_CAP_LAST_CAP + 1] = { NULL };
	int caplen = k2v_get_key(char_array, "drop_caplist", buf, drop_caplist, RURI_CAP_LAST_CAP);
	drop_caplist[caplen] = NULL;
	for (int i = 0; true; i++) {
		if (drop_caplist[i] == NULL) {
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
	// Get no_new_privs.
	container->no_new_privs = k2v_get_key(bool, "no_new_privs", buf);
	// Get enable_seccomp.
	container->enable_default_seccomp = k2v_get_key(bool, "enable_seccomp", buf);
	// Get container_dir.
	container->container_dir = k2v_get_key(char, "container_dir", buf);
	// Get qemu_path.
	container->qemu_path = k2v_get_key(char, "qemu_path", buf);
	// Get cross_arch.
	container->cross_arch = k2v_get_key(char, "cross_arch", buf);
	// Get rootless.
	container->rootless = k2v_get_key(bool, "rootless", buf);
	// Get mount_host_runtime.
	container->mount_host_runtime = k2v_get_key(bool, "mount_host_runtime", buf);
	// Get ro_root.
	container->ro_root = k2v_get_key(bool, "ro_root", buf);
	// Get no_warnings.
	container->no_warnings = k2v_get_key(bool, "no_warnings", buf);
	// Get use_rurienv.
	container->use_rurienv = k2v_get_key(bool, "use_rurienv", buf);
#ifdef DISABLE_RURIENV
	container->use_rurienv = false;
#endif
	// Get cpuset.
	container->cpuset = k2v_get_key(char, "cpuset", buf);
	// Get memory.
	container->memory = k2v_get_key(char, "memory", buf);
	// Get cpupercent.
	container->cpupercent = k2v_get_key(int, "cpupercent", buf);
	// Get just_chroot.
	container->just_chroot = k2v_get_key(bool, "just_chroot", buf);
	// Get work_dir.
	container->work_dir = k2v_get_key(char, "work_dir", buf);
	// Get rootfs_source.
	container->rootfs_source = k2v_get_key(char, "rootfs_source", buf);
	// Get unmask_dirs.
	container->unmask_dirs = k2v_get_key(bool, "unmask_dirs", buf);
	// Get hostname.
	container->hostname = k2v_get_key(char, "hostname", buf);
	// Get no_network.
	container->no_network = k2v_get_key(bool, "no_network", buf);
	// Get use_kvm.
	container->use_kvm = k2v_get_key(bool, "use_kvm", buf);
	// Get hidepid.
	container->hidepid = k2v_get_key(int, "hidepid", buf);
	// Get oom_score_adj.
	container->oom_score_adj = k2v_get_key(int, "oom_score_adj", buf);
	// Get skip_setgroups.
	container->skip_setgroups = k2v_get_key(bool, "skip_setgroups", buf);
	// Get user.
	if (container->user == NULL) {
		container->user = k2v_get_key(char, "user", buf);
	}
	// Get env.
	int envlen = k2v_get_key(char_array, "env", buf, container->env, RURI_MAX_ENVS);
	if (envlen % 2 != 0) {
		ruri_error("{red}Invalid env format\n{clear}");
	}
	container->env[envlen] = NULL;
	container->env[envlen + 1] = NULL;
	// Get extra_mountpoint.
	int mlen = k2v_get_key(char_array, "extra_mountpoint", buf, container->extra_mountpoint, RURI_MAX_MOUNTPOINTS);
	if (mlen % 2 != 0) {
		ruri_error("{red}Invalid extra_mountpoint format\n{clear}");
	}
	container->extra_mountpoint[mlen] = NULL;
	container->extra_mountpoint[mlen + 1] = NULL;
	// Get extra_ro_mountpoint.
	mlen = k2v_get_key(char_array, "extra_ro_mountpoint", buf, container->extra_ro_mountpoint, RURI_MAX_MOUNTPOINTS);
	if (mlen % 2 != 0) {
		ruri_error("{red}Invalid extra_ro_mountpoint format\n{clear}");
	}
	container->extra_ro_mountpoint[mlen] = NULL;
	container->extra_ro_mountpoint[mlen + 1] = NULL;
	// Get char_devs.
	int charlen = k2v_get_key(char_array, "char_devs", buf, container->char_devs, RURI_MAX_CHAR_DEVS);
	container->char_devs[charlen] = NULL;
	if (charlen % 3 != 0) {
		ruri_error("{red}Invalid char_devs format\n{clear}");
	}
	// Get seccomp_denied_syscall.
	int seccomplen = k2v_get_key(char_array, "deny_syscall", buf, container->seccomp_denied_syscall, RURI_MAX_SECCOMP_DENIED_SYSCALL);
	container->seccomp_denied_syscall[seccomplen] = NULL;
	// Get time offset.
	container->timens_realtime_offset = k2v_get_key(long, "timens_realtime_offset", buf);
	container->timens_monotonic_offset = k2v_get_key(long, "timens_monotonic_offset", buf);
	// Get masked_path.
	int maskedlen = k2v_get_key(char_array, "masked_path", buf, container->masked_path, RURI_MAX_MOUNTPOINTS);
	container->masked_path[maskedlen] = NULL;
	// Get enable_tty_signals.
	container->enable_tty_signals = k2v_get_key(bool, "enable_tty_signals", buf);
	// Get command.
	int comlen = k2v_get_key(char_array, "command", buf, container->command, RURI_MAX_COMMANDS);
	container->command[comlen] = NULL;
	free(buf);
	buf = ruri_container_info_to_k2v(container);
	ruri_log("{base}Container config in %s:{cyan}\n%s", path, buf);
	free(buf);
}
void ruri_correct_config(const char *_Nonnull path)
{
	/*
	 * Correct the config file.
	 * This is useful when upgrading ruri to the new version.
	 */
	// Disable strict mode for libk2v.
	k2v_show_warning = false;
	k2v_stop_at_warning = false;
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		ruri_error("{red}No such file or directory:%s\n{clear}", path);
	}
	struct stat filestat;
	fstat(fd, &filestat);
	off_t size = filestat.st_size;
	if (size >= 65536) {
		ruri_error("{red}Config file is too large, it should be less than 65536 bytes.\n{clear}");
	}
	close(fd);
	char *buf = k2v_open_file(path, (size_t)size);
	if (!have_key("container_dir", buf)) {
		ruri_error("{red}Invalid config file, there is no key:container_dir\n{clear}");
	}
	struct RURI_CONTAINER container;
	container.container_dir = k2v_get_key(char, "container_dir", buf);
#ifndef DISABLE_LIBCAP
	if (!have_key("drop_caplist", buf)) {
		ruri_warning("{green}No key drop_caplist, we build a default one\n{clear}");
		cap_value_t nullcaplist[2] = { RURI_INIT_VALUE };
		ruri_build_caplist(container.drop_caplist, false, nullcaplist, nullcaplist);
	} else {
		char *drop_caplist[RURI_CAP_LAST_CAP + 1] = { NULL };
		int caplen = k2v_get_key(char_array, "drop_caplist", buf, drop_caplist, RURI_CAP_LAST_CAP);
		drop_caplist[caplen] = NULL;
		for (int i = 0; true; i++) {
			if (drop_caplist[i] == NULL) {
				break;
			}
			if (atoi(drop_caplist[i]) > 0) {
				container.drop_caplist[i] = atoi(drop_caplist[i]);
			} else {
				if (ruri_cap_from_name(drop_caplist[i], &(container.drop_caplist[i])) < 0) {
					ruri_warning("{green}Invalid capability in drop_caplist, we build a default one\n{clear}");
					cap_value_t nullcaplist[2] = { RURI_INIT_VALUE };
					ruri_build_caplist(container.drop_caplist, false, nullcaplist, nullcaplist);
				}
			}
			free(drop_caplist[i]);
			container.drop_caplist[i + 1] = RURI_INIT_VALUE;
		}
	}
#else
	container.drop_caplist[0] = RURI_INIT_VALUE;
#endif
	if (!have_key("command", buf)) {
		ruri_warning("{green}No key command found, set to {NULL}\n{clear}");
		container.command[0] = NULL;
	} else {
		int comlen = k2v_get_key(char_array, "command", buf, container.command, RURI_MAX_COMMANDS);
		container.command[comlen] = NULL;
	}
	if (!have_key("env", buf)) {
		ruri_warning("{green}No key env found, set to {NULL}\n{clear}");
		container.env[0] = NULL;
	} else {
		int envlen = k2v_get_key(char_array, "env", buf, container.env, RURI_MAX_ENVS);
		if (envlen % 2 != 0) {
			ruri_warning("{red}Invalid env format\n{clear}");
			container.env[0] = NULL;
		}
		container.env[envlen] = NULL;
		container.env[envlen + 1] = NULL;
	}
	if (!have_key("extra_mountpoint", buf)) {
		ruri_warning("{green}No key extra_mountpoint found, set to {NULL}\n{clear}");
		container.extra_mountpoint[0] = NULL;
	} else {
		int mlen = k2v_get_key(char_array, "extra_mountpoint", buf, container.extra_mountpoint, RURI_MAX_MOUNTPOINTS);
		if (mlen % 2 != 0) {
			ruri_warning("{red}Invalid extra_mountpoint format\n{clear}");
			container.extra_mountpoint[0] = NULL;
		}
		container.extra_mountpoint[mlen] = NULL;
		container.extra_mountpoint[mlen + 1] = NULL;
	}
	if (!have_key("char_devs", buf)) {
		ruri_warning("{green}No key char_devs found, set to {NULL}\n{clear}");
		container.char_devs[0] = NULL;
	} else {
		int charlen = k2v_get_key(char_array, "char_devs", buf, container.char_devs, RURI_MAX_CHAR_DEVS);
		container.char_devs[charlen] = NULL;
		if (charlen % 3 != 0) {
			ruri_warning("{red}Invalid char_devs format\n{clear}");
			container.char_devs[0] = NULL;
		}
	}
	if (!have_key("extra_ro_mountpoint", buf)) {
		ruri_warning("{green}No key extra_ro_mountpoint found, set to {NULL}\n{clear}");
		container.extra_ro_mountpoint[0] = NULL;
	} else {
		int mrlen2 = k2v_get_key(char_array, "extra_ro_mountpoint", buf, container.extra_ro_mountpoint, RURI_MAX_MOUNTPOINTS);
		if (mrlen2 % 2 != 0) {
			ruri_warning("{red}Invalid extra_ro_mountpoint format\n{clear}");
			container.extra_ro_mountpoint[0] = NULL;
		}
		container.extra_ro_mountpoint[mrlen2] = NULL;
		container.extra_ro_mountpoint[mrlen2 + 1] = NULL;
	}
	if (!have_key("no_new_privs", buf)) {
		ruri_warning("{green}No key no_new_privs found, set to false\n{clear}");
		container.no_new_privs = false;
	} else {
		container.no_new_privs = k2v_get_key(bool, "no_new_privs", buf);
	}
	if (!have_key("enable_seccomp", buf)) {
		ruri_warning("{green}No key enable_seccomp found, set to false\n{clear}");
		container.enable_default_seccomp = false;
	} else {
		container.enable_default_seccomp = k2v_get_key(bool, "enable_seccomp", buf);
	}
	if (!have_key("no_warnings", buf)) {
		ruri_warning("{green}No key no_warnings found, set to false\n{clear}");
		container.no_warnings = false;
	} else {
		container.no_warnings = k2v_get_key(bool, "no_warnings", buf);
	}
	if (!have_key("enable_unshare", buf)) {
		ruri_warning("{green}No key enable_unshare found, set to false\n{clear}");
		container.enable_unshare = false;
	} else {
		container.enable_unshare = k2v_get_key(bool, "enable_unshare", buf);
	}
	if (!have_key("rootless", buf)) {
		ruri_warning("{green}No key rootless found, set to false\n{clear}");
		container.rootless = false;
	} else {
		container.rootless = k2v_get_key(bool, "rootless", buf);
	}
	if (!have_key("mount_host_runtime", buf)) {
		ruri_warning("{green}No key mount_host_runtime found, set to false\n{clear}");
		container.mount_host_runtime = false;
	} else {
		container.mount_host_runtime = k2v_get_key(bool, "mount_host_runtime", buf);
	}
	if (!have_key("qemu_path", buf)) {
		ruri_warning("{green}No key qemu_path found, set to NULL\n{clear}");
		container.qemu_path = NULL;
	} else {
		container.qemu_path = k2v_get_key(char, "qemu_path", buf);
	}
	if (!have_key("cross_arch", buf)) {
		ruri_warning("{green}No key cross_arch found, set to NULL\n{clear}");
		container.cross_arch = NULL;
	} else {
		container.cross_arch = k2v_get_key(char, "cross_arch", buf);
	}
	if (!have_key("use_rurienv", buf)) {
		ruri_warning("{green}No key use_rurienv found, set to true\n{clear}");
		container.use_rurienv = true;
	} else {
		container.use_rurienv = k2v_get_key(bool, "use_rurienv", buf);
	}
#ifdef DISABLE_RURIENV
	container.use_rurienv = false;
#endif
	if (!have_key("ro_root", buf)) {
		ruri_warning("{green}No key ro_root found, set to false\n{clear}");
		container.ro_root = false;
	} else {
		container.ro_root = k2v_get_key(bool, "ro_root", buf);
	}
	if (!have_key("hidepid", buf)) {
		ruri_warning("{green}No key hidepid found, set to default value\n{clear}");
		container.hidepid = RURI_INIT_VALUE;
	} else {
		container.hidepid = k2v_get_key(int, "hidepid", buf);
	}
	if (!have_key("cpuset", buf)) {
		ruri_warning("{green}No key cpuset found, set to NULL\n{clear}");
		container.cpuset = NULL;
	} else {
		container.cpuset = k2v_get_key(char, "cpuset", buf);
	}
	if (!have_key("memory", buf)) {
		ruri_warning("{green}No key memory found, set to NULL\n{clear}");
		container.memory = NULL;
	} else {
		container.memory = k2v_get_key(char, "memory", buf);
	}
	if (!have_key("cpupercent", buf)) {
		ruri_warning("{green}No key cpupercent found, set to -114\n{clear}");
		container.cpupercent = RURI_INIT_VALUE;
	} else {
		container.cpupercent = k2v_get_key(int, "cpupercent", buf);
	}
	if (!have_key("just_chroot", buf)) {
		ruri_warning("{green}No key just_chroot found, set to false\n{clear}");
		container.just_chroot = false;
	} else {
		container.just_chroot = k2v_get_key(bool, "just_chroot", buf);
	}
	if (!have_key("unmask_dirs", buf)) {
		ruri_warning("{green}No key unmask_dirs found, set to false\n{clear}");
		container.unmask_dirs = false;
	} else {
		container.unmask_dirs = k2v_get_key(bool, "unmask_dirs", buf);
	}
	if (!have_key("work_dir", buf)) {
		ruri_warning("{green}No key work_dir found, set to NULL\n{clear}");
		container.work_dir = NULL;
	} else {
		container.work_dir = k2v_get_key(char, "work_dir", buf);
	}
	if (!have_key("rootfs_source", buf)) {
		ruri_warning("{green}No key rootfs_source found, set to NULL\n{clear}");
		container.rootfs_source = NULL;
	} else {
		container.rootfs_source = k2v_get_key(char, "rootfs_source", buf);
	}
	if (!have_key("no_network", buf)) {
		ruri_warning("{green}No key no_network found, set to false\n{clear}");
		container.no_network = false;
	} else {
		container.no_network = k2v_get_key(bool, "no_network", buf);
		if (container.no_network) {
			container.enable_unshare = true;
		}
	}
	if (!have_key("hostname", buf)) {
		ruri_warning("{green}No key hostname found, set to NULL\n{clear}");
		container.hostname = NULL;
	} else {
		container.hostname = k2v_get_key(char, "hostname", buf);
	}
	if (!have_key("use_kvm", buf)) {
		ruri_warning("{green}No key use_kvm found, set to false\n{clear}");
		container.use_kvm = false;
	} else {
		container.use_kvm = k2v_get_key(bool, "use_kvm", buf);
	}
	if (!have_key("timens_realtime_offset", buf)) {
		ruri_warning("{green}No key timens_realtime_offset found, set to 0\n{clear}");
		container.timens_realtime_offset = 0;
	} else {
		container.timens_realtime_offset = k2v_get_key(long, "timens_realtime_offset", buf);
	}
	if (!have_key("timens_monotonic_offset", buf)) {
		ruri_warning("{green}No key timens_monotonic_offset found, set to 0\n{clear}");
		container.timens_monotonic_offset = 0;
	} else {
		container.timens_monotonic_offset = k2v_get_key(long, "timens_monotonic_offset", buf);
	}
	if (!have_key("oom_score_adj", buf)) {
		ruri_warning("{green}No key oom_score_adj found, set to 0\n{clear}");
		container.oom_score_adj = 0;
	} else {
		container.oom_score_adj = k2v_get_key(int, "oom_score_adj", buf);
	}
	free(buf);
	unlink(path);
	remove(path);
	fd = open(path, O_CREAT | O_CLOEXEC | O_RDWR, S_IRUSR | S_IRGRP | S_IROTH | S_IWGRP | S_IWUSR | S_IWOTH);
	if (fd < 0) {
		ruri_error("{red}Error: failed to open output file QwQ\n");
	}
	char *config = ruri_container_info_to_k2v(&container);
	write(fd, config, strlen(config));
	close(fd);
	free(config);
}