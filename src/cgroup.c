// SPDX-License-Identifier: MIT
/*
 *
 * This file is part of ruri, with ABSOLUTELY NO WARRANTY.
 *
 * MIT License
 *
 * Copyright (c) 2022-2026 Moe-hacker
 *  and partially...  2026 BarryLhm
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
 * This file provides functions to set cgoup limits for container.
 * ${container_id} is set by the time creating the container,
 * And it will be unified by .rurienv file.
 *
 * TODO:
 * Add more cgroups support.
 */
// Returns -1 for malformed size
// Returns -2 for too large
static ssize_t humansize_to_bytes(const char *_Nonnull human)
{
	char *endptr = NULL;
	errno = 0;
	long long ret = strtoll(human, &endptr, 10);
	// these become too long after formatted
	// clang-format off
	if (errno == ERANGE) return -2;
	if (endptr == human || ret < 0) return -1; // no number or negative
	if (!*endptr) { if (ret > SSIZE_MAX) return -2;
	} else {
		if (*(endptr + 1)) return -1; // invalid unit
		switch (*endptr) {
		case 'k': case 'K': if (ret > SSIZE_MAX / 1024) return -2; ret *= 1024; break;
		case 'm': case 'M': if (ret > SSIZE_MAX / 1024 / 1024) return -2; ret *= 1024 * 1024; break;
		case 'g': case 'G': if (ret > SSIZE_MAX / 1024 / 1024 / 1024) return -2; ret *= 1024 * 1024 * 1024; break;
		default: return -1; // invalid unit
		}
	}
	// clang-format on
	return ret;
}
// Returns 1 for failed open() and 2 for failed write().
// Only write control files!!
static int open_and_write(const char *file, const char *value)
{
	// Open and write control file
	int fd = open(file, O_WRONLY | O_CLOEXEC);
	if (fd < 0) {
		return 1;
	}
	if (write(fd, value, strlen(value)) < 0) {
		close(fd);
		return 2;
	};
	close(fd);
	return 0;
}
/*
 *                                          _
 *   ___ __ _ _ __ ___  _   _ _ __   __   _/ |
 *  / __/ _` | '__/ _ \| | | | '_ \  \ \ / / |
 * | (_| (_| | | | (_) | |_| | |_) |  \ V /| |
 *  \___\__, |_|  \___/ \__,_| .__/    \_/ |_|
 *      |___/                |_|
 */
// Returns 1 for failed mount().
// Don't forget to usleep(200) after mount;
static int mount_cgroup_v1(const char *_Nonnull controller)
{
	/*
	 * Mount Cgroup v1 _any_ controller.
	 */
	mkdir("/sys/fs/cgroup", S_IRUSR | S_IWUSR);
	// Mount /sys/fs/cgroup as tmpfs.
	if (mount("tmpfs", "/sys/fs/cgroup", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RELATIME, NULL)) {
		goto fail;
	}
	// Mount memory controller.
	char cgroup_controller_path[PATH_MAX] = "";
	sprintf(cgroup_controller_path, "/sys/fs/cgroup/%s", controller);
	mkdir(cgroup_controller_path, S_IRUSR | S_IWUSR);
	if (mount("none", cgroup_controller_path, "cgroup", MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RELATIME, controller)) {
		goto fail;
	}
	char cgroup_root_node_path[PATH_MAX] = "";
	sprintf(cgroup_root_node_path, "/sys/fs/cgroup/%s/ruri", controller);
	// Create root node.
	errno = 0;
	if (mkdir(cgroup_root_node_path, S_IRUSR | S_IWUSR) && errno != EEXIST) {
		goto fail;
	};
	ruri_log("{base}Successfully mounted cgroup v1 %s\n", controller);
	return 0;
fail:
	ruri_log("{base}Failed to mount cgroup v1 %s\n", controller);
	return 1;
}
// Returns the same as open_and_write().
static int cgroup_v1_attach(const struct RURI_CONTAINER *_Nonnull container, const char *_Nonnull controller)
{
	pid_t pid = getpid();
	char buf[256] = "";
	char cgroup_path[PATH_MAX] = "";
	sprintf(cgroup_path, "/sys/fs/cgroup/%s/ruri/%d", controller, container->container_id);
	mkdir(cgroup_path, S_IRUSR | S_IWUSR);
	usleep(200);
	char cgroup_procs_path[PATH_MAX] = "";
	sprintf(cgroup_procs_path, "/sys/fs/cgroup/%s/ruri/%d/cgroup.procs", controller, container->container_id);
	// Add pid to container_id memory cgroup.
	sprintf(buf, "%d\n", pid);
	return open_and_write(cgroup_procs_path, buf);
}
static void set_cgroup_v1(const struct RURI_CONTAINER *_Nonnull container, const char *_Nonnull controller)
{
	/*
	 * Mount cgroupv1 _any_ controller and set limit.
	 * Nothing to return, only warnings to show if cgroup is not supported.
	 */
	mount_cgroup_v1(controller);
	char cgroup_node_path[PATH_MAX] = "";
	sprintf(cgroup_node_path, "/sys/fs/cgroup/%s/ruri/%d", controller, container->container_id);
	mkdir(cgroup_node_path, S_IRUSR | S_IWUSR);
	usleep(200);
	char *controller_name = "!!!internal error!!!";
	if (!strcmp(controller, "memory")) {
		if (!container->memory) {
			goto cleanup;
		}
		controller_name = "memory";
		// Set memory limit.
		char memory_cgroup_limit_path[PATH_MAX] = "";
		sprintf(memory_cgroup_limit_path, "/sys/fs/cgroup/memory/ruri/%d/memory.limit_in_bytes", container->container_id);
		ssize_t memory = humansize_to_bytes(container->memory);
		switch (memory) {
		case -1:
			if (!container->no_warnings) {
				ruri_error("Memory format error, only ^[1-9]+[kKmMgG]$ is supported\n");
			}
			goto cleanup;
		case -2:
			if (!container->no_warnings) {
				ruri_error("Memory value too big to current platform\n");
			}
			goto cleanup;
		}
		char buf[256] = "";
		sprintf(buf, "%zd\n", memory);
		if (open_and_write(memory_cgroup_limit_path, buf)) {
			goto fail;
		}
		char memory_cgroup_oom_path[PATH_MAX] = "";
		sprintf(memory_cgroup_oom_path, "/sys/fs/cgroup/memory/ruri/%d/memory.oom_control", container->container_id);
		if (open_and_write(memory_cgroup_oom_path, "1\n")) {
			goto fail;
		}
	} else if (!strcmp(controller, "cpu")) {
		if (!container->cpupercent) {
			goto cleanup;
		}
		controller_name = "cpupercent";
		// Set cpu limit.
		char cpu_cgroup_quota_path[PATH_MAX] = "";
		sprintf(cpu_cgroup_quota_path, "/sys/fs/cgroup/cpu/ruri/%d/cpu.cfs_quota_us", container->container_id);
		char buf[256] = "";
		sprintf(buf, "%d\n", container->cpupercent * 1000);
		if (open_and_write(cpu_cgroup_quota_path, buf)) {
			goto fail;
		}
		char cpu_cgroup_period_path[PATH_MAX] = "";
		sprintf(cpu_cgroup_period_path, "/sys/fs/cgroup/cpu/ruri/%d/cpu.cfs_period_us", container->container_id);
		sprintf(buf, "%d\n", 100000);
		if (open_and_write(cpu_cgroup_period_path, buf)) {
			goto fail;
		}

	} else if (!strcmp(controller, "cpuset")) {
		if (!container->cpuset) {
			goto cleanup;
		}
		controller_name = "cpuset";
		// Set cpuset limit.
		char cpuset_cgroup_mems_path[PATH_MAX] = "";
		sprintf(cpuset_cgroup_mems_path, "/sys/fs/cgroup/cpuset/ruri/%d/cpuset.mems", container->container_id);
		if (open_and_write(cpuset_cgroup_mems_path, "all\n")) {
			goto fail;
		}
		char cpuset_cgroup_cpus_path[PATH_MAX] = "";
		sprintf(cpuset_cgroup_cpus_path, "/sys/fs/cgroup/cpuset/ruri/%d/cpuset.cpus", container->container_id);
		char buf[256] = "";
		sprintf(buf, "%s\n", container->cpuset);
		if (open_and_write(cpuset_cgroup_cpus_path, buf)) {
			goto fail;
		}
	} else {
		controller_name = "!!!internal error!!!";
		goto fail;
	}
	if (cgroup_v1_attach(container, controller)) {
		goto fail;
	}
	goto cleanup;
fail:
	if (!container->no_warnings) {
		ruri_warning("{yellow}Set %s limit failed{clear}\n", controller_name);
	}
cleanup:
	umount2("/sys/fs/cgroup", MNT_DETACH | MNT_FORCE);
}
/*
 *                                          ____
 *   ___ __ _ _ __ ___  _   _ _ __   __   _|___ \
 *  / __/ _` | '__/ _ \| | | | '_ \  \ \ / / __) |
 * | (_| (_| | | | (_) | |_| | |_) |  \ V / / __/
 *  \___\__, |_|  \___/ \__,_| .__/    \_/ |_____|
 *      |___/                |_|
 */
// Returns 1 for failed mount
// Don't forget to usleep(200) after mount
static int mount_cgroup_v2(void)
{
	mkdir("/sys/fs/cgroup", S_IRUSR | S_IWUSR);
	// Mount /sys/fs/cgroup as cgroup2.
	if (mount("none", "/sys/fs/cgroup", "cgroup2", MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RELATIME, NULL)) {
		goto fail;
	}
	// Create root node
	errno = 0;
	if (mkdir("/sys/fs/cgroup/ruri", S_IRUSR | S_IWUSR) && errno != EEXIST) {
		goto fail;
	}
	ruri_log("{base}Successfully mounted cgroup v2\n");
	return 0;
fail:
	ruri_log("{base}Failed to mount cgroup v2\n");
	return 1;
}
// Returns 1 for failure.
static int cgroup_v2_attach(const struct RURI_CONTAINER *_Nonnull container)
{
	pid_t pid = getpid();
	char buf[256] = "";
	char cgroup_path[PATH_MAX] = "";
	sprintf(cgroup_path, "/sys/fs/cgroup/ruri/%d", container->container_id);
	mkdir(cgroup_path, S_IRUSR | S_IWUSR);
	usleep(200);
	// Add pid to container_id cgroup.
	char cgroup_procs_path[PATH_MAX] = "";
	sprintf(cgroup_procs_path, "/sys/fs/cgroup/ruri/%d/cgroup.procs", container->container_id);
	sprintf(buf, "%d\n", pid);
	if (open_and_write(cgroup_procs_path, buf)) {
		ruri_warning("{yellow}Attach cgroup failed{clear}\n");
		// Report failure for apifs cleanup
		return 1;
	}
	return 0;
}
static bool is_cgroupv2_support(const char *_Nonnull controller)
{
	/*
	 * Check if cgroup v2 supports _any_ controller.
	 * Return true if cgroup.controllers contains _controller_.
	 */
	// We love cgroup2, because it's easy to mount and control.
	if (mount_cgroup_v2()) {
		return false;
	}
	usleep(200);
	char buf[256] = "";
	sprintf(buf, "+%s\n", controller);
	if (open_and_write("/sys/fs/cgroup/ruri/cgroup.subtree_control", buf)) {
		goto fail;
	}
	umount2("/sys/fs/cgroup", MNT_DETACH | MNT_FORCE);
	ruri_log("{base}Cgroup v2 supports %s controller\n", controller);
	return true;
fail:
	umount2("/sys/fs/cgroup", MNT_DETACH | MNT_FORCE);
	ruri_log("{base}Cgroup v2 does not support %s controller\n", controller);
	return false;
}
static void set_cgroup_v2(const struct RURI_CONTAINER *_Nonnull container, const char *_Nonnull controller)
{
	/*
	 * Mount cgroupv2 _any_ controller and set limit.
	 * Nothing to return, only warnings to show if cgroup is not supported.
	 */
	// Mount /sys/fs/cgroup as cgroup2.
	if (mount_cgroup_v2()) {
		return;
	}
	char cgroup_node_path[PATH_MAX] = "";
	sprintf(cgroup_node_path, "/sys/fs/cgroup/ruri/%d", container->container_id);
	mkdir(cgroup_node_path, S_IRUSR | S_IWUSR);
	usleep(200);
	char *controller_name = "!!!internal error!!!";
	if (!strcmp(controller, "attach")) {
		; // no controller to set, only attach the container
	} else if (!strcmp(controller, "memory")) {
		if (!container->memory) {
			goto cleanup;
		}
		controller_name = "memory";
		// Set memory limit.
		char cgroup_memlimit_path[PATH_MAX] = "";
		sprintf(cgroup_memlimit_path, "/sys/fs/cgroup/ruri/%d/memory.high", container->container_id);
		char buf[256] = "";
		sprintf(buf, "%s\n", container->memory);
		if (open_and_write(cgroup_memlimit_path, buf)) {
			goto fail;
		}
		char cgroup_memlimit_path2[PATH_MAX] = "";
		sprintf(cgroup_memlimit_path2, "/sys/fs/cgroup/ruri/%d/memory.max", container->container_id);
		if (open_and_write(cgroup_memlimit_path2, buf)) {
			goto fail;
		}
		char cgroup_oom_path[PATH_MAX] = "";
		sprintf(cgroup_oom_path, "/sys/fs/cgroup/ruri/%d/memory.oom.group", container->container_id);
		sprintf(buf, "1\n");
		if (open_and_write(cgroup_oom_path, buf)) {
			goto fail;
		}
	} else if (!strcmp(controller, "cpu")) {
		if (!container->cpupercent) {
			goto cleanup;
		}
		controller_name = "cpupercent";
		// Set cpuset limit.
		char cgroup_cpu_path[PATH_MAX] = "";
		sprintf(cgroup_cpu_path, "/sys/fs/cgroup/ruri/%d/cpu.max", container->container_id);
		char buf[256] = "";
		sprintf(buf, "%d 100000\n", container->cpupercent * 1000);
		if (open_and_write(cgroup_cpu_path, buf)) {
			goto fail;
		}
	} else if (!strcmp(controller, "cpuset")) {
		if (!container->cpuset) {
			goto cleanup;
		}
		controller_name = "cpuset";
		// Set cpuset limit.
		char cgroup_mems_path[PATH_MAX] = "";
		sprintf(cgroup_mems_path, "/sys/fs/cgroup/ruri/%d/cpuset.mems", container->container_id);
		if (open_and_write(cgroup_mems_path, "all\n")) {
			goto fail;
		}
		char cgroup_cpuset_path[PATH_MAX] = "";
		sprintf(cgroup_cpuset_path, "/sys/fs/cgroup/ruri/%d/cpuset.cpus", container->container_id);
		char buf[256] = "";
		sprintf(buf, "%s\n", container->cpuset);
		if (open_and_write(cgroup_cpuset_path, buf)) {
			goto fail;
		}
	} else {
		controller_name = "!!!unknown controller!!!";
		goto fail;
	}
	// Add pid to container_id cgroup.
	if (cgroup_v2_attach(container)) {
		goto fail;
	}
	goto cleanup;
fail:
	if (!container->no_warnings) {
		ruri_warning("{yellow}Set %s limit failed{clear}\n", controller_name);
	}
cleanup:
	umount2("/sys/fs/cgroup", MNT_DETACH | MNT_FORCE);
}
/*
 *  ___       _             __
 * |_ _|_ __ | |_ ___ _ __ / _| __ _  ___ ___
 *  | || '_ \| __/ _ \ '__| |_ / _` |/ __/ _ \
 *  | || | | | ||  __/ |  |  _| (_| | (_|  __/
 * |___|_| |_|\__\___|_|  |_|  \__,_|\___\___|
 */
void ruri_attach_cgroup_v2(const struct RURI_CONTAINER *_Nonnull container)
{
	/*
	 * Mount cgroupv2 hierarchy and attach process.
	 * Nothing to return, only warnings to show if cgroup is not supported.
	 * Control file: /sys/fs/cgroup/ruri/${container_id}/cgroup.procs
	 */
	// Add pid to container_id cgroup.
	set_cgroup_v2(container, "attach");
}
void ruri_set_limit(const struct RURI_CONTAINER *_Nonnull container)
{
	/*
	 * Mount cgroup controller and set limit.
	 * Nothing to return, only warnings to show if cgroup is not supported.
	 */
	char *controllers[] = { "memory", "cpu", "cpuset" };
	for (int i = 0; i < sizeof controllers / sizeof(char *); ++i) {
		if (is_cgroupv2_support(controllers[i])) {
			set_cgroup_v2(container, controllers[i]);
		} else {
			set_cgroup_v1(container, controllers[i]);
		}
	}
}
// Returns 1 for failed try
int ruri_try_cgroup_kill(const struct RURI_CONTAINER *_Nonnull container)
{
	/*
	 * Kill all processes in corresponding cgroup v2 structure.
	 * FIXME I don't think this will be useful if we can't determine
	 *	that the container is attached beforehand.
	 */
	if (mount_cgroup_v2()) {
		goto fail;
	}
	usleep(200);
	char cgroup_kill_path[PATH_MAX] = "";
	sprintf(cgroup_kill_path, "/sys/fs/cgroup/ruri/%d/cgroup.kill", container->container_id);
	// Pid should be added beforehand.
	if (open_and_write(cgroup_kill_path, "1\n")) {
		umount2("/sys/fs/cgroup", MNT_DETACH | MNT_FORCE);
		goto fail;
	}
	umount2("/sys/fs/cgroup", MNT_DETACH | MNT_FORCE);
	return 0;
fail:
	if (!container->no_warnings) {
		ruri_log("{base}trying to kill container with cgroup v2 failed\n");
	}
	return 1;
}
void container_ps_with_cgroup_v2(const struct RURI_CONTAINER *_Nonnull container)
{
	; // TODO
}
