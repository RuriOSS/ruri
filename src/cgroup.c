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
 * Maybe cgroup freezer and killer?
 */
// For cgroup detection on host side.
enum RURI_CGROUP_TYPE { RURI_CGROUP_V1, RURI_CGROUP_V2, RURI_CGROUP_ENOSYS };
struct RURI_CGROUP_NODE {
	// prefix is the path prefix for cgroup control files,
	// e.g. "/sys/fs/cgroup/memory/ruri/" for memory cgroup v1.
	char *prefix;
	// RURI_CGROUP_V1 for cgroup v1, RURI_CGROUP_V2 for cgroup v2,
	// RURI_CGROUP_ENOSYS for not supported.
	enum RURI_CGROUP_TYPE type;
};
struct RURI_CGROUP_ENV {
	// TODO: add more cgroup controllers if needed.
	struct RURI_CGROUP_NODE memory;
	struct RURI_CGROUP_NODE cpuset;
	struct RURI_CGROUP_NODE cpupercent;
	struct RURI_CGROUP_NODE pids;
	struct RURI_CGROUP_NODE io;
};
// Returns -1 for malformed size
// Returns -2 for too large
static ssize_t humansize_to_bytes(const char *_Nonnull human)
{
	char *endptr = NULL;
	errno = 0;
	long long ret = strtoll(human, &endptr, 10);

	if (errno == ERANGE) {
		return -2;
	}
	// no number or negative
	if (endptr == human || ret < 0) {
		return -1;
	}
	if (!*endptr) {
		if (ret > SSIZE_MAX) {
			return -2;
		}
	} else {
		// these become too long after formatted
		// clang-format off
		// NOLINTBEGIN
		if (*(endptr + 1)) return -1; // invalid unit
		switch (*endptr) {
		case 'k': case 'K': if (ret > SSIZE_MAX / 1024) return -2; ret *= 1024; break;
		case 'm': case 'M': if (ret > SSIZE_MAX / 1024 / 1024) return -2; ret *= 1024 * 1024; break;
		case 'g': case 'G': if (ret > SSIZE_MAX / 1024 / 1024 / 1024) return -2; ret *= 1024 * 1024 * 1024; break;
		default: return -1; // invalid unit
		}
		// NOLINTEND
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
	if (write(fd, value, strlen(value)) != strlen(value)) {
		close(fd);
		return 2;
	};
	close(fd);
	return 0;
}
static void detect_cgroup_unified(struct RURI_CGROUP_ENV *cg_env)
{
	// Detect cgroup v2 unified hierarchy, which is used by systemd and some modern distros.
	if (access("/sys/fs/cgroup/unified/memory.high", F_OK) == 0 && cg_env->memory.type == RURI_CGROUP_ENOSYS) {
		mkdir("/sys/fs/cgroup/unified/ruri", S_IRUSR | S_IWUSR);
		open_and_write("/sys/fs/cgroup/unified/cgroup.subtree_control", "+memory\n");
		open_and_write("/sys/fs/cgroup/unified/ruri/cgroup.subtree_control", "+memory\n");
		cg_env->memory.prefix = "/sys/fs/cgroup/unified/ruri/";
		cg_env->memory.type = RURI_CGROUP_V2;
	}
	if (access("/sys/fs/cgroup/unified/cpu.max", F_OK) == 0 && cg_env->cpupercent.type == RURI_CGROUP_ENOSYS) {
		mkdir("/sys/fs/cgroup/unified/ruri", S_IRUSR | S_IWUSR);
		open_and_write("/sys/fs/cgroup/unified/cgroup.subtree_control", "+cpu\n");
		open_and_write("/sys/fs/cgroup/unified/ruri/cgroup.subtree_control", "+cpu\n");
		cg_env->cpupercent.prefix = "/sys/fs/cgroup/unified/ruri/";
		cg_env->cpupercent.type = RURI_CGROUP_V2;
	}
	if (access("/sys/fs/cgroup/unified/cpuset.cpus", F_OK) == 0 && cg_env->cpuset.type == RURI_CGROUP_ENOSYS) {
		mkdir("/sys/fs/cgroup/unified/ruri", S_IRUSR | S_IWUSR);
		open_and_write("/sys/fs/cgroup/unified/cgroup.subtree_control", "+cpuset\n");
		open_and_write("/sys/fs/cgroup/unified/ruri/cgroup.subtree_control", "+cpuset\n");
		cg_env->cpuset.prefix = "/sys/fs/cgroup/unified/ruri/";
		cg_env->cpuset.type = RURI_CGROUP_V2;
	}
	if (access("/sys/fs/cgroup/unified/pids.max", F_OK) == 0 && cg_env->pids.type == RURI_CGROUP_ENOSYS) {
		mkdir("/sys/fs/cgroup/unified/ruri", S_IRUSR | S_IWUSR);
		open_and_write("/sys/fs/cgroup/unified/cgroup.subtree_control", "+pids\n");
		open_and_write("/sys/fs/cgroup/unified/ruri/cgroup.subtree_control", "+pids\n");
		cg_env->pids.prefix = "/sys/fs/cgroup/unified/ruri/";
		cg_env->pids.type = RURI_CGROUP_V2;
	}
	if (access("/sys/fs/cgroup/unified/io.max", F_OK) == 0 && cg_env->io.type == RURI_CGROUP_ENOSYS) {
		mkdir("/sys/fs/cgroup/unified/ruri", S_IRUSR | S_IWUSR);
		open_and_write("/sys/fs/cgroup/unified/cgroup.subtree_control", "+io\n");
		open_and_write("/sys/fs/cgroup/unified/ruri/cgroup.subtree_control", "+io\n");
		cg_env->io.prefix = "/sys/fs/cgroup/unified/ruri/";
		cg_env->io.type = RURI_CGROUP_V2;
	}
}
static void detect_cgroup_v1_fallback(struct RURI_CGROUP_ENV *cg_env)
{
	// Detect cgroup v1 fallback, which is used by some old distros and non-systemd distros.
	if (access("/sys/fs/cgroup/cpu/cpu.cfs_quota_us", F_OK) == 0 && cg_env->cpupercent.type == RURI_CGROUP_ENOSYS) {
		mkdir("/sys/fs/cgroup/cpu/ruri", S_IRUSR | S_IWUSR);
		cg_env->cpupercent.prefix = "/sys/fs/cgroup/cpu/ruri/";
		cg_env->cpupercent.type = RURI_CGROUP_V1;
	}
	if (access("/sys/fs/cgroup/memory/memory.limit_in_bytes", F_OK) == 0 && cg_env->memory.type == RURI_CGROUP_ENOSYS) {
		mkdir("/sys/fs/cgroup/memory/ruri", S_IRUSR | S_IWUSR);
		cg_env->memory.prefix = "/sys/fs/cgroup/memory/ruri/";
		cg_env->memory.type = RURI_CGROUP_V1;
	}
	if (access("/sys/fs/cgroup/cpuset/cpuset.cpus", F_OK) == 0 && cg_env->cpuset.type == RURI_CGROUP_ENOSYS) {
		mkdir("/sys/fs/cgroup/cpuset/ruri", S_IRUSR | S_IWUSR);
		cg_env->cpuset.prefix = "/sys/fs/cgroup/cpuset/ruri/";
		cg_env->cpuset.type = RURI_CGROUP_V1;
	}
	if (access("/sys/fs/cgroup/pids/pids.max", F_OK) == 0 && cg_env->pids.type == RURI_CGROUP_ENOSYS) {
		mkdir("/sys/fs/cgroup/pids/ruri", S_IRUSR | S_IWUSR);
		cg_env->pids.prefix = "/sys/fs/cgroup/pids/ruri/";
		cg_env->pids.type = RURI_CGROUP_V1;
	}
	if (access("/sys/fs/cgroup/blkio/blkio.throttle.read_bps_device", F_OK) == 0 && cg_env->io.type == RURI_CGROUP_ENOSYS) {
		mkdir("/sys/fs/cgroup/blkio/ruri", S_IRUSR | S_IWUSR);
		cg_env->io.prefix = "/sys/fs/cgroup/blkio/ruri/";
		cg_env->io.type = RURI_CGROUP_V1;
	}
	// For some Android devices, they mount cgroup v1 controllers in /dev.
	if (access("/dev/memcg/memory.limit_in_bytes", F_OK) == 0 && cg_env->memory.type == RURI_CGROUP_ENOSYS) {
		mkdir("/dev/memcg/ruri", S_IRUSR | S_IWUSR);
		cg_env->memory.prefix = "/dev/memcg/ruri/";
		cg_env->memory.type = RURI_CGROUP_V1;
	}
	if (access("/dev/cpuset/cpus", F_OK) == 0 && cg_env->cpuset.type == RURI_CGROUP_ENOSYS) {
		mkdir("/dev/cpuset/ruri", S_IRUSR | S_IWUSR);
		cg_env->cpuset.prefix = "/dev/cpuset/ruri/";
		cg_env->cpuset.type = RURI_CGROUP_V1;
	}
#ifdef __ANDROID__
	// For some Android devices, they mount cpu controller in /dev/cpuctl.
	if (access("/dev/cpuctl/cpu.cfs_quota_us", F_OK) == 0 && cg_env->cpupercent.type == RURI_CGROUP_ENOSYS) {
		mkdir("/dev/cpuctl/ruri", S_IRUSR | S_IWUSR);
		cg_env->cpupercent.prefix = "/dev/cpuctl/ruri/";
		cg_env->cpupercent.type = RURI_CGROUP_V1;
	}
#endif
}
static void detect_cgroup_v2(struct RURI_CGROUP_ENV *cg_env)
{
	// Detect cgroup v2, which is used by most modern distros.
	// If every system supports cgroup v2, the world will be like heaven.
	mkdir("/sys/fs/cgroup/ruri", S_IRUSR | S_IWUSR);
	open_and_write("/sys/fs/cgroup/cgroup.subtree_control", "+memory\n");
	open_and_write("/sys/fs/cgroup/cgroup.subtree_control", "+cpu\n");
	open_and_write("/sys/fs/cgroup/cgroup.subtree_control", "+cpuset\n");
	open_and_write("/sys/fs/cgroup/cgroup.subtree_control", "+pids\n");
	open_and_write("/sys/fs/cgroup/cgroup.subtree_control", "+io\n");
	if (!open_and_write("/sys/fs/cgroup/ruri/cgroup.subtree_control", "+memory\n")) {
		cg_env->memory.type = RURI_CGROUP_V2;
		cg_env->memory.prefix = "/sys/fs/cgroup/ruri/";
	}
	if (!open_and_write("/sys/fs/cgroup/ruri/cgroup.subtree_control", "+cpu\n")) {
		cg_env->cpupercent.type = RURI_CGROUP_V2;
		cg_env->cpupercent.prefix = "/sys/fs/cgroup/ruri/";
	}
	if (!open_and_write("/sys/fs/cgroup/ruri/cgroup.subtree_control", "+cpuset\n")) {
		cg_env->cpuset.type = RURI_CGROUP_V2;
		cg_env->cpuset.prefix = "/sys/fs/cgroup/ruri/";
	}
	if (!open_and_write("/sys/fs/cgroup/ruri/cgroup.subtree_control", "+pids\n")) {
		cg_env->pids.type = RURI_CGROUP_V2;
		cg_env->pids.prefix = "/sys/fs/cgroup/ruri/";
	}
	if (!open_and_write("/sys/fs/cgroup/ruri/cgroup.subtree_control", "+io\n")) {
		cg_env->io.type = RURI_CGROUP_V2;
		cg_env->io.prefix = "/sys/fs/cgroup/ruri/";
	}
}
static void ruri_detect_cgroup_env(struct RURI_CGROUP_ENV *cg_env)
{
	// Detect cgroup environment, including cgroup version and available controllers.
	// This function is called at host side.
	cg_env->memory.prefix = NULL;
	cg_env->memory.type = RURI_CGROUP_ENOSYS;
	cg_env->cpuset.prefix = NULL;
	cg_env->cpuset.type = RURI_CGROUP_ENOSYS;
	cg_env->cpupercent.prefix = NULL;
	cg_env->cpupercent.type = RURI_CGROUP_ENOSYS;
	cg_env->pids.prefix = NULL;
	cg_env->pids.type = RURI_CGROUP_ENOSYS;
	cg_env->io.prefix = NULL;
	cg_env->io.type = RURI_CGROUP_ENOSYS;
	detect_cgroup_v2(cg_env);
	detect_cgroup_unified(cg_env);
	detect_cgroup_v1_fallback(cg_env);
}
static void ruri_dump_cg_env(struct RURI_CGROUP_ENV *cg_env)
{
	// Only for debugging.
	// NOLINTBEGIN
	ruri_log("{blue}Cgroup environment:\n");
	if (cg_env->memory.type != RURI_CGROUP_ENOSYS) {
		ruri_log("{base}  Memory controller: %s (type: %s)\n", cg_env->memory.prefix, cg_env->memory.type == RURI_CGROUP_V2 ? "v2" : "v1");
	} else {
		ruri_log("{base}  Memory controller: not supported\n");
	}
	if (cg_env->cpupercent.type != RURI_CGROUP_ENOSYS) {
		ruri_log("{base}  CPU percent controller: %s (type: %s)\n", cg_env->cpupercent.prefix, cg_env->cpupercent.type == RURI_CGROUP_V2 ? "v2" : "v1");
	} else {
		ruri_log("{base}  CPU percent controller: not supported\n");
	}
	if (cg_env->cpuset.type != RURI_CGROUP_ENOSYS) {
		ruri_log("{base}  Cpuset controller: %s (type: %s)\n", cg_env->cpuset.prefix, cg_env->cpuset.type == RURI_CGROUP_V2 ? "v2" : "v1");
	} else {
		ruri_log("{base}  Cpuset controller: not supported\n");
	}
	if (cg_env->pids.type != RURI_CGROUP_ENOSYS) {
		ruri_log("{base}  PIDs controller: %s (type: %s)\n", cg_env->pids.prefix, cg_env->pids.type == RURI_CGROUP_V2 ? "v2" : "v1");
	} else {
		ruri_log("{base}  PIDs controller: not supported\n");
	}
	if (cg_env->io.type != RURI_CGROUP_ENOSYS) {
		ruri_log("{base}  I/O controller: %s (type: %s)\n", cg_env->io.prefix, cg_env->io.type == RURI_CGROUP_V2 ? "v2" : "v1");
	} else {
		ruri_log("{base}  I/O controller: not supported\n");
	}
	// NOLINTEND
}
static void ruri_set_memory_limit(const struct RURI_CONTAINER *_Nonnull container, const struct RURI_CGROUP_ENV *cg_env)
{
	// Set memory limit for the container.
	//
	// Join cgroup, this option will be enforced even if no memory limit is set.
	// Because for the same container, we will only setup cgroup once.
	if (cg_env->memory.type == RURI_CGROUP_V2) {
		char cgroup_memory_path[PATH_MAX] = "";
		sprintf(cgroup_memory_path, "%s%d/", cg_env->memory.prefix, container->container_id);
		mkdir(cgroup_memory_path, S_IRUSR | S_IWUSR);
		char cgroup_procs_path[PATH_MAX] = "";
		sprintf(cgroup_procs_path, "%scgroup.procs", cgroup_memory_path);
		char buf[256] = "";
		sprintf(buf, "%d", getpid());
		if (open_and_write(cgroup_procs_path, buf)) {
			ruri_warn_on_error(1, 0, !container->no_warnings, "{red}Failed to attach cgroup for cgroup v2 for %s\n", cgroup_procs_path);
			return;
		}
	} else if (cg_env->memory.type == RURI_CGROUP_V1) {
		char cgroup_memory_path[PATH_MAX] = "";
		sprintf(cgroup_memory_path, "%s%d/", cg_env->memory.prefix, container->container_id);
		mkdir(cgroup_memory_path, S_IRUSR | S_IWUSR);
		char cgroup_procs_path[PATH_MAX] = "";
		sprintf(cgroup_procs_path, "%scgroup.procs", cgroup_memory_path);
		char buf[256] = "";
		sprintf(buf, "%d", getpid());
		if (open_and_write(cgroup_procs_path, buf)) {
			ruri_warn_on_error(1, 0, !container->no_warnings, "{red}Failed to attach cgroup for cgroup v1 for %s\n", cgroup_procs_path);
			return;
		}
	} else {
		ruri_warn_on_error(1, 0, !container->no_warnings, "{red}No memory cgroup support detected\n");
		return;
	}
	// If memory limit is not set, just join the cgroup without setting memory limit.
	if (container->memory == NULL) {
		return;
	}
	// Set memory limit for our cgroup.
	if (cg_env->memory.type == RURI_CGROUP_V2) {
		char buf[256] = "";
		ssize_t memory = humansize_to_bytes(container->memory);
		// NOLINTBEGIN
		switch (memory) {
		case -1:
			ruri_error("Memory format error, only ^[1-9]+[kKmMgG]$ is supported\n");
		case -2:
			ruri_error("Memory value too big to current platform\n");
		}
		// NOLINTEND
		sprintf(buf, "%zd\n", memory);
		// set memory.max
		char cgroup_memory_max_path[PATH_MAX] = "";
		sprintf(cgroup_memory_max_path, "%s%d/memory.max", cg_env->memory.prefix, container->container_id);
		if (open_and_write(cgroup_memory_max_path, buf)) {
			ruri_warn_on_error(1, 0, !container->no_warnings, "{red}Failed to set cgroup v2 memory max limit for %s\n", cgroup_memory_max_path);
			return;
		}
		// set memory.oom.group
		char cgroup_memory_oom_group_path[PATH_MAX] = "";
		sprintf(cgroup_memory_oom_group_path, "%s%d/memory.oom.group", cg_env->memory.prefix, container->container_id);
		if (open_and_write(cgroup_memory_oom_group_path, "1\n")) {
			ruri_warn_on_error(1, 0, !container->no_warnings, "{red}Failed to set cgroup v2 memory oom group for %s\n", cgroup_memory_oom_group_path);
			return;
		}
	} else if (cg_env->memory.type == RURI_CGROUP_V1) {
		char memory_cgroup_limit_path[PATH_MAX] = "";
		sprintf(memory_cgroup_limit_path, "%s%d/memory.limit_in_bytes", cg_env->memory.prefix, container->container_id);
		ssize_t memory = humansize_to_bytes(container->memory);
		// NOLINTBEGIN
		switch (memory) {
		case -1:
			ruri_error("Memory format error, only ^[1-9]+[kKmMgG]$ is supported\n");
		case -2:
			ruri_error("Memory value too big to current platform\n");
		}
		// NOLINTEND
		char buf[256] = "";
		sprintf(buf, "%zd\n", memory);
		if (open_and_write(memory_cgroup_limit_path, buf)) {
			ruri_warn_on_error(1, 0, !container->no_warnings, "{red}Failed to set cgroup v1 memory limit\n");
			return;
		}
		char memory_cgroup_oom_path[PATH_MAX] = "";
		sprintf(memory_cgroup_oom_path, "%s%d/memory.oom_control", cg_env->memory.prefix, container->container_id);
		if (open_and_write(memory_cgroup_oom_path, "0\n")) {
			ruri_warn_on_error(1, 0, !container->no_warnings, "{red}Failed to set cgroup v1 memory limit for %s\n", memory_cgroup_oom_path);
			return;
		}
	} else {
		ruri_warn_on_error(1, 0, !container->no_warnings, "{red}No memory cgroup support detected\n");
	}
}
static void ruri_set_cpuset(const struct RURI_CONTAINER *_Nonnull container, const struct RURI_CGROUP_ENV *cg_env)
{
	// Set cpuset for the container.
	//
	// Join cgroup, this option will be enforced even if no cpuset limit is set.
	// Because for the same container, we will only setup cgroup once.
	if (cg_env->cpuset.type == RURI_CGROUP_V2) {
		char cgroup_cpuset_path[PATH_MAX] = "";
		sprintf(cgroup_cpuset_path, "%s%d/", cg_env->cpuset.prefix, container->container_id);
		mkdir(cgroup_cpuset_path, S_IRUSR | S_IWUSR);
		char cgroup_subtree_control_path[PATH_MAX] = "";
		char cgroup_procs_path[PATH_MAX] = "";
		sprintf(cgroup_procs_path, "%scgroup.procs", cgroup_cpuset_path);
		char buf[256] = "";
		sprintf(buf, "%d", getpid());
		if (open_and_write(cgroup_procs_path, buf)) {
			ruri_warn_on_error(1, 0, !container->no_warnings, "{red}Failed to attach cgroup for cgroup v2 for %s\n", cgroup_procs_path);
			return;
		}
	} else if (cg_env->cpuset.type == RURI_CGROUP_V1) {
		char cgroup_cpuset_path[PATH_MAX] = "";
		sprintf(cgroup_cpuset_path, "%s%d/", cg_env->cpuset.prefix, container->container_id);
		mkdir(cgroup_cpuset_path, S_IRUSR | S_IWUSR);
		char cgroup_procs_path[PATH_MAX] = "";
		sprintf(cgroup_procs_path, "%scgroup.procs", cgroup_cpuset_path);
		char buf[256] = "";
		sprintf(buf, "%d\n", getpid());
		if (open_and_write(cgroup_procs_path, buf)) {
			ruri_warn_on_error(1, 0, !container->no_warnings, "{red}Failed to attach cgroup for cgroup v1 for %s\n", cgroup_procs_path);
			return;
		}
	} else {
		ruri_warn_on_error(1, 0, !container->no_warnings, "{red}No cpuset cgroup support detected\n");
		return;
	}
	// If cpuset is not set, just join the cgroup without setting cpuset.cpus.
	if (container->cpuset == NULL) {
		return;
	}
	// Set cpuset for our cgroup.
	if (cg_env->cpuset.type == RURI_CGROUP_V2) {
		char cgroup_cpuset_cpus_path[PATH_MAX] = "";
		sprintf(cgroup_cpuset_cpus_path, "%s%d/cpuset.cpus", cg_env->cpuset.prefix, container->container_id);
		char buf[256] = "";
		sprintf(buf, "%s\n", container->cpuset);
		if (open_and_write(cgroup_cpuset_cpus_path, buf)) {
			ruri_warn_on_error(1, 0, !container->no_warnings, "{red}Failed to set cgroup v2 cpuset limit for %s\n", cgroup_cpuset_cpus_path);
			return;
		}
	} else if (cg_env->cpuset.type == RURI_CGROUP_V1) {
		// Set cpuset.mems to 0, otherwise cpuset.cpus will not work.
		char cgroup_cpuset_mems_path[PATH_MAX] = "";
		sprintf(cgroup_cpuset_mems_path, "%s%d/cpuset.mems", cg_env->cpuset.prefix, container->container_id);
		if (open_and_write(cgroup_cpuset_mems_path, "0\n")) {
			ruri_warn_on_error(1, 0, !container->no_warnings, "{red}Failed to set cgroup v1 cpuset mems for %s\n", cgroup_cpuset_mems_path);
			return;
		}
		// Set cpuset.cpus to the value specified by user.
		char cgroup_cpuset_cpus_path[PATH_MAX] = "";
		sprintf(cgroup_cpuset_cpus_path, "%s%d/cpuset.cpus", cg_env->cpuset.prefix, container->container_id);
		char buf[256] = "";
		sprintf(buf, "%s\n", container->cpuset);
		if (open_and_write(cgroup_cpuset_cpus_path, buf)) {
			ruri_warn_on_error(1, 0, !container->no_warnings, "{red}Failed to set cgroup v1 cpuset limit for %s\n", cgroup_cpuset_cpus_path);
			return;
		}
	} else {
		ruri_warn_on_error(1, 0, !container->no_warnings, "{red}No cpuset cgroup support detected\n");
		return;
	}
}
static void ruri_set_cpupercent(const struct RURI_CONTAINER *_Nonnull container, const struct RURI_CGROUP_ENV *cg_env)
{
	// Set cpu percent limit for the container.
	//
	// Join cgroup, this option will be enforced even if no cpu percent limit is set.
	// Because for the same container, we will only setup cgroup once.
	if (cg_env->cpupercent.type == RURI_CGROUP_V2) {
		char cgroup_cpu_path[PATH_MAX] = "";
		sprintf(cgroup_cpu_path, "%s%d/", cg_env->cpupercent.prefix, container->container_id);
		mkdir(cgroup_cpu_path, S_IRUSR | S_IWUSR);
		char cgroup_procs_path[PATH_MAX] = "";
		sprintf(cgroup_procs_path, "%scgroup.procs", cgroup_cpu_path);
		char buf[256] = "";
		sprintf(buf, "%d", getpid());
		if (open_and_write(cgroup_procs_path, buf)) {
			ruri_warn_on_error(1, 0, !container->no_warnings, "{red}Failed to attach cgroup for cgroup v2 for %s\n", cgroup_procs_path);
			return;
		}
	} else if (cg_env->cpupercent.type == RURI_CGROUP_V1) {
		char cgroup_cpu_path[PATH_MAX] = "";
		sprintf(cgroup_cpu_path, "%s%d/", cg_env->cpupercent.prefix, container->container_id);
		mkdir(cgroup_cpu_path, S_IRUSR | S_IWUSR);
		char cgroup_procs_path[PATH_MAX] = "";
		sprintf(cgroup_procs_path, "%scgroup.procs", cgroup_cpu_path);
		char buf[256] = "";
		sprintf(buf, "%d\n", getpid());
		if (open_and_write(cgroup_procs_path, buf)) {
			ruri_warn_on_error(1, 0, !container->no_warnings, "{red}Failed to attach cgroup for cgroup v1\n");
			return;
		}
	} else {
		ruri_warn_on_error(1, 0, !container->no_warnings, "{red}No cpu cgroup support detected\n");
		return;
	}
	// If cpu percent limit is not set, just join the cgroup without setting cpu percent limit.
	if (container->cpupercent <= 0) {
		return;
	}
	// Set cpu percent limit for our cgroup.
	if (cg_env->cpupercent.type == RURI_CGROUP_V2) {
		char cgroup_cpu_path[PATH_MAX] = "";
		sprintf(cgroup_cpu_path, "%s%d/cpu.max", cg_env->cpupercent.prefix, container->container_id);
		char buf[256] = "";
		sprintf(buf, "%d 100000\n", container->cpupercent * 1000);
		if (open_and_write(cgroup_cpu_path, buf)) {
			ruri_warn_on_error(1, 0, !container->no_warnings, "{red}Failed to set cgroup v2 cpu percent limit\n");
			return;
		}
	} else if (cg_env->cpupercent.type == RURI_CGROUP_V1) {
		char cgroup_cpu_quota_path[PATH_MAX] = "";
		sprintf(cgroup_cpu_quota_path, "%s%d/cpu.cfs_quota_us", cg_env->cpupercent.prefix, container->container_id);
		char buf[256] = "";
		sprintf(buf, "%d\n", container->cpupercent * 1000);
		if (open_and_write(cgroup_cpu_quota_path, buf)) {
			ruri_warn_on_error(1, 0, !container->no_warnings, "{red}Failed to set cgroup v1 cpu percent limit\n");
			return;
		}
		char cgroup_cpu_period_path[PATH_MAX] = "";
		sprintf(cgroup_cpu_period_path, "%s%d/cpu.cfs_period_us", cg_env->cpupercent.prefix, container->container_id);
		sprintf(buf, "%d\n", 100000);
		if (open_and_write(cgroup_cpu_period_path, buf)) {
			ruri_warn_on_error(1, 0, !container->no_warnings, "{red}Failed to set cgroup v1 cpu percent limit\n");
			return;
		}
	} else {
		ruri_warn_on_error(1, 0, !container->no_warnings, "{red}No cpu cgroup support detected\n");
		return;
	}
}
static void ruri_set_pids(const struct RURI_CONTAINER *_Nonnull container, const struct RURI_CGROUP_ENV *cg_env)
{
	// Set PIDs limit for the container.
	//
	// Join cgroup, this option will be enforced even if no PIDs limit is set.
	// Because for the same container, we will only setup cgroup once.
	if (cg_env->pids.type == RURI_CGROUP_V2) {
		char cgroup_pids_path[PATH_MAX] = "";
		sprintf(cgroup_pids_path, "%s%d/", cg_env->pids.prefix, container->container_id);
		mkdir(cgroup_pids_path, S_IRUSR | S_IWUSR);
		char cgroup_procs_path[PATH_MAX] = "";
		sprintf(cgroup_procs_path, "%scgroup.procs", cgroup_pids_path);
		char buf[256] = "";
		sprintf(buf, "%d", getpid());
		if (open_and_write(cgroup_procs_path, buf)) {
			ruri_warn_on_error(1, 0, !container->no_warnings, "{red}Failed to attach cgroup for cgroup v2 for %s\n", cgroup_procs_path);
			return;
		}
	} else if (cg_env->pids.type == RURI_CGROUP_V1) {
		char cgroup_pids_path[PATH_MAX] = "";
		sprintf(cgroup_pids_path, "%s%d/", cg_env->pids.prefix, container->container_id);
		mkdir(cgroup_pids_path, S_IRUSR | S_IWUSR);
		char cgroup_procs_path[PATH_MAX] = "";
		sprintf(cgroup_procs_path, "%scgroup.procs", cgroup_pids_path);
		char buf[256] = "";
		sprintf(buf, "%d\n", getpid());
		if (open_and_write(cgroup_procs_path, buf)) {
			ruri_warn_on_error(1, 0, !container->no_warnings, "{red}Failed to attach cgroup for cgroup v1 for %s\n", cgroup_procs_path);
			return;
		}
	} else {
		ruri_warn_on_error(1, 0, !container->no_warnings, "{red}No PIDs cgroup support detected\n");
		return;
	}
	// If PIDs limit is not set, just join the cgroup without setting PIDs limit.
	if (container->max_pids <= 0) {
		return;
	}
	// Set PIDs limit for our cgroup.
	if (cg_env->pids.type == RURI_CGROUP_V2 || cg_env->pids.type == RURI_CGROUP_V1) {
		char cgroup_pids_max_path[PATH_MAX] = "";
		sprintf(cgroup_pids_max_path, "%s%d/pids.max", cg_env->pids.prefix, container->container_id);
		char buf[256] = "";
		sprintf(buf, "%d\n", container->max_pids);
		if (open_and_write(cgroup_pids_max_path, buf)) {
			ruri_warn_on_error(1, 0, !container->no_warnings, "{red}Failed to set PIDs limit for %s\n", cgroup_pids_max_path);
			return;
		}
	} else {
		ruri_warn_on_error(1, 0, !container->no_warnings, "{red}No PIDs cgroup support detected\n");
		return;
	}
}
static void ruri_set_io(const struct RURI_CONTAINER *_Nonnull container, const struct RURI_CGROUP_ENV *cg_env)
{
	// Set I/O bandwidth limit for the container.
	//
	// Join cgroup, this option will be enforced even if no I/O limit is set.
	// Because for the same container, we will only setup cgroup once.
	if (cg_env->io.type == RURI_CGROUP_V2) {
		char cgroup_io_path[PATH_MAX] = "";
		sprintf(cgroup_io_path, "%s%d/", cg_env->io.prefix, container->container_id);
		mkdir(cgroup_io_path, S_IRUSR | S_IWUSR);
		char cgroup_procs_path[PATH_MAX] = "";
		sprintf(cgroup_procs_path, "%scgroup.procs", cgroup_io_path);
		char buf[256] = "";
		sprintf(buf, "%d", getpid());
		if (open_and_write(cgroup_procs_path, buf)) {
			ruri_warn_on_error(1, 0, !container->no_warnings, "{red}Failed to attach cgroup for cgroup v2 for %s\n", cgroup_procs_path);
			return;
		}
	} else if (cg_env->io.type == RURI_CGROUP_V1) {
		char cgroup_io_path[PATH_MAX] = "";
		sprintf(cgroup_io_path, "%s%d/", cg_env->io.prefix, container->container_id);
		mkdir(cgroup_io_path, S_IRUSR | S_IWUSR);
		char cgroup_procs_path[PATH_MAX] = "";
		sprintf(cgroup_procs_path, "%scgroup.procs", cgroup_io_path);
		char buf[256] = "";
		sprintf(buf, "%d\n", getpid());
		if (open_and_write(cgroup_procs_path, buf)) {
			ruri_warn_on_error(1, 0, !container->no_warnings, "{red}Failed to attach cgroup for cgroup v1 for %s\n", cgroup_procs_path);
			return;
		}
	} else {
		ruri_warn_on_error(1, 0, !container->no_warnings, "{red}No I/O cgroup support detected\n");
		return;
	}
	// If I/O limit is not set, just join the cgroup without setting I/O limit.
	if ((container->io_rbps == NULL && container->io_wbps == NULL) || container->io_device == NULL) {
		return;
	}
	// Set I/O limit for our cgroup.
	if (cg_env->io.type == RURI_CGROUP_V2) {
		char cgroup_io_max_path[PATH_MAX] = "";
		sprintf(cgroup_io_max_path, "%s%d/io.max", cg_env->io.prefix, container->container_id);
		char buf[1024] = "";
		// Format: "major:minor rbps=xxx wbps=xxx"
		sprintf(buf, "%s", container->io_device);
		if (container->io_rbps != NULL) {
			ssize_t rbps = humansize_to_bytes(container->io_rbps);
			// NOLINTBEGIN
			switch (rbps) {
			case -1:
				ruri_error("I/O rbps format error, only ^[1-9]+[kKmMgG]$ is supported\n");
			case -2:
				ruri_error("I/O rbps value too big to current platform\n");
			}
			// NOLINTEND
			sprintf(buf + strlen(buf), " rbps=%zd", rbps);
		}
		if (container->io_wbps != NULL) {
			ssize_t wbps = humansize_to_bytes(container->io_wbps);
			// NOLINTBEGIN
			switch (wbps) {
			case -1:
				ruri_error("I/O wbps format error, only ^[1-9]+[kKmMgG]$ is supported\n");
			case -2:
				ruri_error("I/O wbps value too big to current platform\n");
			}
			// NOLINTEND
			sprintf(buf + strlen(buf), " wbps=%zd", wbps);
		}
		sprintf(buf + strlen(buf), "\n");
		if (open_and_write(cgroup_io_max_path, buf)) {
			ruri_warn_on_error(1, 0, !container->no_warnings, "{red}Failed to set cgroup v2 I/O limit for %s\n", cgroup_io_max_path);
			return;
		}
	} else if (cg_env->io.type == RURI_CGROUP_V1) {
		if (container->io_rbps != NULL) {
			char cgroup_blkio_read_path[PATH_MAX] = "";
			sprintf(cgroup_blkio_read_path, "%s%d/blkio.throttle.read_bps_device", cg_env->io.prefix, container->container_id);
			ssize_t rbps = humansize_to_bytes(container->io_rbps);
			// NOLINTBEGIN
			switch (rbps) {
			case -1:
				ruri_error("I/O rbps format error, only ^[1-9]+[kKmMgG]$ is supported\n");
			case -2:
				ruri_error("I/O rbps value too big to current platform\n");
			}
			// NOLINTEND
			char buf[1024] = "";
			sprintf(buf, "%s %zd\n", container->io_device, rbps);
			if (open_and_write(cgroup_blkio_read_path, buf)) {
				ruri_warn_on_error(1, 0, !container->no_warnings, "{red}Failed to set cgroup v1 I/O read limit for %s\n", cgroup_blkio_read_path);
				return;
			}
		}
		if (container->io_wbps != NULL) {
			char cgroup_blkio_write_path[PATH_MAX] = "";
			sprintf(cgroup_blkio_write_path, "%s%d/blkio.throttle.write_bps_device", cg_env->io.prefix, container->container_id);
			ssize_t wbps = humansize_to_bytes(container->io_wbps);
			// NOLINTBEGIN
			switch (wbps) {
			case -1:
				ruri_error("I/O wbps format error, only ^[1-9]+[kKmMgG]$ is supported\n");
			case -2:
				ruri_error("I/O wbps value too big to current platform\n");
			}
			// NOLINTEND
			char buf[1024] = "";
			sprintf(buf, "%s %zd\n", container->io_device, wbps);
			if (open_and_write(cgroup_blkio_write_path, buf)) {
				ruri_warn_on_error(1, 0, !container->no_warnings, "{red}Failed to set cgroup v1 I/O write limit for %s\n", cgroup_blkio_write_path);
				return;
			}
		}
	} else {
		ruri_warn_on_error(1, 0, !container->no_warnings, "{red}No I/O cgroup support detected\n");
		return;
	}
}
void ruri_set_limit(const struct RURI_CONTAINER *_Nonnull container)
{
	/*
	 * Set cgroup controller limit.
	 * Nothing to return, only warnings to show if cgroup is not supported.
	 */
	struct RURI_CGROUP_ENV cg_env;
	ruri_detect_cgroup_env(&cg_env);
	ruri_dump_cg_env(&cg_env);
	ruri_set_memory_limit(container, &cg_env);
	ruri_set_cpuset(container, &cg_env);
	ruri_set_cpupercent(container, &cg_env);
	ruri_set_pids(container, &cg_env);
	ruri_set_io(container, &cg_env);
}
static bool is_cgroup_v2_mounted()
{
	/*
	 * Use statfs() to check if cgroup v2 is mounted.
	 * Return true if cgroup v2 is mounted.
	 */
	struct statfs buf;
	if (statfs("/sys/fs/cgroup", &buf) < 0) {
		return false;
	}
	return buf.f_type == CGROUP2_SUPER_MAGIC;
}
// Returns 1 for failed try
int ruri_try_cgroup_kill(const struct RURI_CONTAINER *_Nonnull container)
{
	/*
	 * Kill all processes in corresponding cgroup v2 structure.
	 */
	if (!is_cgroup_v2_mounted()) {
		return 1;
	}
	char cgroup_kill_path[PATH_MAX] = "";
	sprintf(cgroup_kill_path, "/sys/fs/cgroup/ruri/%d/cgroup.kill", container->container_id);
	// Pid should be added beforehand.
	if (open_and_write(cgroup_kill_path, "1\n")) {
		goto fail;
	}
	char cgroup_systemd_path[PATH_MAX] = "";
	sprintf(cgroup_systemd_path, "/sys/fs/cgroup/ruri/%d/ruri-%d", container->container_id, container->container_id);
	rmdir(cgroup_systemd_path);
	char cgroup_path[PATH_MAX] = "";
	sprintf(cgroup_path, "/sys/fs/cgroup/ruri/%d", container->container_id);
	rmdir(cgroup_path);
	return 0;
fail:
	if (!container->no_warnings) {
		ruri_warning("{yellow}trying to kill container with cgroup v2 failed\n");
	}
	return 1;
}
bool ruri_pid_in_cgroup(pid_t pid, int container_id)
{
	/*
	 * Check if the process is in the container by cgroup.
	 * Return true if the process is in the container.
	 */
	struct RURI_CGROUP_ENV cg_env;
	ruri_detect_cgroup_env(&cg_env);
	char cgroup_procs_path[PATH_MAX] = "";
	// NOLINTBEGIN
	// Any one of the cgroup controllers can be used.
	if (cg_env.memory.type == RURI_CGROUP_V2) {
		sprintf(cgroup_procs_path, "%s%d/cgroup.procs", cg_env.memory.prefix, container_id);
	} else if (cg_env.memory.type == RURI_CGROUP_V1) {
		sprintf(cgroup_procs_path, "%s%d/cgroup.procs", cg_env.memory.prefix, container_id);
	} else if (cg_env.cpuset.type == RURI_CGROUP_V2) {
		sprintf(cgroup_procs_path, "%s%d/cgroup.procs", cg_env.cpuset.prefix, container_id);
	} else if (cg_env.cpuset.type == RURI_CGROUP_V1) {
		sprintf(cgroup_procs_path, "%s%d/cgroup.procs", cg_env.cpuset.prefix, container_id);
	} else if (cg_env.cpupercent.type == RURI_CGROUP_V2) {
		sprintf(cgroup_procs_path, "%s%d/cgroup.procs", cg_env.cpupercent.prefix, container_id);
	} else if (cg_env.cpupercent.type == RURI_CGROUP_V1) {
		sprintf(cgroup_procs_path, "%s%d/cgroup.procs", cg_env.cpupercent.prefix, container_id);
	} else if (cg_env.pids.type == RURI_CGROUP_V2) {
		sprintf(cgroup_procs_path, "%s%d/cgroup.procs", cg_env.pids.prefix, container_id);
	} else if (cg_env.pids.type == RURI_CGROUP_V1) {
		sprintf(cgroup_procs_path, "%s%d/cgroup.procs", cg_env.pids.prefix, container_id);
	} else if (cg_env.io.type == RURI_CGROUP_V2) {
		sprintf(cgroup_procs_path, "%s%d/cgroup.procs", cg_env.io.prefix, container_id);
	} else if (cg_env.io.type == RURI_CGROUP_V1) {
		sprintf(cgroup_procs_path, "%s%d/cgroup.procs", cg_env.io.prefix, container_id);
	} else {
		return false;
	}
	// NOLINTEND
	FILE *f = fopen(cgroup_procs_path, "re");
	if (f == NULL) {
		return false;
	}
	char line[256];
	while (fgets(line, sizeof(line), f)) {
		if (atoi(line) == pid) {
			fclose(f);
			return true;
		}
	}
	fclose(f);
	return false;
}
