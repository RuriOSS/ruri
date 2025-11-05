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
#include <limits.h>
/*
 * This file provides functions to set cgoup limits for container.
 * ${container_id} is set by the time creating the container,
 * And it will be unified by .rurienv file.
 *
 * TODO:
 * Add more cgroups support.
 */
static void mount_cgroup_v1_memory(void)
{
	/*
	 * Mount Cgroup v1 memory controller.
	 * Nothing to return because if this function run failed,
	 * that means cgroup is fully not supported on the device.
	 */
	mkdir("/sys/fs/cgroup", S_IRUSR | S_IWUSR);
	// Maybe needless.
	umount2("/sys/fs/cgroup", MNT_DETACH | MNT_FORCE);
	// Mount /sys/fs/cgroup as tmpfs.
	mount("tmpfs", "/sys/fs/cgroup", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RELATIME, NULL);
	// Mount memory controller.
	mkdir("/sys/fs/cgroup/memory", S_IRUSR | S_IWUSR);
	usleep(2000);
	mount("none", "/sys/fs/cgroup/memory", "cgroup", MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RELATIME, "memory");
	ruri_log("{base}Tried to mount cgroup v1 memory\n");
}
static void mount_cgroup_v1_cpu(void)
{
	/*
	 * Mount Cgroup v1 cpu controller.
	 * Nothing to return because if this function run failed,
	 * that means cgroup is fully not supported on the device.
	 */
	mkdir("/sys/fs/cgroup", S_IRUSR | S_IWUSR);
	// Maybe needless.
	umount2("/sys/fs/cgroup", MNT_DETACH | MNT_FORCE);
	// Mount /sys/fs/cgroup as tmpfs.
	mount("tmpfs", "/sys/fs/cgroup", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RELATIME, NULL);
	// Mount cpu controller.
	mkdir("/sys/fs/cgroup/cpu", S_IRUSR | S_IWUSR);
	usleep(2000);
	mount("none", "/sys/fs/cgroup/cpu", "cgroup", MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RELATIME, "cpu");
	ruri_log("{base}Tried to mount cgroup v1 cpu\n");
}
static void mount_cgroup_v1_cpuset(void)
{
	/*
	 * Mount Cgroup v1 cpuset controller.
	 * Nothing to return because if this function run failed,
	 * that means cgroup is fully not supported on the device.
	 */
	mkdir("/sys/fs/cgroup", S_IRUSR | S_IWUSR);
	// Maybe needless.
	umount2("/sys/fs/cgroup", MNT_DETACH | MNT_FORCE);
	// Mount /sys/fs/cgroup as tmpfs.
	mount("tmpfs", "/sys/fs/cgroup", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RELATIME, NULL);
	// Mount cpuset controller.
	mkdir("/sys/fs/cgroup/cpuset", S_IRUSR | S_IWUSR);
	usleep(2000);
	mount("none", "/sys/fs/cgroup/cpuset", "cgroup", MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RELATIME, "cpuset");
	ruri_log("{base}Tried to mount cgroup v1 cpuset\n");
}
static bool is_cgroupv2_support(const char *_Nonnull type)
{
	/*
	 * Check if cgroup v2 supports type controller.
	 * Return true if cgroup.controllers contains type.
	 */
	mkdir("/sys/fs/cgroup", S_IRUSR | S_IWUSR);
	// Maybe needless.
	umount2("/sys/fs/cgroup", MNT_DETACH | MNT_FORCE);
	// I love cgroup2, because it's easy to mount and control.
	int stat = mount("none", "/sys/fs/cgroup", "cgroup2", MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RELATIME, NULL);
	if (stat != 0) {
		return false;
	}
	usleep(200);
	int subtree_control_fd = open("/sys/fs/cgroup/cgroup.subtree_control", O_RDWR | O_CLOEXEC);
	write(subtree_control_fd, "+memory\n", strlen("+memory\n"));
	write(subtree_control_fd, "+cpu\n", strlen("+cpu\n"));
	write(subtree_control_fd, "+cpuset\n", strlen("+cpuset\n"));
	close(subtree_control_fd);
	usleep(200);
	// Check if we have a controlable cgroup for `type`.
	mkdir("/sys/fs/cgroup/ruri", S_IRUSR | S_IWUSR);
	int fd = open("/sys/fs/cgroup/ruri/cgroup.controllers", O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		umount2("/sys/fs/cgroup", MNT_DETACH | MNT_FORCE);
		ruri_log("{base}Cgroup v2 does not support %s\n", type);
		ruri_log("{base}cgroup.controllers does not exist\n");
		return false;
	}
	char buf[256] = { '\0' };
	ssize_t len = read(fd, buf, 255);
	if (len <= 0) {
		close(fd);
		umount2("/sys/fs/cgroup", MNT_DETACH | MNT_FORCE);
		ruri_log("{base}Cgroup v2 does not support %s\n", type);
		ruri_log("{base}cgroup.controllers read failed\n");
		return false;
	}
	if (len <= 0) {
		umount2("/sys/fs/cgroup", MNT_DETACH | MNT_FORCE);
		ruri_log("{base}Cgroup v2 does not support %s\n", type);
		ruri_log("{base}cgroup.controllers read failed\n");
		return false;
	}
	buf[len] = '\0';
	char str_to_find[32] = { '\0' };
	ruri_log("{base}cgroup.controllers: %s\n", buf);
	snprintf(str_to_find, sizeof(str_to_find), "%s", type);
	ruri_log("{base}str_to_find: %s\n", str_to_find);
	// If str_to_find is in buf and str_to_find+1 is space (' ') or end ('\0').
	// We return true.
	if (strstr(buf, str_to_find) != NULL && (strstr(buf, str_to_find)[strlen(str_to_find)] == ' ' || strstr(buf, str_to_find)[strlen(str_to_find)] == '\0')) {
		umount2("/sys/fs/cgroup", MNT_DETACH | MNT_FORCE);
		ruri_log("{base}Cgroup v2 supports %s\n", type);
		return true;
	}
	umount2("/sys/fs/cgroup", MNT_DETACH | MNT_FORCE);
	ruri_log("{base}Cgroup v2 does not support %s\n", type);
	return false;
}
static char *memory_to_bytes(const char *_Nonnull memory)
{
	/*
	 * Convert memory string to bytes.
	 * Return a string of bytes.
	 */
	char *bytes = NULL;
	char *memory_dup = strdup(memory);
	char *ret = malloc(1024);
	if (strstr(memory_dup, "K") != NULL) {
		bytes = strtok(memory_dup, "K");
		long kilobytes = atol(bytes);
		if (kilobytes < 0 || kilobytes > INT_MAX / 1024) {
			free(memory_dup);
			free(ret);
			ruri_error("Memory value out of range\n");
		}
		snprintf(ret, 1024, "%ld", kilobytes * 1024);
	} else if (strstr(memory_dup, "M") != NULL) {
		bytes = strtok(memory_dup, "M");
		long megabytes = atol(bytes);
		if (megabytes < 0 || megabytes > INT_MAX / (1024 * 1024)) {
			free(memory_dup);
			free(ret);
			ruri_error("Memory value out of range\n");
		}
		snprintf(ret, 1024, "%ld", megabytes * 1024 * 1024);
	} else if (strstr(memory_dup, "G") != NULL) {
		bytes = strtok(memory_dup, "G");
		long gigabytes = atol(bytes);
		if (gigabytes < 0 || gigabytes > INT_MAX / (1024L * 1024 * 1024)) {
			free(memory_dup);
			free(ret);
			ruri_error("Memory value out of range\n");
		}
		snprintf(ret, 1024, "%ld", gigabytes * 1024L * 1024 * 1024);
	} else {
		free(memory_dup);
		free(ret);
		ruri_error("Memory format error, only K M G is supported\n");
	}
	free(memory_dup);
	return ret;
}
static void set_cgroup_v1_memory(const struct RURI_CONTAINER *_Nonnull container)
{
	/*
	 * Mount cgroupv1 memory controller and set limit.
	 * Nothing to return, only warnings to show if cgroup is not supported.
	 * Control file:
	 * /sys/fs/cgroup/memory/${container_id}/memory.limit_in_bytes
	 */
	mount_cgroup_v1_memory();
	pid_t pid = getpid();
	char buf[128] = { '\0' };
	char memory_cgroup_path[PATH_MAX] = { '\0' };
	snprintf(memory_cgroup_path, sizeof(memory_cgroup_path), "/sys/fs/cgroup/memory/%d", container->container_id);
	mkdir(memory_cgroup_path, S_IRUSR | S_IWUSR);
	usleep(200);
	int fd = -1;
	if (container->memory != NULL) {
		// Set memory limit.
		char memory_cgroup_limit_path[PATH_MAX] = { '\0' };
		snprintf(memory_cgroup_limit_path, sizeof(memory_cgroup_limit_path), "/sys/fs/cgroup/memory/%d/memory.limit_in_bytes", container->container_id);
		fd = open(memory_cgroup_limit_path, O_RDWR | O_CLOEXEC);
		if (fd < 0 && !container->no_warnings) {
			ruri_warning("{yellow}Set memory limit failed{clear}\n");
			umount2("/sys/fs/cgroup", MNT_DETACH | MNT_FORCE);
			return;
		}
		char *memory = memory_to_bytes(container->memory);
		snprintf(buf, sizeof(buf), "%s\n", memory);
		if (write(fd, buf, strlen(buf)) < 0 && !container->no_warnings) {
			ruri_warning("{yellow}Set memory limit failed{clear}\n");
		}
		free(memory);
		close(fd);
		char memory_oom[PATH_MAX] = { '\0' };
		snprintf(memory_oom, sizeof(memory_oom), "/sys/fs/cgroup/memory/%d/memory.oom_control", container->container_id);
		fd = open(memory_oom, O_RDWR | O_CLOEXEC);
		if (fd < 0 && !container->no_warnings) {
			ruri_warning("{yellow}Set memory limit failed{clear}\n");
			umount2("/sys/fs/cgroup", MNT_DETACH | MNT_FORCE);
			return;
		}
		snprintf(buf, sizeof(buf), "1\n");
		if (write(fd, buf, strlen(buf)) < 0 && !container->no_warnings) {
			ruri_warning("{yellow}Set memory limit failed{clear}\n");
		}
		close(fd);
	}
	char memory_cgroup_procs_path[PATH_MAX] = { '\0' };
	snprintf(memory_cgroup_procs_path, sizeof(memory_cgroup_procs_path), "/sys/fs/cgroup/memory/%d/cgroup.procs", container->container_id);
	// Add pid to container_id memory cgroup.
	fd = open(memory_cgroup_procs_path, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		umount2("/sys/fs/cgroup", MNT_DETACH | MNT_FORCE);
		return;
	}
	snprintf(buf, sizeof(buf), "%d\n", pid);
	write(fd, buf, strlen(buf));
	close(fd);
	umount2("/sys/fs/cgroup", MNT_DETACH | MNT_FORCE);
}
static void set_cgroup_v1_cpu(const struct RURI_CONTAINER *_Nonnull container)
{
	/*
	 * Mount cgroupv1 cpu controller and set limit.
	 * Nothing to return, only warnings to show if cgroup is not supported.
	 * Control file:
	 * /sys/fs/cgroup/cpu/${container_id}/cpu.cfs_quota_us
	 * /sys/fs/cgroup/cpu/${container_id}/cpu.cfs_period_us
	 */
	mount_cgroup_v1_cpu();
	char cpu_cgroup_path[PATH_MAX] = { '\0' };
	snprintf(cpu_cgroup_path, sizeof(cpu_cgroup_path), "/sys/fs/cgroup/cpu/%d", container->container_id);
	mkdir(cpu_cgroup_path, S_IRUSR | S_IWUSR);
	pid_t pid = getpid();
	char buf[128] = { '\0' };
	usleep(200);
	int fd = -1;
	if (container->cpupercent > 0) {
		// Set memory limit.
		char cpu_cgroup_quota_path[PATH_MAX] = { '\0' };
		snprintf(cpu_cgroup_quota_path, sizeof(cpu_cgroup_quota_path), "/sys/fs/cgroup/cpu/%d/cpu.cfs_quota_us", container->container_id);
		fd = open(cpu_cgroup_quota_path, O_RDWR | O_CLOEXEC);
		if (fd < 0 && !container->no_warnings) {
			ruri_warning("{yellow}Set memory limit failed{clear}\n");
			umount2("/sys/fs/cgroup", MNT_DETACH | MNT_FORCE);
			return;
		}
		snprintf(buf, sizeof(buf), "%d\n", container->cpupercent * 1000);
		if (write(fd, buf, strlen(buf)) < 0 && !container->no_warnings) {
			ruri_warning("{yellow}Set cpupercent limit failed{clear}\n");
		}
		close(fd);
		char cpu_cgroup_period_path[PATH_MAX] = { '\0' };
		snprintf(cpu_cgroup_period_path, sizeof(cpu_cgroup_period_path), "/sys/fs/cgroup/cpu/%d/cpu.cfs_period_us", container->container_id);
		fd = open(cpu_cgroup_period_path, O_RDWR | O_CLOEXEC);
		if (fd < 0 && !container->no_warnings) {
			ruri_warning("{yellow}Set cpupercent limit failed{clear}\n");
			umount2("/sys/fs/cgroup", MNT_DETACH | MNT_FORCE);
			return;
		}
		snprintf(buf, sizeof(buf), "%d\n", 100000);
		if (write(fd, buf, strlen(buf)) < 0 && !container->no_warnings) {
			ruri_warning("{yellow}Set cpupercent limit failed{clear}\n");
		}
		close(fd);
	}
	char cpu_cgroup_procs_path[PATH_MAX] = { '\0' };
	snprintf(cpu_cgroup_procs_path, sizeof(cpu_cgroup_procs_path), "/sys/fs/cgroup/cpu/%d/cgroup.procs", container->container_id);
	// Add pid to container_id cpupercent cgroup.
	fd = open(cpu_cgroup_procs_path, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		umount2("/sys/fs/cgroup", MNT_DETACH | MNT_FORCE);
		return;
	}
	snprintf(buf, sizeof(buf), "%d\n", pid);
	write(fd, buf, strlen(buf));
	close(fd);
	umount2("/sys/fs/cgroup", MNT_DETACH | MNT_FORCE);
}
static void set_cgroup_v1_cpuset(const struct RURI_CONTAINER *_Nonnull container)
{
	/*
	 * Mount cgroupv1 cpuset controller and set limit.
	 * Nothing to return, only warnings to show if cgroup is not supported.
	 * Control file: /sys/fs/cgroup/cpuset/${container_id}/cpuset.cpus
	 */
	mount_cgroup_v1_cpuset();
	char cpuset_cgroup_path[PATH_MAX] = { '\0' };
	snprintf(cpuset_cgroup_path, sizeof(cpuset_cgroup_path), "/sys/fs/cgroup/cpuset/%d", container->container_id);
	mkdir(cpuset_cgroup_path, S_IRUSR | S_IWUSR);
	pid_t pid = getpid();
	char buf[128] = { '\0' };
	int fd = -1;
	if (container->cpuset != NULL) {
		// Set cpuset limit.
		char cpuset_cgroup_mems_path[PATH_MAX] = { '\0' };
		snprintf(cpuset_cgroup_mems_path, sizeof(cpuset_cgroup_mems_path), "/sys/fs/cgroup/cpuset/%d/cpuset.mems", container->container_id);
		fd = open(cpuset_cgroup_mems_path, O_RDWR | O_CLOEXEC);
		if (fd < 0 && !container->no_warnings) {
			ruri_warning("{yellow}Set cpuset limit failed{clear}\n");
			// Do not keep the apifs mounted.
			umount2("/sys/fs/cgroup", MNT_DETACH | MNT_FORCE);
			return;
		}
		write(fd, "0\n", strlen("0\n"));
		close(fd);
		char cpuset_cgroup_cpus_path[PATH_MAX] = { '\0' };
		snprintf(cpuset_cgroup_cpus_path, sizeof(cpuset_cgroup_cpus_path), "/sys/fs/cgroup/cpuset/%d/cpuset.cpus", container->container_id);
		fd = open(cpuset_cgroup_cpus_path, O_RDWR | O_CLOEXEC);
		if (fd < 0 && !container->no_warnings) {
			ruri_warning("{yellow}Set cpuset limit failed{clear}\n");
			// Do not keep the apifs mounted.
			umount2("/sys/fs/cgroup", MNT_DETACH | MNT_FORCE);
			return;
		}
		snprintf(buf, sizeof(buf), "%s\n", container->cpuset);
		if (write(fd, buf, strlen(buf)) < 0 && !container->no_warnings) {
			ruri_warning("{yellow}Set cpu limit failed{clear}\n");
		}
		close(fd);
	}
	char cpuset_cgroup_procs_path[PATH_MAX] = { '\0' };
	snprintf(cpuset_cgroup_procs_path, sizeof(cpuset_cgroup_procs_path), "/sys/fs/cgroup/cpuset/%d/cgroup.procs", container->container_id);
	// Add pid to container_id cpuset cgroup.
	fd = open(cpuset_cgroup_procs_path, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		// Do not keep the apifs mounted.
		umount2("/sys/fs/cgroup", MNT_DETACH | MNT_FORCE);
		return;
	}
	snprintf(buf, sizeof(buf), "%d\n", pid);
	write(fd, buf, strlen(buf));
	close(fd);
	// Do not keep the apifs mounted.
	umount2("/sys/fs/cgroup", MNT_DETACH | MNT_FORCE);
}
static void set_cgroup_v2_memory(const struct RURI_CONTAINER *_Nonnull container)
{
	/*
	 * Mount cgroupv2 memory controller and set limit.
	 * Nothing to return, only warnings to show if cgroup is not supported.
	 * Control file: /sys/fs/cgroup/${container_id}/memory.max
	 */
	mkdir("/sys/fs/cgroup", S_IRUSR | S_IWUSR);
	// Maybe needless.
	umount2("/sys/fs/cgroup", MNT_DETACH | MNT_FORCE);
	// Mount /sys/fs/cgroup as cgroup2.
	mount("none", "/sys/fs/cgroup", "cgroup2", MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RELATIME, NULL);
	pid_t pid = getpid();
	char buf[128] = { '\0' };
	char cgroup_path[PATH_MAX] = { '\0' };
	snprintf(cgroup_path, sizeof(cgroup_path), "/sys/fs/cgroup/%d", container->container_id);
	mkdir(cgroup_path, S_IRUSR | S_IWUSR);
	usleep(200);
	char cgroup_procs_path[PATH_MAX] = { '\0' };
	snprintf(cgroup_procs_path, sizeof(cgroup_procs_path), "/sys/fs/cgroup/%d/cgroup.procs", container->container_id);
	// Add pid to container_id cgroup.
	int fd = open(cgroup_procs_path, O_RDWR | O_CLOEXEC);
	if (fd < 0 && !container->no_warnings) {
		ruri_warning("{yellow}Set cgroup.procs failed{clear}\n");
		// Do not keep the apifs mounted.
		umount2("/sys/fs/cgroup", MNT_DETACH | MNT_FORCE);
		return;
	}
	snprintf(buf, sizeof(buf), "%d\n", pid);
	write(fd, buf, strlen(buf));
	close(fd);
	if (container->memory != NULL) {
		// Set memory limit.
		char cgroup_memlimit_path[PATH_MAX] = { '\0' };
		snprintf(cgroup_memlimit_path, sizeof(cgroup_memlimit_path), "/sys/fs/cgroup/%d/memory.high", container->container_id);
		fd = open(cgroup_memlimit_path, O_RDWR | O_CLOEXEC);
		if (fd < 0 && !container->no_warnings) {
			ruri_warning("{yellow}Set memory limit failed{clear}\n");
			// Do not keep the apifs mounted.
			umount2("/sys/fs/cgroup", MNT_DETACH | MNT_FORCE);
			return;
		}
		snprintf(buf, sizeof(buf), "%s\n", container->memory);
		if (write(fd, buf, strlen(buf)) < 0 && !container->no_warnings) {
			ruri_warning("{yellow}Set memory limit failed{clear}\n");
		}
		close(fd);
		char cgroup_memlimit_path2[PATH_MAX] = { '\0' };
		snprintf(cgroup_memlimit_path2, sizeof(cgroup_memlimit_path2), "/sys/fs/cgroup/%d/memory.max", container->container_id);
		fd = open(cgroup_memlimit_path2, O_RDWR | O_CLOEXEC);
		if (fd < 0 && !container->no_warnings) {
			ruri_warning("{yellow}Set memory limit failed{clear}\n");
			// Do not keep the apifs mounted.
			umount2("/sys/fs/cgroup", MNT_DETACH | MNT_FORCE);
			return;
		}
		snprintf(buf, sizeof(buf), "%s\n", container->memory);
		if (write(fd, buf, strlen(buf)) < 0 && !container->no_warnings) {
			ruri_warning("{yellow}Set memory limit failed{clear}\n");
		}
		close(fd);
		char cgroup_oom[PATH_MAX] = { '\0' };
		snprintf(cgroup_oom, sizeof(cgroup_oom), "/sys/fs/cgroup/%d/memory.oom.group", container->container_id);
		fd = open(cgroup_oom, O_RDWR | O_CLOEXEC);
		if (fd < 0 && !container->no_warnings) {
			ruri_warning("{yellow}Set memory limit failed{clear}\n");
			// Do not keep the apifs mounted.
			umount2("/sys/fs/cgroup", MNT_DETACH | MNT_FORCE);
			return;
		}
		snprintf(buf, sizeof(buf), "1\n");
		if (write(fd, buf, strlen(buf)) < 0 && !container->no_warnings) {
			ruri_warning("{yellow}Set memory limit failed{clear}\n");
		}
		close(fd);
	}
	umount2("/sys/fs/cgroup", MNT_DETACH | MNT_FORCE);
}
static void set_cgroup_v2_cpuset(const struct RURI_CONTAINER *_Nonnull container)
{
	/*
	 * Mount cgroupv2 cpuset controller and set limit.
	 * Nothing to return, only warnings to show if cgroup is not supported.
	 * Control file: /sys/fs/cgroup/${container_id}/cpuset.cpus
	 */
	mkdir("/sys/fs/cgroup", S_IRUSR | S_IWUSR);
	// Maybe needless.
	umount2("/sys/fs/cgroup", MNT_DETACH | MNT_FORCE);
	// Mount /sys/fs/cgroup as cgroup2.
	mount("none", "/sys/fs/cgroup", "cgroup2", MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RELATIME, NULL);
	pid_t pid = getpid();
	char buf[128] = { '\0' };
	char cgroup_path[PATH_MAX] = { '\0' };
	snprintf(cgroup_path, sizeof(cgroup_path), "/sys/fs/cgroup/%d", container->container_id);
	mkdir(cgroup_path, S_IRUSR | S_IWUSR);
	usleep(200);
	char cgroup_procs_path[PATH_MAX] = { '\0' };
	snprintf(cgroup_procs_path, sizeof(cgroup_procs_path), "/sys/fs/cgroup/%d/cgroup.procs", container->container_id);
	// Add pid to container_id cgroup.
	int fd = open(cgroup_procs_path, O_RDWR | O_CLOEXEC);
	if (fd < 0 && !container->no_warnings) {
		ruri_warning("{yellow}Set cgroup.procs failed{clear}\n");
		// Do not keep the apifs mounted.
		umount2("/sys/fs/cgroup", MNT_DETACH | MNT_FORCE);
		return;
	}
	snprintf(buf, sizeof(buf), "%d\n", pid);
	if (write(fd, buf, strlen(buf)) < 0 && !container->no_warnings) {
		ruri_warning("{yellow}Set cgroup.procs failed{clear}\n");
	}
	close(fd);
	if (container->cpuset != NULL) {
		// Set cpuset limit.
		char cgroup_cpuset_path[PATH_MAX] = { '\0' };
		snprintf(cgroup_cpuset_path, sizeof(cgroup_cpuset_path), "/sys/fs/cgroup/%d/cpuset.cpus", container->container_id);
		fd = open(cgroup_cpuset_path, O_RDWR | O_CLOEXEC);
		if (fd < 0 && !container->no_warnings) {
			ruri_warning("{yellow}Set cpuset limit failed{clear}\n");
			// Do not keep the apifs mounted.
			umount2("/sys/fs/cgroup", MNT_DETACH | MNT_FORCE);
			return;
		}
		snprintf(buf, sizeof(buf), "%s\n", container->cpuset);
		if (write(fd, buf, strlen(buf)) < 0 && !container->no_warnings) {
			ruri_warning("{yellow}Set cpuset limit failed{clear}\n");
		}
		close(fd);
	}
	// Do not keep the apifs mounted.
	umount2("/sys/fs/cgroup", MNT_DETACH | MNT_FORCE);
}
static void set_cgroup_v2_cpu(const struct RURI_CONTAINER *_Nonnull container)
{
	/*
	 * Mount cgroupv2 cpu controller and set limit.
	 * Nothing to return, only warnings to show if cgroup is not supported.
	 * Control file: /sys/fs/cgroup/${container_id}/cpu.max
	 */
	mkdir("/sys/fs/cgroup", S_IRUSR | S_IWUSR);
	// Maybe needless.
	umount2("/sys/fs/cgroup", MNT_DETACH | MNT_FORCE);
	// Mount /sys/fs/cgroup as cgroup2.
	mount("none", "/sys/fs/cgroup", "cgroup2", MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RELATIME, NULL);
	pid_t pid = getpid();
	char buf[128] = { '\0' };
	char cgroup_path[PATH_MAX] = { '\0' };
	snprintf(cgroup_path, sizeof(cgroup_path), "/sys/fs/cgroup/%d", container->container_id);
	mkdir(cgroup_path, S_IRUSR | S_IWUSR);
	usleep(200);
	char cgroup_procs_path[PATH_MAX] = { '\0' };
	snprintf(cgroup_procs_path, sizeof(cgroup_procs_path), "/sys/fs/cgroup/%d/cgroup.procs", container->container_id);
	// Add pid to container_id cgroup.
	int fd = open(cgroup_procs_path, O_RDWR | O_CLOEXEC);
	if (fd < 0 && !container->no_warnings) {
		ruri_warning("{yellow}Set cgroup.procs failed{clear}\n");
		// Do not keep the apifs mounted.
		umount2("/sys/fs/cgroup", MNT_DETACH | MNT_FORCE);
		return;
	}
	snprintf(buf, sizeof(buf), "%d\n", pid);
	if (write(fd, buf, strlen(buf)) < 0 && !container->no_warnings) {
		ruri_warning("{yellow}Set cgroup.procs failed{clear}\n");
	}
	close(fd);
	if (container->cpupercent > 0) {
		// Set cpuset limit.
		char cgroup_cpu_path[PATH_MAX] = { '\0' };
		snprintf(cgroup_cpu_path, sizeof(cgroup_cpu_path), "/sys/fs/cgroup/%d/cpu.max", container->container_id);
		fd = open(cgroup_cpu_path, O_RDWR | O_CLOEXEC);
		if (fd < 0 && !container->no_warnings) {
			ruri_warning("{yellow}Set cpupercent limit failed{clear}\n");
			// Do not keep the apifs mounted.
			umount2("/sys/fs/cgroup", MNT_DETACH | MNT_FORCE);
			return;
		}
		snprintf(buf, sizeof(buf), "%d 100000\n", container->cpupercent * 1000);
		if (write(fd, buf, strlen(buf)) < 0 && !container->no_warnings) {
			ruri_warning("{yellow}Set cpupercent limit failed{clear}\n");
		}
		close(fd);
	}
	// Do not keep the apifs mounted.
	umount2("/sys/fs/cgroup", MNT_DETACH | MNT_FORCE);
}
void ruri_set_limit(const struct RURI_CONTAINER *_Nonnull container)
{
	/*
	 * Mount cgroup controller and set limit.
	 * Nothing to return, only warnings to show if cgroup is not supported.
	 */
	// Umount the mask of /sys/fs
	if (!container->unmask_dirs) {
		umount2("/sys/fs", MNT_DETACH | MNT_FORCE);
	}
	if (is_cgroupv2_support("memory")) {
		set_cgroup_v2_memory(container);
	} else {
		set_cgroup_v1_memory(container);
	}
	if (is_cgroupv2_support("cpu")) {
		set_cgroup_v2_cpu(container);
	} else {
		set_cgroup_v1_cpu(container);
	}
	if (is_cgroupv2_support("cpuset")) {
		set_cgroup_v2_cpuset(container);
	} else {
		set_cgroup_v1_cpuset(container);
	}
	// Mask /sys/fs again.
	if (!container->unmask_dirs) {
		mount("tmpfs", "/sys/fs", "tmpfs", MS_RDONLY, NULL);
	}
}
