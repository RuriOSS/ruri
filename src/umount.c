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
 * This file provides function to umount the container.
 * All pids detected in the container will be killed at the same time.
 *
 */
static void umount_subdir(const char *_Nonnull dir)
{
	/*
	 * Umount subdir, use info in /proc/mounts
	 * This is another implementation of umount_container,
	 * we use it as a double-check.
	 */
	FILE *fp = setmntent("/proc/mounts", "r");
	if (fp == NULL) {
		return;
	}
	char dir_new[PATH_MAX];
	if (dir[strlen(dir)] == '/') {
		snprintf(dir_new, sizeof(dir_new), "%s", dir);
		dir_new[strlen(dir_new)] = '\0';
		dir = dir_new;
	}
	// A simple way to check if container is umounted.
	struct mntent *entry = NULL;
	while ((entry = getmntent(fp)) != NULL) {
		if (strncmp(entry->mnt_dir, dir, strlen(dir)) == 0) {
			// Check if end for `/` or `\0`.
			if (entry->mnt_dir[strlen(dir)] == '/' || entry->mnt_dir[strlen(dir)] == '\0') {
				ruri_log("{base}Found subdirectory %s\n", entry->mnt_dir);
				// Check for fuse(.*), we will not MNT_FORCE for it.
				if (strncmp(entry->mnt_type, "fuse", 4) == 0) {
					umount2(entry->mnt_dir, MNT_DETACH);
				} else {
					umount2(entry->mnt_dir, MNT_DETACH | MNT_FORCE);
				}
			}
		}
	}
	endmntent(fp);
}
// Umount container.
void ruri_umount_container(const char *_Nonnull container_dir)
{
	/*
	 * Read /.rurienv file and umount all mountpoints,
	 * including extra_mountpoint and extra_ro_mountpoint,
	 * and umount system runtime directories.
	 */
	ruri_proc_mark(RURI_UMOUNT);
	if (container_dir == NULL) {
		ruri_error("{red}Error: container directory does not exist QwQ\n");
	}
	// Do not use '/' for container_dir.
	if (strcmp(container_dir, "/") == 0) {
		ruri_error("{red}Error: `/` is not allowed to use as a container directory QwQ\n");
	}
	// Check if container_dir exist.
	char *test = realpath(container_dir, NULL);
	if (test == NULL) {
		ruri_error("{red}Error: container directory does not exist QwQ\n");
	}
	free(test);
	struct RURI_CONTAINER *container = ruri_read_info(NULL, container_dir);
	container->container_dir = strdup(container_dir);
	// Kill ns_pid.
	if (container->ns_pid > 0) {
		ruri_log("{base}Kill ns pid: {blue}%d\n", container->ns_pid);
		kill(container->ns_pid, SIGKILL);
	}
	// Kill all processes in container.
	// For container with PID ns enabled, when ns_pid is killed,
	// all process will die, but without PID ns, we still need to
	// find & kill other process.
	ruri_kill_container(container);
	ruri_log("{base}Umounting container...\n");
	char infofile[PATH_MAX] = { '\0' };
	if (snprintf(infofile, sizeof(infofile), "%s/.rurienv", container_dir) >= (int)sizeof(infofile)) {
		ruri_error("{red}Error: container directory path is too long QwQ\n");
	}
	// Umount .rurienv file.
	umount2(infofile, MNT_DETACH | MNT_FORCE);
	int fd = open(infofile, O_RDONLY | O_CLOEXEC);
	// Unset immutable flag on .rurienv.
	int attr = 0;
	if (fd >= 0) {
		ioctl(fd, FS_IOC_GETFLAGS, &attr);
		attr &= ~FS_IMMUTABLE_FL;
		ioctl(fd, FS_IOC_SETFLAGS, &attr);
		remove(infofile);
		close(fd);
	} else {
		ruri_warning("{yellow}Warning: .rurienv does not exist\n");
	}
	// Get path to umount.
	char sys_dir[PATH_MAX];
	char proc_dir[PATH_MAX];
	char dev_dir[PATH_MAX];
	char to_umountpoint[PATH_MAX];
	if (snprintf(sys_dir, sizeof(sys_dir), "%s/sys", container_dir) >= (int)sizeof(sys_dir) || snprintf(proc_dir, sizeof(proc_dir), "%s/proc", container_dir) >= (int)sizeof(proc_dir) || snprintf(dev_dir, sizeof(dev_dir), "%s/dev", container_dir) >= (int)sizeof(dev_dir)) {
		ruri_error("{red}Error: container directory path is too long QwQ\n");
	}
	// Umount other mountpoints.
	if (container != NULL) {
		// Umount extra_mountpoint.
		for (int i = 1; true; i += 2) {
			if (container->extra_mountpoint[i] == NULL) {
				break;
			}
			if (snprintf(to_umountpoint, sizeof(to_umountpoint), "%s%s", container_dir, container->extra_mountpoint[i]) >= (int)sizeof(to_umountpoint)) {
				ruri_error("{red}QwQ? Why we are here?\n");
			}
			ruri_log("{base}Umounting %s\n", to_umountpoint);
			for (int j = 0; j < 10; j++) {
				umount2(to_umountpoint, MNT_DETACH);
				umount(to_umountpoint);
				usleep(20000);
			}
			// Remove the empty file we created for mounting files into container.
			remove(to_umountpoint);
			// Make ASAN happy.
			free(container->extra_mountpoint[i]);
			free(container->extra_mountpoint[i - 1]);
		}
		// Umount extra_ro_mountpoint.
		for (int i = 1; true; i += 2) {
			if (container->extra_ro_mountpoint[i] == NULL) {
				break;
			}
			if (snprintf(to_umountpoint, sizeof(to_umountpoint), "%s%s", container_dir, container->extra_ro_mountpoint[i]) >= (int)sizeof(to_umountpoint)) {
				ruri_error("{red}QwQ? Why we are here?\n");
			}
			for (int j = 0; j < 10; j++) {
				ruri_log("{base}Umounting %s\n", to_umountpoint);
				umount2(to_umountpoint, MNT_DETACH);
				umount(to_umountpoint);
				usleep(20000);
			}
			// Remove the empty file we created for mounting files into container.
			// Not rmdir(), so directory will not be removed.
			remove(to_umountpoint);
			// Make ASAN happy.
			free(container->extra_ro_mountpoint[i]);
			free(container->extra_ro_mountpoint[i - 1]);
		}
	}
	// Force umount system runtime directories for 10 times.
	// Not necessary, but I think it's more secure.
	ruri_log("{base}Umounting %s\n", sys_dir);
	ruri_log("{base}Umounting %s\n", proc_dir);
	ruri_log("{base}Umounting %s\n", dev_dir);
	ruri_log("{base}Umounting %s\n", container_dir);
	for (int i = 1; i < 10; i++) {
		umount2(sys_dir, MNT_DETACH | MNT_FORCE);
		usleep(2000);
		umount2(dev_dir, MNT_DETACH | MNT_FORCE);
		usleep(2000);
		umount2(proc_dir, MNT_DETACH | MNT_FORCE);
		usleep(2000);
		umount2(container_dir, MNT_DETACH);
		usleep(2000);
	}
	// Make Asan happy.
	free(container->container_dir);
	free(container);
	// Use info in /proc/mounts to umount container.
	// This is a double check.
	umount_subdir(container_dir);
}
