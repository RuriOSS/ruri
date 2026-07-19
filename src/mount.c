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
 * This file provides the mount functions for ruri.
 * It's used to mount disk devices, loop devices, and dir/files.
 * It also provides ruri_mkdirs() to create directories recursively.
 */
// Return the same value as mkdir().
int ruri_mkdirs(const char *_Nonnull dir, mode_t mode)
{
	/*
	 * A very simple implementation of mkdir -p.
	 * I don't know why it seems that there isn't an existing function to do this...
	 * EEXIST will be ignored.
	 */
	char buf[PATH_MAX + 1] = { '\0' };
	int ret = 0;
	/* If dir is path/to/mkdir
	 * We do:
	 * ret = mkdir("path",mode);
	 * ret = mkdir("path/to",mode);
	 * ret = mkdir("path/to/mkdir",mode);
	 * return ret;
	 */
	for (size_t i = 1; i < strlen(dir); i++) {
		if (dir[i] == '/') {
			for (size_t j = 0; j < i; j++) {
				buf[j] = dir[j];
				buf[j + 1] = '\0';
			}
			ret = mkdir(buf, mode);
			if (ret != 0 && errno != EEXIST) {
				return ret;
			}
		}
	}
	// If the end of `dir` is not '/', create the last level of the directory.
	if (dir[strlen(dir) - 1] != '/') {
		ret = mkdir(dir, mode);
	}
	if (ret != 0 && errno == EEXIST) {
		ret = 0;
	}
	return ret;
}
static char *cut_mount_flags(const char *_Nonnull source)
{
	/*
	 * Cut all mount flags from source, and return the flag.
	 * Flags:
	 *   "RDONLY:"      -> MS_RDONLY
	 *   "NOSUID:"      -> MS_NOSUID
	 *   "NODEV:"       -> MS_NODEV
	 *   "NOEXEC:"      -> MS_NOEXEC
	 *   "NODIRATIME:"  -> MS_NODIRATIME
	 *   "NOATIME:"     -> MS_NOATIME
	 *   "SYNCHRONOUS:" -> MS_SYNCHRONOUS
	 *   "DIRSYNC:"     -> MS_DIRSYNC
	 *   "MANDLOCK:"    -> MS_MANDLOCK
	 *   "RELATIME:"    -> MS_RELATIME
	 *   "SLAVE:"       -> MS_SLAVE
	 *   "SHARED:"      -> MS_SHARED
	 *   "PRIVATE:"     -> MS_PRIVATE
	 *   "UNBINDABLE:"  -> MS_UNBINDABLE
	 *   "SILENT:"      -> MS_SILENT
	 *   "POSIXACL:"    -> MS_POSIXACL
	 *   "LAZYTIME:"    -> MS_LAZYTIME
	 *
	 * Fs types:
	 *
	 */
	char *flags[] = { "RDONLY:", "NOSUID:", "NODEV:", "NOEXEC:", "NODIRATIME:", "NOATIME:", "SYNCHRONOUS:", "DIRSYNC:", "MANDLOCK:", "RELATIME:", "SLAVE:", "SHARED:", "PRIVATE:", "UNBINDABLE:", "SILENT:", "POSIXACL:", "LAZYTIME:" };
	char *ret = NULL;
	while (true) {
		for (size_t i = 0; i < sizeof(flags) / sizeof(flags[0]); i++) {
			if (strncmp(source, flags[i], strlen(flags[i])) == 0) {
				if (ret == NULL) {
					ret = strdup(flags[i]);
				} else {
					char *tmp = ruri_malloc(strlen(ret) + strlen(flags[i]) + 1);
					strcpy(tmp, ret);
					strcat(tmp, flags[i]);
					free(ret);
					ret = tmp;
				}
				source += strlen(flags[i]);
				break;
			}
			if (i == sizeof(flags) / sizeof(flags[0]) - 1) {
				return ret;
			}
		}
	}
	return NULL;
}
static char *cut_mount_fs_type(const char *_Nonnull source)
{
	/*
	 * Cut all fs type from source, and return the fs type.
	 * Fs types:
	 *   - "OVERLAY:" : Mounts an OverlayFS at the target using the provided options.
	 *   - "TMPFS:"   : Mounts a tmpfs at the target using the provided options.
	 *   - "EXT4:"    : Mounts an ext4 filesystem at the target.
	 *   - "FAT32:"   : Mounts a FAT32 (vfat) filesystem at the target.
	 *   - "NTFS:"    : Mounts an NTFS filesystem at the target.
	 *   - "XFS:"     : Mounts an XFS filesystem at the target.
	 *   - "BTRFS:"   : Mounts a Btrfs filesystem at the target.
	 *   - "EXFAT:"   : Mounts an exFAT filesystem at the target.
	 *   - "F2FS:"    : Mounts an F2FS filesystem at the target.
	 *   - "EROFS:"   : Mounts an EROFS filesystem at the target.
	 */
	char *fstypes[] = { "OVERLAY:", "TMPFS:", "EXT4:", "FAT32:", "NTFS:", "XFS:", "BTRFS:", "EXFAT:", "F2FS:", "EROFS:" };
	for (int i = 0; i < sizeof(fstypes) / sizeof(fstypes[0]); i++) {
		if (strncmp(source, fstypes[i], strlen(fstypes[i])) == 0) {
			return strdup(fstypes[i]);
		}
	}
	return NULL;
}
void ruri_convert_mountpoints_to_absolute(struct RURI_CONTAINER *container)
{
	/*
	 * Convert all mountpoints to absolute path.
	 * This is to avoid some unexpected errors.
	 */
	for (int i = 0; container->extra_mountpoint[i] != NULL; i += 2) {
		char *source = container->extra_mountpoint[i];
		char *flags = cut_mount_flags(container->extra_mountpoint[i]);
		if (flags) {
			if (strncmp(source, flags, strlen(flags)) != 0) {
				ruri_error("{red}Error: Internal error: cut_mount_flags() returned wrong flags for source %s\n", source);
			}
			source += strlen(flags);
		}
		char *fstype = cut_mount_fs_type(source);
		if (fstype) {
			if (strncmp(source, fstype, strlen(fstype)) != 0) {
				ruri_error("{red}Error: Internal error: cut_mount_fs_type() returned wrong fs type for source %s\n", source);
			}
			source += strlen(fstype);
			// For OVERLAY and TMPFS, we don't need to convert to absolute path.
			if (strcmp(fstype, "OVERLAY:") == 0 || strcmp(fstype, "TMPFS:") == 0) {
				free(fstype);
				free(flags);
				continue;
			}
		}
		char *abs_source = realpath(source, NULL);
		if (!abs_source) {
			ruri_error("{red}Error: realpath() failed for source %s\n", source);
		}
		char *new_source = ruri_malloc(strlen(flags ? flags : "") + strlen(fstype ? fstype : "") + strlen(abs_source) + 1);
		strcpy(new_source, flags ? flags : "");
		strcat(new_source, fstype ? fstype : "");
		strcat(new_source, abs_source);
		free(abs_source);
		free(container->extra_mountpoint[i]);
		container->extra_mountpoint[i] = new_source;
		free(fstype);
		free(flags);
	}
	for (int i = 0; container->extra_ro_mountpoint[i] != NULL; i += 2) {
		char *source = container->extra_ro_mountpoint[i];
		char *flags = cut_mount_flags(container->extra_ro_mountpoint[i]);
		if (flags) {
			if (strncmp(source, flags, strlen(flags)) != 0) {
				ruri_error("{red}Error: Internal error: cut_mount_flags() returned wrong flags for source %s\n", source);
			}
			source += strlen(flags);
		}
		char *fstype = cut_mount_fs_type(source);
		if (fstype) {
			if (strncmp(source, fstype, strlen(fstype)) != 0) {
				ruri_error("{red}Error: Internal error: cut_mount_fs_type() returned wrong fs type for source %s\n", source);
			}
			source += strlen(fstype);
			// For OVERLAY and TMPFS, we don't need to convert to absolute path.
			if (strcmp(fstype, "OVERLAY:") == 0 || strcmp(fstype, "TMPFS:") == 0) {
				free(fstype);
				free(flags);
				continue;
			}
		}
		char *abs_source = realpath(source, NULL);
		if (!abs_source) {
			ruri_error("{red}Error: realpath() failed for source %s\n", source);
		}
		char *new_source = ruri_malloc(strlen(flags ? flags : "") + strlen(fstype ? fstype : "") + strlen(abs_source) + 1);
		strcpy(new_source, flags ? flags : "");
		strcat(new_source, fstype ? fstype : "");
		strcat(new_source, abs_source);
		free(abs_source);
		free(container->extra_ro_mountpoint[i]);
		container->extra_ro_mountpoint[i] = new_source;
		free(fstype);
		free(flags);
	}
}
void ruri_convert_rootfs_source_to_absolute(struct RURI_CONTAINER *container)
{
	/*
	 * Convert rootfs source to absolute path.
	 * This is to avoid some unexpected errors.
	 */
	if (container->rootfs_source) {
		char *source = container->rootfs_source;
		char *flags = cut_mount_flags(container->rootfs_source);
		if (flags) {
			if (strncmp(source, flags, strlen(flags)) != 0) {
				ruri_error("{red}Error: Internal error: cut_mount_flags() returned wrong flags for source %s\n", source);
			}
			source += strlen(flags);
		}
		char *fstype = cut_mount_fs_type(source);
		if (fstype) {
			if (strncmp(source, fstype, strlen(fstype)) != 0) {
				ruri_error("{red}Error: Internal error: cut_mount_fs_type() returned wrong fs type for source %s\n", source);
			}
			source += strlen(fstype);
			// For OVERLAY and TMPFS, we don't need to convert to absolute path.
			if (strcmp(fstype, "OVERLAY:") == 0 || strcmp(fstype, "TMPFS:") == 0) {
				free(fstype);
				free(flags);
				return;
			}
		}
		char *abs_source = realpath(source, NULL);
		if (!abs_source) {
			ruri_error("{red}Error: realpath() failed for source %s\n", source);
		}
		char *new_source = ruri_malloc(strlen(flags ? flags : "") + strlen(fstype ? fstype : "") + strlen(abs_source) + 1);
		strcpy(new_source, flags ? flags : "");
		strcat(new_source, fstype ? fstype : "");
		strcat(new_source, abs_source);
		free(abs_source);
		free(container->rootfs_source);
		container->rootfs_source = new_source;
		free(fstype);
		free(flags);
	}
}
// Mount disk device.
static int mount_device(const char *_Nonnull source, const char *_Nonnull target, unsigned long mountflags)
{
	/*
	 * /proc/filesystems format just like:
	 *
	 * nodev'\t'sysfs'\n'
	 * '\t'ext4'\n'
	 *
	 * So, every time, we read the buf until we get '\t',
	 * check if we got before is "nodev" (that means it's not a filesystem type for devices),
	 * if we reached '\n', and nodev is not set,
	 * that means we got a true filesystem type to mount,
	 * so we try to use the type we get for mount(2);
	 */
	int ret = -1;
	// Get filesystems supported.
	int fssfd = open("/proc/filesystems", O_RDONLY | O_CLOEXEC);
	if (fssfd < 0) {
		return -1;
	}
	FILE *filesystems = fdopen(fssfd, "r");
	if (filesystems == NULL) {
		close(fssfd);
		return -1;
	}
	char line[PATH_MAX];
	char first[16];
	char type[PATH_MAX];
	while (fgets(line, sizeof(line), filesystems) != NULL) {
		memset(first, '\0', sizeof(first));
		memset(type, '\0', sizeof(type));
		int fields = sscanf(line, "%15s %4095s", first, type);
		if (fields < 1) {
			continue;
		}
		// Lines with two fields have the form "nodev <filesystem>".
		if (fields == 2 && strcmp(first, "nodev") == 0) {
			continue;
		}
		const char *fstype = fields == 2 ? type : first;
		ret = mount(source, target, fstype, mountflags, NULL);
		if (ret != 0) {
			continue;
		}
		// MS_RDONLY is honored by the initial filesystem mount. A remount
		// is only needed when the caller explicitly requested read-only.
		if ((mountflags & MS_RDONLY) == 0) {
			ret = 0;
			break;
		}
		ret = mount(source, target, fstype, mountflags | MS_REMOUNT, NULL);
		if (ret != 0) {
			int saved_errno = errno;
			umount2(target, MNT_DETACH | MNT_FORCE);
			errno = saved_errno;
		}
		break;
	}
	int saved_errno = errno;
	fclose(filesystems);
	errno = saved_errno;
	return ret;
}
static int get_loop_nr(int devnr)
{
	// Read /sys/block/loop{devnr}/dev for minor.
	// Format: major:minor
	char sysfs_path[PATH_MAX];
	sprintf(sysfs_path, "/sys/block/loop%d/dev", devnr);
	int fd = open(sysfs_path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		return -1;
	}
	char buf[32];
	ssize_t n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n < 0) {
		return -1;
	}
	buf[n] = '\0';
	if (strchr(buf, ':') == NULL) {
		return -1;
	}
	return atoi(strchr(buf, ':') + 1);
}
// Same as `losetup` command.
static char *losetup(const char *_Nonnull img)
{
	/*
	 * We return the loopfile we get for losetup,
	 * so that we can use the return value to mount the image.
	 */
	// Get a new loopfile for losetup.
	bool is_android = false;
	int loopctlfd = open("/dev/loop-control", O_RDWR | O_CLOEXEC);
	if (loopctlfd < 0) {
		loopctlfd = open("/dev/block/loop-control", O_RDWR | O_CLOEXEC);
		if (loopctlfd < 0) {
			ruri_log("{red}Error: {base}Cannot open /dev/loop-control or /dev/block/loop-control.\n");
			return NULL;
		}
		is_android = true;
	}
	// It takes the same effect as `losetup -f`.
	int devnr = ioctl(loopctlfd, LOOP_CTL_GET_FREE);
	if (devnr < 0) {
		close(loopctlfd);
		return NULL;
	}
	// Sleep 0.2s to wait udev.
	usleep(200000);
	close(loopctlfd);
	char *loopfile = ruri_malloc(PATH_MAX);
	memset(loopfile, 0, PATH_MAX);
	if (is_android) {
		sprintf(loopfile, "/dev/block/loop%d", devnr);
	} else {
		sprintf(loopfile, "/dev/loop%d", devnr);
	}
	int loopfd = open(loopfile, O_RDWR | O_CLOEXEC);
	if (loopfd < 0) {
		int nr_to_mknod = get_loop_nr(devnr);
		if (nr_to_mknod < 0) {
			if (is_android) {
				nr_to_mknod = devnr * 8;
			} else {
				nr_to_mknod = devnr;
			}
		}
		// Just mknod it.
		mknod(loopfile, S_IFBLK | 0660, makedev(7, nr_to_mknod));
		// Sleep 0.1s.
		usleep(100000);
		loopfd = open(loopfile, O_RDWR | O_CLOEXEC);
		if (loopfd < 0) {
			free(loopfile);
			return NULL;
		}
	}
	// It takes the same efferct as `losetup` command.
	int imgfd = open(img, O_RDWR | O_CLOEXEC);
	if (imgfd < 0) {
		free(loopfile);
		return NULL;
	}
	if (ioctl(loopfd, LOOP_SET_FD, imgfd) == -1) {
		free(loopfile);
		close(loopfd);
		close(imgfd);
		return NULL;
	}
	close(loopfd);
	close(imgfd);
	ruri_log("{base}losetup {cyan}%s{base} ==> {cyan}%s{base}\n", img, loopfile);
	return loopfile;
}
static int mk_mountpoint_dir(const char *_Nonnull target)
{
	/*
	 * Just to mkdir(target).
	 */
	// remove the target if it exists as a file.
	// I know this can hardly be happen, just to avoid some unexpected errors.
	remove(target);
	// Check if mountpoint exists.
	char *test = realpath(target, NULL);
	if (test == NULL) {
		if (ruri_mkdirs(target, S_IRGRP | S_IWGRP | S_IRUSR | S_IWUSR | S_IROTH | S_IWOTH) != 0) {
			return -1;
		}
	} else {
		free(test);
		return 0;
	}
	return 0;
}
static int touch_mountpoint_file(const char *_Nonnull target)
{
	/*
	 * Create a common file at target.
	 */
	// We use ruri_mkdirs() to create the parent directory of the file,
	// And rmdir() target, so we will never get error that
	// the parent directory of the file is not exist.
	ruri_mkdirs(target, S_IRGRP | S_IWGRP | S_IRUSR | S_IWUSR | S_IROTH | S_IWOTH);
	rmdir(target);
	// Check if mountpoint exists.
	int fd = open(target, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		fd = open(target, O_CREAT | O_CLOEXEC | O_RDWR, S_IRGRP | S_IWGRP | S_IRUSR | S_IWUSR | S_IROTH | S_IWOTH);
		if (fd < 0) {
			return -1;
		}
		close(fd);
	} else {
		close(fd);
	}
	return 0;
}
static int mount_as_filesystem(const char *_Nonnull source, const char *_Nonnull target, const char *_Nonnull fstype, unsigned int mountflags)
{
	/*
	 * Mounts a filesystem at target with the given source and fstype.
	 * This function is used to mount filesystems like ext4, vfat, ntfs, etc.
	 *
	 * Parameters:
	 *   - source:     The source string (e.g., "/dev/sda1").
	 *   - target:     The target directory where the filesystem will be mounted.
	 *   - fstype:     The type of filesystem (e.g., "ext4", "vfat", "ntfs").
	 *   - mountflags: Mount flags to be used in the mount operation.
	 *
	 * Returns:
	 *   - 0 on success.
	 *   - -1 on failure.
	 */
	struct stat dev_stat;
	// Check if source exists.
	if (lstat(source, &dev_stat) != 0) {
		ruri_warn_on_error(1, 0, true, "{red}Error: {base}Source {cyan}%s{base} does not exist.\n", source);
		return -1;
	}
	ruri_log("{base}Mounting {cyan}%s{base} to {cyan}%s{base} with fstype {cyan}%s{base} and flags {cyan}%d{base}\n", source, target, fstype, mountflags);
	int ret = 0;
	// If source is not a block device, losetup it.
	if (!S_ISBLK(dev_stat.st_mode)) {
		char *loopfile = losetup(source);
		if (loopfile == NULL) {
			return -1;
		}
		ret = mount(loopfile, target, fstype, mountflags, NULL);
		if (ret == 0 && (mountflags & MS_RDONLY) != 0) {
			ret = mount(loopfile, target, fstype, mountflags | MS_REMOUNT, NULL);
		}
		free(loopfile);
		return ret;
	}
	ret = mount(source, target, fstype, mountflags, NULL);
	if (ret == 0 && (mountflags & MS_RDONLY) != 0) {
		ret = mount(source, target, fstype, mountflags | MS_REMOUNT, NULL);
	}
	return ret;
}
static int mount_other_type(const char *_Nonnull source, const char *_Nonnull target, unsigned int mountflags)
{
	/*
	 * Mounts various types of filesystems based on the prefix of the source string.
	 *
	 * Supported source prefixes and their corresponding filesystems:
	 *   - "OVERLAY:" : Mounts an OverlayFS at the target using the provided options.
	 *   - "TMPFS:"   : Mounts a tmpfs at the target using the provided options.
	 *   - "EXT4:"    : Mounts an ext4 filesystem at the target.
	 *   - "FAT32:"   : Mounts a FAT32 (vfat) filesystem at the target.
	 *   - "NTFS:"    : Mounts an NTFS filesystem at the target.
	 *   - "XFS:"     : Mounts an XFS filesystem at the target.
	 *   - "BTRFS:"   : Mounts a Btrfs filesystem at the target.
	 *   - "EXFAT:"   : Mounts an exFAT filesystem at the target.
	 *   - "F2FS:"    : Mounts an F2FS filesystem at the target.
	 *   - "EROFS:"   : Mounts an EROFS filesystem at the target.
	 *
	 * Parameters:
	 *   - source:     The source string with a filesystem type prefix (e.g., "EXT4:/dev/sda1").
	 *   - target:     The target directory where the filesystem will be mounted.
	 *   - mountflags: Mount flags to be used in the mount operation.
	 *
	 * Returns:
	 *   - 0 on success.
	 *   - -1 on failure or if the source type is unsupported.
	 */
	if (strncmp(source, "OVERLAY:", strlen("OVERLAY:")) == 0) {
		// OverlayFS mount.
		ruri_log("{base}Mounting {cyan}%s{base} to {cyan}%s{base} with flags {cyan}%d{base}\n", source, target, mountflags);
		if (mk_mountpoint_dir(target) != 0) {
			return -1;
		}
		char *overlay_flag = strdup(source + strlen("OVERLAY:"));
		int ret = mount("overlay", target, "overlay", mountflags, overlay_flag);
		free(overlay_flag);
		return ret;
	}
	if (strncmp(source, "TMPFS:", strlen("TMPFS:")) == 0) {
		// Tmpfs mount.
		ruri_log("{base}Mounting {cyan}%s{base} to {cyan}%s{base} with flags {cyan}%d{base}\n", source, target, mountflags);
		if (mk_mountpoint_dir(target) != 0) {
			return -1;
		}
		char *tmpfs_flag = strdup(source + strlen("TMPFS:"));
		int ret = mount("tmpfs", target, "tmpfs", mountflags, tmpfs_flag);
		if (ret == 0 && (mountflags & MS_RDONLY) != 0) {
			ret = mount("tmpfs", target, "tmpfs", mountflags | MS_REMOUNT, tmpfs_flag);
		}
		free(tmpfs_flag);
		return ret;
	}
	if (strncmp(source, "EXT4:", strlen("EXT4:")) == 0) {
		// Ext4 mount.
		ruri_log("{base}Mounting {cyan}%s{base} to {cyan}%s{base} with flags {cyan}%d{base}\n", source, target, mountflags);
		if (mk_mountpoint_dir(target) != 0) {
			return -1;
		}
		char *ext4_source = strdup(source + strlen("EXT4:"));
		int ret = mount_as_filesystem(ext4_source, target, "ext4", mountflags);
		free(ext4_source);
		return ret;
	}
	if (strncmp(source, "FAT32:", strlen("FAT32:")) == 0) {
		// FAT32 mount.
		ruri_log("{base}Mounting {cyan}%s{base} to {cyan}%s{base} with flags {cyan}%d{base}\n", source, target, mountflags);
		if (mk_mountpoint_dir(target) != 0) {
			return -1;
		}
		char *fat32_source = strdup(source + strlen("FAT32:"));
		int ret = mount_as_filesystem(fat32_source, target, "vfat", mountflags);
		free(fat32_source);
		return ret;
	}
	if (strncmp(source, "NTFS:", strlen("NTFS:")) == 0) {
		// NTFS mount.
		ruri_log("{base}Mounting {cyan}%s{base} to {cyan}%s{base} with flags {cyan}%d{base}\n", source, target, mountflags);
		if (mk_mountpoint_dir(target) != 0) {
			return -1;
		}
		char *ntfs_source = strdup(source + strlen("NTFS:"));
		int ret = mount_as_filesystem(ntfs_source, target, "ntfs", mountflags);
		free(ntfs_source);
		return ret;
	}
	if (strncmp(source, "XFS:", strlen("XFS:")) == 0) {
		// XFS mount.
		ruri_log("{base}Mounting {cyan}%s{base} to {cyan}%s{base} with flags {cyan}%d{base}\n", source, target, mountflags);
		if (mk_mountpoint_dir(target) != 0) {
			return -1;
		}
		char *xfs_source = strdup(source + strlen("XFS:"));
		int ret = mount_as_filesystem(xfs_source, target, "xfs", mountflags);
		free(xfs_source);
		return ret;
	}
	if (strncmp(source, "BTRFS:", strlen("BTRFS:")) == 0) {
		// BTRFS mount.
		ruri_log("{base}Mounting {cyan}%s{base} to {cyan}%s{base} with flags {cyan}%d{base}\n", source, target, mountflags);
		if (mk_mountpoint_dir(target) != 0) {
			return -1;
		}
		char *btrfs_source = strdup(source + strlen("BTRFS:"));
		int ret = mount_as_filesystem(btrfs_source, target, "btrfs", mountflags);
		free(btrfs_source);
		return ret;
	}
	if (strncmp(source, "EXFAT:", strlen("EXFAT:")) == 0) {
		// ExFAT mount.
		ruri_log("{base}Mounting {cyan}%s{base} to {cyan}%s{base} with flags {cyan}%d{base}\n", source, target, mountflags);
		if (mk_mountpoint_dir(target) != 0) {
			return -1;
		}
		char *exfat_source = strdup(source + strlen("EXFAT:"));
		int ret = mount_as_filesystem(exfat_source, target, "exfat", mountflags);
		free(exfat_source);
		return ret;
	}
	if (strncmp(source, "F2FS:", strlen("F2FS:")) == 0) {
		// F2FS mount.
		ruri_log("{base}Mounting {cyan}%s{base} to {cyan}%s{base} with flags {cyan}%d{base}\n", source, target, mountflags);
		if (mk_mountpoint_dir(target) != 0) {
			return -1;
		}
		char *f2fs_source = strdup(source + strlen("F2FS:"));
		int ret = mount_as_filesystem(f2fs_source, target, "f2fs", mountflags);
		free(f2fs_source);
		return ret;
	}
	if (strncmp(source, "EROFS:", strlen("EROFS:")) == 0) {
		// EROFS mount.
		ruri_log("{base}Mounting {cyan}%s{base} to {cyan}%s{base} with flags {cyan}%d{base}\n", source, target, mountflags);
		if (mk_mountpoint_dir(target) != 0) {
			return -1;
		}
		char *erofs_source = strdup(source + strlen("EROFS:"));
		int ret = mount_as_filesystem(erofs_source, target, "erofs", mountflags);
		free(erofs_source);
		return ret;
	}
	// For source that cannot be mounted.
	return -1;
}
static const char *parse_mount_flags(const char *source, unsigned int *mountflag)
{
	/*
	 * Parse mount flags from source.
	 * Save the mount flags to mountflag.
	 * Return the start of source without mount flags.
	 *
	 * Recognized prefixes and their corresponding flags:
	 *   "RDONLY:"      -> MS_RDONLY
	 *   "NOSUID:"      -> MS_NOSUID
	 *   "NODEV:"       -> MS_NODEV
	 *   "NOEXEC:"      -> MS_NOEXEC
	 *   "NODIRATIME:"  -> MS_NODIRATIME
	 *   "NOATIME:"     -> MS_NOATIME
	 *   "SYNCHRONOUS:" -> MS_SYNCHRONOUS
	 *   "DIRSYNC:"     -> MS_DIRSYNC
	 *   "MANDLOCK:"    -> MS_MANDLOCK
	 *   "RELATIME:"    -> MS_RELATIME
	 *   "SLAVE:"       -> MS_SLAVE
	 *   "SHARED:"      -> MS_SHARED
	 *   "PRIVATE:"     -> MS_PRIVATE
	 *   "UNBINDABLE:"  -> MS_UNBINDABLE
	 *   "SILENT:"      -> MS_SILENT
	 *   "POSIXACL:"    -> MS_POSIXACL
	 *   "LAZYTIME:"    -> MS_LAZYTIME
	 *
	 * The function stops processing when no recognized prefix is found at the start of 'source'.
	 *
	 */
	while (true) {
		if (strncmp(source, "RDONLY:", strlen("RDONLY:")) == 0) {
			*mountflag |= MS_RDONLY;
			source += strlen("RDONLY:");
		} else if (strncmp(source, "NOSUID:", strlen("NOSUID:")) == 0) {
			*mountflag |= MS_NOSUID;
			source += strlen("NOSUID:");
		} else if (strncmp(source, "NODEV:", strlen("NODEV:")) == 0) {
			*mountflag |= MS_NODEV;
			source += strlen("NODEV:");
		} else if (strncmp(source, "NOEXEC:", strlen("NOEXEC:")) == 0) {
			*mountflag |= MS_NOEXEC;
			source += strlen("NOEXEC:");
		} else if (strncmp(source, "NODIRATIME:", strlen("NODIRATIME:")) == 0) {
			*mountflag |= MS_NODIRATIME;
			source += strlen("NODIRATIME:");
		} else if (strncmp(source, "NOATIME:", strlen("NOATIME:")) == 0) {
			*mountflag |= MS_NOATIME;
			source += strlen("NOATIME:");
		} else if (strncmp(source, "SYNCHRONOUS:", strlen("SYNCHRONOUS:")) == 0) {
			*mountflag |= MS_SYNCHRONOUS;
			source += strlen("SYNCHRONOUS:");
		} else if (strncmp(source, "DIRSYNC:", strlen("DIRSYNC:")) == 0) {
			*mountflag |= MS_DIRSYNC;
			source += strlen("DIRSYNC:");
		} else if (strncmp(source, "MANDLOCK:", strlen("MANDLOCK:")) == 0) {
			*mountflag |= MS_MANDLOCK;
			source += strlen("MANDLOCK:");
		} else if (strncmp(source, "RELATIME:", strlen("RELATIME:")) == 0) {
			*mountflag |= MS_RELATIME;
			source += strlen("RELATIME:");
		} else if (strncmp(source, "SLAVE:", strlen("SLAVE:")) == 0) {
			*mountflag |= MS_SLAVE;
			source += strlen("SLAVE:");
		} else if (strncmp(source, "SHARED:", strlen("SHARED:")) == 0) {
			*mountflag |= MS_SHARED;
			source += strlen("SHARED:");
		} else if (strncmp(source, "PRIVATE:", strlen("PRIVATE:")) == 0) {
			*mountflag |= MS_PRIVATE;
			source += strlen("PRIVATE:");
		} else if (strncmp(source, "UNBINDABLE:", strlen("UNBINDABLE:")) == 0) {
			*mountflag |= MS_UNBINDABLE;
			source += strlen("UNBINDABLE:");
		} else if (strncmp(source, "SILENT:", strlen("SILENT:")) == 0) {
			*mountflag |= MS_SILENT;
			source += strlen("SILENT:");
		} else if (strncmp(source, "POSIXACL:", strlen("POSIXACL:")) == 0) {
			*mountflag |= MS_POSIXACL;
			source += strlen("POSIXACL:");
		} else if (strncmp(source, "LAZYTIME:", strlen("LAZYTIME:")) == 0) {
			*mountflag |= MS_LAZYTIME;
			source += strlen("LAZYTIME:");
		} else {
			break;
		}
	}
	return source;
}
// Mount dev/dir/img to target.
int ruri_trymount(const char *_Nonnull source, const char *_Nonnull target, unsigned int mountflags)
{
	/*
	 * This function is designed to mount a device/dir/image/file to target.
	 * We support to mount:
	 * Block device
	 * Directory
	 * Image file
	 * Common file
	 * Char device
	 * FIFO
	 * Socket
	 * I hope it works as expected.
	 */
	// umount target before mount(2), to avoid `device or resource busy`.
	umount2(target, MNT_DETACH | MNT_FORCE);
	int ret = 0;
	unsigned int mountflags_new = mountflags;
	source = parse_mount_flags(source, &mountflags_new);
	ruri_log("{base}Mounting {cyan}%s{base} to {cyan}%s{base} with flags {cyan}%d{base}\n", source, target, mountflags_new);
	struct stat dev_stat;
	// If source does not exist, try to parse as other type of source.
	if (lstat(source, &dev_stat) != 0) {
		return mount_other_type(source, target, mountflags_new);
	}
	// Bind-mount dir.
	if (S_ISDIR(dev_stat.st_mode)) {
		ruri_log("{base}Bind-mounting {cyan}%s{base} to {cyan}%s{base}\n", source, target);
		if (mk_mountpoint_dir(target) != 0) {
			return -1;
		}
		ret = mount(source, target, NULL, mountflags_new | MS_BIND, NULL);
		// Bind mounts apply their extra flags in a remount. A plain
		// read-write bind mount does not need a second syscall.
		if (ret == 0 && mountflags_new != 0) {
			ret = mount(source, target, NULL, mountflags_new | MS_BIND | MS_REMOUNT, NULL);
		}
	}
	// Block device.
	else if (S_ISBLK(dev_stat.st_mode)) {
		ruri_log("{base}Mounting block device {cyan}%s{base} to {cyan}%s{base}\n", source, target);
		if (mk_mountpoint_dir(target) != 0) {
			return -1;
		}
		ret = mount_device(source, target, mountflags_new);
	}
	// Image and common file.
	// We cannot distinguish image file and common file by stat(2),
	// So we try to mount it as an image file first.
	// If it fails, we bind-mount it as a common file.
	else if (S_ISREG(dev_stat.st_mode)) {
		// Image file.
		if (mk_mountpoint_dir(target) != 0) {
			return -1;
		}
		ruri_log("{base}Mounting as image file {cyan}%s{base} to {cyan}%s{base}\n", source, target);
		char *loopfile = losetup(source);
		if (!loopfile) {
			return -1;
		}
		ret = mount_device(loopfile, target, mountflags_new);
		free(loopfile);
		// Common file.
		if (ret != 0) {
			if (touch_mountpoint_file(target) != 0) {
				return -1;
			}
			ruri_log("{base}Bind-mounting as common file {cyan}%s{base} to {cyan}%s{base}\n", source, target);
			ret = mount(source, target, NULL, mountflags_new | MS_BIND, NULL);
			if (ret == 0 && mountflags_new != 0) {
				ret = mount(source, target, NULL, mountflags_new | MS_BIND | MS_REMOUNT, NULL);
			}
		}
	}
	// For char-device/FIFO/socket, we just bind-mount it.
	else if (S_ISCHR(dev_stat.st_mode) || S_ISFIFO(dev_stat.st_mode) || S_ISSOCK(dev_stat.st_mode)) {
		if (touch_mountpoint_file(target) != 0) {
			return -1;
		}
		ruri_log("{base}Bind-mounting {cyan}%s{base} to {cyan}%s{base}\n", source, target);
		ret = mount(source, target, NULL, mountflags_new | MS_BIND, NULL);
		if (ret == 0 && mountflags_new != 0) {
			ret = mount(source, target, NULL, mountflags_new | MS_BIND | MS_REMOUNT, NULL);
		}
	}
	// We do not support to mount other type of files.
	else {
		ruri_log("{red}Error: {base}Unsupported file type.\n");
		ret = -1;
	}
	return ret;
}
