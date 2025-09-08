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
 * This file is the core of ruri.
 * It provides functions to run container as info in struct RURI_CONTAINER.
 * Bisic functions of ruri is implemented here.
 * Thanks docker and podman for the device list and mask/protect list.
 */
static bool su_biany_exist(char *_Nonnull container_dir)
{
	/*
	 * Check if /bin/su exists in container.
	 * Because in some rootfs, /bin/su is not exist,
	 * so we need to check it.
	 */
	char su_path[PATH_MAX] = { '\0' };
	sprintf(su_path, "%s/bin/su", container_dir);
	int fd = open(su_path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		return false;
	}
	struct stat su_stat;
	if (fstat(fd, &su_stat) != 0) {
		close(fd);
		return false;
	}
	if (!S_ISREG(su_stat.st_mode)) {
		close(fd);
		return false;
	}
	close(fd);
	return true;
}
static bool busybox_exists(char *_Nonnull container_dir)
{
	/*
	 * Check if busybox exists in container.
	 */
	char busybox_path[PATH_MAX] = { '\0' };
	sprintf(busybox_path, "%s/bin/busybox", container_dir);
	int fd = open(busybox_path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		return false;
	}
	struct stat busybox_stat;
	if (fstat(fd, &busybox_stat) != 0) {
		close(fd);
		return false;
	}
	if (!S_ISREG(busybox_stat.st_mode)) {
		close(fd);
		return false;
	}
	close(fd);
	return true;
}
static void check_binary(const struct RURI_CONTAINER *_Nonnull container)
{
	/*
	 * Check for binaries we need for starting the container.
	 */
	/*
	 * Since ruri use execvp() instead of execv(),
	 * we will not check for init binary here now.
	 * So, only check for qemu binary.
	 */
	// Check QEMU path.
	if (container->cross_arch != NULL) {
		if (container->qemu_path == NULL) {
			ruri_umount_container(container->container_dir);
			ruri_error("{red}Error: path of QEMU is not set QwQ\n");
		}
		// Check if QEMU binary exists and is not a directory.
		char qemu_binary[PATH_MAX];
		strcpy(qemu_binary, container->container_dir);
		strcat(qemu_binary, container->qemu_path);
		struct stat qemu_binary_stat;
		// lstat(3) will return -1 while the init_binary does not exist.
		if (lstat(qemu_binary, &qemu_binary_stat) != 0) {
			ruri_umount_container(container->container_dir);
			ruri_error("{red}Please check if path of QEMU is correct QwQ\n");
		}
	}
}
// Run after chroot(2), called by ruri_run_chroot_container().
static void init_container(struct RURI_CONTAINER *_Nonnull container)
{
	/*
	 * It'll be run after chroot(2), so `/` is the root dir of container now.
	 * The device list and permissions are based on common docker containers.
	 * If -A is not set, we will mask some dirs in /sys and /proc to avoid security issues.
	 */
	// If /proc/1 exists, that means container is already initialized.
	// I used to check /sys/class/input, but in WSL1, /sys/class/input is not exist.
	// But /proc/1 is exist in all Linux systems, because it's the init process.
	char *test = realpath("/proc/1", NULL);
	if (test == NULL) {
		// Mount proc,sys and dev.
		mkdir("/sys", S_IRUSR | S_IWUSR | S_IROTH | S_IWOTH | S_IRGRP | S_IWGRP);
		mkdir("/proc", S_IRUSR | S_IWUSR | S_IROTH | S_IWOTH | S_IRGRP | S_IWGRP);
		mkdir("/dev", S_IRUSR | S_IWUSR | S_IROTH | S_IWOTH | S_IRGRP | S_IWGRP);
		if (container->ro_root) {
			mount("proc", "/proc", "proc", MS_NOSUID | MS_NOEXEC | MS_NODEV | MS_RDONLY, NULL);
			mount("sysfs", "/sys", "sysfs", MS_NOSUID | MS_NOEXEC | MS_NODEV | MS_RDONLY, NULL);
		} else {
			mount("proc", "/proc", "proc", MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL);
			mount("sysfs", "/sys", "sysfs", MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL);
		}
		mount("tmpfs", "/dev", "tmpfs", MS_NOSUID, "size=65536k,mode=755");
		// Continue mounting some other directories in /dev.
		mkdir("/dev/pts", S_IRUSR | S_IWUSR | S_IROTH | S_IWOTH | S_IRGRP | S_IWGRP);
		mount("devpts", "/dev/pts", "devpts", MS_NODEV | MS_NOSUID | MS_NOEXEC, "gid=5,mode=620,ptmxmode=666");
		char *devshm_options = NULL;
		if (container->memory == NULL) {
			devshm_options = strdup("mode=1777");
		} else {
			devshm_options = malloc(strlen(container->memory) + strlen("mode=1777") + 114);
			sprintf(devshm_options, "size=65536k,mode=1777");
		}
		mkdir("/dev/shm", S_IRUSR | S_IWUSR | S_IROTH | S_IWOTH | S_IRGRP | S_IWGRP);
		mount("tmpfs", "/dev/shm", "tmpfs", MS_NOSUID | MS_NOEXEC | MS_NODEV, devshm_options);
		usleep(1000);
		free(devshm_options);
		// Mount binfmt_misc.
		mount("binfmt_misc", "/proc/sys/fs/binfmt_misc", "binfmt_misc", 0, NULL);
		// Create system runtime files in /dev and then fix permissions.
		mknod("/dev/null", S_IFCHR, makedev(1, 3));
		chmod("/dev/null", S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
		mknod("/dev/console", S_IFCHR, makedev(5, 1));
		chown("/dev/console", 0, 5);
		chmod("/dev/console", S_IRUSR | S_IWUSR | S_IWGRP | S_IWOTH);
		mknod("/dev/zero", S_IFCHR, makedev(1, 5));
		chmod("/dev/zero", S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
		mknod("/dev/ptmx", S_IFCHR, makedev(5, 2));
		chown("/dev/ptmx", 0, 5);
		chmod("/dev/ptmx", S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
		mknod("/dev/tty", S_IFCHR, makedev(5, 0));
		chown("/dev/tty", 0, 5);
		chmod("/dev/tty", S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
		mknod("/dev/random", S_IFCHR, makedev(1, 8));
		chmod("/dev/random", S_IRUSR | S_IRGRP | S_IROTH);
		mknod("/dev/urandom", S_IFCHR, makedev(1, 9));
		chmod("/dev/urandom", S_IRUSR | S_IRGRP | S_IROTH);
		mkdir("/dev/net", S_IRUSR | S_IWUSR | S_IROTH | S_IWOTH | S_IRGRP | S_IWGRP);
		mknod("/dev/net/tun", S_IFCHR, makedev(10, 200));
		if (container->use_kvm) {
			mknod("/dev/kvm", S_IFCHR, makedev(10, 232));
			chmod("/dev/kvm", S_IRUSR | S_IWUSR | S_IROTH | S_IWOTH | S_IRGRP | S_IWGRP);
		}
		// Create some system runtime link files in /dev.
		symlink("/proc/self/fd", "/dev/fd");
		symlink("/proc/self/fd/0", "/dev/stdin");
		symlink("/proc/self/fd/1", "/dev/stdout");
		symlink("/proc/self/fd/2", "/dev/stderr");
		symlink("/dev/null", "/dev/tty0");
		if (!container->unmask_dirs) {
			// Mask some directories/files that we don't want the container modify it.
			mount("tmpfs", "/proc/asound", "tmpfs", MS_RDONLY, NULL);
			mount("tmpfs", "/proc/acpi", "tmpfs", MS_RDONLY, NULL);
			mount("/dev/null", "/proc/kcore", "", MS_BIND, NULL);
			mount("/dev/null", "/proc/keys", "", MS_BIND, NULL);
			mount("/dev/null", "/proc/latency_stats", "", MS_BIND, NULL);
			mount("/dev/null", "/proc/timer_list", "", MS_BIND, NULL);
			mount("/dev/null", "/proc/timer_stats", "", MS_BIND, NULL);
			mount("/dev/null", "/proc/sched_debug", "", MS_BIND, NULL);
			mount("/dev/null", "/proc/sysrq-trigger", "", MS_BIND, NULL);
			mount("tmpfs", "/proc/scsi", "tmpfs", MS_RDONLY, NULL);
			mount("tmpfs", "/sys/firmware", "tmpfs", MS_RDONLY, NULL);
			mount("tmpfs", "/sys/devices/virtual/powercap", "tmpfs", MS_RDONLY, NULL);
			mount("tmpfs", "/sys/block", "tmpfs", MS_RDONLY, NULL);
			mount("tmpfs", "/sys/kernel/debug", "tmpfs", MS_RDONLY, NULL);
			mount("tmpfs", "/sys/module", "tmpfs", MS_RDONLY, NULL);
			mount("tmpfs", "/sys/class/net", "tmpfs", MS_RDONLY, NULL);
			mount("tmpfs", "/sys/fs/cgroup", "tmpfs", MS_RDONLY, NULL);
			// Protect some system runtime directories by mounting themselves as read-only.
			mount("/proc/bus", "/proc/bus", NULL, MS_BIND | MS_REC, NULL);
			mount("/proc/bus", "/proc/bus", NULL, MS_BIND | MS_RDONLY | MS_REMOUNT, NULL);
			mount("/proc/fs", "/proc/fs", NULL, MS_BIND | MS_REC, NULL);
			mount("/proc/fs", "/proc/fs", NULL, MS_BIND | MS_RDONLY | MS_REMOUNT, NULL);
			mount("/proc/irq", "/proc/irq", NULL, MS_BIND | MS_REC, NULL);
			mount("/proc/irq", "/proc/irq", NULL, MS_BIND | MS_RDONLY | MS_REMOUNT, NULL);
			mount("/proc/sys", "/proc/sys", NULL, MS_BIND | MS_REC, NULL);
			mount("/proc/sys", "/proc/sys", NULL, MS_BIND | MS_RDONLY | MS_REMOUNT, NULL);
			mount("/proc/sys-trigger", "/proc/sys-trigger", NULL, MS_BIND | MS_REC, NULL);
			mount("/proc/sys-trigger", "/proc/sys-trigger", NULL, MS_BIND | MS_RDONLY | MS_REMOUNT, NULL);
		}
		// Mask other user-specified path.
		for (int i = 0; i < RURI_MAX_MOUNTPOINTS; i++) {
			if (container->masked_path[i] == NULL) {
				break;
			}
			// try to mask with ro tmpfs.
			mount("tmpfs", container->masked_path[i], "tmpfs", MS_NOSUID | MS_NOEXEC | MS_NODEV | MS_RDONLY, NULL);
			// Try to mask with /dev/null.
			mount("/dev/null", container->masked_path[i], NULL, MS_BIND, NULL);
			mount("/dev/null", container->masked_path[i], NULL, MS_BIND | MS_REMOUNT | MS_RDONLY, NULL);
		}
	} else {
		free(test);
	}
}
static void mk_char_devs(struct RURI_CONTAINER *_Nonnull container)
{
	chdir("/dev");
	for (int i = 0; true; i += 3) {
		if (container->char_devs[i] == NULL) {
			break;
		}
		ruri_mkdirs(container->char_devs[i], 0666);
		rmdir(container->char_devs[i]);
		mknod(container->char_devs[i], S_IFCHR, makedev((unsigned int)atoi(container->char_devs[i + 1]), (unsigned int)atoi(container->char_devs[i + 2])));
		chmod(container->char_devs[i], S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
	}
	chdir("/");
	if (container->work_dir != NULL) {
		chdir(container->work_dir);
	}
}
// Run before chroot(2), so that init_container() will not take effect.
static void mount_host_runtime(const struct RURI_CONTAINER *_Nonnull container)
{
	/*
	 * It's unsafe to mount /dev, /proc and /sys from the host.
	 * But in some cases, we have to do this.
	 * This function will be called before chroot(2),
	 * so it's before init_container().
	 */
	char buf[PATH_MAX] = { '\0' };
	// Mount /dev.
	memset(buf, '\0', sizeof(buf));
	sprintf(buf, "%s/dev", container->container_dir);
	mount("/dev", buf, NULL, MS_BIND, NULL);
	// mount /proc.
	memset(buf, '\0', sizeof(buf));
	sprintf(buf, "%s/proc", container->container_dir);
	mount("/proc", buf, NULL, MS_BIND, NULL);
	// Mount /sys.
	memset(buf, '\0', sizeof(buf));
	sprintf(buf, "%s/sys", container->container_dir);
	mount("/sys", buf, NULL, MS_BIND, NULL);
	// Mount binfmt_misc.
	memset(buf, '\0', sizeof(buf));
	sprintf(buf, "%s/proc/sys/fs/binfmt_misc", container->container_dir);
	mount("binfmt_misc", buf, "binfmt_misc", 0, NULL);
	// Mount devpts.
	memset(buf, '\0', sizeof(buf));
	sprintf(buf, "%s/dev/pts", container->container_dir);
	mkdir(buf, S_IRUSR | S_IWUSR | S_IROTH | S_IWOTH | S_IRGRP | S_IWGRP);
	mount("/dev/pts", buf, "none", MS_BIND, NULL);
	// Mount devshm.
	char *devshm_options = NULL;
	if (container->memory == NULL) {
		devshm_options = strdup("mode=1777");
	} else {
		devshm_options = malloc(strlen(container->memory) + strlen("mode=1777") + 114);
		sprintf(devshm_options, "size=%s,mode=1777", container->memory);
	}
	memset(buf, '\0', sizeof(buf));
	sprintf(buf, "%s/dev/shm", container->container_dir);
	mkdir(buf, S_IRUSR | S_IWUSR | S_IROTH | S_IWOTH | S_IRGRP | S_IWGRP);
	mount("tmpfs", buf, "tmpfs", MS_NOSUID | MS_NOEXEC | MS_NODEV, devshm_options);
	usleep(1000);
	free(devshm_options);
}
// Drop capabilities.
// Use libcap.
static void drop_caps(const struct RURI_CONTAINER *_Nonnull container)
{
	/*
	 * Drop CapBnd and CapAmb as the config in container->drop_caplist[].
	 * And clear CapInh.
	 * It will be called after chroot(2).
	 */
#ifndef DISABLE_LIBCAP
	for (int i = 0; i < RURI_CAP_LAST_CAP + 1; i++) {
		// RURI_INIT_VALUE is the end of drop_caplist[].
		if (container->drop_caplist[i] == RURI_INIT_VALUE) {
			break;
		}
		// Check if the capability is supported in the kernel,
		// so that we can avoid unnecessary warnings.
		if (CAP_IS_SUPPORTED(container->drop_caplist[i])) {
			// Drop CapBnd.
			if (cap_drop_bound(container->drop_caplist[i]) != 0 && !container->no_warnings) {
				ruri_warning("{yellow}Warning: Failed to drop cap `%s`\n", cap_to_name(container->drop_caplist[i]));
				ruri_warning("{yellow}error reason: %s{clear}\n", strerror(errno));
			}
			// Drop CapAmb.
			prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_LOWER, container->drop_caplist[i], 0, 0);
		}
	}
	// Clear CapInh.
	// hrdp and datap are two pointers, so we malloc() to apply the memory for it first.
	cap_user_header_t hrdp = (cap_user_header_t)malloc(sizeof(*hrdp));
	cap_user_data_t datap = (cap_user_data_t)malloc(sizeof(*datap) * 10);
	hrdp->pid = getpid();
	hrdp->version = _LINUX_CAPABILITY_VERSION_3;
	capget(hrdp, datap);
	datap->inheritable = 0;
	capset(hrdp, datap);
	free(hrdp);
	free(datap);
#endif
}
// Set envs.
static void set_envs(const struct RURI_CONTAINER *_Nonnull container)
{
	/*
	 * Set environment variables.
	 * $PATH and $TMPDIR will also be set here.
	 * And $SHELL will be set to sh, for compatibility.
	 */
	// Set $PATH to the common value in GNU/Linux,
	// because $PATH in termux is not correct for common GNU/Linux containers.
	setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 1);
	// Set $TMPDIR.
	setenv("TMPDIR", "/tmp", 1);
	// Set $SHELL to sh.
	setenv("SHELL", "sh", 1);
	// Set $container to ruri.
	setenv("container", "ruri", 1);
	// Set other envs.
	for (int i = 0; true; i += 2) {
		if (container->env[i] == NULL || container->env[i + 1] == NULL) {
			break;
		}
		setenv(container->env[i], container->env[i + 1], 1);
	}
}
// Run after init_container().
static void setup_binfmt_misc(const struct RURI_CONTAINER *_Nonnull container)
{
	/*
	 * For running multi-arch container.
	 * It need the kernel support binfmt_misc.
	 */
	// Get elf magic header.
	struct RURI_ELF_MAGIC *magic = ruri_get_magic(container->cross_arch);
	// Umount container if we get an error.
	if (magic == NULL) {
		ruri_warning("{red}Error: unknown architecture or same architecture as host: %s\n\nSupported architectures: aarch64, alpha, arm, armeb, cris, hexagon, hppa, i386, loongarch64, m68k, microblaze, mips, mips64, mips64el, mipsel, mipsn32, mipsn32el, ppc, ppc64, ppc64le, riscv32, riscv64, s390x, sh4, sh4eb, sparc, sparc32plus, sparc64, x86_64, xtensa, xtensaeb{clear}\n", container->cross_arch);
		ruri_umount_container(container->container_dir);
		ruri_error(" ");
	}
	char buf[1024] = { '\0' };
	// Format: ":name:type:offset:magic:mask:interpreter:flags".
	sprintf(buf, ":%s%d:M:0:%s:%s:%s:PCF", "ruri-", container->container_id, magic->magic, magic->mask, container->qemu_path);
	// Just to make clang-tidy happy.
	free(magic);
	// This needs CONFIG_BINFMT_MISC enabled in your kernel.
	int register_fd = open("/proc/sys/fs/binfmt_misc/register", O_WRONLY | O_CLOEXEC);
	if (register_fd < 0) {
		ruri_error("{red}Error: Failed to setup binfmt_misc, check your kernel config QwQ");
	}
	// Set binfmt_misc config.
	write(register_fd, buf, strlen(buf));
	close(register_fd);
	// Umount the apifs.
	umount2("/proc/sys/fs/binfmt_misc", MNT_DETACH | MNT_FORCE);
}
static void mount_rootfs(const struct RURI_CONTAINER *_Nonnull container)
{
	/*
	 * Mount rootfs of container.
	 * It will be called before chroot(2).
	 * Rootfs (/) is the first mountpoint.
	 */
	// Mount rootfs.
	if (container->rootfs_source != NULL) {
		if (ruri_trymount(container->rootfs_source, container->container_dir, 0) != 0) {
			ruri_error("{red}Error: failed to mount rootfs QwQ\n");
		}
	}
}
// Mount other mountpoints.
// Run before chroot(2).
static void mount_mountpoints(const struct RURI_CONTAINER *_Nonnull container)
{
	/*
	 * Mount extra_mountpoint and extra_ro_mountpoint.
	 * It will be called before chroot(2).
	 */
	if (!container->rootless && (container->rootfs_source == NULL)) {
		// '/' should be a mountpoint in container.
		mount(container->container_dir, container->container_dir, NULL, MS_BIND | MS_REC, NULL);
	}
	char *mountpoint_dir = NULL;
	// Mount extra_mountpoint.
	for (int i = 0; true; i += 2) {
		if (container->extra_mountpoint[i] == NULL || container->extra_mountpoint[i + 1] == NULL) {
			break;
		}
		// Set the mountpoint to mount.
		mountpoint_dir = (char *)malloc(strlen(container->extra_mountpoint[i + 1]) + strlen(container->container_dir) + 2);
		strcpy(mountpoint_dir, container->container_dir);
		strcat(mountpoint_dir, container->extra_mountpoint[i + 1]);
		ruri_trymount(container->extra_mountpoint[i], mountpoint_dir, 0);
		free(mountpoint_dir);
	}
	// Mount extra_ro_mountpoint as read-only.
	for (int i = 0; true; i += 2) {
		if (container->extra_ro_mountpoint[i] == NULL || container->extra_ro_mountpoint[i + 1] == NULL) {
			break;
		}
		// Set the mountpoint to mount.
		mountpoint_dir = (char *)malloc(strlen(container->extra_ro_mountpoint[i + 1]) + strlen(container->container_dir) + 2);
		strcpy(mountpoint_dir, container->container_dir);
		strcat(mountpoint_dir, container->extra_ro_mountpoint[i + 1]);
		ruri_trymount(container->extra_ro_mountpoint[i], mountpoint_dir, MS_RDONLY);
		free(mountpoint_dir);
	}
	// If rootfs_source is not empty, we bind mount it now.
	if (container->rootfs_source != NULL) {
		mount(container->container_dir, container->container_dir, NULL, MS_BIND | MS_REC, NULL);
	}
}
// Copy qemu static binary.
static void copy_qemu_binary(struct RURI_CONTAINER *container)
{
	/*
	 * Copy qemu binary into container.
	 * ruri support to use qemu-path in host,
	 * but, to use qemu, we need to copy qemu binary into container.
	 */
	// If -q is not set, return.
	if (container->qemu_path == NULL) {
		return;
	}
	// Check if qemu binary is the path on the host.
	char *qemu_path = realpath(container->qemu_path, NULL);
	// Copy qemu binary into container.
	if (qemu_path != NULL) {
		char target[PATH_MAX] = { '\0' };
		sprintf(target, "%s/qemu-ruri", container->container_dir);
		unlink(target);
		remove(target);
		rmdir(target);
		int sourcefd = open(qemu_path, O_RDONLY | O_CLOEXEC);
		if (sourcefd < 0) {
			ruri_error("{red}Error: failed to open qemu binary QwQ\n");
		}
		int targetfd = open(target, O_WRONLY | O_CREAT | O_CLOEXEC, S_IRGRP | S_IXGRP | S_IWGRP | S_IWUSR | S_IRUSR | S_IXUSR | S_IWOTH | S_IXOTH | S_IROTH);
		if (targetfd < 0) {
			ruri_error("{red}Error: failed to create qemu binary in container QwQ\nIf your / is mounted read-only, please copy qemu to /path/to/container/qemu-ruri and use -q /qemu-ruri to start!\n");
		}
		struct stat stat_buf;
		fstat(sourcefd, &stat_buf);
		off_t offset = 0;
		// In linux, I think it's more safe to use sendfile(2) to copy files,
		// because it does not need a buffer.
		// !NOTE: Linux version under 2.6.33 does not support sendfile(2) for copying files.
		sendfile(targetfd, sourcefd, &offset, (size_t)stat_buf.st_size);
		close(targetfd);
		close(sourcefd);
		chmod(target, S_IRGRP | S_IXGRP | S_IRUSR | S_IXUSR | S_IROTH | S_IXOTH);
		free(qemu_path);
		// Correct the qemu-path.
		free(container->qemu_path);
		container->qemu_path = strdup("/qemu-ruri");
		usleep(2000);
	}
}
static bool pivot_root_succeed(const char *_Nonnull container_dir)
{
	/*
	 * Check if pivot_root(2) succeed.
	 */
	// Check if ${container_dir}/dev/null is a character device.
	struct stat dev_null_stat;
	char dev_null[PATH_MAX] = { '\0' };
	if (chdir(container_dir) != 0) {
		return true;
	}
	sprintf(dev_null, "%s/./dev/null", container_dir);
	if (stat(dev_null, &dev_null_stat) != 0) {
		return true;
	}
	if (S_ISCHR(dev_null_stat.st_mode)) {
		return false;
	}
	return true;
}
// Try to use pivot_root(2).
static int try_pivot_root(const struct RURI_CONTAINER *_Nonnull container)
{
	/*
	 * Try to use pivot_root(2) to change the root directory.
	 * If pivot_root(2) is not available, return -1.
	 */
	ruri_log("{base}ns pid: %d\n", container->ns_pid);
	if (container->ns_pid > 0 && pivot_root_succeed(container->container_dir)) {
		ruri_log("{base}Using setns(2) to change root directory.\n");
		chdir("/");
		return 0;
	}
	chdir(container->container_dir);
	mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL);
	usleep(2000);
	chdir(container->container_dir);
	if (syscall(SYS_pivot_root, ".", ".") == -1) {
		ruri_log("{base}pivot_root(2) failed, using chroot(2) instead.\n");
		if (!container->no_warnings) {
			ruri_warning("{yellow}Warning: pivot_root(2) failed, using chroot(2) instead QwQ\n");
		}
		return -1;
	}
	chdir("/");
	umount2(".", MNT_DETACH);
	ruri_log("{base}pivot_root(2) success.\n");
	return 0;
}
// Set uid and gid.
static void change_user(const struct RURI_CONTAINER *_Nonnull container)
{
	/*
	 * Change uid and gid.
	 * It will be called before exec(3).
	 */
	if (container->user != NULL) {
		if (atoi(container->user) > 0) {
			int groups_count = 0;
			gid_t *groups = malloc(NGROUPS_MAX * sizeof(gid_t));
			groups_count = ruri_get_groups((uid_t)atoi(container->user), groups);
			if (groups_count > 0) {
				setgroups((size_t)groups_count, groups);
			} else {
				groups[0] = (gid_t)atoi(container->user);
				setgroups(1, groups);
			}
			usleep(1000);
			free(groups);
			setgid((gid_t)atoi(container->user));
			setuid((uid_t)atoi(container->user));
		} else {
			if (!ruri_user_exist(container->user)) {
				ruri_error("{red}Error: user `%s` does not exist QwQ\n", container->user);
			} else {
				int groups_count = 0;
				gid_t *groups = malloc(NGROUPS_MAX * sizeof(gid_t));
				groups_count = ruri_get_groups(ruri_get_user_uid(container->user), groups);
				if (groups_count > 0) {
					setgroups((size_t)groups_count, groups);
				} else {
					groups[0] = ruri_get_user_uid(container->user);
					setgroups(1, groups);
				}
				usleep(1000);
				free(groups);
				setgid(ruri_get_user_gid(container->user));
				setuid(ruri_get_user_uid(container->user));
			}
		}
	}
}
static void set_hostname(struct RURI_CONTAINER *_Nonnull container)
{
	/*
	 * Set hostname.
	 * Only for unshare container,
	 * because hostname is a global setting in the system,
	 * and we do not want to change the hostname of the host.
	 */
	if (container->hostname != NULL) {
		if (container->enable_unshare) {
			size_t len = strlen(container->hostname);
			if (len > HOST_NAME_MAX) {
				ruri_error("{red}Error: hostname is too long QwQ\n");
			}
			syscall(SYS_sethostname, container->hostname, len);
		}
	}
}
static void hidepid(int stat)
{
	/*
	 * Hide pid option for mounting /proc.
	 */
	if (stat <= 0) {
		return;
	}
	usleep(1000);
	if (stat == 1) {
		mount("none", "/proc", "proc", MS_REMOUNT, "hidepid=1");
	} else if (stat == 2) {
		mount("none", "/proc", "proc", MS_REMOUNT, "hidepid=2");
	}
}
static void set_oom_score(int score)
{
	/*
	 * Set OOM score.
	 * It will be called after /proc is mounted.
	 * The score is between -1000 and 1000.
	 * If the score is 0, it will not be set.
	 * This feature need linux kernel 2.6.36 or later.
	 */
	if (score < -1000 || score > 1000) {
		ruri_error("{red}Error: OOM score must be between -1000 and 1000 QwQ\n");
	}
	if (score == 0) {
		return;
	}
	// Set OOM score.
	char buf[PATH_MAX] = { '\0' };
	sprintf(buf, "/proc/%d/oom_score_adj", getpid());
	int fd = open(buf, O_WRONLY | O_CLOEXEC);
	if (fd < 0) {
		ruri_error("{red}Error: failed to open /proc/%d/oom_score_adj QwQ\n", getpid());
	}
	char score_str[16] = { '\0' };
	sprintf(score_str, "%d", score);
	write(fd, score_str, strlen(score_str));
	close(fd);
}
// Run chroot container.
void ruri_run_chroot_container(struct RURI_CONTAINER *_Nonnull container)
{
	/*
	 * It's called by main() and ruri_run_unshare_container().
	 * It will run container as the config in CONTAINER struct.
	 */
	// Set hostname.
	set_hostname(container);
	// Ignore SIGTTIN, if we are running in the background, SIGTTIN may kill this process.
	if (!container->enable_tty_signals) {
		sigset_t sigs;
		sigemptyset(&sigs);
		sigaddset(&sigs, SIGTTIN);
		sigaddset(&sigs, SIGTTOU);
		sigprocmask(SIG_BLOCK, &sigs, 0);
	}
	// Check if system runtime files are already created.
	// container_dir should bind-mount before chroot(2),
	// mount_host_runtime() and ruri_store_info() will be called here.
	char buf[PATH_MAX] = { '\0' };
	// I used to check /sys/class/input, but in WSL1, /sys/class/input is not exist.
	sprintf(buf, "%s/proc/1", container->container_dir);
	char *test = realpath(buf, NULL);
	if (test == NULL) {
		// Mount mountpoints.
		mount_rootfs(container);
		mount_mountpoints(container);
		// Copy qemu binary into container.
		copy_qemu_binary(container);
		// Store container info.
		if (!container->enable_unshare && !container->just_chroot && container->use_rurienv) {
			ruri_store_info(container);
		}
		// If `-S` option is set, bind-mount /dev/, /sys/ and /proc/ from host.
		if (container->mount_host_runtime && !container->just_chroot) {
			mount_host_runtime(container);
		}
		// If `-R` option is set, make / read-only.
		if (container->ro_root) {
			mount(container->container_dir, container->container_dir, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY, NULL);
		}
	}
	// If container already mounted, sync the config.
	else {
		free(test);
		// Read container info.
		if (container->use_rurienv) {
			ruri_read_info(container, container->container_dir);
		}
	}
	// Set default command for exec().
	if (container->command[0] == NULL) {
		if (su_biany_exist(container->container_dir) && container->user == NULL) {
			container->command[0] = "/bin/su";
			container->command[1] = "-";
			container->command[2] = NULL;
		} else {
			container->command[0] = "/bin/sh";
			container->command[1] = NULL;
		}
	}
	// Check binary used.
	check_binary(container);
	// chroot(2) into container, or use pivot_root(2) if `-u` is set.
	if (!container->enable_unshare) {
		chdir(container->container_dir);
		chroot(".");
		chdir("/");
	} else {
		if (try_pivot_root(container) == -1) {
			chdir(container->container_dir);
			chroot(".");
			chdir("/");
		}
	}
	// Change to the work dir.
	if (container->work_dir != NULL) {
		if (chdir(container->work_dir) == -1 && !container->no_warnings) {
			ruri_warning("{yellow}Warning: Failed to change to work dir `%s`\n", container->work_dir);
		}
	}
	// Mount/create system runtime dir/files.
	if (!container->just_chroot) {
		init_container(container);
	}
	// Hide pid.
	hidepid(container->hidepid);
	// Fix /etc/mtab.
	if (!container->just_chroot) {
		remove("/etc/mtab");
		unlink("/etc/mtab");
		symlink("/proc/mounts", "/etc/mtab");
	}
	// Setup binfmt_misc.
	if (container->cross_arch != NULL) {
		setup_binfmt_misc(container);
	}
	// Umount binfmt_misc apifs.
	umount2("/proc/sys/fs/binfmt_misc", MNT_DETACH | MNT_FORCE);
	// Set up cgroup limit.
	if (!container->just_chroot) {
		ruri_set_limit(container);
	}
	// Create character devices.
	if (container->char_devs[0] != NULL) {
		mk_char_devs(container);
	}
	// Set OOM score.
	if (container->oom_score_adj != 0) {
		set_oom_score(container->oom_score_adj);
	}
	// Set up Seccomp BPF.
	if (container->enable_default_seccomp || container->seccomp_denied_syscall[0] != NULL) {
		ruri_setup_seccomp(container);
	}
	// Drop caps.
	drop_caps(container);
	// Set envs.
	set_envs(container);
	// Fix a bug that the terminal is frozen.
	usleep(2000);
	// Set NO_NEW_PRIVS Flag.
	// It requires Linux3.5 or later.
	// It will make sudo unavailable in container.
	if (container->no_new_privs) {
		prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	}
	// Disallow raising ambient capabilities via the prctl(2) PR_CAP_AMBIENT_RAISE operation.
	prctl(PR_SET_SECUREBITS, SECBIT_NO_CAP_AMBIENT_RAISE);
	// We only need 0(stdin), 1(stdout), 2(stderr),
	// So we close the other fds to avoid security issues.
	// NOTE: this might cause unknown issues.
	for (int i = 3; i <= 10; i++) {
		close(i);
	}
	// Fix console color.
	cprintf("{clear}");
	// Change uid and gid.
	change_user(container);
	// Execute command in container.
	// Use exec(3) function because system(3) may be unavailable now.
	if (execvp(container->command[0], container->command) == -1) {
		// Catch exceptions.
		ruri_error("{red}Failed to execute `%s`\nexecv() returned: %d\nerror reason: %s\nNote: unset $LD_PRELOAD before running ruri might fix this{clear}\n", container->command[0], errno, strerror(errno));
	}
}
// Run chroot container.
void ruri_run_rootless_chroot_container(struct RURI_CONTAINER *_Nonnull container)
{
	/*
	 * It's called by ruri_run_rootless_container().
	 * It will run container as the config in RURI_CONTAINER struct.
	 *
	 * This function is modified from ruri_run_chroot_container().
	 */
	// Ignore SIGTTIN, if we are running in the background, SIGTTIN may kill this process.
	if (!container->enable_tty_signals) {
		sigset_t sigs;
		sigemptyset(&sigs);
		sigaddset(&sigs, SIGTTIN);
		sigaddset(&sigs, SIGTTOU);
		sigprocmask(SIG_BLOCK, &sigs, 0);
	}
	// Mount mountpoints.
	mount_rootfs(container);
	mount_mountpoints(container);
	// Copy qemu binary into container.
	copy_qemu_binary(container);
	// If `-R` option is set, make / read-only.
	if (container->ro_root) {
		mount(container->container_dir, container->container_dir, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY, NULL);
	}
	// Set default command for exec().
	if (container->command[0] == NULL) {
		if (su_biany_exist(container->container_dir) && container->user == NULL) {
			container->command[0] = "/bin/su";
			container->command[1] = "-";
			container->command[2] = NULL;
		} else {
			if (busybox_exists(container->container_dir)) {
				container->command[0] = "/bin/busybox";
				container->command[1] = "sh";
				container->command[2] = NULL;
			} else {
				container->command[0] = "/bin/sh";
				container->command[1] = NULL;
			}
		}
	}
	// Check binary used.
	check_binary(container);
	// chroot(2) into container.
	chdir(container->container_dir);
	if (chroot(".") == -1) {
		ruri_error("{red}Error: failed to chroot(2) into container QwQ\n");
	}
	chdir("/");
	// Change to the work dir.
	if (container->work_dir != NULL) {
		if (chdir(container->work_dir) == -1 && !container->no_warnings) {
			ruri_warning("{yellow}Warning: Failed to change to work dir `%s`\n", container->work_dir);
		}
	}
	// Fix /etc/mtab.
	if (!container->just_chroot) {
		remove("/etc/mtab");
		unlink("/etc/mtab");
		symlink("/proc/mounts", "/etc/mtab");
	}
	// Hide pid.
	hidepid(container->hidepid);
	// Setup binfmt_misc.
	if (container->cross_arch != NULL) {
		setup_binfmt_misc(container);
	}
	// Setup oom_score_adj.
	if (container->oom_score_adj != 0) {
		set_oom_score(container->oom_score_adj);
	}
	// Set up Seccomp BPF.
	if (container->enable_default_seccomp || container->seccomp_denied_syscall[0] != NULL) {
		ruri_setup_seccomp(container);
	}
	// Drop caps.
	drop_caps(container);
	// Set envs.
	set_envs(container);
	// Fix a bug that the terminal is frozen.
	usleep(2000);
	// Set NO_NEW_PRIVS Flag.
	// It requires Linux3.5 or later.
	// It will make sudo unavailable in container.
	if (container->no_new_privs) {
		prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	}
	// Disallow raising ambient capabilities via the prctl(2) PR_CAP_AMBIENT_RAISE operation.
	prctl(PR_SET_SECUREBITS, SECBIT_NO_CAP_AMBIENT_RAISE);
	// We only need 0(stdin), 1(stdout), 2(stderr),
	// So we close the other fds to avoid security issues.
	for (int i = 3; i <= 10; i++) {
		close(i);
	}
	// Fix console color.
	cprintf("{clear}");
	// Change uid and gid.
	change_user(container);
	// Execute command in container.
	// Use exec(3) function because system(3) may be unavailable now.
	if (execvp(container->command[0], container->command) == -1) {
		// Catch exceptions.
		ruri_error("{red}Failed to execute `%s`\nexecv() returned: %d\nerror reason: %s\nNote: unset $LD_PRELOAD before running ruri might fix this{clear}\n", container->command[0], errno, strerror(errno));
	}
}
