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
 * This file provides rootless container support,
 * as ruri_run_rootless_chroot_container() needs some functions in chroot.c,
 * it's in chroot.c, not here.
 * This part need newuidmap and newgidmap binary,
 * that's the only runtime dependency for ruri, and it's optional.
 */
static int try_execvp(char *_Nonnull argv[])
{
	/*
	 * fork(2) and then execvp(3).
	 * Return the exit status of the child process.
	 */
	int pid = fork();
	if (pid == 0) {
		execvp(argv[0], argv);
		// If execvp(3) failed, exit as error status 114.
		exit(114);
	}
	int status = 0;
	waitpid(pid, &status, 0);
	return WEXITSTATUS(status);
}
static int try_setup_idmap(pid_t ppid, uid_t uid, gid_t gid)
{
	/*
	 * Try to use `uidmap` suid binary to setup uid and gid map.
	 * If this function failed, we will use set_id_map() to setup the id map.
	 */
	struct RURI_ID_MAP id_map = ruri_get_idmap(uid, gid);
	// Failed to get /etc/subuid or /etc/subgid config for current user.
	if (id_map.gid_lower == 0 || id_map.uid_lower == 0) {
		return -1;
	}
	char ppid_text[128] = { '\0' };
	char uid_text[128] = { '\0' };
	char uid_lower[128] = { '\0' };
	char uid_count[128] = { '\0' };
	char gid_text[128] = { '\0' };
	char gid_lower[128] = { '\0' };
	char gid_count[128] = { '\0' };
	snprintf(ppid_text, sizeof(ppid_text), "%d", ppid);
	snprintf(uid_text, sizeof(uid_text), "%d", id_map.uid);
	snprintf(uid_lower, sizeof(uid_lower), "%d", id_map.uid_lower);
	snprintf(uid_count, sizeof(uid_count), "%d", id_map.uid_count);
	snprintf(gid_text, sizeof(gid_text), "%d", id_map.gid);
	snprintf(gid_lower, sizeof(gid_lower), "%d", id_map.gid_lower);
	snprintf(gid_count, sizeof(gid_count), "%d", id_map.gid_count);
	// In fact I don't know how it works, but it works.
	// newuidmap pid 0 uid 1 1 uid_lower uid_count
	char *newuidmap[] = { "newuidmap", ppid_text, "0", uid_text, "1", "1", uid_lower, uid_count, NULL };
	if (try_execvp(newuidmap) != 0) {
		return -1;
	}
	// newgidmap pid 0 gid 1 1 gid_lower gid_count
	char *newgidmap[] = { "newgidmap", ppid_text, "0", gid_text, "1", "1", gid_lower, gid_count, NULL };
	if (try_execvp(newgidmap) != 0) {
		return -1;
	}
	return 0;
}
static void try_unshare(int flags)
{
	/*
	 * Try to use unshare(2),
	 * if failed, we just error() and exit.
	 */
	if (unshare(flags) == -1) {
		ruri_error("{red}Your device does not support some namespaces needed!\n");
	}
}
static void init_rootless_container(struct RURI_CONTAINER *_Nonnull container)
{
	/*
	 * For rootless container, the way to create/mount runtime dir/files is different.
	 * as we don't have the permission to mount sysfs and mknod(2),
	 * we need to bind-mount some dirs/files from host.
	 */
	mount(container->container_dir, container->container_dir, NULL, MS_BIND | MS_REC, NULL);
	chdir(container->container_dir);
	mkdir("./sys", S_IRUSR | S_IWUSR | S_IROTH | S_IWOTH | S_IRGRP | S_IWGRP);
	mount("/sys", "./sys", NULL, MS_BIND | MS_REC, NULL);
	mkdir("./proc", S_IRUSR | S_IWUSR | S_IROTH | S_IWOTH | S_IRGRP | S_IWGRP);
	mount("proc", "./proc", "proc", MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL);
	mkdir("./dev", S_IRUSR | S_IWUSR | S_IROTH | S_IWOTH | S_IRGRP | S_IWGRP);
	mount("tmpfs", "./dev", "tmpfs", MS_NOSUID, "size=65536k,mode=755");
	close(open("./dev/tty", O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, S_IRUSR | S_IWUSR | S_IROTH | S_IWOTH | S_IRGRP | S_IWGRP));
	mount("/dev/tty", "./dev/tty", NULL, MS_BIND, NULL);
	close(open("./dev/console", O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, S_IRUSR | S_IWUSR | S_IROTH | S_IWOTH | S_IRGRP | S_IWGRP));
	mount("/dev/console", "./dev/console", NULL, MS_BIND, NULL);
	close(open("./dev/null", O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, S_IRUSR | S_IWUSR | S_IROTH | S_IWOTH | S_IRGRP | S_IWGRP));
	mount("/dev/null", "./dev/null", NULL, MS_BIND, NULL);
	close(open("./dev/ptmx", O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, S_IRUSR | S_IWUSR | S_IROTH | S_IWOTH | S_IRGRP | S_IWGRP));
	mount("/dev/ptmx", "./dev/ptmx", NULL, MS_BIND, NULL);
	close(open("./dev/random", O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, S_IRUSR | S_IWUSR | S_IROTH | S_IWOTH | S_IRGRP | S_IWGRP));
	mount("/dev/random", "./dev/random", NULL, MS_BIND, NULL);
	close(open("./dev/urandom", O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, S_IRUSR | S_IWUSR | S_IROTH | S_IWOTH | S_IRGRP | S_IWGRP));
	mount("/dev/urandom", "./dev/urandom", NULL, MS_BIND, NULL);
	close(open("./dev/zero", O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, S_IRUSR | S_IWUSR | S_IROTH | S_IWOTH | S_IRGRP | S_IWGRP));
	mount("/dev/zero", "./dev/zero", NULL, MS_BIND, NULL);
	if (container->use_kvm) {
		close(open("./dev/kvm", O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, S_IRUSR | S_IWUSR | S_IROTH | S_IWOTH | S_IRGRP | S_IWGRP));
		mount("/dev/kvm", "./dev/kvm", NULL, MS_BIND, NULL);
	}
	symlink("/proc/self/fd", "./dev/fd");
	symlink("/proc/self/fd/0", "./dev/stdin");
	symlink("/proc/self/fd/1", "./dev/stdout");
	symlink("/proc/self/fd/2", "./dev/stderr");
	symlink("/dev/null", "./dev/tty0");
	mkdir("./dev/pts", S_IRUSR | S_IWUSR | S_IROTH | S_IWOTH | S_IRGRP | S_IWGRP);
	mount("devpts", "./dev/pts", "devpts", MS_NOSUID | MS_NOEXEC, "gid=5,mode=620,ptmxmode=666,max=1024");
	// Mount other char devices.
	if (container->char_devs[0] != NULL) {
		for (int i = 0; true; i += 3) {
			if (container->char_devs[i] == NULL) {
				break;
			}
			ruri_mkdirs(container->char_devs[i], 0666);
			rmdir(container->char_devs[i]);
			char host_dev[PATH_MAX] = { '\0' };
			sprintf(host_dev, "/dev/%s", container->char_devs[i]);
			char container_dev[PATH_MAX] = { '\0' };
			sprintf(container_dev, "./dev/%s", container->char_devs[i]);
			close(open(container_dev, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, S_IRUSR | S_IWUSR | S_IROTH | S_IWOTH | S_IRGRP | S_IWGRP));
			mount(host_dev, container_dev, NULL, MS_BIND, NULL);
		}
	}
	char *devshm_options = NULL;
	if (container->memory == NULL) {
		devshm_options = strdup("mode=1777");
	} else {
		devshm_options = malloc(strlen(container->memory) + strlen("mode=1777") + 114);
		sprintf(devshm_options, "size=65536k,mode=1777");
	}
	mkdir("./dev/shm", S_IRUSR | S_IWUSR | S_IROTH | S_IWOTH | S_IRGRP | S_IWGRP);
	mount("tmpfs", "./dev/shm", "tmpfs", MS_NOSUID | MS_NOEXEC | MS_NODEV, devshm_options);
	usleep(100000);
	free(devshm_options);
	mount("binfmt_misc", "./proc/sys/fs/binfmt_misc", "binfmt_misc", 0, NULL);
	if (!container->unmask_dirs) {
		// Protect some dirs in /proc and /sys.
		mount("./proc/bus", "./proc/bus", NULL, MS_BIND | MS_REC, NULL);
		mount("./proc/bus", "./proc/bus", NULL, MS_BIND | MS_RDONLY | MS_REMOUNT, NULL);
		mount("./proc/fs", "./proc/fs", NULL, MS_BIND | MS_REC, NULL);
		mount("./proc/fs", "./proc/fs", NULL, MS_BIND | MS_RDONLY | MS_REMOUNT, NULL);
		mount("./proc/irq", "./proc/irq", NULL, MS_BIND | MS_REC, NULL);
		mount("./proc/irq", "./proc/irq", NULL, MS_BIND | MS_RDONLY | MS_REMOUNT, NULL);
		mount("./proc/sys", "./proc/sys", NULL, MS_BIND | MS_REC, NULL);
		mount("./proc/sys", "./proc/sys", NULL, MS_BIND | MS_RDONLY | MS_REMOUNT, NULL);
		mount("./proc/sys-trigger", "./proc/sys-trigger", NULL, MS_BIND | MS_REC, NULL);
		mount("./proc/sys-trigger", "./proc/sys-trigger", NULL, MS_BIND | MS_RDONLY | MS_REMOUNT, NULL);
		mount("tmpfs", "./proc/asound", "tmpfs", MS_RDONLY, NULL);
		mount("tmpfs", "./proc/acpi", "tmpfs", MS_RDONLY, NULL);
		mount("/dev/null", "./proc/kcore", "", MS_BIND, NULL);
		mount("/dev/null", "./proc/keys", "", MS_BIND, NULL);
		mount("/dev/null", "./proc/latency_stats", "", MS_BIND, NULL);
		mount("/dev/null", "./proc/timer_list", "", MS_BIND, NULL);
		mount("/dev/null", "./proc/timer_stats", "", MS_BIND, NULL);
		mount("/dev/null", "./proc/sched_debug", "", MS_BIND, NULL);
		mount("/dev/null", "/proc/sysrq-trigger", "", MS_BIND, NULL);
		mount("tmpfs", "./proc/scsi", "tmpfs", MS_RDONLY, NULL);
		mount("tmpfs", "./sys/firmware", "tmpfs", MS_RDONLY, NULL);
		mount("tmpfs", "./sys/devices/virtual/powercap", "tmpfs", MS_RDONLY, NULL);
		mount("tmpfs", "./sys/block", "tmpfs", MS_RDONLY, NULL);
		mount("tmpfs", "/sys/kernel/debug", "tmpfs", MS_RDONLY, NULL);
		mount("tmpfs", "./sys/module", "tmpfs", MS_RDONLY, NULL);
		mount("tmpfs", "./sys/class/net", "tmpfs", MS_RDONLY, NULL);
		mount("tmpfs", "./sys/fs/cgroup", "tmpfs", MS_RDONLY, NULL);
	}
}
static void set_id_map(uid_t uid, gid_t gid)
{
	/*
	 * If try_setup_idmap() failed, this function will be called,
	 * to setup the uid and gid map.
	 * NOTE: command like `su` or `apt` will run failed if we use this function.
	 */
	// Set uid map.
	char uid_map[32] = { "\0" };
	sprintf(uid_map, "0 %d 1\n", uid);
	int uidmap_fd = open("/proc/self/uid_map", O_RDWR | O_CLOEXEC);
	if (uidmap_fd < 0) {
		ruri_warning("{red}Failed to open /proc/self/uid_map, maybe you need to install uidmap package and configure /etc/subuid and /etc/subgid?\n");
		ruri_error("{red}Failed to open /proc/self/uid_map\n");
	}
	write(uidmap_fd, uid_map, strlen(uid_map));
	close(uidmap_fd);
	// Set gid map.
	int setgroups_fd = open("/proc/self/setgroups", O_RDWR | O_CLOEXEC);
	if (setgroups_fd < 0) {
		ruri_warning("{red}Failed to open /proc/self/setgroups, maybe you need to install uidmap package and configure /etc/subuid and /etc/subgid?\n");
		ruri_error("{red}Failed to open /proc/self/setgroups\n");
	}
	write(setgroups_fd, "deny", 5);
	close(setgroups_fd);
	char gid_map[32] = { "\0" };
	sprintf(gid_map, "0 %d 1\n", gid);
	int gidmap_fd = open("/proc/self/gid_map", O_RDWR | O_CLOEXEC);
	if (gidmap_fd < 0) {
		ruri_warning("{red}Failed to open /proc/self/gid_map, maybe you need to install uidmap package and configure /etc/subuid and /etc/subgid?\n");
		ruri_error("{red}Failed to open /proc/self/gid_map\n");
	}
	write(gidmap_fd, gid_map, strlen(gid_map));
	close(gidmap_fd);
	// Maybe needless.
	setuid(0);
	setgid(0);
	setgroups_fd = open("/proc/self/setgroups", O_RDWR | O_CLOEXEC);
	write(setgroups_fd, "allow", 5);
	close(setgroups_fd);
}
void ruri_run_rootless_container(struct RURI_CONTAINER *_Nonnull container)
{
	/*
	 * Setup namespaces and run rootless container.
	 */
	if (container->use_rurienv) {
		ruri_read_info(container, container->container_dir);
	}
	bool container_initlized = false;
	if (container->ns_pid > 0) {
		container_initlized = true;
	}
	uid_t uid = geteuid();
	gid_t gid = getegid();
	bool set_id_map_succeed = false;
	pid_t ppid = getpid();
	// We fork() a new child process, and then,
	// parent process will call unshare(2) to be the owner of a new user ns,
	// then, we can use the child process to call `newuidmap` and `newgidmap`,
	// to change the parent process's id map.
	pid_t pid_1 = fork();
	if (pid_1 > 0) {
		if (container->ns_pid < 0) {
			// Enable user namespace.
			try_unshare(CLONE_NEWUSER);
			int stat = 0;
			waitpid(pid_1, &stat, 0);
			if (WEXITSTATUS(stat) == 0) {
				set_id_map_succeed = true;
			}
		} else {
			char user_ns[PATH_MAX] = { '\0' };
			sprintf(user_ns, "/proc/%d/ns/user", container->ns_pid);
			int user_ns_fd = open(user_ns, O_RDONLY | O_CLOEXEC);
			if (user_ns_fd < 0) {
				ruri_error("{red}Failed to open %s\n", user_ns);
			}
			if (setns(user_ns_fd, CLONE_NEWUSER) == -1) {
				ruri_error("{red}Failed to setns(2) to %s\n", user_ns);
			}
			set_id_map_succeed = true;
		}
	} else {
		if (container->ns_pid < 0) {
			// To ensure that unshare(2) finished in parent process.
			usleep(1000);
			int stat = try_setup_idmap(ppid, uid, gid);
			exit(stat);
		} else {
			exit(0);
		}
	}
	if (container->ns_pid > 0 && set_id_map_succeed) {
		char mnt_ns[PATH_MAX] = { '\0' };
		sprintf(mnt_ns, "/proc/%d/ns/mnt", container->ns_pid);
		int mnt_ns_fd = open(mnt_ns, O_RDONLY | O_CLOEXEC);
		if (mnt_ns_fd < 0) {
			ruri_error("{red}Failed to open %s\n", mnt_ns);
		}
		if (setns(mnt_ns_fd, CLONE_NEWNS) == -1) {
			ruri_error("{red}Failed to setns(2) to %s\n", mnt_ns);
		}
		close(mnt_ns_fd);
		char pid_ns[PATH_MAX] = { '\0' };
		sprintf(pid_ns, "/proc/%d/ns/pid", container->ns_pid);
		int pid_ns_fd = open(pid_ns, O_RDONLY | O_CLOEXEC);
		if (pid_ns_fd < 0) {
			ruri_error("{red}Failed to open %s\n", pid_ns);
		}
		if (setns(pid_ns_fd, CLONE_NEWPID) == -1) {
			ruri_error("{red}Failed to setns(2) to %s\n", pid_ns);
		}
		close(pid_ns_fd);
		char uts_ns[PATH_MAX] = { '\0' };
		sprintf(uts_ns, "/proc/%d/ns/uts", container->ns_pid);
		int uts_ns_fd = open(uts_ns, O_RDONLY | O_CLOEXEC);
		if (uts_ns_fd < 0 && !container->no_warnings) {
			ruri_warning("{yellow}Warning: seems that uts namespace is not supported on this device QwQ{clear}\n");
		} else {
			if (setns(uts_ns_fd, CLONE_NEWUTS) == -1) {
				ruri_error("{red}Failed to setns(2) to %s\n", uts_ns);
			}
		}
		close(uts_ns_fd);
		char ipc_ns[PATH_MAX] = { '\0' };
		sprintf(ipc_ns, "/proc/%d/ns/ipc", container->ns_pid);
		int ipc_ns_fd = open(ipc_ns, O_RDONLY | O_CLOEXEC);
		if (ipc_ns_fd < 0 && !container->no_warnings) {
			ruri_warning("{yellow}Warning: seems that ipc namespace is not supported on this device QwQ{clear}\n");
		} else {
			if (setns(ipc_ns_fd, CLONE_NEWIPC) == -1) {
				ruri_error("{red}Failed to setns(2) to %s\n", ipc_ns);
			}
		}
		close(ipc_ns_fd);
		char cgroup_ns[PATH_MAX] = { '\0' };
		sprintf(cgroup_ns, "/proc/%d/ns/cgroup", container->ns_pid);
		int cgroup_ns_fd = open(cgroup_ns, O_RDONLY | O_CLOEXEC);
		if (cgroup_ns_fd < 0 && !container->no_warnings) {
			ruri_warning("{yellow}Warning: seems that cgroup namespace is not supported on this device QwQ{clear}\n");
		} else {
			if (setns(cgroup_ns_fd, CLONE_NEWCGROUP) == -1) {
				ruri_error("{red}Failed to setns(2) to %s\n", cgroup_ns);
			}
		}
		close(cgroup_ns_fd);
		char time_ns[PATH_MAX] = { '\0' };
		sprintf(time_ns, "/proc/%d/ns/time", container->ns_pid);
		int time_ns_fd = open(time_ns, O_RDONLY | O_CLOEXEC);
		if (time_ns_fd < 0 && !container->no_warnings) {
			ruri_warning("{yellow}Warning: seems that time namespace is not supported on this device QwQ{clear}\n");
		} else {
			if (setns(time_ns_fd, CLONE_NEWTIME) == -1) {
				ruri_error("{red}Failed to setns(2) to %s\n", time_ns);
			}
		}
		close(time_ns_fd);
		// Join net ns.
		// This action will be forced, and will not error.
		char net_ns_file[PATH_MAX] = { '\0' };
		sprintf(net_ns_file, "%s%d%s", "/proc/", container->ns_pid, "/ns/net");
		int net_ns_fd = open(net_ns_file, O_RDONLY | O_CLOEXEC);
		setns(net_ns_fd, CLONE_NEWNET);
	} else {
		// We need to own mount namespace.
		try_unshare(CLONE_NEWNS);
		// Seems we need to own a new pid namespace for mount procfs.
		try_unshare(CLONE_NEWPID);
		if (unshare(CLONE_NEWUTS) == -1 && !container->no_warnings) {
			ruri_warning("{yellow}Warning: seems that uts namespace is not supported on this device QwQ{clear}\n");
		}
		if (unshare(CLONE_NEWIPC) == -1 && !container->no_warnings) {
			ruri_warning("{yellow}Warning: seems that ipc namespace is not supported on this device QwQ{clear}\n");
		}
		if (unshare(CLONE_NEWCGROUP) == -1 && !container->no_warnings) {
			ruri_warning("{yellow}Warning: seems that cgroup namespace is not supported on this device QwQ{clear}\n");
		}
		if (unshare(CLONE_NEWTIME) == -1) {
			if (container->timens_realtime_offset != 0 || container->timens_monotonic_offset != 0) {
				ruri_error("{red}Failed to unshare time namespace QwQ\n");
			}
			if (container->no_warnings) {
				ruri_warning("{yellow}Warning: seems that time namespace is not supported on this device QwQ{clear}\n");
			}
		}
		if (container->timens_monotonic_offset != 0) {
			usleep(1000);
			int fd = open("/proc/self/timens_offsets", O_WRONLY | O_CLOEXEC);
			char buf[1024] = { '\0' };
			sprintf(buf, _Generic((time_t)0, long: "monotonic %ld 0", long long: "monotonic %lld 0", default: "monotonic %ld 0"), container->timens_monotonic_offset);
			write(fd, buf, strlen(buf));
			close(fd);
		}
		if (container->timens_realtime_offset != 0) {
			int fd = open("/proc/self/timens_offsets", O_WRONLY | O_CLOEXEC);
			char buf[1024] = { '\0' };
			sprintf(buf, _Generic((time_t)0, long: "boottime %ld 0", long long: "boottime %lld 0", default: "boottime %ld 0"), container->timens_realtime_offset);
			write(fd, buf, strlen(buf));
			close(fd);
		}
		if (unshare(CLONE_SYSVSEM) == -1 && !container->no_warnings) {
			ruri_warning("{yellow}Warning: seems that semaphore namespace is not supported on this device QwQ{clear}\n");
		}
		if (unshare(CLONE_FILES) == -1 && !container->no_warnings) {
			ruri_warning("{yellow}Warning: seems that we could not unshare file descriptors with child process QwQ{clear}\n");
		}
		if (unshare(CLONE_FS) == -1 && !container->no_warnings) {
			ruri_warning("{yellow}Warning: seems that we could not unshare filesystem information with child process QwQ{clear}\n");
		}
		if (container->no_network) {
			if (unshare(CLONE_NEWNET) == -1) {
				ruri_error("{red}--no-network detected, but failed to unshare network namespace QwQ\n");
			}
		}
	}
	// fork(2) into new namespaces we created.
	pid_t pid = fork();
	if (pid > 0) {
		if (!set_id_map_succeed && !container->no_warnings) {
			ruri_warning("{yellow}Check if uidmap is installed and /etc/subuid and /etc/subgid are configured on your host, command like su will run failed without uidmap.\n");
			set_id_map(uid, gid);
		}
		usleep(1000);
		container->ns_pid = pid;
		if (container->use_rurienv && !container_initlized && !container->just_chroot) {
			ruri_store_info(container);
		} else {
			if (!container->no_warnings && !container_initlized) {
				ruri_warning("{base}NS PID:{green} %d\n", container->ns_pid);
			}
		}
		// Wait for child process to exit.
		int stat = 0;
		waitpid(pid, &stat, 0);
		exit(stat);
	} else if (pid < 0) {
		ruri_error("{red}Fork error QwQ?\n");
	} else {
		// Init rootless container.
		if (!container->just_chroot) {
			init_rootless_container(container);
		}
		usleep(1000);
		ruri_run_rootless_chroot_container(container);
	}
}
