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
 *
 */
// Enable Linux features.
#ifndef __linux__
#error "This program is only for linux."
#else
#define _GNU_SOURCE
#endif
// For core-only build, disable libcap and libseccomp, and do not read .rurienv file.
#ifdef RURI_CORE_ONLY
#ifndef DISABLE_LIBSECCOMP
#define DISABLE_LIBSECCOMP
#endif
#ifndef DISABLE_LIBCAP
#define DISABLE_LIBCAP
#endif
#ifndef DISABLE_RURIENV
#define DISABLE_RURIENV
#endif
#endif
// Just common headers.
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <linux/fs.h>
#include <linux/limits.h>
#include <linux/loop.h>
#include <linux/sched.h>
#include <linux/securebits.h>
#include <linux/version.h>
#include <linux/magic.h>
#include <sys/personality.h>
#include <sys/statfs.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <linux/futex.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <mntent.h>
#include <linux/io_uring.h>
#include <linux/netlink.h>
#include <linux/net.h>
#ifndef DISABLE_LIBSECCOMP
// This program need to be linked with `-lseccomp`.
#include <seccomp.h>
#endif
#ifndef DISABLE_LIBCAP
// This program need to be linked with `-lcap`.
#include <sys/capability.h>
#else
typedef int cap_value_t;
#endif
// We define RURI_CAP_LAST_CAP to 114,
// because for kernel in the future, there may be more capabilities than today.
#define RURI_CAP_LAST_CAP 114
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
#warning "This program has not been tested on Linux 3.x or earlier."
#endif
// For initializing some variables.
#define RURI_INIT_VALUE (-114)
// Limitations.
#define RURI_MAX_COMMANDS (1024)
#define RURI_MAX_ENVS (512 * 2)
#define RURI_MAX_MOUNTPOINTS (512 * 2)
#define RURI_MAX_CHAR_DEVS (128 * 3)
#define RURI_MAX_SECCOMP_DENIED_SYSCALL (2048)
// Force use glibc definition, as this value is too small in musl.
#undef NGROUPS_MAX
#define NGROUPS_MAX 65536
// Include other headers.
#include "cprintf.h"
#include "k2v.h"
#include "k2v3.h"
#include "version.h"
#include "compat.h"
#include "hostarch.h"
// Info of a container to create.
struct RURI_CONTAINER {
	// Container directory.
	char *_Nonnull container_dir;
	// Capabilities to drop.
	cap_value_t drop_caplist[RURI_CAP_LAST_CAP + 1];
	// Command for exec(2).
	char *_Nonnull command[RURI_MAX_COMMANDS + 1];
	// Extra mountpoints.
	char *_Nonnull extra_mountpoint[RURI_MAX_MOUNTPOINTS + 2];
	// Extra read-only mountpoints.
	char *_Nonnull extra_ro_mountpoint[RURI_MAX_MOUNTPOINTS + 2];
	// Environment variables.
	char *_Nonnull env[RURI_MAX_ENVS + 2];
	// Set NO_NEW_PRIV bit.
	bool no_new_privs;
	// Enable built-in seccomp profile.
	bool enable_default_seccomp;
	bool enable_seccomp_whitelist;
	// Unshare container.
	bool enable_unshare;
	// Useless rootless container support.
	bool rootless;
	// Mount host runtime.
	bool mount_host_runtime;
	// Container pid for setns(2).
	pid_t ns_pid;
	// Arch of multi-architecture container.
	char *_Nullable cross_arch;
	// Path of QEMU binary.
	char *_Nullable qemu_path;
	// Do not store .rurienv file.
	bool use_rurienv;
	// Mount / as read-only.
	bool ro_root;
	// Cpuset.
	char *_Nullable cpuset;
	// Memory.
	char *_Nullable memory;
	// Cpulimit.
	int cpupercent;
	// Max PIDs.
	int max_pids;
	// I/O read bandwidth limit (bytes per second).
	char *_Nullable io_rbps;
	// I/O write bandwidth limit (bytes per second).
	char *_Nullable io_wbps;
	// Block device for I/O limit (e.g., "8:0" for /dev/sda).
	char *_Nullable io_device;
	// A number based on the time when creating container.
	int container_id;
	// Do not create runtime directory.
	bool just_chroot;
	// Work directory.
	char *_Nullable work_dir;
	// Rootfs of container will be mount first.
	char *_Nullable rootfs_source;
	// Unmask dirs in /proc and /sys.
	bool unmask_dirs;
	// User.
	char *_Nullable user;
	// Hostname.
	char *_Nullable hostname;
	// No network.
	bool no_network;
	// Use kvm.
	bool use_kvm;
	// Char devices.
	char *_Nonnull char_devs[RURI_MAX_CHAR_DEVS];
	// Hidepid for procfs.
	int hidepid;
	// Timens offset.
	time_t timens_realtime_offset;
	time_t timens_monotonic_offset;
	// Denied syscalls.
	char *_Nonnull seccomp_denied_syscall[RURI_MAX_SECCOMP_DENIED_SYSCALL];
	// OOM score.
	int oom_score_adj;
	// Masked path.
	char *_Nonnull masked_path[RURI_MAX_MOUNTPOINTS + 2];
	// Enable tty signals
	bool enable_tty_signals;
	// Skip setting groups for user
	bool skip_setgroups;
	// First init.
	bool first_init;
	// pid file.
	char *_Nullable pid_file;
	// Is health check process.
	bool is_health_check;
	// Timeout for watchdog killer.
	float timeout;
};
// Warnings.
#define ruri_warning(format, ...)                                                                  \
	do {                                                                                       \
		cfprintf(stderr, "{yellow}in %s() at %s line %d: ", __func__, __FILE__, __LINE__); \
		cfprintf(stderr, format, ##__VA_ARGS__);                                           \
	} while (0)
// Show error msg and exit.
#define ruri_error(format, ...)                                                                                                                      \
	do {                                                                                                                                         \
		ruri_pid_file_write(RURI_PID_FILE_PANIC_INTERNAL, 0);                                                                                \
		cfprintf(stderr, "{red}in %s() at %s line %d:\n", __func__, __FILE__, __LINE__);                                                     \
		cfprintf(stderr, format, ##__VA_ARGS__);                                                                                             \
		cfprintf(stderr, "{base}%s{clear}\n", "\n  .^.   .^.");                                                                              \
		cfprintf(stderr, "{base}%s{clear}\n", "  /⋀\\_ﾉ_/⋀\\");                                                                              \
		cfprintf(stderr, "{base}%s{clear}\n", " /ﾉｿﾉ\\ﾉｿ丶メ");                                                                              \
		cfprintf(stderr, "{base}%s{clear}\n", " ﾙﾘﾘ >  x )ﾘ");                                                                               \
		cfprintf(stderr, "{base}%s{clear}\n", "ﾉノ㇏  ^  ﾉﾉ");                                                                               \
		cfprintf(stderr, "{base}%s{clear}\n", "      ⠁⠁");                                                                                   \
		cfprintf(stderr, "{base}%s{clear}\n", "RURI ERROR MESSAGE");                                                                         \
		cfprintf(stderr, "{base}PROCESS: %s\n", ruri_get_proc_type());                                                                       \
		cfprintf(stderr, "{base}%s{clear}\n", "Note: for some configs, you might need to run `-U` to umount container before changing it."); \
		cfprintf(stderr, "{base}%s{clear}\n", "If you think something is wrong, please report at:");                                         \
		cfprintf(stderr, "\033[4m{base}%s{clear}\n", "https://github.com/rurioss/ruri/issues");                                              \
		exit(114);                                                                                                                           \
	} while (0)
#define ruri_panic_on_error(ret__, expect__, format__, ...)  \
	do {                                                 \
		if (ret__ != expect__) {                     \
			ruri_error(format__, ##__VA_ARGS__); \
		}                                            \
	} while (0)
#define ruri_warn_on_error(ret__, expect__, show__, format__, ...)                         \
	do {                                                                               \
		if (ret__ != expect__) {                                                   \
			if (ruri_flag("force_panic")) {                                    \
				ruri_warning(format__, ##__VA_ARGS__);                     \
				ruri_error("{red}Force panic is enabled, exiting now.\n"); \
			} else {                                                           \
				if (show__) {                                              \
					ruri_warning(format__, ##__VA_ARGS__);             \
				}                                                          \
			}                                                                  \
		}                                                                          \
	} while (0)
// Log system.
#if defined(RURI_DEBUG)
#define ruri_log(format, ...)                                                                                                                               \
	do {                                                                                                                                                \
		struct timeval tv;                                                                                                                          \
		gettimeofday(&tv, NULL);                                                                                                                    \
		cfprintf(stderr, "{green}[%ld.%06ld] from pid %d in %s() at %s line %d:\n", tv.tv_sec, tv.tv_usec, getpid(), __func__, __FILE__, __LINE__); \
		cfprintf(stderr, format, ##__VA_ARGS__);                                                                                                    \
	} while (0)
#else
#define ruri_log(format, ...)
#endif
// Profiling log system.
#if defined(RURI_PROFILING)
#define ruri_profile_log(format, ...)                                                              \
	do {                                                                                       \
		cfprintf(stderr, "{green}In %s() at %s line %d:\n", __func__, __FILE__, __LINE__); \
		fprintf(stderr, format, ##__VA_ARGS__);                                            \
	} while (0)
#else
#define ruri_profile_log(format, ...)
#endif
extern int RURI_PWD_ERRNO;
enum RURI_PROC_TYPE {
	RURI_QUERY,
	RURI_UNSHARE,
	RURI_CHROOT,
	RURI_ROOTLESS,
	RURI_DAEMON,
	RURI_UMOUNT,
};
enum RURI_PID_FILE_REQ {
	RURI_PID_FILE_INIT,
	RURI_PID_FILE_PID,
	RURI_PID_FILE_PANIC_EXEC,
	RURI_PID_FILE_PANIC_INTERNAL,
	RURI_PID_FILE_PANIC_TIMEOUT,
	RURI_PID_FILE_EXITED,
	RURI_PID_FILE_SIGNALED,
	RURI_PID_FILE_UNKNOWN,
};
// For ruri_get_idmap().
struct RURI_ID_MAP {
	uid_t uid;
	uid_t uid_lower;
	uid_t uid_count;
	gid_t gid;
	gid_t gid_lower;
	gid_t gid_count;
};
// For ruri_get_magic().
#define ruri_magicof(x) (x##_magic)
#define ruri_maskof(x) (x##_mask)
struct RURI_ELF_MAGIC {
	char *_Nonnull magic;
	char *_Nonnull mask;
};
int ruri_pid_file_fd(int req);
void ruri_pid_file_write(enum RURI_PID_FILE_REQ req, long long arg);
char *ruri_get_proc_type(void);
void ruri_register_signal(void);
void ruri_setup_seccomp(const struct RURI_CONTAINER *_Nonnull container);
void ruri_show_version_info(void);
void ruri_show_version_code(void);
void ruri_AwA(void);
void ruri_show_helps(void);
void ruri_show_examples(void);
void ruri_store_info(const struct RURI_CONTAINER *_Nonnull container);
struct RURI_CONTAINER *ruri_read_info(struct RURI_CONTAINER *_Nullable container, const char *_Nonnull container_dir);
void ruri_add_to_caplist(cap_value_t *_Nonnull list, cap_value_t cap);
bool ruri_is_in_caplist(const cap_value_t *_Nonnull list, cap_value_t cap);
void ruri_del_from_caplist(cap_value_t *_Nonnull list, cap_value_t cap);
void ruri_build_caplist(cap_value_t caplist[], bool privileged, cap_value_t drop_caplist_extra[], cap_value_t keep_caplist_extra[]);
struct RURI_ELF_MAGIC *ruri_get_magic(const char *_Nonnull cross_arch);
void ruri_run_unshare_container(struct RURI_CONTAINER *_Nonnull container);
char *ruri_container_info_to_k2v(const struct RURI_CONTAINER *_Nonnull container);
void ruri_run_chroot_container(struct RURI_CONTAINER *_Nonnull container);
void ruri_run_rootless_container(struct RURI_CONTAINER *_Nonnull container);
void ruri_run_rootless_chroot_container(struct RURI_CONTAINER *_Nonnull container);
int ruri_trymount(const char *_Nonnull source, const char *_Nonnull target, unsigned int mountflags);
void ruri_umount_container(const char *_Nonnull container_dir);
void ruri_read_config(struct RURI_CONTAINER *_Nonnull container, const char *_Nonnull path);
void ruri_set_limit(const struct RURI_CONTAINER *_Nonnull container);
struct RURI_ID_MAP ruri_get_idmap(uid_t uid, gid_t gid);
void ruri_container_ps(char *_Nonnull container_dir);
void ruri_kill_container(struct RURI_CONTAINER *_Nonnull container);
bool ruri_user_exist(const char *_Nonnull username);
uid_t ruri_get_user_uid(const char *_Nonnull username);
gid_t ruri_get_user_gid(const char *_Nonnull username);
pid_t ruri_get_ns_pid(const char *_Nonnull container_dir);
void ruri_fetch(void);
void ruri_correct_config(const char *_Nonnull path);
int ruri(int argc, char **argv);
void ruri_init_config(struct RURI_CONTAINER *_Nonnull container);
int ruri_mkdirs(const char *_Nonnull dir, mode_t mode);
int ruri_get_groups(uid_t uid, gid_t groups[]);
int ruri_try_cgroup_kill(const struct RURI_CONTAINER *_Nonnull container);
#ifndef DISABLE_LIBCAP
int ruri_cap_from_name(const char *str, cap_value_t *cap);
#endif
void ruri_clear_env(char *const *_Nonnull argv);
bool ruri_pid_in_cgroup(pid_t pid, int container_id);
long long ruri_diff_time(void);
enum RURI_PROC_TYPE ruri_proc_mark(enum RURI_PROC_TYPE mark);
void ruri_stat(const char *pid_file);
void ruri_setup_timeout_watchdog(const struct RURI_CONTAINER *_Nonnull container);
int ruri_setup_pid_file_daemon(struct RURI_CONTAINER *_Nonnull container);
void ruri_fork_as_init(void);
void ruri_check_container_dir(char *dir);
char *ruri_feature_flag(int req, char *_Nonnull flag);
bool ruri_flag(char *_Nonnull flag);
void ruri_convert_mountpoints_to_absolute(struct RURI_CONTAINER *container);
void ruri_convert_rootfs_source_to_absolute(struct RURI_CONTAINER *container);
//   ██╗ ██╗  ███████╗   ████╗   ███████╗
//  ████████╗ ██╔════╝ ██╔═══██╗ ██╔════╝
//  ╚██╔═██╔╝ █████╗   ██║   ██║ █████╗
//  ████████╗ ██╔══╝   ██║   ██║ ██╔══╝
//  ╚██╔═██╔╝ ███████╗ ╚██████╔╝ ██║
//   ╚═╝ ╚═╝  ╚══════╝  ╚═════╝  ╚═╝
