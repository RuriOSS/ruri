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
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <linux/sched.h>
#include <linux/securebits.h>
#include <linux/version.h>
#include <linux/loop.h>
#include <sys/mount.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/sendfile.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <grp.h>
#include <sys/mman.h>
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
// Fix definition of HOST_NAME_MAX
#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 64
#endif
// Fix definition of LOGIN_NAME_MAX
#ifndef LOGIN_NAME_MAX
#define LOGIN_NAME_MAX 256
#endif
// Nullability attributes.
#ifndef _Nullable
#define _Nullable
#endif
#ifndef _Nonnull
#define _Nonnull
#endif
// We define RURI_CAP_LAST_CAP to 114,
// because for kernel in the fulture, there may be more capabilities than today.
#define RURI_CAP_LAST_CAP 114
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
#warning "This program has not been tested on Linux 3.x or earlier."
#endif
// Bool!!!
#if __STDC_VERSION__ < 202000L
#ifndef bool
#define bool _Bool
#define true ((_Bool) + 1u)
#define false ((_Bool) + 0u)
#endif
#endif
// For initializing some variables.
#define RURI_INIT_VALUE (-114)
// Limitations.
#define RURI_MAX_COMMANDS (1024)
#define RURI_MAX_ENVS (512 * 2)
#define RURI_MAX_MOUNTPOINTS (512 * 2)
#define RURI_MAX_CHAR_DEVS (128 * 3)
#define RURI_MAX_SECCOMP_DENIED_SYSCALL (2048)
// Include other headers.
#include "version.h"
#include "k2v.h"
#include "cprintf.h"
#undef cprintf
#undef cfprintf
#define cprintf(format, ...) scprintf(format, ##__VA_ARGS__)
#define cfprintf(stream, format, ...) scfprintf(stream, format, ##__VA_ARGS__)
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
	// Do not show warnings.
	bool no_warnings;
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
};
// For ruri_get_magic().
#define ruri_magicof(x) (x##_magic)
#define ruri_maskof(x) (x##_mask)
struct RURI_ELF_MAGIC {
	char *_Nonnull magic;
	char *_Nonnull mask;
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
// Warnings.
#define ruri_warning(format, ...)                                                                \
	{                                                                                        \
		cfprintf(stderr, "{yellow}at %s() at %d at %s: ", __func__, __LINE__, __FILE__); \
		cfprintf(stderr, format, ##__VA_ARGS__);                                         \
	}
// Show error msg and exit.
#define ruri_error(format, ...)                                                                              \
	{                                                                                                    \
		cfprintf(stderr, "{red}In %s() in %s line %d:\n", __func__, __FILE__, __LINE__);             \
		cfprintf(stderr, format, ##__VA_ARGS__);                                                     \
		cfprintf(stderr, "{base}%s{clear}\n", "\n  .^.   .^.");                                      \
		cfprintf(stderr, "{base}%s{clear}\n", "  /⋀\\_ﾉ_/⋀\\");                                      \
		cfprintf(stderr, "{base}%s{clear}\n", " /ﾉｿﾉ\\ﾉｿ丶)|");                                      \
		cfprintf(stderr, "{base}%s{clear}\n", " ﾙﾘﾘ >  x )ﾘ");                                       \
		cfprintf(stderr, "{base}%s{clear}\n", "ﾉノ㇏  ^  ﾉ|ﾉ");                                      \
		cfprintf(stderr, "{base}%s{clear}\n", "      ⠁⠁");                                           \
		cfprintf(stderr, "{base}%s{clear}\n", "RURI ERROR MESSAGE");                                 \
		cfprintf(stderr, "{base}%s{clear}\n", "If you think something is wrong, please report at:"); \
		cfprintf(stderr, "\033[4m{base}%s{clear}\n", "https://github.com/Moe-hacker/ruri/issues");   \
		exit(114);                                                                                   \
	}
// Log system.
#if defined(RURI_DEBUG)
#define ruri_log(format, ...)                                                                                                         \
	{                                                                                                                             \
		struct timeval tv;                                                                                                    \
		gettimeofday(&tv, NULL);                                                                                              \
		cfprintf(stderr, "{green}[%ld.%06ld] in %s() in %s line %d:\n", tv.tv_sec, tv.tv_usec, __func__, __FILE__, __LINE__); \
		cfprintf(stderr, format, ##__VA_ARGS__);                                                                              \
	}
#else
#define ruri_log(format, ...)
#endif
// Shared functions.
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
void ruri_kill_container(const char *_Nonnull container_dir);
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
#ifndef DISABLE_LIBCAP
int ruri_cap_from_name(const char *str, cap_value_t *cap);
#endif
void ruri_clear_env(char *const *_Nonnull argv);
// Bionic does not have memfd_create()
#ifdef __ANDROID__
#define memfd_create(...) syscall(SYS_memfd_create, __VA_ARGS__)
#endif
//   ██╗ ██╗  ███████╗   ████╗   ███████╗
//  ████████╗ ██╔════╝ ██╔═══██╗ ██╔════╝
//  ╚██╔═██╔╝ █████╗   ██║   ██║ █████╗
//  ████████╗ ██╔══╝   ██║   ██║ ██╔══╝
//  ╚██╔═██╔╝ ███████╗ ╚██████╔╝ ██║
//   ╚═╝ ╚═╝  ╚══════╝  ╚═════╝  ╚═╝
