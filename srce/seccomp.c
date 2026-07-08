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
 * This file provides the built-in seccomp filter rules for ruri.
 * Thanks docker for denied syscall list.
 *    ,-----,,
 *   /########\    This is Cheems.
 *   ●//● #####|   He will ban unsafe syscalls for you.
 *   ,●=ノ____,=≤   What the dog doin?
 *  /|\  /|\
 *  "Oh, bad process, I'll kill it......."
 */
// Reslove prefix for errno.
#ifndef DISABLE_LIBSECCOMP
static void ruri_check_seccomp_ret(int res, bool no_warnings)
{
	if (res < 0 && res != -EEXIST) {
		ruri_warn_on_error(1, 0, !no_warnings, "seccomp rule add failed: %s\n", strerror(-res));
	}
}
static int ruri_resolve_seccomp_errno(const char *_Nonnull syscall, scmp_filter_ctx *_Nonnull ctx)
{
	const char *syscall_name = syscall;
	uint32_t action = SCMP_ACT_KILL;
	// Support errno prefixes like EACCES:chroot, EPERM:unshare, etc.
	// clang-format off
	struct {
  		const char *name;
  		unsigned int value;
	} errno_map[] = {{"ERRNO:", 0},
                 {"E2BIG:", E2BIG},
                 {"EACCES:", EACCES},
                 {"EADDRINUSE:", EADDRINUSE},
                 {"EADDRNOTAVAIL:", EADDRNOTAVAIL},
                 {"EAFNOSUPPORT:", EAFNOSUPPORT},
                 {"EAGAIN:", EAGAIN},
                 {"EALREADY:", EALREADY},
                 {"EBADE:", EBADE},
                 {"EBADF:", EBADF},
                 {"EBADFD:", EBADFD},
                 {"EBADMSG:", EBADMSG},
                 {"EBADR:", EBADR},
                 {"EBADRQC:", EBADRQC},
                 {"EBADSLT:", EBADSLT},
                 {"EBUSY:", EBUSY},
                 {"ECANCELED:", ECANCELED},
                 {"ECHILD:", ECHILD},
                 {"ECHRNG:", ECHRNG},
                 {"ECOMM:", ECOMM},
                 {"ECONNABORTED:", ECONNABORTED},
                 {"ECONNREFUSED:", ECONNREFUSED},
                 {"ECONNRESET:", ECONNRESET},
                 {"EDEADLK:", EDEADLK},
                 {"EDEADLOCK:", EDEADLOCK},
                 {"EDESTADDRREQ:", EDESTADDRREQ},
                 {"EDOM:", EDOM},
                 {"EDQUOT:", EDQUOT},
                 {"EEXIST:", EEXIST},
                 {"EFAULT:", EFAULT},
                 {"EFBIG:", EFBIG},
                 {"EHOSTDOWN:", EHOSTDOWN},
                 {"EHOSTUNREACH:", EHOSTUNREACH},
                 {"EHWPOISON:", EHWPOISON},
                 {"EIDRM:", EIDRM},
                 {"EILSEQ:", EILSEQ},
                 {"EINPROGRESS:", EINPROGRESS},
                 {"EINTR:", EINTR},
                 {"EINVAL:", EINVAL},
                 {"EIO:", EIO},
                 {"EISCONN:", EISCONN},
                 {"EISDIR:", EISDIR},
                 {"EISNAM:", EISNAM},
                 {"EKEYEXPIRED:", EKEYEXPIRED},
                 {"EKEYREJECTED:", EKEYREJECTED},
                 {"EKEYREVOKED:", EKEYREVOKED},
                 {"EL2HLT:", EL2HLT},
                 {"EL2NSYNC:", EL2NSYNC},
                 {"EL3HLT:", EL3HLT},
                 {"EL3RST:", EL3RST},
                 {"ELIBACC:", ELIBACC},
                 {"ELIBBAD:", ELIBBAD},
                 {"ELIBMAX:", ELIBMAX},
                 {"ELIBSCN:", ELIBSCN},
                 {"ELIBEXEC:", ELIBEXEC},
                 {"ELNRNG:", ELNRNG},
                 {"ELOOP:", ELOOP},
                 {"EMEDIUMTYPE:", EMEDIUMTYPE},
                 {"EMFILE:", EMFILE},
                 {"EMLINK:", EMLINK},
                 {"EMSGSIZE:", EMSGSIZE},
                 {"EMULTIHOP:", EMULTIHOP},
                 {"ENAMETOOLONG:", ENAMETOOLONG},
                 {"ENETDOWN:", ENETDOWN},
                 {"ENETRESET:", ENETRESET},
                 {"ENETUNREACH:", ENETUNREACH},
                 {"ENFILE:", ENFILE},
                 {"ENOANO:", ENOANO},
                 {"ENOBUFS:", ENOBUFS},
                 {"ENODATA:", ENODATA},
                 {"ENODEV:", ENODEV},
                 {"ENOENT:", ENOENT},
                 {"ENOEXEC:", ENOEXEC},
                 {"ENOKEY:", ENOKEY},
                 {"ENOLCK:", ENOLCK},
                 {"ENOLINK:", ENOLINK},
                 {"ENOMEDIUM:", ENOMEDIUM},
                 {"ENOMEM:", ENOMEM},
                 {"ENOMSG:", ENOMSG},
                 {"ENONET:", ENONET},
                 {"ENOPKG:", ENOPKG},
                 {"ENOPROTOOPT:", ENOPROTOOPT},
                 {"ENOSPC:", ENOSPC},
                 {"ENOSR:", ENOSR},
                 {"ENOSTR:", ENOSTR},
                 {"ENOSYS:", ENOSYS},
                 {"ENOTBLK:", ENOTBLK},
                 {"ENOTCONN:", ENOTCONN},
                 {"ENOTDIR:", ENOTDIR},
                 {"ENOTEMPTY:", ENOTEMPTY},
                 {"ENOTRECOVERABLE:", ENOTRECOVERABLE},
                 {"ENOTSOCK:", ENOTSOCK},
                 {"ENOTSUP:", ENOTSUP},
                 {"ENOTTY:", ENOTTY},
                 {"ENOTUNIQ:", ENOTUNIQ},
                 {"ENXIO:", ENXIO},
                 {"EOPNOTSUPP:", EOPNOTSUPP},
                 {"EOVERFLOW:", EOVERFLOW},
                 {"EOWNERDEAD:", EOWNERDEAD},
                 {"EPERM:", EPERM},
                 {"EPFNOSUPPORT:", EPFNOSUPPORT},
                 {"EPIPE:", EPIPE},
                 {"EPROTO:", EPROTO},
                 {"EPROTONOSUPPORT:", EPROTONOSUPPORT},
                 {"EPROTOTYPE:", EPROTOTYPE},
                 {"ERANGE:", ERANGE},
                 {"EREMCHG:", EREMCHG},
                 {"EREMOTE:", EREMOTE},
                 {"EREMOTEIO:", EREMOTEIO},
                 {"ERESTART:", ERESTART},
                 {"ERFKILL:", ERFKILL},
                 {"EROFS:", EROFS},
                 {"ESHUTDOWN:", ESHUTDOWN},
                 {"ESPIPE:", ESPIPE},
                 {"ESOCKTNOSUPPORT:", ESOCKTNOSUPPORT},
                 {"ESRCH:", ESRCH},
                 {"ESTALE:", ESTALE},
                 {"ESTRPIPE:", ESTRPIPE},
                 {"ETIME:", ETIME},
                 {"ETIMEDOUT:", ETIMEDOUT},
                 {"ETOOMANYREFS:", ETOOMANYREFS},
                 {"ETXTBSY:", ETXTBSY},
                 {"EUCLEAN:", EUCLEAN},
                 {"EUNATCH:", EUNATCH},
                 {"EUSERS:", EUSERS},
                 {"EWOULDBLOCK:", EWOULDBLOCK},
                 {"EXDEV:", EXDEV},
                 {"EXFULL:", EXFULL}};
	// clang-format on
	for (size_t i = 0; i < sizeof(errno_map) / sizeof(errno_map[0]); i++) {
		if (strncmp(syscall_name, errno_map[i].name, strlen(errno_map[i].name)) == 0) {
			action = SCMP_ACT_ERRNO(errno_map[i].value);
			syscall_name += strlen(errno_map[i].name);
			int syscall_nr = seccomp_syscall_resolve_name(syscall_name);
			if (syscall_nr == __NR_SCMP_ERROR) {
				ruri_error("Failed to resolve syscall: %s\n", syscall_name);
			}
			return seccomp_rule_add(*ctx, action, syscall_nr, 0);
		}
	}
	return -1;
}
#endif
static bool kernel_version_le(int major, int minor, int patch)
{
	struct utsname buf;
	uname(&buf);
	int k_major = 0, k_minor = 0, k_patch = 0;
	sscanf(buf.release, "%d.%d.%d", &k_major, &k_minor, &k_patch);
	if (k_major < major) {
		return true;
	}
	if (k_major == major) {
		if (k_minor < minor) {
			return true;
		}
		if (k_minor == minor) {
			return k_patch <= patch;
		}
	}
	return false;
}
static void ruri_setup_seccomp_whitelist(const struct RURI_CONTAINER *_Nonnull container)
{
	/*
	 * Fully kang moby's default seccomp profile.
	 * See: https://github.com/moby/profiles/blob/main/seccomp/default.json
	 */
#ifndef DISABLE_LIBCAP
#ifndef DISABLE_LIBSECCOMP
	int res = 0;
	scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ERRNO(EPERM));
	// Deny user-defined syscalls.
	for (int i = 0; container->seccomp_denied_syscall[i] != NULL; i++) {
		int syscall_nr = seccomp_syscall_resolve_name(container->seccomp_denied_syscall[i]);
		if (syscall_nr == __NR_SCMP_ERROR) {
			if (ruri_resolve_seccomp_errno(container->seccomp_denied_syscall[i], &ctx) != 0) {
				ruri_error("Failed to resolve syscall: %s\n", container->seccomp_denied_syscall[i]);
			}
		} else {
			seccomp_rule_add(ctx, SCMP_ACT_KILL, syscall_nr, 0) :<;
		}
	}
	if (ruri_flag("ban_futex_pi")) {
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EACCES), SCMP_SYS(futex), 1, SCMP_CMP(1, SCMP_CMP_EQ, FUTEX_LOCK_PI)) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EACCES), SCMP_SYS(futex), 1, SCMP_CMP(1, SCMP_CMP_EQ, FUTEX_LOCK_PI2)) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EACCES), SCMP_SYS(futex), 1, SCMP_CMP(1, SCMP_CMP_EQ, FUTEX_TRYLOCK_PI)) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EACCES), SCMP_SYS(futex), 1, SCMP_CMP(1, SCMP_CMP_EQ, FUTEX_UNLOCK_PI)) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EACCES), SCMP_SYS(futex), 1, SCMP_CMP(1, SCMP_CMP_EQ, FUTEX_WAIT_REQUEUE_PI)) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EACCES), SCMP_SYS(futex), 1, SCMP_CMP(1, SCMP_CMP_EQ, FUTEX_CMP_REQUEUE_PI)) :<;
	}
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(accept), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(accept4), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(access), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(adjtimex), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(alarm), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(bind), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(cachestat), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(capget), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(capset), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(chdir), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(chmod), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(chown), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(chown32), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_adjtime), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_adjtime64), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_getres), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_getres_time64), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_gettime), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_gettime64), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_nanosleep), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_nanosleep_time64), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close_range), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(connect), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(copy_file_range), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(creat), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup2), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup3), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_create), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_create1), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_ctl), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_ctl_old), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_pwait), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_pwait2), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_wait), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_wait_old), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(eventfd), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(eventfd2), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execve), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execveat), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(faccessat), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(faccessat2), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fadvise64), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fadvise64_64), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fallocate), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fanotify_mark), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fchdir), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fchmod), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fchmodat), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fchmodat2), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fchown), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fchown32), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fchownat), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl64), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fdatasync), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fgetxattr), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(flistxattr), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(flock), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fork), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fremovexattr), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fsetxattr), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat64), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstatat64), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstatfs), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstatfs64), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fsync), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ftruncate), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ftruncate64), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex_requeue), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex_time64), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex_wait), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex_waitv), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex_wake), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futimesat), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getcpu), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getcwd), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getdents), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getdents64), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getegid), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getegid32), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(geteuid), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(geteuid32), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getgid), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getgid32), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getgroups), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getgroups32), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getitimer), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpeername), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpgid), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpgrp), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getppid), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpriority), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrandom), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getresgid), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getresgid32), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getresuid), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getresuid32), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrlimit), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(get_robust_list), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrusage), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getsid), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getsockname), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getsockopt), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(get_thread_area), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(gettid), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(gettimeofday), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getuid), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getuid32), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getxattr), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, seccomp_syscall_resolve_name("getxattrat"), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(inotify_add_watch), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(inotify_init), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(inotify_init1), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(inotify_rm_watch), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(io_cancel), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(io_destroy), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(io_getevents), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(io_pgetevents), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(io_pgetevents_time64), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioprio_get), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioprio_set), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(io_setup), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(io_submit), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ipc), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(kill), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(landlock_add_rule), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(landlock_create_ruleset), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(landlock_restrict_self), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lchown), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lchown32), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lgetxattr), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(link), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(linkat), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(listen), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, seccomp_syscall_resolve_name("listmount"), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(listxattr), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, seccomp_syscall_resolve_name("listxattrat"), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(llistxattr), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(_llseek), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lremovexattr), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lsetxattr), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lstat), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lstat64), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(madvise), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(map_shadow_stack), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(membarrier), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(memfd_create), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(memfd_secret), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mincore), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mkdir), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mkdirat), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mknod), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mknodat), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mlock), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mlock2), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mlockall), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap2), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mq_getsetattr), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mq_notify), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mq_open), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mq_timedreceive), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mq_timedreceive_time64), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mq_timedsend), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mq_timedsend_time64), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mq_unlink), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mremap), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, seccomp_syscall_resolve_name("mseal"), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(msgctl), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(msgget), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(msgrcv), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(msgsnd), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(msync), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munlock), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munlockall), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(name_to_handle_at), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(nanosleep), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(newfstatat), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(_newselect), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat2), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pause), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pidfd_open), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pidfd_send_signal), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pipe), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pipe2), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pkey_alloc), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pkey_free), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pkey_mprotect), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(poll), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ppoll), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ppoll_time64), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(prctl), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pread64), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(preadv), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(preadv2), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(prlimit64), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(process_mrelease), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pselect6), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pselect6_time64), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pwrite64), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pwritev), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pwritev2), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readahead), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readlink), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readlinkat), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readv), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recv), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvfrom), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvmmsg), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvmmsg_time64), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvmsg), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(remap_file_pages), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(removexattr), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, seccomp_syscall_resolve_name("removexattrat"), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rename), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(renameat), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(renameat2), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(restart_syscall), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, seccomp_syscall_resolve_name("riscv_hwprobe"), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rmdir), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rseq), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigaction), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigpending), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigqueueinfo), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigsuspend), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigtimedwait), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigtimedwait_time64), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_tgsigqueueinfo), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_getaffinity), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_getattr), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_getparam), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_get_priority_max), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_get_priority_min), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_getscheduler), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_rr_get_interval), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_rr_get_interval_time64), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_setaffinity), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_setattr), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_setparam), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_setscheduler), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_yield), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(seccomp), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(select), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(semctl), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(semget), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(semop), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(semtimedop), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(semtimedop_time64), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(send), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendfile), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendfile64), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendmmsg), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendmsg), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendto), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setfsgid), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setfsgid32), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setfsuid), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setfsuid32), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setgid), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setgid32), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setgroups), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setgroups32), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setitimer), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setpgid), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setpriority), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setregid), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setregid32), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setresgid), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setresgid32), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setresuid), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setresuid32), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setreuid), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setreuid32), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setrlimit), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_robust_list), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setsid), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setsockopt), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_thread_area), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_tid_address), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setuid), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setuid32), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setxattr), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, seccomp_syscall_resolve_name("setxattrat"), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(shmat), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(shmctl), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(shmdt), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(shmget), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(shutdown), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sigaltstack), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(signalfd), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(signalfd4), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sigprocmask), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sigreturn), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socketcall), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socketpair), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(splice), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(stat), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(stat64), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(statfs), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(statfs64), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, seccomp_syscall_resolve_name("statmount"), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(statx), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(symlink), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(symlinkat), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sync), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sync_file_range), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(syncfs), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sysinfo), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(tee), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(tgkill), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(time), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(timer_create), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(timer_delete), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(timer_getoverrun), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(timer_gettime), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(timer_gettime64), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(timer_settime), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(timer_settime64), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(timerfd_create), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(timerfd_gettime), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(timerfd_gettime64), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(timerfd_settime), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(timerfd_settime64), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(times), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(tkill), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(truncate), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(truncate64), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ugetrlimit), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(umask), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(uname), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(unlink), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(unlinkat), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, seccomp_syscall_resolve_name("uretprobe"), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(utime), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(utimensat), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(utimensat_time64), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(utimes), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(vfork), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(vmsplice), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(wait4), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(waitid), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(waitpid), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(writev), 0) :<;
	if (!kernel_version_le(4, 8, 0)) {
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ptrace), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(process_vm_readv), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(process_vm_writev), 0) :<;
	}
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_LT, AF_ALG)) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_NFC)) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_GT, AF_VSOCK)) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(personality), 1, SCMP_CMP(0, SCMP_CMP_EQ, PER_LINUX)) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(personality), 1, SCMP_CMP(0, SCMP_CMP_EQ, PER_LINUX32)) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(personality), 1, SCMP_CMP(0, SCMP_CMP_EQ, UNAME26)) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(personality), 1, SCMP_CMP(0, SCMP_CMP_EQ, UNAME26 | PER_LINUX32)) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(personality), 1, SCMP_CMP(0, SCMP_CMP_EQ, 0xffffffff)) :<;
	if (seccomp_arch_native() == SCMP_ARCH_PPC64LE) {
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sync_file_range2), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(swapcontext), 0) :<;
	}
	if (seccomp_arch_native() == SCMP_ARCH_ARM || seccomp_arch_native() == SCMP_ARCH_AARCH64) {
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(arm_fadvise64_64), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(arm_sync_file_range), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sync_file_range2), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(breakpoint), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(cacheflush), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_tls), 0) :<;
	}
	if (seccomp_arch_native() == SCMP_ARCH_X86_64 || seccomp_arch_native() == SCMP_ARCH_X32) {
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(arch_prctl), 0) :<;
	}
	if (seccomp_arch_native() == SCMP_ARCH_X86_64 || seccomp_arch_native() == SCMP_ARCH_X86 || seccomp_arch_native() == SCMP_ARCH_X32) {
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(modify_ldt), 0) :<;
	}
	if (seccomp_arch_native() == SCMP_ARCH_S390 || seccomp_arch_native() == SCMP_ARCH_S390X) {
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(s390_pci_mmio_read), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(s390_pci_mmio_write), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(s390_runtime_instr), 0) :<;
	}
	if (seccomp_arch_native() == SCMP_ARCH_RISCV64) {
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(riscv_flush_icache), 0) :<;
	}
	if (!ruri_is_in_caplist(container->drop_caplist, CAP_DAC_READ_SEARCH)) {
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open_by_handle_at), 0) :<;
	}
	if (!ruri_is_in_caplist(container->drop_caplist, CAP_SYS_ADMIN)) {
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(bpf), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clone), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clone3), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fanotify_init), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fsconfig), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fsmount), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fsopen), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fspick), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lookup_dcookie), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, seccomp_syscall_resolve_name("lsm_get_self_attr"), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, seccomp_syscall_resolve_name("lsm_list_modules"), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, seccomp_syscall_resolve_name("lsm_set_self_attr"), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mount), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mount_setattr), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(move_mount), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open_tree), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(perf_event_open), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(quotactl), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(quotactl_fd), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setdomainname), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sethostname), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setns), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(syslog), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(umount), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(umount2), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(unshare), 0) :<;
	}
	if (ruri_is_in_caplist(container->drop_caplist, CAP_SYS_ADMIN) && !(seccomp_arch_native() == SCMP_ARCH_S390 || seccomp_arch_native() == SCMP_ARCH_S390X)) {
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clone), 1, SCMP_CMP(0, SCMP_CMP_MASKED_EQ, CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWUSER, 0)) :<;
	}
	if (ruri_is_in_caplist(container->drop_caplist, CAP_SYS_ADMIN) && (seccomp_arch_native() == SCMP_ARCH_S390 || seccomp_arch_native() == SCMP_ARCH_S390X)) {
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clone), 1, SCMP_CMP(1, SCMP_CMP_MASKED_EQ, CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWUSER, 0)) :<;
	}
	if (ruri_is_in_caplist(container->drop_caplist, CAP_SYS_ADMIN)) {
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(38), SCMP_SYS(clone3), 0) :<;
	}
	if (!ruri_is_in_caplist(container->drop_caplist, CAP_SYS_BOOT)) {
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(reboot), 0) :<;
	}
	if (!ruri_is_in_caplist(container->drop_caplist, CAP_SYS_CHROOT)) {
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(chroot), 0) :<;
	}
	if (!ruri_is_in_caplist(container->drop_caplist, CAP_SYS_MODULE)) {
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(init_module), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(delete_module), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(finit_module), 0) :<;
	}
	if (!ruri_is_in_caplist(container->drop_caplist, CAP_SYS_PACCT)) {
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(acct), 0) :<;
	}
	if (!ruri_is_in_caplist(container->drop_caplist, CAP_SYS_PTRACE)) {
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(kcmp), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pidfd_getfd), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(process_madvise), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(process_vm_readv), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(process_vm_writev), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ptrace), 0) :<;
	}
	if (!ruri_is_in_caplist(container->drop_caplist, CAP_SYS_RAWIO)) {
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioperm), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(iopl), 0) :<;
	}
	if (!ruri_is_in_caplist(container->drop_caplist, CAP_SYS_TIME)) {
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(settimeofday), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(stime), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_settime), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_settime64), 0) :<;
	}
	if (!ruri_is_in_caplist(container->drop_caplist, CAP_SYS_TTY_CONFIG)) {
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(vhangup), 0) :<;
	}
	if (!ruri_is_in_caplist(container->drop_caplist, CAP_SYS_NICE)) {
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(get_mempolicy), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mbind), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_mempolicy), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_mempolicy_home_node), 0) :<;
	}
	if (!ruri_is_in_caplist(container->drop_caplist, CAP_SYSLOG)) {
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(syslog), 0) :<;
	}
	if (!ruri_is_in_caplist(container->drop_caplist, CAP_BPF)) {
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(bpf), 0) :<;
	}
	if (!ruri_is_in_caplist(container->drop_caplist, CAP_PERFMON)) {
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(perf_event_open), 0) :<;
	}
	// Disable no_new_privs bit by default.
	seccomp_attr_set(ctx, SCMP_FLTATR_CTL_NNP, 0);
	// Load seccomp rules.
	if (seccomp_load(ctx) != 0) {
		ruri_warn_on_error(1, 0, !container->no_warnings, "{yellow}Warning: failed to load seccomp filter QwQ{clear}\n");
	}
#else
	ruri_error("libseccomp is disabled, cannot setup seccomp whitelist filter\n");
#endif // DISABLE_LIBSECCOMP
#else
	ruri_error("libcap is disabled, cannot setup seccomp whitelist filter\n");
#endif // DISABLE_LIBCAP
}
// Setup seccomp filter rule, with libseccomp.
static void ruri_setup_seccomp_blacklist(const struct RURI_CONTAINER *_Nonnull container)
{
#ifndef DISABLE_LIBSECCOMP
	/*
	 * Based on docker's default seccomp profile.
	 * And act on other 0day vulnerabilities.
	 * This is a blacklist profile.
	 * Also thanks: Gemini, ChatGPT and DeepSeek.
	 * NOTE: This profile is not fully tested.
	 */
	int res = 0;
	if (!container->enable_default_seccomp && !container->seccomp_denied_syscall[0] && !container->systemd_mode) {
		return;
	}
	scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
	// Deny user-defined syscalls.
	for (int i = 0; container->seccomp_denied_syscall[i] != NULL; i++) {
		int syscall_nr = seccomp_syscall_resolve_name(container->seccomp_denied_syscall[i]);
		if (syscall_nr == __NR_SCMP_ERROR) {
			if (ruri_resolve_seccomp_errno(container->seccomp_denied_syscall[i], &ctx) != 0) {
				ruri_error("Failed to resolve syscall: %s\n", container->seccomp_denied_syscall[i]);
			}
		} else {
			seccomp_rule_add(ctx, SCMP_ACT_KILL, syscall_nr, 0) :<;
		}
	}
	if (!container->enable_default_seccomp && !container->systemd_mode) {
		// Disable no_new_privs bit by default.
		seccomp_attr_set(ctx, SCMP_FLTATR_CTL_NNP, 0);
		// Load seccomp rules.
		if (seccomp_load(ctx) != 0) {
			ruri_warn_on_error(1, 0, !container->no_warnings, "{yellow}Warning: failed to load seccomp filter QwQ{clear}\n");
		}
		ruri_log("{base}Seccomp filter loaded\n");
	}
	// For non-root user, pass capability checks.
	bool not_root_user = false;
	if (container->user != NULL) {
		if (strcmp(container->user, "root") != 0 && strcmp(container->user, "0") != 0) {
			not_root_user = true;
		}
	}
	// Default rules.
#ifndef DISABLE_LIBCAP
	if (ruri_is_in_caplist(container->drop_caplist, CAP_SYS_PACCT) || not_root_user) {
		// acct() is used for process accounting, which is not needed in most cases and can be abused for DoS attacks.
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(acct), 0) :<;
	}
	// Disallow AF_ALG.
	// See Copy-Fail.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_ALG)) :<;
	// Disallow AF_RDS.
	// See pintheft.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_RDS)) :<;
	// Disallow AF_RXRPC.
	// See DirtyFrag.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_RXRPC)) :<;
	// Disallow NETLINK_XFRM for AF_NETLINK.
	// See DirtyFrag.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 2, SCMP_CMP(0, SCMP_CMP_EQ, AF_NETLINK), SCMP_CMP(2, SCMP_CMP_EQ, NETLINK_XFRM)) :<;
	//
	// Anyway, go ahead and disallow these unused socket families.
	//
	// Disallow AF_AX25.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_AX25)) :<;
	// Disallow AF_IPX.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_IPX)) :<;
	// Disallow AF_APPLETALK.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_APPLETALK)) :<;
	// Disallow AF_X25.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_X25)) :<;
	// Disallow AF_DECnet.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_DECnet)) :<;
	// Disallow AF_PPPOX.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_PPPOX)) :<;
	// Disallow AF_LLC.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_LLC)) :<;
	// Disallow AF_IB.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_IB)) :<;
	// Disallow AF_MPLS.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_MPLS)) :<;
	// Disallow AF_CAN.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_CAN)) :<;
	// Disallow AF_TIPC.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_TIPC)) :<;
	// Disallow AF_BLUETOOTH.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_BLUETOOTH)) :<;
	// Disallow AF_KCM.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_KCM)) :<;
	// Disallow AF_KEY.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_KEY)) :<;
	if (ruri_is_in_caplist(container->drop_caplist, CAP_NET_RAW) || not_root_user) {
		// Disallow AF_PACKET.
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_PACKET)) :<;
		// Disallow SOCKET_RAW.
		if (!container->systemd_mode && (ruri_is_in_caplist(container->drop_caplist, CAP_AUDIT_WRITE) || not_root_user)) {
			seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(socket), 1, SCMP_CMP(1, SCMP_CMP_MASKED_EQ, SOCK_TYPE_MASK, SOCK_RAW)) :<;
		}
		// Disallow SOCKET_PACKET.
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(socket), 1, SCMP_CMP(1, SCMP_CMP_MASKED_EQ, SOCK_TYPE_MASK, SOCK_PACKET)) :<;
	}
	// Ban socketcall(2) for 64bit devices.
	if (seccomp_arch_native() == SCMP_ARCH_X86_64 || seccomp_arch_native() == SCMP_ARCH_AARCH64 || seccomp_arch_native() == SCMP_ARCH_LOONGARCH64 || seccomp_arch_native() == SCMP_ARCH_RISCV64) {
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(socketcall), 0) :<;
	}
	// Fully ban io_uring
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(io_uring_register), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(io_uring_enter), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(io_uring_setup), 0) :<;
	// add_key(2) and keyctl(2) are used for kernel key management.
	// See CVE-2016-0728, CVE-2017-15951.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(add_key), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(request_key), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(keyctl), 0) :<;
	// Ban eBPF, it should be used outside of container, not inside.
	if (ruri_is_in_caplist(container->drop_caplist, CAP_BPF) || not_root_user) {
		// bpf(2) can be used to load eBPF programs, which can be very dangerous.
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(bpf), 0) :<;
	}
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(bpf), 0) :<;
	// Fix `TIODSTI should be a privileged operation`.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(ioctl), 1, SCMP_CMP(1, SCMP_CMP_EQ, TIOCSTI)) :<;
	// Also, TIOCLINUX.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(ioctl), 1, SCMP_CMP(1, SCMP_CMP_EQ, TIOCLINUX)) :<;
	if (ruri_is_in_caplist(container->drop_caplist, CAP_SYS_ADMIN) || not_root_user) {
		// lookup_dcookie(2) is used to look up the path of a file descriptor.
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(lookup_dcookie), 0) :<;
		// mount(2), as we all know.
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(mount), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(umount), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(umount2), 0) :<;
		// new mount api.
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(fsopen), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(fsconfig), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(fsmount), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(move_mount), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(open_tree), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(mount_setattr), 0) :<;
		// quotactl(2) is used to manage disk quotas, which is not needed in most cases and can be abused for DoS attacks.
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(quotactl), 0) :<;
		// Why you setup swap in container? Bro so crazy.
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(swapon), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(swapoff), 0) :<;
		// setns(2) and unshare(2) can be used to escape container in many cases.
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(setns), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(unshare), 0) :<;
		// clone(2) can have the same effect as unshare(2), we deny it.
		unsigned int clone_flags[] = { CLONE_NEWCGROUP, CLONE_NEWIPC, CLONE_NEWNET, CLONE_NEWNS, CLONE_NEWPID, CLONE_NEWUSER, CLONE_NEWUTS };
		for (size_t i = 0; i < sizeof(clone_flags) / sizeof(clone_flags[0]); i++) {
			// For s390, they use arg1, not arg0.
			if (seccomp_arch_native() == SCMP_ARCH_S390) {
				seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(clone), 1, SCMP_CMP(1, SCMP_CMP_MASKED_EQ, clone_flags[i], clone_flags[i])) :<;
			} else {
				seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(clone), 1, SCMP_CMP(0, SCMP_CMP_MASKED_EQ, clone_flags[i], clone_flags[i])) :<;
			}
		}
		if (!container->systemd_mode) {
			seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(clone3), 0) :<;
		}
		// Why you run 8086 vm in container? Weird.
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(vm86), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(vm86old), 0) :<;
		// syslog(2) can be used to read kernel logs, which may contain sensitive information.
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(syslog), 0) :<;
	}
	// memfd_secret() can be used for rootkits, we return ENOSYS.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(memfd_secret), 0) :<;
	// It's anyway so weird to change system time in container.
	// Maybe in time ns it's okey?
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(clock_adjtime), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(clock_settime), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(settimeofday), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(stime), 0) :<;
	// Hey, what are you doing? .ko files should on your host, not in container.
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(create_module), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(delete_module), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(finit_module), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(init_module), 0) :<;
	// Deprecated syscalls, we kill it directly.
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(get_kernel_syms), 0) :<;
	if (ruri_is_in_caplist(container->drop_caplist, CAP_SYS_NICE) || not_root_user) {
		// Seems not very dangerous, so just follow CAP_SYS_NICE.
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(get_mempolicy), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(mbind), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(set_mempolicy), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(sched_setscheduler), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(sched_setattr), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(move_pages), 0) :<;
	}
	// Do not touch any hardware I/O ports in container, it's really dangerous and not needed.
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(ioperm), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(iopl), 0) :<;
	if (ruri_is_in_caplist(container->drop_caplist, CAP_SYS_PTRACE) || not_root_user) {
		// kcmp(2) can be used for side channel attacks, we deny it for non-root users.
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(kcmp), 0) :<;
		// process_vm_readv(2) and process_vm_writev(2) can be used to read/write another process's memory, which is very dangerous.
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(process_vm_readv), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(process_vm_writev), 0) :<;
		// ptrace(2) can be used to trace another process, which is very dangerous.
		// But strace and gdb need ptrace.
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(ptrace), 0) :<;
		// perf_event_open(2) can be used to monitor another process's performance, can be used for side channel attacks.
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(perf_event_open), 0) :<;
		// Disable process_mrelease(2).
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(process_mrelease), 0) :<;
	}
	// Why you need to load kernel in container? Anyway, no.
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(kexec_file_load), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(kexec_load), 0) :<;
	// As systemd eats everything, let it cook.
	if (!container->systemd_mode) {
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(reboot), 0) :<;
	} else {
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(reboot), 0) :<;
	}
	// Deprecated syscall, we kill it directly.
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(nfsservctl), 0) :<;
	if (ruri_is_in_caplist(container->drop_caplist, CAP_DAC_READ_SEARCH) || not_root_user) {
		if (!container->systemd_mode) {
			// open_by_handle_at(2) can be used to access files outside of their intended scope, which is very dangerous.
			seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(open_by_handle_at), 0) :<;
			// also, name_to_handle_at(2).
			seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(name_to_handle_at), 0) :<;
		}
	}
	// Wine/box86 needs personality syscall.
	// But, we cannot SCMP_ACT_ALLOW it, so just ban.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(personality), 1, SCMP_CMP(0, SCMP_CMP_NE, 0xFFFFFFFFUL)) :<;
	// I think I just called pivot_root() for you bro.
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(pivot_root), 0) :<;
	// Deprecated syscall, we kill it directly.
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(query_module), 0) :<;
	// Deprecated syscall, we kill it directly.
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(sysfs), 0) :<;
	// Deprecated syscall, we kill it directly.
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(_sysctl), 0) :<;
	// Deprecated syscall, we kill it directly.
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(uselib), 0) :<;
	// userfaultfd(2) can be used for UAF.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(userfaultfd), 0) :<;
	// Deprecated syscall, we kill it directly.
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(ustat), 0) :<;
	if (ruri_is_in_caplist(container->drop_caplist, CAP_SYS_CHROOT) || not_root_user) {
		// You don't need chroot(2) in container.
		// Can be used to escape container in some cases, and it's really dangerous.
		// But, as systemctl even tries this, we just deny it as EPERM.
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(chroot), 0) :<;
	}
#else
	// acct() is used for process accounting, which is not needed in most cases and can be abused for DoS attacks.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(acct), 0) :<;
	// Disallow AF_ALG.
	// See Copy-Fail.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_ALG)) :<;
	// Disallow AF_RDS.
	// See pintheft.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_RDS)) :<;
	// Disallow AF_RXRPC.
	// See DirtyFrag.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_RXRPC)) :<;
	// Disallow NETLINK_XFRM for AF_NETLINK.
	// See DirtyFrag.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 2, SCMP_CMP(0, SCMP_CMP_EQ, AF_NETLINK), SCMP_CMP(2, SCMP_CMP_EQ, NETLINK_XFRM)) :<;
	//
	// Anyway, go ahead and disallow these unused socket families.
	//
	// Disallow AF_AX25.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_AX25)) :<;
	// Disallow AF_IPX.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_IPX)) :<;
	// Disallow AF_APPLETALK.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_APPLETALK)) :<;
	// Disallow AF_X25.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_X25)) :<;
	// Disallow AF_DECnet.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_DECnet)) :<;
	// Disallow AF_PPPOX.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_PPPOX)) :<;
	// Disallow AF_LLC.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_LLC)) :<;
	// Disallow AF_IB.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_IB)) :<;
	// Disallow AF_MPLS.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_MPLS)) :<;
	// Disallow AF_CAN.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_CAN)) :<;
	// Disallow AF_TIPC.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_TIPC)) :<;
	// Disallow AF_BLUETOOTH.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_BLUETOOTH)) :<;
	// Disallow AF_KCM.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_KCM)) :<;
	// Disallow AF_KEY.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_KEY)) :<;
	// Disallow AF_PACKET.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_PACKET)) :<;
	// Disallow SOCKET_RAW.
	if (!container->systemd_mode) {
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(socket), 1, SCMP_CMP(1, SCMP_CMP_MASKED_EQ, SOCK_TYPE_MASK, SOCK_RAW)) :<;
	}
	// Disallow SOCKET_PACKET.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(socket), 1, SCMP_CMP(1, SCMP_CMP_MASKED_EQ, SOCK_TYPE_MASK, SOCK_PACKET)) :<;
	// Ban socketcall(2) for 64bit devices.
	if (seccomp_arch_native() == SCMP_ARCH_X86_64 || seccomp_arch_native() == SCMP_ARCH_AARCH64 || seccomp_arch_native() == SCMP_ARCH_LOONGARCH64 || seccomp_arch_native() == SCMP_ARCH_RISCV64) {
		// What the dog doin? There's actually no socketcall in 64bit kernel.
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(socketcall), 0) :<;
	}
	// Fully ban io_uring
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(io_uring_register), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(io_uring_enter), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(io_uring_setup), 0) :<;
	// add_key(2) and keyctl(2) are used for kernel key management.
	// See CVE-2016-0728, CVE-2017-15951.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(add_key), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(request_key), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(keyctl), 0) :<;
	// Ban eBPF, it should be used outside of container, not inside.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(bpf), 0) :<;
	// Fix `TIODSTI should be a privileged operation`.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(ioctl), 1, SCMP_CMP(1, SCMP_CMP_EQ, TIOCSTI)) :<;
	// Also, TIOCLINUX.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(ioctl), 1, SCMP_CMP(1, SCMP_CMP_EQ, TIOCLINUX)) :<;
	// lookup_dcookie(2) is used to look up the path of a file descriptor.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(lookup_dcookie), 0) :<;
	// mount(2), as we all know.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(mount), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(umount), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(umount2), 0) :<;
	// new mount api.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(fsopen), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(fsconfig), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(fsmount), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(move_mount), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(open_tree), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(mount_setattr), 0) :<;
	// quotactl(2) is used to manage disk quotas, which is not needed in most cases and can be abused for DoS attacks.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(quotactl), 0) :<;
	// Why you setup swap in container? Bro so crazy.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(swapon), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(swapoff), 0) :<;
	// setns(2) and unshare(2) can be used to escape container in many cases.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(setns), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(unshare), 0) :<;
	// clone(2) can have the same effect as unshare(2), we deny it.
	unsigned int clone_flags[] = { CLONE_NEWCGROUP, CLONE_NEWIPC, CLONE_NEWNET, CLONE_NEWNS, CLONE_NEWPID, CLONE_NEWUSER, CLONE_NEWUTS };
	for (size_t i = 0; i < sizeof(clone_flags) / sizeof(clone_flags[0]); i++) {
		// For s390, they use arg1, not arg0.
		if (seccomp_arch_native() == SCMP_ARCH_S390) {
			seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(clone), 1, SCMP_CMP(1, SCMP_CMP_MASKED_EQ, clone_flags[i], clone_flags[i])) :<;
		} else {
			seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(clone), 1, SCMP_CMP(0, SCMP_CMP_MASKED_EQ, clone_flags[i], clone_flags[i])) :<;
		}
	}
	if (!container->systemd_mode) {
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(clone3), 0) :<;
	}
	// Why you run 8086 vm in container? Weird.
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(vm86), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(vm86old), 0) :<;
	// syslog(2) can be used to read kernel logs, which may contain sensitive information.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(syslog), 0) :<;
	// memfd_secret() can be used for rootkits, we return ENOSYS.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(memfd_secret), 0) :<;
	// It's anyway so weird to change system time in container.
	// Maybe in time ns it's okey?
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(clock_adjtime), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(clock_settime), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(settimeofday), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(stime), 0) :<;
	// Hey, what are you doing? .ko files should on your host, not in container.
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(create_module), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(delete_module), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(finit_module), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(init_module), 0) :<;
	// Deprecated syscalls, we kill it directly.
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(get_kernel_syms), 0) :<;
	// Seems not very dangerous, so just follow CAP_SYS_NICE.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(get_mempolicy), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(mbind), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(set_mempolicy), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(sched_setscheduler), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(sched_setattr), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(move_pages), 0) :<;
	// Do not touch any hardware I/O ports in container, it's really dangerous and not needed.
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(ioperm), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(iopl), 0) :<;
	// kcmp(2) can be used for side channel attacks, we deny it for non-root users.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(kcmp), 0) :<;
	// process_vm_readv(2) and process_vm_writev(2) can be used to read/write another process's memory, which is very dangerous.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(process_vm_readv), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(process_vm_writev), 0) :<;
	// ptrace(2) can be used to trace another process, which is very dangerous.
	// But strace and gdb need ptrace.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(ptrace), 0) :<;
	// perf_event_open(2) can be used to monitor another process's performance, can be used for side channel attacks.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(perf_event_open), 0) :<;
	// Disable process_mrelease(2).
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(process_mrelease), 0) :<;
	// Why you need to load kernel in container? Anyway, no.
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(kexec_file_load), 0) :<;
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(kexec_load), 0) :<;
	// As systemd eats everything, let it cook.
	if (!container->systemd_mode) {
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(reboot), 0) :<;
	} else {
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(reboot), 0) :<;
	}
	// Deprecated syscall, we kill it directly.
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(nfsservctl), 0) :<;
	if (!container->systemd_mode) {
		// open_by_handle_at(2) can be used to access files outside of their intended scope, which is very dangerous.
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(open_by_handle_at), 0) :<;
		// also, name_to_handle_at(2).
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(name_to_handle_at), 0) :<;
	}
	// wine/box86 needs personality syscall.
	// But, we cannot SCMP_ACT_ALLOW it, so just ban.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(personality), 1, SCMP_CMP(0, SCMP_CMP_NE, 0xFFFFFFFFUL)) :<;
	// I think I just called pivot_root() for you bro.
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(pivot_root), 0) :<;
	// Deprecated syscall, we kill it directly.
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(query_module), 0) :<;
	// Deprecated syscall, we kill it directly.
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(sysfs), 0) :<;
	// Deprecated syscall, we kill it directly.
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(_sysctl), 0) :<;
	// Deprecated syscall, we kill it directly.
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(uselib), 0) :<;
	// userfaultfd(2) can be used for UAF.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(userfaultfd), 0) :<;
	// Deprecated syscall, we kill it directly.
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(ustat), 0) :<;
	// You don't need chroot(2) in container.
	// Can be used to escape container in some cases, and it's really dangerous.
	// But, as systemctl even tries this, we just deny it as EPERM.
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(chroot), 0) :<;
#endif
	if (container->systemd_mode) {
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(kexec_load), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(open_by_handle_at), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(init_module), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(delete_module), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(finit_module), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(kexec_file_load), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(reboot), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(umount2), 1, SCMP_CMP(5, SCMP_CMP_MASKED_EQ, MNT_FORCE, MNT_FORCE)) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(keyctl), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(add_key), 0) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(request_key), 0) :<;
	}
	if (ruri_flag("ban_futex_pi")) {
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(futex), 1, SCMP_CMP(1, SCMP_CMP_EQ, FUTEX_LOCK_PI)) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(futex), 1, SCMP_CMP(1, SCMP_CMP_EQ, FUTEX_LOCK_PI2)) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(futex), 1, SCMP_CMP(1, SCMP_CMP_EQ, FUTEX_TRYLOCK_PI)) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(futex), 1, SCMP_CMP(1, SCMP_CMP_EQ, FUTEX_UNLOCK_PI)) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(futex), 1, SCMP_CMP(1, SCMP_CMP_EQ, FUTEX_WAIT_REQUEUE_PI)) :<;
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(futex), 1, SCMP_CMP(1, SCMP_CMP_EQ, FUTEX_CMP_REQUEUE_PI)) :<;
	}
	// Disable no_new_privs bit by default.
	seccomp_attr_set(ctx, SCMP_FLTATR_CTL_NNP, 0);
	// Load seccomp rules.
	if (seccomp_load(ctx) != 0) {
		ruri_warn_on_error(1, 0, !container->no_warnings, "{yellow}Warning: failed to load seccomp filter QwQ{clear}\n");
	}
	ruri_log("{base}Seccomp filter loaded\n");
#endif
}
void ruri_setup_seccomp(const struct RURI_CONTAINER *_Nonnull container)
{
	if (container->enable_seccomp_whitelist) {
		ruri_setup_seccomp_whitelist(container);
	} else {
		ruri_setup_seccomp_blacklist(container);
	}
}