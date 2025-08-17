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
 */
// Reslove prefix for errno.
#ifndef DISABLE_LIBSECCOMP
static int ruri_resolve_seccomp_errno(const char *_Nonnull syscall, scmp_filter_ctx *_Nonnull ctx)
{
	const char *syscall_name = syscall;
	uint32_t action = SCMP_ACT_KILL;
	// Support errno prefixes like EACCES:chroot, EPERM:unshare, etc.
	struct {
		const char *name;
		int value;
	} errno_map[] = { { "ERRNO:", 0 }, { "E2BIG:", E2BIG }, { "EACCES:", EACCES }, { "EADDRINUSE:", EADDRINUSE }, { "EADDRNOTAVAIL:", EADDRNOTAVAIL }, { "EAFNOSUPPORT:", EAFNOSUPPORT }, { "EAGAIN:", EAGAIN }, { "EALREADY:", EALREADY }, { "EBADE:", EBADE }, { "EBADF:", EBADF }, { "EBADFD:", EBADFD }, { "EBADMSG:", EBADMSG }, { "EBADR:", EBADR }, { "EBADRQC:", EBADRQC }, { "EBADSLT:", EBADSLT }, { "EBUSY:", EBUSY }, { "ECANCELED:", ECANCELED }, { "ECHILD:", ECHILD }, { "ECHRNG:", ECHRNG }, { "ECOMM:", ECOMM }, { "ECONNABORTED:", ECONNABORTED }, { "ECONNREFUSED:", ECONNREFUSED }, { "ECONNRESET:", ECONNRESET }, { "EDEADLK:", EDEADLK }, { "EDEADLOCK:", EDEADLOCK }, { "EDESTADDRREQ:", EDESTADDRREQ }, { "EDOM:", EDOM }, { "EDQUOT:", EDQUOT }, { "EEXIST:", EEXIST }, { "EFAULT:", EFAULT }, { "EFBIG:", EFBIG }, { "EHOSTDOWN:", EHOSTDOWN }, { "EHOSTUNREACH:", EHOSTUNREACH }, { "EHWPOISON:", EHWPOISON }, { "EIDRM:", EIDRM }, { "EILSEQ:", EILSEQ }, { "EINPROGRESS:", EINPROGRESS }, { "EINTR:", EINTR }, { "EINVAL:", EINVAL }, { "EIO:", EIO }, { "EISCONN:", EISCONN }, { "EISDIR:", EISDIR }, { "EISNAM:", EISNAM }, { "EKEYEXPIRED:", EKEYEXPIRED }, { "EKEYREJECTED:", EKEYREJECTED }, { "EKEYREVOKED:", EKEYREVOKED }, { "EL2HLT:", EL2HLT }, { "EL2NSYNC:", EL2NSYNC }, { "EL3HLT:", EL3HLT }, { "EL3RST:", EL3RST }, { "ELIBACC:", ELIBACC }, { "ELIBBAD:", ELIBBAD }, { "ELIBMAX:", ELIBMAX }, { "ELIBSCN:", ELIBSCN }, { "ELIBEXEC:", ELIBEXEC }, { "ELNRNG:", ELNRNG }, { "ELOOP:", ELOOP }, { "EMEDIUMTYPE:", EMEDIUMTYPE }, { "EMFILE:", EMFILE }, { "EMLINK:", EMLINK }, { "EMSGSIZE:", EMSGSIZE }, { "EMULTIHOP:", EMULTIHOP }, { "ENAMETOOLONG:", ENAMETOOLONG }, { "ENETDOWN:", ENETDOWN }, { "ENETRESET:", ENETRESET }, { "ENETUNREACH:", ENETUNREACH }, { "ENFILE:", ENFILE }, { "ENOANO:", ENOANO }, { "ENOBUFS:", ENOBUFS }, { "ENODATA:", ENODATA }, { "ENODEV:", ENODEV }, { "ENOENT:", ENOENT }, { "ENOEXEC:", ENOEXEC }, { "ENOKEY:", ENOKEY }, { "ENOLCK:", ENOLCK }, { "ENOLINK:", ENOLINK }, { "ENOMEDIUM:", ENOMEDIUM }, { "ENOMEM:", ENOMEM }, { "ENOMSG:", ENOMSG }, { "ENONET:", ENONET }, { "ENOPKG:", ENOPKG }, { "ENOPROTOOPT:", ENOPROTOOPT }, { "ENOSPC:", ENOSPC }, { "ENOSR:", ENOSR }, { "ENOSTR:", ENOSTR }, { "ENOSYS:", ENOSYS }, { "ENOTBLK:", ENOTBLK }, { "ENOTCONN:", ENOTCONN }, { "ENOTDIR:", ENOTDIR }, { "ENOTEMPTY:", ENOTEMPTY }, { "ENOTRECOVERABLE:", ENOTRECOVERABLE }, { "ENOTSOCK:", ENOTSOCK }, { "ENOTSUP:", ENOTSUP }, { "ENOTTY:", ENOTTY }, { "ENOTUNIQ:", ENOTUNIQ }, { "ENXIO:", ENXIO }, { "EOPNOTSUPP:", EOPNOTSUPP }, { "EOVERFLOW:", EOVERFLOW }, { "EOWNERDEAD:", EOWNERDEAD }, { "EPERM:", EPERM }, { "EPFNOSUPPORT:", EPFNOSUPPORT }, { "EPIPE:", EPIPE }, { "EPROTO:", EPROTO }, { "EPROTONOSUPPORT:", EPROTONOSUPPORT }, { "EPROTOTYPE:", EPROTOTYPE }, { "ERANGE:", ERANGE }, { "EREMCHG:", EREMCHG }, { "EREMOTE:", EREMOTE }, { "EREMOTEIO:", EREMOTEIO }, { "ERESTART:", ERESTART }, { "ERFKILL:", ERFKILL }, { "EROFS:", EROFS }, { "ESHUTDOWN:", ESHUTDOWN }, { "ESPIPE:", ESPIPE }, { "ESOCKTNOSUPPORT:", ESOCKTNOSUPPORT }, { "ESRCH:", ESRCH }, { "ESTALE:", ESTALE }, { "ESTRPIPE:", ESTRPIPE }, { "ETIME:", ETIME }, { "ETIMEDOUT:", ETIMEDOUT }, { "ETOOMANYREFS:", ETOOMANYREFS }, { "ETXTBSY:", ETXTBSY }, { "EUCLEAN:", EUCLEAN }, { "EUNATCH:", EUNATCH }, { "EUSERS:", EUSERS }, { "EWOULDBLOCK:", EWOULDBLOCK }, { "EXDEV:", EXDEV }, { "EXFULL:", EXFULL } };
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
// Setup seccomp filter rule, with libseccomp.
void ruri_setup_seccomp(const struct RURI_CONTAINER *_Nonnull container)
{
#ifndef DISABLE_LIBSECCOMP
	/*
	 * Based on docker's default seccomp profile.
	 * This is a blacklist profile.
	 * NOTE: This profile is not fully tested.
	 */
	scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
	// Deny user-defined syscalls.
	for (int i = 0; container->seccomp_denied_syscall[i] != NULL; i++) {
		int syscall_nr = seccomp_syscall_resolve_name(container->seccomp_denied_syscall[i]);
		if (syscall_nr == __NR_SCMP_ERROR) {
			if (ruri_resolve_seccomp_errno(container->seccomp_denied_syscall[i], &ctx) != 0) {
				ruri_error("Failed to resolve syscall: %s\n", container->seccomp_denied_syscall[i]);
			}
		}
		seccomp_rule_add(ctx, SCMP_ACT_KILL, syscall_nr, 0);
	}
	// Default rules.
	if (container->enable_default_seccomp) {
#ifndef DISABLE_LIBCAP
		if (ruri_is_in_caplist(container->drop_caplist, CAP_SYS_PACCT)) {
			seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(acct), 0);
		}
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(add_key), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(bpf), 0);
		if (ruri_is_in_caplist(container->drop_caplist, CAP_SYS_ADMIN)) {
			// Fix `TIODSTI should be a privileged operation`.
			seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(ioctl), 1, SCMP_CMP(1, SCMP_CMP_EQ, TIOCSTI));
			seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(lookup_dcookie), 0);
			seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(mount), 0);
			seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(quotactl), 0);
			seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(setns), 0);
			seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(swapon), 0);
			seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(swapoff), 0);
			seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(umount), 0);
			seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(umount2), 0);
			seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(unshare), 0);
			// clone(2) can have the same effect as unshare(2), we deny it.
			unsigned int clone_flags[] = { CLONE_NEWCGROUP, CLONE_NEWIPC, CLONE_NEWNET, CLONE_NEWNS, CLONE_NEWPID, CLONE_NEWUSER, CLONE_NEWUTS };
			for (size_t i = 0; i < sizeof(clone_flags) / sizeof(clone_flags[0]); i++) {
				seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(clone), 1, SCMP_CMP(2, SCMP_CMP_MASKED_EQ, clone_flags[i], clone_flags[i]));
			}
			seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(vm86), 0);
			seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(vm86old), 0);
		}
		if (ruri_is_in_caplist(container->drop_caplist, CAP_SYS_TIME)) {
			seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(clock_adjtime), 0);
			seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(clock_settime), 0);
			seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(settimeofday), 0);
			seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(stime), 0);
		}
		if (ruri_is_in_caplist(container->drop_caplist, CAP_SYS_MODULE)) {
			seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(create_module), 0);
			seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(delete_module), 0);
			seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(finit_module), 0);
			seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(init_module), 0);
		}
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(get_kernel_syms), 0);
		if (ruri_is_in_caplist(container->drop_caplist, CAP_SYS_NICE)) {
			seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(get_mempolicy), 0);
			seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(mbind), 0);
			seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(set_mempolicy), 0);
			seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(sched_setscheduler), 0);
			seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(sched_setattr), 0);
		}
		if (ruri_is_in_caplist(container->drop_caplist, CAP_SYS_RAWIO)) {
			seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(ioperm), 0);
			seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(iopl), 0);
		}
		if (ruri_is_in_caplist(container->drop_caplist, CAP_SYS_PTRACE)) {
			seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(kcmp), 0);
			seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(process_vm_readv), 0);
			seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(process_vm_writev), 0);
		}
		if (ruri_is_in_caplist(container->drop_caplist, CAP_SYS_BOOT)) {
			seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(kexec_file_load), 0);
			seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(kexec_load), 0);
			seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(reboot), 0);
		}
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(keyctl), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(move_pages), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(nfsservctl), 0);
		if (ruri_is_in_caplist(container->drop_caplist, CAP_DAC_READ_SEARCH)) {
			seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(open_by_handle_at), 0);
		}
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(perf_event_open), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(personality), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(pivot_root), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(query_module), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(request_key), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(sysfs), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(_sysctl), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(uselib), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(userfaultfd), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(ustat), 0);
		if (ruri_is_in_caplist(container->drop_caplist, CAP_SYS_CHROOT)) {
			seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(chroot), 0);
		}
	}
#else
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(acct), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(add_key), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(bpf), 0);
		// Fix `TIODSTI should be a privileged operation`.
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(ioctl), 1, SCMP_CMP(1, SCMP_CMP_EQ, TIOCSTI));
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(lookup_dcookie), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(mount), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(quotactl), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(setns), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(swapon), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(swapoff), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(umount), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(umount2), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(unshare), 0);
		// clone(2) can have the same effect as unshare(2), we deny it.
		unsigned int clone_flags[] = { CLONE_NEWCGROUP, CLONE_NEWIPC, CLONE_NEWNET, CLONE_NEWNS, CLONE_NEWPID, CLONE_NEWUSER, CLONE_NEWUTS };
		for (size_t i = 0; i < sizeof(clone_flags) / sizeof(clone_flags[0]); i++) {
			seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(clone), 1, SCMP_CMP(2, SCMP_CMP_MASKED_EQ, clone_flags[i], clone_flags[i]));
		}
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(vm86), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(vm86old), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(clock_adjtime), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(clock_settime), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(settimeofday), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(stime), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(create_module), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(delete_module), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(finit_module), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(init_module), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(get_kernel_syms), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(get_mempolicy), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(mbind), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(set_mempolicy), 0);
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(sched_setscheduler), 0);
		seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(sched_setattr), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(ioperm), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(iopl), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(kcmp), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(process_vm_readv), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(process_vm_writev), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(kexec_file_load), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(kexec_load), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(reboot), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(keyctl), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(move_pages), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(nfsservctl), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(open_by_handle_at), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(perf_event_open), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(personality), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(pivot_root), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(query_module), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(request_key), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(sysfs), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(_sysctl), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(uselib), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(userfaultfd), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(ustat), 0);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(chroot), 0);
	}
#endif
	// Disable no_new_privs bit by default.
	seccomp_attr_set(ctx, SCMP_FLTATR_CTL_NNP, 0);
	// Load seccomp rules.
	seccomp_load(ctx);
	ruri_log("{base}Seccomp filter loaded\n");
#endif
}
