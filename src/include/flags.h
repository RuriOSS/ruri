// SPDX-License-Identifier: MIT
/*
 *
 * This file is part of ruri, with ABSOLUTELY NO WARRANTY.
 *
 * MIT License
 *
 * Copyright (c) 2026 Moe-hacker
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
#include <stddef.h>
// Bool!!!
#if __STDC_VERSION__ < 202000L
#ifndef bool
#define bool _Bool
#define true ((_Bool)1u)
#define false ((_Bool)0u)
#endif
#endif // bool
struct __attribute__((packed, aligned(1))) RURI_FLAGS {
	char *ban_futex_pi;
	char *wait_before_exec;
	char *allow_personality;
	char *force_panic;
	char *no_time_ns;
	char *no_uts_ns;
	char *no_ipc_ns;
	char *no_pid_ns;
	char *no_cgroup_ns;
	char *meow;
	char *fork_as_init;
	char *disable_warnings;
	char *auto_umount;
	char *auto_umount_on_panic;
	char *systemd_init;
	char *is_health_check;
	char *enable_tty_signals;
	char *skip_setgroups;
	char *empty_net_ns;
	char *no_reset_pidfile;
	char *no_logs;
	char *wait_pidfile_lock;
	char *no_seccomp;
	char *no_rurienv;
	char *no_cgroup;
	char *no_pidfile_daemon;
	char *no_drop_caps;
	char *no_memory_cgroup;
	char *no_cpuset_cgroup;
	char *no_cpupercent_cgroup;
	char *no_pids_cgroup;
	char *no_io_cgroup;
	char *no_freezer_cgroup;
	char *no_pidfd;
	char *dev_nodes;
	char *just_chroot;
	char *ruri_dbg;
	char *use_host_runtime;
	char *no_mask_paths;
	char *read_only_rootfs;
	char *no_new_privs;
	char *rlimits;
};
struct __attribute__((packed, aligned(1))) RURI_DEV_NODES {
	bool has_console;
	bool has_full;
	bool has_null;
	bool has_random;
	bool has_tty;
	bool has_urandom;
	bool has_zero;
	bool has_kvm;
	bool has_gunyah;
	bool has_gzvm;
	bool has_devpts;
	bool has_devshm;
	bool has_net_tun;
};
// For ruri_feature_flag().
#define RURI_SET_FLAG (114)
#define RURI_QUERY_FLAG (-514)
#define ruri_set_flag(flag) ruri_feature_flag(RURI_SET_FLAG, flag, 0)
#define ruri_flag(flag) (ruri_feature_flag(RURI_QUERY_FLAG, NULL, offsetof(struct RURI_FLAGS, flag)) != NULL)
#define ruri_has_dev(dev) (ruri_dev_nodes(RURI_QUERY_FLAG, NULL, offsetof(struct RURI_DEV_NODES, has_##dev)) != false)