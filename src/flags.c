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
 */
/*
 * This file contains feature flags control logic.
 * Feature flags are used to enable or disable certain features in ruri.
 */
#include "include/ruri.h"
// Feature flags.
char *ruri_feature_flag(int req, char *_Nonnull flag)
{
	/*
	 * We set all value to char*,
	 * because we will have someting like flag_foo="bar" in the future.
	 * -1 for query, other value for set.
	 */
	static thread_local struct {
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
		char *create_kvm_node;
		char *create_gunyah_node;
		char *create_geniezone_node;
		char *empty_net_ns;
		char *no_reset_pidfile;
		char *no_logs;
		char *wait_pidfile_lock;
		char *no_seccomp;
		char *no_rurienv;
		char *no_cgroup;
	} flags = { .ban_futex_pi = NULL, .wait_before_exec = NULL, .allow_personality = NULL, .force_panic = NULL, .no_time_ns = NULL, .no_uts_ns = NULL, .no_ipc_ns = NULL, .no_pid_ns = NULL, .no_cgroup_ns = NULL, .meow = NULL, .fork_as_init = NULL, .disable_warnings = NULL, .auto_umount = NULL, .auto_umount_on_panic = NULL, .systemd_init = NULL, .is_health_check = NULL, .enable_tty_signals = NULL, .skip_setgroups = NULL, .create_kvm_node = NULL, .empty_net_ns = NULL, .create_geniezone_node = NULL, .create_gunyah_node = NULL, .no_reset_pidfile = NULL, .no_logs = NULL, .wait_pidfile_lock = NULL, .no_seccomp = NULL, .no_rurienv = NULL, .no_cgroup = NULL };
	if (req == -1) {
		if (!strcmp(flag, "ban_futex_pi")) {
			return flags.ban_futex_pi;
		}
		if (!strcmp(flag, "wait_before_exec")) {
			return flags.wait_before_exec;
		}
		if (!strcmp(flag, "allow_personality")) {
			return flags.allow_personality;
		}
		if (!strcmp(flag, "force_panic")) {
			return flags.force_panic;
		}
		if (!strcmp(flag, "no_time_ns")) {
			return flags.no_time_ns;
		}
		if (!strcmp(flag, "no_uts_ns")) {
			return flags.no_uts_ns;
		}
		if (!strcmp(flag, "no_ipc_ns")) {
			return flags.no_ipc_ns;
		}
		if (!strcmp(flag, "no_pid_ns")) {
			return flags.no_pid_ns;
		}
		if (!strcmp(flag, "no_cgroup_ns")) {
			return flags.no_cgroup_ns;
		}
		if (!strcmp(flag, "meow")) {
			return flags.meow;
		}
		if (!strcmp(flag, "fork_as_init")) {
			return flags.fork_as_init;
		}
		if (!strcmp(flag, "disable_warnings")) {
			return flags.disable_warnings;
		}
		if (!strcmp(flag, "auto_umount")) {
			return flags.auto_umount;
		}
		if (!strcmp(flag, "auto_umount_on_panic")) {
			return flags.auto_umount_on_panic;
		}
		if (!strcmp(flag, "systemd_init")) {
			return flags.systemd_init;
		}
		if (!strcmp(flag, "is_health_check")) {
			return flags.is_health_check;
		}
		if (!strcmp(flag, "enable_tty_signals")) {
			return flags.enable_tty_signals;
		}
		if (!strcmp(flag, "skip_setgroups")) {
			return flags.skip_setgroups;
		}
		if (!strcmp(flag, "create_kvm_node")) {
			return flags.create_kvm_node;
		}
		if (!strcmp(flag, "empty_net_ns")) {
			return flags.empty_net_ns;
		}
		if (!strcmp(flag, "create_gunyah_node")) {
			return flags.create_gunyah_node;
		}
		if (!strcmp(flag, "create_geniezone_node")) {
			return flags.create_geniezone_node;
		}
		if (!strcmp(flag, "no_reset_pidfile")) {
			return flags.no_reset_pidfile;
		}
		if (!strcmp(flag, "no_logs")) {
			return flags.no_logs;
		}
		if (!strcmp(flag, "wait_pidfile_lock")) {
			return flags.wait_pidfile_lock;
		}
		if (!strcmp(flag, "no_seccomp")) {
			return flags.no_seccomp;
		}
		if (!strcmp(flag, "no_rurienv")) {
			return flags.no_rurienv;
		}
		if (!strcmp(flag, "no_cgroup")) {
			return flags.no_cgroup;
		}
		ruri_error("{red}Unknown flag: %s\n", flag);
		return "unknown";
	}
	if (!strcmp(flag, "ban_futex_pi")) {
		flags.ban_futex_pi = strdup("true");
		return flags.ban_futex_pi;
	}
	if (!strcmp(flag, "wait_before_exec")) {
		flags.wait_before_exec = strdup("true");
		return flags.wait_before_exec;
	}
	if (!strcmp(flag, "allow_personality")) {
		flags.allow_personality = strdup("true");
		return flags.allow_personality;
	}
	if (!strcmp(flag, "force_panic")) {
		flags.force_panic = strdup("true");
		return flags.force_panic;
	}
	if (!strcmp(flag, "no_time_ns")) {
		flags.no_time_ns = strdup("true");
		return flags.no_time_ns;
	}
	if (!strcmp(flag, "no_uts_ns")) {
		flags.no_uts_ns = strdup("true");
		return flags.no_uts_ns;
	}
	if (!strcmp(flag, "no_ipc_ns")) {
		flags.no_ipc_ns = strdup("true");
		return flags.no_ipc_ns;
	}
	if (!strcmp(flag, "no_pid_ns")) {
		flags.no_pid_ns = strdup("true");
		return flags.no_pid_ns;
	}
	if (!strcmp(flag, "no_cgroup_ns")) {
		flags.no_cgroup_ns = strdup("true");
		return flags.no_cgroup_ns;
	}
	if (!strcmp(flag, "meow")) {
		flags.meow = strdup("true");
		return flags.meow;
	}
	if (!strcmp(flag, "fork_as_init")) {
		flags.fork_as_init = strdup("true");
		return flags.fork_as_init;
	}
	if (!strcmp(flag, "disable_warnings")) {
		flags.disable_warnings = strdup("true");
		return flags.disable_warnings;
	}
	if (!strcmp(flag, "auto_umount")) {
		flags.auto_umount = strdup("true");
		return flags.auto_umount;
	}
	if (!strcmp(flag, "auto_umount_on_panic")) {
		flags.auto_umount_on_panic = strdup("true");
		return flags.auto_umount_on_panic;
	}
	if (!strcmp(flag, "systemd_init")) {
		flags.systemd_init = strdup("true");
		return flags.systemd_init;
	}
	if (!strcmp(flag, "is_health_check")) {
		flags.is_health_check = strdup("true");
		return flags.is_health_check;
	}
	if (!strcmp(flag, "enable_tty_signals")) {
		flags.enable_tty_signals = strdup("true");
		return flags.enable_tty_signals;
	}
	if (!strcmp(flag, "skip_setgroups")) {
		flags.skip_setgroups = strdup("true");
		return flags.skip_setgroups;
	}
	if (!strcmp(flag, "create_kvm_node")) {
		flags.create_kvm_node = strdup("true");
		return flags.create_kvm_node;
	}
	if (!strcmp(flag, "empty_net_ns")) {
		flags.empty_net_ns = strdup("true");
		return flags.empty_net_ns;
	}
	if (!strcmp(flag, "create_gunyah_node")) {
		flags.create_gunyah_node = strdup("true");
		return flags.create_gunyah_node;
	}
	if (!strcmp(flag, "create_geniezone_node")) {
		flags.create_geniezone_node = strdup("true");
		return flags.create_geniezone_node;
	}
	if (!strcmp(flag, "no_reset_pidfile")) {
		flags.no_reset_pidfile = strdup("true");
		return flags.no_reset_pidfile;
	}
	if (!strcmp(flag, "no_logs")) {
		flags.no_logs = strdup("true");
		return flags.no_logs;
	}
	if (!strcmp(flag, "wait_pidfile_lock")) {
		flags.wait_pidfile_lock = strdup("true");
		return flags.wait_pidfile_lock;
	}
	if (!strcmp(flag, "no_seccomp")) {
		flags.no_seccomp = strdup("true");
		return flags.no_seccomp;
	}
	if (!strcmp(flag, "no_rurienv")) {
		flags.no_rurienv = strdup("true");
		return flags.no_rurienv;
	}
	if (!strcmp(flag, "no_cgroup")) {
		flags.no_cgroup = strdup("true");
		return flags.no_cgroup;
	}
	ruri_error("{red}Unknown flag: %s\n", flag);
	return "unknown";
}
bool ruri_flag(char *_Nonnull flag)
{
	char *value = ruri_feature_flag(-1, flag);
	if (value == NULL) {
		return false;
	}
	if (!strcmp(value, "true")) {
		return true;
	}
	return false;
}