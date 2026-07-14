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
bool ruri_dev_nodes(int req, const char *_Nonnull dev)
{
	static thread_local struct {
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
	} dev_nodes = {
		// clang-format off
		.has_console = false,
		.has_full = true,
		.has_null = true,
		.has_random = true,
		.has_tty = false,
		.has_urandom = true,
		.has_zero = true,
		.has_kvm = false,
		.has_gunyah = false,
		.has_gzvm = false
		// clang-format on
	};
	if (req == RURI_QUERY_FLAG) {
		if (!strcmp(dev, "console")) {
			return dev_nodes.has_console;
		}
		if (!strcmp(dev, "full")) {
			return dev_nodes.has_full;
		}
		if (!strcmp(dev, "null")) {
			return dev_nodes.has_null;
		}
		if (!strcmp(dev, "random")) {
			return dev_nodes.has_random;
		}
		if (!strcmp(dev, "tty")) {
			return dev_nodes.has_tty;
		}
		if (!strcmp(dev, "urandom")) {
			return dev_nodes.has_urandom;
		}
		if (!strcmp(dev, "zero")) {
			return dev_nodes.has_zero;
		}
		if (!strcmp(dev, "kvm")) {
			return dev_nodes.has_kvm;
		}
		if (!strcmp(dev, "gunyah")) {
			return dev_nodes.has_gunyah;
		}
		if (!strcmp(dev, "gzvm")) {
			return dev_nodes.has_gzvm;
		}
		ruri_error("{red}Unknown device: %s\n", dev);
	}
	if (req != RURI_SET_FLAG) {
		ruri_error("{red}Unknown request: %d\nThis must be an internal error QwQ", req);
	}
	// Parse flag string.
	char *value = ruri_feature_flag(RURI_QUERY_FLAG, "dev_nodes");
	if (value == NULL && dev == NULL) {
		return false;
	}
	if (dev) {
		value = ruri_malloc(strlen(value) + strlen(dev) + 2);
		strcpy(value, value);
		strcat(value, ",");
		strcat(value, dev);
	} else {
		value = strdup(value);
	}
	char *token = strtok(value, ",");
	while (token != NULL) {
		// +dev logic.
		if (!strcmp(token, "+console")) {
			dev_nodes.has_console = true;
		} else if (!strcmp(token, "+full")) {
			dev_nodes.has_full = true;
		} else if (!strcmp(token, "+null")) {
			dev_nodes.has_null = true;
		} else if (!strcmp(token, "+random")) {
			dev_nodes.has_random = true;
		} else if (!strcmp(token, "+tty")) {
			dev_nodes.has_tty = true;
		} else if (!strcmp(token, "+urandom")) {
			dev_nodes.has_urandom = true;
		} else if (!strcmp(token, "+zero")) {
			dev_nodes.has_zero = true;
		}
		if (!strcmp(token, "+kvm")) {
			dev_nodes.has_kvm = true;
		} else if (!strcmp(token, "+gunyah")) {
			dev_nodes.has_gunyah = true;
		} else if (!strcmp(token, "+gzvm")) {
			dev_nodes.has_gzvm = true;
		}
		// -dev logic.
		else if (!strcmp(token, "-console")) {
			dev_nodes.has_console = false;
		} else if (!strcmp(token, "-full")) {
			dev_nodes.has_full = false;
		} else if (!strcmp(token, "-null")) {
			dev_nodes.has_null = false;
		} else if (!strcmp(token, "-random")) {
			dev_nodes.has_random = false;
		} else if (!strcmp(token, "-tty")) {
			dev_nodes.has_tty = false;
		} else if (!strcmp(token, "-urandom")) {
			dev_nodes.has_urandom = false;
		} else if (!strcmp(token, "-zero")) {
			dev_nodes.has_zero = false;
		} else if (!strcmp(token, "-kvm")) {
			dev_nodes.has_kvm = false;
		} else if (!strcmp(token, "-gunyah")) {
			dev_nodes.has_gunyah = false;
		} else if (!strcmp(token, "-gzvm")) {
			dev_nodes.has_gzvm = false;
		}
		// Unknown device logic.
		else {
			ruri_error("{red}Unsupported device: %s\n", token);
			free(value);
			return false;
		}
		token = strtok(NULL, ",");
	}
	free(value);
	return false;
}
bool ruri_has_dev(const char *_Nonnull dev)
{
	return ruri_dev_nodes(RURI_QUERY_FLAG, dev);
}
static char *true_or_null(const char *str, const char *full_flag)
{
	/*
	 * This function is used to convert a string to a boolean value.
	 *
	 * return strdup("true") if the string is "=true", "=1", or ""
	 * return NULL if the string is "=false" or "=0"
	 * panic if the string is anything else.
	 *
	 */
	if (str[0] == 0) {
		return strdup("true");
	}
	if (!strcmp(str, "=true")) {
		return strdup("true");
	}
	if (!strcmp(str, "=false")) {
		return NULL;
	}
	if (!strcmp(str, "=1")) {
		return strdup("true");
	}
	if (!strcmp(str, "=0")) {
		return NULL;
	}
	ruri_error("{red}Unknown flag: %s, for value `%s`\n", full_flag, str);
}
// Feature flags.
char *ruri_feature_flag(int req, const char *_Nonnull flag)
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
	} flags = { // clang-format off
		.ban_futex_pi = NULL,
		.wait_before_exec = NULL,
		.allow_personality = NULL,
		.force_panic = NULL,
		.no_time_ns = NULL,
		.no_uts_ns = NULL,
		.no_ipc_ns = NULL,
		.no_pid_ns = NULL,
		.no_cgroup_ns = NULL,
		.meow = NULL,
		.fork_as_init = NULL,
		.disable_warnings = NULL,
		.auto_umount = NULL,
		.auto_umount_on_panic = NULL,
		.systemd_init = NULL,
		.is_health_check = NULL,
		.enable_tty_signals = NULL,
		.skip_setgroups = NULL,
		.empty_net_ns = NULL,
		.no_reset_pidfile = NULL,
		.no_logs = NULL,
		.wait_pidfile_lock = NULL,
		.no_seccomp = NULL,
		.no_rurienv = NULL,
		.no_cgroup = NULL,
		.no_pidfile_daemon = NULL,
		.no_drop_caps = NULL,
		.no_memory_cgroup = NULL,
		.no_cpuset_cgroup = NULL,
		.no_cpupercent_cgroup = NULL,
		.no_pids_cgroup = NULL,
		.no_io_cgroup = NULL,
		.no_freezer_cgroup = NULL,
		.no_pidfd = NULL,
		.dev_nodes = NULL
	};
	// clang-format on
	if (req == RURI_QUERY_FLAG) {
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
		if (!strcmp(flag, "empty_net_ns")) {
			return flags.empty_net_ns;
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
		if (!strcmp(flag, "no_pidfile_daemon")) {
			return flags.no_pidfile_daemon;
		}
		if (!strcmp(flag, "no_drop_caps")) {
			return flags.no_drop_caps;
		}
		if (!strcmp(flag, "no_memory_cgroup")) {
			return flags.no_memory_cgroup;
		}
		if (!strcmp(flag, "no_cpuset_cgroup")) {
			return flags.no_cpuset_cgroup;
		}
		if (!strcmp(flag, "no_cpupercent_cgroup")) {
			return flags.no_cpupercent_cgroup;
		}
		if (!strcmp(flag, "no_pids_cgroup")) {
			return flags.no_pids_cgroup;
		}
		if (!strcmp(flag, "no_io_cgroup")) {
			return flags.no_io_cgroup;
		}
		if (!strcmp(flag, "no_freezer_cgroup")) {
			return flags.no_freezer_cgroup;
		}
		if (!strcmp(flag, "no_pidfd")) {
			return flags.no_pidfd;
		}
		if (!strcmp(flag, "dev_nodes")) {
			return flags.dev_nodes;
		}
		ruri_error("{red}Unknown flag: %s\n", flag);
		return "unknown";
	}
	if (req != RURI_SET_FLAG) {
		ruri_error("{red}Unknown request: %d\nThis must be an internal error QwQ", req);
		return NULL;
	}
	if (!strncmp(flag, "ban_futex_pi", strlen("ban_futex_pi"))) {
		free(flags.ban_futex_pi);
		flags.ban_futex_pi = true_or_null(flag + strlen("ban_futex_pi"), flag);
		return flags.ban_futex_pi;
	}
	if (!strncmp(flag, "wait_before_exec", strlen("wait_before_exec"))) {
		free(flags.wait_before_exec);
		flags.wait_before_exec = true_or_null(flag + strlen("wait_before_exec"), flag);
		return flags.wait_before_exec;
	}
	if (!strncmp(flag, "allow_personality", strlen("allow_personality"))) {
		free(flags.allow_personality);
		flags.allow_personality = true_or_null(flag + strlen("allow_personality"), flag);
		return flags.allow_personality;
	}
	if (!strncmp(flag, "force_panic", strlen("force_panic"))) {
		free(flags.force_panic);
		flags.force_panic = true_or_null(flag + strlen("force_panic"), flag);
		return flags.force_panic;
	}
	if (!strncmp(flag, "no_time_ns", strlen("no_time_ns"))) {
		free(flags.no_time_ns);
		flags.no_time_ns = true_or_null(flag + strlen("no_time_ns"), flag);
		return flags.no_time_ns;
	}
	if (!strncmp(flag, "no_uts_ns", strlen("no_uts_ns"))) {
		free(flags.no_uts_ns);
		flags.no_uts_ns = true_or_null(flag + strlen("no_uts_ns"), flag);
		return flags.no_uts_ns;
	}
	if (!strncmp(flag, "no_ipc_ns", strlen("no_ipc_ns"))) {
		free(flags.no_ipc_ns);
		flags.no_ipc_ns = true_or_null(flag + strlen("no_ipc_ns"), flag);
		return flags.no_ipc_ns;
	}
	if (!strncmp(flag, "no_pid_ns", strlen("no_pid_ns"))) {
		free(flags.no_pid_ns);
		flags.no_pid_ns = true_or_null(flag + strlen("no_pid_ns"), flag);
		return flags.no_pid_ns;
	}
	if (!strncmp(flag, "no_cgroup_ns", strlen("no_cgroup_ns"))) {
		free(flags.no_cgroup_ns);
		flags.no_cgroup_ns = true_or_null(flag + strlen("no_cgroup_ns"), flag);
		return flags.no_cgroup_ns;
	}
	if (!strncmp(flag, "meow", strlen("meow"))) {
		free(flags.meow);
		flags.meow = true_or_null(flag + strlen("meow"), flag);
		return flags.meow;
	}
	if (!strncmp(flag, "fork_as_init", strlen("fork_as_init"))) {
		free(flags.fork_as_init);
		flags.fork_as_init = true_or_null(flag + strlen("fork_as_init"), flag);
		return flags.fork_as_init;
	}
	if (!strncmp(flag, "disable_warnings", strlen("disable_warnings"))) {
		free(flags.disable_warnings);
		flags.disable_warnings = true_or_null(flag + strlen("disable_warnings"), flag);
		return flags.disable_warnings;
	}
	if (!strncmp(flag, "auto_umount_on_panic", strlen("auto_umount_on_panic"))) {
		free(flags.auto_umount_on_panic);
		flags.auto_umount_on_panic = true_or_null(flag + strlen("auto_umount_on_panic"), flag);
		return flags.auto_umount_on_panic;
	}
	if (!strncmp(flag, "auto_umount", strlen("auto_umount"))) {
		free(flags.auto_umount);
		flags.auto_umount = true_or_null(flag + strlen("auto_umount"), flag);
		return flags.auto_umount;
	}
	if (!strncmp(flag, "systemd_init", strlen("systemd_init"))) {
		free(flags.systemd_init);
		flags.systemd_init = true_or_null(flag + strlen("systemd_init"), flag);
		return flags.systemd_init;
	}
	if (!strncmp(flag, "is_health_check", strlen("is_health_check"))) {
		free(flags.is_health_check);
		flags.is_health_check = true_or_null(flag + strlen("is_health_check"), flag);
		return flags.is_health_check;
	}
	if (!strncmp(flag, "enable_tty_signals", strlen("enable_tty_signals"))) {
		free(flags.enable_tty_signals);
		flags.enable_tty_signals = true_or_null(flag + strlen("enable_tty_signals"), flag);
		return flags.enable_tty_signals;
	}
	if (!strncmp(flag, "skip_setgroups", strlen("skip_setgroups"))) {
		free(flags.skip_setgroups);
		flags.skip_setgroups = true_or_null(flag + strlen("skip_setgroups"), flag);
		return flags.skip_setgroups;
	}
	if (!strncmp(flag, "create_kvm_node", strlen("create_kvm_node"))) {
		// Update dev_nodes string to include +kvm or -kvm.
		char *enable_kvm = true_or_null(flag + strlen("create_kvm_node"), flag);
		if (enable_kvm) {
			ruri_dev_nodes(RURI_SET_FLAG, "+kvm");
		} else {
			ruri_dev_nodes(RURI_SET_FLAG, "-kvm");
		}
		free(enable_kvm);
		return NULL;
	}
	if (!strncmp(flag, "empty_net_ns", strlen("empty_net_ns"))) {
		free(flags.empty_net_ns);
		flags.empty_net_ns = true_or_null(flag + strlen("empty_net_ns"), flag);
		return flags.empty_net_ns;
	}
	if (!strncmp(flag, "create_gunyah_node", strlen("create_gunyah_node"))) {
		// Update dev_nodes string to include +gunyah or -gunyah.
		char *enable_gunyah = true_or_null(flag + strlen("create_gunyah_node"), flag);
		if (enable_gunyah) {
			ruri_dev_nodes(RURI_SET_FLAG, "+gunyah");
		} else {
			ruri_dev_nodes(RURI_SET_FLAG, "-gunyah");
		}
		free(enable_gunyah);
		return NULL;
	}
	if (!strncmp(flag, "create_geniezone_node", strlen("create_geniezone_node"))) {
		// Update dev_nodes string to include +gzvm or -gzvm.
		char *enable_gzvm = true_or_null(flag + strlen("create_geniezone_node"), flag);
		if (enable_gzvm) {
			ruri_dev_nodes(RURI_SET_FLAG, "+gzvm");
		} else {
			ruri_dev_nodes(RURI_SET_FLAG, "-gzvm");
		}
		free(enable_gzvm);
		return NULL;
	}
	if (!strncmp(flag, "no_reset_pidfile", strlen("no_reset_pidfile"))) {
		free(flags.no_reset_pidfile);
		flags.no_reset_pidfile = true_or_null(flag + strlen("no_reset_pidfile"), flag);
		return flags.no_reset_pidfile;
	}
	if (!strncmp(flag, "no_logs", strlen("no_logs"))) {
		free(flags.no_logs);
		flags.no_logs = true_or_null(flag + strlen("no_logs"), flag);
		return flags.no_logs;
	}
	if (!strncmp(flag, "wait_pidfile_lock", strlen("wait_pidfile_lock"))) {
		free(flags.wait_pidfile_lock);
		flags.wait_pidfile_lock = true_or_null(flag + strlen("wait_pidfile_lock"), flag);
		return flags.wait_pidfile_lock;
	}
	if (!strncmp(flag, "no_seccomp", strlen("no_seccomp"))) {
		free(flags.no_seccomp);
		flags.no_seccomp = true_or_null(flag + strlen("no_seccomp"), flag);
		return flags.no_seccomp;
	}
	if (!strncmp(flag, "no_rurienv", strlen("no_rurienv"))) {
		free(flags.no_rurienv);
		flags.no_rurienv = true_or_null(flag + strlen("no_rurienv"), flag);
		return flags.no_rurienv;
	}
	if (!strncmp(flag, "no_cgroup", strlen("no_cgroup"))) {
		free(flags.no_cgroup);
		flags.no_cgroup = true_or_null(flag + strlen("no_cgroup"), flag);
		return flags.no_cgroup;
	}
	if (!strncmp(flag, "no_pidfile_daemon", strlen("no_pidfile_daemon"))) {
		free(flags.no_pidfile_daemon);
		flags.no_pidfile_daemon = true_or_null(flag + strlen("no_pidfile_daemon"), flag);
		return flags.no_pidfile_daemon;
	}
	if (!strncmp(flag, "no_drop_caps", strlen("no_drop_caps"))) {
		free(flags.no_drop_caps);
		flags.no_drop_caps = true_or_null(flag + strlen("no_drop_caps"), flag);
		return flags.no_drop_caps;
	}
	if (!strncmp(flag, "no_memory_cgroup", strlen("no_memory_cgroup"))) {
		free(flags.no_memory_cgroup);
		flags.no_memory_cgroup = true_or_null(flag + strlen("no_memory_cgroup"), flag);
		return flags.no_memory_cgroup;
	}
	if (!strncmp(flag, "no_cpuset_cgroup", strlen("no_cpuset_cgroup"))) {
		free(flags.no_cpuset_cgroup);
		flags.no_cpuset_cgroup = true_or_null(flag + strlen("no_cpuset_cgroup"), flag);
		return flags.no_cpuset_cgroup;
	}
	if (!strncmp(flag, "no_cpupercent_cgroup", strlen("no_cpupercent_cgroup"))) {
		free(flags.no_cpupercent_cgroup);
		flags.no_cpupercent_cgroup = true_or_null(flag + strlen("no_cpupercent_cgroup"), flag);
		return flags.no_cpupercent_cgroup;
	}
	if (!strncmp(flag, "no_pids_cgroup", strlen("no_pids_cgroup"))) {
		free(flags.no_pids_cgroup);
		flags.no_pids_cgroup = true_or_null(flag + strlen("no_pids_cgroup"), flag);
		return flags.no_pids_cgroup;
	}
	if (!strncmp(flag, "no_io_cgroup", strlen("no_io_cgroup"))) {
		free(flags.no_io_cgroup);
		flags.no_io_cgroup = true_or_null(flag + strlen("no_io_cgroup"), flag);
		return flags.no_io_cgroup;
	}
	if (!strncmp(flag, "no_freezer_cgroup", strlen("no_freezer_cgroup"))) {
		free(flags.no_freezer_cgroup);
		flags.no_freezer_cgroup = true_or_null(flag + strlen("no_freezer_cgroup"), flag);
		return flags.no_freezer_cgroup;
	}
	if (!strncmp(flag, "no_pidfd", strlen("no_pidfd"))) {
		free(flags.no_pidfd);
		flags.no_pidfd = true_or_null(flag + strlen("no_pidfd"), flag);
		return flags.no_pidfd;
	}
	if (!strncmp(flag, "dev_nodes=", strlen("dev_nodes="))) {
		free(flags.dev_nodes);
		if (strlen(flag) == strlen("dev_nodes=")) {
			flags.dev_nodes = NULL;
			return flags.dev_nodes;
		}
		flags.dev_nodes = strdup(flag + strlen("dev_nodes="));
		ruri_dev_nodes(RURI_SET_FLAG, NULL); // Update dev_nodes struct.
		return flags.dev_nodes;
	}
	ruri_error("{red}Unknown flag: %s\n", flag);
	return "unknown";
}
bool ruri_flag(char *_Nonnull flag)
{
	char *value = ruri_feature_flag(RURI_QUERY_FLAG, flag);
	if (value == NULL) {
		return false;
	}
	if (!strcmp(value, "true")) {
		return true;
	}
	return false;
}
void ruri_set_flag(const char *_Nonnull flag)
{
	ruri_feature_flag(RURI_SET_FLAG, flag);
}