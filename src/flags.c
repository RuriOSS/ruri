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
bool ruri_dev_nodes(int req, const char *_Nonnull dev, size_t offset)
{
	static thread_local struct RURI_DEV_NODES dev_nodes = {
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
		.has_gzvm = false,
		.has_devpts = true,
		.has_devshm = true,
		.has_net_tun = true,
		// clang-format on
	};
	if (req == RURI_QUERY_FLAG) {
		if (offset >= sizeof(struct RURI_DEV_NODES)) {
			ruri_error("{red}Unknown offset: %zu\nThis must be an internal error QwQ", offset);
		}
		return *(bool *)((char *)&dev_nodes + offset);
	}
	if (req != RURI_SET_FLAG) {
		ruri_error("{red}Unknown request: %d\nThis must be an internal error QwQ", req);
	}
	// Parse flag string.
	char *value = ruri_feature_flag(RURI_QUERY_FLAG, NULL, offsetof(struct RURI_FLAGS, dev_nodes));
	char *new_value = NULL;
	if (value == NULL && dev == NULL) {
		return false;
	}
	if (dev) {
		if (value) {
			new_value = ruri_malloc(strlen(value) + strlen(dev) + 2);
			strcpy(new_value, value);
			strcat(new_value, ",");
			strcat(new_value, dev);
		} else {
			new_value = strdup(dev);
		}
	} else {
		if (value) {
			new_value = strdup(value);
		} else {
			return false;
		}
	}
	char *token = strtok(new_value, ",");
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
		} else if (!strcmp(token, "+kvm")) {
			dev_nodes.has_kvm = true;
		} else if (!strcmp(token, "+gunyah")) {
			dev_nodes.has_gunyah = true;
		} else if (!strcmp(token, "+gzvm")) {
			dev_nodes.has_gzvm = true;
		} else if (!strcmp(token, "+devpts")) {
			dev_nodes.has_devpts = true;
		} else if (!strcmp(token, "+devshm")) {
			dev_nodes.has_devshm = true;
		} else if (!strcmp(token, "+net_tun")) {
			dev_nodes.has_net_tun = true;
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
		} else if (!strcmp(token, "-devpts")) {
			dev_nodes.has_devpts = false;
		} else if (!strcmp(token, "-devshm")) {
			dev_nodes.has_devshm = false;
		} else if (!strcmp(token, "-net_tun")) {
			dev_nodes.has_net_tun = false;
		}
		// Unknown device logic.
		else {
			ruri_error("{red}Unsupported device: %s\n", token);
			free(new_value);
			return false;
		}
		token = strtok(NULL, ",");
	}
	free(new_value);
	return false;
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
char *ruri_feature_flag(int req, const char *_Nonnull flag, size_t offset)
{
	/*
	 * We set all value to char*,
	 * because we will have someting like flag_foo="bar" in the future.
	 * -1 for query, other value for set.
	 */
	static struct RURI_FLAGS flags = {
		// clang-format off
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
		.dev_nodes = NULL,
		.just_chroot = NULL,
		.ruri_dbg = NULL,
		.use_host_runtime = NULL,
		.no_mask_paths = NULL,
		.read_only_rootfs = NULL,
		.no_new_privs = NULL,
		.rlimits = NULL,
		.outside_rurienv = NULL,
		.rw_rurienv = NULL,
		.ruri_perf = NULL,
		.is_termux=NULL,
		.img_sectx=NULL,
	};
	// clang-format on
	if (req == RURI_QUERY_FLAG) {
		if (offset >= sizeof(struct RURI_FLAGS)) {
			ruri_error("{red}Unknown offset: %zu\nThis must be an internal error QwQ", offset);
		}
		return *(char **)((char *)&flags + offset);
	}
	if (req != RURI_SET_FLAG) {
		ruri_error("{red}Unknown request: %d\nThis must be an internal error QwQ", req);
		return NULL;
	}
	ruri_flags_buf(RURI_SET_FLAG, flag);
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
			ruri_dev_nodes(RURI_SET_FLAG, "+kvm", 0);
		} else {
			ruri_dev_nodes(RURI_SET_FLAG, "-kvm", 0);
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
			ruri_dev_nodes(RURI_SET_FLAG, "+gunyah", 0);
		} else {
			ruri_dev_nodes(RURI_SET_FLAG, "-gunyah", 0);
		}
		free(enable_gunyah);
		return NULL;
	}
	if (!strncmp(flag, "create_geniezone_node", strlen("create_geniezone_node"))) {
		// Update dev_nodes string to include +gzvm or -gzvm.
		char *enable_gzvm = true_or_null(flag + strlen("create_geniezone_node"), flag);
		if (enable_gzvm) {
			ruri_dev_nodes(RURI_SET_FLAG, "+gzvm", 0);
		} else {
			ruri_dev_nodes(RURI_SET_FLAG, "-gzvm", 0);
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
		ruri_dev_nodes(RURI_SET_FLAG, NULL, 0); // Update dev_nodes struct.
		return flags.dev_nodes;
	}
	if (!strncmp(flag, "just_chroot", strlen("just_chroot"))) {
		free(flags.just_chroot);
		flags.just_chroot = true_or_null(flag + strlen("just_chroot"), flag);
		return flags.just_chroot;
	}
	if (!strncmp(flag, "ruri_dbg", strlen("ruri_dbg"))) {
		free(flags.ruri_dbg);
		flags.ruri_dbg = true_or_null(flag + strlen("ruri_dbg"), flag);
		return flags.ruri_dbg;
	}
	if (!strncmp(flag, "use_host_runtime", strlen("use_host_runtime"))) {
		free(flags.use_host_runtime);
		flags.use_host_runtime = true_or_null(flag + strlen("use_host_runtime"), flag);
		return flags.use_host_runtime;
	}
	if (!strncmp(flag, "no_mask_paths", strlen("no_mask_paths"))) {
		free(flags.no_mask_paths);
		flags.no_mask_paths = true_or_null(flag + strlen("no_mask_paths"), flag);
		return flags.no_mask_paths;
	}
	if (!strncmp(flag, "read_only_rootfs", strlen("read_only_rootfs"))) {
		free(flags.read_only_rootfs);
		flags.read_only_rootfs = true_or_null(flag + strlen("read_only_rootfs"), flag);
		return flags.read_only_rootfs;
	}
	if (!strncmp(flag, "no_new_privs", strlen("no_new_privs"))) {
		free(flags.no_new_privs);
		flags.no_new_privs = true_or_null(flag + strlen("no_new_privs"), flag);
		return flags.no_new_privs;
	}
	if (!strncmp(flag, "rlimits=", strlen("rlimits="))) {
		free(flags.rlimits);
		if (strlen(flag) == strlen("rlimits=")) {
			flags.rlimits = NULL;
			return flags.rlimits;
		}
		flags.rlimits = strdup(flag + strlen("rlimits="));
		return flags.rlimits;
	}
	if (!strncmp(flag, "outside_rurienv=", strlen("outside_rurienv="))) {
		free(flags.outside_rurienv);
		if (strlen(flag) == strlen("outside_rurienv=")) {
			flags.outside_rurienv = NULL;
			return flags.outside_rurienv;
		}
		flags.outside_rurienv = strdup(flag + strlen("outside_rurienv="));
		int fd = open(flags.outside_rurienv, O_CREAT | O_RDWR | O_CLOEXEC, S_IRUSR | S_IWUSR);
		if (fd >= 0) {
			ruri_env_fd(fd);
		} else {
			ruri_error("{red}Error: failed to open outside_rurienv fd QwQ\n");
		}
		char *rurienv_realpath = realpath(flags.outside_rurienv, NULL);
		if (rurienv_realpath) {
			free(flags.outside_rurienv);
			flags.outside_rurienv = rurienv_realpath;
		} else {
			ruri_error("{red}Error: failed to get realpath of outside_rurienv QwQ\n");
		}
		return flags.outside_rurienv;
	}
	if (!strncmp(flag, "rw_rurienv", strlen("rw_rurienv"))) {
		free(flags.rw_rurienv);
		flags.rw_rurienv = true_or_null(flag + strlen("rw_rurienv"), flag);
		return flags.rw_rurienv;
	}
	if (!strncmp(flag, "ruri_perf", strlen("ruri_perf"))) {
		free(flags.ruri_perf);
		flags.ruri_perf = true_or_null(flag + strlen("ruri_perf"), flag);
		return flags.ruri_perf;
	}
	if (!strncmp(flag, "is_termux", strlen("is_termux"))) {
		free(flags.is_termux);
		flags.is_termux = true_or_null(flag + strlen("is_termux"), flag);
		return flags.is_termux;
	}
	if (!strncmp(flag, "img_sectx=", strlen("img_sectx="))) {
		free(flags.img_sectx);
		if (strlen(flag) == strlen("img_sectx=")) {
			flags.img_sectx = NULL;
			return flags.img_sectx;
		}
		flags.img_sectx = strdup(flag + strlen("img_sectx="));
		return flags.img_sectx;
	}
	ruri_error("{red}Unknown flag: %s\n", flag);
	return "unknown";
}
char **ruri_flags_buf(int req, const char *_Nonnull flag)
{
	/*
	 * Save the flag to a char** buffer, so we can dump the record later.
	 */
	static thread_local char **buf = NULL;
	static thread_local size_t buf_size = 0;
	if (req == RURI_QUERY_FLAG) {
		return buf;
	}
	if (req == RURI_SET_FLAG) {
		if (!buf) {
			buf_size++;
			buf = malloc(sizeof(char *) * (buf_size + 1));
		} else {
			buf_size++;
			buf = realloc(buf, sizeof(char *) * (buf_size + 1));
		}
		buf[buf_size - 1] = strdup(flag);
		buf[buf_size] = NULL;
		return buf;
	}
	return NULL;
}
int ruri_env_fd(int fd)
{
	/*
	 * Store the fd of the rurienv file, so we can use it later.
	 */
	static thread_local int env_fd = RURI_INIT_VALUE;
	if (fd == -1) {
		return env_fd;
	}
	env_fd = fd;
	return env_fd;
}