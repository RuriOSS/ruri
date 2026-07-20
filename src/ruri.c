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
 * This file was the main.c of ruri.
 * It will parse the arguments, and do the action.
 * I know code here is too shit, but it works,
 * maybe I will rewrite it one day, I hope.
 */
// For profiling.
long long ruri_diff_time(void)
{
	static thread_local long long last_nsec = 0;
	long long ret = 0;
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	if (last_nsec > 0) {
		ret = now.tv_nsec - last_nsec;
		last_nsec = now.tv_nsec;
		return ret;
	} else {
		last_nsec = now.tv_nsec;
		return 0;
	}
}
static void ruri_meow(void)
{
	char *meows[] = { "≽^•⩊•^≼", "^•ω•^=", "₍^ >ヮ<^₎", "~(=^‥^)", "/ᐠ｡ꞈ｡ᐟ\\", "/ᐠ .ᆺ. ᐟ\\ﾉ", "₍^. .^₎⟆", "ᓚ₍⑅^..^₎♡", "/ᐠ - ˕ -マ", "^. .^₎Ⳋ", "/ᐠ ¬`‸´¬ マ", "⚞ • ⚟", "/ᐠ ˵> ˕ <˵マ", "ᗜ⩊ᗜ", "(˵◝ ⩊  ◜˵マ", "(•˕ •マ.ᐟ", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL };
	// NOLINTBEGIN
	// Get a random meow
	srand(time(NULL));
	int random_index = rand() % (int)(sizeof(meows) / sizeof(meows[0]));
	// NOLINTEND
	if (meows[random_index]) {
		cprintf("\n{base}  %s{clear}\n", meows[random_index]);
		cprintf("{base}How do you meow?{clear}\n");
	} else {
		switch (rand() % 5) {
		case 0:
			ruri_hoppou_art();
			break;
		case 1:
			cprintf("  {black}[255;115;108]/ᐠ˵>˕<˵マ{clear}\n");
			cprintf("{base}How do you meow?{clear}\n");
			break;
		case 2:
			cprintf("  {black}[121;167;252]₍ ^. .^₎Ⳋ{clear}\n");
			cprintf("{base}How do you meow?{clear}\n");
			break;
		case 3:
			cprintf("  {black}[255;174;193]^>_<^= ₎~{clear}\n");
			cprintf("{base}How do you meow?{clear}\n");
			break;
		case 4:
			cprintf("  {black}[255;226;2]₍^ >ヮ<^₎{clear}\n");
			cprintf("{base}How do you meow?{clear}\n");
			break;
		}
	}
	exit(EXIT_SUCCESS);
}
// Clear environment variables.
void ruri_clear_env(char *const *_Nonnull argv)
{
	/*
	 * This function will:
	 * - Clear the environment variables.
	 * - Re-exec the ruri binary from the memfd.
	 */
	// Save $PATH.
	char *path_env_cont = getenv("PATH");
	char *path_env = NULL;
	if (path_env_cont) {
		path_env = ruri_malloc(strlen(path_env_cont) + 16);
		snprintf(path_env, strlen(path_env_cont) + 16, "PATH=%s", path_env_cont);
	}
	// Save ruri_path.
	char ruri_bin_path[PATH_MAX] = { '\0' };
	ssize_t ruri_bin_path_len = readlink("/proc/self/exe", ruri_bin_path, PATH_MAX - 1);
	if (ruri_bin_path_len <= 0) {
		snprintf(ruri_bin_path, sizeof(ruri_bin_path), "%s", "/usr/bin/ruri");
	} else {
		ruri_bin_path[ruri_bin_path_len] = '\0';
	}
	char *ruri_path_env = ruri_malloc(strlen(ruri_bin_path) + 16);
	snprintf(ruri_path_env, strlen(ruri_bin_path) + 16, "ruri_path=%s", ruri_bin_path);
	char *no_logs_env = getenv("ruri_no_logs");
	if (no_logs_env) {
		no_logs_env = strdup("ruri_no_logs=1");
	} else {
		no_logs_env = NULL;
	}
	char *envp[] = { "ruri_rexec=1", path_env, ruri_path_env, no_logs_env, NULL };
	if (getenv("ruri_rexec") == NULL) {
		// Use memfd to store ruri binary.
		// This is to prevent ruri binary from being modified by the container.
		int fd = memfd_create("ruri_bin", MFD_CLOEXEC | MFD_ALLOW_SEALING);
		if (fd < 0) {
			ruri_warn_on_error(0, 1, true, "Failed to create memfd for ruri binary\n");
			execve("/proc/self/exe", argv, envp);
			ruri_error("{red}Failed to re-exec ruri binary QwQ\n");
		}
		// Set the file as executable.
		fchmod(fd, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IWOTH | S_IXOTH);
		// Read the ruri binary from /proc/self/exe and write it to the memfd.
		int orig_fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
		char buf[4096];
		ssize_t bytes_read = 0;
		while ((bytes_read = read(orig_fd, buf, sizeof(buf))) > 0) {
			if (write(fd, buf, (size_t)bytes_read) < 0) {
				execve("/proc/self/exe", argv, envp);
			}
		}
		close(orig_fd);
		// Seal the memfd to prevent it from being modified.
		fcntl(fd, F_ADD_SEALS, F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_SEAL);
		// Replace the current process with the ruri binary in memfd.
		char path[PATH_MAX];
		snprintf(path, sizeof(path), "/proc/%d/fd/%d", getpid(), fd);
		if (execve(path, argv, envp) < 0) {
			execve("/proc/self/exe", argv, envp);
		}
	} else {
		free(path_env);
		free(no_logs_env);
		free(ruri_path_env);
		return;
	}
}
// Do some checks before chroot(2),called by main().
static void check_container(const struct RURI_CONTAINER *_Nonnull container)
{
	/*
	 * It's called by main() to check if container config is correct.
	 * It will also check the running environment.
	 * Note that it can only do basic checks,
	 * and we can't know if the config can really run a container properly.
	 */
	// Check if container directory is given.
	if (container->container_dir == NULL) {
		ruri_error("{red}Error: container directory is not set or does not exist QwQ\n");
	}
	// Refuse to use `/` for container directory.
	if (strcmp(container->container_dir, "/") == 0) {
		ruri_error("{red}Error: `/` is not allowed to use as a container directory QwQ\n");
	}
	// rootless container should not be run with root privileges.
	if (container->rootless && (geteuid() == 0 || getuid() == 0 || getgid() == 0 || getegid() == 0)) {
		ruri_error("{red}Error: rootless container should not be run with root privileges QwQ\n");
	}
	// `--arch` and `--qemu-path` should be set at the same time.
	if ((container->cross_arch == NULL) != (container->qemu_path == NULL)) {
		ruri_error("{red}Error: --arch and --qemu-path should be set at the same time QwQ\n");
	}
	for (int i = 0; container->extra_mountpoint[i] != NULL; i++) {
		if (strlen(container->extra_mountpoint[i]) > PATH_MAX) {
			ruri_error("{red}Error: mountpoint path is too long QwQ\n");
		}
	}
	for (int i = 0; container->extra_ro_mountpoint[i] != NULL; i++) {
		if (strlen(container->extra_ro_mountpoint[i]) > PATH_MAX) {
			ruri_error("{red}Error: mountpoint path is too long QwQ\n");
		}
	}
	if (ruri_flag(systemd_init) && ruri_flag(use_host_runtime)) {
		ruri_error("{red}Error: --systemd should not run with --mount-host-runtime QwQ\n");
	}
	// If container_dir/.rurienv and container_dir/.ruri_umounted both exists, panic.
	// Get current working directory.
	char cwd[PATH_MAX];
	if (getcwd(cwd, sizeof(cwd)) == NULL) {
		ruri_error("{red}Error: getcwd() failed QwQ\n");
	}
	if (chdir(container->container_dir) != 0) {
		ruri_error("{red}Error: chdir() failed QwQ\n");
	}
	if (access(".rurienv", F_OK) == 0 && access(".ruri_umounted", F_OK) == 0) {
		ruri_warning("{red}Error: .ruri_umounted and .rurienv both exists, this can only happen when ruri has a bug or container is hacked QwQ\n");
	}
	remove("./.ruri_umounted");
	unlink("./.ruri_umounted");
	rmdir("./.ruri_umounted");
	// chdir() back.
	if (chdir(cwd) != 0) {
		ruri_error("{red}Error: chdir() failed QwQ\n");
	}
}
static void parse_cgroup_settings(const char *_Nonnull str, struct RURI_CONTAINER *_Nonnull container)
{
	/*
	 * Parse and set cgroup limit.
	 * The format should be like `cpuset=1` or `memory=1M`.
	 * We will not check if the config is valid.
	 */
	char buf[16] = { '\0' };
	char *limit = NULL;
	// Get limit type.
	for (size_t i = 0; i < 15; i++) {
		// Avoid overflow.
		if (i >= strlen(str)) {
			break;
		}
		if (str[i] == '=') {
			limit = strdup(&(str[i + 1]));
			break;
		}
		buf[i] = str[i];
		buf[i + 1] = '\0';
	}
	if (limit == NULL) {
		ruri_error("{red}Error: cgroup limit should be like `cpuset=1` or `memory=1M`\n");
	}
	if (strcmp("cpuset", buf) == 0) {
		container->cpuset = limit;
	} else if (strcmp("memory", buf) == 0) {
		container->memory = limit;
	} else if (strcmp("cpupercent", buf) == 0) {
		container->cpupercent = atoi(limit);
		free(limit);
		if (container->cpupercent < 1 || container->cpupercent > 100) {
			ruri_error("{red}Error: cpupercent should be in range 1-100\n");
		}
	} else if (strcmp("pids", buf) == 0) {
		container->max_pids = atoi(limit);
		free(limit);
		if (container->max_pids < 1) {
			ruri_error("{red}Error: pids should be a positive number\n");
		}
	} else if (strcmp("io_rbps", buf) == 0) {
		container->io_rbps = limit;
	} else if (strcmp("io_wbps", buf) == 0) {
		container->io_wbps = limit;
	} else if (strcmp("io_device", buf) == 0) {
		container->io_device = limit;
	} else {
		ruri_error("{red}Unknown cgroup option %s\n", str);
	}
}
static bool is_container_dir(char *dir)
{
	/*
	 * Check if the given directory is a container directory.
	 * It will only check if the directory exists now.
	 */
	if (dir == NULL) {
		ruri_warning("{red}Error: container directory is not set or does not exist QwQ{clear}\n");
		return false;
	}
	struct stat st;
	// Directory does not exist.
	if (stat(dir, &st) != 0) {
		ruri_warning("{red}Error: container directory does not exist QwQ{clear}\n");
		return false;
	}
	// Not a directory.
	if (!S_ISDIR(st.st_mode)) {
		ruri_warning("{red}Error: container directory is not a directory QwQ{clear}\n");
		return false;
	}
	return true;
}
void ruri_check_container_dir(char *dir)
{
	/*
	 * Check if the container directory is valid.
	 * If it's not valid, we will panic the container.
	 */
	if (!is_container_dir(dir)) {
		ruri_error("{red}Error: container directory does not exist QwQ\n");
	}
}

static void parse_args(int argc, char **_Nonnull argv, struct RURI_CONTAINER *_Nonnull container)
{
	/*
	 * 100% shit-code here.
	 * But anyway, Fuck U LLMs, U just rewrite this for me or no shitting for my code.
	 * U never know that only working code can become good code.
	 * At least it works...
	 * It has cognitive complexity of 120+, be happy reading~
	 * If the code is hard to write,
	 * it should be hard to read nya~
	 */
	// Check if arguments are given.
	if (argc <= 1) {
		cfprintf(stderr, "{red}Error: too few arguments QwQ{clear}\n");
		ruri_show_helps();
		exit(114);
	}
	// Init configs.
	bool even_unstable = false;
	bool fork_exec = false;
	bool dump_config = false;
	char *output_path = NULL;
	cap_value_t keep_caplist_extra[RURI_CAP_LAST_CAP + 1] = { RURI_INIT_VALUE };
	cap_value_t drop_caplist_extra[RURI_CAP_LAST_CAP + 1] = { RURI_INIT_VALUE };
	cap_value_t cap = RURI_INIT_VALUE;
	bool privileged = false;
	bool use_config_file = false;
	bool background = false;
	char *log_file = NULL;
	ruri_init_config(container);
	// A very large and shit-code for() loop.
	// At least it works fine...
	for (int index = 1; index < argc; index++) {
		/**** For other options ****/
		// As an easter egg.
		if (strcmp(argv[index], "AwA") == 0) {
			ruri_AwA();
			exit(EXIT_SUCCESS);
		}
		// Meow~
		if (strcmp(argv[index], "meow") == 0) {
			ruri_meow();
		}
		// Show version info.
		if (strcmp(argv[index], "-v") == 0 || strcmp(argv[index], "--version") == 0) {
			ruri_show_version_info();
			exit(EXIT_SUCCESS);
		}
		// Show version code, very useless right now.
		if (strcmp(argv[index], "-V") == 0 || strcmp(argv[index], "--version-code") == 0) {
			ruri_show_version_code();
			exit(EXIT_SUCCESS);
		}
		// Show help page.
		if (strcmp(argv[index], "-h") == 0 || strcmp(argv[index], "--help") == 0) {
			ruri_show_helps();
			exit(EXIT_SUCCESS);
		}
		// Show help page and example usage.
		if (strcmp(argv[index], "-H") == 0 || strcmp(argv[index], "--show-examples") == 0) {
			ruri_show_examples();
			exit(EXIT_SUCCESS);
		}
		// Show neofeth-like ruri version info.
		if (strcmp(argv[index], "-F") == 0 || strcmp(argv[index], "--ruri-fetch") == 0) {
			ruri_fetch();
			exit(EXIT_SUCCESS);
		}
		// Umount a container.
		if (strcmp(argv[index], "-U") == 0 || strcmp(argv[index], "--umount") == 0) {
			index += 1;
			struct stat st;
			if (stat(argv[index], &st) != 0) {
				ruri_error("{red}Container directory or config does not exist QwQ\n");
			}
			if (S_ISDIR(st.st_mode)) {
				char *container_dir = realpath(argv[index], NULL);
				ruri_umount_container(container_dir);
				free(container_dir);
				exit(EXIT_SUCCESS);
			} else if (S_ISREG(st.st_mode)) {
				ruri_read_config(container, argv[index]);
				ruri_umount_container(container->container_dir);
				exit(EXIT_SUCCESS);
			} else {
				ruri_error("{red}Error: unknown file type QwQ\n");
			}
			exit(114);
		}
		// Show process status of a container.
		if (strcmp(argv[index], "-P") == 0 || strcmp(argv[index], "--ps") == 0) {
			index += 1;
			struct stat st;
			if (stat(argv[index], &st) != 0) {
				ruri_error("{red}Container directory or config does not exist QwQ\n");
			}
			if (S_ISDIR(st.st_mode)) {
				char *container_dir = realpath(argv[index], NULL);
				ruri_container_ps(container_dir);
				exit(EXIT_SUCCESS);
			} else if (S_ISREG(st.st_mode)) {
				ruri_read_config(container, argv[index]);
				ruri_container_ps(container->container_dir);
				exit(EXIT_SUCCESS);
			} else {
				ruri_error("{red}Error: unknown file type QwQ\n");
			}
			exit(114);
		}
		// --stat
		if (strcmp(argv[index], "--stat") == 0) {
			index += 1;
			char *pid_file = NULL;
			if (argv[index] != NULL) {
				pid_file = argv[index];
			}
			ruri_stat(pid_file);
			exit(EXIT_FAILURE);
		}
		// Freeze (pause) a container via cgroup freezer.
		if (strcmp(argv[index], "--freeze") == 0) {
			index += 1;
			struct stat st;
			if (stat(argv[index], &st) != 0) {
				ruri_error("{red}Container directory or config does not exist QwQ\n");
			}
			int ret;
			if (S_ISDIR(st.st_mode)) {
				struct RURI_CONTAINER *tmp = ruri_read_info(NULL, argv[index]);
				if (tmp->container_id < 0) {
					ruri_error("{red}Error: container is not running, cannot freeze QwQ\n");
				}
				ret = ruri_freeze_container(tmp->container_id);
				free(tmp);
			} else if (S_ISREG(st.st_mode)) {
				struct RURI_CONTAINER tmp;
				ruri_init_config(&tmp);
				ruri_read_config(&tmp, argv[index]);
				ret = ruri_freeze_container(tmp.container_id);
			} else {
				ruri_error("{red}Error: unknown file type QwQ\n");
			}
			if (ret != 0) {
				ruri_warning("{yellow}Failed to freeze container, cgroup freezer not available\n");
				exit(114);
			}
			exit(EXIT_SUCCESS);
		}
		// Thaw (resume) a container via cgroup freezer.
		if (strcmp(argv[index], "--thaw") == 0) {
			index += 1;
			struct stat st;
			if (stat(argv[index], &st) != 0) {
				ruri_error("{red}Container directory or config does not exist QwQ\n");
			}
			int ret;
			if (S_ISDIR(st.st_mode)) {
				struct RURI_CONTAINER *tmp = ruri_read_info(NULL, argv[index]);
				if (tmp->container_id < 0) {
					ruri_error("{red}Error: container is not running, cannot thaw QwQ\n");
				}
				ret = ruri_thaw_container(tmp->container_id);
				free(tmp);
			} else if (S_ISREG(st.st_mode)) {
				struct RURI_CONTAINER tmp;
				ruri_init_config(&tmp);
				ruri_read_config(&tmp, argv[index]);
				ret = ruri_thaw_container(tmp.container_id);
			} else {
				ruri_error("{red}Error: unknown file type QwQ\n");
			}
			if (ret != 0) {
				ruri_warning("{yellow}Failed to thaw container, cgroup freezer not available\n");
				exit(114);
			}
			exit(EXIT_SUCCESS);
		}
		// Correct a container config.
		if (strcmp(argv[index], "-C") == 0 || strcmp(argv[index], "--correct-config") == 0) {
			index += 1;
			if (argv[index] != NULL) {
				ruri_correct_config(argv[index]);
				exit(EXIT_SUCCESS);
			}
			exit(114);
		}
		/**** For running a container ****/
		// Just make clang-tidy happy.
		if (argv[index] == NULL) {
			ruri_error("{red}Failed to parse arguments.\n");
		}
		// Use config file.
		if (strcmp(argv[index], "-c") == 0 || strcmp(argv[index], "--config") == 0) {
			if (index == argc - 1) {
				ruri_error("{red}Please specify a config file !\n{clear}");
			}
			index++;
			ruri_read_config(container, argv[index]);
			use_config_file = true;
			index++;
			if (index == argc) {
				break;
			}
		}
		// Dump config.
		if (strcmp(argv[index], "-D") == 0 || strcmp(argv[index], "--dump-config") == 0) {
			dump_config = true;
		}
		// Output file.
		else if (strcmp(argv[index], "-o") == 0 || strcmp(argv[index], "--output") == 0) {
			index++;
			if (index == argc - 1) {
				ruri_error("{red}Please specify the output file\n{clear}");
			}
			output_path = argv[index];
		}
		// log file.
		else if (strcmp(argv[index], "-L") == 0 || strcmp(argv[index], "--log-file") == 0) {
			index++;
			if (index == argc - 1) {
				ruri_error("{red}Please specify the log file\n{clear}");
			}
			background = true;
			log_file = argv[index];
		}
		// Run in background.
		else if (strcmp(argv[index], "-b") == 0 || strcmp(argv[index], "--background") == 0) {
			background = true;
		}
		// Fork to exec.
		else if (strcmp(argv[index], "-f") == 0 || strcmp(argv[index], "--fork") == 0) {
			fork_exec = true;
		}
		// Set hostname.
		else if (strcmp(argv[index], "-t") == 0 || strcmp(argv[index], "--hostname") == 0) {
			if (index == argc - 1) {
				ruri_error("{red}Please specify the hostname !\n{clear}");
			}
			index++;
			container->hostname = strdup(argv[index]);
		}
		// Set no_new_privs bit.
		else if (strcmp(argv[index], "-n") == 0 || strcmp(argv[index], "--no-new-privs") == 0) {
			ruri_set_flag("no_new_privs");
		}
		// Do not store .rurienv file.
		else if (strcmp(argv[index], "-N") == 0 || strcmp(argv[index], "--no-rurienv") == 0) {
			ruri_set_flag("no_rurienv");
		}
		// Unmask dirs in /proc and /sys.
		else if (strcmp(argv[index], "-A") == 0 || strcmp(argv[index], "--unmask-dirs") == 0) {
			ruri_set_flag("no_mask_paths");
		}
		// User.
		else if (strcmp(argv[index], "-E") == 0 || strcmp(argv[index], "--user") == 0) {
			if (index == argc - 1) {
				ruri_error("{red}Please specify the user\n{clear}");
			}
			index++;
			container->user = strdup(argv[index]);
		}
		// Simulate architecture.
		else if (strcmp(argv[index], "-a") == 0 || strcmp(argv[index], "--arch") == 0) {
			if (index == argc - 1) {
				ruri_error("{red}Please specify the arch\n{clear}");
			}
			index++;
			container->cross_arch = strdup(argv[index]);
		}
		// Path of QEMU.
		else if (strcmp(argv[index], "-q") == 0 || strcmp(argv[index], "--qemu-path") == 0) {
			index++;
			if (index == argc - 1) {
				ruri_error("{red}Please specify the path of qemu binary\n{clear}");
			}
			container->qemu_path = strdup(argv[index]);
		}
		// Enable built-in seccomp profile.
		else if (strcmp(argv[index], "-s") == 0 || strcmp(argv[index], "--enable-seccomp") == 0) {
			container->enable_default_seccomp = true;
		}
		// Run unshare container.
		else if (strcmp(argv[index], "-u") == 0 || strcmp(argv[index], "--unshare") == 0) {
			container->enable_unshare = true;
		}
		// Run privileged container.
		else if (strcmp(argv[index], "-p") == 0 || strcmp(argv[index], "--privileged") == 0) {
			privileged = true;
		}
		// Run rootless container.
		else if (strcmp(argv[index], "-r") == 0 || strcmp(argv[index], "--rootless") == 0) {
			ruri_warning("{yellow}--rootless is deprecated, and ruri will automatically try rootless mode if running with root privileges.{clear}\n");
			container->rootless = true;
		}
		// Skip setting groups.
		else if (strcmp(argv[index], "-g") == 0 || strcmp(argv[index], "--skip-setgroups") == 0) {
			ruri_set_flag("skip_setgroups");
		}
		// Do not show warnings.
		else if (strcmp(argv[index], "-w") == 0 || strcmp(argv[index], "--no-warnings") == 0) {
			ruri_set_flag("disable_warnings");
		}
		// Just chroot.
		else if (strcmp(argv[index], "-j") == 0 || strcmp(argv[index], "--just-chroot") == 0) {
			ruri_set_flag("just_chroot");
		}
		// Force bind-mount host /dev/, /sys/ and /proc/.
		else if (strcmp(argv[index], "-S") == 0 || strcmp(argv[index], "--host-runtime") == 0) {
			ruri_set_flag("use_host_runtime");
		}
		// Mount / as read-only.
		else if (strcmp(argv[index], "-R") == 0 || strcmp(argv[index], "--read-only") == 0) {
			ruri_set_flag("read_only_root");
		}
		// No network.
		else if (strcmp(argv[index], "-x") == 0 || strcmp(argv[index], "--no-network") == 0) {
			container->enable_unshare = true;
			ruri_set_flag("empty_net_ns");
		}
		// Use kvm.
		else if (strcmp(argv[index], "-K") == 0 || strcmp(argv[index], "--use-kvm") == 0) {
			ruri_set_flag("create_kvm_node");
		}
		// Hidepid.
		else if (strcmp(argv[index], "-i") == 0 || strcmp(argv[index], "--hidepid") == 0) {
			index++;
			container->hidepid = atoi(argv[index]);
			if (container->hidepid < 0 || container->hidepid > 2) {
				ruri_error("{red}hidepid should be in range 0-2\n");
			}
		}
		// OOM score.
		else if (strcmp(argv[index], "-O") == 0 || strcmp(argv[index], "--oom-score-adj") == 0) {
			index++;
			container->oom_score_adj = atoi(argv[index]);
			if (container->oom_score_adj < -1000 || container->oom_score_adj > 1000) {
				ruri_error("{red}oom_score_adj should be in range [-1000]-[1000]\n");
			}
		}
		// Join ns.
		else if (strcmp(argv[index], "-J") == 0 || strcmp(argv[index], "--join-ns") == 0) {
			index++;
			container->ns_pid = atoi(argv[index]);
			if (container->ns_pid <= 0) {
				ruri_error("{red}NS_PID should be in range 0-2\n");
			}
		}
		// cgroup limit.
		else if (strcmp(argv[index], "-l") == 0 || strcmp(argv[index], "--limit") == 0) {
			index++;
			if ((argv[index] != NULL)) {
				parse_cgroup_settings(argv[index], container);
			} else {
				ruri_error("{red}Unknown cgroup option\n");
			}
		}
		// Work dir.
		else if (strcmp(argv[index], "-W") == 0 || strcmp(argv[index], "--work-dir") == 0) {
			index++;
			if (index < argc) {
				container->work_dir = strdup(argv[index]);
			} else {
				ruri_error("{red}Unknown work directory\n");
			}
		}
		// Masked path.
		else if (strcmp(argv[index], "-Q") == 0 || strcmp(argv[index], "--mask-path") == 0) {
			index++;
			if (index < argc) {
				for (int i = 0; i < RURI_MAX_MOUNTPOINTS; i++) {
					if (container->masked_path[i] == NULL) {
						container->masked_path[i] = strdup(argv[index]);
						container->masked_path[i + 1] = NULL;
						break;
					}
					// Max 512 mountpoints.
					if (i == (RURI_MAX_MOUNTPOINTS - 1)) {
						ruri_error("{red}Too many masked paths QwQ\n");
					}
				}
			} else {
				ruri_error("{red}Unknown masked path QwQ\n");
			}
		}
		// Set extra env.
		else if (strcmp(argv[index], "-e") == 0 || strcmp(argv[index], "--env") == 0) {
			index++;
			if ((argv[index] != NULL) && (argv[index + 1] != NULL)) {
				for (int i = 0; i < RURI_MAX_ENVS; i++) {
					if (container->env[i] == NULL) {
						container->env[i] = strdup(argv[index]);
						index++;
						container->env[i + 1] = strdup(argv[index]);
						container->env[i + 2] = NULL;
						break;
					}
					// Max 512 envs.
					if (i == (RURI_MAX_ENVS - 1)) {
						ruri_error("{red}Too many envs QwQ\n");
					}
				}
			} else {
				ruri_error("{red}Error: unknown env QwQ\n");
			}
		}
		// Set extra mountpoints.
		else if (strcmp(argv[index], "-m") == 0 || strcmp(argv[index], "--mount") == 0) {
			index++;
			if ((argv[index] != NULL) && (argv[index + 1] != NULL)) {
				if (strcmp(argv[index], "/") == 0) {
					ruri_error("{red}/ is not allowed to use as a mountpoint QwQ\n");
				}
				for (int i = 0; i < RURI_MAX_MOUNTPOINTS; i++) {
					if (container->extra_mountpoint[i] == NULL) {
						container->extra_mountpoint[i] = strdup(argv[index]);
						index++;
						container->extra_mountpoint[i + 1] = strdup(argv[index]);
						if (strcmp(argv[index], "/") == 0) {
							free(container->extra_mountpoint[i]);
							free(container->extra_mountpoint[i + 1]);
							container->extra_mountpoint[i] = NULL;
							container->extra_mountpoint[i + 1] = NULL;
							if (container->rootfs_source == NULL) {
								container->rootfs_source = strdup(argv[index - 1]);
							} else {
								ruri_error("{red}You can only mount one source to / QwQ\n");
							}
						}
						container->extra_mountpoint[i + 2] = NULL;
						break;
					}
					// Max 512 mountpoints.
					if (i == (RURI_MAX_MOUNTPOINTS - 1)) {
						ruri_error("{red}Too many mountpoints QwQ\n");
					}
				}
			} else {
				ruri_error("{red}Error: unknown mountpoint QwQ\n");
			}
		}
		// Set extra read-only mountpoints.
		else if (strcmp(argv[index], "-M") == 0 || strcmp(argv[index], "--ro-mount") == 0) {
			index++;
			if ((argv[index] != NULL) && (argv[index + 1] != NULL)) {
				for (int i = 0; i < RURI_MAX_MOUNTPOINTS; i++) {
					if (container->extra_ro_mountpoint[i] == NULL) {
						container->extra_ro_mountpoint[i] = strdup(argv[index]);
						index++;
						container->extra_ro_mountpoint[i + 1] = strdup(argv[index]);
						container->extra_ro_mountpoint[i + 2] = NULL;
						if (strcmp(argv[index], "/") == 0) {
							free(container->extra_ro_mountpoint[i]);
							free(container->extra_ro_mountpoint[i + 1]);
							container->extra_ro_mountpoint[i] = NULL;
							container->extra_ro_mountpoint[i + 1] = NULL;
							if (container->rootfs_source == NULL) {
								container->rootfs_source = strdup(argv[index - 1]);
								ruri_set_flag("read_only_rootfs");
							} else {
								ruri_error("{red}You can only mount one source to / QwQ\n");
							}
						}
						break;
					}
					// Max 512 mountpoints.
					if (i == (RURI_MAX_MOUNTPOINTS - 1)) {
						ruri_error("{red}Too many mountpoints QwQ\n");
					}
				}
			} else {
				ruri_error("{red}Error: unknown mountpoint QwQ\n");
			}
		}
		// Char devices.
		else if (strcmp(argv[index], "-I") == 0 || strcmp(argv[index], "--char-dev") == 0) {
			index++;
			if ((argv[index] != NULL) && (argv[index + 1] != NULL) && (argv[index + 2] != NULL)) {
				for (int i = 0; i < RURI_MAX_CHAR_DEVS; i++) {
					if (container->char_devs[i] == NULL) {
						container->char_devs[i] = strdup(argv[index]);
						index++;
						if (atoi(argv[index]) < 0) {
							ruri_error("{red}Error: invalid major number QwQ\n");
						}
						container->char_devs[i + 1] = strdup(argv[index]);
						index++;
						if (atoi(argv[index]) <= 0 && strcmp(argv[index], "0") != 0) {
							ruri_error("{red}Error: invalid minor number QwQ\n");
						}
						container->char_devs[i + 2] = strdup(argv[index]);
						container->char_devs[i + 3] = NULL;
						// If major is 0, we will auto-detect the major and minor number from the host device.
						if (atoi(container->char_devs[i + 1]) == 0) {
							free(container->char_devs[i + 1]);
							free(container->char_devs[i + 2]);
							char dev_path[PATH_MAX];
							sprintf(dev_path, "/dev/%s", container->char_devs[i]);
							struct stat st;
							if (stat(dev_path, &st) != 0) {
								ruri_error("{red}Error: device %s does not exist on host QwQ\n", dev_path);
							}
							if (!S_ISCHR(st.st_mode)) {
								ruri_error("{red}Error: device %s is not a char device on host QwQ\n", dev_path);
							}
							container->char_devs[i + 1] = ruri_malloc(16);
							container->char_devs[i + 2] = ruri_malloc(16);
							snprintf(container->char_devs[i + 1], 16, "%d", major(st.st_rdev));
							snprintf(container->char_devs[i + 2], 16, "%d", minor(st.st_rdev));
							ruri_log("{base}Auto-detected char device: %s (major: %s, minor: %s)\n", container->char_devs[i], container->char_devs[i + 1], container->char_devs[i + 2]);
						}
						break;
					}
					if (i == (RURI_MAX_CHAR_DEVS - 1)) {
						ruri_error("{red}Too many char devices QwQ\n");
					}
				}
			} else {
				ruri_error("{red}Error: unknown char devices QwQ\n");
			}
		}
		// Deny syscall.
		else if (strcmp(argv[index], "-X") == 0 || strcmp(argv[index], "--deny-syscall") == 0) {
#ifndef DISABLE_LIBSECCOMP
			index++;
			if (argv[index] != NULL) {
				for (int i = 0; i < RURI_MAX_SECCOMP_DENIED_SYSCALL; i++) {
					if (container->seccomp_denied_syscall[i] == NULL) {
						container->seccomp_denied_syscall[i] = strdup(argv[index]);
						container->seccomp_denied_syscall[i + 1] = NULL;
						break;
					}
					if (i == (RURI_MAX_SECCOMP_DENIED_SYSCALL - 1)) {
						ruri_error("{red}Too many syscalls QwQ\n");
					}
				}
			} else {
				ruri_error("{red}Error: unknown syscall QwQ\n");
			}
#else
			ruri_error("{red}Error: libseccomp is disabled, please recompile ruri with libseccomp support QwQ\n");
#endif
		}
		// Time ns offset.
		else if (strcmp(argv[index], "-T") == 0 || strcmp(argv[index], "--timens-offset") == 0) {
			index++;
			if (argv[index] != NULL) {
				container->timens_monotonic_offset = strtoll(argv[index], NULL, 10);
			} else {
				ruri_error("{red}Error: unknown time ns offset QwQ\n");
			}
			index++;
			if (argv[index] != NULL) {
				container->timens_realtime_offset = strtoll(argv[index], NULL, 10);
			} else {
				ruri_error("{red}Error: unknown time ns offset QwQ\n");
			}
			container->enable_unshare = true;
		}
		// Extra capabilities to keep.
		else if (strcmp(argv[index], "-k") == 0 || strcmp(argv[index], "--keep") == 0 || strcmp(argv[index], "--cap-add") == 0) {
#ifndef DISABLE_LIBCAP
			index++;
			if (argv[index] != NULL) {
				// We both support capability name and number,
				// because in the fulture, there might be new capabilities that
				// we can not use the name to match it in current libcap.
				if (atoi(argv[index]) != 0) {
					ruri_add_to_caplist(keep_caplist_extra, atoi(argv[index]));
				} else if (ruri_cap_from_name(argv[index], &cap) == 0) {
					ruri_add_to_caplist(keep_caplist_extra, cap);
					ruri_log("{base}Keep capability: %s\n", argv[index]);
				} else {
					ruri_error("{red}or: unknown capability `%s`\nQwQ{clear}\n", argv[index]);
				}
			} else {
				ruri_error("{red}Missing argument\n");
			}
#else
			ruri_error("{red}Error: libcap is disabled, please recompile ruri with libcap support QwQ\n");
#endif
		}
		// Extra capabilities to drop.
		else if (strcmp(argv[index], "-d") == 0 || strcmp(argv[index], "--drop") == 0 || strcmp(argv[index], "--cap-drop") == 0) {
#ifndef DISABLE_LIBCAP
			index++;
			if (argv[index] != NULL) {
				if (atoi(argv[index]) != 0) {
					ruri_add_to_caplist(drop_caplist_extra, atoi(argv[index]));
				} else if (cap_from_name(argv[index], &cap) == 0) {
					ruri_add_to_caplist(drop_caplist_extra, cap);
				} else {
					ruri_error("{red}Error: unknown capability `%s`\nQwQ{clear}\n", argv[index]);
				}
			} else {
				ruri_error("{red}Missing argument\n");
			}
#else
			ruri_error("{red}Error: libcap is disabled, please recompile ruri with libcap support QwQ\n");
#endif
		} else if (strcmp(argv[index], "-U") == 0 || strcmp(argv[index], "--umount") == 0) {
			if (use_config_file) {
				ruri_umount_container(container->container_dir);
				exit(EXIT_SUCCESS);
			} else {
				ruri_error("{red}Error: --umount should only be used without other arguments QwQ\n");
			}
		} else if (strcmp(argv[index], "-z") == 0 || strcmp(argv[index], "--enable-tty-signals") == 0) {
			ruri_set_flag("enable_tty_signals");
		} else if (strcmp(argv[index], "-y") == 0 || strcmp(argv[index], "--systemd") == 0) {
			ruri_set_flag("systemd_init");
			container->enable_unshare = true;
		}
		// Force enable systemd, as it is very unstable and even might panic host.
		else if (strcmp(argv[index], "--even-unstable") == 0) {
			even_unstable = true;
		}
		// Force panic on error, for security.
		else if (strcmp(argv[index], "--strict-mode") == 0) {
			ruri_set_flag("force_panic");
		}
		// Pid file.
		else if (strcmp(argv[index], "--pid-file") == 0) {
			index++;
			if (index == argc - 1) {
				ruri_error("{red}Please specify the pid file\n{clear}");
			}
			container->pid_file = strdup(argv[index]);
		}
		// Auto umount after running container.
		else if (strcmp(argv[index], "--auto-umount") == 0) {
			ruri_set_flag("auto_umount");
		}
		// Auto umount on panic.
		else if (strcmp(argv[index], "--umount-on-panic") == 0) {
			ruri_set_flag("auto_umount_on_panic");
		}
		// Is health check process.
		else if (strcmp(argv[index], "--health-check") == 0) {
			ruri_set_flag("is_health_check");
		}
		// --enable-seccomp-whitelist
		else if (strcmp(argv[index], "--enable-seccomp-whitelist") == 0) {
			container->enable_seccomp_whitelist = true;
		}
		// --fork-as-init.
		else if (strcmp(argv[index], "--fork-as-init") == 0) {
			ruri_set_flag("fork_as_init");
		}
		// Feature flags.
		else if (strcmp(argv[index], "--set-flag") == 0) {
			index++;
			if (index == argc - 1) {
				ruri_error("{red}Please specify a flag\n{clear}");
			}
			char *flag = argv[index];
			ruri_set_flag(flag);
		}
		// Timeout.
		else if (strcmp(argv[index], "--timeout") == 0) {
			index++;
			if (index == argc - 1) {
				ruri_error("{red}Please specify the timeout in seconds\n{clear}");
			}
			// This is a float, use strtof to parse it.
			char *endptr = NULL;
			container->timeout = strtof(argv[index], &endptr);
			if (*endptr != '\0') {
				ruri_error("{red}Invalid timeout value\n{clear}");
			}
			if (container->timeout < 0) {
				ruri_error("{red}Timeout should be non-negative\n{clear}");
			}
		}
		// If use_config_file is true.
		// The first unrecognized argument will be treated as command to exec in container.
		else if (use_config_file) {
			if (index < argc) {
				for (int i = 0; i < argc; i++) {
					if (index < argc && i < RURI_MAX_COMMANDS) {
						container->command[i] = strdup(argv[index]);
						container->command[i + 1] = NULL;
						index++;
					} else {
						break;
					}
				}
			} else {
				container->command[0] = NULL;
			}
		}
		// If use_config_file is false.
		// The first unrecognized argument will be treated as container directory.
		// If this argument is CONTAINER_DIR.
		else if (is_container_dir(argv[index])) {
			// Set container directory.
			container->container_dir = realpath(argv[index], NULL);
			if (container->container_dir == NULL) {
				ruri_error("{red}Container directory does not exist QwQ\n");
			}
			index++;
			// Arguments after container_dir will be read as command to exec in container.
			if (index < argc) {
				for (int i = 0; i < argc; i++) {
					if (index < argc && i < RURI_MAX_COMMANDS) {
						container->command[i] = strdup(argv[index]);
						container->command[i + 1] = NULL;
						index++;
					} else {
						break;
					}
				}
			} else {
				container->command[0] = NULL;
			}
		}
		// Parse BSD style command-line.
		else if (argv[index][0] == '-') {
			if (strlen(argv[index]) == 1) {
				ruri_error("Invalid argument %s\n", argv[index]);
			}
			// Very shit. I know.
			// At least it works.
			int index_bk = index;
			for (size_t i = 1; i < strlen(argv[index]); i++) {
				if (index_bk != index) {
					break;
				}
				switch (argv[index][i]) {
				case 'r':
					ruri_warning("{yellow}--rootless is deprecated, and ruri will automatically try rootless mode if running with root privileges.{clear}\n");
					container->rootless = true;
					break;
				case 'D':
					dump_config = true;
					break;
				case 'g':
					ruri_set_flag("skip_setgroups");
					break;
				case 'u':
					container->enable_unshare = true;
					break;
				case 'n':
					ruri_set_flag("no_new_privs");
					break;
				case 'N':
					ruri_set_flag("no_rurienv");
					break;
				case 's':
					container->enable_default_seccomp = true;
					break;
				case 'p':
					privileged = true;
					break;
				case 'S':
					ruri_set_flag("use_host_runtime");
					break;
				case 'R':
					ruri_set_flag("read_only_rootfs");
					break;
				case 'w':
					ruri_set_flag("disable_warnings");
					break;
				case 'f':
					fork_exec = true;
					break;
				case 'j':
					ruri_set_flag("just_chroot");
					break;
				case 'A':
					ruri_set_flag("no_mask_paths");
					break;
				case 'x':
					ruri_set_flag("empty_net_ns");
					break;
				case 'K':
					ruri_set_flag("create_kvm_node");
					break;
				case 'b':
					background = true;
					break;
				case 'o':
					if (i == (strlen(argv[index]) - 1)) {
						index++;
						if (index == argc - 1) {
							ruri_error("{red}Please specify the output file\n{clear}");
						}
						output_path = argv[index];
					} else {
						ruri_error("Invalid argument %s\n", argv[index]);
					}
					break;
				case 'Q':
					if (i == (strlen(argv[index]) - 1)) {
						index++;
						if (index < argc) {
							for (int i = 0; i < RURI_MAX_MOUNTPOINTS; i++) {
								if (container->masked_path[i] == NULL) {
									container->masked_path[i] = strdup(argv[index]);
									container->masked_path[i + 1] = NULL;
									break;
								}
								// Max 512 mountpoints.
								if (i == (RURI_MAX_MOUNTPOINTS - 1)) {
									ruri_error("{red}Too many masked paths QwQ\n");
								}
							}
						} else {
							ruri_error("{red}Unknown masked path QwQ\n");
						}
					} else {
						ruri_error("Invalid argument %s\n", argv[index]);
					}
					break;
				case 'c':
					if (i == (strlen(argv[index]) - 1)) {
						if (index == argc - 1) {
							ruri_error("{red}Please specify a config file !\n{clear}");
						}
						index++;
						ruri_read_config(container, argv[index]);
						use_config_file = true;
						index++;
					} else {
						ruri_error("Invalid argument %s\n", argv[index]);
					}
					break;
				case 'a':
					if (i == (strlen(argv[index]) - 1)) {
						if (index == argc - 1) {
							ruri_error("{red}Please specify the arch\n{clear}");
						}
						index++;
						container->cross_arch = strdup(argv[index]);
					} else {
						ruri_error("Invalid argument %s\n", argv[index]);
					}
					break;
				case 'q':
					if (i == (strlen(argv[index]) - 1)) {
						index++;
						if (index == argc - 1) {
							ruri_error("{red}Please specify the path of qemu binary\n{clear}");
						}
						container->qemu_path = strdup(argv[index]);
					} else {
						ruri_error("Invalid argument %s\n", argv[index]);
					}
					break;
				case 'k':
#ifndef DISABLE_LIBCAP
					if (i == (strlen(argv[index]) - 1)) {
						index++;
						if (argv[index] != NULL) {
							// We both support capability name and number,
							// because in the fulture, there might be new capabilities that
							// we can not use the name to match it in current libcap.
							if (atoi(argv[index]) != 0) {
								ruri_add_to_caplist(keep_caplist_extra, atoi(argv[index]));
							} else if (ruri_cap_from_name(argv[index], &cap) == 0) {
								ruri_add_to_caplist(keep_caplist_extra, cap);
								ruri_log("{base}Keep capability: %s\n", argv[index]);
							} else {
								ruri_error("{red}or: unknown capability `%s`\nQwQ{clear}\n", argv[index]);
							}
						} else {
							ruri_error("{red}Missing argument\n");
						}
					} else {
						ruri_error("Invalid argument %s\n", argv[index]);
					}
					break;
#else
					ruri_error("{red}Error: libcap is disabled, please recompile ruri with libcap support QwQ\n");
#endif
				case 'd':
#ifndef DISABLE_LIBCAP
					if (i == (strlen(argv[index]) - 1)) {
						index++;
						if (argv[index] != NULL) {
							if (atoi(argv[index]) != 0) {
								ruri_add_to_caplist(drop_caplist_extra, atoi(argv[index]));
							} else if (ruri_cap_from_name(argv[index], &cap) == 0) {
								ruri_add_to_caplist(drop_caplist_extra, cap);
							} else {
								ruri_error("{red}Error: unknown capability `%s`\nQwQ{clear}\n", argv[index]);
							}
						} else {
							ruri_error("{red}Missing argument\n");
						}
					} else {
						ruri_error("Invalid argument %s\n", argv[index]);
					}
					break;
#else
					ruri_error("{red}Error: libcap is disabled, please recompile ruri with libcap support QwQ\n");
#endif
				case 'e':
					if (i == (strlen(argv[index]) - 1)) {
						index++;
						if ((argv[index] != NULL) && (argv[index + 1] != NULL)) {
							for (int i = 0; i < RURI_MAX_ENVS; i++) {
								if (container->env[i] == NULL) {
									container->env[i] = strdup(argv[index]);
									index++;
									container->env[i + 1] = strdup(argv[index]);
									container->env[i + 2] = NULL;
									break;
								}
								// Max 512 envs.
								if (i == (RURI_MAX_ENVS - 1)) {
									ruri_error("{red}Too many envs QwQ\n");
								}
							}
						} else {
							ruri_error("{red}Error: unknown env QwQ\n");
						}
					} else {
						ruri_error("Invalid argument %s\n", argv[index]);
					}
					break;
				case 'm':
					if (i == (strlen(argv[index]) - 1)) {
						index++;
						if ((argv[index] != NULL) && (argv[index + 1] != NULL)) {
							if (strcmp(argv[index], "/") == 0) {
								ruri_error("{red}/ is not allowed to use as a mountpoint QwQ\n");
							}
							for (int i = 0; i < RURI_MAX_MOUNTPOINTS; i++) {
								if (container->extra_mountpoint[i] == NULL) {
									container->extra_mountpoint[i] = strdup(argv[index]);
									index++;
									container->extra_mountpoint[i + 1] = strdup(argv[index]);
									if (strcmp(argv[index], "/") == 0) {
										free(container->extra_mountpoint[i]);
										free(container->extra_mountpoint[i + 1]);
										container->extra_mountpoint[i] = NULL;
										container->extra_mountpoint[i + 1] = NULL;
										if (container->rootfs_source == NULL) {
											container->rootfs_source = strdup(argv[index - 1]);
										} else {
											ruri_error("{red}You can only mount one source to / QwQ\n");
										}
									}
									container->extra_mountpoint[i + 2] = NULL;
									break;
								}
								// Max 512 mountpoints.
								if (i == (RURI_MAX_MOUNTPOINTS - 1)) {
									ruri_error("{red}Too many mountpoints QwQ\n");
								}
							}
						} else {
							ruri_error("{red}Error: unknown mountpoint QwQ\n");
						}
					} else {
						ruri_error("Invalid argument %s\n", argv[index]);
					}
					break;
				case 'M':
					if (i == (strlen(argv[index]) - 1)) {
						index++;
						if ((argv[index] != NULL) && (argv[index + 1] != NULL)) {
							for (int i = 0; i < RURI_MAX_MOUNTPOINTS; i++) {
								if (container->extra_ro_mountpoint[i] == NULL) {
									container->extra_ro_mountpoint[i] = strdup(argv[index]);
									index++;
									container->extra_ro_mountpoint[i + 1] = strdup(argv[index]);
									container->extra_ro_mountpoint[i + 2] = NULL;
									if (strcmp(argv[index], "/") == 0) {
										free(container->extra_ro_mountpoint[i]);
										free(container->extra_ro_mountpoint[i + 1]);
										container->extra_ro_mountpoint[i] = NULL;
										container->extra_ro_mountpoint[i + 1] = NULL;
										if (container->rootfs_source == NULL) {
											container->rootfs_source = strdup(argv[index - 1]);
											ruri_set_flag("read_only_rootfs");
										} else {
											ruri_error("{red}You can only mount one source to / QwQ\n");
										}
									}
									break;
								}
								// Max 512 mountpoints.
								if (i == (RURI_MAX_MOUNTPOINTS - 1)) {
									ruri_error("{red}Too many mountpoints QwQ\n");
								}
							}
						} else {
							ruri_error("{red}Error: unknown mountpoint QwQ\n");
						}
					} else {
						ruri_error("Invalid argument %s\n", argv[index]);
					}
					break;
				case 'l':
					if (i == (strlen(argv[index]) - 1)) {
						index++;
						if ((argv[index] != NULL)) {
							parse_cgroup_settings(argv[index], container);
						} else {
							ruri_error("{red}Unknown cgroup option\n");
						}
					} else {
						ruri_error("Invalid argument %s\n", argv[index]);
					}
					break;
				case 'W':
					if (i == (strlen(argv[index]) - 1)) {
						index++;
						if (index < argc) {
							container->work_dir = strdup(argv[index]);
						} else {
							ruri_error("{red}Unknown work directory\n");
						}
					} else {
						ruri_error("Invalid argument %s\n", argv[index]);
					}
					break;
				case 'E':
					if (i == (strlen(argv[index]) - 1)) {
						if (index == argc - 1) {
							ruri_error("{red}Please specify the user\n{clear}");
						}
						index++;
						container->user = strdup(argv[index]);
					} else {
						ruri_error("Invalid argument %s\n", argv[index]);
					}
					break;
				case 't':
					if (i == (strlen(argv[index]) - 1)) {
						if (index == argc - 1) {
							ruri_error("{red}Please specify the hostname !\n{clear}");
						}
						index++;
						container->hostname = strdup(argv[index]);
					} else {
						ruri_error("Invalid argument %s\n", argv[index]);
					}
					break;
				case 'I':
					if (i == (strlen(argv[index]) - 1)) {
						index++;
						if ((argv[index] != NULL) && (argv[index + 1] != NULL) && (argv[index + 2] != NULL)) {
							for (int i = 0; i < RURI_MAX_CHAR_DEVS; i++) {
								if (container->char_devs[i] == NULL) {
									container->char_devs[i] = strdup(argv[index]);
									index++;
									if (atoi(argv[index]) <= 0) {
										ruri_error("{red}Error: invalid major number QwQ\n");
									}
									container->char_devs[i + 1] = strdup(argv[index]);
									index++;
									if (atoi(argv[index]) <= 0 && strcmp(argv[index], "0") != 0) {
										ruri_error("{red}Error: invalid minor number QwQ\n");
									}
									container->char_devs[i + 2] = strdup(argv[index]);
									container->char_devs[i + 3] = NULL;
									break;
								}
								if (i == (RURI_MAX_CHAR_DEVS - 1)) {
									ruri_error("{red}Too many char devices QwQ\n");
								}
							}
						} else {
							ruri_error("{red}Error: unknown char devices QwQ\n");
						}
					} else {
						ruri_error("Invalid argument %s\n", argv[index]);
					}
					break;
				case 'i':
					if (i == (strlen(argv[index]) - 1)) {
						index++;
						container->hidepid = atoi(argv[index]);
						if (container->hidepid < 0 || container->hidepid > 2) {
							ruri_error("{red}hidepid should be in range 0-2\n");
						}
					} else {
						ruri_error("Invalid argument %s\n", argv[index]);
					}
					break;
				case 'z':
					ruri_set_flag("enable_tty_signals");
					break;
				case 'y':
					ruri_set_flag("systemd_init");
					container->enable_unshare = true;
					break;
				case 'O':
					if (i == (strlen(argv[index]) - 1)) {
						index++;
						container->oom_score_adj = atoi(argv[index]);
						if (container->oom_score_adj < -1000 || container->oom_score_adj > 1000) {
							ruri_error("{red}oom_score_adj should be in range [-1000]-[1000]\n");
						}
					} else {
						ruri_error("Invalid argument %s\n", argv[index]);
					}
					break;
				case 'T':
					if (i == (strlen(argv[index]) - 1)) {
						index++;
						if (argv[index] != NULL) {
							container->timens_monotonic_offset = strtoll(argv[index], NULL, 10);
						} else {
							ruri_error("{red}Error: unknown time ns offset QwQ\n");
						}
						index++;
						if (argv[index] != NULL) {
							container->timens_realtime_offset = strtoll(argv[index], NULL, 10);
						} else {
							ruri_error("{red}Error: unknown time ns offset QwQ\n");
						}
						container->enable_unshare = true;
					} else {
						ruri_error("Invalid argument %s\n", argv[index]);
					}
					break;
				case 'L':
					if (i == (strlen(argv[index]) - 1)) {
						index++;
						if (index == argc - 1) {
							ruri_error("{red}Please specify the log file\n{clear}");
						}
						background = true;
						log_file = argv[index];
					} else {
						ruri_error("Invalid argument %s\n", argv[index]);
					}
					break;
				case 'X':
#ifndef DISABLE_LIBSECCOMP
					if (i == (strlen(argv[index]) - 1)) {
						if (index == argc - 1) {
							ruri_error("{red}Please specify the syscall\n{clear}");
						}
						index++;
						for (int i = 0; i < RURI_MAX_SECCOMP_DENIED_SYSCALL; i++) {
							if (container->seccomp_denied_syscall[i] == NULL) {
								container->seccomp_denied_syscall[i] = strdup(argv[index]);
								container->seccomp_denied_syscall[i + 1] = NULL;
								break;
							}
							if (i == (RURI_MAX_SECCOMP_DENIED_SYSCALL - 1)) {
								ruri_error("{red}Too many syscalls QwQ\n");
							}
						}
					} else {
						ruri_error("Invalid argument %s\n", argv[index]);
					}
					break;
#else
					ruri_error("{red}Error: libseccomp is disabled, please recompile ruri with libseccomp support QwQ\n");
#endif
				case 'J':
					if (i == (strlen(argv[index]) - 1)) {
						index++;
						container->ns_pid = atoi(argv[index]);
						if (container->ns_pid <= 0) {
							ruri_error("{red}NS_PID should >= 0\n");
						}
					} else {
						ruri_error("Invalid argument %s\n", argv[index]);
					}
					break;
				default:
					ruri_error("Invalid argument %s\n", argv[index]);
				}
			}
		}
		// For unknown arguments, yeah I didn't forgot it...
		else {
			ruri_show_helps();
			ruri_error("{red}Error: unknown option `%s`\nNote that only existing directory can be detected as CONTAINER_DIR\n", argv[index]);
		}
	}
	// Error If systemd mode is enabled but even_unstable is not enabled, for safety.
	if (ruri_flag(systemd_init) && !even_unstable) {
		ruri_error("{red}Error: systemd mode is very unstable, you must enable --even-unstable to use it, if you know what you are doing\n");
	}
	// Fork to background if -b is set.
	if (background) {
		// One more fork().
		pid_t f1 = fork();
		if (f1 > 0) {
			exit(EXIT_SUCCESS);
		}
		pid_t fpid = fork();
		if (fpid > 0) {
			printf("PID: %d\n", fpid);
			usleep(1000);
			exit(EXIT_SUCCESS);
		}
		// Ignore SIGTTIN, we are now running in the background, SIGTTIN may kill this process.
		sigset_t sigs;
		sigemptyset(&sigs);
		sigaddset(&sigs, SIGTTIN);
		sigaddset(&sigs, SIGTTOU);
		sigprocmask(SIG_BLOCK, &sigs, 0);
		// Redirect stdout and stderr to log file or /dev/null.
		if (log_file != NULL) {
			ruri_mkdirs(log_file, 0755);
			rmdir(log_file);
			remove(log_file);
			int logfd = open(log_file, O_CREAT | O_CLOEXEC | O_RDWR, S_IRUSR | S_IRGRP | S_IROTH | S_IWGRP | S_IWUSR | S_IWOTH);
			if (logfd < 0) {
				ruri_error("{red}Error: failed to open log file QwQ\n");
			}
			dup2(logfd, STDOUT_FILENO);
			dup2(logfd, STDERR_FILENO);
			close(logfd);
		} else {
			int nullfd = open("/dev/null", O_RDWR | O_CLOEXEC);
			dup2(nullfd, STDOUT_FILENO);
			dup2(nullfd, STDERR_FILENO);
			close(nullfd);
		}
	}
	// Build the caplist to drop.
	ruri_build_caplist(container->drop_caplist, privileged, drop_caplist_extra, keep_caplist_extra);
	// Convert mountpoints to absolute path.
	ruri_convert_mountpoints_to_absolute(container);
	// Convert rootfs source to absolute path.
	ruri_convert_rootfs_source_to_absolute(container);
	// Dump config.
	if (dump_config) {
		// Check if container directory is given.
		if (container->container_dir == NULL) {
			ruri_error("{red}Error: container directory is not set or does not exist QwQ\n");
		}
		// Refuse to use `/` for container directory.
		if (strcmp(container->container_dir, "/") == 0) {
			ruri_error("{red}Error: `/` is not allowed to use as a container directory QwQ\n");
		}
		char *config = ruri_container_info_to_k2v(container);
		if (output_path == NULL) {
			cprintf("%s", config);
			exit(EXIT_SUCCESS);
		}
		unlink(output_path);
		remove(output_path);
		ruri_mkdirs(output_path, 0755);
		rmdir(output_path);
		int fd = open(output_path, O_CREAT | O_CLOEXEC | O_RDWR, S_IRUSR | S_IRGRP | S_IROTH | S_IWGRP | S_IWUSR | S_IWOTH | S_IXUSR | S_IXGRP | S_IXOTH);
		if (fd < 0) {
			ruri_error("{red}Error: failed to open output file QwQ\n");
		}
		write(fd, config, strlen(config));
		free(config);
		close(fd);
		exit(EXIT_SUCCESS);
	}
	// Enable unshare automatically if we got a ns_pid.
	pid_t ns_pid = ruri_get_ns_pid(container->container_dir);
	if (ns_pid > 0) {
		container->enable_unshare = true;
	}
	// Totally useless, just for backward compatibility.
	if (fork_exec && !container->enable_unshare && !container->rootless) {
		ruri_warning("{yellow}: Warning: --fork is deprecated as useless, make sure you know what you are doing\n");
		pid_t pid = fork();
		if (pid > 0) {
			waitpid(pid, NULL, 0);
			exit(EXIT_SUCCESS);
		}
	}
}
static void detect_suid_or_capability(void)
{
#ifndef DISABLE_LIBCAP
	struct stat st;
	if (stat("/proc/self/exe", &st) == 0) {
		if (((st.st_mode & S_ISUID) || (st.st_mode & S_ISGID)) && (geteuid() == 0 || getegid() == 0)) {
			ruri_warning("{red}Warning: SUID or SGID bit detected on ruri, this is unsafe desu QwQ\n");
		}
	}
	cap_t caps = cap_get_file("/proc/self/exe");
	if (caps == NULL) {
		return;
	}
	char *caps_str = cap_to_text(caps, NULL);
	if (caps_str == NULL) {
		return;
	}
	if (strlen(caps_str) > 0) {
		ruri_warning("{red}Warning: capabilities detected on ruri, this is unsafe desu QwQ\n");
	}
	cap_free(caps);
	cap_free(caps_str);
#endif
}
// The real main() function.
int ruri(int argc, char **argv)
{
#if defined(RURI_DEBUG) || defined(RURI_DEV)
	// Enable debug log.
	ruri_set_flag("ruri_dbg");
#endif
	// Default flags.
	ruri_set_flag("no_pids_cgroup");
	ruri_set_flag("no_io_cgroup");
	// init profiling time.
	ruri_diff_time();
	// Detect SUID or capability.
	detect_suid_or_capability();
	// Exit when we get error reading configs.
	k2v_stop_at_warning = true;
	// Set process name.
	prctl(PR_SET_NAME, "ruri");
	// Catch coredump signal.
	ruri_register_signal();
// Warning for dev/debug build.
#if defined(RURI_DEBUG) || defined(RURI_DEV)
	ruri_warning("{red}Warning: this is a dev/debug build, do not use it in production{clear}\n");
#endif
	// Clear env, and re-exec ruri from memfd.
	ruri_clear_env(argv);
	// Unset ruri_rexec env.
	unsetenv("ruri_rexec");
	char *no_logs_env = getenv("ruri_no_logs");
	if (no_logs_env != NULL) {
		ruri_set_flag("no_logs");
		unsetenv("ruri_no_logs");
	}
	for (int i = 0; i < argc; i++) {
		ruri_log("{base}argv[%d]: {cyan}%s\n", i, argv[i]);
	}
	// Info of container to run.
	struct RURI_CONTAINER *container = (struct RURI_CONTAINER *)ruri_malloc(sizeof(struct RURI_CONTAINER));
	// Parse arguments.
	parse_args(argc, argv, container);
	unsetenv("ruri_path");
	// Set no dumpable.
	if (!ruri_flag(ruri_dbg)) {
		prctl(PR_SET_DUMPABLE, 0);
		// This need YAMA.
		prctl(PR_SET_PTRACER, 0);
	}
	// An easter egg for meow flag.
	if (ruri_flag(meow)) {
		ruri_meow();
	}
	// If --fork-as-init, erase argv.
	if (ruri_flag(fork_as_init)) {
		for (int i = 0; i < argc; i++) {
			memset(argv[i], 0, strlen(argv[i]));
		}
	}
	// Detect rootless mode.
	if (geteuid() != 0) {
		container->rootless = true;
	}
	// Check container and the running environment.
	check_container(container);
	// unset $LD_PRELOAD.
	unsetenv("LD_PRELOAD");
	ruri_profile_log("{green}ruri() to run_container(): %lld ns\n", ruri_diff_time());
	// Daemon for pidfile.
	if (!ruri_flag(no_pidfile_daemon)) {
		ruri_setup_pid_file_daemon(container);
	}
	// Timeout watchdog.
	if (container->timeout > 0) {
		ruri_setup_timeout_watchdog(container);
	}
	// Setup tty.
	if (ruri_flag(new_tty)) {
		ruri_setup_tty_daemon();
	}
	// Run container.
	if ((container->enable_unshare) && !(container->rootless)) {
		// Unshare container.
		ruri_run_unshare_container(container);
	} else if ((container->rootless)) {
		// Rootless container.
		ruri_run_rootless_container(container);
	} else {
		// Common chroot container.
		// Fork once, so we can watch the container process and update pid file in time.
		pid_t chroot_pid = fork();
		if (chroot_pid > 0) {
			// Parent process, wait for child to exit.
			int stat = 0;
			waitpid(chroot_pid, &stat, 0);
			// Write exit status to pid_fd.
			if (WIFEXITED(stat)) {
				ruri_pid_file_write(RURI_PID_FILE_EXITED, WEXITSTATUS(stat));
			} else if (WIFSIGNALED(stat)) {
				ruri_pid_file_write(RURI_PID_FILE_SIGNALED, 128 + WTERMSIG(stat));
			} else {
				ruri_pid_file_write(RURI_PID_FILE_UNKNOWN, 0);
			}
			// Wait pidfile lock.
			if (ruri_flag(wait_pidfile_lock)) {
				close(ruri_pid_file_fd(-1));
				if (container->pid_file != NULL) {
					ruri_pid_file_wait_lock(container->pidfile_lock_fd);
				}
			}
			if (WIFEXITED(stat)) {
				exit(WEXITSTATUS(stat));
			}
			if (WIFSIGNALED(stat)) {
				exit(128 + WTERMSIG(stat));
			}
			exit(EXIT_FAILURE);
		} else if (chroot_pid == 0) {
			container->pid_out = getpid();
			// Write RURI_PID_{PID} to the timeout_pid_fd.
			if (container->timeout_pid_fd >= 0) {
				char pid_str[64] = { 0 };
				snprintf(pid_str, sizeof(pid_str), "RURI_PID_%d", container->pid_out);
				write(container->timeout_pid_fd, pid_str, strlen(pid_str));
				close(container->timeout_pid_fd);
			}
			ruri_run_chroot_container(container);
		} else {
			ruri_error("{red}Failed to fork for chroot container QwQ\n");
		}
	}
	return 0;
}
//  ██╗ ██╗  ███████╗   ████╗   ███████╗
// ████████╗ ██╔════╝ ██╔═══██╗ ██╔════╝
// ╚██╔═██╔╝ █████╗   ██║   ██║ █████╗
// ████████╗ ██╔══╝   ██║   ██║ ██╔══╝
// ╚██╔═██╔╝ ███████╗ ╚██████╔╝ ██║
//  ╚═╝ ╚═╝  ╚══════╝  ╚═════╝  ╚═╝
