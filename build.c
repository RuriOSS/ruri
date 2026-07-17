// SPDX-License-Identifier: MIT
/*
 *
 * This file is part of ruri, with ABSOLUTELY NO WARRANTY.
 *
 * MIT License
 *
 * Copyright (c) 2025 Moe-hacker
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
 */
// SPDX-License-Identifier: MIT
/*
 *
 * This file is part of catsh, with ABSOLUTELY NO WARRANTY.
 *
 * MIT License
 *
 * Copyright (c) 2025 Moe-hacker
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
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
#ifndef __linux__
#error "This code is intended to be compiled on Linux systems only."
#endif
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <poll.h>
#include <sys/stat.h>
#include <stdint.h>
#include <time.h>
// Bool!!!
#if __STDC_VERSION__ < 202000L
#ifndef bool
#define bool _Bool
#define true ((_Bool)1u)
#define false ((_Bool)0u)
#endif
#endif
// Bionic does not have memfd_create()
#ifdef __ANDROID__
#define memfd_create(...) syscall(SYS_memfd_create, __VA_ARGS__)
#endif
#define cth_debug(x) \
	do {         \
		x    \
	} while (0)
#define cth_log(format, ...)                                                                                                  \
	{                                                                                                                     \
		struct timeval tv;                                                                                            \
		gettimeofday(&tv, NULL);                                                                                      \
		fprintf(stderr, "[%ld.%06ld] in %s() in %s line %d:\n", tv.tv_sec, tv.tv_usec, __func__, __FILE__, __LINE__); \
		fprintf(stderr, format, ##__VA_ARGS__);                                                                       \
	}
#define CTH_EXIT_FAILURE 114
#define CTH_EXIT_SUCCESS 0
#define CTH_VERSION_MAJOR 0
#define CTH_VERSION_MINOR 9
#define CTH_VERSION_PATCH 3
#define CTH_VERSION_STRING "0.9.3"
// 128 MiB, for output capturing, should be enough for most cases. Can be changed in the future if needed.
#define CTH_MAX_OUTPUT_SIZE (1024 * 1024 * 128)
struct __attribute__((packed, aligned(1))) cth_result {
	uint32_t cth_version;
	size_t struct_size;
	bool exited;
	int exit_code;
	char *stdout_ret;
	char *stderr_ret;
	pid_t pid;
	// Deprecated, always -1.
	pid_t ppid;
	// In microseconds, for more accurate time measurement. Deprecated, use time_used_ms instead.
	useconds_t time_used;
	// New sections for non-blocking exec.
	// Just overuse memfd magic!
	int stat_fd;
	int stdout_fd;
	int stderr_fd;
	int time_fd;
	// Time used in milliseconds.
	uint64_t time_used_ms;
	// Reserved space for future expansion, should be zeroed.
	uint8_t reserved[256 - sizeof(int) - sizeof(int) - sizeof(int) - sizeof(int) - sizeof(uint64_t)];
};
#define CTH_VERSION ((CTH_VERSION_MAJOR << 16) | (CTH_VERSION_MINOR << 8) | (CTH_VERSION_PATCH))
#define CTH_ABI_COMPATIBLE(res) ((res) != NULL && (res)->cth_version <= CTH_VERSION && (res)->struct_size == sizeof(struct cth_result))
int cth_add_arg(char ***argv, char *arg);
void cth_free_argv(char ***argv);
void cth_free_result(struct cth_result **res);
struct cth_result *cth_exec(char **argv, char *input, bool block, bool get_output);
int cth_fork_rexec_self(char *const argv[]);
int cth_exec_command(char **argv);
int cth_wait(struct cth_result **res);
void *cth_init_argv(void);
struct cth_result *cth_exec_with_file_input(char **argv, int fd, bool block, bool get_output, void (*progress)(float, int), int progress_line_num);
void cth_show_progress(float progress, int line_num);
#define CTH_EXEC_SUCCEED(res) ((res) != NULL && (res)->exited && ((res)->exit_code == 0))
#define CTH_EXEC_FAILED(res) ((res) != NULL && (res)->exited && ((res)->exit_code != 0))
#define CTH_EXEC_RUNNING(res) ((res) != NULL && !(res)->exited)
#define CTH_EXEC_CANNOT_RUN(res) ((res) == NULL)
//
// This program is a new build system for ruri
// It does not depend on any external build system.
// And it's independent of existing configure.ac and CMakeLists.txt
// I just want to show you that, we can do it, and it works fine.
//
// ANYWAY, IT IS A BIG STEP BACKWARDS THE HISTORY OF COMPUTER SCIENCE!!!
//
// This program has Super Neko Powers
//
// Damn bro, it's only for Linux
#ifndef __linux__
#error "This code is only for Linux"
#endif
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <limits.h>
#include <dirent.h>
#include <sys/time.h>
#include <float.h>
#include <linux/limits.h>
#include <sys/prctl.h>
#include <signal.h>
#include <sched.h>
#include <syscall.h>
#if __STDC_VERSION__ < 202000L
#ifndef bool
#define bool _Bool
#define true ((_Bool) + 1u)
#define false ((_Bool) + 0u)
#endif
#endif
#define ERROR_NUM 114
#define error(...)                                                                       \
	{                                                                                \
		fprintf(stderr, "Error in %s:%s%d: ", __FILE__, __FUNCTION__, __LINE__); \
		fprintf(stderr, __VA_ARGS__);                                            \
		fprintf(stderr, "\n");                                                   \
		on_exit__(SIGINT);                                                       \
		exit(ERROR_NUM);                                                         \
	}
void remove_test_dot_c(void);
void on_exit__(int sig)
{
	printf("Exiting %d......\n", getpid());
	while (waitpid(-1, NULL, WNOHANG) > 0)
		;
	remove_test_dot_c();
	exit(ERROR_NUM);
}
int fork_exec(char **argv)
{
	// Return -1 if failed to exec()
	// Or return same as exec()ed program.
	struct cth_result *result = cth_exec(argv, NULL, true, false);
	int ret = -1;
	ret = result ? result->exit_code : -1;
	cth_free_result(&result);
	return ret;
}
char *fork_execvp_get_stdout(char **argv)
{
	/*
	 * Warning: free() after use.
	 * We will fork(2) and then execvp(3).
	 * And then we will get the stdout of the child process.
	 * Return the stdout of the child process.
	 * If failed, return NULL.
	 */
	struct cth_result *result = cth_exec(argv, NULL, true, true);
	char *output = result->stdout_ret ? strdup(result->stdout_ret) : NULL;
	cth_free_result(&result);
	return output;
}
// Never mind, this is safe broooo
char **CFLAGS = NULL;
char **LIBS = NULL;
char *CC = "cc";
char *STRIP = "strip";
char *BUILD_DIR = "out";
char *SRC_DIR = NULL;
char **OBJS = NULL;
char *OUTPUT = NULL;
char *COMMIT_ID = NULL;
int JOBS = 8;
bool FORCE = false; // Force rebuild all files
// Not only args, but (char **) in fact.
void add_args(char ***argv, const char *arg)
{
	if (*argv == NULL) {
		*argv = malloc(2 * sizeof(char *));
		if (!*argv) {
			error("Error: Failed to allocate memory for args");
		}
		(*argv)[0] = strdup(arg);
		if (!(*argv)[0]) {
			free(*argv);
			*argv = NULL;
			error("Error: Failed to duplicate string for args");
		}
		(*argv)[1] = NULL;
	} else {
		size_t len = 0;
		while ((*argv)[len] != NULL)
			len++;
		char **new_argv = realloc(*argv, (len + 2) * sizeof(char *));
		if (!new_argv) {
			error("Error: Failed to reallocate memory for args");
		}
		*argv = new_argv;
		(*argv)[len] = strdup(arg);
		if (!(*argv)[len]) {
			error("Error: Failed to duplicate string for args");
		}
		(*argv)[len + 1] = NULL;
	}
}
// Not only args, but (char **) in fact.
void free_args(char **arg)
{
	for (int i = 0; arg && arg[i] != NULL; i++) {
		free(arg[i]);
	}
	free(arg);
}
// For testing compile environment
void remove_test_dot_c(void)
{
	remove("test.c");
	unlink("test.c");
	rmdir("test.c");
}
void create_test_dot_c(void)
{
	remove_test_dot_c();
	FILE *fp = fopen("test.c", "w");
	if (!fp) {
		error("Failed to create test.c");
	}
	fprintf(fp, "#include <stdio.h>\n");
	fprintf(fp, "int main(void) {\n");
	fprintf(fp, "    printf(\"Hello, World!\\n\");\n");
	fprintf(fp, "    return 0;\n");
	fprintf(fp, "}\n");
	fclose(fp);
}
// Check if CC supports a specific C flag
bool check_c_flag(const char *flag)
{
	create_test_dot_c();
	char **args = NULL;
	add_args(&args, CC);
	for (int i = 0; CFLAGS && CFLAGS[i] != NULL; i++) {
		add_args(&args, CFLAGS[i]);
	}
	add_args(&args, flag);
	add_args(&args, "-o");
	add_args(&args, "/dev/null");
	add_args(&args, "test.c");
	for (int i = 0; LIBS && LIBS[i] != NULL; i++) {
		add_args(&args, LIBS[i]);
	}
	if (fork_exec(args) != 0) {
		printf("Check for flag %s :failed\n", flag);
		free_args(args);
		return false;
	}
	free_args(args);
	printf("Check for flag %s :success\n", flag);
	return true;
}
// Check if we can use a specific library
bool check_lib(const char *lib)
{
	create_test_dot_c();
	char **args = NULL;
	add_args(&args, CC);
	for (int i = 0; CFLAGS && CFLAGS[i] != NULL; i++) {
		add_args(&args, CFLAGS[i]);
	}
	add_args(&args, "-o");
	add_args(&args, "/dev/null");
	add_args(&args, "test.c");
	for (int i = 0; LIBS && LIBS[i] != NULL; i++) {
		add_args(&args, LIBS[i]);
	}
	add_args(&args, lib);
	if (fork_exec(args) != 0) {
		printf("Check for lib %s :failed\n", lib);
		free_args(args);
		return false;
	}
	free_args(args);
	printf("Check for lib %s :success\n", lib);
	return true;
}
// init
void init_env(void)
{
	create_test_dot_c();
	if (getenv("CC")) {
		CC = getenv("CC");
	}
	if (getenv("STRIP")) {
		STRIP = getenv("STRIP");
	}
	if (getenv("CFLAGS")) {
		char *flags = strdup(getenv("CFLAGS"));
		if (!flags) {
			error("Error: Failed to duplicate CFLAGS string");
		}
		char *token = strtok(flags, " ");
		while (token) {
			add_args(&CFLAGS, token);
			token = strtok(NULL, " ");
		}
		free(flags);
	}
	char **arg = NULL;
	add_args(&arg, CC);
	for (int i = 0; CFLAGS && CFLAGS[i] != NULL; i++) {
		add_args(&arg, CFLAGS[i]);
	}
	add_args(&arg, "-o");
	add_args(&arg, "/dev/null");
	add_args(&arg, "test.c");
	if (fork_exec(arg) != 0) {
		error("Error: Compiler %s failed to compile %s\n", CC, "test.c");
		exit(ERROR_NUM);
	}
	printf("CC: %s\n", CC);
	free_args(arg);
	char *commit_id = fork_execvp_get_stdout((char *[]){ "git", "rev-parse", "--short", "HEAD", NULL });
	if (commit_id) {
		if (commit_id[strlen(commit_id) - 1] == '\n') {
			commit_id[strlen(commit_id) - 1] = '\0';
		}
		printf("Commit ID: %s\n", commit_id);
	} else {
		printf("Warning: failed to get commit ID\n");
	}
	COMMIT_ID = commit_id;
	if (fork_exec((char *[]){ STRIP, "--version", NULL }) != 0) {
		STRIP = NULL;
	} else {
		printf("STRIP: %s\n", STRIP);
	}
}
// Switch to the build directory
void switch_to_build_dir(char *dir)
{
	// Check for src dir
	SRC_DIR = realpath("./src", NULL);
	if (!SRC_DIR) {
		error("Error: failed to resolve path for ./src\n");
	}
	char *basedir = realpath(".", NULL);
	if (!basedir) {
		error("Error: failed to resolve current directory path\n");
	}
	static char out[PATH_MAX];
	sprintf(out, "%s/%s", basedir, "ruri");
	OUTPUT = out;
	free(basedir);
	// Change to the build directory
	mkdir(dir, 0755);
	if (chdir(dir) != 0) {
		error("Error: failed to change directory to %s\n", dir);
	}
	BUILD_DIR = realpath(".", NULL);
	if (!BUILD_DIR) {
		error("Error: failed to resolve build directory path\n");
	}
}
// Get file name without path
char *basename_of(const char *path)
{
	const char *name = strrchr(path, '/');
	return name ? (char *)(name + 1) : (char *)path;
}
int copy_file(const char *src, const char *dest)
{
	int src_fd = open(src, O_RDONLY);
	if (src_fd < 0) {
		perror("Error opening source file");
		return -1;
	}
	int dest_fd = open(dest, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (dest_fd < 0) {
		perror("Error opening destination file");
		printf("%s\n", dest);
		close(src_fd);
		return -1;
	}
	struct stat st;
	if (fstat(src_fd, &st) < 0) {
		perror("Error getting source file size");
		close(src_fd);
		close(dest_fd);
		return -1;
	}
	ssize_t result = syscall(SYS_sendfile, dest_fd, src_fd, NULL, st.st_size);
	if (result < 0) {
		perror("Error copying file with sendfile");
		close(src_fd);
		close(dest_fd);
		return -1;
	}
	close(src_fd);
	close(dest_fd);
	return 0;
}
bool file_diff(char *file1, char *file2)
{
	/*
	 * Check if two files are different.
	 * Return true if they are different, false if they are the same.
	 */
	int fd1 = open(file1, O_RDONLY);
	if (fd1 < 0) {
		perror("Error opening file1");
		return true;
	}
	int fd2 = open(file2, O_RDONLY);
	if (fd2 < 0) {
		perror("Error opening file2");
		close(fd1);
		return true;
	}
	// Check file size.
	struct stat st1, st2;
	if (fstat(fd1, &st1) < 0 || fstat(fd2, &st2) < 0) {
		close(fd1);
		close(fd2);
		return true;
	}
	if (st1.st_size != st2.st_size) {
		close(fd1);
		close(fd2);
		return true;
	}
	char buf1[4096], buf2[4096];
	ssize_t read1, read2;
	while ((read1 = read(fd1, buf1, sizeof(buf1))) > 0 && (read2 = read(fd2, buf2, sizeof(buf2))) > 0) {
		if (read1 != read2 || memcmp(buf1, buf2, read1) != 0) {
			close(fd1);
			close(fd2);
			return true; // Files are different
		}
	}
	close(fd1);
	close(fd2);
	return false; // Files are the same
}
char *gen_obj_name(const char *file)
{
	/*
	 * Generate object file name from source file name.
	 * For example, if file is "src/main.c", it will return "main.o".
	 */
	char *base = strstr(file, SRC_DIR);
	if (!base) {
		error("Error: Failed to find source directory in file path");
	}
	base += strlen(SRC_DIR) + 1;
	base = strdup(base);
	for (int i = 0; i < strlen(base); i++) {
		if (base[i] == '/') {
			base[i] = '_';
		}
	}
	static char obj_name[PATH_MAX];
	sprintf(obj_name, "%s.o", base);
	free(base);
	return obj_name;
}
// Compile the specified source file to file.o
void compile(char *file)
{
	char **args = NULL;
	add_args(&args, CC);
	for (int i = 0; CFLAGS && CFLAGS[i] != NULL; i++) {
		add_args(&args, CFLAGS[i]);
	}
	add_args(&args, "-c");
	add_args(&args, "-o");
	char *output_file = gen_obj_name(file);
	add_args(&args, output_file);
	// Check if already compiled
	char saved_source_file[PATH_MAX];
	sprintf(saved_source_file, ".%s.c", output_file);
	if (access(saved_source_file, F_OK) == 0 && access(output_file, F_OK) == 0) {
		if (!file_diff(file, saved_source_file) && !FORCE) {
			printf("Compile %s :skipped\n", file);
			free_args(args);
			return;
		}
	}
	copy_file(file, saved_source_file);
	// Compile
	remove(output_file);
	unlink(output_file);
	rmdir(output_file);
	add_args(&args, file);
	struct cth_result *exec_result = cth_exec(args, NULL, true, true);
	if (!exec_result) {
		error("Error: failed to execute compiler for %s\n", file);
	} else if (!exec_result->exited || exec_result->exit_code != 0) {
		error("Error: failed to compile %s\nCompiler output:\nstderr:\n%s\nstdout:\n%s\n", file, exec_result->stderr_ret ? exec_result->stderr_ret : "No output", exec_result->stdout_ret ? exec_result->stdout_ret : "No output");
	}
	free_args(args);
	printf("Compile %s :success\n", file);
}
int pmcrts(const char *s1, const char *s2)
{
	/*
	 *
	 * Compare two strings, but s2 is in the end of s1.
	 * Return the same value as strcmp() s2 and the end of s1.
	 * If s1 is shorter than s2, it will return -1.
	 *
	 */
	size_t len1 = strlen(s1);
	size_t len2 = strlen(s2);
	if (len1 < len2) {
		return -1; // s1 is shorter than s2
	}
	return strcmp(s2, s1 + len1 - len2);
}
// Find files in a directory
char **find_file(char *dir, const char *end_match, char **blacklist)
{
	DIR *d = opendir(dir);
	if (!d) {
		return NULL;
	}
	struct dirent *entry;
	char **files = NULL;
	while ((entry = readdir(d)) != NULL) {
		if (entry->d_type == DT_REG && pmcrts(entry->d_name, end_match) == 0) {
			bool skip = false;
			for (int i = 0; blacklist && blacklist[i] != NULL; i++) {
				if (pmcrts(entry->d_name, blacklist[i]) == 0) {
					skip = true;
					break;
				}
			}
			if (!skip) {
				char relative_path[PATH_MAX];
				sprintf(relative_path, "%s/%s", dir, entry->d_name);
				char *absolute_path = realpath(relative_path, NULL);
				if (!absolute_path) {
					perror("Error resolving absolute path");
					continue;
				}
				add_args(&files, absolute_path);
				free(absolute_path);
			}
		}
	}
	closedir(d);
	return files;
}
// Compile source files in parallel
void compile_files_parallel(char **files, int max_processes)
{
	if (!files)
		return;
	int file_count = 0;
	while (files[file_count] != NULL)
		file_count++;
	if (file_count == 0)
		return;
	int active_processes = 0;
	int completed = 0;
	int current_file = 0;
	while (completed < file_count) {
		// Start new processes up to the limit
		while (active_processes < max_processes && current_file < file_count) {
			pid_t pid = fork();
			if (pid == 0) {
				// Child process - compile one file
				compile(files[current_file]);
				exit(EXIT_SUCCESS);
			} else if (pid > 0) {
				// Parent process
				active_processes++;
				current_file++;
			} else {
				error("Error: failed to fork process for %s\n", files[current_file]);
			}
		}
		// Wait for at least one child to complete
		if (active_processes > 0) {
			int status;
			pid_t finished_pid = wait(&status);
			if (finished_pid > 0) {
				active_processes--;
				completed++;
				if (WEXITSTATUS(status) != 0) {
					error("Error: compilation failed in child process\n");
				}
			}
		}
	}
	// Wait for any remaining processes
	while (active_processes > 0) {
		int status;
		wait(&status);
		active_processes--;
		if (WEXITSTATUS(status) != 0) {
			error("Error: compilation failed in child process\n");
		}
	}
	// Add compiled object files to OBJS
	for (int i = 0; i < file_count; i++) {
		char *obj_file = gen_obj_name(files[i]);
		add_args(&OBJS, obj_file);
	}
}
// Build
void build()
{
	// compile src/*.c and src/easteregg/*.c
	char **files = find_file(SRC_DIR, ".c", NULL);
	char easteregg_src[PATH_MAX];
	sprintf(easteregg_src, "%s/easteregg", SRC_DIR);
	char **easteregg_files = find_file(easteregg_src, ".c", NULL);
	for (int i = 0; easteregg_files && easteregg_files[i] != NULL; i++) {
		add_args(&files, easteregg_files[i]);
	}
	compile_files_parallel(files, JOBS);
	free_args(easteregg_files);
	free_args(files);
	// Link
	char **args = NULL;
	add_args(&args, CC);
	for (int i = 0; CFLAGS && CFLAGS[i] != NULL; i++) {
		add_args(&args, CFLAGS[i]);
	}
	add_args(&args, "-o");
	add_args(&args, OUTPUT);
	for (int i = 0; OBJS && OBJS[i] != NULL; i++) {
		add_args(&args, OBJS[i]);
	}
	for (int i = 0; LIBS && LIBS[i] != NULL; i++) {
		add_args(&args, LIBS[i]);
	}
	struct cth_result *exec_result = cth_exec(args, NULL, true, true);
	if (!exec_result) {
		error("Error: failed to execute linker\n");
	} else if (!exec_result->exited || exec_result->exit_code != 0) {
		error("Error: failed to link object files\nLinker output:\nstderr:\n%s\nstdout:\n%s\n", exec_result->stderr_ret ? exec_result->stderr_ret : "No output", exec_result->stdout_ret ? exec_result->stdout_ret : "No output");
	}
	printf("Link %s :success\n", OUTPUT);
	free_args(args);
	// Strip
	if (STRIP) {
		if (fork_exec((char *[]){ STRIP, OUTPUT, NULL }) != 0) {
			error("Error: failed to strip object files\n");
		} else {
			printf("Strip %s :success\n", OUTPUT);
		}
	} else {
		printf("Skipping strip: STRIP not set\n");
	}
	printf("Output: %s\n", OUTPUT);
}
// As the name said
void check_and_add_cflag(char *flag, bool panic)
{
	if (check_c_flag(flag)) {
		add_args(&CFLAGS, flag);
	} else if (panic) {
		error("Error: C flag %s is not supported\n", flag);
	}
}
// As the name said
void check_and_add_lib(char *lib, bool panic)
{
	if (check_lib(lib)) {
		add_args(&LIBS, lib);
	} else if (panic) {
		error("Error: Library %s is not supported\n", lib);
	}
}
// Default cflags
void default_cflags(void)
{
	check_and_add_cflag("-ftrivial-auto-var-init=pattern", false);
	check_and_add_cflag("-fcf-protection=full", false);
	check_and_add_cflag("-flto=auto", false);
	check_and_add_cflag("-fPIE", false);
	check_and_add_cflag("-pie", false);
	check_and_add_cflag("-Wl,-z,relro", false);
	check_and_add_cflag("-Wl,-z,noexecstack", false);
	check_and_add_cflag("-Wl,-z,now", false);
	check_and_add_cflag("-fstack-protector-all", false);
	check_and_add_cflag("-fstack-clash-protection", false);
	check_and_add_cflag("-mshstk", false);
	check_and_add_cflag("-Wno-unused-result", false);
	check_and_add_cflag("-O2", false);
	check_and_add_cflag("-Wl,--build-id=sha1", false);
	check_and_add_cflag("-ffunction-sections", false);
	check_and_add_cflag("-fdata-sections", false);
	check_and_add_cflag("-Wl,--gc-sections", false);
	check_and_add_cflag("-Wl,--strip-all", false);
	check_and_add_cflag("-U_FORTIFY_SOURCE", false);
	check_and_add_cflag("-D_FORTIFY_SOURCE=3", false);
}
// Dev cflags
void dev_cflags(void)
{
	check_and_add_cflag("-g", true);
	check_and_add_cflag("-O0", false);
	check_and_add_cflag("-fno-omit-frame-pointer", false);
	check_and_add_cflag("-Wl,-z,norelro", false);
	check_and_add_cflag("-Wl,-z,execstack", false);
	check_and_add_cflag("-fno-stack-protector", false);
	check_and_add_cflag("-Wconversion", false);
	check_and_add_cflag("-Wno-newline-eof", false);
	check_and_add_cflag("-Wno-gnu-zero-variadic-macro-arguments", false);
	check_and_add_cflag("-fsanitize=address,undefined", false);
	check_and_add_cflag("-Wl,--build-id=sha1", false);
	check_and_add_cflag("-ffunction-sections", false);
	check_and_add_cflag("-fdata-sections", false);
	check_and_add_cflag("-Wl,--gc-sections", false);
	check_and_add_cflag("-DRURI_DEBUG", false);
	check_and_add_cflag("-DRURI_DEV", false);
	STRIP = "true";
}
void show_help(void)
{
	char *self_path = realpath("/proc/self/exe", NULL);
	printf("Usage: ./%s [OPTION]...\n", basename_of(self_path));
	printf("    -h, --help             show help\n");
	printf("    -s, --static           compile static binary\n");
	printf("    -d, --dev              compile dev version\n");
	printf("    -f, --force            force rebuild\n");
	printf("    -j, --jobs <num>       number of jobs to run simultaneously\n");
	printf("    -c, --core-only        build core only\n");
}
// So good brooooo, the program works with magic here.
int main(int argc, char **argv)
{
	signal(SIGINT, on_exit__);
	switch_to_build_dir("out");
	init_env();
	bool cflags_configured = false;
	bool core_only = false;
	bool profiling = false;
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--dev") == 0 || strcmp(argv[i], "-d") == 0) {
			dev_cflags();
			cflags_configured = true;
		} else if (strcmp(argv[i], "--force") == 0 || strcmp(argv[i], "-f") == 0) {
			FORCE = true;
		} else if ((strcmp(argv[i], "--jobs") == 0 || strcmp(argv[i], "-j") == 0) && i + 1 < argc) {
			JOBS = atoi(argv[++i]);
			if (JOBS <= 0) {
				error("Error: Invalid number of jobs: %s", argv[i]);
			}
		} else if (strcmp(argv[i], "--static") == 0 || strcmp(argv[i], "-s") == 0) {
			check_and_add_cflag("-static", true);
		} else if (strcmp(argv[i], "--core-only") == 0 || strcmp(argv[i], "-c") == 0) {
			core_only = true;
		} else if (strcmp(argv[i], "--profiling") == 0 || strcmp(argv[i], "-p") == 0) {
			profiling = true;
		} else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
			show_help();
			exit(0);
		} else {
			show_help();
			error("Error: Unknown option: %s", argv[i]);
		}
	}
	if (!cflags_configured) {
		default_cflags();
	}
	check_and_add_cflag("-std=gnu11", true);
	if (COMMIT_ID) {
		char define_commit[PATH_MAX];
		sprintf(define_commit, "-DRURI_COMMIT_ID=\"%s\"", COMMIT_ID);
		check_and_add_cflag(define_commit, false);
	} else {
		check_and_add_cflag("-DRURI_COMMIT_ID=unknown", false);
	}
	if (!core_only) {
		check_and_add_lib("-lcap", true);
		check_and_add_lib("-lseccomp", true);
		check_and_add_lib("-lpthread", false);
	} else {
		check_and_add_cflag("-DRURI_CORE_ONLY", true);
		check_and_add_cflag("-DDISABLE_LIBCAP", true);
		check_and_add_cflag("-DDISABLE_SECCOMP", true);
		check_and_add_cflag("-DDISABLE_RURIENV", true);
	}
	if(profiling) {
		check_and_add_cflag("-DRURI_PROFILING", true);
	}
	build();
	remove_test_dot_c();
	printf("\n\nThe tail will never wag the cat.\n");
	printf("But this program has Super Neko Powers! >w<\n");
	return 0;
}
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
// SPDX-License-Identifier: MIT
/*
 *
 * This file is part of catsh, with ABSOLUTELY NO WARRANTY.
 *
 * MIT License
 *
 * Copyright (c) 2025 Moe-hacker
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
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
static struct cth_result *cth_new(void)
{
	/*
	 * Allocate and initialize a new cth_result structure.
	 * Returns a pointer to the new structure, or NULL on failure.
	 */
	struct cth_result *res = malloc(sizeof(struct cth_result));
	if (res == NULL) {
		return NULL;
	}
	res->exited = false;
	res->exit_code = -1;
	res->stdout_ret = NULL;
	res->stderr_ret = NULL;
	res->pid = -1;
	res->ppid = -1;
	res->time_used = 0;
	res->cth_version = CTH_VERSION;
	res->struct_size = sizeof(struct cth_result);
	res->stat_fd = -1;
	res->stdout_fd = -1;
	res->stderr_fd = -1;
	res->time_fd = -1;
	res->time_used_ms = 0;
	memset(res->reserved, 0, sizeof(res->reserved));
	return res;
}
int cth_add_arg(char ***argv, char *arg)
{
	/*
	 * Add an argument to the argv array.
	 * *argv: Pointer to the argv array. Can be NULL initially.
	 * arg: The argument to add, should be a null-terminated string.
	 * The argv array should be NULL-terminated.
	 * Returns 0 on success, -1 on failure.
	 * Warning: This function allocates memory.
	 * The caller is responsible for freeing it using cth_free_argv().
	 */
	size_t argc = 0;
	if (*argv != NULL) {
		while ((*argv)[argc] != NULL) {
			argc++;
		}
	}
	char **new_argv = realloc(*argv, sizeof(char *) * (argc + 2));
	if (new_argv == NULL) {
		return -1;
	}
	new_argv[argc] = strdup(arg);
	new_argv[argc + 1] = NULL;
	*argv = new_argv;
	return 0;
}
void cth_free_argv(char ***argv)
{
	/*
	 * Free the argv array and its contents.
	 * *argv: Pointer to the argv array, can be NULL.
	 * After calling this function, *argv will be set to NULL.
	 */
	if (*argv == NULL) {
		return;
	}
	size_t argc = 0;
	while ((*argv)[argc] != NULL) {
		free((*argv)[argc]);
		argc++;
	}
	free(*argv);
	*argv = NULL;
}
void cth_free_result(struct cth_result **res)
{
	/*
	 * Free the cth_result structure and its contents.
	 * *res: Pointer to the cth_result structure, can be NULL.
	 * After calling this function, *res will be set to NULL.
	 */
	if (*res == NULL) {
		return;
	}
	free((*res)->stdout_ret);
	free((*res)->stderr_ret);
	free(*res);
	*res = NULL;
}
void *cth_init_argv(void)
{
	/*
	 * Just a wrapper, returns NULL.
	 */
	return NULL;
}
static struct cth_result *cth_exec_block_without_stdio(char **argv)
{
	/*
	 * Just exec the command in blocking mode, without redirecting stdin/stdout/stderr.
	 * This is the simplest case.
	 */
	pid_t pid = fork();
	struct timeval start_time, end_time;
	gettimeofday(&start_time, NULL);
	// Just error handling.
	if (pid < 0) {
		return NULL;
	}
	// Child process, exec the command.
	if (pid == 0) {
		int fd = open("/dev/null", O_RDWR);
		if (fd < 0) {
			exit(CTH_EXIT_FAILURE);
		}
		dup2(fd, STDIN_FILENO);
		dup2(fd, STDOUT_FILENO);
		dup2(fd, STDERR_FILENO);
		if (fd > 2) {
			close(fd);
		}
		execvp(argv[0], argv);
		exit(CTH_EXIT_FAILURE);
	}
	// Parent process, wait for child to exit.
	struct cth_result *res = malloc(sizeof(struct cth_result));
	if (res == NULL) {
		return NULL;
	}
	res->pid = pid;
	res->ppid = -1;
	res->exited = false;
	res->exit_code = -1;
	res->stdout_ret = NULL;
	res->stderr_ret = NULL;
	int status = 0;
	// Wait for child process, handle EINTR.
	while (waitpid(pid, &status, 0) < 0) {
		if (errno == EINTR) {
			continue;
		}
		free(res);
		return NULL;
	}
	gettimeofday(&end_time, NULL);
	// Calculate time used in microseconds.
	res->time_used = (end_time.tv_sec - start_time.tv_sec) * 1000000 + (end_time.tv_usec - start_time.tv_usec);
	// Calculate time used in ms.
	res->time_used_ms = (end_time.tv_sec - start_time.tv_sec) * 1000 + (end_time.tv_usec - start_time.tv_usec) / 1000;
	// Get exit code.
	res->exited = true;
	if (WIFEXITED(status)) {
		res->exit_code = WEXITSTATUS(status);
	} else if (WIFSIGNALED(status)) {
		res->exit_code = 128 + WTERMSIG(status);
	} else {
		res->exit_code = -1;
	}
	return res;
}
static size_t pipe_buf_size(int fd)
{
	/*
	 * Get the pipe buffer size using fcntl.
	 * Returns the size on success, 0 on failure.
	 * Note: this function will also try to set the pipe buffer size to the maximum allowed size.
	 * As this is a internal function, we can do this.
	 */
	// Try to set the pipe buffer size to a large value.
	// Get max allowed size from /proc/sys/fs/pipe-max-size.
	FILE *f = fopen("/proc/sys/fs/pipe-max-size", "r");
	if (f) {
		char line[32];
		if (fgets(line, sizeof(line), f)) {
			size_t max_size = strtoul(line, NULL, 10);
			if (max_size > 0) {
				fcntl(fd, F_SETPIPE_SZ, max_size);
			}
		}
		fclose(f);
	}
	// Get the pipe buffer size using fcntl.
	int size = fcntl(fd, F_GETPIPE_SZ);
	if (size < 0) {
		return 0;
	}
	return (size_t)size;
}
static struct cth_result *cth_exec_block(char **argv, char *input, bool get_output);
static struct cth_result *cth_exec_nonblock(char **argv, char *input, bool get_output)
{
	char memfd_name[32];
	// Never mind, memfd does not really need a unique name, and we will not search it by name as well.
	// NOLINTBEGIN
	srand((unsigned int)time(NULL));
	snprintf(memfd_name, sizeof(memfd_name), "cth_memfd_stdout_%d", rand());
	int stdout_fd = memfd_create(memfd_name, MFD_CLOEXEC);
	snprintf(memfd_name, sizeof(memfd_name), "cth_memfd_stderr_%d", rand());
	int stderr_fd = memfd_create(memfd_name, MFD_CLOEXEC);
	snprintf(memfd_name, sizeof(memfd_name), "cth_memfd_stat_%d", rand());
	int stat_fd = memfd_create(memfd_name, MFD_CLOEXEC);
	snprintf(memfd_name, sizeof(memfd_name), "cth_memfd_pid_%d", rand());
	int pid_fd = memfd_create(memfd_name, MFD_CLOEXEC);
	snprintf(memfd_name, sizeof(memfd_name), "cth_memfd_time_%d", rand());
	int time_fd = memfd_create(memfd_name, MFD_CLOEXEC);
	// NOLINTEND
	if (stdout_fd < 0 || stderr_fd < 0 || stat_fd < 0 || pid_fd < 0 || time_fd < 0) {
		if (stdout_fd >= 0) {
			close(stdout_fd);
		}
		if (stderr_fd >= 0) {
			close(stderr_fd);
		}
		if (stat_fd >= 0) {
			close(stat_fd);
		}
		if (time_fd >= 0) {
			close(time_fd);
		}
		if (pid_fd >= 0) {
			close(pid_fd);
		}
		return NULL;
	}
	pid_t pid = fork();
	if (pid < 0) {
		return NULL;
	}
	if (pid > 0) {
		waitpid(pid, NULL, 0);
		struct cth_result *res = cth_new();
		res->stat_fd = stat_fd;
		res->stdout_fd = stdout_fd;
		res->stderr_fd = stderr_fd;
		res->time_fd = time_fd;
		// Wait pid_fd, and get pid.
		char pid_buf[32];
		while (true) {
			lseek(pid_fd, 0, SEEK_SET);
			ssize_t n = read(pid_fd, pid_buf, sizeof(pid_buf) - 1);
			if (n > 0) {
				pid_buf[n] = 0;
				char *endptr;
				res->pid = (pid_t)strtoul(pid_buf, &endptr, 10);
				if (endptr == pid_buf || *endptr != 0) {
					// Invalid pid, treat as error.
					close(pid_fd);
					close(stat_fd);
					close(stdout_fd);
					close(stderr_fd);
					free(res);
					return NULL;
				}
				break;
			} else if ((n < 0 && errno == EINTR) || n == 0) {
				continue;
			} else if (n < 0) {
				// error, give up.
				close(pid_fd);
				close(stat_fd);
				close(stdout_fd);
				close(stderr_fd);
				free(res);
				return NULL;
			}
		}
		close(pid_fd);
		return res;
	}
	pid_t exec_pid = fork();
	if (exec_pid < 0) {
		write(pid_fd, "CTH_ERROR", 9);
		_exit(CTH_EXIT_FAILURE);
	}
	if (exec_pid > 0) {
		_exit(CTH_EXIT_SUCCESS);
	}
	char pid_str[32];
	snprintf(pid_str, sizeof(pid_str), "%d", getpid());
	write(pid_fd, pid_str, strlen(pid_str));
	struct cth_result *exec_res = cth_exec_block(argv, input, get_output);
	if (exec_res == NULL) {
		write(stat_fd, "CTH_ERROR", 9);
		_exit(CTH_EXIT_FAILURE);
	}
	if (get_output) {
		if (exec_res->stdout_ret) {
			lseek(stdout_fd, 0, SEEK_SET);
			// Buffered write to stdout_fd, as the output can be large.
			size_t total_written = 0;
			size_t to_write = strlen(exec_res->stdout_ret);
			while (total_written < to_write) {
				ssize_t n = write(stdout_fd, exec_res->stdout_ret + total_written, to_write - total_written);
				if (n > 0) {
					total_written += n;
				} else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
					// write buffer full, wait for it to be available.
					struct pollfd pfd;
					pfd.fd = stdout_fd;
					pfd.events = POLLOUT;
					poll(&pfd, 1, -1);
				} else {
					// error, give up writing.
					break;
				}
			}
		}
		if (exec_res->stderr_ret) {
			lseek(stderr_fd, 0, SEEK_SET);
			// Buffered write to stderr_fd, as the output can be large.
			size_t total_written = 0;
			size_t to_write = strlen(exec_res->stderr_ret);
			while (total_written < to_write) {
				ssize_t n = write(stderr_fd, exec_res->stderr_ret + total_written, to_write - total_written);
				if (n > 0) {
					total_written += n;
				} else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
					// write buffer full, wait for it to be available.
					struct pollfd pfd;
					pfd.fd = stderr_fd;
					pfd.events = POLLOUT;
					poll(&pfd, 1, -1);
				} else {
					// error, give up writing.
					break;
				}
			}
			// Read from stderr_fd to make sure the data is consumed by parent process, to avoid child process being blocked on write.
			char buf[1024];
			lseek(stderr_fd, 0, SEEK_SET);
			int tt = read(stderr_fd, buf, sizeof(buf));
			buf[tt] = 0;
		}
	}
	char time_used_ms[128];
	snprintf(time_used_ms, sizeof(time_used_ms), "%llu", (unsigned long long)exec_res->time_used_ms);
	lseek(time_fd, 0, SEEK_SET);
	write(time_fd, time_used_ms, strlen(time_used_ms));
	char stat_str[32];
	snprintf(stat_str, sizeof(stat_str), "%d", exec_res->exit_code);
	lseek(stat_fd, 0, SEEK_SET);
	write(stat_fd, stat_str, strlen(stat_str));
	_exit(CTH_EXIT_SUCCESS);
}
// API function.
struct cth_result *cth_exec(char **argv, char *input, bool block, bool get_output)
{
	/*
	 * Exec the command with given arguments.
	 * argv: The command and its arguments, NULL-terminated array of strings.
	 * input: The input to be passed to the command's stdin, can be NULL.
	 * block: If true, wait for the command to finish and return the result.
	 *        If false, return immediately (not implemented yet).
	 * get_output: If true, capture stdout and stderr output.
	 * Returns a cth_result structure on success, NULL on failure.
	 * The caller is responsible for freeing the result using cth_free_result().
	 */
	if (argv == NULL || argv[0] == NULL) {
		return NULL;
	}
	// For now, only blocking mode is implemented.
	if (block) {
		return cth_exec_block(argv, input, get_output);
	}
	return cth_exec_nonblock(argv, input, get_output);
}
// API function.
int cth_exec_command(char **argv)
{
	/*
	 * Just exec the command in blocking mode, and return the exit code.
	 * If the command cannot be executed, return -1.
	 * This is a simple wrapper around cth_exec().
	 */
	struct cth_result *res = cth_exec(argv, NULL, true, false);
	if (res == NULL) {
		return -1;
	}
	int exit_code = res->exit_code;
	cth_free_result(&res);
	return exit_code;
}
int cth_wait(struct cth_result **res)
{
	if (res == NULL || *res == NULL) {
		return -1;
	}
	struct cth_result *r = *res;
	// Get r->stat_fd, read exit code from it.
	if (r->stat_fd >= 0) {
		char stat_buf[32];
		lseek(r->stat_fd, 0, SEEK_SET);
		ssize_t n = read(r->stat_fd, stat_buf, sizeof(stat_buf) - 1);
		if (n > 0) {
			stat_buf[n] = 0;
			char *endptr;
			int exit_code = (int)strtol(stat_buf, &endptr, 10);
			if (endptr != stat_buf && *endptr == 0) {
				r->exit_code = exit_code;
				r->exited = true;
				close(r->stat_fd);
				// read time used from r->time_fd.
				if (r->time_fd >= 0) {
					char time_buf[128];
					lseek(r->time_fd, 0, SEEK_SET);
					ssize_t tn = read(r->time_fd, time_buf, sizeof(time_buf) - 1);
					if (tn > 0) {
						time_buf[tn] = 0;
						char *endptr;
						long long time_used_ms = strtoll(time_buf, &endptr, 10);
						if (endptr != time_buf && *endptr == 0) {
							r->time_used_ms = (uint64_t)time_used_ms;
							r->time_used = r->time_used_ms * 1000; // convert ms to us.
						}
					}
					close(r->time_fd);
				}
				// read stdout and stderr from their fds if needed.
				if (r->stdout_fd >= 0) {
					lseek(r->stdout_fd, 0, SEEK_SET);
					char *stdout_buf = NULL;
					size_t stdout_size = 0;
					size_t BUF_CHUNK = 4096;
					while (true) {
						if (stdout_size + BUF_CHUNK > CTH_MAX_OUTPUT_SIZE) {
							// Limit stdout buffer to CTH_MAX_OUTPUT_SIZE.
							break;
						}
						stdout_buf = realloc(stdout_buf, stdout_size + BUF_CHUNK);
						ssize_t n = read(r->stdout_fd, stdout_buf + stdout_size, BUF_CHUNK);
						if (n > 0) {
							stdout_size += n;
						} else if (n < 0 && errno == EINTR) {
							continue;
						} else {
							break;
						}
					}
					if (stdout_buf) {
						stdout_buf = realloc(stdout_buf, stdout_size + 1);
						stdout_buf[stdout_size] = 0;
						r->stdout_ret = stdout_buf;
					} else {
						r->stdout_ret = NULL;
					}
					close(r->stdout_fd);
					r->stdout_fd = -1;
				}
				if (r->stderr_fd >= 0) {
					lseek(r->stderr_fd, 0, SEEK_SET);
					char *stderr_buf = NULL;
					size_t stderr_size = 0;
					size_t BUF_CHUNK = 4096;
					while (true) {
						if (stderr_size + BUF_CHUNK > CTH_MAX_OUTPUT_SIZE) {
							// Limit stderr buffer to CTH_MAX_OUTPUT_SIZE.
							break;
						}
						stderr_buf = realloc(stderr_buf, stderr_size + BUF_CHUNK);
						ssize_t n = read(r->stderr_fd, stderr_buf + stderr_size, BUF_CHUNK);
						if (n > 0) {
							stderr_size += n;
						} else if (n < 0 && errno == EINTR) {
							continue;
						} else {
							break;
						}
					}
					if (stderr_buf) {
						stderr_buf = realloc(stderr_buf, stderr_size + 1);
						stderr_buf[stderr_size] = 0;
						r->stderr_ret = stderr_buf;
					} else {
						r->stderr_ret = NULL;
					}
					close(r->stderr_fd);
					r->stderr_fd = -1;
				}
			} else {
				r->exit_code = -1;
			}
		} else {
			r->exit_code = -1;
		}
	}
	return r->exit_code;
}
int cth_fork_rexec_self(char *const argv[])
{
	/*
	 * Fork and re-exec the current executable with given arguments.
	 * argv: The arguments to pass to the new executable, NULL-terminated array of strings.
	 * Returns the exit code of the new process on success, -1 on failure.
	 * Note: This function will block, and use current terminal for stdio.
	 */
	pid_t pid = fork();
	if (pid == -1) {
		return -1;
	}
	if (pid == 0) {
		size_t argc = 0;
		while (argv[argc] != NULL) {
			argc++;
		}
		char **new_argv = (char **)malloc(sizeof(char *) * (argc + 2));
		new_argv[0] = "/proc/self/exe";
		for (size_t i = 0; i < argc; i++) {
			new_argv[i + 1] = argv[i];
		}
		new_argv[argc + 1] = NULL;
		execv(new_argv[0], new_argv);
		free(new_argv);
		_exit(CTH_EXIT_FAILURE);
	}
	int status = 0;
	waitpid(pid, &status, 0);
	return WEXITSTATUS(status);
}
static struct cth_result *cth_exec_block_with_file_input(char **argv, int input_fd, bool get_output, void (*progress)(float, int), int progress_line_num)
{
	/*
	 * Exec the command in blocking mode, with file descriptor input and optional stdout/stderr capture.
	 * argv: The command and its arguments, NULL-terminated array of strings.
	 * fd: The file descriptor to read input from, should be readable.
	 * get_output: If true, capture stdout and stderr output.
	 * progress: A callback function to report progress, can be NULL.
	 */
	struct timeval start_time, end_time;
	gettimeofday(&start_time, NULL);
	if (input_fd < 0) {
		return NULL;
	}
	// Create pipes for stdin.
	int stdin_pipe[2] = { -1, -1 };
	// Create memfd for stdout and stderr.
	// No O_CLOEXEC, as we will write to them in child process.
	int stdout_fd = open("/dev/null", O_RDWR);
	int stderr_fd = open("/dev/null", O_RDWR);
	if (get_output) {
		close(stdout_fd);
		close(stderr_fd);
		stdout_fd = memfd_create("cth_stdout", MFD_ALLOW_SEALING);
		stderr_fd = memfd_create("cth_stderr", MFD_ALLOW_SEALING);
		ftruncate(stdout_fd, CTH_MAX_OUTPUT_SIZE);
		ftruncate(stderr_fd, CTH_MAX_OUTPUT_SIZE);
		fcntl(stdout_fd, F_ADD_SEALS, F_SEAL_GROW);
		fcntl(stderr_fd, F_ADD_SEALS, F_SEAL_GROW);
	}
	if (pipe(stdin_pipe) < 0) {
		return NULL;
	}
	// Set write end of stdin pipe to non-blocking.
	int flags = fcntl(stdin_pipe[1], F_GETFL, 0);
	if (flags != -1) {
		fcntl(stdin_pipe[1], F_SETFL, flags | O_NONBLOCK);
	}
	pid_t pid = fork();
	// Error handling.
	if (pid < 0) {
		if (stdin_pipe[0] != -1) {
			close(stdin_pipe[0]);
			close(stdin_pipe[1]);
		}
		close(stdout_fd);
		close(stderr_fd);
		return NULL;
	}
	if (pid == 0) {
		// Child process.
		close(stdin_pipe[1]);
		dup2(stdin_pipe[0], STDIN_FILENO);
		close(stdin_pipe[0]);
		if (get_output) {
			dup2(stdout_fd, STDOUT_FILENO);
			dup2(stderr_fd, STDERR_FILENO);
			close(stdout_fd);
			close(stderr_fd);
		} else {
			int fd = open("/dev/null", O_WRONLY);
			if (fd >= 0) {
				dup2(fd, STDOUT_FILENO);
				dup2(fd, STDERR_FILENO);
				if (fd > 2) {
					close(fd);
				}
			}
		}
		execvp(argv[0], argv);
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
		_exit(CTH_EXIT_FAILURE);
	}
	// Parent process.
	close(stdin_pipe[0]);
	struct cth_result *res = cth_new();
	res->pid = pid;
	if (res == NULL) {
		// Free pipes
		close(stdin_pipe[0]);
		close(stdin_pipe[1]);
		close(stdout_fd);
		close(stderr_fd);
		return NULL;
	}
	// Prgoress callback setup
	float progress_total = 0.0f;
	// Get the size of input_fd, if possible.
	struct stat st;
	if (fstat(input_fd, &st) == 0 && S_ISREG(st.st_mode)) {
		progress_total = (float)st.st_size;
	}
	// Write input to stdin pipe, handle EAGAIN and EINTR.
	size_t pipe_size = pipe_buf_size(stdin_pipe[1]);
	if (pipe_size == 0) {
		pipe_size = 65536; // Fallback to 64KB if we cannot get pipe size.
	}
	if (input_fd >= 0) {
		signal(SIGPIPE, SIG_IGN); // Ignore SIGPIPE, handle EPIPE error instead.
		char buf[pipe_size];
		ssize_t n;
		while ((n = read(input_fd, buf, sizeof(buf))) > 0) {
			ssize_t total_written = 0;
			while (total_written < n) {
				errno = 0;
				ssize_t written = write(stdin_pipe[1], buf + total_written, n - total_written);
				// For EPIPE, break.
				if (errno == EPIPE) {
					break;
				}
				if (written < 0) {
					if (errno == EAGAIN || errno == EINTR) {
						continue;
					} else {
						break;
					}
				}
				total_written += written;
				if (progress != NULL && progress_total > 0.0f) {
					progress((float)total_written / progress_total, progress_line_num);
				}
			}
		}
	}
	if (progress != NULL) {
		progress(1.0f, progress_line_num);
	}
	close(stdin_pipe[1]);
	close(stdin_pipe[0]);
	// Parent process, wait for child to exit.
	int status = 0;
	// Wait for child process, handle EINTR
	while (waitpid(pid, &status, 0) < 0) {
		if (errno == EINTR) {
			continue;
		}
		break;
	}
	gettimeofday(&end_time, NULL);
	// Calculate time used in microseconds.
	res->time_used = (end_time.tv_sec - start_time.tv_sec) * 1000000 + (end_time.tv_usec - start_time.tv_usec);
	// Calculate time used in milliseconds.
	res->time_used_ms = (end_time.tv_sec - start_time.tv_sec) * 1000 + (end_time.tv_usec - start_time.tv_usec) / 1000;
	res->exited = true;
	if (WIFEXITED(status)) {
		res->exit_code = WEXITSTATUS(status);
	} else if (WIFSIGNALED(status)) {
		res->exit_code = 128 + WTERMSIG(status);
	} else {
		res->exit_code = -1;
	}
	// Read stdout and stderr from memfd if get_output is true.
	if (get_output) {
		lseek(stdout_fd, 0, SEEK_SET);
		lseek(stderr_fd, 0, SEEK_SET);
		// Read stdout
		char *stdout_buf = NULL;
		size_t stdout_size = 0;
		size_t BUF_CHUNK = 4096;
		while (true) {
			if (stdout_size + BUF_CHUNK > CTH_MAX_OUTPUT_SIZE) {
				// Limit stdout buffer to CTH_MAX_OUTPUT_SIZE.
				break;
			}
			char buf[BUF_CHUNK];
			ssize_t n = read(stdout_fd, buf, sizeof(buf));
			if (n <= 0) {
				break;
			}
			if (stdout_buf == NULL) {
				stdout_buf = strdup(buf);
			} else {
				size_t old_len = strlen(stdout_buf);
				stdout_buf = realloc(stdout_buf, old_len + n + 1);
				memcpy(stdout_buf + old_len, buf, n);
				stdout_buf[old_len + n] = 0;
			}
			stdout_size += n;
		}
		res->stdout_ret = stdout_buf;
		// Read stderr
		char *stderr_buf = NULL;
		size_t stderr_size = 0;
		while (true) {
			if (stderr_size + BUF_CHUNK > CTH_MAX_OUTPUT_SIZE) {
				// Limit stderr buffer to CTH_MAX_OUTPUT_SIZE.
				break;
			}
			char buf[BUF_CHUNK];
			ssize_t n = read(stderr_fd, buf, sizeof(buf));
			if (n <= 0) {
				break;
			}
			if (stderr_buf == NULL) {
				stderr_buf = strdup(buf);
			} else {
				size_t old_len = strlen(stderr_buf);
				stderr_buf = realloc(stderr_buf, old_len + n + 1);
				memcpy(stderr_buf + old_len, buf, n);
				stderr_buf[old_len + n] = 0;
			}
			stderr_size += n;
		}
		res->stderr_ret = stderr_buf;
	}
	if (progress != NULL) {
		progress(-1.0, progress_line_num);
	}
	return res;
}
static struct cth_result *cth_exec_block(char **argv, char *input, bool get_output)
{
	/*
	 * Exec the command in blocking mode, with optional stdin input and stdout/stderr capture.
	 * argv: The command and its arguments, NULL-terminated array of strings.
	 * input: The input to be passed to the command's stdin, can be NULL.
	 * get_output: If true, capture stdout and stderr output.
	 * Returns a cth_result structure on success, NULL on failure.
	 * The caller is responsible for freeing the result using cth_free_result().
	 */
	struct timeval start_time, end_time;
	gettimeofday(&start_time, NULL);
	// For the simplest case, just exec without stdio redirection
	if (input == NULL && !get_output) {
		return cth_exec_block_without_stdio(argv);
	}
	// Open input as file, and use cth_exec_block_with_file_input.
	int input_fd = -1;
	if (input != NULL) {
		input_fd = memfd_create("cth_input", MFD_CLOEXEC);
		if (input_fd < 0) {
			return NULL;
		}
		write(input_fd, input, strlen(input));
		lseek(input_fd, 0, SEEK_SET);
	} else {
		// Get an empty memfd for input.
		input_fd = memfd_create("cth_input_empty", MFD_CLOEXEC);
		if (input_fd < 0) {
			return NULL;
		}
	}
	struct cth_result *res = cth_exec_block_with_file_input(argv, input_fd, get_output, NULL, 0);
	if (input_fd >= 0) {
		close(input_fd);
	}
	return res;
}
static struct cth_result *cth_exec_nonblock_with_file_input(char **argv, int input_fd, bool get_output, void (*progress)(float, int), int progress_line_num)
{
	char memfd_name[32];
	// Never mind, memfd does not really need a unique name, and we will not search it by name as well.
	// NOLINTBEGIN
	srand((unsigned int)time(NULL));
	snprintf(memfd_name, sizeof(memfd_name), "cth_memfd_stdout_%d", rand());
	int stdout_fd = memfd_create(memfd_name, MFD_CLOEXEC);
	snprintf(memfd_name, sizeof(memfd_name), "cth_memfd_stderr_%d", rand());
	int stderr_fd = memfd_create(memfd_name, MFD_CLOEXEC);
	snprintf(memfd_name, sizeof(memfd_name), "cth_memfd_stat_%d", rand());
	int stat_fd = memfd_create(memfd_name, MFD_CLOEXEC);
	snprintf(memfd_name, sizeof(memfd_name), "cth_memfd_pid_%d", rand());
	int pid_fd = memfd_create(memfd_name, MFD_CLOEXEC);
	snprintf(memfd_name, sizeof(memfd_name), "cth_memfd_time_%d", rand());
	int time_fd = memfd_create(memfd_name, MFD_CLOEXEC);
	// NOLINTEND
	if (stdout_fd < 0 || stderr_fd < 0 || stat_fd < 0 || pid_fd < 0 || time_fd < 0) {
		if (stdout_fd >= 0) {
			close(stdout_fd);
		}
		if (stderr_fd >= 0) {
			close(stderr_fd);
		}
		if (stat_fd >= 0) {
			close(stat_fd);
		}
		if (time_fd >= 0) {
			close(time_fd);
		}
		if (pid_fd >= 0) {
			close(pid_fd);
		}
		return NULL;
	}
	pid_t pid = fork();
	if (pid < 0) {
		return NULL;
	}
	if (pid > 0) {
		waitpid(pid, NULL, 0);
		struct cth_result *res = cth_new();
		res->stat_fd = stat_fd;
		res->stdout_fd = stdout_fd;
		res->stderr_fd = stderr_fd;
		res->time_fd = time_fd;
		// Wait pid_fd, and get pid.
		char pid_buf[32];
		while (true) {
			lseek(pid_fd, 0, SEEK_SET);
			ssize_t n = read(pid_fd, pid_buf, sizeof(pid_buf) - 1);
			if (n > 0) {
				pid_buf[n] = 0;
				char *endptr;
				res->pid = (pid_t)strtoul(pid_buf, &endptr, 10);
				if (endptr == pid_buf || *endptr != 0) {
					// Invalid pid, treat as error.
					close(pid_fd);
					close(stat_fd);
					close(stdout_fd);
					close(stderr_fd);
					free(res);
					return NULL;
				}
				break;
			} else if ((n < 0 && errno == EINTR) || n == 0) {
				continue;
			} else if (n < 0) {
				// error, give up.
				close(pid_fd);
				close(stat_fd);
				close(stdout_fd);
				close(stderr_fd);
				free(res);
				return NULL;
			}
		}
		close(pid_fd);
		return res;
	}
	pid_t exec_pid = fork();
	if (exec_pid < 0) {
		write(pid_fd, "CTH_ERROR", 9);
		_exit(CTH_EXIT_FAILURE);
	}
	if (exec_pid > 0) {
		_exit(CTH_EXIT_SUCCESS);
	}
	char pid_str[32];
	snprintf(pid_str, sizeof(pid_str), "%d", getpid());
	write(pid_fd, pid_str, strlen(pid_str));
	struct cth_result *exec_res = cth_exec_block_with_file_input(argv, input_fd, get_output, progress, progress_line_num);
	if (exec_res == NULL) {
		write(stat_fd, "CTH_ERROR", 9);
		_exit(CTH_EXIT_FAILURE);
	}
	if (get_output) {
		if (exec_res->stdout_ret) {
			lseek(stdout_fd, 0, SEEK_SET);
			// Buffered write to stdout_fd, as the output can be large.
			size_t total_written = 0;
			size_t to_write = strlen(exec_res->stdout_ret);
			while (total_written < to_write) {
				ssize_t n = write(stdout_fd, exec_res->stdout_ret + total_written, to_write - total_written);
				if (n > 0) {
					total_written += n;
				} else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
					// write buffer full, wait for it to be available.
					struct pollfd pfd;
					pfd.fd = stdout_fd;
					pfd.events = POLLOUT;
					poll(&pfd, 1, -1);
				} else {
					// error, give up writing.
					break;
				}
			}
		}
		if (exec_res->stderr_ret) {
			lseek(stderr_fd, 0, SEEK_SET);
			// Buffered write to stderr_fd, as the output can be large.
			size_t total_written = 0;
			size_t to_write = strlen(exec_res->stderr_ret);
			while (total_written < to_write) {
				ssize_t n = write(stderr_fd, exec_res->stderr_ret + total_written, to_write - total_written);
				if (n > 0) {
					total_written += n;
				} else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
					// write buffer full, wait for it to be available.
					struct pollfd pfd;
					pfd.fd = stderr_fd;
					pfd.events = POLLOUT;
					poll(&pfd, 1, -1);
				} else {
					// error, give up writing.
					break;
				}
			}
			// Read from stderr_fd to make sure the data is consumed by parent process, to avoid child process being blocked on write.
			char buf[1024];
			lseek(stderr_fd, 0, SEEK_SET);
			int tt = read(stderr_fd, buf, sizeof(buf));
			buf[tt] = 0;
		}
	}
	char time_used_ms[128];
	snprintf(time_used_ms, sizeof(time_used_ms), "%llu", (unsigned long long)exec_res->time_used_ms);
	lseek(time_fd, 0, SEEK_SET);
	write(time_fd, time_used_ms, strlen(time_used_ms));
	char stat_str[32];
	snprintf(stat_str, sizeof(stat_str), "%d", exec_res->exit_code);
	lseek(stat_fd, 0, SEEK_SET);
	write(stat_fd, stat_str, strlen(stat_str));
	_exit(CTH_EXIT_SUCCESS);
}
// API function.
struct cth_result *cth_exec_with_file_input(char **argv, int fd, bool block, bool get_output, void (*progress)(float, int), int progress_line_num)
{
	/*
	 * Exec the command with given arguments, using the given file descriptor as stdin.
	 * argv: The command and its arguments, NULL-terminated array of strings.
	 * fd: The file descriptor to use as stdin, should be valid and open for reading.
	 * block: If true, wait for the command to finish and return the result.
	 *        If false, return immediately (not implemented yet).
	 * get_output: If true, capture stdout and stderr output.
	 * progress: A callback function to report progress, can be NULL.
	 *           The function will be called with a float value between 0.0 and 1.0,
	 *           representing the progress of reading the input file, and an integer
	 *           line number to indicate where to print the progress (for multi-line progress).
	 * progress_line_num: The line number to use for progress reporting, if progress is not NULL.
	 * Returns a cth_result structure on success, NULL on failure.
	 * The caller is responsible for freeing the result using cth_free_result().
	 */
	if (argv == NULL || argv[0] == NULL) {
		return NULL;
	}
	// For now, only blocking mode is implemented.
	if (block) {
		return cth_exec_block_with_file_input(argv, fd, get_output, progress, progress_line_num);
	}
	return cth_exec_nonblock_with_file_input(argv, fd, get_output, progress, progress_line_num);
}
void cth_show_progress(float progress, int line_num)
{
	/*
	 * This is an example progress reporting function.
	 * Show a progress bar in the terminal.
	 * progress: A float value between 0.0 and 1.0, representing the progress.
	 *           If progress < 0.0, clear the progress bar.
	 *           If progress > 1.0, treat as 1.0.
	 * line_num: The line number to use for progress reporting, if > 0.
	 *           If line_num <= 0, use the current line.
	 * Note: This function uses ANSI escape codes to move the cursor.
	 */
	if (progress < 0.0) {
		printf("\n");
		fflush(stdout);
		return;
	}
	if (progress > 1.0) {
		progress = 1.0;
	}
	const int bar_width = 50;
	int pos = (int)(bar_width * progress);
	// Move cursor to the specified line.
	if (line_num > 0) {
		printf("\033[%dA", line_num);
	}
	printf("[");
	for (int i = 0; i < bar_width; ++i) {
		if (i < pos) {
			printf("=");
		} else if (i == pos) {
			printf(">");
		} else {
			printf(" ");
		}
	}
	printf("] %3d %%\r", (int)(progress * 100.0));
	fflush(stdout);
	// Move cursor back to original position.
	if (line_num > 0) {
		printf("\033[%dB", line_num);
	}
}