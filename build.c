// SPDX-License-Identifier: MIT
/*
 *
 * This file is part of cprintf, with ABSOLUTELY NO WARRANTY.
 *
 * MIT License
 *
 * Copyright (c) 2024 Moe-hacker
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
//
// This program has Super Neko Powers
//
// Damn bro, it's only for Linux
#ifndef __linux__
#error "This code is only for Linux"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
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
#if __STDC_VERSION__ < 202000L
#ifndef bool
#define bool _Bool
#define true ((_Bool) + 1u)
#define false ((_Bool) + 0u)
#endif
#endif
#define error(...)                            \
	{                                     \
		fprintf(stderr, __VA_ARGS__); \
		fprintf(stderr, "\n");        \
		on_exit__(SIGINT);            \
		exit(EXIT_FAILURE);           \
	}
void remove_test_dot_c(void);
void on_exit__(int sig)
{
	// TODO: child process should not call this.
	printf("Exiting %d......\n", getpid());
	while (waitpid(-1, NULL, WNOHANG) > 0)
		;
	remove_test_dot_c();
	exit(1);
}
int fork_exec(char **argv)
{
	// Return -1 if failed to exec()
	// Or return same as exec()ed program.
	int pid = fork();
	if (pid < 0) {
		perror("fork failed");
		return -1;
	} else if (pid == 0) {
		int fd = open("/dev/null", O_WRONLY);
		dup2(fd, STDOUT_FILENO);
		dup2(fd, STDERR_FILENO);
		dup2(fd, STDIN_FILENO);
		close(fd);
		execvp(argv[0], argv);
		perror("exec failed");
		exit(EXIT_FAILURE);
	} else {
		int status;
		waitpid(pid, &status, 0);
		if (WIFEXITED(status)) {
			return WEXITSTATUS(status);
		} else {
			return -1;
		}
	}
}
char *fork_execvp_get_stdout(const char *argv[])
{
	/*
	 * Warning: free() after use.
	 * We will fork(2) and then execvp(3).
	 * And then we will get the stdout of the child process.
	 * Return the stdout of the child process.
	 * If failed, return NULL.
	 */
	// Create a pipe.
	int pipefd[2];
	if (pipe(pipefd) == -1) {
		return NULL;
	}
	// fork(2) and then execvp(3).
	int pid = fork();
	if (pid == -1) {
		return NULL;
	}
	if (pid == 0) {
		// Close the read end of the pipe.
		close(pipefd[0]);
		// Redirect stdout and stderr to the write end of the pipe.
		dup2(pipefd[1], STDOUT_FILENO);
		int nullfd = open("/dev/null", O_WRONLY);
		dup2(nullfd, STDERR_FILENO);
		close(pipefd[1]);
		execvp(argv[0], (char **)argv);
		exit(114);
	} else {
		// Close the write end of the pipe.
		close(pipefd[1]);
		// Get the output from the read end of the pipe.
		size_t buffer_size = 1024;
		size_t total_read = 0;
		char *output = malloc(buffer_size);
		ssize_t bytes_read;
		while ((bytes_read = read(pipefd[0], output + total_read, buffer_size - total_read - 1)) > 0) {
			total_read += (size_t)bytes_read;
			if (total_read >= buffer_size - 1) {
				buffer_size *= 2;
				char *new_output = realloc(output, buffer_size);
				output = new_output;
			}
		}
		if (bytes_read == -1) {
			free(output);
			close(pipefd[0]);
			return NULL;
		}
		output[total_read] = '\0';
		close(pipefd[0]);
		int status = 0;
		waitpid(pid, &status, 0);
		if (WEXITSTATUS(status) != 0) {
			free(output);
			return NULL;
		}
		return output;
	}
	return NULL;
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
// Not only args, but (char **) in fact.
void add_args(char ***argv, const char *arg)
{
	if (*argv == NULL) {
		*argv = malloc(2 * sizeof(char *));
		(*argv)[0] = strdup(arg);
		(*argv)[1] = NULL;
	} else {
		size_t len = 0;
		while ((*argv)[len] != NULL)
			len++;
		*argv = realloc(*argv, (len + 2) * sizeof(char *));
		(*argv)[len] = strdup(arg);
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
		exit(EXIT_FAILURE);
	}
	printf("CC: %s\n", CC);
	free_args(arg);
	char *commit_id = fork_execvp_get_stdout((const char *[]){ "git", "rev-parse", "--short", "HEAD", NULL });
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
	static char out[PATH_MAX];
	sprintf(out, "%s/%s", basedir, "ruri");
	OUTPUT = out;
	free(basedir);
	// Change to the build directory
	mkdir(dir, 0755);
	if (chdir(dir) != 0) {
		error("Error: failed to change directory to %s\n", dir);
	}
	fork_exec((char *[]){ "sh", "-c", "rm ./*.o", NULL });
	BUILD_DIR = realpath(".", NULL);
}
// Get file name without path
char *basename_of(const char *path)
{
	const char *name = strrchr(path, '/');
	return name ? (char *)(name + 1) : (char *)path;
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
	char output_file[PATH_MAX];
	char *name = basename_of(file);
	sprintf(output_file, "%s.o", name);
	add_args(&args, output_file);
	add_args(&args, file);
	if (fork_exec(args) != 0) {
		error("Error: Compiler %s failed to compile %s\n", CC, file);
	}
	free_args(args);
	printf("Compile %s :success\n", file);
}
int pmcrts(const char *s1, const char *s2)
{
	/*
	 *
	 * Compare two strings, but s2 is in the end of s1.
	 * For example,
	 * s1 = "./ruri", s2 = "ruri", it will return 0.
	 * s1 = "./rurima", s2 = "ruri", it will return... 'a' - 'i',
	 * anyway, it's not 0 :)
	 * If s1 is shorter than s2, it will return -1.
	 *
	 */
	size_t len1 = strlen(s1);
	size_t len2 = strlen(s2);
	if (len1 < len2) {
		return -1; // s1 is shorter than s2
	}
	for (size_t i = len1; i > len1 - len2; i--) {
		if (s1[i] != s2[i - (len1 - len2)]) {
			return s1[i] - s2[i - (len1 - len2)];
		}
	}
	return 0; // s1 ends with s2
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
				exit(0);
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
		char obj_file[PATH_MAX];
		sprintf(obj_file, "%s.o", basename_of(files[i]));
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
	if (fork_exec(args) != 0) {
		error("Error: failed to link object files\n");
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
// So good brooooo, the program works with magic here.
int main()
{
	signal(SIGINT, on_exit__);
	switch_to_build_dir("out");
	init_env();
	check_and_add_cflag("-static", true);
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
	check_and_add_cflag("-Wl,--disable-new-dtags", false);
	check_and_add_cflag("-U_FORTIFY_SOURCE", false);
	check_and_add_cflag("-D_FORTIFY_SOURCE=3", false);
	if (COMMIT_ID) {
		char define_commit[PATH_MAX];
		sprintf(define_commit, "-DRURI_COMMIT_ID=\"%s\"", COMMIT_ID);
		check_and_add_cflag(define_commit, false);
	} else {
		check_and_add_cflag("-DRURI_COMMIT_ID=unknown", false);
	}
	check_and_add_lib("-lcap", true);
	check_and_add_lib("-lseccomp", true);
	check_and_add_lib("-lpthread", false);
	build();
	remove_test_dot_c();
	return 0;
}