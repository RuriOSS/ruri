#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <limits.h>
#include <dirent.h>
#include <sys/time.h>
#include <float.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <signal.h>
#include <unistd.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glob.h>
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
		exit(114);                    \
	}
int fork_exec(char **argv)
{
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
		return -1;
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
char **CFLAGS = NULL;
char **LIBS = NULL;
char *CC = "cc";
char *SELF = __FILE__;
char *BUILD_DIR = "out";
char *SRC_DIR = NULL;
char **OBJS = NULL;
char *OUTPUT = NULL;
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
void free_args(char **arg)
{
	for (int i = 0; arg && arg[i] != NULL; i++) {
		free(arg[i]);
	}
	free(arg);
}
bool check_c_flag(const char *flag)
{
	char **args = NULL;
	add_args(&args, CC);
	for (int i = 0; CFLAGS && CFLAGS[i] != NULL; i++) {
		add_args(&args, CFLAGS[i]);
	}
	add_args(&args, flag);
	add_args(&args, "-o");
	add_args(&args, "/dev/null");
	add_args(&args, SELF);
	for (int i = 0; LIBS && LIBS[i] != NULL; i++) {
		add_args(&args, LIBS[i]);
	}
	if (fork_exec(args) != 0) {
		printf("Check for flag %s :failed\n", flag);
		free_args(args);
		return false;
	}
	free_args(args);
	add_args(&CFLAGS, flag);
	printf("Check for flag %s :success\n", flag);
	return true;
}
bool check_lib(const char *lib)
{
	char **args = NULL;
	add_args(&args, CC);
	for (int i = 0; CFLAGS && CFLAGS[i] != NULL; i++) {
		add_args(&args, CFLAGS[i]);
	}
	add_args(&args, "-o");
	add_args(&args, "/dev/null");
	add_args(&args, SELF);
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
	add_args(&LIBS, lib);
	return true;
}
void update_cc(void)
{
	if (getenv("CC")) {
		CC = getenv("CC");
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
	add_args(&arg, SELF);
	if (fork_exec(arg) != 0) {
		error("Error: Compiler %s failed to compile %s\n", CC, SELF);
		exit(EXIT_FAILURE);
	}
	printf("CC: %s\n", CC);
	free_args(arg);
}
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
	// Check if SELF exists
	if (access(SELF, F_OK) != -1) {
		char *resolved_path = realpath(SELF, NULL);
		if (resolved_path) {
			SELF = resolved_path;
		} else {
			error("Error: failed to resolve path for %s\n", SELF);
		}
		// Change to the build directory
		mkdir(dir, 0755);
		chdir(dir);
		// TODO: ?
		fork_exec((char *[]){ "rm", "*", NULL });
		BUILD_DIR = realpath(".", NULL);
	} else {
		error("Error: failed to get source file %s\n", SELF);
	}
}
char *basename(const char *path)
{
	const char *name = strrchr(path, '/');
	return name ? (char *)(name + 1) : (char *)path;
}
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
	char *name = basename(file);
	sprintf(output_file, "%s.o", name);
	add_args(&args, output_file);
	add_args(&args, file);
	if (fork_exec(args) != 0) {
		error("Error: Compiler %s failed to compile %s\n", CC, file);
	}
	free_args(args);
	add_args(&OBJS, output_file);
	printf("Compile %s :success\n", file);
}
void build()
{
	// compile src/*.c and src/easteregg/*.c
	glob_t glob_result;
	char src[PATH_MAX];
	sprintf(src, "%s/*.c", SRC_DIR);
	glob(src, 0, NULL, &glob_result);
	for (size_t i = 0; i < glob_result.gl_pathc; i++) {
		compile(glob_result.gl_pathv[i]);
	}
	globfree(&glob_result);
	sprintf(src, "%s/easteregg/*.c", SRC_DIR);
	glob(src, 0, NULL, &glob_result);
	for (size_t i = 0; i < glob_result.gl_pathc; i++) {
		compile(glob_result.gl_pathv[i]);
	}
	globfree(&glob_result);
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
	printf("Build successful: %s\n", OUTPUT);
	free_args(args);
}
int main()
{
	switch_to_build_dir("out");
	update_cc();
	if (!check_c_flag("-static")) {
		error("Error: -static flag is not supported\n");
	}
	check_lib("-lcap");
	check_lib("-lseccomp");
	check_lib("-lpthread");
	build();
	return 0;
}