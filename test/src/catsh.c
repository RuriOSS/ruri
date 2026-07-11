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
#include "include/catsh.h"
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