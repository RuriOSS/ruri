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
#include "../../src/include/ruri.h"
#include "include/catsh.h"
#include "include/cprintf.h"
void test_wait_before_exec(int append_argc, char **append_argv)
{
	int fd = memfd_create("test", MFD_CLOEXEC);
	fchmod(fd, S_IRUSR | S_IWUSR);
	if (fd == -1) {
		perror("memfd_create");
		exit(114);
	}
	char proc_fs_fd_path[PATH_MAX];
	snprintf(proc_fs_fd_path, sizeof(proc_fs_fd_path), "/proc/%d/fd/%d", getpid(), fd);
	// Prepare args.
	char *argv_new[append_argc + 16];
	argv_new[0] = "./ruri"; // Program name
	argv_new[1] = "--pid-file"; // Option flag
	argv_new[2] = proc_fs_fd_path; // Path to the memfd file descriptor
	argv_new[3] = "--set-flag";
	argv_new[4] = "wait_before_exec"; // Flag to set
	for (int i = 0; i < append_argc; i++) {
		argv_new[i + 5] = append_argv[i]; // Copy original arguments
	}
	argv_new[append_argc + 5] = NULL; // Null-terminate the argument list
	cprintf("Executing command: ");
	for (int i = 0; argv_new[i] != NULL; i++) {
		cprintf("%s ", argv_new[i]);
	}
	cprintf("\n");
	struct cth_result *result = cth_exec(argv_new, NULL, false, false);
	sleep(1);
	int loop = 0;
	cth_wait(&result);
	if (!CTH_EXEC_RUNNING(result)) {
		cprintf("{red}Child process has already exited unexpectedly\n");
		exit(114);
	}
	while (CTH_EXEC_RUNNING(result)) {
		cth_wait(&result);
		if (!CTH_EXEC_RUNNING(result)) {
			cprintf("{red}Child process has exited unexpectedly\n");
			exit(114);
		}
		// Child is still running, sleep for a short time
		usleep(100000); // Sleep for 100 milliseconds
		// Read pid file content from memfd
		lseek(fd, 0, SEEK_SET); // Reset file offset to the beginning
		char pid_file_content[64] = { 0 };
		ssize_t bytes_read = read(fd, pid_file_content, sizeof(pid_file_content) - 1);
		if (bytes_read > 0) {
			pid_file_content[bytes_read] = '\0'; // Null-terminate the string
			cprintf("Current pid file content: %s\n", pid_file_content);
			// Get pid of the child process
			pid_t child_pid = strtol(pid_file_content + strlen("RURI_WAIT_EXEC_"), NULL, 10);
			if (child_pid > 0) {
				loop++;
				cprintf("Loop %d: Child PID from pid file: %d\n", loop, child_pid);
				sleep(1);
				if (loop == 3) {
					cprintf("Sending SIGUSR1 to child process (PID: %d)\n", child_pid);
					kill(child_pid, SIGUSR1);
					usleep(500000); // Sleep for 500 milliseconds to allow signal handling
					// Read pid file content again after sending signal
					lseek(fd, 0, SEEK_SET); // Reset file offset to the beginning
					bytes_read = read(fd, pid_file_content, sizeof(pid_file_content) - 1);
					if (bytes_read > 0) {
						pid_file_content[bytes_read] = '\0'; // Null-terminate the string
						cprintf("After SIGUSR1, pid file content: %s\n", pid_file_content);
					} else {
						perror("read");
					}
					cth_wait(&result);
					if (CTH_EXEC_RUNNING(result)) {
						cprintf("Child process is still running after SIGUSR1, sending SIGKILL\n");
						exit(114);
					} else {
						cprintf("Child process has exited after SIGUSR1\n");
						exit(0);
					}
				}
			}
		}
	}
}
void test_wait_before_exec_unshare(int append_argc, char **append_argv)
{
	int fd = memfd_create("test", MFD_CLOEXEC);
	fchmod(fd, S_IRUSR | S_IWUSR);
	if (fd == -1) {
		perror("memfd_create");
		exit(114);
	}
	char proc_fs_fd_path[PATH_MAX];
	snprintf(proc_fs_fd_path, sizeof(proc_fs_fd_path), "/proc/%d/fd/%d", getpid(), fd);
	// Prepare args.
	char *argv_new[append_argc + 16];
	argv_new[0] = "./ruri"; // Program name
	argv_new[1] = "--pid-file"; // Option flag
	argv_new[2] = proc_fs_fd_path; // Path to the memfd file descriptor
	argv_new[3] = "--set-flag";
	argv_new[4] = "wait_before_exec"; // Flag to set
	argv_new[5] = "--unshare"; // Unshare option
	for (int i = 0; i < append_argc; i++) {
		argv_new[i + 6] = append_argv[i]; // Copy original arguments
	}
	argv_new[append_argc + 6] = NULL; // Null-terminate the argument list
	cprintf("Executing command with unshare: ");
	for (int i = 0; argv_new[i] != NULL; i++) {
		cprintf("%s ", argv_new[i]);
	}
	cprintf("\n");
	struct cth_result *result = cth_exec(argv_new, NULL, false, false);
	sleep(1);
	int loop = 0;
	cth_wait(&result);
	if (!CTH_EXEC_RUNNING(result)) {
		cprintf("{red}Child process has already exited unexpectedly\n");
		exit(114);
	}
	while (CTH_EXEC_RUNNING(result)) {
		cth_wait(&result);
		if (!CTH_EXEC_RUNNING(result)) {
			cprintf("{red}Child process has exited unexpectedly\n");
			exit(114);
		}
		// Child is still running, sleep for a short time
		usleep(100000); // Sleep for 100 milliseconds
		// Read pid file content from memfd
		lseek(fd, 0, SEEK_SET); // Reset file offset to the beginning
		char pid_file_content[64] = { 0 };
		ssize_t bytes_read = read(fd, pid_file_content, sizeof(pid_file_content) - 1);
		if (bytes_read > 0) {
			pid_file_content[bytes_read] = '\0'; // Null-terminate the string
			cprintf("Current pid file content: %s\n", pid_file_content);
			// Get pid of the child process
			pid_t child_pid = strtol(pid_file_content + strlen("RURI_WAIT_EXEC_"), NULL, 10);
			if (child_pid > 0) {
				loop++;
				cprintf("Loop %d: Child PID from pid file: %d\n", loop, child_pid);
				sleep(1);
				if (loop == 3) {
					cprintf("Sending SIGUSR1 to child process (PID: %d)\n", child_pid);
					kill(child_pid, SIGUSR1);
					usleep(500000); // Sleep for 500 milliseconds to allow signal handling
					// Read pid file content again after sending signal
					lseek(fd, 0, SEEK_SET); // Reset file offset to the beginning
					bytes_read = read(fd, pid_file_content, sizeof(pid_file_content) - 1);
					if (bytes_read > 0) {
						pid_file_content[bytes_read] = '\0'; // Null-terminate the string
						cprintf("After SIGUSR1, pid file content: %s\n", pid_file_content);
					} else {
						perror("read");
					}
					cth_wait(&result);
					if (CTH_EXEC_RUNNING(result)) {
						cprintf("Child process is still running after SIGUSR1, sending SIGKILL\n");
						exit(114);
					} else {
						cprintf("Child process has exited after SIGUSR1\n");
						exit(0);
					}
				}
			}
		}
	}
}
int main(int argc, char **argv)
{
	cprintf("\n");
	cprintf("\n{blue}=== Test: Wait Before Exec ===\n\n");
	// Wait before exec test
	pid_t pid = fork();
	if (pid == -1) {
		perror("fork");
		exit(114);
	} else if (pid == 0) {
		// Child process
		test_wait_before_exec(argc - 1, &argv[1]);
		exit(114);
	}
	int status;
	waitpid(pid, &status, 0);
	if (WIFEXITED(status)) {
		int exit_code = WEXITSTATUS(status);
		if (exit_code == 0) {
			cprintf("\n{green}# Test passed\n");
		} else {
			cprintf("\n{red}# Test failed with exit code: %d\n", exit_code);
			exit(114);
		}
	} else {
		cprintf("{red}Child process did not exit normally\n");
		exit(114);
	}
	//
	//
	//
	cprintf("\n");
	cprintf("\n{blue}=== Test: Wait Before Exec with Unshare ===\n\n");
	// Wait before exec test
	pid = fork();
	if (pid == -1) {
		perror("fork");
		exit(114);
	} else if (pid == 0) {
		// Child process
		test_wait_before_exec_unshare(argc - 1, &argv[1]);
		exit(114);
	}
	waitpid(pid, &status, 0);
	if (WIFEXITED(status)) {
		int exit_code = WEXITSTATUS(status);
		if (exit_code == 0) {
			cprintf("\n{green}# Test passed\n");
		} else {
			cprintf("\n{red}# Test failed with exit code: %d\n", exit_code);
			exit(114);
		}
	} else {
		cprintf("{red}Child process did not exit normally\n");
		exit(114);
	}
	exit(0);
}