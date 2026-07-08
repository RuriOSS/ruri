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
#include "../src/include/ruri.h"
// Usage: ./test_pid_file [expected] [ruri args].
// No any other boundary/coner case check, as this file is not for common users.
int main(int argc, char *argv[])
{
	int fd = memfd_create("test", MFD_CLOEXEC);
	fchmod(fd, S_IRUSR | S_IWUSR);
	if (fd == -1) {
		perror("memfd_create");
		return 1;
	}
	char proc_fs_fd_path[PATH_MAX];
	snprintf(proc_fs_fd_path, sizeof(proc_fs_fd_path), "/proc/%d/fd/%d", getpid(), fd);
	pid_t fork_pid = fork();
	if (fork_pid == -1) {
		perror("fork");
		return 1;
	} else if (fork_pid == 0) {
		// Child process
		char *argv_new[argc + 3];
		argv_new[0] = "ruri"; // Program name
		argv_new[1] = "--pid-file"; // Option flag
		argv_new[2] = proc_fs_fd_path; // Path to the memfd file descriptor
		for (int i = 2; i < argc; i++) {
			argv_new[i + 1] = argv[i]; // Copy original arguments
		}
		argv_new[argc + 1] = NULL; // Null-terminate the argument list
		execv("./ruri", argv_new); // Execute the new program
		perror("execv"); // If execv returns, it must have failed
		return 1;
	} else {
		// Do non-blocking wait for the child process to finish
		int status;
		int loop = 0;
		while (waitpid(fork_pid, &status, WNOHANG) == 0) {
			// Child is still running, sleep for a short time
			usleep(100000); // Sleep for 100 milliseconds
			// Read pid file content from memfd
			lseek(fd, 0, SEEK_SET); // Reset file offset to the beginning
			char pid_file_content[64] = { 0 };
			ssize_t bytes_read = read(fd, pid_file_content, sizeof(pid_file_content) - 1);
			if (bytes_read > 0) {
				pid_file_content[bytes_read] = '\0'; // Null-terminate the string
				printf("Current pid file content: %s\n", pid_file_content);
				// Get pid of the child process
				pid_t child_pid = strtol(pid_file_content, NULL, 10);
				if (child_pid > 0) {
					loop++;
					printf("Loop %d: Child PID from pid file: %d\n", loop, child_pid);
					sleep(1);
					if (loop == 3) {
						printf("Sending SIGUSR1 to child process (PID: %d)\n", child_pid);
						kill(child_pid, SIGUSR1);
					}
				}
			}
		}
		printf("Child process finished with status: %d\n", status);
	}
	return 0;
}