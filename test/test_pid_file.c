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
		waitpid(fork_pid, NULL, 0); // Wait for the child process to finish
		// Get lock on pid file, to wait for the child process to write to it.
		struct flock fl;
		fl.l_type = F_WRLCK;
		fl.l_whence = SEEK_SET;
		fl.l_start = 0;
		fl.l_len = 0;
		// For catching the race condition in loop testing.
		// Will not affect any logic for memfd usage.
		bool sleep_3s_after_finish_all = false;
		// Get the lock in non-blocking mode first, if failed, wait for the lock.
		if (fcntl(fd, F_SETLK, &fl) < 0) {
			perror("fcntl");
			sleep_3s_after_finish_all = true;
			if (fcntl(fd, F_SETLKW, &fl) < 0) {
				perror("fcntl");
				printf("Failed to get lock on pid file.\n");
				exit(114);
			}
			printf("Got lock on pid file after waiting.\n");
		} else {
			printf("Got lock on pid file.\n");
		}
		// Now we can safely read the pid file, as the child process has exited and released the lock.
		char buffer[256];
		ssize_t bytesRead = read(fd, buffer, sizeof(buffer) - 1);
		if (bytesRead == -1) {
			perror("read");
			exit(114);
		}
		buffer[bytesRead] = '\0'; // Null-terminate the buffer
		if (strncmp(buffer, argv[1], strlen(argv[1])) != 0) {
			fprintf(stderr, "\033[31mFailed. Expected: %s, Got: %s\033[0m\n", argv[1], buffer);
			exit(114);
		}
		printf("\033[32mPassed. Expected: %s, Got: %s\033[0m\n", argv[1], buffer);
		// Just to freeze the terminal to see the result.
		// Human is too slow to read the rolling test log.
		if (sleep_3s_after_finish_all) {
			printf("Sleeping for 3 seconds\n");
			sleep(3);
		}
	}
	return 0;
}