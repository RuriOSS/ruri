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
	// Prepare args.
	char *argv_new[argc + 3];
	argv_new[0] = "./ruri"; // Program name
	argv_new[1] = "--pid-file"; // Option flag
	argv_new[2] = proc_fs_fd_path; // Path to the memfd file descriptor
	for (int i = 1; i < argc; i++) {
		argv_new[i + 2] = argv[i]; // Copy original arguments
	}
	argv_new[argc + 2] = NULL; // Null-terminate the argument list
	struct cth_result *result = cth_exec(argv_new, NULL, false, false);
	sleep(1);
	int loop = 0;
	cth_wait(&result);
	while (CTH_EXEC_RUNNING(result)) {
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
			pid_t child_pid = strtol(pid_file_content + strlen("RURI_WAIT_EXEC_"), NULL, 10);
			if (child_pid > 0) {
				loop++;
				printf("Loop %d: Child PID from pid file: %d\n", loop, child_pid);
				sleep(1);
				if (loop == 3) {
					printf("Sending SIGUSR1 to child process (PID: %d)\n", child_pid);
					kill(child_pid, SIGUSR1);
					usleep(500000); // Sleep for 500 milliseconds to allow signal handling
					// Read pid file content again after sending signal
					lseek(fd, 0, SEEK_SET); // Reset file offset to the beginning
					bytes_read = read(fd, pid_file_content, sizeof(pid_file_content) - 1);
					if (bytes_read > 0) {
						pid_file_content[bytes_read] = '\0'; // Null-terminate the string
						printf("After SIGUSR1, pid file content: %s\n", pid_file_content);
					} else {
						perror("read");
					}
					cth_wait(&result);
					if (CTH_EXEC_RUNNING(result)) {
						printf("Child process is still running after SIGUSR1, sending SIGKILL\n");
						exit(1);
					} else {
						printf("Child process has exited after SIGUSR1\n");
						exit(0);
					}
				}
			}
		}
	}
}