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
#include "include/ruri.h"
int ruri_pid_file_fd(int req)
{
	/*
	 * Store fd for pid file daemon.
	 * If req >= 0, set the pid file fd to req and return it.
	 * If req < 0, return the stored pid file fd.
	 * In fact this fd is a socket, but no matter.
	 */
	static thread_local int ret = -1;
	if (req < 0) {
		return ret;
	}
	ret = req;
	return ret;
}
void ruri_pid_file_write(enum RURI_PID_FILE_REQ req, long long arg)
{
	/*
	 * Write content to pid file fd,
	 * the content is determined by req and arg.
	 */
	if (ruri_pid_file_fd(-1) < 0) {
		return;
	}
	char buf[256] = { '\0' };
	switch (req) {
	case RURI_PID_FILE_INIT:
		// Not here.
		return;
	case RURI_PID_FILE_PID:
		snprintf(buf, sizeof(buf), "%lld\n", arg);
		break;
	case RURI_PID_FILE_PANIC_EXEC:
		snprintf(buf, sizeof(buf), "RURI_PANIC_EXE\n");
		break;
	case RURI_PID_FILE_PANIC_INTERNAL:
		snprintf(buf, sizeof(buf), "RURI_PANIC_INTERNAL\n");
		break;
	case RURI_PID_FILE_PANIC_TIMEOUT:
		snprintf(buf, sizeof(buf), "RURI_PANIC_TIMEOUT\n");
		break;
	case RURI_PID_FILE_EXITED:
		snprintf(buf, sizeof(buf), "RURI_EXITED_%lld\n", arg);
		break;
	case RURI_PID_FILE_SIGNALED:
		snprintf(buf, sizeof(buf), "RURI_SIGNALED_%lld\n", arg);
		break;
	case RURI_PID_FILE_UNKNOWN:
		snprintf(buf, sizeof(buf), "RURI_EXIT_UNKNOWN\n");
		break;
	default:
		return;
	}
	write(ruri_pid_file_fd(-1), buf, strlen(buf));
}
void ruri_setup_timeout_watchdog(const struct RURI_CONTAINER *_Nonnull container)
{
	/*
	 * Fork a timeout watchdog process.
	 * The watchdog will kill the container process if it runs for too long.
	 */
	// Get pid to watch.
	pid_t to_watch = getpid();
	// fork() twice.
	pid_t timeout_pid1 = fork();
	if (timeout_pid1 > 0) {
		// Parent process, wait for child to exit.
		waitpid(timeout_pid1, NULL, 0);
	} else {
		// Ignore SIGTTIN and SIGTTOU.
		signal(SIGTTIN, SIG_IGN);
		signal(SIGTTOU, SIG_IGN);
		ruri_proc_mark(RURI_DAEMON);
		pid_t timeout_pid = fork();
		if (timeout_pid < 0) {
			ruri_error("{red}Failed to fork for timeout watchdog QwQ\n");
		}
		if (timeout_pid > 0) {
			exit(0);
		}
		// Redirect output to /dev/null.
		int dev_null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
		if (dev_null_fd >= 0) {
			dup2(dev_null_fd, STDOUT_FILENO);
			dup2(dev_null_fd, STDERR_FILENO);
			close(dev_null_fd);
		}
		ruri_proc_mark(RURI_DAEMON);
		// Get current time in ns.
		struct timespec ts;
		clock_gettime(CLOCK_MONOTONIC, &ts);
		long long start_ns = (ts.tv_sec * 1000000000LL) + ts.tv_nsec;
		while (1) {
			// If pid died, exit.
			if (kill(to_watch, 0) < 0) {
				exit(0);
			}
			// Check for timeout.
			clock_gettime(CLOCK_MONOTONIC, &ts);
			long long now_ns = (ts.tv_sec * 1000000000LL) + ts.tv_nsec;
			// Timeout reached, kill the container process.
			if ((now_ns - start_ns) >= (long long)(container->timeout * 1000000000LL)) {
				// This will exit pid_file daemon.
				ruri_pid_file_write(RURI_PID_FILE_PANIC_TIMEOUT, 0);
				usleep(100000); // Sleep 0.1s to wait for the pid file to be updated.
				if (!container->fork_as_init) {
					kill(to_watch, SIGKILL);
				} else {
					kill(to_watch, SIGUSR1);
					// 3s timeout for waitpid() in daemon.
					sleep(3);
					kill(to_watch, SIGKILL);
				}
				usleep(100000); // Sleep 0.1s to wait for the process to be killed.
				if (container->auto_umount_on_panic) {
					// Sleep 0.5s.
					usleep(500000);
					ruri_umount_container(container->container_dir);
				}
				exit(EXIT_FAILURE);
			}
			// Sleep 1/10 of timeout.
			usleep((useconds_t)((container->timeout * 1000000) / 10));
		}
		exit(EXIT_SUCCESS);
	}
}
int ruri_setup_pid_file_daemon(struct RURI_CONTAINER *_Nonnull container)
{
	/*
	 * Create a socket pipe and fork() a daemon.
	 * The daemon will listen the pipe and update pid file on host side.
	 * The daemon will also call auto-umount if requested.
	 */
	// Use SOCK_SEQPACKET to create a socket pair for pid file, so we can read the pid from it without worrying about buffering.
	int pid_pipe[2] = { -1, -1 };
	if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pid_pipe) < 0) {
		ruri_warning("{red}Warning: failed to create socket pair for pid file, pid file will not be updated QwQ\n");
	}
	int pid_file_fd = pid_pipe[0];
	ruri_pid_file_fd(pid_pipe[1]);
	signal(SIGPIPE, SIG_IGN);
	// fork() twice then watch pid_file_fd, and write content to pidfile.
	// Get a pipe sync for grandchild process.
	int sync_pipe[2] = { -1, -1 };
	if (pipe2(sync_pipe, O_CLOEXEC) < 0) {
		ruri_warning("{red}Warning: failed to create pipe for pid file daemon sync, pid file may be updated late QwQ\n");
	}
	pid_t pid1 = fork();
	if (pid1 > 0) {
		// Close the write end, we read sync pipe for grandchild ok signal.
		close(sync_pipe[1]);
		// Parent process, wait for child to exit.
		waitpid(pid1, NULL, 0);
		// Get ok signal.
		char buf[16] = { 0 };
		ssize_t n = read(sync_pipe[0], buf, sizeof(buf) - 1);
		if (n > 0) {
			buf[n] = '\0';
			if (strcmp(buf, "OK") != 0) {
				ruri_error("{red}Failed to get sync signal from pid file daemon.\n");
			}
			close(sync_pipe[0]);
		} else {
			ruri_warn_on_error(0, 1, true, "{red}Warning: failed to read sync signal from pid file daemon, pid file may be updated late QwQ\n");
			// Just ignore it, the daemon may still work.
			// But if we got error, just return, the daemon will not work.
			if (n < 0) {
				return -1;
			}
			close(sync_pipe[0]);
		}
	} else {
		// First child process, fork again.
		// Ignore SIGTTIN and SIGTTOU.
		signal(SIGTTIN, SIG_IGN);
		signal(SIGTTOU, SIG_IGN);
		pid_t pid2 = fork();
		if (pid2 > 0) {
			exit(EXIT_SUCCESS);
		} else {
			// Close the read end of sync pipe, we only write to it.
			close(sync_pipe[0]);
			ruri_proc_mark(RURI_DAEMON);
			// Redirect output to /dev/null.
			int dev_null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
			if (dev_null_fd >= 0) {
				dup2(dev_null_fd, STDOUT_FILENO);
				dup2(dev_null_fd, STDERR_FILENO);
				close(dev_null_fd);
			}
			// Close the write end of the pipe in the child process, we only need to read from it.
			close(pid_pipe[1]);
			signal(SIGPIPE, SIG_IGN);
			// read pid from pid_file_fd and write to pidfile.
			int file_fd = -1;
			if (container->pid_file == NULL) {
				file_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
			} else {
				file_fd = open(container->pid_file, O_CREAT | O_CLOEXEC | O_RDWR, S_IRUSR | S_IWUSR);
			}
			if (file_fd < 0) {
				exit(EXIT_FAILURE);
			}
			ftruncate(file_fd, 0);
			lseek(file_fd, 0, SEEK_SET);
			// Try to add a F_WRLCK to the pid file, so we can lock it when writing to it.
			struct flock fl;
			fl.l_type = F_WRLCK;
			fl.l_whence = SEEK_SET;
			fl.l_start = 0;
			fl.l_len = 0;
			if (container->pid_file != NULL) {
				if (fcntl(file_fd, F_SETLK, &fl) < 0) {
					exit(EXIT_FAILURE);
				}
			}
			char buf[256] = { 0 };
			// Write current time to pid file, so we can detect if the container is running by checking if the pid file is updated.
			// Get current time in ns.
			struct timespec ts;
			clock_gettime(CLOCK_MONOTONIC, &ts);
			long long now_ns = (ts.tv_sec * 1000000000LL) + ts.tv_nsec;
			snprintf(buf, sizeof(buf), "RURI_INIT_%lld\n", now_ns);
			write(file_fd, buf, strlen(buf));
			// Write ok signal to sync pipe, so the parent process can continue.
			write(sync_pipe[1], "OK", 2);
			close(sync_pipe[1]);
			while (1) {
read_again:
				memset(buf, 0, sizeof(buf));
				ssize_t n = read(pid_file_fd, buf, sizeof(buf) - 1);
				if (n > 0) {
					buf[n] = '\0';
					// only 0-9,a-z,A-Z and _ are allowed in the pid file, for safety.
					for (ssize_t i = 0; i < n; i++) {
						if (!((buf[i] >= '0' && buf[i] <= '9') || (buf[i] >= 'a' && buf[i] <= 'z') || (buf[i] >= 'A' && buf[i] <= 'Z') || buf[i] == '_' || buf[i] == '\n')) {
							memset(buf, 0, sizeof(buf));
							goto read_again;
						}
					}
					ftruncate(file_fd, 0);
					lseek(file_fd, 0, SEEK_SET);
					write(file_fd, buf, n);
					fsync(file_fd);
					// If we got RURI_PANIC_*, exit now.
					if (strncmp(buf, "RURI_PANIC_", strlen("RURI_PANIC_")) == 0) {
						// release the lock on pid file.
						fl.l_type = F_UNLCK;
						fcntl(file_fd, F_SETLK, &fl);
						// For timeout panic, just exit.
						if (strncmp(buf, "RURI_PANIC_TIMEOUT", strlen("RURI_PANIC_TIMEOUT")) == 0) {
							exit(EXIT_FAILURE);
						}
						if (container->auto_umount || container->auto_umount_on_panic) {
							// Sleep 0.5s.
							usleep(500000);
							ruri_umount_container(container->container_dir);
						}
						exit(EXIT_FAILURE);
					}
				} else if (n == 0) {
					// Read pid file,
					// if we don't get RURI_EXIT*, RURI_SIGNALED* or RURI_PANIC*,
					// Write a RURI_EXIT_UNKNOWN to it.
					lseek(file_fd, 0, SEEK_SET);
					char check_buf[256] = { 0 };
					int check_len = read(file_fd, check_buf, sizeof(check_buf) - 1);
					if (check_len > 0) {
						check_buf[check_len] = '\0';
					}
					if (strncmp(check_buf, "RURI_EXIT", strlen("RURI_EXIT")) && strncmp(check_buf, "RURI_SIGNALED", strlen("RURI_SIGNALED")) && strncmp(check_buf, "RURI_PANIC", strlen("RURI_PANIC"))) {
						ftruncate(file_fd, 0);
						lseek(file_fd, 0, SEEK_SET);
						write(file_fd, "RURI_EXIT_UNKNOWN\n", strlen("RURI_EXIT_UNKNOWN\n"));
						fsync(file_fd);
					}
					// release the lock on pid file.
					fl.l_type = F_UNLCK;
					fcntl(file_fd, F_SETLK, &fl);
					// EOF, the other side has closed the connection, exit.
					if (container->auto_umount) {
						// Sleep 0.5s.
						usleep(500000);
						ruri_umount_container(container->container_dir);
					}
					exit(EXIT_SUCCESS);
				} else {
					// Error, maybe EINTR or EAGAIN, try again.
					if (errno == EINTR || errno == EAGAIN) {
						continue;
					}
					// Other errors, exit.
					//
					// Read pid file,
					// if we don't get RURI_EXIT*, RURI_SIGNALED* or RURI_PANIC*,
					// Write a RURI_EXIT_UNKNOWN to it.
					lseek(file_fd, 0, SEEK_SET);
					char check_buf[256] = { 0 };
					int check_len = read(file_fd, check_buf, sizeof(check_buf) - 1);
					if (check_len > 0) {
						check_buf[check_len] = '\0';
					}
					if (strncmp(check_buf, "RURI_EXIT", strlen("RURI_EXIT")) && strncmp(check_buf, "RURI_SIGNALED", strlen("RURI_SIGNALED")) && strncmp(check_buf, "RURI_PANIC", strlen("RURI_PANIC"))) {
						ftruncate(file_fd, 0);
						lseek(file_fd, 0, SEEK_SET);
						write(file_fd, "RURI_EXIT_UNKNOWN\n", strlen("RURI_EXIT_UNKNOWN\n"));
						fsync(file_fd);
					}
					// release the lock on pid file.
					fl.l_type = F_UNLCK;
					fcntl(file_fd, F_SETLK, &fl);
					if (container->auto_umount) {
						// Sleep 0.5s.
						usleep(500000);
						ruri_umount_container(container->container_dir);
					}
					exit(EXIT_FAILURE);
				}
			}
		}
	}
	close(pid_pipe[0]);
	return pid_file_fd;
}
static int ruri_tgid_init(int req)
{
	/*
	 * Store tgid for sig handler when we got SIGUSER1.
	 * If req >= 0, set the tgid to req and return it.
	 * If req < 0, return the stored tgid.
	 */
	// Just to store tgid for sig handler when we got SIGUSER1.
	static thread_local int tgid = -1;
	if (req < 0) {
		return tgid;
	}
	tgid = req;
	return tgid;
}
static void kill_subprocess_and_die(int __attribute__((unused)) signum)
{
	/*
	 * For init process, when we got SIGUSER1,
	 * it means the timeout watchdog has detected a timeout.
	 * So we need to kill all subprocesses and exit.
	 */
	int tgid = ruri_tgid_init(-1);
	if (tgid > 0) {
		kill(-tgid, SIGKILL);
	}
	// Keep do non-blocking wait for 3s.
	// Get time.
	struct timeval start, now;
	gettimeofday(&start, NULL);
	int wait_time_ms = 3000;
	while (true) {
		while (waitpid(-1 * ruri_tgid_init(-1), NULL, WNOHANG) > 0)
			;
		for (int i = 0; i < 15; i++) {
			if (waitpid(-1 * ruri_tgid_init(-1), NULL, WNOHANG) < 0) {
				exit(EXIT_FAILURE);
			}
			// usleep 0.03s to avoid busy loop, total sleep time is 0.45s.
			usleep(30000);
		}
		// check timeout.
		gettimeofday(&now, NULL);
		if (((now.tv_sec - start.tv_sec) * 1000) + ((now.tv_usec - start.tv_usec) / 1000) >= wait_time_ms) {
			kill(0, SIGKILL);
			exit(EXIT_FAILURE);
		}
	}
	exit(EXIT_FAILURE);
}
void ruri_fork_as_init(void)
{
	/*
	 * Fork as init process, and setpgid to create a new process group for the container processes.
	 * The init process will wait for all child processes, and exit when they all exited.
	 * When the init process got SIGUSER1, it means the timeout watchdog has detected a timeout,
	 * so it will kill all subprocesses and exit.
	 */
	ruri_proc_mark(RURI_DAEMON);
	pid_t pid = fork();
	if (pid < 0) {
		ruri_error("{red}Failed to fork for init process QwQ\n");
	}
	if (pid == 0) {
		setpgid(0, 0);
		if (tcsetpgrp(STDIN_FILENO, getpid()) < 0) {
			// This may fail if the parent process is not a terminal, just ignore it.
			ruri_warning("{yellow}: Warning: failed to set controlling terminal for init process, maybe the parent process is not a terminal QwQ\n");
		}
		return;
	}
	signal(SIGTTIN, SIG_IGN);
	signal(SIGTTOU, SIG_IGN);
	close(ruri_pid_file_fd(-1));
	for (int i = 3; i < 10; i++) {
		close(i);
	}
	setpgid(pid, pid);
	ruri_tgid_init(pid);
	// Set PR_SET_PDEATHSIG to SIGKILL.
	prctl(PR_SET_PDEATHSIG, SIGKILL);
	// Set SIGUSR1 handler to kill subprocesses.
	signal(SIGUSR1, kill_subprocess_and_die);
	// Keep do non-blocking wait for child process, if all child process exited, exit too.
	int status = 0;
	int last_status = EXIT_SUCCESS;
	while (true) {
		if (waitpid(-pid, &status, 0) < 0) {
			exit(last_status);
		}
		if (WIFEXITED(status)) {
			last_status = WEXITSTATUS(status);
		} else if (WIFSIGNALED(status)) {
			last_status = 128 + WTERMSIG(status);
		}
	}
}