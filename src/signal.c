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
 * This file is used to catch segfault,
 * So that we can show some extra info when segfault.
 *
 *   .^.   .^.
 *   /⋀\_ﾉ_/⋀\
 *  /ﾉｿﾉ\ﾉｿ丶メ    This is Ruri Hakozaki.
 *  ﾙﾘﾘ >  x )ﾘ   If you see her, blame your cmdline and the author.
 * ﾉノ㇏  ^  ﾉﾉ
 *       ⠁⠁
 *  "I don't know what's happening, but I got killed in the game..."
 */
char *ruri_get_proc_type(void)
{
	/*
	 * This is useful for debugging.
	 */
	switch (ruri_proc_mark(RURI_QUERY)) {
	case RURI_UNSHARE:
		return "unshare container";
	case RURI_CHROOT:
		return "chroot container";
	case RURI_ROOTLESS:
		return "rootless container";
	case RURI_DAEMON:
		return "daemon process";
	case RURI_UMOUNT:
		return "umount container";
	default:
		return "unknown process";
	}
	return "";
}
enum RURI_PROC_TYPE ruri_proc_mark(enum RURI_PROC_TYPE mark)
{
	/*
	 * Just for debugging.
	 */
	static thread_local enum RURI_PROC_TYPE ret = RURI_CHROOT;
	if (mark == RURI_QUERY) {
		return ret;
	}
	ret = mark;
	return ret;
}
static void sig_write_str(const char *s)
{
	if (s == NULL)
		return;
	size_t len = 0;
	while (s[len] != '\0')
		len++;
	write(STDERR_FILENO, s, len);
}
static void sig_write_int(int val)
{
	char tmp[16];
	int i = 0;
	unsigned int uval;
	if (val < 0) {
		write(STDERR_FILENO, "-", 1);
		uval = (unsigned int)(-(val + 1)) + 1u;
	} else {
		uval = (unsigned int)val;
	}
	if (uval == 0) {
		write(STDERR_FILENO, "0", 1);
		return;
	}
	while (uval > 0) {
		tmp[i++] = '0' + (char)(uval % 10);
		uval /= 10;
	}
	while (--i >= 0)
		write(STDERR_FILENO, &tmp[i], 1);
}
static void sig_write_uint(unsigned int val)
{
	sig_write_int((int)val);
}
// Show some extra info when segfault (async-signal-safe).
static void panic(int sig)
{
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_DFL;
	sigaction(sig, &sa, NULL);

	int clifd = open("/proc/self/cmdline", O_RDONLY | O_CLOEXEC);
	char buf[1024];
	ssize_t bufsize = 0;
	if (clifd >= 0) {
		bufsize = read(clifd, buf, sizeof(buf));
		close(clifd);
	}
	sig_write_str("  .^.   .^.\n");
	sig_write_str("  /⋀\\_ﾉ_/⋀\\\n");
	sig_write_str(" /ﾉｿﾉ\\ﾉｿ丶メ\n");
	sig_write_str(" ﾙﾘﾘ >  x )ﾘ\n");
	sig_write_str("ﾉノ㇏  ^  ﾉﾉ\n");
	sig_write_str("      ⠁⠁\n");
	sig_write_str("RURI ERROR MESSAGE\n");
	sig_write_str("Seems that it's time to abort.\n");
	sig_write_str("SIG: ");
	sig_write_int(sig);
	sig_write_str("\nUID: ");
	sig_write_uint(getuid());
	sig_write_str("\nPID: ");
	sig_write_int(getpid());
	sig_write_str("\nPROCESS: ");
	sig_write_str(ruri_get_proc_type());
	sig_write_str("\nCLI: ");
	for (ssize_t i = 0; i < bufsize; i++) {
		if (buf[i] == '\0') {
			write(STDERR_FILENO, " ", 1);
		} else {
			write(STDERR_FILENO, &buf[i], 1);
		}
	}
	sig_write_str("\nThis message might caused by an internal error.\n");
	sig_write_str("If you think something is wrong, please report at:\n");
	sig_write_str("https://github.com/rurioss/ruri/issues\n\n");
	_exit(114);
}
// Catch coredump signal.
void ruri_register_signal(void)
{
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = panic;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESETHAND;
	sigaction(SIGABRT, &sa, NULL);
	sigaction(SIGBUS, &sa, NULL);
	sigaction(SIGFPE, &sa, NULL);
	sigaction(SIGILL, &sa, NULL);
	sigaction(SIGQUIT, &sa, NULL);
	sigaction(SIGSEGV, &sa, NULL);
	sigaction(SIGSYS, &sa, NULL);
	sigaction(SIGTRAP, &sa, NULL);
	sigaction(SIGXCPU, &sa, NULL);
	sigaction(SIGXFSZ, &sa, NULL);
}
