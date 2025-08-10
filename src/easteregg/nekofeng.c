// SPDX-License-Identifier: MIT
/*
 *
 * This file is part of ruri, with ABSOLUTELY NO WARRANTY.
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
 *
 */
#include "include/nekofeng.h"
// NOLINTBEGIN
/*
 * This file was the main.c in nekofeng project.
 * Now, it provides the function ruri_AwA() as the easteregg of ruri.
 *
 * Note:
 * This part of code is just for fun, do not take it seriously.
 * It will not affect the main function of ruri.
 * And, it works on my machine!
 */
#ifndef RURI_CORE_ONLY
// The global variables are defined here.
int nekofeng_x;
int nekofeng_y;
atomic_flag nekofeng_lock = ATOMIC_FLAG_INIT;
atomic_flag nekofeng_lock2 = ATOMIC_FLAG_INIT;
// The spin lock.
void nekofeng_spin_lock(atomic_flag *_Nonnull l)
{
	while (atomic_flag_test_and_set(l)) {
	}
}
// The spin unlock.
void nekofeng_spin_unlock(atomic_flag *_Nonnull l)
{
	atomic_flag_clear(l);
}
// The function to get the length of a string.
size_t nekofeng_strlen(const char32_t *_Nonnull str)
{
	size_t len = 0;
	while (str[len] != U'\0') {
		len++;
	}
	return len;
}
// The function to duplicate a string.
char32_t *nekofeng_strdup(const char32_t *_Nonnull str)
{
	size_t len = nekofeng_strlen(str);
	char32_t *dup = malloc((len + 1) * sizeof(char32_t));
	if (dup == NULL) {
		return NULL;
	}
	for (size_t i = 0; i < len; i++) {
		dup[i] = str[i];
	}
	dup[len] = U'\0';
	return dup;
}
// init() function for getting window size.
static void init(void)
{
	printf("\033[H\033[2J");
	// Use ioctl(2) to get the window size.
	struct winsize size;
	ioctl(STDOUT_FILENO, TIOCGWINSZ, &size);
	if (size.ws_col < 70 || size.ws_row < 24) {
		printf("\033[31mThe window size is too small.\n");
		exit(1);
	}
	nekofeng_x = size.ws_col / 2 - NEKOFENG_X_SIZE / 2;
	nekofeng_y = size.ws_row / 2 - NEKOFENG_Y_SIZE / 2;
}
static long nekofeng_tids[6] = { -114 };
static void update_tids(void)
{
	long tid = syscall(SYS_gettid);
	nekofeng_spin_lock(&nekofeng_lock2);
	for (int i = 0; i < 6; i++) {
		if (nekofeng_tids[i] < 0) {
			nekofeng_tids[i] = tid;
			nekofeng_tids[i + 1] = -114;
			nekofeng_spin_unlock(&nekofeng_lock2);
			return;
		}
	}
}
static void *test0(void *arg)
{
	update_tids();
	nekofeng_face(100000, 7);
	return arg;
}
static void *test1(void *arg)
{
	update_tids();
	nekofeng_blink_lefteye(200000, 7);
	return arg;
}
static void *test2(void *arg)
{
	update_tids();
	nekofeng_blink_righteye(200000, 7);
	return arg;
}
static void *test3(void *arg)
{
	update_tids();
	nekofeng_mouth(200000, 7);
	return arg;
}
static void *test4(void *arg)
{
	update_tids();
	for (int i = 0; i < 11; i++) {
		nekofeng_ahoge(300000, 0);
	}
	return arg;
}
void ruri_AwA(void)
{
	printf("\033[?25l");
	printf("\033[?1049h");
	fflush(stdout);
	// Maybe this is more secure?
	if (geteuid() == 0) {
		setgid(65534);
		setuid(65534);
	}
	// If we didn't set this, c32rtomb() will not work.
	setlocale(LC_ALL, "");
	init();
	struct NEKOFENG_LAYER layer;
	layer.layer = U"\033[1;38;2;254;228;208m\n"
			"          Keep moe.\n"
			"          Keep cool.\n"
			"         Keep hacking.\n"
			"Keep on the side of technology.\n\n"
			"      But talk is cheap,\n"
			"       Show me the code.\n";
	layer.x_offset = 3;
	layer.y_offset = -2;
	nekofeng_typewrite_layer(&layer, 50000, true);
	sleep(2);
	nekofeng_clear_typewrite_layer(&layer, 50000);
	// It works with bug, don't care about it.
	pid_t pid = fork();
	if (pid > 0) {
		wait(NULL);
	} else {
		pthread_t t0, t1, t2, t3, t4;
		pthread_create(&t0, NULL, test0, NULL);
		pthread_create(&t3, NULL, test3, NULL);
		pthread_create(&t1, NULL, test1, NULL);
		pthread_create(&t2, NULL, test2, NULL);
		pthread_create(&t4, NULL, test4, NULL);
		sleep(7);
		printf("\033[H\033[2J");
		for (int i = 0; i < 6; i++) {
			if (nekofeng_tids[i] > 0) {
				syscall(SYS_tgkill, getpid(), nekofeng_tids[i], SIGKILL);
			} else {
				break;
			}
		}
	}
	printf("\033[H\033[2J");
	layer.layer = U"\033[1;38;2;254;228;208m\n\n"
			"●   ●  ●●●  ●●●●●       ●   ●   ●    ●●●  ●●●●● ●●●●  \n"
			"●● ●● ●   ● ●           ●   ●  ● ●  ●   ● ●     ●   ● \n"
			"● ● ● ●   ● ●●●●  ●●●●● ●●●●● ●●●●● ●     ●●●●  ●●●●● \n"
			"●   ● ●   ● ●           ●   ● ●   ● ●   ● ●     ●  ●  \n"
			"●   ●  ●●●  ●●●●●       ●   ● ●   ●  ●●●  ●●●●● ●   ● \n";
	layer.x_offset = -10;
	layer.y_offset = -2;
	nekofeng_typewrite_layer(&layer, 5000, false);
	sleep(4);
	printf("\033[H\033[2J");
	printf("\033[?1049l");
	printf("\033[?25h");
	fflush(stdout);
	exit(EXIT_SUCCESS);
}
#else
#include "../include/ruri.h"
void ruri_AwA()
{
	cprintf("{red}ruri was build with core-only mode QwQ.\n");
}
#endif
// NOLINTEND