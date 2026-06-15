// SPDX-License-Identifier: MIT
/*
 *
 * This file is part of cprintf, with ABSOLUTELY NO WARRANTY.
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
 */
#pragma once
#ifdef __linux__
#define _GNU_SOURCE
#endif
#include <ctype.h>
#include <poll.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <termios.h>
#include <threads.h>
#include <unistd.h>
#ifndef _Nullable
#define _Nullable
#endif
#ifndef _Nonnull
#define _Nonnull
#endif
#if __STDC_VERSION__ < 202000L
#define bool _Bool
#define true ((_Bool)1u)
#define false ((_Bool)0u)
#endif
#define CPRINTF_MAJOR 3
#define CPRINTF_MINOR 0
bool cp_xterm_is_dark_mode(void);
// Color support.
struct CPRINTF_COLOR__ {
	char *base;
	char *red_fg;
	char *green_fg;
	char *yellow_fg;
	char *blue_fg;
	char *purple_fg;
	char *cyan_fg;
	char *white_fg;
	char *black_fg;
	char *red_bg;
	char *green_bg;
	char *yellow_bg;
	char *blue_bg;
	char *purple_bg;
	char *cyan_bg;
	char *white_bg;
	char *black_bg;
};
extern struct CPRINTF_COLOR__ cprintf_color;
#define cprintf_base_color cprintf_color.base
// Do not print color if the stream is not a terminal.
extern bool cprintf_print_color_only_tty;
char *cprintf_regen_format(FILE *_Nonnull stream, const char *_Nonnull format);
#define cprintf(format, ...)                                            \
	({                                                              \
		int cfp_ret__ = 0;                                      \
		char *cfp_buf__ = cprintf_regen_format(stdout, format); \
		cfp_ret__ = printf(cfp_buf__, ##__VA_ARGS__);           \
		free(cfp_buf__);                                        \
		cfp_ret__;                                              \
	})
#define cfprintf(stream, format, ...)                                   \
	({                                                              \
		int cfp_ret__ = 0;                                      \
		char *cfp_buf__ = cprintf_regen_format(stream, format); \
		cfp_ret__ = fprintf(stream, cfp_buf__, ##__VA_ARGS__);  \
		free(cfp_buf__);                                        \
		cfp_ret__;                                              \
	})
