// SPDX-License-Identifier: MIT
/*
 *
 * This file is part of cprintf, with ABSOLUTELY NO WARRANTY.
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
 */
// NOLINTBEGIN
#pragma once
#ifdef __linux__
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <sys/stat.h>
#include <threads.h>
#include <stdint.h>
#include <termios.h>
#include <poll.h>
#include <signal.h>
#include <setjmp.h>
#ifndef _Nullable
#define _Nullable
#endif
#ifndef _Nonnull
#define _Nonnull
#endif
#if __STDC_VERSION__ < 202000L
#define bool _Bool
#define true ((_Bool) + 1u)
#define false ((_Bool) + 0u)
#endif
#define CPRINTF_MAJOR 2
#define CPRINTF_MINOR 1
bool cp_xterm_is_dark_mode(void);
int cprintf__(const char *_Nonnull buf);
int cfprintf__(FILE *_Nonnull stream, const char *_Nonnull buf);
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

// Do not print color if the stream is a FIFO.
extern bool cprintf_print_color_only_tty;

// Generic support.
#define cprintf_strlen__(cpsl_f__) (cpsl_f__ == NULL ? 0 : strlen(cpsl_f__))
#define cprintf_avoid_null__(cpan_f__) (cpan_f__ == NULL ? "" : cpan_f__)
#define cprintf_buf_len__(cpbl_f__, cpbl_d__) (cpbl_f__ != NULL ? (size_t)snprintf(NULL, 0, cpbl_f__, cpbl_d__) : 0)
#define cprintf_get_fmt__(cpgf_d__, cpgf_f__)                                                                                                                                                                                                                                                                                                                                                                                                                              \
	({                                                                                                                                                                                                                                                                                                                                                                                                                                                                 \
		char *cpgf_buf__ = malloc(cprintf_strlen__(cpgf_f__) + 16);                                                                                                                                                                                                                                                                                                                                                                                                \
		sprintf(cpgf_buf__, _Generic((cpgf_d__), _Bool: (cpgf_d__ ? "true" : "false"), char: "%%%sc", signed char: "%%%sd", unsigned char: "%%%sd", short: "%%%shd", unsigned short: "%%%shu", int: "%%%sd", unsigned int: "%%%su", long: "%%%sld", unsigned long: "%%%slu", long long: "%%%slld", unsigned long long: "%%%sllu", float: "%%%sf", double: "%%%sf", long double: "%%%sLf", void *: "%%%sp", default: "{unknown}"), cprintf_avoid_null__(cpgf_f__)); \
		cprintf_mark_buf__(cpgf_buf__);                                                                                                                                                                                                                                                                                                                                                                                                                            \
		cpgf_buf__;                                                                                                                                                                                                                                                                                                                                                                                                                                                \
	})

#define cprintf_to_char__(cpdc_d__, cpdc_f__)                                          \
	({                                                                             \
		char *cptc_buf__ = malloc(cprintf_buf_len__(cpdc_f__, cpdc_d__) + 32); \
		sprintf(cptc_buf__, cpdc_f__, cpdc_d__);                               \
		cprintf_mark_buf__(cptc_buf__);                                        \
		cptc_buf__;                                                            \
	})

#define F(cp_f_data__, cp_f_format__) cprintf_to_char__(cp_f_data__, cprintf_get_fmt__(cp_f_data__, cp_f_format__))
#define T(cp_t_data__) F(cp_t_data__, NULL)
#define cprintf_len__(cpl_format__, ...) (snprintf(NULL, 0, cprintf_regen_format__(cpl_format__), ##__VA_ARGS__) + 8)
#define csprintf(string, format, ...)                                          \
	({                                                                     \
		int csp_ret__ = 0;                                             \
		if (format == NULL) {                                          \
			csp_ret__ = sprintf(string, "%s", "(null)");           \
		} else {                                                       \
			char *csp_fmt__ = cprintf_regen_format__(format);      \
			csp_ret__ = sprintf(string, csp_fmt__, ##__VA_ARGS__); \
			cprintf_free_buf__();                                  \
		}                                                              \
		csp_ret__;                                                     \
	})
#define cprintf(format, ...)                                                   \
	({                                                                     \
		int cp_ret__ = 0;                                              \
		char *cp_buf__ = malloc(cprintf_len__(format, ##__VA_ARGS__)); \
		csprintf(cp_buf__, format, ##__VA_ARGS__);                     \
		cp_ret__ = cprintf__(cp_buf__);                                \
		free(cp_buf__);                                                \
		cp_ret__;                                                      \
	})
#define cfprintf(stream, format, ...)                                           \
	({                                                                      \
		int cfp_ret__ = 0;                                              \
		char *cfp_buf__ = malloc(cprintf_len__(format, ##__VA_ARGS__)); \
		csprintf(cfp_buf__, format, ##__VA_ARGS__);                     \
		cfp_ret__ = cfprintf__(stream, cfp_buf__);                      \
		free(cfp_buf__);                                                \
		cfp_ret__;                                                      \
	})
#define scprintf(format, ...)                                                                  \
	{                                                                                      \
		char *cp_buf__ = malloc((size_t)snprintf(NULL, 0, format, ##__VA_ARGS__) + 1); \
		sprintf(cp_buf__, format, ##__VA_ARGS__);                                      \
		cprintf__(cp_buf__);                                                           \
		free(cp_buf__);                                                                \
	}
#define scfprintf(stream, format, ...)                                                          \
	{                                                                                       \
		char *cfp_buf__ = malloc((size_t)snprintf(NULL, 0, format, ##__VA_ARGS__) + 1); \
		sprintf(cfp_buf__, format, ##__VA_ARGS__);                                      \
		cfprintf__(stream, cfp_buf__);                                                  \
		free(cfp_buf__);                                                                \
	}
// For generic support.
char *cprintf_regen_format__(const char *f);
void cprintf_free_buf__(void);
void cprintf_mark_buf__(char *b);
// NOLINTEND
