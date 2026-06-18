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
 *
 */
#include "include/cprintf.h"
// This is safe bro. If you realloc a <1024 byte memory failed, kill your device pls.
#define cp_safe_realloc(ptr_, size_) realloc(ptr_, size_)
// NOLINTBEGIN
struct CPRINTF_COLOR__ cprintf_color = {
	.base = "254;228;208",
	.black_fg = "\033[30m",
	.red_fg = "\033[31m",
	.green_fg = "\033[32m",
	.yellow_fg = "\033[33m",
	.blue_fg = "\033[34m",
	.purple_fg = "\033[35m",
	.cyan_fg = "\033[36m",
	.white_fg = "\033[37m",
	.black_bg = "\033[40m",
	.red_bg = "\033[41m",
	.green_bg = "\033[42m",
	.yellow_bg = "\033[43m",
	.blue_bg = "\033[44m",
	.purple_bg = "\033[45m",
	.cyan_bg = "\033[46m",
	.white_bg = "\033[47m",
};
bool cprintf_print_color_only_tty = true;
// NOLINTEND
static bool is_rgb_color(const char *_Nonnull color)
{
	/*
	 * Check if color is an R;G;B format color.
	 */
	int sem = 0;
	// If R > 255, it's not a color.
	if (atoi(color) > 255) {
		return false;
	}
	for (size_t i = 1; i < strlen(color) - 1; i++) {
		if (color[i] == ';') {
			sem++;
			// If G or B > 255, it's not a color.
			if (atoi(&color[i + 1]) > 255) {
				return false;
			}
		}
		// If there are more than 2 `;`, the format is not correct.
		if (sem > 2) {
			return false;
		}
		// If the color include other charactor, the format is not correct.
		if (!isdigit(color[i]) && color[i] != ';') {
			return false;
		}
	}
	// If there are not 2 `;`, the format is not correct.
	if (sem != 2) {
		return false;
	}
	return true;
}
static const char *cprintf_add_fg_color(const char *_Nonnull buf, char **_Nonnull str, bool skip)
{
	/*
	 * Only valid {color} will be recognized,
	 * and for other '{' without 'color}', we print a '{'.
	 * we return the pointer to the last character that is
	 * not recognized as color.
	 */
	const char *ret = buf;
	char color[17] = { '\0' };
	for (int i = 0; i < 16; i++) {
		if (buf[i] == '\0') {
			*str = cp_safe_realloc(*str, strlen(*str) + 2);
			strcat(*str, "{");
			return buf;
		}
		if (buf[i] == '}') {
			color[i] = buf[i];
			color[i + 1] = 0;
			ret = &(buf[i]);
			break;
		}
		color[i] = buf[i];
		color[i + 1] = 0;
	}
	if (strcmp(color, "{clear}") == 0) {
		if (!skip) {
			*str = cp_safe_realloc(*str, strlen(*str) + 10);
			strcat(*str, "\033[0m");
		}
	} else if (strcmp(color, "{black}") == 0) {
		if (!skip) {
			*str = cp_safe_realloc(*str, strlen(*str) + 5 + strlen(cprintf_color.black_fg));
			strncat(*str, cprintf_color.black_fg, strlen(cprintf_color.black_fg));
		}
	} else if (strcmp(color, "{red}") == 0) {
		if (!skip) {
			*str = cp_safe_realloc(*str, strlen(*str) + 5 + strlen(cprintf_color.red_fg));
			strncat(*str, cprintf_color.red_fg, strlen(cprintf_color.red_fg));
		}
	} else if (strcmp(color, "{green}") == 0) {
		if (!skip) {
			*str = cp_safe_realloc(*str, strlen(*str) + 5 + strlen(cprintf_color.green_fg));
			strncat(*str, cprintf_color.green_fg, strlen(cprintf_color.green_fg));
		}
	} else if (strcmp(color, "{yellow}") == 0) {
		if (!skip) {
			*str = cp_safe_realloc(*str, strlen(*str) + 5 + strlen(cprintf_color.yellow_fg));
			strncat(*str, cprintf_color.yellow_fg, strlen(cprintf_color.yellow_fg));
		}
	} else if (strcmp(color, "{blue}") == 0) {
		if (!skip) {
			*str = cp_safe_realloc(*str, strlen(*str) + 5 + strlen(cprintf_color.blue_fg));
			strncat(*str, cprintf_color.blue_fg, strlen(cprintf_color.blue_fg));
		}
	} else if (strcmp(color, "{purple}") == 0) {
		if (!skip) {
			*str = cp_safe_realloc(*str, strlen(*str) + 5 + strlen(cprintf_color.purple_fg));
			strncat(*str, cprintf_color.purple_fg, strlen(cprintf_color.purple_fg));
		}
	} else if (strcmp(color, "{cyan}") == 0) {
		if (!skip) {
			*str = cp_safe_realloc(*str, strlen(*str) + 5 + strlen(cprintf_color.cyan_fg));
			strncat(*str, cprintf_color.cyan_fg, strlen(cprintf_color.cyan_fg));
		}
	} else if (strcmp(color, "{white}") == 0) {
		if (!skip) {
			*str = cp_safe_realloc(*str, strlen(*str) + 5 + strlen(cprintf_color.white_fg));
			strncat(*str, cprintf_color.white_fg, strlen(cprintf_color.white_fg));
		}
	} else if (strcmp(color, "{base}") == 0) {
		if (!skip) {
			*str = cp_safe_realloc(*str, strlen(*str) + 114);
			strcat(*str, "\033[38;2;");
			strncat(*str, cprintf_color.base, strlen(cprintf_color.base));
			strcat(*str, "m");
		}
	} else if (strcmp(color, "{underline}") == 0) {
		if (!skip) {
			*str = cp_safe_realloc(*str, strlen(*str) + 10);
			strcat(*str, "\033[4m");
		}
	} else if (strcmp(color, "{highlight}") == 0) {
		if (!skip) {
			*str = cp_safe_realloc(*str, strlen(*str) + 10);
			strcat(*str, "\033[1m");
		}
	} else if (is_rgb_color(color)) {
		if (!skip) {
			*str = cp_safe_realloc(*str, strlen(*str) + 114);
			strcat(*str, "\033[38;2;");
			strncat(*str, color + 1, strlen(color) - 2);
			strcat(*str, "m");
		}
	} else {
		ret = buf;
		if (!skip) {
			*str = cp_safe_realloc(*str, strlen(*str) + 2);
			strcat(*str, "{");
		}
	}
	return ret;
}
static const char *cprintf_add_bg_color(const char *_Nonnull buf, char **_Nonnull str, bool skip)
{
	/*
	 * Only valid [color] will be recognized,
	 * and for other '[' without 'color[', we print a '['.
	 * we return the pointer to the last character that is
	 * not recognized as color.
	 */
	const char *ret = buf;
	char color[17] = { '\0' };
	for (int i = 0; i < 16; i++) {
		if (buf[i] == '\0') {
			*str = cp_safe_realloc(*str, strlen(*str) + 2);
			strcat(*str, "[");
			return buf;
		}
		if (buf[i] == ']') {
			color[i] = buf[i];
			color[i + 1] = 0;
			ret = &(buf[i]);
			break;
		}
		color[i] = buf[i];
		color[i + 1] = 0;
	}
	if (strcmp(color, "[clear]") == 0) {
		if (!skip) {
			*str = cp_safe_realloc(*str, strlen(*str) + 10);
			strcat(*str, "\033[0m");
		}
	} else if (strcmp(color, "[black]") == 0) {
		if (!skip) {
			*str = cp_safe_realloc(*str, strlen(*str) + 5 + strlen(cprintf_color.black_bg));
			strncat(*str, cprintf_color.black_bg, strlen(cprintf_color.black_bg));
		}
	} else if (strcmp(color, "[red]") == 0) {
		if (!skip) {
			*str = cp_safe_realloc(*str, strlen(*str) + 5 + strlen(cprintf_color.red_bg));
			strncat(*str, cprintf_color.red_bg, strlen(cprintf_color.red_bg));
		}
	} else if (strcmp(color, "[green]") == 0) {
		if (!skip) {
			*str = cp_safe_realloc(*str, strlen(*str) + 5 + strlen(cprintf_color.green_bg));
			strncat(*str, cprintf_color.green_bg, strlen(cprintf_color.green_bg));
		}
	} else if (strcmp(color, "[yellow]") == 0) {
		if (!skip) {
			*str = cp_safe_realloc(*str, strlen(*str) + 5 + strlen(cprintf_color.yellow_bg));
			strncat(*str, cprintf_color.yellow_bg, strlen(cprintf_color.yellow_bg));
		}
	} else if (strcmp(color, "[blue]") == 0) {
		if (!skip) {
			*str = cp_safe_realloc(*str, strlen(*str) + 5 + strlen(cprintf_color.blue_bg));
			strncat(*str, cprintf_color.blue_bg, strlen(cprintf_color.blue_bg));
		}
	} else if (strcmp(color, "[purple]") == 0) {
		if (!skip) {
			*str = cp_safe_realloc(*str, strlen(*str) + 5 + strlen(cprintf_color.purple_bg));
			strncat(*str, cprintf_color.purple_bg, strlen(cprintf_color.purple_bg));
		}
	} else if (strcmp(color, "[cyan]") == 0) {
		if (!skip) {
			*str = cp_safe_realloc(*str, strlen(*str) + 5 + strlen(cprintf_color.cyan_bg));
			strncat(*str, cprintf_color.cyan_bg, strlen(cprintf_color.cyan_bg));
		}
	} else if (strcmp(color, "[white]") == 0) {
		if (!skip) {
			*str = cp_safe_realloc(*str, strlen(*str) + 5 + strlen(cprintf_color.white_bg));
			strncat(*str, cprintf_color.white_bg, strlen(cprintf_color.white_bg));
		}
	} else if (strcmp(color, "[base]") == 0) {
		if (!skip) {
			*str = cp_safe_realloc(*str, strlen(*str) + 114);
			strncat(*str, "\033[1;48;2;", 7);
			strncat(*str, cprintf_color.base, strlen(cprintf_color.base));
			strcat(*str, "m");
		}
	} else if (strcmp(color, "[underline]") == 0) {
		if (!skip) {
			*str = cp_safe_realloc(*str, strlen(*str) + 10);
			strcat(*str, "\033[4m");
		}
	} else if (strcmp(color, "[highlight]") == 0) {
		if (!skip) {
			*str = cp_safe_realloc(*str, strlen(*str) + 10);
			strcat(*str, "\033[1m");
		}
	} else if (is_rgb_color(color)) {
		if (!skip) {
			*str = cp_safe_realloc(*str, strlen(*str) + 114);
			strcat(*str, "\033[48;2;");
			strncat(*str, color + 1, strlen(color) - 2);
			strcat(*str, "m");
		}
	} else {
		ret = buf;
		if (!skip) {
			*str = cp_safe_realloc(*str, strlen(*str) + 2);
			strcat(*str, "[");
		}
	}
	return ret;
}
char *cprintf_regen_format(FILE *_Nonnull stream, const char *_Nonnull format)
{
	bool skip = (cprintf_print_color_only_tty && !isatty(fileno(stream)));
	char *ret = malloc(strlen(format) + 1);
	ret[0] = '\0';
	const char *p = NULL;
	p = format;
	for (size_t i = 0; i < strlen(format); i++) {
		// Search for '{'.
		if (*p == '{') {
			// *p will be moved because we need to skip the {color} string.
			p = cprintf_add_fg_color(p, &ret, skip);
		} else if (*p == '[') {
			// *p will be moved because we need to skip the [color] string.
			p = cprintf_add_bg_color(p, &ret, skip);
		} else {
			ret = cp_safe_realloc(ret, strlen(ret) + 2);
			strncat(ret, p, 1);
		}
		// Recompute the value of i.
		i = (size_t)(p - format);
		// Goto the next charactor.
		p = &(p[1]);
	}
	if (!skip) {
		ret = cp_safe_realloc(ret, strlen(ret) + 5);
		strcat(ret, "\033[0m");
	}
	return ret;
}

// NOLINTBEGIN
jmp_buf cprintf_jmp_buf;
// NOLINTEND
void cp_time_out(int sig)
{
	/*
	 * This function is used to handle the timeout signal.
	 * It will do nothing, just to avoid the program to exit.
	 */
	(void)sig; // Avoid unused parameter warning.
	longjmp(cprintf_jmp_buf, 1);
}
static char *get_bg_color__(void)
{
	/*
	 * Only xterm **might** support this.
	 * At least, better than nothing.
	 * It works with magic on my machine :)
	 */
	int stat = setjmp(cprintf_jmp_buf);
	if (stat) {
		// If we got a timeout, we will return NULL.
		return NULL;
	}
	struct termios old_termios;
	struct termios new_termios;
	tcgetattr(STDERR_FILENO, &old_termios);
	new_termios = old_termios;
	// Don't ask me why, idk QwQ
	cfmakeraw(&new_termios);
	tcsetattr(STDERR_FILENO, TCSANOW, &new_termios);
	write(STDERR_FILENO, "\033]11;?\a", strlen("\033]11;?\a"));
	char buf[128];
	buf[0] = '\0';
	// Don't ask me why, idk QwQ
	struct sigaction sa;
	sa.sa_handler = cp_time_out;
	sigaction(SIGALRM, &sa, NULL);
	// Set a timeout of 0.1 second.
	struct itimerval timer;
	timer.it_value.tv_sec = 0;
	// Timeout of 0.2 second.
	// And we will wait for the response for 0.1 second.
	// So the real timeout is 0.1 second.
	timer.it_value.tv_usec = 200000;
	timer.it_interval.tv_sec = 0;
	timer.it_interval.tv_usec = 0;
	setitimer(ITIMER_REAL, &timer, NULL);
	// Sleep for 0.1 second to wait for the response.
	usleep(100000);
	ssize_t n = read(STDERR_FILENO, buf, sizeof(buf) - 1);
	if (n < 0) {
		// If read failed, we will return NULL.
		return NULL;
	}
	// Reset the timer.
	sigaction(SIGALRM, NULL, NULL);
	// At least I know this nya~
	// restore the old termios settings.
	tcsetattr(STDERR_FILENO, TCSANOW, &old_termios);
	fflush(stderr);
	if (n > 0) {
		buf[n] = '\0';
		int j = 0;
		char *p = strstr(buf, "rgb:");
		if (!p) {
			return NULL;
		}
		p += strlen("rgb:");
		char *ret = malloc(32);
		for (size_t i = 0; i < strlen(p); i++) {
			if (p[i] >= 32 && p[i] <= 126) {
				ret[j++] = p[i];
				ret[j] = '\0';
			}
		}
		return ret;
	}
	return NULL;
}
bool cp_xterm_is_dark_mode(void)
{
	struct stat _stat_buf;
	if (fstat(STDERR_FILENO, &_stat_buf) != 0 || !S_ISCHR(_stat_buf.st_mode)) {
		// If stderr is not a terminal,
		// we cannot determine the background color.
		return false;
	}
	char *bg_color = get_bg_color__();
	if (!bg_color) {
		return false;
	}
	char *r_str = strtok(bg_color, "/");
	char *g_str = strtok(NULL, "/");
	char *b_str = strtok(NULL, "/");
	if (!r_str || !g_str || !b_str) {
		free(bg_color);
		return false;
	}
	unsigned int r = (unsigned int)strtol(r_str, NULL, 16);
	unsigned int g = (unsigned int)strtol(g_str, NULL, 16);
	unsigned int b = (unsigned int)strtol(b_str, NULL, 16);
	// ITU-R BT.601 luminance.
	// It works, why?
	// Y = 0.299*R + 0.587*G + 0.114*B
	double luminance = (r * 0.299) + (g * 0.587) + (b * 0.114);
	free(bg_color);
	return (luminance <= 32768.0);
}
