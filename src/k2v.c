// SPDX-License-Identifier: MIT
/*
 *
 * This file is part of libk2v, with ABSOLUTELY NO WARRANTY.
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
#include "include/k2v.h"
// Warnings && stop at warning.
#define warning(...)                                                                                   \
	{                                                                                              \
		if (k2v_show_warning) {                                                                \
			fprintf(stderr, "\033[31mAt %s at %d at %s:\n", __FILE__, __LINE__, __func__); \
			fprintf(stderr, ##__VA_ARGS__);                                                \
			fprintf(stderr, "\033[0m");                                                    \
		}                                                                                      \
		if (k2v_stop_at_warning) {                                                             \
			fprintf(stderr, "\033[31mlibk2v stop_at_warning set, exit now\n\033[0m");      \
			exit(114);                                                                     \
		}                                                                                      \
	}
static void __k2v_lint(const char *_Nonnull buf);
// For warning() macro.
// We use global variables here, because we need it to be simple for developers.
bool k2v_stop_at_warning = false;
bool k2v_show_warning = true;
// Correct backslash.
static char *correct_backslash(char *buf)
{
	/*
	 * Delete the backslash.
	 * '\n' -> '\n' (no change)
	 * '\t' -> '\t' (no change)
	 * '\r' -> '\r' (no change)
	 * '\\' -> '\' (delete one backslash)
	 * '\x' -> 'x' (delete the backslash)
	 * '\0' -> '0' (delete the backslash)
	 * '\"' -> '\"' (no change)
	 * As I need it to follow the Shell standard,
	 * '\"' will output as '\"'.
	 */
	char *ret = strdup(buf);
	int j = 0;
	size_t buf_len = strlen(buf);
	for (size_t i = 0; i < buf_len; i++) {
		if (buf[i] == '\\') {
			if (i < buf_len - 1) {
				i++;
				if (buf[i] == 'n') {
					ret[j] = '\\';
					j++;
					ret[j] = 'n';
				} else if (buf[i] == 't') {
					ret[j] = '\\';
					j++;
					ret[j] = 't';
				} else if (buf[i] == 'r') {
					ret[j] = '\\';
					j++;
					ret[j] = 'r';
				} else if (buf[i] == '"') {
					ret[j] = '\\';
					j++;
					ret[j] = '"';
				} else {
					ret[j] = buf[i];
				}
				j++;
				ret[j] = '\0';
				continue;
			}
		}
		ret[j] = buf[i];
		j++;
		ret[j] = '\0';
	}
	free(buf);
	return ret;
}
// Get the first line in buffer.
static char *get_current_line(const char *_Nonnull buf)
{
	/*
	 * Warning: free() after use.
	 */
	// NULL check.
	if (buf == NULL) {
		return NULL;
	}
	char *ret = strdup(buf);
	if (strchr(ret, '\n') == NULL) {
		return ret;
	}
	*strchr(ret, '\n') = '\0';
	// ret will be larger than the line we got.
	// But never mind, '\0' is the end of string.
	return ret;
}
// Goto next line.
static char *goto_next_line(const char *_Nonnull buf)
{
	/*
	 * Warning: do not free() it.
	 */
	// NULL check.
	if (buf == NULL) {
		return NULL;
	}
	if (strlen(buf) == 0) {
		return NULL;
	}
	char *ret = strchr(buf, '\n');
	if (ret == NULL) {
		return NULL;
	}
	// Skip '\n'.
	return ret + 1;
}
// Get file size.
size_t k2v_get_filesize(const char *_Nonnull path)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "\033[31mNo such file or directory:%s\n\033[0m", path);
		if (k2v_stop_at_warning) {
			exit(114);
		} else {
			return 0;
		}
	}
	struct stat filestat;
	fstat(fd, &filestat);
	off_t ret = filestat.st_size;
	close(fd);
	// To avoid overflow.
	return (size_t)ret + 3;
}
char *k2v_open_file(const char *_Nonnull path, size_t bufsize)
{
	/*
	 * It will automatically call malloc(2),
	 * open config file specified by `path`,
	 * read the file to ret, and do basic checks.
	 * If config file does not exist, return NULL.
	 */
	// NULL check.
	if (path == NULL) {
		return NULL;
	}
	// bufsize+2 might avoid overflow(I hope).
	char *ret = (char *)malloc(bufsize + 2);
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		free(ret);
		return NULL;
	}
	ssize_t len = read(fd, ret, bufsize);
	if (len < 0) {
		free(ret);
		close(fd);
		warning("\033[31mRead file %s failed\n\033[0m", path);
		return NULL;
	}
	ret[len] = '\0';
	if (len != strlen(ret)) {
		warning("\033[31m \\0 is not the end of file\n");
	}
	__k2v_lint(ret);
	close(fd);
	return ret;
}
char *char_to_k2v(const char *_Nonnull key, const char *_Nonnull val)
{
	// NULL check.
	if (key == NULL) {
		return NULL;
	}
	char *ret = NULL;
	if (val != NULL) {
		ret = malloc(strlen(key) + strlen(val) + 8);
		sprintf(ret, "%s=\"%s\"\n", key, val);
	} else {
		ret = malloc(strlen(key) + 8);
		sprintf(ret, "%s=\"\"\n", key);
	}
	return ret;
}
char *int_to_k2v(const char *_Nonnull key, int val)
{
	// NULL check.
	if (key == NULL) {
		return NULL;
	}
	char *ret = malloc(strlen(key) + 18 + 8);
	sprintf(ret, "%s=\"%d\"\n", key, val);
	return ret;
}
char *long_to_k2v(const char *_Nonnull key, long val)
{
	// NULL check.
	if (key == NULL) {
		return NULL;
	}
	char *ret = malloc(strlen(key) + 18 + 8 + 114);
	sprintf(ret, "%s=\"%ld\"\n", key, val);
	return ret;
}
char *bool_to_k2v(const char *_Nonnull key, bool val)
{
	// NULL check.
	if (key == NULL) {
		return NULL;
	}
	char *ret = malloc(strlen(key) + 8 + 8);
	sprintf(ret, "%s=\"%s\"\n", key, val ? "true" : "false");
	return ret;
}
char *float_to_k2v(const char *_Nonnull key, float val)
{
	// NULL check.
	if (key == NULL) {
		return NULL;
	}
	char *buf = malloc(strlen(key) + 400 + 8);
	sprintf(buf, "%s=\"%f\"\n", key, val);
	char *ret = strdup(buf);
	free(buf);
	return ret;
}
char *char_array_to_k2v(const char *_Nonnull key, char *const *_Nonnull val, int len)
{
	// NULL check.
	if (key == NULL) {
		return NULL;
	}
	char *buf = malloc(strlen(key) + 8);
	if (len == 0) {
		sprintf(buf, "%s=[]\n", key);
		char *ret = strdup(buf);
		free(buf);
		return ret;
	}
	size_t size = strlen(key) + 8;
	sprintf(buf, "%s=[", key);
	char *tmp = NULL;
	for (int i = 0; i < len; i++) {
		tmp = malloc(strlen(val[i]) + 8);
		sprintf(tmp, "\"%s\"", val[i]);
		size += strlen(val[i]) + 8;
		buf = realloc(buf, size);
		strcat(buf, tmp);
		if (i != len - 1) {
			strcat(buf, ",");
		} else {
			strcat(buf, "]");
		}
		free(tmp);
	}
	strcat(buf, "\n");
	char *ret = strdup(buf);
	free(buf);
	return ret;
}
char *int_array_to_k2v(const char *_Nonnull key, int *_Nonnull val, int len)
{
	// NULL check.
	if (key == NULL) {
		return NULL;
	}
	char *buf = malloc(strlen(key) + 18 * ((size_t)len + 8));
	if (len == 0) {
		sprintf(buf, "%s=[]\n", key);
		char *ret = strdup(buf);
		free(buf);
		return ret;
	}
	sprintf(buf, "%s=[", key);
	char *tmp = malloc(18);
	for (int i = 0; i < len; i++) {
		sprintf(tmp, "\"%d\"", val[i]);
		strcat(buf, tmp);
		if (i != len - 1) {
			strcat(buf, ",");
		} else {
			strcat(buf, "]");
		}
	}
	strcat(buf, "\n");
	char *ret = strdup(buf);
	free(buf);
	free(tmp);
	return ret;
}
char *float_array_to_k2v(const char *_Nonnull key, float *_Nonnull val, int len)
{
	// NULL check.
	if (key == NULL) {
		return NULL;
	}
	char *buf = malloc(strlen(key) + 400 * (size_t)len + 8);
	if (len == 0) {
		sprintf(buf, "%s=[]\n", key);
		char *ret = strdup(buf);
		free(buf);
		return ret;
	}
	sprintf(buf, "%s=[", key);
	char *tmp = malloc(400);
	for (int i = 0; i < len; i++) {
		sprintf(tmp, "\"%f\"", val[i]);
		strcat(buf, tmp);
		if (i != len - 1) {
			strcat(buf, ",");
		} else {
			strcat(buf, "]");
		}
	}
	strcat(buf, "\n");
	char *ret = strdup(buf);
	free(buf);
	free(tmp);
	return ret;
}
char *k2v_add_comment(char *_Nonnull buf, char *_Nonnull comment)
{
	size_t size = 0;
	if (buf != NULL) {
		size += strlen(buf);
	}
	size += strlen(comment);
	char *ret = malloc(size + 8);
	if (buf != NULL) {
		sprintf(ret, "%s# %s\n", buf, comment);
	} else {
		sprintf(ret, "# %s\n", comment);
	}
	free(buf);
	// Correct memory size.
	char *tmp = strdup(ret);
	free(ret);
	ret = tmp;
	return ret;
}
char *k2v_add_newline(char *_Nonnull buf)
{
	size_t size = 0;
	if (buf != NULL) {
		size += strlen(buf);
	}
	size += strlen("\n") + 2;
	char *ret = malloc(size + 8);
	if (buf != NULL) {
		sprintf(ret, "%s\n", buf);
	} else {
		sprintf(ret, "\n");
	}
	free(buf);
	// Correct memory size.
	char *tmp = strdup(ret);
	free(ret);
	ret = tmp;
	return ret;
}
static bool is_comment_line(const char *_Nonnull buf)
{
	// NULL check.
	if (buf == NULL) {
		// It is not a comment line.
		// But, we return true, so it will be skipped.
		return true;
	}
	// It is an empty line.
	size_t buf_len = strlen(buf);
	if (buf_len == 0) {
		return true;
	}
	for (size_t i = 0; i < buf_len; i++) {
		if (buf[i] == ' ') {
			continue;
		}
		if (buf[i] == '\0') {
			// It is not a comment line.
			// But, it is a empty line.
			return true;
		}
		if (buf[i] == '#') {
			return true;
		}
		return false;
	}
	return false;
}
static char *remove_comment(const char *_Nonnull buf)
{
	// NULL check.
	if (buf == NULL) {
		return NULL;
	}
	char *ret = NULL;
	const char *p = buf;
	char *line = NULL;
	while (p != NULL) {
		if (p == NULL) {
			break;
		}
		line = get_current_line(p);
		if (line == NULL) {
			p = goto_next_line(p);
			continue;
		}
		if (is_comment_line(line)) {
			free(line);
			p = goto_next_line(p);
			continue;
		}
		if (ret == NULL) {
			ret = strdup(line);
			free(line);
		} else {
			ret = realloc(ret, strlen(ret) + strlen(line) + 2);
			strcat(ret, "\n");
			strcat(ret, line);
			free(line);
		}
		p = goto_next_line(p);
		if (p == NULL) {
			break;
		}
	}
	return ret;
}
static char *line_get_left(const char *_Nonnull line)
{
	// Skip space.
	size_t line_len = strlen(line);
	for (size_t i = 0; i < line_len; i++) {
		if (line[i] == ' ') {
			continue;
		}
		line = &line[i];
		break;
	}
	line_len = strlen(line);
	char *ret = malloc(line_len + 1);
	for (size_t i = 0; i < line_len; i++) {
		if (line[i] == '\\') {
			if (i < line_len - 2) {
				ret[i] = line[i];
				i++;
				ret[i] = line[i];
				continue;
			}
			ret[i] = line[i];
		}
		if (line[i] == '=') {
			ret[i] = '\0';
			break;
		}
		ret[i] = line[i];
		ret[i + 1] = '\0';
	}
	// Skip space.
	size_t ret_len = strlen(ret);
	for (size_t i = ret_len - 1; i > 0; i--) {
		if (ret[i] == ' ') {
			continue;
		}
		ret[i + 1] = '\0';
		break;
	}
	return ret;
}
static char *line_get_right(const char *_Nonnull line)
{
	// Skip space.
	size_t line_len = strlen(line);
	for (size_t i = 0; i < line_len; i++) {
		if (line[i] == ' ') {
			continue;
		}
		line = &line[i];
		break;
	}
	// Goto value.
	line_len = strlen(line);
	for (size_t i = 0; i < line_len; i++) {
		// We allow to use \ in key.
		if (line[i] == '\\') {
			i++;
			continue;
		}
		if (line[i] == '=') {
			line = &line[i + 1];
			break;
		}
	}
	// Skip space.
	line_len = strlen(line);
	for (size_t i = 0; i < line_len; i++) {
		if (line[i] == ' ') {
			continue;
		}
		line = &line[i];
		break;
	}
	char *ret = strdup(line);
	size_t ret_len = strlen(ret);
	for (size_t i = ret_len - 1; i > 0; i--) {
		if (ret[i] == ' ') {
			continue;
		}
		ret[i + 1] = '\0';
		break;
	}
	ret = correct_backslash(ret);
	return ret;
}
static bool __k2v_is_array(const char *_Nonnull line)
{
	// NULL check.
	if (line == NULL) {
		return false;
	}
	const char *p = line;
	// Goto value.
	size_t line_len = strlen(line);
	for (size_t i = 0; i < line_len; i++) {
		// We allow to use \ in key.
		if (line[i] == '\\') {
			i++;
			continue;
		}
		if (line[i] == '=') {
			p = &line[i + 1];
			break;
		}
	}
	// Check if the start of value is '['.
	size_t p_len = strlen(p);
	for (size_t i = 0; i < p_len; i++) {
		if (p[i] == ' ') {
			continue;
		}
		if (p[i] == '[') {
			return true;
		}
		return false;
	}
	return false;
}
static int __k2v_basic_lint(const char *_Nonnull line)
{
	// We need a = to split key and value.
	// `"` should not appear in key, except `\"`.
	// We need a key without space.
	// We need a value, with "" or [].
	// So:
	// NULL check.
	// Skip space.
	size_t line_len = strlen(line);
	for (size_t i = 0; i < line_len; i++) {
		if (line[i] == ' ') {
			continue;
		}
		line = &line[i];
		break;
	}
	// Check key.
	// Check if we have key.
	if (strchr(line, '=') == NULL) {
		warning("No key found: %s\n", line);
		return -1;
	}
	if (strchr(line, '=') == line) {
		warning("Key should not be empty: %s\n", line);
		return -1;
	}
	line_len = strlen(line);
	for (size_t i = 0; i < line_len; i++) {
		if (line[i] == '\\') {
			i++;
			continue;
		}
		if (line[i] == '=') {
			break;
		}
		if (line[i] == '"') {
			warning("Key should not contain \": %s\n", line);
			return -1;
		}
	}
	// Goto value.
	const char *p = NULL;
	line_len = strlen(line);
	for (size_t i = 0; i < line_len; i++) {
		// We allow to use \ in key.
		if (line[i] == '\\') {
			i++;
			continue;
		}
		if (line[i] == '=') {
			p = &line[i + 1];
			break;
		}
	}
	// Check if we have key.
	if (p == NULL) {
		warning("No key found: %s\n", line);
		return -1;
	}
	// Check if value is empty.
	size_t p_len = strlen(p);
	if (p_len == 0) {
		warning("Value should not be empty: %s\n", line);
		return -1;
	}
	// Skip space.
	for (size_t i = 0; i < p_len; i++) {
		if (p[i] == ' ') {
			continue;
		}
		p = &p[i];
		break;
	}
	// Check if value start with `"` or `[`, and end with `"` or `]`.
	p_len = strlen(p);
	if (p[0] == '"') {
		for (size_t i = p_len - 1; i > 0; i--) {
			if (p[i] == ' ') {
				continue;
			}
			if (p[i] == '"') {
				break;
			}
			warning("Value should end with \": %s\n", line);
			return -1;
		}
	} else if (p[0] == '[') {
		for (size_t i = p_len - 1; i > 0; i--) {
			if (p[i] == ' ') {
				continue;
			}
			if (p[i] == ']') {
				break;
			}
			warning("Value should end with ]: %s\n", line);
			return -1;
		}
	} else {
		warning("Value should start with \" or [: %s\n", line);
		return -1;
	}
	return 0;
}
static int __k2v_array_lint(const char *_Nonnull line)
{
	const char *p = line;
	// Goto value.
	size_t line_len = strlen(line);
	for (size_t i = 0; i < line_len; i++) {
		// We allow to use \ in key.
		if (line[i] == '\\') {
			i++;
			continue;
		}
		if (line[i] == '=') {
			p = &line[i + 1];
			break;
		}
	}
	// Skip space.
	size_t p_len = strlen(p);
	for (size_t i = 0; i < p_len; i++) {
		if (p[i] == ' ') {
			continue;
		}
		p = &p[i];
		break;
	}
	// Check for `[]`.
	int bracket = 0;
	p_len = strlen(p);
	for (size_t i = 0; i < p_len; i++) {
		if (p[i] == '\\') {
			i++;
			continue;
		}
		if (p[i] == '[' || p[i] == ']') {
			bracket++;
		}
	}
	if (bracket != 2) {
		warning("Value should be in [], and you can not nest [] in array: %s\n", line);
		return -1;
	}
	// Check for `"`.
	int quote = 0;
	for (size_t i = 0; i < p_len; i++) {
		if (p[i] == '\\') {
			i++;
			continue;
		}
		if (p[i] == '"') {
			quote++;
		}
	}
	if (quote % 2 != 0) {
		warning("Value should be quoted properly, and do not include `\"` in quote: %s\n", line);
		return -1;
	}
	// We do not force empty array have a `""`.
	if (quote == 0) {
		quote = 2;
	}
	// Check value number.
	int count = 0;
	bool in_quote = false;
	for (size_t i = 0; i < p_len; i++) {
		if (p[i] == '\\') {
			i++;
			continue;
		}
		if (p[i] == '"') {
			in_quote = !in_quote;
		}
		if (p[i] == ',' && !in_quote) {
			count++;
		}
	}
	if (count != quote / 2 - 1) {
		warning("Value should be quoted by `"
			"`, separated by `,`, and the last value should not have a `,`: %s\n",
			line);
		return -1;
	}
	in_quote = false;
	size_t last = 0;
	// Check for null value.
	// If quote is 2, we do not need to check.
	if (quote == 2) {
		return 0;
	}
	for (size_t i = 0; i < p_len; i++) {
		if (p[i] == '\\') {
			i++;
			continue;
		}
		if (p[i] == '"') {
			in_quote = !in_quote;
			if (in_quote) {
				last = i;
			}
		}
		if (!in_quote) {
			if (last == i - 1) {
				warning("Value in array should not be empty: %s\n", line);
				return -1;
			}
		}
	}
	return 0;
}
static int __k2v_scalar_lint(const char *_Nonnull line)
{
	const char *p = line;
	// Goto value.
	size_t line_len = strlen(line);
	for (size_t i = 0; i < line_len; i++) {
		// We allow to use \ in key.
		if (line[i] == '\\') {
			i++;
			continue;
		}
		if (line[i] == '=') {
			p = &line[i + 1];
			break;
		}
	}
	// Skip space.
	size_t p_len = strlen(p);
	for (size_t i = 0; i < p_len; i++) {
		if (p[i] == ' ') {
			continue;
		}
		p = &p[i];
		break;
	}
	// Check for `"`.
	int quote = 0;
	p_len = strlen(p);
	for (size_t i = 0; i < p_len; i++) {
		if (p[i] == '\\') {
			i++;
			continue;
		}
		if (p[i] == '"') {
			quote++;
		}
	}
	if (quote != 2) {
		warning("Value should be quoted properly, and do not include `\"` in quote: %s\n", line);
		return -1;
	}
	return 0;
}
static char *k2v_auto_tidy(const char *_Nonnull buf)
{
	// NULL check.
	if (buf == NULL) {
		return NULL;
	}
	char *ret = NULL;
	char *tmp = remove_comment(buf);
	char *p = tmp;
	char *line = NULL;
	while (p != NULL) {
		if (p == NULL) {
			break;
		}
		line = get_current_line(p);
		if (line == NULL) {
			p = goto_next_line(p);
			continue;
		}
		if (__k2v_basic_lint(line) != 0) {
			free(line);
			p = goto_next_line(p);
			continue;
		}
		if (__k2v_is_array(line)) {
			if (__k2v_array_lint(line) == 0) {
				if (ret == NULL) {
					ret = strdup(line);
				} else {
					ret = realloc(ret, strlen(ret) + strlen(line) + 3);
					strcat(ret, "\n");
					strcat(ret, line);
				}
			}
		} else {
			if (__k2v_scalar_lint(line) == 0) {
				if (ret == NULL) {
					ret = strdup(line);
				} else {
					ret = realloc(ret, strlen(ret) + strlen(line) + 3);
					strcat(ret, "\n");
					strcat(ret, line);
				}
			}
		}
		free(line);
		p = goto_next_line(p);
		if (p == NULL) {
			break;
		}
	}
	free(tmp);
	return ret;
}
static void __k2v_check_singularity(const char *_Nonnull buf)
{
	char **keys = NULL;
	const char *p = buf;
	char *line = NULL;
	size_t count = 0;
	while (p != NULL) {
		if (p == NULL) {
			break;
		}
		line = get_current_line(p);
		if (line == NULL) {
			p = goto_next_line(p);
			continue;
		}
		char *key = line_get_left(line);
		if (keys == NULL) {
			keys = malloc(sizeof(char *) * 3);
			keys[0] = key;
			keys[1] = NULL;
			count++;
		} else {
			for (int i = 0; keys[i] != NULL; i++) {
				if (strcmp(keys[i], key) == 0) {
					warning("Key should be unique: %s\n", line);
				}
			}
			keys = realloc(keys, sizeof(char *) * (count + 2));
			keys[count] = key;
			keys[count + 1] = NULL;
			count++;
		}
		free(line);
		p = goto_next_line(p);
		if (p == NULL) {
			break;
		}
	}
	if (keys == NULL) {
		return;
	}
	for (int i = 0; keys[i] != NULL; i++) {
		free(keys[i]);
	}
	free(keys);
}
static void __k2v_lint(const char *_Nonnull buf)
{
	if (buf == NULL) {
		warning("NULL buf");
		return;
	}
	char *tmp = remove_comment(buf);
	char *p = tmp;
	char *line = NULL;
	while (p != NULL) {
		if (p == NULL) {
			break;
		}
		line = get_current_line(p);
		if (line == NULL) {
			if (goto_next_line(p) == NULL) {
				break;
			}
			p = goto_next_line(p);
			continue;
		}
		if (__k2v_basic_lint(line) != 0) {
			warning("\033[31mLint error: %s\n", line);
			free(line);
			p = goto_next_line(p);
			continue;
		}
		if (__k2v_is_array(line)) {
			if (__k2v_array_lint(line) != 0) {
				warning("\033[31mLint error: %s\n", line);
			}
		} else {
			if (__k2v_scalar_lint(line) != 0) {
				warning("\033[31mLint error: %s\n", line);
			}
		}
		free(line);
		if (goto_next_line(p) == NULL) {
			break;
		}
		p = goto_next_line(p);
		if (p == NULL) {
			break;
		}
	}
	char *tmp2 = k2v_auto_tidy(tmp);
	__k2v_check_singularity(tmp2);
	free(tmp2);
	free(tmp);
}
static char *key_get_line(const char *_Nonnull key, const char *_Nonnull buf)
{
	const char *p = buf;
	char *line = NULL;
	char *left = NULL;
	while (p != NULL) {
		if (p == NULL) {
			break;
		}
		line = get_current_line(p);
		if (line == NULL) {
			p = goto_next_line(p);
			continue;
		}
		left = line_get_left(line);
		if (strcmp(left, key) == 0) {
			free(left);
			return line;
		}
		free(line);
		free(left);
		p = goto_next_line(p);
		if (p == NULL) {
			break;
		}
	}
	return NULL;
}
char *key_get_char(const char *_Nonnull key, const char *_Nonnull buf)
{
	if (buf == NULL || key == NULL) {
		return NULL;
	}
	if (strlen(key) == 0 || strlen(buf) == 0) {
		return NULL;
	}
	__k2v_lint(buf);
	char *buf_to_read = k2v_auto_tidy(buf);
	char *line = key_get_line(key, buf_to_read);
	if (line == NULL) {
		return NULL;
	}
	char *tmp = line_get_right(line);
	free(line);
	char *p = strdup(&tmp[1]);
	free(tmp);
	p[strlen(p) - 1] = '\0';
	char *ret = strdup(p);
	if (strlen(ret) == 0) {
		free(p);
		free(ret);
		free(buf_to_read);
		return NULL;
	}
	free(p);
	free(buf_to_read);
	return ret;
}
int key_get_int(const char *_Nonnull key, const char *_Nonnull buf)
{
	if (buf == NULL || key == NULL) {
		return 0;
	}
	if (strlen(key) == 0 || strlen(buf) == 0) {
		return 0;
	}
	__k2v_lint(buf);
	char *buf_to_read = k2v_auto_tidy(buf);
	char *line = key_get_line(key, buf_to_read);
	if (line == NULL) {
		return 0;
	}
	char *tmp = line_get_right(line);
	free(line);
	char *p = strdup(&tmp[1]);
	free(tmp);
	p[strlen(p) - 1] = '\0';
	int ret = atoi(p);
	free(p);
	free(buf_to_read);
	return ret;
}
long long key_get_long(const char *_Nonnull key, const char *_Nonnull buf)
{
	if (buf == NULL || key == NULL) {
		return 0;
	}
	if (strlen(key) == 0 || strlen(buf) == 0) {
		return 0;
	}
	__k2v_lint(buf);
	char *buf_to_read = k2v_auto_tidy(buf);
	char *line = key_get_line(key, buf_to_read);
	if (line == NULL) {
		return 0;
	}
	char *tmp = line_get_right(line);
	free(line);
	char *p = strdup(&tmp[1]);
	free(tmp);
	p[strlen(p) - 1] = '\0';
	long ret = strtol(p, NULL, 10);
	free(p);
	free(buf_to_read);
	return ret;
}
float key_get_float(const char *_Nonnull key, const char *_Nonnull buf)
{
	if (buf == NULL || key == NULL) {
		return 0;
	}
	if (strlen(key) == 0 || strlen(buf) == 0) {
		return 0;
	}
	__k2v_lint(buf);
	char *buf_to_read = k2v_auto_tidy(buf);
	char *line = key_get_line(key, buf_to_read);
	if (line == NULL) {
		return 0;
	}
	char *tmp = line_get_right(line);
	free(line);
	char *p = strdup(&tmp[1]);
	free(tmp);
	p[strlen(p) - 1] = '\0';
	float ret = strtof(p, NULL);
	free(p);
	free(buf_to_read);
	return ret;
}
bool key_get_bool(const char *_Nonnull key, const char *_Nonnull buf)
{
	if (buf == NULL || key == NULL) {
		return false;
	}
	if (strlen(key) == 0 || strlen(buf) == 0) {
		return false;
	}
	__k2v_lint(buf);
	char *buf_to_read = k2v_auto_tidy(buf);
	char *line = key_get_line(key, buf_to_read);
	if (line == NULL) {
		return false;
	}
	char *tmp = line_get_right(line);
	free(line);
	char *p = strdup(&tmp[1]);
	free(tmp);
	p[strlen(p) - 1] = '\0';
	bool ret = false;
	if (strcmp(p, "true") == 0) {
		ret = true;
	}
	free(p);
	free(buf_to_read);
	return ret;
}
static char *__goto_next_val(const char *_Nonnull p)
{
	/*
	 * Need not free().
	 */
	int quote = 0;
	char *ret = NULL;
	// Check if we reached the end.
	if (p == NULL) {
		return NULL;
	}
	size_t p_len = strlen(p);
	for (size_t i = 0; i < p_len; i++) {
		if (p[i] == ' ') {
			i++;
			continue;
		}
		if (p[i] == ']') {
			return NULL;
		}
		break;
	}
	for (size_t i = 0; i < p_len; i++) {
		if (p[i] == '\\') {
			i++;
			continue;
		}
		if (p[i] == '"') {
			quote++;
		}
		if (quote == 2) {
			if (strchr(&p[i], ',') == NULL) {
				return (char *)&p[i];
			}
			ret = strchr(&p[i], ',') + 1;
		}
	}
	return (char *)ret;
}
static char *__current_val(const char *_Nonnull p)
{
	/*
	 * free() after use.
	 */
	size_t p_len = strlen(p);
	if (p == NULL || p_len == 0) {
		return NULL;
	}
	char *tmp = malloc(p_len + 8);
	if (strchr(p, '"') == NULL) {
		free(tmp);
		return NULL;
	}
	char *q = strchr(p, '"') + 1;
	size_t j = 0;
	size_t q_len = strlen(q);
	for (size_t i = 0; i < q_len; i++) {
		if (q[i] == '\\') {
			if (i < q_len - 2) {
				tmp[j] = q[i];
				i++;
				j++;
				tmp[j] = q[i];
				tmp[j + 1] = '\0';
				continue;
			}
			tmp[j] = q[i];
			tmp[j + 1] = '\0';
			break;
		}
		if (q[i] == '"') {
			tmp[j] = '\0';
			break;
		}
		tmp[j] = q[i];
		tmp[j + 1] = '\0';
		j++;
	}
	char *ret = strdup(tmp);
	if (strchr(ret, ']') == ret) {
		free(ret);
		free(tmp);
		return NULL;
	}
	free(tmp);
	return ret;
}
static char **array_to_str_array(const char *_Nonnull array)
{
	char **ret = malloc(sizeof(char *) * 2);
	ret[0] = NULL;
	if (strcmp(array, "[]") == 0 || strcmp(array, "[\"\"]") == 0) {
		return ret;
	}
	size_t count = 0;
	char *val = NULL;
	const char *p = &array[1];
	while (p != NULL) {
		val = __current_val(p);
		if (val == NULL) {
			break;
		}
		p = __goto_next_val(p);
		if (ret[0] == NULL) {
			free(ret);
			ret = malloc(sizeof(char *) * 3);
			ret[0] = val;
			ret[1] = NULL;
			count++;
		} else {
			ret = realloc(ret, sizeof(char *) * (count + 2));
			ret[count] = val;
			ret[count + 1] = NULL;
			count++;
		}
	}
	return ret;
}
int key_get_int_array(const char *_Nonnull key, const char *_Nonnull buf, int *_Nonnull array, int limit)
{
	if (buf == NULL || key == NULL || array == NULL || limit == 0) {
		return 0;
	}
	if (strlen(key) == 0 || strlen(buf) == 0) {
		return 0;
	}
	__k2v_lint(buf);
	char *buf_to_read = k2v_auto_tidy(buf);
	int ret = 0;
	char *line = key_get_line(key, buf_to_read);
	if (line == NULL) {
		array[0] = 0;
		return 0;
	}
	char *tmp = line_get_right(line);
	free(line);
	char **str_array = array_to_str_array(tmp);
	for (int i = 0; i < limit; i++) {
		if (str_array[i] == NULL) {
			break;
		}
		if (i >= limit) {
			break;
		}
		array[i] = atoi(str_array[i]);
		ret++;
	}
	for (int i = 0; str_array[i] != NULL; i++) {
		free(str_array[i]);
	}
	free(str_array);
	free(tmp);
	free(buf_to_read);
	return ret;
}
int key_get_char_array(const char *_Nonnull key, const char *_Nonnull buf, char *_Nonnull array[], int limit)
{
	if (buf == NULL || key == NULL || array == NULL || limit == 0) {
		return 0;
	}
	if (strlen(key) == 0 || strlen(buf) == 0) {
		return 0;
	}
	__k2v_lint(buf);
	char *buf_to_read = k2v_auto_tidy(buf);
	int ret = 0;
	char *line = key_get_line(key, buf_to_read);
	if (line == NULL) {
		array[0] = 0;
		return 0;
	}
	char *tmp = line_get_right(line);
	free(line);
	char **str_array = array_to_str_array(tmp);
	for (int i = 0; i < limit; i++) {
		if (str_array[i] == NULL) {
			break;
		}
		if (i >= limit) {
			break;
		}
		array[i] = str_array[i];
		ret++;
	}
	free(str_array);
	free(tmp);
	free(buf_to_read);
	return ret;
}
int key_get_float_array(const char *_Nonnull key, const char *_Nonnull buf, float *_Nonnull array, int limit)
{
	if (buf == NULL || key == NULL || array == NULL || limit == 0) {
		return 0;
	}
	if (strlen(key) == 0 || strlen(buf) == 0) {
		return 0;
	}
	__k2v_lint(buf);
	char *buf_to_read = k2v_auto_tidy(buf);
	int ret = 0;
	char *line = key_get_line(key, buf_to_read);
	if (line == NULL) {
		free(buf_to_read);
		array[0] = 0;
		return 0;
	}
	char *tmp = line_get_right(line);
	free(line);
	char **str_array = array_to_str_array(tmp);
	for (int i = 0; i < limit; i++) {
		if (str_array[i] == NULL) {
			break;
		}
		if (i >= limit) {
			break;
		}
		array[i] = strtof(str_array[i], NULL);
		ret++;
	}
	for (int i = 0; str_array[i] != NULL; i++) {
		free(str_array[i]);
	}
	free(str_array);
	free(tmp);
	free(buf_to_read);
	return ret;
}
bool have_key(const char *_Nonnull key, const char *_Nonnull buf)
{
	if (buf == NULL || key == NULL) {
		return false;
	}
	if (strlen(key) == 0 || strlen(buf) == 0) {
		return false;
	}
	__k2v_lint(buf);
	char *buf_to_read = k2v_auto_tidy(buf);
	char *tmp = key_get_line(key, buf_to_read);
	if (tmp == NULL) {
		free(buf_to_read);
		return false;
	}

	free(tmp);
	free(buf_to_read);
	return true;
}