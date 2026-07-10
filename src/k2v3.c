// SPDX-License-Identifier: MIT
/*
 *
 * This file is part of libk2v, with ABSOLUTELY NO WARRANTY.
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
#include "include/k2v3.h"
#define k2v3_error(...)                                                                             \
	do {                                                                                        \
		k2v3_errno(K2V3_UNRECOVERABLE);                                                     \
		fprintf(stderr, "[libk2v]: in %s() at %s line %d :", __func__, __FILE__, __LINE__); \
		fprintf(stderr, __VA_ARGS__);                                                       \
		fprintf(stderr, "\n");                                                              \
		if (k2v3_stop_at_warning(-1)) {                                                     \
			fprintf(stderr, "[libk2v]: k2v_stop_at_warning set, exit\n");               \
			exit(114);                                                                  \
		}                                                                                   \
		longjmp(k2v3_jmp, 1);                                                               \
	} while (0)
#define k2v3_warning(...)                                                                                   \
	do {                                                                                                \
		k2v3_errno(K2V3_RECOVERABLE);                                                               \
		if (k2v3_show_warning(-1) || k2v3_stop_at_warning(-1)) {                                    \
			fprintf(stderr, "[libk2v]: in %s() at %s line %d :", __func__, __FILE__, __LINE__); \
			fprintf(stderr, __VA_ARGS__);                                                       \
			fprintf(stderr, "\n");                                                              \
		}                                                                                           \
		if (k2v3_stop_at_warning(-1)) {                                                             \
			fprintf(stderr, "[libk2v]: k2v_stop_at_warning set, exit\n");                       \
			exit(114);                                                                          \
		}                                                                                           \
	} while (0)
#ifdef K2V3_FUZZ
#undef k2v3_warning
#define k2v3_warning(...) \
	do {              \
	} while (0)
#endif
bool k2v3_stop_at_warning(int req)
{
	static thread_local bool ret = false;
	if (req == -1) {
		return ret;
	}
	if (req == 0) {
		ret = false;
	} else {
		ret = true;
	}
	return ret;
}
bool k2v3_show_warning(int req)
{
	static thread_local bool ret = false;
	if (req == -1) {
		return ret;
	}
	if (req == 0) {
		ret = false;
	} else {
		ret = true;
	}
	return ret;
}
enum K2V3_ERRNO k2v3_errno(enum K2V3_ERRNO req)
{
	static thread_local enum K2V3_ERRNO ret = K2V3_NORMAL;
	if (req == K2V3_QUERY) {
		return ret;
	}
	ret = req;
	return ret;
}
// Warning: when this happen, this lib has fully internal error and you should panic yourself.
thread_local jmp_buf k2v3_jmp;
//
//
// Parse into cache.
//
//
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
	size_t len = strlen(buf);
	for (size_t i = 0; i < len; i++) {
		if (buf[i] == '\\') {
			if (i < len - 1) {
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
				continue;
			}
		}
		ret[j] = buf[i];
		j++;
	}
	free(buf);
	ret[j] = '\0';
	return ret;
}
struct K2V3_STRING {
	char *str;
	size_t len;
};
struct K2V3_KEY {
	char *key;
	size_t jmp;
};
struct K2V3_VALUE {
	enum K2V3_TYPE type;
	char *scalar_val;
	size_t array_len;
	char **array_val;
	bool empty;
	size_t jmp;
};
static struct K2V3_KEY get_key(struct K2V3_STRING conf)
{
	struct K2V3_KEY ret = { .key = NULL, .jmp = 0 };
	// Key should be a non-empty string without spaces, and end with `=`.
	// Only 0-9, a-z, A-Z and `_` are allowed in keys.
	size_t i = 0;
	while (i < conf.len && conf.str[i] != '=' && conf.str[i] != '\n') {
		if (conf.str[i] == ' ') {
			k2v3_warning("Spaces are not allowed in keys.");
			ret.key = NULL;
			ret.jmp = 0;
			return ret;
		}
		if (!((conf.str[i] >= '0' && conf.str[i] <= '9') || (conf.str[i] >= 'a' && conf.str[i] <= 'z') || (conf.str[i] >= 'A' && conf.str[i] <= 'Z') || conf.str[i] == '_')) {
			k2v3_warning("Invalid character in key, got '%c'. Only 0-9, a-z, A-Z and '_' are allowed.", conf.str[i]);
			ret.key = NULL;
			return ret;
		}
		i++;
	}
	if (i == 0) {
		k2v3_warning("Key cannot be empty.");
		ret.key = NULL;
		ret.jmp = 0;
		return ret;
	}
	// Dump key.
	ret.key = strndup(conf.str, i);
	if (!ret.key) {
		k2v3_error("Failed to allocate memory for key. This is an internal error.");
	}
	// Get jump length.
	if (i < conf.len && conf.str[i] == '=') {
		ret.jmp = i + 1;
	} else {
		k2v3_warning("Key must end with '='");
		free(ret.key);
		ret.key = NULL;
		ret.jmp = 0;
		return ret;
	}
	return ret;
}
static struct K2V3_VALUE get_value(struct K2V3_STRING conf)
{
	struct K2V3_VALUE ret = { .type = K2V3_SCALAR, .scalar_val = NULL, .array_val = NULL, .jmp = 0, .empty = false };
	// Value can be a scalar or an array.
	// Value should start with `"` for scalar and `[` for array.
	if (conf.len == 0) {
		k2v3_error("Internal error: conf is empty. This should not happen because we check it before.");
	}
	bool priv_backslash = false;
	// We allow `[]` for null array, `""` for null scalar.
	if (conf.len >= 2) {
		if (conf.str[0] == '"' && conf.str[1] == '"') {
			ret.type = K2V3_SCALAR;
			ret.scalar_val = NULL;
			ret.jmp = 2;
			ret.empty = true;
			goto end;
		}
		if (conf.str[0] == '[') {
			// skip spaces after `[`.
			size_t spaces = 0;
			while (spaces + 1 < conf.len && (conf.str[spaces + 1] == ' ' || conf.str[spaces + 1] == '\n')) {
				spaces++;
			}
			if (spaces + 1 < conf.len && conf.str[spaces + 1] == ']') {
				ret.type = K2V3_ARRAY;
				ret.array_len = 0;
				ret.array_val = NULL;
				ret.jmp = spaces + 2;
				ret.empty = true;
				goto end;
			}
		}
	}
	// Parse value.
	if (conf.str[0] == '"') {
		ret.type = K2V3_SCALAR;
		// Scalar value. Get the string until the next unescaped `"` character.
		// Boundary is next "\n" or end of string.
		size_t boundary = conf.len;
		char *newline = memchr(conf.str, '\n', conf.len);
		if (newline) {
			boundary = (size_t)(newline - conf.str);
		}
		size_t i = 1;
		while (i < conf.len) {
			if (priv_backslash) {
				priv_backslash = false;
			} else if (conf.str[i] == '\\') {
				priv_backslash = true;
			} else if (conf.str[i] == '"') {
				break;
			}
			if (i >= boundary) {
				k2v3_warning("Unterminated scalar value.");
				ret.type = K2V3_SCALAR;
				free(ret.scalar_val);
				ret.scalar_val = NULL;
				ret.empty = true;
				// Goto next line or end of string.
				char *newline = memchr(conf.str, '\n', conf.len);
				if (newline) {
					ret.jmp = (size_t)(newline - conf.str) + 1;
				} else {
					ret.jmp = conf.len;
				}
				return ret;
			}
			i++;
		}
		// Dump scalar value.
		if (i >= conf.len) {
			k2v3_warning("Unterminated scalar value.");
			ret.type = K2V3_SCALAR;
			ret.empty = true;
			// Goto next line or end of string.
			char *newline = memchr(conf.str, '\n', conf.len);
			if (newline) {
				ret.jmp = (size_t)(newline - conf.str) + 1;
			} else {
				ret.jmp = conf.len;
			}
			return ret;
		}
		ret.scalar_val = strndup(conf.str + 1, i - 1);
		if (!ret.scalar_val) {
			k2v3_error("Failed to allocate memory for scalar value. This is an internal error.");
		}
		// Get jump length.
		ret.jmp = i + 1;
	} else if (conf.str[0] == '[') {
		ret.type = K2V3_ARRAY;
		priv_backslash = false;
		// Array value.
		// Boundry is next excepted `]` character that is not escaped.
		// Newline is allowed in array values, so we do not consider newline as boundary here.
		size_t i = 1;
		while (i < conf.len) {
			if (priv_backslash) {
				priv_backslash = false;
			} else if (conf.str[i] == '\\') {
				priv_backslash = true;
			} else if (conf.str[i] == ']') {
				break;
			}
			i++;
		}
		priv_backslash = false;
		if (i >= conf.len) {
			k2v3_warning("Unterminated array value.");
			ret.type = K2V3_SCALAR;
			ret.empty = true;
			// Goto next line or end of string.
			char *newline = memchr(conf.str, '\n', conf.len);
			if (newline) {
				ret.jmp = (size_t)(newline - conf.str) + 1;
			} else {
				ret.jmp = conf.len;
			}
			return ret;
		}
		// Get array elements.
		// Each element should be a scalar value, and separated by `,` or `;`.
		// We also do not allow empty elements.
		size_t array_len = 0;
		char **array_val = NULL;
		size_t j = 1;
		while (j < i) {
			// Skip spaces before the element.
			while (j < i && (conf.str[j] == ' ' || conf.str[j] == '\n')) {
				j++;
			}
			// First is `"`.
			if (conf.str[j] != '"') {
				k2v3_warning("Array elements must start with '\"'.");
				for (size_t i = 0; i < array_len; i++) {
					free(array_val[i]);
				}
				free((void *)array_val);
				ret.type = K2V3_SCALAR;
				ret.empty = true;
				// Goto next line or end of string.
				char *newline = memchr(conf.str, '\n', conf.len);
				if (newline) {
					ret.jmp = (size_t)(newline - conf.str) + 1;
				} else {
					ret.jmp = conf.len;
				}
				return ret;
			}
			// Get the string until the next unescaped `"` character.
			// If there is no next unescaped `"` character before the boundary, it's an error.
			// Get the next unescaped `"` character.
			size_t k = j + 1;
			while (k < i) {
				if (priv_backslash) {
					priv_backslash = false;
				} else if (conf.str[k] == '\\') {
					priv_backslash = true;
				} else if (conf.str[k] == '"') {
					break;
				}
				if (k >= i - 1) {
					k2v3_warning("Unterminated array element.");
					for (size_t i = 0; i < array_len; i++) {
						free(array_val[i]);
					}
					free((void *)array_val);
					ret.type = K2V3_SCALAR;
					ret.empty = true;
					// Goto next line or end of string.
					char *newline = memchr(conf.str, '\n', conf.len);
					if (newline) {
						ret.jmp = (size_t)(newline - conf.str) + 1;
					} else {
						ret.jmp = conf.len;
					}
					return ret;
				}
				k++;
			}
			priv_backslash = false;
			// Do not allow null elements, so k-j-1 should >0.
			if (k - j - 1 <= 0) {
				k2v3_warning("NULL element in array is not allowed");
				for (size_t i = 0; i < array_len; i++) {
					free(array_val[i]);
				}
				free((void *)array_val);
				ret.type = K2V3_SCALAR;
				ret.empty = true;
				// Goto next line or end of string.
				char *newline = memchr(conf.str, '\n', conf.len);
				if (newline) {
					ret.jmp = (size_t)(newline - conf.str) + 1;
				} else {
					ret.jmp = conf.len;
				}
				return ret;
			}
			// Dump array element.
			char *element = strndup(conf.str + j + 1, k - j - 1);
			if (!element) {
				k2v3_warning("Failed to allocate memory for array element.");
				ret.type = K2V3_SCALAR;
				ret.empty = true;
				// Goto next line or end of string.
				char *newline = memchr(conf.str, '\n', conf.len);
				if (newline) {
					ret.jmp = (size_t)(newline - conf.str) + 1;
				} else {
					ret.jmp = conf.len;
				}
				return ret;
			}
			// Add to array.
			char **new_array_val = (char **)realloc((void *)array_val, sizeof(char *) * (array_len + 1));
			if (!new_array_val) {
				free(element);
				k2v3_error("Failed to allocate memory for array. This is an internal error.");
			}
			array_val = new_array_val;
			array_val[array_len] = element;
			array_len++;
			// Move to the next element.
			j = k + 1;
			// Skip spaces after the element.
			while (j < i && (conf.str[j] == ' ' || conf.str[j] == '\n')) {
				j++;
			}
			// Skip separators.
			if (conf.str[j] == ',' || conf.str[j] == ';') {
				j++;
				// Do not allow separators at the end of array.
				while (j < i && (conf.str[j] == ' ' || conf.str[j] == '\n')) {
					j++;
				}
				if (j == i) {
					k2v3_warning("Trailing separator in array is not allowed.");
					ret.type = K2V3_SCALAR;
					ret.empty = true;
					for (size_t i = 0; i < array_len; i++) {
						free(array_val[i]);
					}
					free((void *)array_val);
					// Goto next line or end of string.
					ret.jmp = i + 1;
					goto end;
				}
			} else {
				// If there is no separator, it should be the end of array.
				if (j < i) {
					k2v3_warning("Array elements must be separated by ',' or ';'.");
					ret.type = K2V3_SCALAR;
					ret.empty = true;
					for (size_t i = 0; i < array_len; i++) {
						free(array_val[i]);
					}
					free((void *)array_val);
					// Goto next line or end of string.
					char *newline = memchr(conf.str, '\n', conf.len);
					if (newline) {
						ret.jmp = (size_t)(newline - conf.str) + 1;
					} else {
						ret.jmp = conf.len;
					}
					return ret;
				}
			}
		}
		ret.array_len = array_len;
		ret.array_val = array_val;
		// Get jump length.
		ret.jmp = i + 1;
	} else {
		k2v3_warning("Value must start with '\"' for scalar or '[' for array.");
		ret.type = K2V3_SCALAR;
		free(ret.scalar_val);
		ret.scalar_val = NULL;
		ret.empty = true;
		// Goto next line or end of string.
		char *newline = memchr(conf.str, '\n', conf.len);
		if (newline) {
			ret.jmp = (size_t)(newline - conf.str) + 1;
		} else {
			ret.jmp = conf.len;
		}
		return ret;
	}
end:
	// Skip spaces after value.
	while (ret.jmp < conf.len && (conf.str[ret.jmp] == ' ')) {
		ret.jmp++;
	}
	// If we got `#`, skip until newline or end of string, because it's a comment.
	if (ret.jmp < conf.len && conf.str[ret.jmp] == '#') {
		char *newline = memchr(conf.str, '\n', conf.len);
		if (newline) {
			ret.jmp = (size_t)(newline - conf.str);
		} else {
			ret.jmp = conf.len;
		}
	}
	// Ensure the value is followed by a newline or end of string.
	if (ret.jmp < conf.len && conf.str[ret.jmp] != '\n') {
		k2v3_warning("Value must be followed by a newline, but got '%c'.", conf.str[ret.jmp]);
		if (ret.type == K2V3_ARRAY) {
			for (size_t i = 0; i < ret.array_len; i++) {
				free(ret.array_val[i]);
			}
			free((void *)ret.array_val);
		} else {
			free((void *)ret.scalar_val);
		}
		ret.type = K2V3_SCALAR;
		ret.empty = true;
		// Goto next line or end of string.
		char *newline = memchr(conf.str, '\n', conf.len);
		if (newline) {
			ret.jmp = (size_t)(newline - conf.str) + 1;
		} else {
			ret.jmp = conf.len;
		}
		return ret;
	}
	return ret;
}
k2v3_cache k2v3_parse(char *const _Nonnull buf)
{
	k2v3_cache ret = NULL;
	if (setjmp(k2v3_jmp) != 0) {
		// Free cache before returning NULL.
		k2v3_free_cache(&ret);
		return NULL;
	}
	struct K2V3_STRING conf = { .str = buf, .len = strlen(buf) };
	while (conf.len > 0) {
		// We do not allow leading spaces.
		if (conf.str[0] == ' ') {
			k2v3_warning("Leading spaces are not allowed.");
			// Goto next line.
			char *newline = memchr(conf.str, '\n', conf.len);
			if (!newline) {
				break;
			}
			conf.str = newline + 1;
			conf.len = strlen(conf.str);
			continue;
		}
		// Skip comments and empty lines.
		if (conf.str[0] == '\n') {
			conf.str++;
			conf.len--;
			continue;
		}
		if (conf.str[0] == '#') {
			char *newline = memchr(conf.str, '\n', conf.len);
			if (!newline) {
				break;
			}
			conf.str = newline + 1;
			conf.len = strlen(conf.str);
			continue;
		}
		// Get key.
		struct K2V3_KEY key = get_key(conf);
		if (!key.key) {
			k2v3_warning("Failed to parse key.");
			// Goto next line.
			char *newline = memchr(conf.str, '\n', conf.len);
			if (!newline) {
				break;
			}
			conf.str = newline + 1;
			conf.len = strlen(conf.str);
			continue;
		}
		conf.str += key.jmp;
		conf.len -= key.jmp;
		if (conf.len == 0) {
			free(key.key);
			return ret;
		}
		// Get value.
		struct K2V3_VALUE value = get_value(conf);
		if (!value.scalar_val && !value.array_val && !value.empty) {
			printf("Debug info: conf.str:\n%s\n", conf.str);
			k2v3_error("Failed to parse value. This is an internal error.");
		}
		conf.str += value.jmp;
		conf.len -= value.jmp;
		// Add to cache.
		k2v3_cache node = malloc(sizeof(struct K2V3_BUF));
		if (!node) {
			k2v3_error("Failed to allocate cache node. This is an internal error.");
		}
		*node = (struct K2V3_BUF){ .type = value.type, .key = key.key, .next = NULL };
		if (value.empty) {
			node->empty = true;
		} else {
			node->empty = false;
			if (value.type == K2V3_ARRAY) {
				node->array_len = value.array_len;
				node->array_val = value.array_val;
			} else {
				node->scalar_val = value.scalar_val;
			}
		}
		// Append to the cache.
		if (ret == NULL) {
			ret = node;
		} else {
			k2v3_cache cur = ret;
			while (cur->next != NULL) {
				// Also check for duplicate keys.
				if (strcmp(cur->key, key.key) == 0) {
					k2v3_warning("Duplicate keys are not allowed.");
					if (node->type == K2V3_ARRAY) {
						for (size_t i = 0; i < node->array_len; i++) {
							free(node->array_val[i]);
						}
						free((void *)node->array_val);
					} else {
						free((void *)node->scalar_val);
					}
					free(node);
					free(key.key);
					node = NULL;
					break;
				}
				cur = cur->next;
			}
			if (node) {
				if (strcmp(cur->key, key.key) == 0) {
					k2v3_warning("Duplicate keys are not allowed.");
					if (node->type == K2V3_ARRAY) {
						for (size_t i = 0; i < node->array_len; i++) {
							free(node->array_val[i]);
						}
						free((void *)node->array_val);
					} else {
						free((void *)node->scalar_val);
					}
					free(node);
					free(key.key);
					node = NULL;
				}
				cur->next = node;
			}
		}
	}
	// Correct backslash in value.
	k2v3_cache tmp = ret;
	while (tmp != NULL) {
		if (tmp->empty) {
			tmp = tmp->next;
			continue;
		}
		if (tmp->type == K2V3_ARRAY) {
			for (size_t i = 0; i < tmp->array_len; i++) {
				tmp->array_val[i] = correct_backslash(tmp->array_val[i]);
			}
		} else {
			tmp->scalar_val = correct_backslash(tmp->scalar_val);
		}
		tmp = tmp->next;
	}
	return ret;
}
void k2v3_free_cache(k2v3_cache *cache)
{
	if (cache == NULL || *cache == NULL) {
		return;
	}
	k2v3_cache cur = *cache;
	while (cur != NULL) {
		k2v3_cache next = cur->next;
		if (cur->type == K2V3_ARRAY) {
			for (size_t i = 0; i < cur->array_len; i++) {
				free(cur->array_val[i]);
			}
			free((void *)cur->array_val);
		} else {
			free(cur->scalar_val);
		}
		free(cur->key);
		free(cur);
		cur = next;
	}
	*cache = NULL;
}
void k2v3_dump(k2v3_cache cache)
{
	while (cache != NULL) {
		if (cache->empty) {
			printf("%s: %s\n", cache->key, cache->type == K2V3_ARRAY ? "[]" : "\"\"");
			cache = cache->next;
			continue;
		}
		if (cache->type == K2V3_ARRAY) {
			printf("%s: [", cache->key);
			for (size_t i = 0; i < cache->array_len; i++) {
				printf("\"%s\"", cache->array_val[i]);
				if (i < cache->array_len - 1) {
					printf(", ");
				}
			}
			printf("]\n");
		} else {
			printf("%s: %s\n", cache->key, cache->scalar_val);
		}
		cache = cache->next;
	}
}
static char *k2v3_open_file_fallback(const char *_Nonnull path, off_t limit)
{
	if (!path) {
		return NULL;
	}
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		return NULL;
	}
	struct stat st;
	if (fstat(fd, &st) < 0) {
		close(fd);
		return NULL;
	}
	if (st.st_size == 0) {
		close(fd);
		return NULL;
	}
	if (st.st_size > limit) {
		close(fd);
		k2v3_warning("File size exceeds the specified limit. This file will be ignored.");
		return NULL;
	}
	char *buf = malloc((size_t)st.st_size + 1);
	if (!buf) {
		close(fd);
		return NULL;
	}
	ssize_t read_size = read(fd, buf, (size_t)st.st_size);
	if (read_size < 0) {
		free(buf);
		close(fd);
		return NULL;
	}
	buf[read_size] = '\0';
	if (strlen(buf) != (size_t)read_size) {
		k2v3_warning("File size changed during read. This file will be ignored.");
		free(buf);
		close(fd);
		return NULL;
	}
	close(fd);
	return buf;
}
char *k2v3_open_file(const char *_Nonnull path, off_t limit)
{
	// Try O_DIRECT first, if it fails, fallback to normal read.
	// Maybe can mitigate page cache based attacks, but not guaranteed.
	int fd = open(path, O_RDONLY | O_CLOEXEC | O_DIRECT);
	if (fd < 0) {
		return k2v3_open_file_fallback(path, limit);
	}
	void *buf = NULL;
	// 4k alignment for O_DIRECT.
	// Get file size.
	struct stat st;
	if (fstat(fd, &st) < 0) {
		close(fd);
		return k2v3_open_file_fallback(path, limit);
	}
	if (st.st_size == 0) {
		close(fd);
		return NULL;
	}
	if (st.st_size > limit) {
		close(fd);
		k2v3_warning("File size exceeds the specified limit. This file will be ignored.");
		return NULL;
	}
	size_t read_size = (size_t)st.st_size;
	size_t aligned_size = read_size / 4096 * 4096 + 4096; // Round up to the next multiple of 4096
	if (posix_memalign(&buf, 4096, aligned_size) != 0) {
		close(fd);
		return k2v3_open_file_fallback(path, limit);
	}
	ssize_t ret = read(fd, buf, aligned_size);
	if (ret < 0) {
		free(buf);
		close(fd);
		return k2v3_open_file_fallback(path, limit);
	}
	((char *)buf)[read_size] = '\0';
	if (strlen(buf) != (size_t)read_size) {
		k2v3_warning("File size changed during read. This file will be ignored.");
		free(buf);
		close(fd);
		return NULL;
	}
	close(fd);
	return (char *)buf;
}
int k2v3_have_key(k2v3_cache cache, const char *const _Nonnull key, enum K2V3_TYPE type)
{
	/*
	 * 0 for key exists with the expected type.
	 * 1 for key exists but with different type.
	 * -1 for key does not exist.
	 */
	if (type == K2V3_ANY) {
		while (cache != NULL) {
			if (strcmp(cache->key, key) == 0) {
				return 0;
			}
			cache = cache->next;
		}
		return -1;
	}
	while (cache != NULL) {
		if (strcmp(cache->key, key) == 0 && cache->type == type) {
			return 0;
		}
		if (strcmp(cache->key, key) == 0 && cache->type != type) {
			return 1;
		}
		cache = cache->next;
	}

	return -1;
}

//
//
// Get values.
//
//
static k2v3_cache get_key_cache(const char *_Nonnull key, enum K2V3_TYPE type, k2v3_cache cache)
{
	while (cache != NULL) {
		if (strcmp(cache->key, key) == 0) {
			if (cache->type != type) {
				k2v3_warning("Key '%s' exists but with different type. Expected %s but got %s.", key, type == K2V3_ARRAY ? "array" : "scalar", cache->type == K2V3_ARRAY ? "array" : "scalar");
				return NULL;
			}
			return cache;
		}
		cache = cache->next;
	}
	return NULL;
}
char *k2v3_get_char(const char *_Nonnull key, k2v3_cache cache)
{
	k2v3_cache node = get_key_cache(key, K2V3_SCALAR, cache);
	if (node == NULL) {
		k2v3_warning("Key '%s' not found.", key);
		return NULL;
	}
	if (node->empty) {
		return NULL;
	}
	return strdup(node->scalar_val);
}
int k2v3_get_int(const char *_Nonnull key, k2v3_cache cache)
{
	k2v3_cache node = get_key_cache(key, K2V3_SCALAR, cache);
	if (node == NULL) {
		k2v3_warning("Key '%s' not found.", key);
		return 0;
	}
	if (node->empty) {
		return 0;
	}
	char *endptr = NULL;
	long ret = strtol(node->scalar_val, &endptr, 10);
	if (*endptr != '\0') {
		return 0;
	}
	if (ret > INT_MAX || ret < INT_MIN) {
		k2v3_warning("Value for key '%s' is too large for int.", key);
		return 0;
	}
	return (int)ret;
}
float k2v3_get_float(const char *_Nonnull key, k2v3_cache cache)
{
	k2v3_cache node = get_key_cache(key, K2V3_SCALAR, cache);
	if (node == NULL) {
		k2v3_warning("Key '%s' not found.", key);
		return 0;
	}
	if (node->empty) {
		return 0;
	}
	char *endptr = NULL;
	float val = strtof(node->scalar_val, &endptr);
	if (*endptr != '\0') {
		k2v3_warning("Value for key '%s' is not a valid float.", key);
		return 0;
	}
	return val;
}
bool k2v3_get_bool(const char *_Nonnull key, k2v3_cache cache)
{
	k2v3_cache node = get_key_cache(key, K2V3_SCALAR, cache);
	if (node == NULL) {
		k2v3_warning("Key '%s' not found.", key);
		return false;
	}
	if (node->empty) {
		k2v3_warning("Key '%s' is empty.", key);
		return false;
	}
	if (strcmp(node->scalar_val, "true") == 0) {
		return true;
	}
	if (strcmp(node->scalar_val, "false") == 0) {
		return false;
	}
	k2v3_warning("Value for key '%s' is not a valid boolean. Expected 'true' or 'false' but got '%s'.", key, node->scalar_val);
	return false;
}
long long k2v3_get_long(const char *_Nonnull key, k2v3_cache cache)
{
	k2v3_cache node = get_key_cache(key, K2V3_SCALAR, cache);
	if (node == NULL) {
		k2v3_warning("Key '%s' not found.", key);
		return 0;
	}
	if (node->empty) {
		return 0;
	}
	char *endptr = NULL;
	long long ret = strtoll(node->scalar_val, &endptr, 10);
	if (*endptr != '\0') {
		k2v3_warning("Value for key '%s' is not a valid long integer.", key);
		return 0;
	}
	return ret;
}
int k2v3_get_int_array(const char *_Nonnull key, k2v3_cache cache, int *_Nonnull array, int limit)
{
	k2v3_cache node = get_key_cache(key, K2V3_ARRAY, cache);
	if (node == NULL) {
		k2v3_warning("Key '%s' not found.", key);
		return 0;
	}
	if (node->empty) {
		return 0;
	}
	if (node->array_len > (size_t)limit) {
		k2v3_warning("Array length for key '%s' exceeds the limit of %d.", key, limit);
		return 0;
	}
	int count = 0;
	for (size_t i = 0; i < node->array_len; i++) {
		char *endptr = NULL;
		long val = strtol(node->array_val[i], &endptr, 10);
		if (*endptr != '\0') {
			k2v3_warning("Value '%s' in array for key '%s' is not a valid integer.", node->array_val[i], key);
			val = 0;
		}
		if (val > INT_MAX || val < INT_MIN) {
			k2v3_warning("Value '%s' in array for key '%s' is too large for int.", node->array_val[i], key);
			val = 0;
		}
		array[count++] = (int)val;
	}
	return count;
}
int k2v3_get_char_array(const char *_Nonnull key, k2v3_cache cache, char *_Nonnull array[], int limit)
{
	k2v3_cache node = get_key_cache(key, K2V3_ARRAY, cache);
	if (node == NULL) {
		k2v3_warning("Key '%s' not found.", key);
		return 0;
	}
	if (node->empty) {
		return 0;
	}
	if (node->array_len > (size_t)limit) {
		k2v3_warning("Array length for key '%s' exceeds the limit of %d.", key, limit);
		return 0;
	}
	int count = 0;
	for (size_t i = 0; i < node->array_len; i++) {
		array[count++] = strdup(node->array_val[i]);
	}
	return count;
}
int k2v3_get_float_array(const char *_Nonnull key, k2v3_cache cache, float *_Nonnull array, int limit)
{
	k2v3_cache node = get_key_cache(key, K2V3_ARRAY, cache);
	if (node == NULL) {
		k2v3_warning("Key '%s' not found.", key);
		return 0;
	}
	if (node->empty) {
		return 0;
	}
	if (node->array_len > (size_t)limit) {
		k2v3_warning("Array length for key '%s' exceeds the limit of %d.", key, limit);
		return 0;
	}
	int count = 0;
	for (size_t i = 0; i < node->array_len; i++) {
		char *endptr = NULL;
		float val = strtof(node->array_val[i], &endptr);
		if (*endptr != '\0') {
			k2v3_warning("Value '%s' in array for key '%s' is not a valid float.", node->array_val[i], key);
			val = 0;
		}
		array[count++] = val;
	}
	return count;
}
int k2v3_get_long_array(const char *_Nonnull key, k2v3_cache cache, long long *_Nonnull array, int limit)
{
	k2v3_cache node = get_key_cache(key, K2V3_ARRAY, cache);
	if (node == NULL) {
		k2v3_warning("Key '%s' not found.", key);
		return 0;
	}
	if (node->empty) {
		return 0;
	}
	if (node->array_len > (size_t)limit) {
		k2v3_warning("Array length for key '%s' exceeds the limit of %d.", key, limit);
		return 0;
	}
	int count = 0;
	for (size_t i = 0; i < node->array_len; i++) {
		char *endptr = NULL;
		long long val = strtoll(node->array_val[i], &endptr, 10);
		if (*endptr != '\0') {
			k2v3_warning("Value '%s' in array for key '%s' is not a valid long integer.", node->array_val[i], key);
			val = 0;
		}
		array[count++] = val;
	}
	return count;
}

//
//
// Generation functions.
//
//

char *k2v3_add_comment(char *_Nonnull buf, char *_Nonnull comment)
{
	size_t buf_len = (buf != NULL) ? strlen(buf) : 0;
	size_t comment_len = strlen(comment);
	size_t total_size = buf_len + comment_len + 5; // "# " + "\n" + '\0'

	char *ret = malloc(total_size);
	if (!ret) {
		return NULL;
	}

	if (buf != NULL) {
		snprintf(ret, total_size, "%s# %s\n", buf, comment);
	} else {
		snprintf(ret, total_size, "# %s\n", comment);
	}
	free(buf);
	return ret;
}
char *k2v3_add_newline(char *_Nonnull buf)
{
	size_t buf_len = (buf != NULL) ? strlen(buf) : 0;
	size_t total_size = buf_len + 2; // "\n" + '\0'

	char *ret = malloc(total_size);
	if (!ret) {
		return NULL;
	}

	if (buf != NULL) {
		snprintf(ret, total_size, "%s\n", buf);
	} else {
		snprintf(ret, total_size, "\n");
	}
	free(buf);
	return ret;
}
char *k2v3_add_config_func(char *_Nullable buf, char *_Nonnull tmp)
{
	size_t size = 4;
	if (buf != NULL) {
		size += strlen(buf);
	}
	size += strlen(tmp) + 4;
	char *ret = malloc(size);
	if (buf != NULL) {
		sprintf(ret, "%s%s", buf, tmp);
	} else {
		sprintf(ret, "%s", tmp);
	}
	free(buf);
	free(tmp);
	return ret;
}
char *char_to_k2v3(const char *_Nonnull key, const char *_Nonnull val)
{
	if (key == NULL) {
		return NULL;
	}
	size_t key_len = strlen(key);
	size_t val_len = val ? strlen(val) : 0;
	size_t total_size = key_len + val_len + 5; // ="\"\n\0"

	char *ret = malloc(total_size);
	if (!ret) {
		return NULL;
	}

	if (val != NULL) {
		snprintf(ret, total_size, "%s=\"%s\"\n", key, val);
	} else {
		snprintf(ret, total_size, "%s=\"\"\n", key);
	}
	return ret;
}
char *int_to_k2v3(const char *_Nonnull key, int val)
{
	if (key == NULL) {
		return NULL;
	}
	size_t max_len = strlen(key) + 32; // Safe upper bound for integer
	char *ret = malloc(max_len);
	if (ret) {
		snprintf(ret, max_len, "%s=\"%d\"\n", key, val);
	}
	return ret;
}
char *long_to_k2v3(const char *_Nonnull key, long long val)
{
	if (key == NULL) {
		return NULL;
	}
	size_t max_len = strlen(key) + 64; // Safe upper bound for long
	char *ret = malloc(max_len);
	if (ret) {
		snprintf(ret, max_len, "%s=\"%lld\"\n", key, val);
	}
	return ret;
}
char *bool_to_k2v3(const char *_Nonnull key, bool val)
{
	// NULL check.
	if (key == NULL) {
		return NULL;
	}
	char *ret = malloc(strlen(key) + 8 + 8);
	sprintf(ret, "%s=\"%s\"\n", key, val ? "true" : "false");
	return ret;
}
char *float_to_k2v3(const char *_Nonnull key, float val)
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
char *char_array_to_k2v3(const char *_Nonnull key, char *const *_Nonnull val, int len)
{
	if (key == NULL) {
		return NULL;
	}

	if (len == 0 || val == NULL) {
		size_t size = strlen(key) + 5; // =[]\n\0
		char *ret = malloc(size);
		if (ret) {
			snprintf(ret, size, "%s=[]\n", key);
		}
		return ret;
	}

	size_t total_size = strlen(key) + 5; // key + =[\n + \0
	for (int i = 0; i < len; i++) {
		total_size += strlen(val[i]) + 2; // ""
		if (i != len - 1) {
			total_size += 1; // ,
		}
	}

	char *buf = malloc(total_size);
	if (!buf) {
		return NULL;
	}

	char *ptr = buf;
	ptr += sprintf(ptr, "%s=[", key);

	for (int i = 0; i < len; i++) {
		ptr += sprintf(ptr, "\"%s\"", val[i]);
		if (i != len - 1) {
			*ptr++ = ',';
		}
	}

	*ptr++ = ']';
	*ptr++ = '\n';
	*ptr = '\0';

	return buf;
}
char *int_array_to_k2v3(const char *_Nonnull key, int *_Nonnull val, int len)
{
	if (key == NULL) {
		return NULL;
	}
	if (len == 0 || val == NULL) {
		size_t size = strlen(key) + 5;
		char *ret = malloc(size);
		if (ret) {
			snprintf(ret, size, "%s=[]\n", key);
		}
		return ret;
	}

	size_t max_size = strlen(key) + ((size_t)len * 32) + 5; // 32 per int + padding
	char *buf = malloc(max_size);
	if (!buf) {
		return NULL;
	}

	char *ptr = buf;
	ptr += sprintf(ptr, "%s=[", key);

	for (int i = 0; i < len; i++) {
		ptr += sprintf(ptr, "\"%d\"", val[i]);
		if (i != len - 1) {
			*ptr++ = ',';
		}
	}

	*ptr++ = ']';
	*ptr++ = '\n';
	*ptr = '\0';

	return buf;
}
char *float_array_to_k2v3(const char *_Nonnull key, float *_Nonnull val, int len)
{
	if (key == NULL) {
		return NULL;
	}
	if (len == 0 || val == NULL) {
		size_t size = strlen(key) + 5;
		char *ret = malloc(size);
		if (ret) {
			snprintf(ret, size, "%s=[]\n", key);
		}
		return ret;
	}

	size_t max_size = strlen(key) + ((size_t)len * 64) + 5; // 64 per float + padding
	char *buf = malloc(max_size);
	if (!buf) {
		return NULL;
	}

	char *ptr = buf;
	ptr += sprintf(ptr, "%s=[", key);

	for (int i = 0; i < len; i++) {
		ptr += sprintf(ptr, "\"%f\"", (double)val[i]);
		if (i != len - 1) {
			*ptr++ = ',';
		}
	}

	*ptr++ = ']';
	*ptr++ = '\n';
	*ptr = '\0';

	return buf;
}
char *long_array_to_k2v3(const char *_Nonnull key, long long *_Nonnull val, int len)
{
	if (key == NULL) {
		return NULL;
	}
	if (len == 0 || val == NULL) {
		size_t size = strlen(key) + 5;
		char *ret = malloc(size);
		if (ret) {
			snprintf(ret, size, "%s=[]\n", key);
		}
		return ret;
	}

	size_t max_size = strlen(key) + ((size_t)len * 64) + 5; // 64 per long + padding
	char *buf = malloc(max_size);
	if (!buf) {
		return NULL;
	}

	char *ptr = buf;
	ptr += sprintf(ptr, "%s=[", key);

	for (int i = 0; i < len; i++) {
		ptr += sprintf(ptr, "\"%lld\"", val[i]);
		if (i != len - 1) {
			*ptr++ = ',';
		}
	}

	*ptr++ = ']';
	*ptr++ = '\n';
	*ptr = '\0';

	return buf;
}