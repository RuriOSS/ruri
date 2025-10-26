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
 * Since we cannot statically link getpwuid() in glibc,
 * we need to implement it.
 * This file provides functions to parse /etc/passwd,
 * and it can also parse /etc/subuid and /etc/subgid.
 *
 * TODO:
 * As I don't think these code is safe enough,
 * I will rewrite them in the future.
 *
 */
int RURI_PWD_ERRNO = 0;
static int RURI_PWD_ERRNO_INTERNAL = 0;
static char *line_get_username(const char *_Nonnull p)
{
	/*
	 * Get username by line.
	 * free() after use.
	 */
	char *ret = malloc(LOGIN_NAME_MAX * 4);
	ret[0] = '\0';
	// /etc/passwd format:
	// name:password:uid:gid:comment:home directory:login shell
	// So we only need the string before the first colon.
	// Check if there is a colon.
	if ((strchr(p, ':') == NULL) || (strchr(p, ':') > (strchr(p, '\n') == NULL ? 0 : strchr(p, '\n')))) {
		return ret;
	}
	// Read the username until we meet the first colon.
	for (int i = 0; p[i] != '\0' && i < (LOGIN_NAME_MAX * 2); i++) {
		if (p[i] == ':') {
			break;
		}
		ret[i] = p[i];
		ret[i + 1] = '\0';
	}
	return ret;
}
static uid_t line_get_uid(const char *_Nonnull p)
{
	/*
	 * Get uid by line.
	 */
	uid_t ret = 0;
	const char *bound = p + strlen(p);
	// /etc/passwd format:
	// name:password:uid:gid:comment:home directory:login shell
	// So we need to skip 2 colons.
	for (int i = 0; i < 2; i++) {
		if ((strchr(p, ':') == NULL) || (strchr(p, ':') > (strchr(p, '\n') == NULL ? 0 : strchr(p, '\n')))) {
			return 0;
		}
		p = strchr(p, ':') + 1;
	}
	// Check for bound.
	if (p >= bound) {
		return 0;
	}
	// Check if there is still a colon.
	if ((strchr(p, ':') == NULL) || (strchr(p, ':') > (strchr(p, '\n') == NULL ? 0 : strchr(p, '\n')))) {
		return 0;
	}
	// Now, after we skip 2 colons, we can get the uid.
	// Read the uid until we meet the next colon.
	for (int i = 0; p[i] != '\0'; i++) {
		if (p[i] == ':') {
			return ret;
		}
		ret = ret * 10 + (uid_t)(p[i] - '0');
	}
	return 0;
}
static gid_t line_get_gid(const char *_Nonnull p)
{
	/*
	 * Get gid by line.
	 */
	uid_t ret = 0;
	const char *bound = p + strlen(p);
	// /etc/passwd format:
	// name:password:uid:gid:comment:home directory:login shell
	// So we need to skip 3 colons.
	for (int i = 0; i < 3; i++) {
		if ((strchr(p, ':') == NULL) || (strchr(p, ':') > (strchr(p, '\n') == NULL ? 0 : strchr(p, '\n')))) {
			return 0;
		}
		p = strchr(p, ':') + 1;
	}
	// Check for bound.
	if (p >= bound) {
		return 0;
	}
	// Check if there is still a colon.
	if ((strchr(p, ':') == NULL) || (strchr(p, ':') > (strchr(p, '\n') == NULL ? 0 : strchr(p, '\n')))) {
		return 0;
	}
	// Now, after we skip 3 colons, we can get the gid.
	// Read the uid until we meet the next colon.
	for (int i = 0; p[i] != '\0'; i++) {
		if (p[i] == ':') {
			return ret;
		}
		ret = ret * 10 + (uid_t)(p[i] - '0');
	}
	return 0;
}
static char *get_username(uid_t uid)
{
	/*
	 * Get username by uid.
	 */
	int fd = open("/etc/passwd", O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		return NULL;
	}
	struct stat filestat;
	fstat(fd, &filestat);
	off_t size = filestat.st_size;
	if (size >= 65536) {
		// If the file is too large, just error.
		close(fd);
		ruri_error("{red}The /etc/passwd file is too large, please check it.\n");
	}
	char *buf = malloc((size_t)size + 1);
	read(fd, buf, (size_t)size);
	buf[size] = '\0';
	close(fd);
	if (strlen(buf) != (size_t)size) {
		free(buf);
		return NULL;
	}
	char *p = buf;
	const char *bound = p + strlen(p);
	uid_t tmpuid = 0;
	char *tmpusername = NULL;
	// Every time, we get the username and uid by line.
	// If the uid is equal to the uid we want, we return the username.
	while (true) {
		tmpusername = line_get_username(p);
		tmpuid = line_get_uid(p);
		if (tmpuid == uid) {
			free(buf);
			return tmpusername;
		}
		free(tmpusername);
		p = strchr(p, '\n');
		if (p == NULL) {
			break;
		}
		p = p + 1;
		if (p >= bound) {
			break;
		}
	}
	free(buf);
	return NULL;
}
static uid_t line_get_uid_lower(const char *_Nonnull p)
{
	/*
	 * Get uid_lower by line.
	 */
	uid_t ret = 0;
	const char *bound = p + strlen(p);
	// /etc/subuid format:
	//   foo:uid_lower:uid_count
	// So we need to skip a colon.
	if ((strchr(p, ':') == NULL) || (strchr(p, ':') > (strchr(p, '\n') == NULL ? 0 : strchr(p, '\n')))) {
		return 0;
	}
	p = strchr(p, ':') + 1;
	// Check for bound.
	if (p >= bound) {
		return 0;
	}
	// Check if there is still a colon.
	if ((strchr(p, ':') == NULL) || (strchr(p, ':') > (strchr(p, '\n') == NULL ? 0 : strchr(p, '\n')))) {
		return 0;
	}
	// Read the uid_lower until we meet the next colon.
	for (int i = 0; p[i] != '\0'; i++) {
		if (p[i] == ':') {
			return ret;
		}
		ret = ret * 10 + (uid_t)(p[i] - '0');
	}
	return ret;
}
static uid_t line_get_uid_count(const char *_Nonnull p)
{
	/*
	 * Get uid_count by line.
	 */
	uid_t ret = 0;
	const char *bound = p + strlen(p);
	// /etc/subuid format:
	//   foo:uid_lower:uid_count
	// So we need to skip 2 colons.
	if ((strchr(p, ':') == NULL) || (strchr(p, ':') > (strchr(p, '\n') == NULL ? 0 : strchr(p, '\n')))) {
		return 0;
	}
	p = strchr(p, ':') + 1;
	// Check for bound.
	if (p >= bound) {
		return 0;
	}
	if ((strchr(p, ':') == NULL) || (strchr(p, ':') > (strchr(p, '\n') == NULL ? 0 : strchr(p, '\n')))) {
		return 0;
	}
	p = strchr(p, ':') + 1;
	// Check for bound.
	if (p >= bound) {
		return 0;
	}
	// Check if there is a '\n' (newline).
	if (strchr(p, '\n') == NULL) {
		return 0;
	}
	// Read the uid_count until we meet the newline.
	for (int i = 0; p[i] != '\0'; i++) {
		if (p[i] == '\n') {
			return ret;
		}
		ret = ret * 10 + (uid_t)(p[i] - '0');
	}
	return ret;
}
static void get_uid_map(char *_Nonnull user, struct RURI_ID_MAP *_Nonnull id_map)
{
	/*
	 * Get uid_map.
	 */
	id_map->uid_lower = 0;
	id_map->uid_count = 0;
	// Read file to memory.
	int fd = open("/etc/subuid", O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		return;
	}
	struct stat filestat;
	fstat(fd, &filestat);
	off_t size = filestat.st_size;
	if (size >= 65536) {
		// If the file is too large, just error.
		close(fd);
		ruri_error("{red}The /etc/subuid file is too large, please check it.\n");
	}
	char *buf = malloc((size_t)size + 1);
	read(fd, buf, (size_t)size);
	buf[size] = '\0';
	close(fd);
	if (strlen(buf) != (size_t)size) {
		free(buf);
		return;
	}
	// Find username in /etc/subuid.
	char *str_to_find = malloc(strlen(user) + 4);
	strcpy(str_to_find, user);
	strcat(str_to_find, ":");
	char *map = strstr(buf, str_to_find);
	free(str_to_find);
	if (map == NULL) {
		// If username is not in /etc/subuid.
		id_map->uid_lower = 0;
		id_map->uid_count = 0;
		return;
	}
	// Get uid_lower and uid_count.
	id_map->uid_lower = line_get_uid_lower(map);
	id_map->uid_count = line_get_uid_count(map);
	free(buf);
}
static gid_t line_get_gid_lower(const char *_Nonnull p)
{
	/*
	 * See comments in line_get_uid_lower().
	 */
	gid_t ret = 0;
	const char *bound = p + strlen(p);
	if ((strchr(p, ':') == NULL) || (strchr(p, ':') > (strchr(p, '\n') == NULL ? 0 : strchr(p, '\n')))) {
		return 0;
	}
	p = strchr(p, ':') + 1;
	// Check for bound.
	if (p >= bound) {
		return 0;
	}
	if ((strchr(p, ':') == NULL) || (strchr(p, ':') > (strchr(p, '\n') == NULL ? 0 : strchr(p, '\n')))) {
		return 0;
	}
	for (int i = 0; p[i] != '\0'; i++) {
		if (p[i] == ':') {
			return ret;
		}
		ret = ret * 10 + (gid_t)(p[i] - '0');
	}
	return ret;
}
static gid_t line_get_gid_count(const char *_Nonnull p)
{
	/*
	 * See comments in line_get_uid_count().
	 */
	gid_t ret = 0;
	const char *bound = p + strlen(p);
	if ((strchr(p, ':') == NULL) || (strchr(p, ':') > (strchr(p, '\n') == NULL ? 0 : strchr(p, '\n')))) {
		return 0;
	}
	p = strchr(p, ':') + 1;
	if (p >= bound) {
		return 0;
	}
	if ((strchr(p, ':') == NULL) || (strchr(p, ':') > (strchr(p, '\n') == NULL ? 0 : strchr(p, '\n')))) {
		return 0;
	}
	p = strchr(p, ':') + 1;
	if (p >= bound) {
		return 0;
	}
	if (strchr(p, '\n') == NULL) {
		return 0;
	}
	for (int i = 0; p[i] != '\0'; i++) {
		if (p[i] == '\n') {
			return ret;
		}
		ret = ret * 10 + (gid_t)(p[i] - '0');
	}
	return ret;
}
static void get_gid_map(const char *_Nonnull user, struct RURI_ID_MAP *_Nonnull id_map)
{
	/*
	 * Get gid_map.
	 */
	id_map->gid_lower = 0;
	id_map->gid_count = 0;
	// /etc/subgid format:
	//   foo:gid_lower:gid_count
	//   bar:gid_lower:gid_count
	int fd = open("/etc/subgid", O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		return;
	}
	struct stat filestat;
	fstat(fd, &filestat);
	off_t size = filestat.st_size;
	if (size >= 65536) {
		// If the file is too large, just error.
		close(fd);
		ruri_error("{red}The /etc/subgid file is too large, please check it.\n");
	}
	char *buf = malloc((size_t)size + 1);
	read(fd, buf, (size_t)size);
	buf[size] = '\0';
	close(fd);
	if (strlen(buf) != (size_t)size) {
		free(buf);
		return;
	}
	char *str_to_find = malloc(strlen(user) + 4);
	strcpy(str_to_find, user);
	strcat(str_to_find, ":");
	char *map = strstr(buf, str_to_find);
	free(str_to_find);
	if (map == NULL) {
		id_map->gid_lower = 0;
		id_map->gid_count = 0;
		return;
	}
	// Get gid_lower and uid_count.
	id_map->gid_lower = line_get_gid_lower(map);
	id_map->gid_count = line_get_gid_count(map);
	free(buf);
}
struct RURI_ID_MAP ruri_get_idmap(uid_t uid, gid_t gid)
{
	/*
	 * Get uid_map and gid_map.
	 * This function will return a RURI_ID_MAP struct for `newuidmap` and `newgidmap`.
	 * If there is any error, all the id_map will be 0.
	 */
	struct RURI_ID_MAP ret;
	ret.uid = uid;
	ret.gid = gid;
	char *username = get_username(uid);
	ruri_log("{base}Username: {cyan}%s\n", username);
	if (username == NULL) {
		ret.uid_lower = 0;
		ret.uid_count = 0;
		ret.gid_lower = 0;
		ret.gid_count = 0;
		return ret;
	}
	get_uid_map(username, &ret);
	get_gid_map(username, &ret);
	ruri_log("{base}uid: {cyan}%d\n", ret.uid);
	ruri_log("{base}gid: {cyan}%d\n", ret.gid);
	ruri_log("{base}uid_lower: {cyan}%d\n", ret.uid_lower);
	ruri_log("{base}uid_count: {cyan}%d\n", ret.uid_count);
	ruri_log("{base}gid_lower: {cyan}%d\n", ret.gid_lower);
	ruri_log("{base}gid_count: {cyan}%d\n", ret.gid_count);
	free(username);
	return ret;
}
bool ruri_user_exist(const char *_Nonnull username)
{
	/*
	 * Check if the user exists.
	 */
	int fd = open("/etc/passwd", O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		return false;
	}
	struct stat filestat;
	fstat(fd, &filestat);
	off_t size = filestat.st_size;
	if (size >= 65536) {
		// If the file is too large, just error.
		close(fd);
		ruri_error("{red}The /etc/passwd file is too large, please check it.\n");
	}
	char *buf = malloc((size_t)size + 1);
	read(fd, buf, (size_t)size);
	buf[size] = '\0';
	close(fd);
	if (strlen(buf) != (size_t)size) {
		free(buf);
		return false;
	}
	char *p = buf;
	const char *bound = p + strlen(p);
	char *tmpusername = NULL;
	while (true) {
		tmpusername = line_get_username(p);
		if (strcmp(tmpusername, username) == 0) {
			free(buf);
			free(tmpusername);
			return true;
		}
		free(tmpusername);
		p = strchr(p, '\n');
		if (p == NULL) {
			break;
		}
		p = p + 1;
		if (p >= bound) {
			break;
		}
	}
	free(buf);
	return false;
}
uid_t ruri_get_user_uid(const char *_Nonnull username)
{
	/*
	 * Get uid by username.
	 */
	RURI_PWD_ERRNO = 0;
	int fd = open("/etc/passwd", O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		RURI_PWD_ERRNO = 1;
		return 1145;
	}
	struct stat filestat;
	fstat(fd, &filestat);
	off_t size = filestat.st_size;
	if (size >= 65536) {
		// If the file is too large, just error.
		close(fd);
		ruri_error("{red}The /etc/passwd file is too large, please check it.\n");
	}
	char *buf = malloc((size_t)size + 1);
	read(fd, buf, (size_t)size);
	buf[size] = '\0';
	close(fd);
	if (strlen(buf) != (size_t)size) {
		free(buf);
		RURI_PWD_ERRNO = 1;
		return 1145;
	}
	char *p = buf;
	const char *bound = p + strlen(p);
	uid_t tmpuid = 0;
	char *tmpusername = NULL;
	while (true) {
		tmpusername = line_get_username(p);
		tmpuid = line_get_uid(p);
		if (strcmp(tmpusername, username) == 0) {
			free(buf);
			free(tmpusername);
			RURI_PWD_ERRNO = 0;
			return tmpuid;
		}
		free(tmpusername);
		p = strchr(p, '\n');
		if (p == NULL) {
			break;
		}
		p = p + 1;
		if (p >= bound) {
			break;
		}
	}
	free(buf);
	RURI_PWD_ERRNO = 1;
	return 1145;
}
gid_t ruri_get_user_gid(const char *_Nonnull username)
{
	/*
	 * Get gid by username.
	 */
	RURI_PWD_ERRNO = 0;
	int fd = open("/etc/passwd", O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		RURI_PWD_ERRNO = 1;
		return 1145;
	}
	struct stat filestat;
	fstat(fd, &filestat);
	off_t size = filestat.st_size;
	if (size >= 65536) {
		// If the file is too large, just error.
		close(fd);
		ruri_error("{red}The /etc/passwd file is too large, please check it.\n");
	}
	char *buf = malloc((size_t)size + 1);
	read(fd, buf, (size_t)size);
	buf[size] = '\0';
	close(fd);
	if (strlen(buf) != (size_t)size) {
		free(buf);
		RURI_PWD_ERRNO = 1;
		return 1145;
	}
	char *p = buf;
	const char *bound = p + strlen(p);
	gid_t tmpgid = 0;
	char *tmpusername = NULL;
	while (true) {
		tmpusername = line_get_username(p);
		tmpgid = line_get_gid(p);
		if (strcmp(tmpusername, username) == 0) {
			free(buf);
			free(tmpusername);
			RURI_PWD_ERRNO = 0;
			return tmpgid;
		}
		free(tmpusername);
		p = strchr(p, '\n');
		if (p == NULL) {
			break;
		}
		p = p + 1;
		if (p >= bound) {
			break;
		}
	}
	free(buf);
	RURI_PWD_ERRNO = 1;
	return 1145;
}
static gid_t line_get_group_gid(const char *p)
{
	/*
	 * /etc/groups format:
	 * groupname:password:gid:user1,user2,user3
	 * So we need to skip 2 colons.
	 */
	// Bounds
	const char *bound = p + strlen(p);
	RURI_PWD_ERRNO_INTERNAL = 0;
	gid_t ret = 1145;
	for (int i = 0; i < 2; i++) {
		if ((strchr(p, ':') == NULL) || (strchr(p, ':') > (strchr(p, '\n') == NULL ? 0 : strchr(p, '\n')))) {
			RURI_PWD_ERRNO_INTERNAL = 1;
			return 1145;
		}
		p = strchr(p, ':') + 1;
		if (p >= bound) {
			RURI_PWD_ERRNO_INTERNAL = 1;
			return 1145;
		}
	}
	// Now, after we skip 2 colons, we can get the gid.
	// Read the gid until we meet the next colon.
	ret = 0;
	for (int i = 0; p[i] != '\0'; i++) {
		if (p[i] == ':') {
			RURI_PWD_ERRNO_INTERNAL = 0;
			return ret;
		}
		if (p[i] < '0' || p[i] > '9') {
			RURI_PWD_ERRNO_INTERNAL = 1;
			return 1145;
		}
		ret = ret * 10 + (gid_t)(p[i] - '0');
	}
	RURI_PWD_ERRNO_INTERNAL = 1;
	return 1145;
}
static bool groups_line_have_user(const char *p, const char *username)
{
	/*
	 * Check if the line have the user.
	 */
	// /etc/groups format:
	// groupname:password:gid:user1,user2,user3
	// So we need to skip 3 colons.
	// Bounds
	const char *bound = p + strlen(p);
	for (int i = 0; i < 3; i++) {
		if ((strchr(p, ':') == NULL) || (strchr(p, ':') > (strchr(p, '\n') == NULL ? 0 : strchr(p, '\n')))) {
			return false;
		}
		p = strchr(p, ':') + 1;
		if (p >= bound) {
			return false;
		}
	}
	// Now, after we skip 3 colons, we can get the users.
	// If we reached the end of the line, we return false.
	if (p[0] == '\0' || p[0] == '\n') {
		return false;
	}
	// Read the users until we meet the next colon.
	char *users = malloc(strlen(p) + 1);
	strcpy(users, p);
	if (strchr(users, '\n') != NULL) {
		*strchr(users, '\n') = '\0';
	}
	char *user = strtok(users, ",");
	while (user != NULL) {
		if (strcmp(user, username) == 0) {
			free(users);
			return true;
		}
		user = strtok(NULL, ",");
	}
	free(users);
	return false;
}
int ruri_get_groups(uid_t uid, gid_t groups[])
{
	/*
	 * Get groups by uid.
	 */
	char *username = get_username(uid);
	if (username == NULL) {
		return 0;
	}
	gid_t user_gid = ruri_get_user_gid(username);
	if (RURI_PWD_ERRNO != 0) {
		ruri_warning("{yellow}Warning: failed to parse user gid for `%s`\n", username);
		free(username);
		return 0;
	}
	groups[0] = user_gid;
	int ret = 1;
	int fd = open("/etc/group", O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		free(username);
		return 1;
	}
	struct stat filestat;
	fstat(fd, &filestat);
	off_t size = filestat.st_size;
	if (size >= 65536) {
		// If the file is too large, just error.
		close(fd);
		free(username);
		ruri_error("{red}The /etc/group file is too large, please check it.\n");
	}
	char *buf = malloc((size_t)size + 1);
	read(fd, buf, (size_t)size);
	buf[size] = '\0';
	close(fd);
	if (strlen(buf) != (size_t)size) {
		free(username);
		free(buf);
		return 1;
	}
	char *p = buf;
	const char *bound = p + strlen(p);
	gid_t tmpgid = 114514;
	while (p != NULL) {
		tmpgid = line_get_group_gid(p);
		if (RURI_PWD_ERRNO_INTERNAL != 0) {
			ruri_warning("{yellow}Warning: failed to parse /etc/group line: %s{clear}\n", p);
			free(username);
			free(buf);
			return 0;
		}
		if (groups_line_have_user(p, username)) {
			groups[ret] = tmpgid;
			ret++;
		}
		if (ret >= NGROUPS_MAX - 1) {
			break;
		}
		p = strchr(p, '\n');
		if (p == NULL) {
			break;
		}
		p = p + 1;
		if (p >= bound) {
			break;
		}
	}
	free(username);
	return ret;
}