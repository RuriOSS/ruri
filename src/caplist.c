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
 * This file provides functions to manage capability list.
 * But drop_caps() is in chroot.c, not here.
 * RURI_INIT_VALUE is the end of caplist.
 * RURI_CAP_LAST_CAP is large to 114 to cover future capabilities.
 *
 */
#ifndef DISABLE_LIBCAP
static int get_last_cap(void)
{
	/*
	 * Try to read the last capability from /proc/sys/kernel/cap_last_cap first,
	 * if failed, we will try to get it by cap_get_bound() one by one.
	 * And we will cache the result in thread local variable ret, to avoid reading file or
	 * calling cap_get_bound() again and again.
	 * Fallback to CAP_LAST_CAP if we cannot get the last capability.
	 */
	static thread_local int ret = -1;
	if (ret != -1) {
		return ret;
	}
	FILE *fp = fopen("/proc/sys/kernel/cap_last_cap", "re");
	if (fp != NULL) {
		if (fscanf(fp, "%d", &ret) == 1) {
			fclose(fp);
			if (ret >= RURI_CAP_LAST_CAP) {
				ret = CAP_LAST_CAP;
			}
			return ret;
		}
		fclose(fp);
	}
	for (int i = 0; i < RURI_CAP_LAST_CAP; i++) {
		if (cap_get_bound(i) < 0 && errno == EINVAL) {
			ret = i - 1;
			break;
		}
	}
	if (ret == -1) {
		ret = CAP_LAST_CAP;
	}
	return ret;
}
// cap_from_name() that supports both upper and lower case.
int ruri_cap_from_name(const char *str, cap_value_t *cap)
{
	char *buf = malloc(strlen(str) + 1);
	for (int i = 0; str[i] != '\0'; i++) {
		buf[i] = (char)tolower(str[i]);
	}
	buf[strlen(str)] = '\0';
	if (strlen(buf) > 4 && strncmp(buf, "cap_", 4) != 0) {
		char *new_buf = malloc(strlen(buf) + 5);
		sprintf(new_buf, "cap_%s", buf);
		free(buf);
		buf = new_buf;
	}
	int ret = cap_from_name(buf, cap);
	free(buf);
	return ret;
}
#endif
// Add a cap to caplist.
void ruri_add_to_caplist(cap_value_t *_Nonnull list, cap_value_t cap)
{
/*
 * If cap is already in list, just do nothing and quit.
 * list[] is initialized by RURI_INIT_VALUE,
 * and the RURI_INIT_VALUE is the end of the list.
 */
#ifndef DISABLE_LIBCAP
	// We do not add non-supported capabilities to caplist.
	if (cap > get_last_cap()) {
		return;
	}
	// Add cap to caplist.
	if (!ruri_is_in_caplist(list, cap)) {
		for (int k = 0; k < RURI_CAP_LAST_CAP; k++) {
			if (list[k] == RURI_INIT_VALUE) {
				list[k] = cap;
				list[k + 1] = RURI_INIT_VALUE;
				break;
			}
		}
	}
#endif
}
// Check if the cap is in the list.
bool ruri_is_in_caplist(const cap_value_t *_Nonnull list, cap_value_t cap)
{
	/*
	 * If cap is in list, return true,
	 * else, return false.
	 * RURI_INIT_VALUE is the end of the list.
	 */
	for (int i = 0; i < RURI_CAP_LAST_CAP; i++) {
		if (list[i] == cap) {
			return true;
			break;
		}
		if (list[i] == RURI_INIT_VALUE) {
			break;
		}
	}
	return false;
}
// Del a cap from caplist.
void ruri_del_from_caplist(cap_value_t *_Nonnull list, cap_value_t cap)
{
	/*
	 * If the cap is not in list, just do nothing and quit.
	 * Or we will delete it from the list.
	 */
	for (int i = 0; i < RURI_CAP_LAST_CAP; i++) {
		if (list[i] == cap) {
			while (i < RURI_CAP_LAST_CAP && list[i] != RURI_INIT_VALUE) {
				list[i] = list[i + 1];
				i++;
			}
			list[i - 1] = RURI_INIT_VALUE;
			return;
		}
		if (list[i] == RURI_INIT_VALUE) {
			return;
		}
	}
}
void ruri_build_caplist(cap_value_t caplist[], bool privileged, cap_value_t drop_caplist_extra[], cap_value_t keep_caplist_extra[])
{
	/*
	 * If privileged is true, we setup a full list of all capabilities,
	 * del keep_caplist_common[] from the list,
	 * and then add drop_caplist_extra[] to the list,
	 * and del keep_caplist_extra[] from the list.
	 *
	 * If privileged is false, we just add drop_caplist_extra[] to the list,
	 * and del keep_caplist_extra[] from the list.
	 *
	 * NOTE: keep_caplist_extra[] will cover drop_caplist_extra[],
	 * if they have the same capabilities.
	 */

#ifndef DISABLE_LIBCAP
	// Based on docker's default capability set.
	// And I removed some unneeded capabilities.
	cap_value_t keep_caplist_common[] = { CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_FSETID, CAP_FOWNER, CAP_SETGID, CAP_SETUID, CAP_SETFCAP, CAP_SETPCAP, CAP_NET_BIND_SERVICE, CAP_KILL, CAP_AUDIT_WRITE, RURI_INIT_VALUE };
	// Set default caplist to drop.
	caplist[0] = RURI_INIT_VALUE;
	if (!privileged) {
		// Add all capabilities to caplist.
		for (int i = 0; i <= get_last_cap(); i++) {
			caplist[i] = i;
			caplist[i + 1] = RURI_INIT_VALUE;
		}
		// Del keep_caplist_common[] from caplist.
		for (int i = 0; i < RURI_CAP_LAST_CAP; i++) {
			if (keep_caplist_common[i] == RURI_INIT_VALUE) {
				break;
			}
			ruri_del_from_caplist(caplist, keep_caplist_common[i]);
		}
	}
	// Add drop_caplist_extra[] to caplist.
	if (drop_caplist_extra[0] != RURI_INIT_VALUE) {
		for (int i = 0; i < RURI_CAP_LAST_CAP; i++) {
			if (drop_caplist_extra[i] == RURI_INIT_VALUE) {
				break;
			}
			ruri_add_to_caplist(caplist, drop_caplist_extra[i]);
		}
	}
	// Del keep_caplist_extra[] from caplist.
	if (keep_caplist_extra[0] != RURI_INIT_VALUE) {
		for (int i = 0; i < RURI_CAP_LAST_CAP; i++) {
			if (keep_caplist_extra[i] == RURI_INIT_VALUE) {
				break;
			}
			ruri_del_from_caplist(caplist, keep_caplist_extra[i]);
		}
	}
#else
	caplist[0] = RURI_INIT_VALUE;
#endif
}
