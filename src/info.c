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
 * This file provides some functions to show help/version info.
 * As ruri_fetch() is too long but useless, I put it in rurifetch.c.
 * Emmm... I hope users can understand the help page.
 */
void ruri_show_version_info(void)
{
	/*
	 * Just show some info.
	 * Version info is defined in macro RURI_VERSION.
	 * RURI_COMMIT_ID is defined as -D option of compiler.
	 */
	cprintf("\n");
	cprintf("{base}               ●●●●  ●   ● ●●●●   ●●●\n");
	cprintf("{base}               ●   ● ●   ● ●   ●   ●\n");
	cprintf("{base}               ●●●●  ●   ● ●●●●    ●\n");
	cprintf("{base}               ●  ●  ●   ● ●  ●    ●\n");
	cprintf("{base}               ●   ●  ●●●  ●   ●  ●●●\n");
	cprintf("{base}Lightweight, User-friendly Linux-container Implementation\n");
	cprintf("{base}             Revamp, Until Reach the Ideal\n");
	cprintf("{base}            Licensed under the MIT License\n");
	cprintf("{base}              <https://mit-license.org>\n");
	cprintf("{base}         Copyright (C) 2022-2024 Moe-hacker\n\n");
	cprintf("{base}%s%d.%d.%d%s", "ruri version .....:  ", RURI_VERSION_MAJOR, RURI_VERSION_MINOR, RURI_VERSION_PATCH, "\n");
#if defined(RURI_COMMIT_ID)
	cprintf("{base}%s%s%s", "ruri commit id ...:  ", RURI_COMMIT_ID, "\n");
#endif
	cprintf("{base}%s%s%s", "Architecture .....:  ", RURI_HOST_ARCH, "\n");
	struct stat st;
	if (stat("/proc/self/exe", &st) == 0) {
		cprintf(_Generic((off_t)0, long: "{base}Binary size ......:  %ldK\n", long long: "{base}Binary size ......:  %lldK\n", default: "{base}Binary size ......:  %ldK\n"), (st.st_size / 1024));
	}
#if defined(LIBCAP_MAJOR) && defined(LIBCAP_MINOR)
	cprintf("{base}%s%d%s%d%s", "libcap ...........:  ", LIBCAP_MAJOR, ".", LIBCAP_MINOR, "\n");
#endif
#if defined(SCMP_VER_MAJOR) && defined(SCMP_VER_MINOR) && defined(SCMP_VER_MICRO)
	cprintf("{base}%s%d%s%d%s%d%s", "libseccomp .......:  ", SCMP_VER_MAJOR, ".", SCMP_VER_MINOR, ".", SCMP_VER_MICRO, "\n");
#endif
	cprintf("{base}%s%d%s%d%s", "libk2v ...........:  ", LIBK2V_MAJOR, ".", LIBK2V_MINOR, "\n");
	cprintf("{base}%s%d%s%d%s", "cprintf ..........:  ", CPRINTF_MAJOR, ".", CPRINTF_MINOR, "\n");
	cprintf("{base}%s%s\n", "Compiler version .:  ", __VERSION__);
	cprintf("{base}%s%s\n", "Build date .......:  ", __TIMESTAMP__);
	cprintf("{base}\nThere is NO WARRANTY, to the extent permitted by law\n");
	cprintf("{clear}\n");
}
// For `ruri -V`.
void ruri_show_version_code(void)
{
	/*
	 * The version code is not standard now,
	 * so in fact it's very useless.
	 * Maybe it can be useful one day...
	 */
	printf("%d.%d.%d\n", RURI_VERSION_MAJOR, RURI_VERSION_MINOR, RURI_VERSION_PATCH);
}
// For `ruri -h`.
void ruri_show_helps(void)
{
	/*
	 * Help page of ruri.
	 * I think you can understand...
	 */
	cprintf("{base}ruri %s\n\n", RURI_VERSION);
	cprintf("{base}Lightweight, User-friendly Linux-container Implementation\n");
	cprintf("\n");
	cprintf("{base}Usage:\n");
	cprintf("{base}  ruri [OPTIONS]...\n");
	cprintf("{base}  ruri [ARGS]... [CONTAINER_DIRECTORY]... [COMMAND [ARGS]...]\n");
	cprintf("\n");
	cprintf("{base}OPTIONS:\n");
	cprintf("{base}  -v, --version ...............................: Show version info\n");
	cprintf("{base}  -V, --version-code ..........................: Show version code\n");
	cprintf("{base}  -h, --help ..................................: Show help\n");
	cprintf("{base}  -H, --show-examples .........................: Show command line examples\n");
	cprintf("{base}  -U, --umount [container_dir/config] .........: Unmount a container\n");
	cprintf("{base}  -P, --ps [container_dir/config] .............: Show process status of the container (*1)\n");
	cprintf("{base}  -C, --correct-config [config]................: Correct a container config\n");
	cprintf("\n");
	cprintf("{base}ARGS:\n");
	cprintf("{base}  -r, --rootless ..............................: Run rootless container\n");
	cprintf("{base}  -D, --dump-config ...........................: Dump the config\n");
	cprintf("{base}  -o, --output [config] .......................: Set output file for the `-D` option\n");
	cprintf("{base}  -c, --config [config] [args] [COMMAND [ARGS]]: Use config file\n");
	cprintf("{base}  -a, --arch [arch] ...........................: Simulate architecture via binfmt_misc/QEMU (*2)\n");
	cprintf("{base}  -q, --qemu-path [path] ......................: Specify the path of QEMU\n");
	cprintf("{base}  -u, --unshare ...............................: Enable unshare feature\n");
	cprintf("{base}  -n, --no-new-privs ..........................: Set NO_NEW_PRIVS flag\n");
	cprintf("{base}  -N, --no-rurienv ............................: Do not use .rurienv file\n");
	cprintf("{base}  -s, --enable-seccomp ........................: Enable built-in Seccomp profile\n");
	cprintf("{base}  -p, --privileged ............................: Run privileged container\n");
	cprintf("{base}  -k, --cap-add [cap] .........................: Add the specified capability (*3)\n");
	cprintf("{base}  -d, --cap-drop [cap] ........................: Drop the specified capability\n");
	cprintf("{base}  -e, --env [env] [value] .....................: Set environment variable to its value (*4)\n");
	cprintf("{base}  -m, --mount [dir/dev/img/file] [target] .....: Mount dir/block-device/image/file to target (*5)\n");
	cprintf("{base}  -M, --ro-mount [dir/dev/img/file] [target] ..: Mount dir/block-device/image/file as read-only\n");
	cprintf("{base}  -S, --host-runtime ..........................: Bind-mount /dev/, /sys/, and /proc/ from host\n");
	cprintf("{base}  -R, --read-only .............................: Mount / as read-only\n");
	cprintf("{base}  -l, --limit [limit=lin] .....................: Set cpuset/memory limit (*6)\n");
	cprintf("{base}  -w, --no-warnings ...........................: Disable warnings\n");
	cprintf("{base}  -f, --fork ..................................: fork() before executing the command (*7)\n");
	cprintf("{base}  -j, --just-chroot ...........................: Just chroot, do not create the runtime dirs\n");
	cprintf("{base}  -W, --work-dir [dir] ........................: Set the working directory in container\n");
	cprintf("{base}  -A, --unmask-dirs ...........................: Unmask dirs in /proc and /sys\n");
	cprintf("{base}  -E, --user [user/uid] .......................: Set the user to run the command in the container (*8)\n");
	cprintf("{base}  -t, --hostname [hostname] ...................: Set the hostname of the container (*9)\n");
	cprintf("{base}  -x, --no-network ............................: Disable network (*10)\n");
	cprintf("{base}  -K, --use-kvm ...............................: Enable /dev/kvm for container\n");
	cprintf("{base}  -I, --char-dev [device] [major] [minor] .....: Add a character device to container (*11)\n");
	cprintf("{base}  -i, --hidepid [1/2] .........................: Hidepid for /proc\n");
	cprintf("{base}  -T, --timens-offset [monotonic] [realtime]...: Set time offset for timens (*12)\n");
	cprintf("{base}  -b, --background ............................: Fork to background\n");
	cprintf("{base}  -L, --logfile [file] ........................: Set log file for -b option\n");
	cprintf("{base}  -X, --deny-syscall [syscall] ................: Deny syscall, use seccomp\n");
	cprintf("{base}  -J, --join-ns [NS_PID] ......................: Join namespace using ns_pid (*13)\n");
	cprintf("{base}  -O, --oom-score-adj [score] .................: Set oom_score_adj for container (*14)\n");
	cprintf("{base}  -Q, --mask-path [path] ......................: Mask a path in the container\n");
	cprintf("{base}  -z, --enable-tty-signals ....................: Enable TTY signals in the container (*15)\n");
	cprintf("\n");
	cprintf("{base}Note:\n");
	cprintf("{base}(*1)  : Will not work for unshare containers without PID ns support\n");
	cprintf("{base}(*2)  : The `-a` option also requires `-q` to be set\n");
	cprintf("{base}(*3)  : cap can be either a value or name (e.g., cap_chown == 0)\n");
	cprintf("{base}(*4)  : Will not work if [COMMAND [ARGS]...] is like `/bin/su -`\n");
	cprintf("{base}(*5)  : You can use `-m/-M [source] /` to mount another source as root\n");
	cprintf("{base}(*6)  : Each `-l` option can only set one of the cpuset/memory/cpupercent limits\n");
	cprintf("{base}        for example: `ruri -l memory=1M -l cpupercent=60 -l cpuset=1 /test`\n");
	cprintf("{base}(*7)  : This option is totally useless\n");
	cprintf("{base}(*8)  : If you use a username, please make sure it's in /etc/passwd in the container\n");
	cprintf("{base}(*9)  : This option is only for unshare containers\n");
	cprintf("{base}(*10) : This option needs net ns, and will enable unshare feature by default\n");
	cprintf("{base}(*11) : For example, `-I kvm 10 232` or `-I dri/card0 226 0`\n");
	cprintf("{base}(*12) : This feature might not work. The value is in seconds. This feature will auto-enable unshare\n");
	cprintf("{base}(*13) : This can only be used when the `-N` option is enabled\n");
	cprintf("{base}(*14) : The value is in the range of -1000 to 1000, but setting a negative value might cause security issues\n");
	cprintf("{base}(*15) : ruri will ignore SIGTTIN and SIGTTOU by default, enable this option to allow TTY signals in the container\n");
	cprintf("\n{base}Note:\n");
	cprintf("{base}BSD style usage is partially supported now. For example, you can use `-pW /root`, but `-W/root` is not allowed.\n");
	cprintf("{base}{clear}\n");
}
// For `ruri -H`.
void ruri_show_examples(void)
{
	/*
	 * Command line examples.
	 * I think you can understand...
	 */
	cprintf("\n");
	cprintf("{base}# Quickly setup a container(with rurima):\n");
	cprintf("  {green}. {yellow}<({green}curl {blue}-sL {purple}https://get.ruri.zip/rurima{yellow})\n");
	cprintf("  {green}./rurima lxc {blue}pull {blue}-a {purple}alpine {blue} -v {purple}edge {blue}-s {purple} /tmp/alpine\n");
	cprintf("\n");
	cprintf("{base}# Run chroot container:\n");
	cprintf("  {green}sudo ruri {purple}/tmp/alpine\n");
	cprintf("{base}# Very simple as you can see.\n");
	cprintf("\n");
	cprintf("{base}# About the capabilities:\n");
	cprintf("{base}# Run privileged chroot container:\n");
	cprintf("  {green}sudo ruri {blue}-p {purple}/tmp/alpine\n");
	cprintf("\n");
	cprintf("{base}# If you want to run privileged chroot container,\n");
	cprintf("{base}# but you don't want to give the container cap_sys_chroot privileges:\n");
	cprintf("  {green}sudo ruri {blue}-p -d \033[36mcap_sys_chroot {purple}/tmp/alpine\n");
	cprintf("\n");
	cprintf("{base}# If you want to run chroot container with common privileges,\n");
	cprintf("{base}# but you want cap_sys_admin to be kept:\n");
	cprintf("  {green}sudo ruri {blue}-k \033[36mcap_sys_admin {purple}/tmp/alpine\n");
	cprintf("\n");
	cprintf("{base}# About unshare:\n");
	cprintf("{base}# Unshare container's capability options are same with chroot.\n");
	cprintf("{base}# Run unshare container:\n");
	cprintf("  {green}sudo ruri {blue}-u {purple}/tmp/alpine\n");
	cprintf("\n");
	cprintf("{base}# Finally, umount the container:\n");
	cprintf("  {green}sudo ruri {blue}-U {purple}/tmp/alpine\n");
	cprintf("{clear}\n");
}
