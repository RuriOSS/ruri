# Note

BSD-style usage is partially supported now. For example, you can use `-pW /root`, but `-W/root` is not allowed.

# Usage

```sh
ruri [OPTIONS]...
ruri [ARGS]... [CONTAINER_DIRECTORY]... [COMMAND [ARGS]...]
```

## Options

| Option | Description |
|--------|-------------|
| `-v`, `--version` | Show version info |
| `-V`, `--version-code` | Show version code |
| `-h`, `--help` | Show help |
| `-H`, `--show-examples` | Show command-line examples |
| `-P`, `--ps [container_dir/config]` | Show process status of the container |

These options will display information.

---

| Option | Description |
|--------|-------------|
| `-U`, `--umount [container_dir/config]` | Unmount a container |

When you run a container, ruri mounts several necessary directories inside it. After you're done using the container, use the `-U` option to unmount it. This works for both rootless and rootful containers. For rootful containers, you must run this command with root privileges (e.g., using `sudo` or `doas`).

**Behavior note:**  
- Running `-U` will also kill any processes detected inside the container.
- Running `-U` will automatically remove the `.rurienv` file in the container.

**Warning:**  
Always run `ruri -U /path/to/container` before deleting the container directory to prevent issues.

---

| Option | Description |
|--------|-------------|
| `-C`, `--correct-config` | Correct config. |

Try to correct an incomplete config file.

## Arguments

By default, ruri containers should be run with `sudo` for root privileges.  
However, in recent versions, you can also run ruri as a non-privileged user—there's no need to use the `-r` (rootless) option anymore.  
ruri will automatically detect whether it is running as root or as a non-privileged user.

---

| Option | Description |
|--------|-------------|
| `-D`, `--dump-config` | Dump the config |

ruri supports using a config file. You can use the `-D` option to dump the current config of a container.  
For example:

```sh
ruri -D -k cap_sys_admin -d cap_sys_chroot ./t
```

This will dump the container config with `-k cap_sys_admin -d cap_sys_chroot`, so next time you can just use the config instead of the `-k cap_sys_admin -d cap_sys_chroot` arguments.

---

| Option | Description |
|--------|-------------|
| `-o`, `--output [config file]` | Set output file for the `-D` option |

This option is used with the `-D` option to save the config to a file.  
For example:

```sh
ruri -D -o test.conf -k cap_sys_admin -d cap_sys_chroot ./t
```

This will save the config to `test.conf`.  
**Behavior note:** The config file will be an executable file with a shebang line, so you can run it directly:

```sh
./test.conf
```

This will run the container with the config file.

---

| Option | Description |
|--------|-------------|
| `-c`, `--config [config] [args] [COMMAND [ARGS]]` | Use config file |

You can use `ruri -c config_file` to run a container with a config file.  
For example:

```sh
ruri -c test.conf
```

or

```sh
ruri -c test.conf -k cap_sys_admin /bin/su root -
```

This will run the container using `test.conf`.  
**Behavior note:** The config file has a hard size limit of 64K; this behavior can only be changed by modifying the source code.  
With the new version, you can also just execute the config file directly.

---

| Option | Description |
|--------|-------------|
| `-a`, `--arch [arch]` | Simulate architecture via binfmt_misc/QEMU |
| `-q`, `--qemu-path [path]` | Specify the path of QEMU |

These two arguments should be set at the same time.  
ruri supports using qemu-user-static with the binfmt_misc feature of the kernel to run cross-arch containers.  
The `-q` option can use the QEMU path in the host; it will be copied to `/qemu-ruri` in the container.  
For example:

```sh
ruri -q /usr/bin/qemu-x86_64-static -a x86_64 ./test-x86_64
```

But remember not to use this feature to simulate the host architecture.

> **Note:** This option requires kernel support for `binfmt_misc`. The QEMU binary must be statically linked or include all required dependencies within the container.
>
> **Behavior:** If the specified QEMU binary is outside the container, ruri will automatically copy it to `/qemu-ruri` inside the container. And, ruri will always copy the QEMU binary to the container, even if it already exists.
>
> **Experimental:** This feature is experimental and may not work as expected. Please report any issues you encounter.
>
> ruri uses this feature to build itself with GitHub Actions, and it works well.
>
> Other interpreters may work, but ruri has only been tested with QEMU.

---

| Option | Description |
|--------|-------------|
| `-u`, `--unshare` | Enable unshare feature |

ruri supports running containers with the unshare feature, which isolates processes using Linux namespaces.  
**Limitations:** Currently, NET and USER namespaces are not fully supported. While you can use the `-x` option to disable the network, the user namespace is used only for rootless containers.

**Behavior notes:**  
- When PID 1 exits in a PID namespace, the entire namespace is destroyed and all processes within it are terminated.
- This option requires kernel support for namespaces. ruri will attempt to enable all supported namespaces; if any fail, warnings will be displayed.
- When unshare is enabled, ruri uses `pivot_root(2)` instead of `chroot(2)`.

For more details, see the man pages: `unshare(1)`, `unshare(2)`, and `namespaces(7)`.

---

| Option | Description |
|--------|-------------|
| `-n`, `--no-new-privs` | Set NO_NEW_PRIVS flag |

This argument will set NO_NEW_PRIVS; commands like `sudo` will be unavailable for non-privileged users.  
For more info, refer to the man page of `prctl(2)` and `PR_SET_NO_NEW_PRIVS`.

---

| Option | Description |
|--------|-------------|
| `-N`, `--no-rurienv` | Do not use .rurienv file |

ruri will create `/.rurienv` in the container to save container config by default. You can use this option to disable it.  
**Behavior note:** For unshare/rootless containers, this option will print the PID, so that you can use it to join the namespace later.

---

| Option | Description |
|--------|-------------|
| `-J`, `--join-ns [NS_PID]` | Join namespace using NS_PID. |

If you use an unshare/rootless container with the `-N` option enabled, you can use this option to join its namespace.  
This will only work with the `-uN` or `-rN` options enabled.  
For more info, refer to the man page of `setns(2)` and `unshare(2)`.

---

| Option | Description |
|--------|-------------|
| `-s`, `--enable-seccomp` | Enable built-in Seccomp profile |

ruri provides a built-in seccomp profile, but if you really need to use seccomp, you might need to edit `src/seccomp.c` with your own rules and recompile it.  
Note: This option needs kernel support for seccomp.  
Note: This option is experimental and may not work as expected. Report issues if you find any bugs.  
For more info, refer to the man page of `seccomp(2)`, `prctl(2)`, and `seccomp(3)`.

---

| Option | Description |
|--------|-------------|
| `-p`, `--privileged` | Run privileged container |

This argument will give all capabilities to the container, but you can also use the `-d` option to filter out capabilities you don't want to keep.  
For more info, refer to the man page of `capabilities(7)`.

---

| Option | Description |
|--------|-------------|
| `-r`, `--rootless` | Run rootless container |

This option should be run as a non-privileged user, so you can run a rootless container with user namespaces.  
This option requires the `uidmap` package and user namespace support.  
Remember to set up `/etc/subuid` and `/etc/subgid` before running a rootless container.  
Note: This option needs user namespace support, and the kernel must allow creating user namespaces with non-privileged users.  
**NOTE:** This option is already deprecated; you can just run ruri as a non-privileged user now, and it will automatically detect if it's rootless or not.  
For more info, refer to the man page of `user_namespaces(7)` and `unshare(2)`.

---

| Option | Description |
|--------|-------------|
| `-k`, `--cap-add [cap]` | Add the specified capability |
| `-d`, `--cap-drop [cap]` | Drop the specified capability |

These two options can control the capabilities in the container. Cap can be either a value or a name.  
For example, `-k cap_chown` has the same effect as `-k 0`.  
**Behavior note:** ruri will automatically drop some capabilities like `CAP_SYS_ADMIN`, `CAP_SYS_CHROOT`, etc. If you want to keep them, you can use the `-k` option.  
For more info, refer to the man page of `capabilities(7)`.

---

| Option | Description |
|--------|-------------|
| `-e`, `--env [env] [value]` | Set environment variable to its value |

**Behavior note:** ruri clears all environment variables before launching the container for security and consistency. Therefore, `LD_PRELOAD` and other environment-based injection methods will not work. Also, they will not work for ruri itself.  
These environment variables will always be preset in the container; you can only use the `-e` option to overwrite them:

```sh
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
TMPDIR=/tmp
SHELL=sh
container=ruri
```

---

| Option | Description |
|--------|-------------|
| `-m`, `--mount [dir/dev/img/file] [target]` | Mount dir/block-device/image/file to target |
| `-M`, `--ro-mount [dir/dev/img/file] [target]` | Mount dir/block-device/image/file as read-only |

ruri provides a powerful mount function. Here are some examples:

```sh
ruri -m /dev/sda1 / ./test
ruri -m ./test.img / ./test
ruri -m /sdcard /sdcard ./test
```

It can also bind-mount files/FIFOs/sockets.  
Note: For the full specification of mount options, please refer to [mount.md](mount.md).

---

| Option | Description |
|--------|-------------|
| `-S`, `--host-runtime` | Bind-mount /dev/, /sys/, and /proc/ from host |

ruri will create `/dev/`, `/sys/`, and `/proc/` after `chroot(2)` into the container for better security. You can use the `-S` option to force it to bind-mount system runtime directories.  
**Behavior note:** This option might make info in `/proc` inaccurate, might leak some info from the host, and might cause some security issues. Enable it only if you know what you are doing.  
For more info, refer to the man page of `mount(2)`, `proc(5)`, and `sysfs(5)`.

---

| Option | Description |
|--------|-------------|
| `-R`, `--read-only` | Mount / as read-only |

This will make the whole container rootfs read-only.

---

| Option | Description |
|--------|-------------|
| `-l`, `--limit [cpuset=cpu/memory=mem]` | Set cpuset/memory limit |

ruri currently supports cpuset and memory cgroups.  
Each `-l` option can only set one of the cpuset/memory limits.  
For example:

```sh
ruri -l memory=1M -l cpuset=1 /test
```

Note: This option needs kernel support for the specified cgroup.  
Note: This option is experimental and may not work as expected. Report issues if you find any bugs.  
TODO: Add support for other cgroup limits like cpu, blkio.  
For more info, refer to the man page of `cgroups(7)` and `cgroup(7)`.

---

| Option | Description |
|--------|-------------|
| `-w`, `--no-warnings` | Disable warnings |

There might be some warnings when running ruri. If you don't like them, use the `-w` option to disable them.  
Note: This is just a cosmetic option; it will not affect the behavior of ruri.

---

| Option | Description |
|--------|-------------|
| `-f`, `--fork` | fork() before exec the command |

Unshare and rootless containers will always fork() before running commands in the container.  
You can use this option to make a common chroot container have the same behavior.  
Note: This is only a useless option; I forgot why I added it, but it is here only for compatibility.

---

| Option | Description |
|--------|-------------|
| `-j`, `--just-chroot` | Just chroot, do not create the runtime directories |

If you enable this option, ruri will not create runtime directories (`/dev`, `/proc`, and `/sys`) in the container.  
And it will not set up cgroup limits.

---

| Option | Description |
|--------|-------------|
| `-W`, `--work-dir [dir]` | Change working directory in container. |

The default working directory is `/`. You can use this option to change it to other directories.  
Note: This option is for compatibility with other container implementations. It's useful when you run a Docker container image with ruri.

---

| Option | Description |
|--------|-------------|
| `-A`, `--unmask-dirs` | Unmask directories in /proc and /sys |

ruri will protect some files/directories in `/proc` and `/sys` by default. Use `-A` to disable this.  
Note: This option will downgrade the security of the container, so use it with caution.

---

| Option | Description |
|--------|-------------|
| `-E`, `--user [user/uid]` | Set the user to run the command in the container. |

You can use this option to switch to a non-privileged user before `exec(3)`.  
**Behavior note:** This option will parse user info from `/etc/passwd` in the container, so you need to make sure the user exists in the container. Also, make sure that your container is secure so the user cannot modify the `/etc/passwd` file.

---

| Option | Description |
|--------|-------------|
| `-t`, `--hostname [hostname]` | Set hostname |

Set hostname, only for unshare containers.  
Note: For non-unshare containers, setting the hostname in the container will also affect the host. ruri does not support that, and it's not recommended to do so in a container.

---

| Option | Description |
|--------|-------------|
| `-x`, `--no-network` | Disable network |

Disable network. This option needs net namespace support and will enable unshare at the same time.  
Note: This option needs kernel support for network namespaces.

---

| Option | Description |
|--------|-------------|
| `-K`, `--use-kvm` | Enable /dev/kvm support |

Enable `/dev/kvm` for the container.  
Note: This option needs kernel and host support for KVM.  
**Behavior note:** This option will automatically add `/dev/kvm` to the container, so you can run KVM-based applications in the container.

---

| Option | Description |
|--------|-------------|
| `-I`, `--char-dev [device] [major] [minor]` | Add a character device to the container |

Add a character device to the container, for example `-I kvm 10 232` or `-I dri/card0 226 0`.  
Note: For security reasons, creating block devices is not supported. You can use the `-m` option to mount a block device into the container instead.  
**Behavior note:** This option will create a character device in the `/dev/` directory of the container; no need to add the `/dev/` prefix.

**Behavior note:** For rootless containers, this option will bind-mount the character device from the host to the container. And it will not do mknod(2) in the container because it is not allowed for non-privileged users.

---

| Option | Description |
|--------|-------------|
| `-i`, `--hidepid 1/2` | Hidepid for /proc |

Hidepid option for `/proc`.  
For more info, refer to the man page of `proc(5)`.

---

| Option | Description |
|--------|-------------|
| `-b`, `--background` | Fork to background |
| `-L`, `--logfile [file]` | Set log file for the -b option |

Run ruri in the background and set the output file.  
**Behavior note:** This option will fork ruri to the background and redirect output to the specified file. If no file is specified, it will use `/dev/null` by default.  
Note: ruri will print the PID of the background process to stdout, so you can use it to manage the background process later.

---

| Option | Description |
|--------|-------------|
| `-X`, `--deny-syscall [syscall]` | Deny a syscall |

Use Seccomp to set `SCMP_ACT_KILL` for the syscall.  
**Behavior note:** This option will set the syscall to `SCMP_ACT_KILL`. It will not affect the built-in seccomp profile.  
This option is isolated from the built-in seccomp profile, so using this option will not enable the built-in seccomp profile automatically.  
Note: This option is experimental and may not work as expected. Report issues if you find any bugs.  
For more info, refer to the man page of `seccomp(2)`, `prctl(2)`, and `seccomp(3)`.

**Note:** For the newest version, you can use ERRNO:syscall to set the action for the syscall.
For example, if you want to set `SCMP_ACT_ERRNO(EPERM)` for the `open` syscall, you can use `EPERM:open` as the argument. And, `ERRNO:` is a special prefix means `SCMP_ACT_ERRNO(0)`. For ERRNO, refer to the `errno(3)` man page.

---

| Option | Description |
|--------|-------------|
| `-O`, `--oom-score-adj [score]` | Set oom_score_adj for the container. |

Set `oom_score_adj`. Note that using a negative value is dangerous. For negative values, it will not work with rootless containers.  
For more info, refer to the man page of `proc_pid_oom_score_adj(5)`.

---
| Option | Description |
|--------|-------------|
| `-Q`, `--mask-path [path]` | Mask a path in the container |
This option allows you to mask a path in the container with a read-only tmpfs or `/dev/null`.