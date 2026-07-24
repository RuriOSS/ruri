It's another huge release since v3.9.3. So v3.9.5-rc1 is now ready, all caught up :>     
  * Add `--freeze`/`--thaw` subcommands to pause and resume a container via cgroup freezer (**NOTE**: needs cgroup freezer support, both cgroup v2 built-in freezer and v1 `/sys/fs/cgroup/freezer` or Android `/dev/freezer` are detected).
  * Add `--set-flag` for developers to enable feature flags.
  * Add a `.ruri_umounted` file to indicate that the container has been unmounted.
  * Fix a race condition when udev didn't create /dev/loopx device before ruri tries to mount it.
  * Fix re-enter unshare container failed in v3.9.4.
  * Fix pipe-sync issue in unshare container.
  * Always convert mount source to absolute path.
  * Support new feature flags:
    - `ban_futex_pi`: Ban futex_pi syscalls, for GhostLock mitigation.
    - `wait_before_exec`: Wait for SIGUSR1 signal before exec() in the container.
    - `allow_personality`: Allow personality() syscall, for compatibility with some software like debian reprotest, box86/wine, etc.    
    - `force_panic`: The internal implementation of `--strict-mode`, will force ruri to panic on any error.    
    - `no_time_ns`: disable time namespace.
    - `no_uts_ns`: disable UTS namespace.
    - `no_ipc_ns`: disable IPC namespace.
    - `no_pid_ns`: disable PID namespace.
    - `no_cgroup_ns`: disable cgroup namespace.
    - `fork_as_init`: The internal implementation of `--fork-as-init`, will make ruri fork() before exec() to be the init process in the container.
    - `disable_warnings`: The internal implementation of `--no-warnings`, will disable all warnings.
    - `auto_umount`: The internal implementation of `--auto-umount`, will automatically umount the container when it exits.
    - `auto_umount_on_panic`: The internal implementation of `--umount-on-panic`, will automatically umount the container when it panics.
    - `is_health_check`: The internal implementation of `--health-check`, will run as health check process in the container.
    - `systemd_init`: The internal implementation of `--systemd`, will enable systemd init support in the container.
    - `enable_tty_signals`: The internal implementation of `--enable-tty-signals`, will not mask SIGTTIN and SIGTTOU signals in the container.
    - `skip_setgroups`: The internal implementation of `--skip-setgroups`, will skip setgroups() call when changing the user in the container.
    - `make_kvm_node`: Will be converted to `dev_nodes=+kvm`.
    - `empty_net_ns`: The internal implementation of `--no-network`, will disable network in the container.
    - `create_gunyah_node`: Will be converted to `dev_nodes=+gunyah`.
    - `create_geniezone_node`: Will be converted to `dev_nodes=+gzvm`.
    - `no_reset_pidfile`: will keep writing to the pidfile without cleaning it. For debugging.
    - `no_logs`: ruri will auto convert `ruri_no_logs` env to this flag, and will disable all logs. For debugging.
    - `wait_pidfile_lock`: As pidfile is updated asynchronously, this flag will make sure the pidfile is updated before exiting.
    - `no_seccomp`: Disable all seccomp-based features.
    - `no_rurienv`: The internal implementation of `--no-rurienv`.
    - `no_cgroup`: Disable all cgroup-based features.
    - `no_pidfile_daemon`: Disable the pidfile daemon, `--auto-umount` and `--umount-on-panic` will also be disabled.
    - `no_drop_caps`: Do not really call cap_drop_bound(), only for debugging.
    - `no_memory_cgroup`: Disable all memory cgroup based features.
    - `no_cpuset_cgroup`: Disable all cpuset cgroup based features.
    - `no_cpupercent_cgroup`: Disable all cpupercent cgroup based features.
    - `no_pids_cgroup`: Disable all pids cgroup based features.
    - `no_io_cgroup`: Disable all io cgroup based features.
    - `no_freezer_cgroup`: Disable all freezer cgroup based features.
    - `no_pidfd`: Disable all pidfd based features, for debugging.
    - `dev_nodes`: A comma-separated list to override default device nodes in the container. For example, `dev_nodes=+kvm,-full` means create /dev/kvm but disable /dev/full in the container.  
    - `just_chroot`: The internal implementation of `--just-chroot`, will just chroot into the container without creating runtime directories.    
    - `ruri_dbg`: Enable ruri debug mode, will print logs and do other debug stuff. For debugging.
    - `use_host_runtime`: The internal implementation of `--host-runtime`, will bind-mount /dev/, /sys/, and /proc/ from host.
    - `no_mask_paths`: The internal implementation of `--unmask-dirs`, will not mask sensitive paths in /proc and /sys.
    - `read_only_rootfs`: The internal implementation of `--read-only`, will mount / as read-only.
    - `no_new_privs`: The internal implementation of `--no-new-privs`, will set NO_NEW_PRIVS flag.
    - `rlimits`: A comma-separated list to set rlimits in the container. For example, `rlimits=nproc:16:32,core:1` means set RLIMIT_NPROC to 16 (soft) and 32 (hard), and set RLIMIT_CORE to 1 (soft) and 1 (hard).
    - `outside_rurienv`: Use outside .rurienv file instead of the one in the container. For example, `outside_rurienv=/tmp/rurienv` means use `/tmp/rurienv` instead of `/.rurienv` in the container.
    - `rw_rurienv`: make .rurienv rw, will not set immutable flag and ro bind-mount on it.
    - `ruri_perf`: enable profiling log, only for debugging.
    - `is_termux`: if we are running in termux.
    - `img_sectx`: SELinux context for image file, to fix loop-mount on android.
    - `new_tty`: create a new pty in container.
    - `create_ntsync_node`: Will be converted to `dev_nodes=+ntsync`.