# Initialization of container:
The design of ruri is very simple, just init the environment and then call exec() to run the command in the container. For unshare container, ruri will fork() into namwspace, so there will be a process called `ruri` on host, but chroot container will not have this behavior.  

## Signal:
ruri will ignore SIGTTIN and SIGTTOU signals, so that the container can run in the background without being killed by these signals. This behavior can be disabled by `--enable-tty-signals`.

## The runtime files:
### Mounts:
- /sys will be mounted as sysfs.
- /proc will be mounted as procfs.
- /dev will be mounted as tmpfs.
- /dev/pts will be mounted as devpts.
- /dev/shm will be mounted as tmpfs.
### Devices:
ruri will automatically create these devices in the container:
```console
/ # tree /dev
/dev
├── console
├── fd -> /proc/self/fd
├── net
│   └── tun
├── null
├── ptmx
├── pts
│   └── ptmx
├── random
├── shm
├── stderr -> /proc/self/fd/2
├── stdin -> /proc/self/fd/0
├── stdout -> /proc/self/fd/1
├── tty
├── tty0 -> /dev/null
├── urandom
└── zero
```
### Masked paths:
And, some path will be masked by ruri, unless `--unmask-dirs` is set, for details, see init_container() in src/chroot.c and init_rootless_container() in src/rootless.c.
### Customizable behavior:
You can use `-j` option to disable mounting/creating these files.      
You can use `-I` option to create a custom character device in /dev.   #Note: rootless container will not support this option.     
You can use `-m` option to mount custom source from host.    
## Noteable file changes:
- /.rurienv is managed by ruri, you should not try to edit or remove it.
- /qemu-ruri will be created by ruri if `-q` option is set, and the path of qemu binary is on host but not in container.
- /etc/mtab is a symlink to /proc/mounts, ruri will always create this file unless `-j` option is set.
