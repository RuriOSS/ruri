![](https://github.com/rurioss/ruri/raw/main/logo/logo.png)

---

<p align="center">「 须臾水面明月出，沧江万顷琉璃寒 」</p>

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.14021121.svg)](https://doi.org/10.5281/zenodo.14021121) [![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/RuriOSS/ruri)

![](https://img.shields.io/badge/backward-compatible-00d000?style=flat&labelColor=gray)
![](https://img.shields.io/badge/Powered%20By-GNU%20C-00d000?style=flat&labelColor=gray&logo=C)

[![Build release](https://github.com/RuriOSS/ruri/actions/workflows/build.yml/badge.svg)](https://github.com/RuriOSS/ruri/actions/workflows/build.yml) [![Run autotest](https://github.com/RuriOSS/ruri/actions/workflows/test.yml/badge.svg)](https://github.com/RuriOSS/ruri/actions/workflows/test.yml)

# Backward compatibility:
We promise that ruri has backward compatibility of cli usage and config file since v3.9.0, you can keep updated to the newest version. Any breaking changes will not be introduced to v3.9.x

# Important Notice:
It's fully recommended to drop CAP_SYS_CHROOT or enable unshare, chroot container without these options is not secure at all!

*Update: Considering the security issues of chroot, ruri will drop CAP_SYS_CHROOT by default now  
If you got any issues with this, please report.

# WARNING

For production, I fully recommand you to use tools like [crun](https://github.com/containers/crun), [youki](https://github.com/youki-dev/youki), [containerd](https://containerd.io/), [docker](https://www.docker.com/), [podman](https://podman.io/), [LXC](https://linuxcontainers.org/), [bubblewrap](https://github.com/containers/bubblewrap), they are more secure and stable. This is a non-OCI tool and, you take your own risk using it when you really need. The whole project is experimental!
```
* Your warranty is void.
* I am not responsible for anything that may happen to your device by using this program.
* You do it at your own risk and take the responsibility upon yourself.
* This project is open source, you can make your own fork/rewrite but not to blame the author.
* This program has no Super Cow Powers.
```

# Bug reporting

If you think something does not work as expected, please [open a new isssue](https://github.com/rurioss/ruri/issues)

# WIP wiki

https://wiki.crack.moe/ruri

# Asking LLM:
See [Asking LLM](doc/askllm.md) for how to ask LLM about ruri.

# About:

&emsp;Was a toy, to be a tool.    
&emsp;ruri is pronounced as `luli`, or you can call it `[瑠璃/琉璃]` ~~(るり)~~ in Chinese or Japanese as well.    
&emsp;ruri is acronym to Lightweight, User-friendly Linux-container Implementation.    
&emsp;ruri is a powerful container implementation that runs on almost any Linux device, even with incomplete kernel configurations or minimal storage space.    

# The enhanced version

[rurima](https://github.com/Moe-hacker/rurima) was planned to be the ruri manager, but since it now has a full integration of ruri, you can use it as an enhanced version of ruri.
Note that rurima is still WIP.

# Highlights

- **Powerful Features**
  - Supports chroot, unshare with pivot_root, capability control, cgroups, no_new_privs, environment/user/workdir setup, seccomp, and more.
  - Built-in binfmt_misc & QEMU for easy multi-arch containers.
  - Rootless mode (requires user namespaces).
  - Flexible mount options: mount images/partitions, set mountpoints as read-only or rw.
  - Config file support.

- **Ultra-lightweight & Zero Dependencies**
  - Only optional `uidmap` needed for rootless mode; all other features are built-in.
  - Statically linked binaries for many architectures.
  - Very small binary size (even <200k with upx), yet over 30 options.

- **Flexible & Cross-platform**
  - Runs on rooted Android, IoT, amd64, s390x, and more, just needs root.

- **Secure by Design**
  - Rootless containers, security options, and read-only filesystem support.

- **Simple for Beginners**
  - Can replace `chroot` directly; easy to use without learning every option.

  <p align="center">
  <img src="https://github.com/Moe-hacker/ruri/raw/main/logo/rurifetch.png" alt="" style="width:75%;align: center;">
  </p>


# Get ruri

You can get ruri binary (statically linked) for arm64, armv7, armhf, riscv64, i386, loong64, s390x, ppc64le and x86_64 devices in [Release](https://github.com/Moe-hacker/ruri/releases/).
Or you can run the following command to download ruri automatically

```sh
. <(curl -sL https://get.ruri.zip/ruri)
```

This will automatically download ruri binary to `./ruri`.

# Usage

See [USAGE](doc/USAGE.md) to explore all features of ruri.

# Container Security

See [Enhance Container Security](doc/Security.md).

# Build Manually

Ruri provides statically linked binary, but if you want to build it yourself, see [Build](doc/Build.md).

# Integration

ruri is ready to integrate into other projects, with the MIT License, it is compatiblte to be redistribute with almost all license, or commercial/closed source.
An example is ruri's own build action , it runs containers for 9 different architectures to build itself, that shows its broad application prospects.
Another example is [rurima](https://github.com/Moe-hacker/rurima), I made ruri built-in for it, so it can be run as a subcommand.
See [Integration](doc/Integration.md) for a guide to integrate ruri into your projects.

# Behavior of rurienv

After initing the container, ruri will create a file /.rurienv by default, this config can unify container config, but it will also cover some of the command-line args, you can use `--no-rurienv` to disable it, or see [rurienv.md](doc/rurienv.md) to see its behavior.
You might cannot remove this file unless you run `chattr -i .rurienv`, but don't worry, after umounting conainer by `ruri -U`, this config file will be removed automatically.
If you want to change the container config, just use -U to umount it and re-run the container.

# FAQ

[FAQ](doc/FAQ.md)

# Quick start(with rurima)

## Download and unpack a rootfs

```
. <(curl -sL https://get.ruri.zip/rurima)
./rurima lxc pull -o alpine -v edge -s /tmp/alpine
```

## Then

```
sudo ruri /tmp/alpine
```
## Setup dns:
In container:    
```shell
rm test/etc/resolv.conf
echo nameserver 1.1.1.1|tee test/etc/resolv.conf
```
## For unshare container

```
sudo ruri -u /tmp/alpine
```

Very simple as you can see.
For command line examples, please see `ruri -H`.

# Example Usage

```
# Run chroot container
  sudo ruri /tmp/alpine

# Very simple as you can see.

# About the capabilities
# Run privileged chroot container
  sudo ruri -p /tmp/alpine

# If you want to run privileged chroot container,
# but you don't want to give the container cap_sys_chroot privileges
  sudo ruri -p -d cap_sys_chroot /tmp/alpine

# If you want to run chroot container with common privileges,
# but you want cap_sys_admin to be kept
  sudo ruri -k cap_sys_admin /tmp/alpine

# About unshare
# Unshare container's capability options are same with chroot.
# Run unshare container
  sudo ruri -u /tmp/alpine

# Finally, umount the container
  sudo ruri -U /tmp/alpine
```
# Performance

On AMD Ryzen 5 5500U, Windows 11, Ubuntu 22.04.5 WSL 2

```
# uname -m
x86_64
# /usr/bin/time -f "Time: %E\nMax memory: %M KB" ./ruri ../t /bin/true
Time: 0:00.01
Max memory: 860 KB
```

## Binary size(amd64)

|           | ruri | crun | %      |
| --------- | ---- | ---- | ------ |
| (noupx)   | 454K | 3.0M | -84.9% |
| (withupx) | 147K | 1.3M | -88.7% |

## ~~Alphabet coverage~~

| Alphabet | ruri used | %   |
| -------- | --------- | --- |
| 52       | 46        | 88% |

# License

License of code

- Licensed under the MIT License
- Copyright (c) 2022-2025 Moe-hacker

License of clang-format config file

- GPL-2.0

---

<p align="center">「 咲誇る花 美しく、</p>
<p align="center">散り行く運命 知りながら、</p>
<p align="center">僅かな時の彩を 」</p>
<p align="center">(>_×)</p>
