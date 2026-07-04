/*
 * This file is part of ruri.
 * Just some compatibility definitions and macros.
 * This file contains no copyrightable information.
 */
// Bool!!!
#if __STDC_VERSION__ < 202000L
#ifndef bool
#define bool _Bool
#define true ((_Bool)1u)
#define false ((_Bool)0u)
#endif
#endif
// Fix definition of HOST_NAME_MAX
#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 64
#endif
// Fix definition of LOGIN_NAME_MAX
#ifndef LOGIN_NAME_MAX
#define LOGIN_NAME_MAX 256
#endif
// Fix definition of CGROUP2_SUPER_MAGIC
#ifndef CGROUP2_SUPER_MAGIC
#define CGROUP2_SUPER_MAGIC 0x63677270
#endif
// Fix definition of TMPFS_MAGIC
#ifndef TMPFS_MAGIC
#define TMPFS_MAGIC 0x01021994
#endif
// Fix definition of PROC_SUPER_MAGIC
#ifndef PROC_SUPER_MAGIC
#define PROC_SUPER_MAGIC 0x9fa0
#endif
// Fix definition of IORING_REGISTER_CLONE_BUFFERS
#ifndef IORING_REGISTER_CLONE_BUFFERS
#define IORING_REGISTER_CLONE_BUFFERS 30
#endif
// Fix definition of AF_IB
#ifndef AF_IB
#define AF_IB 27
#endif
// Fix definition of AF_MPLS
#ifndef AF_MPLS
#define AF_MPLS 28
#endif
// Fix definition of SOCK_TYPE_MASK
#ifndef SOCK_TYPE_MASK
#define SOCK_TYPE_MASK 0xff
#endif
// Fix definition of SCMP_ARCH_LOONGARCH64
#ifndef AUDIT_ARCH_LOONGARCH64
#ifndef EM_LOONGARCH
#define EM_LOONGARCH 258
#endif /* EM_LOONGARCH */
#define AUDIT_ARCH_LOONGARCH64 (EM_LOONGARCH | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE)
#endif /* AUDIT_ARCH_LOONGARCH64 */
#ifndef SCMP_ARCH_LOONGARCH64
#define SCMP_ARCH_LOONGARCH64 AUDIT_ARCH_LOONGARCH64
#endif /* SCMP_ARCH_LOONGARCH64 */
// Nullability attributes.
#ifndef _Nullable
#define _Nullable
#endif
#ifndef _Nonnull
#define _Nonnull
#endif
// Bionic does not have memfd_create()
#ifdef __ANDROID__
#define memfd_create(...) syscall(SYS_memfd_create, __VA_ARGS__)
#endif