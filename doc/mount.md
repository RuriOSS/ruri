# Mount Option

`ruri` supports mounting various types of resources into the container, with advanced mount types and flags.

## Syntax

```
-m [source] [target]
-M [source] [target]
```

- `-m`: Mount a resource at the specified target path.
- `-M`: Same as `-m`, but enforces read-only. In the new version, you can also use the `RDONLY:` prefix instead.

The target path is always interpreted relative to the container's filesystem (not the host). If the target does not exist in the container, it will be created automatically.

## Source Types

Depending on the type of source, different mount strategies are applied:

1. **Directory**  
    If the source is a directory on the host, it will be bind-mounted into the container at the target.

2. **Image File**  
    If the source is a regular file recognized as a disk image, it will be mounted via a loop device at the target.

3. **Block Device**  
    If the source is a block device (e.g., `/dev/sdb1`), it will be mounted directly at the target.

4. **Other Regular Files**  
    If the source is a file that is not a recognized image, it will be bind-mounted as a file at the target.

5. **Special Mount Sources**
    - **tmpfs**  
      Specify with format:  
      ```
      TMPFS:size=[size]
      ```
      Mounts a tmpfs at the target with the given size (e.g., `TMPFS:size=100M`).  
      Note: The size can be specified in bytes, kilobytes (K), megabytes (M), or gigabytes (G).  
      `TMPFS:` without size defaults to kernel behavior.  

    - **overlayfs**  
      Specify with format:  
      ```
      OVERLAY:lowerdir=/path/to/lower,upperdir=/path/to/upper,workdir=/path/to/work
      ```
      Mounts an overlay filesystem at the target using the specified options.
    - **filesystem**  
      - **EXT4:** Mounts an ext4 filesystem at the target.
      - **FAT32:** Mounts a FAT32 (vfat) filesystem at the target.
      - **NTFS:** Mounts an NTFS filesystem at the target.
      - **XFS:** Mounts an XFS filesystem at the target.
      - **BTRFS:** Mounts a Btrfs filesystem at the target.
      - **EXFAT:** Mounts an exFAT filesystem at the target.
      - **F2FS:** Mounts an F2FS filesystem at the target.
      - **EROFS:** Mounts an EROFS filesystem at the target.

      **Example:**
        ```
        -m EXT4:/dev/sdb1 /mnt/data
        ```
        This mounts `/dev/sdb1` as an ext4 filesystem at `/mnt/data`.
## Behavior:
For image files and block devices, if the filesystem type is not specified in prefix, ruri will attempt to auto-detect the filesystem type by trying all `nodev` filesystems in your `/proc/filesystems`.  
## Mount Flags

Mount flags can be set using prefixes in the source string. Prefixes are colon-separated.

**Example:**
```
-m RDONLY:NOEXEC:/dev/sdb1 /mnt/disk
```
This mounts `/dev/sdb1` at `/mnt/disk` as read-only and with the `noexec` flag enabled.

### Supported Flags

| Prefix      | Description                                 |
|-------------|---------------------------------------------|
| RDONLY      | Mount read-only (same as `-M`)              |
| NOSUID      | Do not allow set-user-ID or set-group-ID    |
| NOEXEC      | Do not allow execution of binaries          |
| NODIRATIME  | Do not update directory access times        |
| NOATIME     | Do not update access times                  |
| SYNCHRONOUS | Writes are synced immediately               |
| DIRSYNC     | Directory updates are synchronous           |
| MANDLOCK    | Enable mandatory locking                    |
| RELATIME    | Update access time relative to modification |
| SLAVE       | Make mount a slave in shared subtree        |
| SHARED      | Make mount a shared subtree                 |
| PRIVATE     | Make mount private                          |
| UNBINDABLE  | Prevent remounting elsewhere                |
| SILENT      | Suppress mount errors in logs (if supported)|
| POSIXACL    | Enable POSIX ACLs                           |
| LAZYTIME    | Delay access/modify time updates            |

**Notes:**
- Prefixes are order-insensitive but must be placed before the source path.
- If the source does not exist or cannot be recognized, the mount will fail.
- To ensure container isolation and prevent security risks, custom mounting of special filesystems such as `proc`, `sysfs`, `debugfs`, or similar filesystems is not permitted. If required, you can manually modify the implementation of `mount_other_type()` in `src/mount.c`.
