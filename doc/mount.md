# Mount Option

Ruri supports mounting various types of resources into the container, with advanced mount types and flags.

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
    **NOTE:** You can use `BIND:` prefix to force bind-mounting a regular file instead of trying to mount it as an image.

3. **Block Device**  
    If the source is a block device (e.g., `/dev/sdb1`), it will be mounted directly at the target.

4. **Other Regular Files**  
    If the source is a file that is not a recognized image, or if it has `BIND:` prefix, it will be bind-mounted as a file at the target.

5. **Special Mount Sources**
    - **tmpfs**  
      Specify with format:  
      ```
      TMPFS:size=[size]
      ```
      Mounts a tmpfs at the target with the given size (e.g., `TMPFS:size=100M`).  
      Note: The size can be specified in bytes, kilobytes (K), megabytes (M), or gigabytes (G).  
      `TMPFS:` without size defaults to kernel behavior.  
      For example:
      ```
      -m NOSUID:NODEV:NOEXEC:TMPFS:size=100M /tmp
      ```
      **NOTE:** If you mount TMPFS as rootfs, ruri will create a .ruri_wait file in it, you should extract the rootfs to container_dir and then remove the .ruri_wait file, so ruri will continue to run the container. 

      A real example is:
      ```
      [moe-hacker@fedora ruri]$ sudo ./ruri -M TMPFS: / --set-flag new_tty ../root
      // Container is now frozen, and tmpfs is ready in ../root.

      // Then, in another terminal:
      [moe-hacker@fedora ruri]$ sudo tar -xf ../rootfs.tar.xz -C ../root
      [moe-hacker@fedora ruri]$ sudo rm ../root/.ruri_wait 
      
      // Now, the container will continue to run.
      [moe-hacker@fedora ruri]$ sudo ./ruri -M TMPFS: / --set-flag new_tty ../root
      / # 
      ```

    - **overlayfs**  
      Specify with format:  
      ```
      OVERLAY:lowerdir=/path/to/lower,upperdir=/path/to/upper,workdir=/path/to/work
      ```
      Mounts an overlay filesystem at the target using the specified options.
      - **Volatile rootfs**
        You can create a tmpfs overlay for rootfs, and all changes will be lost after the container stops.
        ```
        root@studio:/home/moehacker/ruri# mkdir /tmp/ruri
        root@studio:/home/moehacker/ruri# mount -t tmpfs tmpfs /tmp/ruri
        root@studio:/home/moehacker/ruri# mkdir /tmp/ruri/upper
        root@studio:/home/moehacker/ruri# mkdir /tmp/ruri/work
        root@studio:/home/moehacker/ruri# ./ruri -m OVERLAY:lowerdir=/home/moehacker/alpine,upperdir=/tmp/ruri/upper,workdir=/tmp/ruri/work / /tmp/ruri/work
        ```
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

      **NOTE:**
        For btrfs, you can use two colons to specify additional arguments: `BTRFS::args::[SOURCE]` to specify additional mount options. For example:
        ```
        -m BTRFS::subvol=/my_subvolume::/dev/sdb1 /
        ```
        A real example is:
        ```
        [moe-hacker@fedora ruri]$ sudo ./ruri -m NOATIME:BTRFS::nodatasum,nodatacow,ssd,discard,space_cache=v2,subvolid=261,subvol=/scon/containers/01KS7GR8N0JHVFEXEDVDJCFDAT::/dev/vdb1 /mnt ../ubuntu/
        root@fedora:~# ls /mnt/rootfs/
        Applications  Users    afs  boot  etc   lib    media  opt      proc  run   srv  tmp  var
        Library       Volumes  bin  dev   home  lib64  mnt    private  root  sbin  sys  usr
        root@fedora:~# 
        ```
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
| NODEV       | Do not interpret character or block devices |
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
| BIND        | Bind mount the source to the target         |

**Notes:**
- Prefixes are order-insensitive but must be placed before the source path.
- If the source does not exist or cannot be recognized, the mount will fail.
- To ensure container isolation and prevent security risks, custom mounting of special filesystems such as `proc`, `sysfs`, `debugfs`, or similar filesystems is not permitted. If required, you can manually modify the implementation of `mount_other_type()` in `src/mount.c`.
# Prefix order:
- Mount flags (e.g., `RDONLY`, `NOEXEC`, etc.)
- Filesystem type (e.g., `EXT4`, `FAT32`, etc.)
- Source path (e.g., `/dev/sdb1`, `image.img`, etc.)

The order should be: `[FLAGS]:[FSTYPE:][SOURCE]`, cannot be mixed. For example, `RDONLY:EXT4:/dev/sdb1` is valid, but `EXT4:RDONLY:/dev/sdb1` is not.
# NOTE:
If you have a dir called `./RDONLY:/tmp` or something like that, ruri might mount it instead of `read-only /tmp`, then you should remove your brain.      