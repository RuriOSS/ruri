#include <stdbool.h>
#include <stdio.h>

bool ruri_test_is_submount(const char *dir, const char *mount_point);
bool ruri_test_should_use_mnt_force(const char *mnt_type);

static int expect_true(bool value, const char *message)
{
	if (value) {
		return 0;
	}
	fprintf(stderr, "failed: %s\n", message);
	return 1;
}

static int expect_false(bool value, const char *message)
{
	return expect_true(!value, message);
}

int main(void)
{
	int ret = 0;
	ret += expect_true(ruri_test_is_submount("/mnt/data/var/rootfs", "/mnt/data/var/rootfs"), "equal mountpoint should match");
	ret += expect_true(ruri_test_is_submount("/mnt/data/var/rootfs", "/mnt/data/var/rootfs/proc"), "subdir mountpoint should match");
	ret += expect_false(ruri_test_is_submount("/mnt/data/var/rootfs", "/mnt/data/var/rootfs2"), "prefix-only mountpoint should not match");
	ret += expect_false(ruri_test_is_submount("/mnt/data/var/rootfs", "/mnt/data/var"), "parent mountpoint should not match");
	ret += expect_false(ruri_test_is_submount("/mnt/data/var/rootfs", "/mnt/data/var/root"), "sibling mountpoint should not match");

	ret += expect_false(ruri_test_should_use_mnt_force("fuse"), "fuse should not use MNT_FORCE");
	ret += expect_false(ruri_test_should_use_mnt_force("fuse.ext4"), "fuse.* should not use MNT_FORCE");
	ret += expect_true(ruri_test_should_use_mnt_force("tmpfs"), "non-fuse should keep MNT_FORCE");
	return ret;
}
