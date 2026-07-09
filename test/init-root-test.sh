#!/bin/bash
source global.sh

export TEST_NO=0
export DESCRIPTION="This script is used to create files and directories for testing."
show_test_description

export SUBTEST_NO=1
export SUBTEST_DESCRIPTION="Build ruri"
export TMPDIR=tmpdir-$RANDOM
show_subtest_description
cd ..
mkdir ${TMPDIR}
check_if_succeed $?
export TMPDIR=$(realpath ${TMPDIR})
check_if_succeed $?
cc build.c
./a.out -d -f
cc test/test_pid_file.c -o test_pid_file
check_if_succeed $?
mv ruri ${TMPDIR}/ruri-dev
mv test_pid_file ${TMPDIR}
./a.out -f
mv ruri ${TMPDIR}/ruri-release
cp ${TMPDIR}/ruri-release ${TMPDIR}/ruri
check_if_succeed $?
pass_subtest

export SUBTEST_NO=2
export SUBTEST_DESCRIPTION="Check ruri"
show_subtest_description
cd ${TMPDIR}
./ruri -v
check_if_succeed $?
pass_subtest

export SUBTEST_NO=3
export SUBTEST_DESCRIPTION="Get rootfs.tar.xz"
show_subtest_description
${TEST_ROOT}/rootfstool d -d alpine -v edge
check_if_succeed $?
pass_subtest

export SUBTEST_NO=4
export SUBTEST_DESCRIPTION="Create test.img as rootfs"
show_subtest_description
if [[ -e /tmp/test ]]; then
    rm /tmp/test
fi
if [[ -d /tmp/test ]]; then
    ./ruri -U /tmp/test
    rm -rf /tmp/test
fi
dd if=/dev/zero of=test.img bs=1M count=256
check_if_succeed $?
mkfs.ext4 test.img
check_if_succeed $?
mkdir /tmp/test
check_if_succeed $?
LOOPFILE=$(losetup -f)
losetup ${LOOPFILE} ./test.img
mount ${LOOPFILE} /tmp/test
check_if_succeed $?
tar -xf rootfs.tar.xz -C /tmp/test
check_if_succeed $?
umount -lvf /tmp/test
check_if_succeed $?
pass_subtest

export SUBTEST_NO=5
export SUBTEST_DESCRIPTION="Create test2.img as extra mountpoint"
show_subtest_description
dd if=/dev/zero of=test2.img bs=1M count=256
check_if_succeed $?
mkfs.ext4 test2.img
check_if_succeed $?
LOOPFILE=$(losetup -f)
losetup ${LOOPFILE} ./test2.img
mount ${LOOPFILE} /tmp/test
check_if_succeed $?
touch /tmp/test/test.txt
check_if_succeed $?
echo "x" >/tmp/test/test.txt
check_if_succeed $?
umount -lvf /tmp/test
check_if_succeed $?
pass_subtest

export SUBTEST_NO=6
export SUBTEST_DESCRIPTION="Create ./test as rootfs"
show_subtest_description
mkdir test
check_if_succeed $?
tar -xf rootfs.tar.xz -C test
check_if_succeed $?
pass_subtest

export SUBTEST_NO=7
export SUBTEST_DESCRIPTION="Create ./aarch64 as aarch64 rootfs"
show_subtest_description
mkdir aarch64
check_if_succeed $?
rm rootfs.tar.xz || true
${TEST_ROOT}/rootfstool d -d alpine -v edge -a arm64
check_if_succeed $?
tar -xf rootfs.tar.xz -C aarch64
check_if_succeed $?
pass_subtest

export SUBTEST_NO=8
export SUBTEST_DESCRIPTION="Create ./armhf as armhf rootfs"
show_subtest_description
mkdir armhf
check_if_succeed $?
rm rootfs.tar.xz || true
${TEST_ROOT}/rootfstool d -d alpine -v edge -a armhf
check_if_succeed $?
tar -xf rootfs.tar.xz -C armhf
check_if_succeed $?
pass_subtest

pass_test
