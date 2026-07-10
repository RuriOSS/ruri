cd ${TEST_ROOT}
source global.sh

export TEST_NO=1
export DESCRIPTION="This is ruri basic test"
show_test_description

export SUBTEST_NO=1
export SUBTEST_DESCRIPTION="Chroot container with no args"
show_subtest_description
cd ${TMPDIR}
./ruri ./test /bin/echo -e "${BASE}==> Running echo command in container"
check_if_succeed $?
if ! mountpoint -q ./test/sys; then
    error "Seems that container did not mounted properly!"
fi
pass_subtest

export SUBTEST_NO=2
export SUBTEST_DESCRIPTION="Umount container"
show_subtest_description
cd ${TMPDIR}
./ruri -U ./test
check_if_succeed $?
if mountpoint -q ./test/sys; then
    error "Seems that container did not unmounted properly!"
fi
if mountpoint -q ./test/dev; then
    error "Seems that container did not unmounted properly!"
fi
if mountpoint -q ./test/proc; then
    error "Seems that container did not unmounted properly!"
fi
if mountpoint -q ./test; then
    error "Seems that container did not unmounted properly!"
fi
echo -e "${BASE}==> Container unmounted successfully"
pass_subtest

export SUBTEST_NO=3
export SUBTEST_DESCRIPTION="Chroot container with -m option"
show_subtest_description
cd ${TMPDIR}
./ruri -m /tmp /tm ./test /bin/echo -e "${BASE}==> Running echo command in container"
check_if_succeed $?
if ! mountpoint -q ./test/tm; then
    error "mount /tmp to /tm failed!"
fi
echo -e "${BASE}==> /tmp mount to /tm successfully"
pass_subtest

export SUBTEST_NO=4
export SUBTEST_DESCRIPTION="Umount container with extra mountpoint /tm"
show_subtest_description
cd ${TMPDIR}
./ruri -U ./test
check_if_succeed $?
if mountpoint -q ./test/tm; then
    error "Umount /tm failed!"
fi
echo -e "${BASE}==> umount /tm successfully"
pass_subtest

export SUBTEST_NO=5
export SUBTEST_DESCRIPTION="Test unshare container"
show_subtest_description
cd ${TMPDIR}
./ruri -U ./test
./ruri -u ./test dd if=/dev/zero of=/nullfile bs=1M count=1
if [[ ! -e test/nullfile ]]; then
    error "File /nullfile does not exist!"
fi
if [[ $(stat -c %s test/nullfile) -ne 1048576 ]]; then
    error "File /nullfile size is not 1M!"
fi
echo -e "${BASE}==> unshare container create /nullfile in container successfully"
pass_subtest

pass_test
