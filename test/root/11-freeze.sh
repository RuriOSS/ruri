cd ${TEST_ROOT}
source global.sh

export TEST_NO=11
export DESCRIPTION="Test if --freeze/--thaw options work properly"
show_test_description

run_freeze_test() {
    # Skip if no cgroup freezer is available on this host
    # (cgroup v2 freezer, v1 at /sys/fs/cgroup/freezer, or Android /dev/freezer).
    if [[ ! -f /sys/fs/cgroup/cgroup.controllers ]] || ! grep -qw freezer /sys/fs/cgroup/cgroup.controllers 2>/dev/null; then
        if [[ ! -f /sys/fs/cgroup/freezer/freezer.state && ! -f /dev/freezer/freezer.state ]]; then
            echo -e "${YELLOW}cgroup freezer controller not available, skipping test #${TEST_NO}${CLEAR}"
            return 0
        fi
    fi

    export SUBTEST_NO=1
    export SUBTEST_DESCRIPTION="--freeze/--thaw with chroot container"
    show_subtest_description
    cd ${TMPDIR}
    cat <<EOF >test/test.sh
#!/bin/sh
# Write a counter file so we can observe the process is actually paused.
i=0
while true; do
    echo \$i > /tmp/freeze_counter
    i=\$((i + 1))
    sleep 0.2
done
EOF
    chmod +x test/test.sh

    # Mount a tmpfs so the counter file does not collide with the host.
    mkdir -p test/tmp
    ./ruri -m tmpfs tmp -o test/tmp /bin/sh /test.sh &
    sleep 1

    # Freeze the container.
    ./ruri --freeze ./test
    check_if_succeed $?
    sleep 1
    before=$(cat test/tmp/freeze_counter 2>/dev/null || echo "missing")
    sleep 2
    after=$(cat test/tmp/freeze_counter 2>/dev/null || echo "missing")
    if [[ "${before}" != "${after}" ]]; then
        error "container was not frozen, counter moved from ${before} to ${after}"
    fi
    echo -e "${BASE}==> --freeze paused the container${CLEAR}"

    # Thaw the container.
    ./ruri --thaw ./test
    check_if_succeed $?
    sleep 1
    before=$(cat test/tmp/freeze_counter 2>/dev/null || echo "missing")
    sleep 2
    after=$(cat test/tmp/freeze_counter 2>/dev/null || echo "missing")
    if [[ "${before}" == "${after}" ]]; then
        error "container was not thawed, counter stayed at ${before}"
    fi
    echo -e "${BASE}==> --thaw resumed the container${CLEAR}"

    # Cleanup.
    ./ruri -P ./test | awk '{print $1}' | xargs kill -9 2>/dev/null
    ./ruri -U ./test >/dev/null 2>&1
    echo -e "${BASE}==> --freeze/--thaw passed!${CLEAR}\n"
    pass_subtest

    pass_test
}

run_freeze_test
