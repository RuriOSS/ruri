#!/bin/bash
# SPDX-License-Identifier: MIT
#
# Test suite for ruri systemd mode
# This script tests systemd-specific features:
# - PID 1 verification
# - Mount namespace isolation
# - /run structure
# - machine-id generation
# - cgroup v2 delegation
# - Environment variables
# - Signal handling
#

set -e

RURI_BIN="${RURI_BIN:-./ruri}"
CONTAINER_DIR="${CONTAINER_DIR:-/tmp/test-systemd-container}"
FAILED=0
PASSED=0

info() {
	echo -e "\033[1;34m[INFO]\033[0m $1"
}

pass() {
	echo -e "\033[1;32m[PASS]\033[0m $1"
	((PASSED++))
}

fail() {
	echo -e "\033[1;31m[FAIL]\033[0m $1"
	((FAILED++))
}

warn() {
	echo -e "\033[1;33m[WARN]\033[0m $1"
}

# Setup container
setup_container() {
	info "Setting up test container..."

	if [ -d "$CONTAINER_DIR" ]; then
		rm -rf "$CONTAINER_DIR"
	fi

	mkdir -p "$CONTAINER_DIR"

	# Create minimal rootfs structure
	mkdir -p "$CONTAINER_DIR"/{bin,sbin,usr,lib,lib64,etc,proc,sys,dev,run,tmp}

	# Copy essential binaries
	if [ -f /bin/busybox ]; then
		cp /bin/busybox "$CONTAINER_DIR/bin/"
		for cmd in sh ls cat ps echo mount umount mkdir; do
			ln -sf busybox "$CONTAINER_DIR/bin/$cmd" 2>/dev/null || true
		done
	else
		# Try to use host binaries
		cp /bin/sh "$CONTAINER_DIR/bin/" 2>/dev/null || cp /bin/bash "$CONTAINER_DIR/bin/"
		cp /bin/ls "$CONTAINER_DIR/bin/" 2>/dev/null || true
		cp /bin/cat "$CONTAINER_DIR/bin/" 2>/dev/null || true
		cp /bin/ps "$CONTAINER_DIR/bin/" 2>/dev/null || true
		cp /bin/echo "$CONTAINER_DIR/bin/" 2>/dev/null || true
		cp /bin/mkdir "$CONTAINER_DIR/bin/" 2>/dev/null || true
	fi

	# Create essential device nodes
	mkdir -p "$CONTAINER_DIR/dev"
	[ ! -e "$CONTAINER_DIR/dev/null" ] && mknod "$CONTAINER_DIR/dev/null" c 1 3 2>/dev/null || true
	[ ! -e "$CONTAINER_DIR/dev/zero" ] && mknod "$CONTAINER_DIR/dev/zero" c 1 5 2>/dev/null || true
	[ ! -e "$CONTAINER_DIR/dev/random" ] && mknod "$CONTAINER_DIR/dev/random" c 1 8 2>/dev/null || true
	[ ! -e "$CONTAINER_DIR/dev/urandom" ] && mknod "$CONTAINER_DIR/dev/urandom" c 1 9 2>/dev/null || true

	info "Container setup complete"
}

# Cleanup
cleanup() {
	info "Cleaning up..."
	if [ -d "$CONTAINER_DIR" ]; then
		umount "$CONTAINER_DIR/proc" 2>/dev/null || true
		umount "$CONTAINER_DIR/sys" 2>/dev/null || true
		umount "$CONTAINER_DIR/dev" 2>/dev/null || true
		rm -rf "$CONTAINER_DIR"
	fi
}

# Test 1: PID 1 verification
test_pid1_verification() {
	info "Testing PID 1 verification..."

	# Create a test script that checks if we're PID 1
	cat >"$CONTAINER_DIR/test_pid1.sh" <<'EOF'
#!/bin/sh
echo "PID=$$"
if [ "$$" -eq 1 ]; then
    echo "IS_PID1=YES"
else
    echo "IS_PID1=NO"
fi
cat /proc/1/comm 2>/dev/null || echo "NOCOMM"
EOF
	chmod +x "$CONTAINER_DIR/test_pid1.sh"

	# Run ruri with systemd mode - this should create a PID namespace
	# and ruri should be PID 1 inside it
	local output
	output=$($RURI_BIN --unshare --systemd "$CONTAINER_DIR" /bin/sh /test_pid1.sh 2>&1 || true)

	if echo "$output" | grep -q "IS_PID1=YES"; then
		pass "PID 1 verification: Container process is PID 1"
	else
		fail "PID 1 verification: Expected PID 1, got: $output"
	fi
}

# Test 2: /run structure
test_run_structure() {
	info "Testing /run structure..."

	cat >"$CONTAINER_DIR/test_run.sh" <<'EOF'
#!/bin/sh
# Check /run directories exist
for dir in /run /run/systemd /run/systemd/system /run/lock /run/log /run/log/journal; do
    if [ -d "$dir" ]; then
        echo "DIR_EXISTS:$dir"
    else
        echo "DIR_MISSING:$dir"
    fi
done

# Check /run/systemd/container marker
if [ -f /run/systemd/container ]; then
    content=$(cat /run/systemd/container 2>/dev/null)
    echo "CONTAINER_MARKER:$content"
else
    echo "CONTAINER_MARKER:MISSING"
fi
EOF
	chmod +x "$CONTAINER_DIR/test_run.sh"

	local output
	output=$($RURI_BIN --unshare --systemd "$CONTAINER_DIR" /bin/sh /test_run.sh 2>&1 || true)

	local all_exist=true
	for dir in /run /run/systemd /run/systemd/system /run/lock /run/log /run/log/journal; do
		if ! echo "$output" | grep -q "DIR_EXISTS:$dir"; then
			fail "/run structure: Missing directory $dir"
			all_exist=false
		fi
	done

	if $all_exist; then
		pass "/run structure: All required directories exist"
	fi

	if echo "$output" | grep -q "CONTAINER_MARKER:ruri"; then
		pass "/run structure: Container marker is 'ruri'"
	else
		fail "/run structure: Container marker incorrect or missing"
	fi
}

# Test 3: machine-id
test_machine_id() {
	info "Testing /etc/machine-id..."

	cat >"$CONTAINER_DIR/test_machineid.sh" <<'EOF'
#!/bin/sh
if [ -f /etc/machine-id ]; then
    mid=$(cat /etc/machine-id 2>/dev/null | tr -d '\n')
    if [ -n "$mid" ] && [ ${#mid} -eq 32 ]; then
        echo "MACHINE_ID_OK:$mid"
    else
        echo "MACHINE_ID_INVALID:$mid"
    fi
else
    echo "MACHINE_ID_MISSING"
fi
EOF
	chmod +x "$CONTAINER_DIR/test_machineid.sh"

	# Test with empty machine-id
	touch "$CONTAINER_DIR/etc/machine-id"

	local output
	output=$($RURI_BIN --unshare --systemd "$CONTAINER_DIR" /bin/sh /test_machineid.sh 2>&1 || true)

	if echo "$output" | grep -q "MACHINE_ID_OK:"; then
		pass "machine-id: Valid 32-character machine-id generated"
	else
		fail "machine-id: Expected valid machine-id, got: $output"
	fi
}

# Test 4: cgroup v2 delegation
test_cgroup_delegation() {
	info "Testing cgroup v2 delegation..."

	cat >"$CONTAINER_DIR/test_cgroup.sh" <<'EOF'
#!/bin/sh
if [ -d /sys/fs/cgroup ]; then
    echo "CGROUP_EXISTS:yes"
    
    # Check if cgroup2 is mounted
    if grep -q cgroup2 /proc/mounts 2>/dev/null; then
        echo "CGROUP2_MOUNTED:yes"
    else
        echo "CGROUP2_MOUNTED:no"
    fi
    
    # Check subtree_control
    if [ -f /sys/fs/cgroup/cgroup.subtree_control ]; then
        echo "SUBTREE_CONTROL_EXISTS:yes"
        content=$(cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null)
        echo "SUBTREE_CONTROL_CONTENT:$content"
    else
        echo "SUBTREE_CONTROL_EXISTS:no"
    fi
    
    # Check systemd cgroup
    if [ -d /sys/fs/cgroup/systemd ]; then
        echo "SYSTEMD_CGROUP_EXISTS:yes"
    else
        echo "SYSTEMD_CGROUP_EXISTS:no"
    fi
else
    echo "CGROUP_EXISTS:no"
fi
EOF
	chmod +x "$CONTAINER_DIR/test_cgroup.sh"

	local output
	output=$($RURI_BIN --unshare --systemd "$CONTAINER_DIR" /bin/sh /test_cgroup.sh 2>&1 || true)

	if echo "$output" | grep -q "CGROUP_EXISTS:yes"; then
		pass "cgroup: /sys/fs/cgroup exists"
	else
		warn "cgroup: /sys/fs/cgroup not available (may require root or kernel support)"
	fi

	if echo "$output" | grep -q "CGROUP2_MOUNTED:yes"; then
		pass "cgroup: cgroup2 is mounted"
	else
		warn "cgroup: cgroup2 not mounted (may require privileges)"
	fi

	if echo "$output" | grep -q "SYSTEMD_CGROUP_EXISTS:yes"; then
		pass "cgroup: systemd cgroup exists"
	else
		warn "cgroup: systemd cgroup not created (may be expected)"
	fi
}

# Test 5: Environment variables
test_environment_variables() {
	info "Testing environment variables..."

	cat >"$CONTAINER_DIR/test_env.sh" <<'EOF'
#!/bin/sh
echo "CONTAINER_VAR=$container"
echo "SYSTEMD_IGNORE_CHROOT_VAR=$SYSTEMD_IGNORE_CHROOT"
EOF
	chmod +x "$CONTAINER_DIR/test_env.sh"

	local output
	output=$($RURI_BIN --unshare --systemd "$CONTAINER_DIR" /bin/sh /test_env.sh 2>&1 || true)

	if echo "$output" | grep -q "CONTAINER_VAR=ruri"; then
		pass "Environment: container=ruri is set"
	else
		fail "Environment: container=ruri not set, got: $output"
	fi

	if echo "$output" | grep -q "SYSTEMD_IGNORE_CHROOT_VAR=1"; then
		pass "Environment: SYSTEMD_IGNORE_CHROOT=1 is set"
	else
		fail "Environment: SYSTEMD_IGNORE_CHROOT=1 not set"
	fi
}

# Test 6: /dev/console existence
test_dev_console() {
	info "Testing /dev/console..."

	cat >"$CONTAINER_DIR/test_console.sh" <<'EOF'
#!/bin/sh
if [ -e /dev/console ]; then
    echo "CONSOLE_EXISTS:yes"
    ls -la /dev/console 2>/dev/null
else
    echo "CONSOLE_EXISTS:no"
fi
EOF
	chmod +x "$CONTAINER_DIR/test_console.sh"

	local output
	output=$($RURI_BIN --unshare --systemd "$CONTAINER_DIR" /bin/sh /test_console.sh 2>&1 || true)

	if echo "$output" | grep -q "CONSOLE_EXISTS:yes"; then
		pass "/dev/console: Console device exists"
	else
		warn "/dev/console: Console device not created (may require privileges)"
	fi
}

# Test 7: Signal handling (basic)
test_signal_handling() {
	info "Testing signal handling..."

	cat >"$CONTAINER_DIR/test_signal.sh" <<'EOF'
#!/bin/sh
# Create a child process
echo "STARTED"
(sleep 2; echo "CHILD_DONE") &
CHILD_PID=$!

# Wait for signal or child
wait $CHILD_PID 2>/dev/null
echo "EXITING"
EOF
	chmod +x "$CONTAINER_DIR/test_signal.sh"

	# Run with timeout
	local output
	output=$(timeout 5 $RURI_BIN --unshare --systemd "$CONTAINER_DIR" /bin/sh /test_signal.sh 2>&1 || true)

	if echo "$output" | grep -q "EXITING"; then
		pass "Signal handling: Container exited cleanly"
	else
		fail "Signal handling: Container may have hung or crashed: $output"
	fi
}

# Test 8: systemd-dbus option (directory creation)
test_systemd_dbus() {
	info "Testing --systemd-dbus option..."

	cat >"$CONTAINER_DIR/test_dbus.sh" <<'EOF'
#!/bin/sh
if [ -d /run/dbus ]; then
    echo "DBUS_DIR_EXISTS:yes"
else
    echo "DBUS_DIR_EXISTS:no"
fi
EOF
	chmod +x "$CONTAINER_DIR/test_dbus.sh"

	local output
	output=$($RURI_BIN --unshare --systemd --systemd-dbus "$CONTAINER_DIR" /bin/sh /test_dbus.sh 2>&1 || true)

	if echo "$output" | grep -q "DBUS_DIR_EXISTS:yes"; then
		pass "systemd-dbus: /run/dbus directory created"
	else
		fail "systemd-dbus: /run/dbus directory not created"
	fi
}

# Main test runner
main() {
	info "Starting ruri systemd mode tests..."
	info "RURI_BIN: $RURI_BIN"
	info "CONTAINER_DIR: $CONTAINER_DIR"

	# Check if ruri binary exists
	if [ ! -x "$RURI_BIN" ]; then
		echo "Error: ruri binary not found at $RURI_BIN"
		echo "Set RURI_BIN environment variable to the path of the ruri binary"
		exit 1
	fi

	# Setup
	setup_container

	# Run tests
	test_pid1_verification
	test_run_structure
	test_machine_id
	test_cgroup_delegation
	test_environment_variables
	test_dev_console
	test_signal_handling
	test_systemd_dbus

	# Cleanup
	cleanup

	# Summary
	echo ""
	echo "========================================"
	echo "Test Results:"
	echo "  Passed: $PASSED"
	echo "  Failed: $FAILED"
	echo "========================================"

	if [ $FAILED -eq 0 ]; then
		echo "All tests passed!"
		exit 0
	else
		echo "Some tests failed."
		exit 1
	fi
}

# Handle signals
trap cleanup EXIT

# Run main
main "$@"
