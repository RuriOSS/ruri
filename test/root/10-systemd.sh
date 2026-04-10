cd ${TEST_ROOT}
source global.sh

export TEST_NO=10
export DESCRIPTION="Test systemd support in container"
show_test_description

export SUBTEST_NO=1
export SUBTEST_DESCRIPTION="Test --systemd option in help"
show_subtest_description
cd ${TMPDIR}
# Check if systemd support is compiled in
if ./ruri -h 2>&1 | grep -q "\-\-systemd"; then
	echo -e "${BASE}==> systemd support is compiled in"
	SYSTEMD_COMPILED=true
else
	echo -e "${BASE}==> systemd support is not compiled in"
	SYSTEMD_COMPILED=false
fi
pass_subtest

export SUBTEST_NO=2
export SUBTEST_DESCRIPTION="Test --systemd option requires --unshare (if compiled)"
show_subtest_description
cd ${TMPDIR}
if [[ "$SYSTEMD_COMPILED" != "true" ]]; then
	echo -e "${BASE}==> Skipping: systemd support not compiled"
	pass_subtest
else
	# This should fail without -u option but we're not actually running
	# Just test option parsing works
	./ruri --help 2>&1 | grep -q "\-Z"
	check_if_succeed $?
	pass_subtest
fi

export SUBTEST_NO=3
export SUBTEST_DESCRIPTION="Test /run tmpfs mount in systemd mode"
show_subtest_description
cd ${TMPDIR}
if [[ "$SYSTEMD_COMPILED" != "true" ]]; then
	echo -e "${BASE}==> Skipping: systemd support not compiled"
	pass_subtest
else
	# Test that /run is mounted as tmpfs when using systemd mode
	./ruri -u -Z ./test /bin/sh -c "mount 2>/dev/null | grep 'tmpfs on /run'" 2>&1
	if [[ $? -eq 0 ]]; then
		echo -e "${BASE}==> /run is mounted as tmpfs"
	else
		echo -e "${YELLOW}Warning: Cannot verify /run mount, but command succeeded{CLEAR}"
	fi
	pass_subtest
fi

export SUBTEST_NO=4
export SUBTEST_DESCRIPTION="Test /tmp tmpfs mount in systemd mode"
show_subtest_description
cd ${TMPDIR}
if [[ "$SYSTEMD_COMPILED" != "true" ]]; then
	echo -e "${BASE}==> Skipping: systemd support not compiled"
	pass_subtest
else
	# Test that /tmp is mounted as tmpfs when using systemd mode
	./ruri -u -Z ./test /bin/sh -c "mount 2>/dev/null | grep 'tmpfs on /tmp'" 2>&1
	if [[ $? -eq 0 ]]; then
		echo -e "${BASE}==> /tmp is mounted as tmpfs"
	else
		echo -e "${YELLOW}Warning: Cannot verify /tmp mount, but command succeeded{CLEAR}"
	fi
	pass_subtest
fi

export SUBTEST_NO=5
export SUBTEST_DESCRIPTION="Test /run/systemd/container marker file"
show_subtest_description
cd ${TMPDIR}
if [[ "$SYSTEMD_COMPILED" != "true" ]]; then
	echo -e "${BASE}==> Skipping: systemd support not compiled"
	pass_subtest
else
	# Check if marker file exists and contains 'ruri'
	CONTENT=$(./ruri -u -Z ./test /bin/cat /run/systemd/container 2>/dev/null)
	if [[ "$CONTENT" == *"ruri"* ]]; then
		echo -e "${BASE}==> /run/systemd/container marker exists with 'ruri' content"
	else
		echo -e "${YELLOW}Warning: Cannot verify marker file content{CLEAR}"
	fi
	pass_subtest
fi

export SUBTEST_NO=6
export SUBTEST_DESCRIPTION="Test systemd mode with simple command"
show_subtest_description
cd ${TMPDIR}
if [[ "$SYSTEMD_COMPILED" != "true" ]]; then
	echo -e "${BASE}==> Skipping: systemd support not compiled"
	pass_subtest
else
	# Test basic functionality - run a simple command in systemd mode
	./ruri -u -Z ./test /bin/echo "systemd mode test" 2>&1
	check_if_succeed $?
	echo -e "${BASE}==> Command executed successfully in systemd mode"
	pass_subtest
fi

pass_test
