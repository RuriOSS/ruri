#!/bin/bash
source global.sh

# This will set $TEST_ROOT
export TEST_ROOT=$(pwd)

DESCRIPTION="This is a test script that runs all test scripts."
echo -e "${BASE}Running $0"
echo -e "${BASE}Description:\n${CYAN} ${DESCRIPTION}"
printf "${CLEAR}"
sleep 1

# This will set $TMPDIR
cd ${TEST_ROOT}
source init-root-test.sh
check_if_succeed $?

mv ${TMPDIR}/ruri-release ${TMPDIR}/ruri
# Do all tests
cd ${TEST_ROOT}
for i in $(ls root/*.sh); do
    cd ${TEST_ROOT}
    source $i
    check_if_succeed $?
done

mv ${TMPDIR}/ruri-dev ${TMPDIR}/ruri
# Do all tests
cd ${TEST_ROOT}
for i in $(ls root/*.sh); do
    cd ${TEST_ROOT}
    source $i
    check_if_succeed $?
done

# Clean up
cd ${TEST_ROOT}
source clean.sh

echo -e "${BASE}Passed all root tests!${CLEAR}"
