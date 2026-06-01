#include <check.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

/* Test that sprintf-based path construction doesn't overflow buffers */
#define NS_PATH_BUFFER_SIZE 64  /* Typical buffer size used in unshare.c */

START_TEST(test_ns_path_buffer_overflow)
{
    /* Invariant: Buffer writes for /proc/<pid>/ns/* paths must never exceed buffer size */
    
    /* Test PIDs: valid, boundary, and extreme values */
    pid_t test_pids[] = {
        1,          /* Valid: minimal PID */
        32768,      /* Valid: typical max PID */
        INT_MAX,    /* Boundary: maximum int value */
    };
    int num_pids = sizeof(test_pids) / sizeof(test_pids[0]);

    for (int i = 0; i < num_pids; i++) {
        char safe_buffer[NS_PATH_BUFFER_SIZE];
        char expected_path[256];
        int written;
        
        /* Calculate what sprintf would write */
        written = snprintf(expected_path, sizeof(expected_path), 
                          "/proc/%d/ns/cgroup", test_pids[i]);
        
        /* Invariant: the formatted string must fit in the fixed buffer */
        ck_assert_msg(written < NS_PATH_BUFFER_SIZE,
            "PID %d would cause buffer overflow: needs %d bytes, buffer is %d",
            test_pids[i], written + 1, NS_PATH_BUFFER_SIZE);
        
        /* Verify snprintf truncates safely when buffer is too small */
        int result = snprintf(safe_buffer, NS_PATH_BUFFER_SIZE,
                             "/proc/%d/ns/cgroup", test_pids[i]);
        
        /* snprintf must null-terminate and not write beyond buffer */
        ck_assert(safe_buffer[NS_PATH_BUFFER_SIZE - 1] == '\0' || 
                  strlen(safe_buffer) < NS_PATH_BUFFER_SIZE);
        ck_assert_int_ge(result, 0);
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_ns_path_buffer_overflow);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}