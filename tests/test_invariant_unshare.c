#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <stdint.h>

/* Simulate a safe string copy function that enforces buffer bounds.
 * This models the invariant: buffer reads never exceed declared length.
 * The function must truncate or reject oversized input.
 */
static int safe_process_input(const char *input, char *output, size_t output_size) {
    if (input == NULL || output == NULL || output_size == 0) {
        return -1;
    }
    /* Safe bounded copy - must never read beyond output_size */
    strncpy(output, input, output_size - 1);
    output[output_size - 1] = '\0';
    return 0;
}

/* Simulate parsing a namespace argument as might appear in unshare.c */
static int parse_namespace_arg(const char *arg, char *buf, size_t buf_size) {
    if (arg == NULL || buf == NULL || buf_size == 0) {
        return -1;
    }
    size_t arg_len = strnlen(arg, buf_size * 10 + 1);
    if (arg_len >= buf_size) {
        /* Reject oversized input */
        return -1;
    }
    strncpy(buf, arg, buf_size - 1);
    buf[buf_size - 1] = '\0';
    return 0;
}

/* Simulate processing a mount point path as might appear in unshare.c */
static int process_mount_path(const char *path, char *result, size_t result_size) {
    if (path == NULL || result == NULL || result_size == 0) {
        return -1;
    }
    /* Use snprintf for safe bounded formatting */
    int written = snprintf(result, result_size, "%s", path);
    if (written < 0) {
        return -1;
    }
    /* If truncation occurred, treat as error */
    if ((size_t)written >= result_size) {
        result[0] = '\0';
        return -1;
    }
    return 0;
}

#define SMALL_BUF_SIZE   16
#define MEDIUM_BUF_SIZE  64
#define LARGE_BUF_SIZE   256

START_TEST(test_buffer_reads_never_exceed_declared_length)
{
    /* Invariant: Buffer reads never exceed the declared length regardless of input size */
    const char *payloads[] = {
        /* 2x oversized inputs */
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",  /* 31 chars, 2x SMALL_BUF_SIZE */
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",  /* 31 chars */
        /* 10x oversized inputs */
        "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",  /* 10x+ */
        /* Path traversal attacks */
        "/../../../../../../../../../../../etc/passwd",
        "/proc/self/../../../../etc/shadow",
        /* Format string attacks */
        "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
        "%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n",
        "%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x",
        /* Null byte injection */
        "normal\x00malicious_overflow_data_here_AAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        /* Long namespace-like strings */
        "user:uts:ipc:net:pid:mnt:cgroup:time:user:uts:ipc:net:pid:mnt:cgroup:time:user:uts:ipc:net:pid:mnt:cgroup:time",
        /* Repeated special chars */
        "////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////",
        /* Mixed attack payload */
        "A\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41",
        /* Very long string simulating heap spray */
        "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF",
        /* Newline injection */
        "valid_input\nmalicious_second_line_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        /* Tab injection */
        "valid\tAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        /* Empty string */
        "",
        /* Single char */
        "A",
        /* Exactly at boundary (SMALL_BUF_SIZE - 1 = 15 chars) */
        "123456789012345",
        /* One over boundary */
        "1234567890123456",
        /* Unicode-like byte sequences */
        "\xc0\xaf\xc0\xaf\xc0\xaf\xc0\xaf\xc0\xaf\xc0\xaf\xc0\xaf\xc0\xaf\xc0\xaf\xc0\xaf\xc0\xaf\xc0\xaf\xc0\xaf\xc0\xaf\xc0\xaf\xc0\xaf",
    };
    int num_payloads = sizeof(payloads) / sizeof(payloads[0]);

    for (int i = 0; i < num_payloads; i++) {
        char small_buf[SMALL_BUF_SIZE];
        char medium_buf[MEDIUM_BUF_SIZE];
        char large_buf[LARGE_BUF_SIZE];

        /* Guard bytes to detect overflow */
        unsigned char guard_small[8];
        unsigned char guard_medium[8];
        unsigned char guard_large[8];

        memset(guard_small,  0xAB, sizeof(guard_small));
        memset(guard_medium, 0xCD, sizeof(guard_medium));
        memset(guard_large,  0xEF, sizeof(guard_large));

        memset(small_buf,  0, sizeof(small_buf));
        memset(medium_buf, 0, sizeof(medium_buf));
        memset(large_buf,  0, sizeof(large_buf));

        /* Test safe_process_input with small buffer */
        int ret_small = safe_process_input(payloads[i], small_buf, SMALL_BUF_SIZE);
        /* Invariant: return value is 0 or -1, never undefined */
        ck_assert_msg(ret_small == 0 || ret_small == -1,
            "safe_process_input returned unexpected value %d for payload %d", ret_small, i);
        /* Invariant: output buffer must be null-terminated within bounds */
        if (ret_small == 0) {
            ck_assert_msg(small_buf[SMALL_BUF_SIZE - 1] == '\0',
                "small_buf not null-terminated at boundary for payload %d", i);
            size_t out_len = strlen(small_buf);
            ck_assert_msg(out_len < SMALL_BUF_SIZE,
                "small_buf output length %zu >= buffer size %d for payload %d",
                out_len, SMALL_BUF_SIZE, i);
        }

        /* Test parse_namespace_arg with medium buffer */
        int ret_medium = parse_namespace_arg(payloads[i], medium_buf, MEDIUM_BUF_SIZE);
        ck_assert_msg(ret_medium == 0 || ret_medium == -1,
            "parse_namespace_arg returned unexpected value %d for payload %d", ret_medium, i);
        if (ret_medium == 0) {
            ck_assert_msg(medium_buf[MEDIUM_BUF_SIZE - 1] == '\0',
                "medium_buf not null-terminated at boundary for payload %d", i);
            size_t out_len = strlen(medium_buf);
            ck_assert_msg(out_len < MEDIUM_BUF_SIZE,
                "medium_buf output length %zu >= buffer size %d for payload %d",
                out_len, MEDIUM_BUF_SIZE, i);
            /* Invariant: if accepted, output must match input exactly (no corruption) */
            ck_assert_msg(strncmp(medium_buf, payloads[i], MEDIUM_BUF_SIZE - 1) == 0,
                "medium_buf content mismatch for payload %d", i);
        }

        /* Test process_mount_path with large buffer */
        int ret_large = process_mount_path(payloads[i], large_buf, LARGE_BUF_SIZE);
        ck_assert_msg(ret_large == 0 || ret_large == -1,
            "process_mount_path returned unexpected value %d for payload %d", ret_large, i);
        if (ret_large == 0) {
            ck_assert_msg(large_buf[LARGE_BUF_SIZE - 1] == '\0',
                "large_buf not null-terminated at boundary for payload %d", i);
            size_t out_len = strlen(large_buf);
            ck_assert_msg(out_len < LARGE_BUF_SIZE,
                "large_buf output length %zu >= buffer size %d for payload %d",
                out_len, LARGE_BUF_SIZE, i);
        }

        /* Invariant: guard bytes must be intact (no overflow occurred) */
        for (int g = 0; g < 8; g++) {
            ck_assert_msg(guard_small[g]  == 0xAB,
                "guard_small[%d] corrupted (0x%02x) for payload %d", g, guard_small[g], i);
            ck_assert_msg(guard_medium[g] == 0xCD,
                "guard_medium[%d] corrupted (0x%02x) for payload %d", g, guard_medium[g], i);
            ck_assert_msg(guard_large[g]  == 0xEF,
                "guard_large[%d] corrupted (0x%02x) for payload %d", g, guard_large[g], i);
        }

        /* Invariant: input string length check - if input fits, it must be accepted */
        size_t input_len = strlen(payloads[i]);
        if (input_len < SMALL_BUF_SIZE) {
            ck_assert_msg(ret_small == 0,
                "safe_process_input rejected fitting input (len=%zu) for payload %d",
                input_len, i);
        }
        if (input_len < MEDIUM_BUF_SIZE) {
            ck_assert_msg(ret_medium == 0,
                "parse_namespace_arg rejected fitting input (len=%zu) for payload %d",
                input_len, i);
        }
        if (input_len < LARGE_BUF_SIZE) {
            ck_assert_msg(ret_large == 0,
                "process_mount_path rejected fitting input (len=%zu) for payload %d",
                input_len, i);
        }
    }
}
END_TEST

START_TEST(test_null_input_rejected)
{
    /* Invariant: NULL inputs must be safely rejected without crashing */
    char buf[SMALL_BUF_SIZE];
    memset(buf, 0, sizeof(buf));

    int ret1 = safe_process_input(NULL, buf, SMALL_BUF_SIZE);
    ck_assert_int_eq(ret1, -1);

    int ret2 = safe_process_input("valid", NULL, SMALL_BUF_SIZE);
    ck_assert_int_eq(ret2, -1);

    int ret3 = safe_process_input("valid", buf, 0);
    ck_assert_int_eq(ret3, -1);
}
END_TEST

START_TEST(test_exact_boundary_inputs)
{
    /* Invariant: inputs exactly at boundary are handled correctly */
    char buf[SMALL_BUF_SIZE];

    /* Exactly SMALL_BUF_SIZE - 1 chars (fits perfectly) */
    char exact_fit[SMALL_BUF_SIZE];
    memset(exact_fit, 'X', SMALL_BUF_SIZE - 1);
    exact_fit[SMALL_BUF_SIZE - 1] = '\0';

    memset(buf, 0, sizeof(buf));
    int ret = safe_process_input(exact_fit, buf, SMALL_BUF_SIZE);
    ck_assert_int_eq(ret, 0);
    ck_assert_msg(buf[SMALL_BUF_SIZE - 1] == '\0',
        "Buffer not null-terminated at exact boundary");
    ck_assert_msg(strlen(buf) == SMALL_BUF_SIZE - 1,
        "Exact fit string length mismatch");

    /* Exactly SMALL_BUF_SIZE chars (one too many) */
    char one_over[SMALL_BUF_SIZE + 1];
    memset(one_over, 'Y', SMALL_BUF_SIZE);
    one_over[SMALL_BUF_SIZE] = '\0';

    memset(buf, 0, sizeof(buf));
    ret = safe_process_input(one_over, buf, SMALL_BUF_SIZE);
    /* Must either truncate (ret==0, buf truncated) or reject (ret==-1) */
    ck_assert_msg(ret == 0 || ret == -1,
        "Unexpected return for one-over-boundary input");
    if (ret == 0) {
        /* If accepted, must be truncated */
        ck_assert_msg(buf[SMALL_BUF_SIZE - 1] == '\0',
            "Buffer not null-terminated after truncation");
        ck_assert_msg(strlen(buf) < SMALL_BUF_SIZE,
            "Truncated buffer length not within bounds");
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_buffer_reads_never_exceed_declared_length);
    tcase_add_test(tc_core, test_null_input_rejected);
    tcase_add_test(tc_core, test_exact_boundary_inputs);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s