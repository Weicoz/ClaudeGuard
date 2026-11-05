#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#define HELPER_SCRIPT "/Library/Application Support/ClaudeGuard/macos_network_helper.py"

/* Root runs only this root-owned isolated script, never user-writable modules. */
int main(int argc, char **argv) {
    if (argc != 3 || geteuid() != 0) {
        fputs("hosts-helper: root and <config-dir> <uid> required\n", stderr);
        return 2;
    }
    char *end = NULL;
    errno = 0;
    unsigned long uid = strtoul(argv[2], &end, 10);
    if (errno || !*argv[2] || *end || argv[2][0] == '-' || uid > 0xffffffffUL) return 2;
    int fd = open(HELPER_SCRIPT, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return 1;
    struct stat st;
    int trusted = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == 0 && !(st.st_mode & 0022);
    close(fd);
    if (!trusted) {
        fputs("hosts-helper: refusing untrusted helper script\n", stderr);
        return 1;
    }
    char *args[] = {"/usr/bin/python3", "-I", HELPER_SCRIPT, "--config", argv[1], "--uid", argv[2], NULL};
    execv(args[0], args);
    perror("hosts-helper: exec");
    return 1;
}
