#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef ONIONDESK_ARCH
#error ONIONDESK_ARCH must be x86_64 or aarch64
#endif

/* Linux resolves the running inode, independently of argv[0], PATH and cwd. */
static char *executable_path(void) {
    size_t capacity = 256;
    while (capacity <= 1024 * 1024) {
        char *path = malloc(capacity + 1);
        if (!path) return NULL;
        ssize_t count = readlink("/proc/self/exe", path, capacity);
        if (count < 0) { free(path); return NULL; }
        if ((size_t)count < capacity) { path[count] = '\0'; return path; }
        free(path);
        capacity *= 2;
    }
    errno = ENAMETOOLONG;
    return NULL;
}

static int fail(const char *detail) {
    fprintf(stderr, "OnionDesk: %s\n", detail);
    fprintf(stderr, "Keep the .oniondesk folder beside this application and extract the complete archive before opening it.\n");
    return 1;
}

int main(int argc, char **argv) {
    char *self = executable_path();
    if (!self) return fail("cannot locate this application.");
    char *slash = strrchr(self, '/');
    if (!slash) { free(self); return fail("cannot locate the application folder."); }
    *slash = '\0';
    const char suffix[] = "/.oniondesk/Linux/" ONIONDESK_ARCH "/OnionDesk/OnionDesk";
    size_t length = strlen(self) + sizeof suffix;
    char *target = malloc(length);
    char **arguments = calloc((size_t)argc + 1, sizeof *arguments);
    if (!target || !arguments) { free(self); free(target); free(arguments); return fail("not enough memory."); }
    snprintf(target, length, "%s%s", self, suffix);
    free(self);
    struct stat entry;
    if (stat(target, &entry) != 0 || !S_ISREG(entry.st_mode) || access(target, X_OK) != 0) {
        free(target); free(arguments);
        return fail("application resources are missing or are not executable.");
    }
    arguments[0] = target;
    for (int i = 1; i < argc; ++i) arguments[i] = argv[i];
    execv(target, arguments);
    int saved = errno;
    free(target); free(arguments);
    if (saved == ENOENT) return fail("the Linux runtime required by this application is unavailable.");
    if (saved == EACCES) return fail("the application folder does not permit execution.");
    return fail("the application could not be started.");
}
