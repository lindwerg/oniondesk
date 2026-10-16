#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#include <windows.h>
#include <wincrypt.h>
#include <shellapi.h>
#include <stdint.h>
#include <stdlib.h>
#include <wchar.h>
#include "oniondesk-data-pins.h"

/* An installer-only verifier. Paths and hashes are generated from source pins. */
static int check_path(const wchar_t *root, const struct data_pin *pin) {
    size_t root_length = wcslen(root), length = root_length + wcslen(pin->path) + 2;
    wchar_t *path = calloc(length, sizeof *path);
    if (!path) return 1;
    wcscpy(path, root);
    path[root_length] = L'\\';
    wcscpy(path + root_length + 1, pin->path);
    /* Reject reparse points in the root and every descendant component. */
    for (wchar_t *cursor = path + 3; ; ++cursor) {
        if (*cursor != L'\\' && *cursor != L'\0') continue;
        wchar_t previous = *cursor;
        *cursor = L'\0';
        DWORD attributes = GetFileAttributesW(path);
        *cursor = previous;
        if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) { free(path); return 2; }
        if (!previous) break;
    }
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                             FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    free(path);
    if (file == INVALID_HANDLE_VALUE) return 3;
    LARGE_INTEGER size;
    BY_HANDLE_FILE_INFORMATION information;
    if (!GetFileInformationByHandle(file, &information) || (information.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) ||
        !GetFileSizeEx(file, &size) || (uint64_t)size.QuadPart != pin->size) { CloseHandle(file); return 4; }
    HCRYPTPROV provider = 0;
    HCRYPTHASH hash = 0;
    int result = 5;
    if (!CryptAcquireContextW(&provider, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) ||
        !CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash)) goto cleanup;
    unsigned char buffer[65536];
    DWORD count;
    for (;;) {
        if (!ReadFile(file, buffer, sizeof buffer, &count, NULL)) goto cleanup;
        if (!count) break;
        if (!CryptHashData(hash, buffer, count, 0)) goto cleanup;
    }
    BYTE actual[32];
    DWORD hash_size = sizeof actual;
    if (!CryptGetHashParam(hash, HP_HASHVAL, actual, &hash_size, 0) || hash_size != sizeof actual) goto cleanup;
    for (size_t i = 0; i < sizeof actual; ++i) if (actual[i] != pin->sha256[i]) { result = 6; goto cleanup; }
    result = 0;
cleanup:
    if (hash) CryptDestroyHash(hash);
    if (provider) CryptReleaseContext(provider, 0);
    CloseHandle(file);
    return result;
}

static int verify_arguments(int argc, wchar_t **argv) {
    if (argc != 2 || wcslen(argv[1]) < 3 || argv[1][1] != L':' || argv[1][2] != L'\\' || wcslen(argv[1]) > 32000) return 10;
    for (size_t i = 0; i < sizeof data_pins / sizeof data_pins[0]; ++i) {
        int failure = check_path(argv[1], &data_pins[i]);
        if (failure) return failure;
    }
    return 0;
}

/* GUI subsystem avoids a console during the multi-gigabyte SHA check. The
 * installer owns all user messages and interprets this process's exit code. */
int WINAPI wWinMain(HINSTANCE instance, HINSTANCE previous, LPWSTR command_line, int show) {
    (void)instance;
    (void)previous;
    (void)command_line;
    (void)show;
    int argc = 0;
    wchar_t **argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) return 10;
    int result = verify_arguments(argc, argv);
    LocalFree(argv);
    return result;
}
