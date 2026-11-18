/*
 * memcpy_gate.c - determine which glibc memcpy IFUNC variant is active.
 *
 * Run this *inside* the target container (or with the target's glibc) to see
 * which memcpy implementation glibc selected for the current CPU features and
 * environment. For CVE-2026-123007 the relevant implementations are:
 *
 *   0x1727c0  EVEX/YMM  (vmovdqu64, 32-byte vectors)  <- calibrated profile
 *   0x162880  AVX/YMM   (vmovdqu,   32-byte vectors)  <- geometry-equivalent
 *   0xadd00   SSE/XMM   (movdqu,    16-byte vectors)  <- not compatible
 *
 * The offsets are relative to the libc base and are specific to the Debian 13
 * glibc build used by the official nginx image (glibc 2.41-12+deb13u4).
 *
 * Build:   cc -O2 -Wall -o memcpy_gate memcpy_gate.c -ldl
 * Usage:   docker cp memcpy_gate <container>:/tmp/memcpy_gate
 *          docker exec <container> /tmp/memcpy_gate
 *
 * Authorized lab use only. See DISCLAIMER.md.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uintptr_t libc_lowest_base(void)
{
    FILE *maps = fopen("/proc/self/maps", "r");
    char line[1024];
    uintptr_t lowest = UINTPTR_MAX;

    if (!maps) {
        return 0;
    }

    while (fgets(line, sizeof line, maps)) {
        if (strstr(line, "libc.so.6")) {
            uintptr_t start = (uintptr_t) strtoul(line, NULL, 16);
            if (start < lowest) {
                lowest = start;
            }
        }
    }
    fclose(maps);

    return lowest == UINTPTR_MAX ? 0 : lowest;
}

int main(void)
{
    void *memcpy_addr = dlsym(RTLD_DEFAULT, "memcpy");
    uintptr_t base = libc_lowest_base();
    const char *variant = "unknown";
    const char *tunables = getenv("GLIBC_TUNABLES");

    if (!memcpy_addr || !base) {
        fprintf(stderr, "could not resolve memcpy or libc base\n");
        return 1;
    }

    unsigned long offset = (unsigned long) ((uintptr_t) memcpy_addr - base);

    if (offset == 0x1727c0UL) {
        variant = "EVEX/YMM (AVX-512 encoding, 32-byte)";
    } else if (offset == 0x162880UL) {
        variant = "AVX/YMM (32-byte, geometry-equivalent to EVEX path)";
    } else if (offset == 0xadd00UL) {
        variant = "SSE/XMM (16-byte, incompatible)";
    }

    printf("memcpy=%p libc_base=%p offset=0x%lx\n",
           memcpy_addr, (void *) base, offset);
    printf("variant=%s\n", variant);
    printf("GLIBC_TUNABLES=%s\n", tunables ? tunables : "(unset)");
    return 0;
}
