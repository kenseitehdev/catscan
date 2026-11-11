#ifndef MONITOR_VM_ASCII_MAP_H
#define MONITOR_VM_ASCII_MAP_H
#include <stddef.h>
#include <stdint.h>

/* These are OS-reported mapped virtual memory regions, NOT malloc blocks or
   physical RAM addresses. Region list must be in ascending address order. */
typedef struct { uint64_t start, end; char perm[8], path[192]; } MonRegion;
typedef struct {
    uint64_t start, end;
    int first_region, last_region;
    size_t cells;
} MonVmWindow;

/* Returns 0 on success. Output is a row-major array of rows * cols ASCII
   characters, without trailing NULs. Codes: '.' gap, 'E' executable,
   'F' file mapped, 'W' writable anonymous, 'A' other anonymous,
   '*' regions of different types compressed into one cell, '@' selection. */
int mon_vm_ascii_map(const MonRegion *r, int count, int selected, int zoom,
                     int cols, int rows, char *out, MonVmWindow *view);
#endif
