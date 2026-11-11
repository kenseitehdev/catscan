#ifndef MONITOR_THREAD_ASCII_MAP_H
#define MONITOR_THREAD_ASCII_MAP_H
#include <stddef.h>
#include <stdint.h>
/* Logical per-process thread map, not physical CPU/core placement. */
typedef struct {uint64_t tid, user_ns, sys_ns; char name[64], state[24]; double cpu_pct;} MonThread;
char mon_thread_state_char(const char *state);
int mon_thread_cmp_tid(const void *a,const void *b);
/* Render one ASCII row: @ selected, R running, W waiting, S stopped,
 * ? other, . unused slot. Output NUL-terminated. */
int mon_thread_ascii_row(const MonThread *threads,int count,int selected,
                         int start,int cols,char *out,size_t capacity);
#endif
