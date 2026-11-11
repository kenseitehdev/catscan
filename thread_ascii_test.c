#include "thread_ascii_map.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void){
    MonThread t[5]={{.tid=70},{.tid=30},{.tid=40},{.tid=10},{.tid=20}};
    strcpy(t[0].state,"running");strcpy(t[1].state,"waiting");
    strcpy(t[2].state,"stopped");strcpy(t[3].state,"other");
    strcpy(t[4].state,"waiting");
    char b[32];
    assert(mon_thread_ascii_row(t,5,2,0,8,b,sizeof b)==0);
    assert(strcmp(b,"RW@?W...")==0);
    assert(mon_thread_ascii_row(t,5,4,3,4,b,sizeof b)==0);
    assert(strcmp(b,"?@..")==0);
    assert(mon_thread_ascii_row(t,5,0,0,32,b,sizeof b)==-1);
    assert(mon_thread_ascii_row(t,5,0,0,1,b,1)==-1);
    assert(mon_thread_ascii_row(t,5,0,-1,1,b,sizeof b)==-1);
    assert(mon_thread_state_char("other")=='?');
    assert(mon_thread_state_char("running")=='R');
    qsort(t,5,sizeof(*t),mon_thread_cmp_tid);
    assert(t[0].tid==10&&t[4].tid==70);
    puts("thread ASCII raster tests OK");return 0;
}
