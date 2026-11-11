#include "vm_ascii_map.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

static void map_basic(void){
    MonRegion r[3]={
        {.start=0x1000,.end=0x2000,.perm="rw-"},
        {.start=0x3000,.end=0x4000,.perm="r--",.path="/tmp/data.bin"},
        {.start=0x4000,.end=0x5000,.perm="r-x",.path="/tmp/main"}
    };
    char cells[16]={0};MonVmWindow v={0};
    assert(mon_vm_ascii_map(r,3,1,0,16,1,cells,&v)==0);
    assert(v.start==0x1000 && v.end==0x5000);
    assert(!memcmp(cells,"WWWW....@@@@EEEE",16));
    assert(mon_vm_ascii_map(r,3,1,4,16,1,cells,&v)==0);
    assert(v.start==0x3000 && v.end==0x4000);
    for(int i=0;i<16;i++)assert(cells[i]=='@');
}
static void map_subcell(void){
    MonRegion r[3]={
        {.start=0,.end=1,.perm="r--"},
        {.start=1000,.end=1001,.perm="r-x"},
        {.start=2000,.end=3000,.perm="rw-"}
    };
    char cells[48]={0};MonVmWindow v={0};
    assert(mon_vm_ascii_map(r,3,0,0,12,4,cells,&v)==0);
    assert(memchr(cells,'@',48)!=NULL);
    assert(memchr(cells,'.',48)!=NULL);
}
static void map_overflow(void){
    MonRegion r[2]={
        {.start=UINT64_MAX-200000,.end=UINT64_MAX-100000,.perm="r--"},
        {.start=UINT64_MAX-30000,.end=UINT64_MAX-1,.perm="rw-"}
    };
    char cells[24]={0};MonVmWindow v={0};
    assert(mon_vm_ascii_map(r,2,1,0,8,3,cells,&v)==0);
    assert(v.start==r[0].start && v.end==r[1].end);
    assert(memchr(cells,'@',24)!=NULL);
}
int main(void){map_basic();map_subcell();map_overflow();puts("VM ASCII map: fixtures, gaps, selected markers, zoom and 64-bit edges OK");return 0;}
