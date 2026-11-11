#include "vm_ascii_map.h"
#include <string.h>
#include <limits.h>

static int clamp(int x,int lo,int hi){return x<lo?lo:x>hi?hi:x;}
static char region_symbol(const MonRegion *r){
    if(strchr(r->perm,'x'))return 'E';
    if(r->path[0])return 'F';
    if(strchr(r->perm,'w'))return 'W';
    return 'A';
}
static size_t cell_pos(uint64_t offset, uint64_t span, size_t cells, int ceiling){
    if(!span || !cells)return 0;
    __uint128_t n=(__uint128_t)offset*cells;
    if(ceiling)n+=(span-1);
    n/=span;
    return n>cells?cells:(size_t)n;
}
int mon_vm_ascii_map(const MonRegion *r,int count,int selected,int zoom,
                     int cols,int rows,char *out,MonVmWindow *view){
    if(!r||!out||!view||count<=0||cols<=0||rows<=0||
       (size_t)cols > SIZE_MAX/(size_t)rows)return -1;
    selected=clamp(selected,0,count-1);zoom=clamp(zoom,-3,4);
    int reach=12;
    if(zoom<0)reach<<=-zoom;
    else reach>>=zoom;
    if(reach<0)reach=0;
    int lo=clamp(selected-reach,0,count-1);
    int hi=clamp(selected+reach,0,count-1);
    uint64_t a=r[lo].start,b=r[hi].end;
    if(b<=a)return -1;
    size_t cells=(size_t)cols*(size_t)rows;
    memset(out,'.',cells);
    uint64_t span=b-a;
    for(int i=lo;i<=hi;i++){
        uint64_t st=r[i].start>a?r[i].start:a;
        uint64_t en=r[i].end<b?r[i].end:b;
        if(en<=st)continue;
        size_t first=cell_pos(st-a,span,cells,0);
        size_t last=cell_pos(en-a,span,cells,1);
        if(first>=cells)continue;
        if(last<=first)last=first+1;
        if(last>cells)last=cells;
        char code=region_symbol(&r[i]);
        for(size_t k=first;k<last;k++){
            if(out[k]=='.')out[k]=code;
            else if(out[k]!=code && out[k]!='@')out[k]='*';
        }
    }
    /* Force a selection marker even when its region occupies less than a cell. */
    uint64_t st=r[selected].start>a?r[selected].start:a;
    uint64_t en=r[selected].end<b?r[selected].end:b;
    if(en>st){
        size_t first=cell_pos(st-a,span,cells,0);
        size_t last=cell_pos(en-a,span,cells,1);
        if(first>=cells)first=cells-1;
        if(last<=first)last=first+1;
        if(last>cells)last=cells;
        for(size_t k=first;k<last;k++)out[k]='@';
    }
    view->start=a;view->end=b;view->cells=cells;
    view->first_region=lo;view->last_region=hi;
    return 0;
}
