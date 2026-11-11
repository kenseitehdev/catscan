#include "thread_ascii_map.h"
#include <string.h>
char mon_thread_state_char(const char *state){
    if(!state)return '?';
    if(!strcmp(state,"running"))return 'R';
    if(!strcmp(state,"waiting"))return 'W';
    if(!strcmp(state,"stopped"))return 'S';
    return '?';
}
int mon_thread_cmp_tid(const void *a,const void *b){
    const MonThread *x=a,*y=b;
    return (x->tid>y->tid)-(x->tid<y->tid);
}
int mon_thread_ascii_row(const MonThread *threads,int count,int selected,
                         int start,int cols,char *out,size_t capacity){
    if(!threads||!out||count<0||start<0||cols<1||(size_t)cols>=capacity)return -1;
    for(int i=0;i<cols;i++){
        int k=start+i;
        out[i]=k>=count?'.':k==selected?'@':mon_thread_state_char(threads[k].state);
    }
    out[cols]='\0';
    return 0;
}
