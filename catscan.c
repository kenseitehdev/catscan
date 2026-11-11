/* CATSCAN v0.9.1: macOS-first unified live TUI.
 * Uses the supplied netinspect.c in-process, retaining its collectors and
 * socket -> packet -> payload navigation. Does not shell out to pi.
 * Build: clang -O2 -Wall -Wextra -pthread catscan.c -lncurses -o catscan
 * Run:   sudo -v && ./catscan       (network capture requires sudo ticket)
 * Demo:  ./catscan --demo           (portable, sample network data)
 */
#define _DARWIN_C_SOURCE 1
#define _DEFAULT_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#define main netinspect_standalone_main
#include "netinspect.c"
#undef main

#include <math.h>
#include "hardware.h"
#include "vm_ascii_map.h"
#include "thread_ascii_map.h"
#include <sys/resource.h>
#include <sys/statvfs.h>
#if defined(__APPLE__)
#include <libproc.h>
#include <sys/sysctl.h>
#include <mach/mach.h>
#include <mach/vm_region.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <net/if.h>
#include <ifaddrs.h>
#elif defined(__FreeBSD__)
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/proc.h>
#include <sys/dkstat.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <ifaddrs.h>
#else
#include <dirent.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#endif

#define MON_PROCS 4096
#define MON_MOUNTS 128
#define MON_THREADS 4096
#define MON_REGIONS 4096
#define MON_HISTORY 60
#define MON_EVENTS 160

/* Keep snapshots modest. One producer owns S, all reads take its mutex. */
typedef struct {int pid, uid, threads; char name[96], state; uint64_t rss, virt, cpu_ns, faults, pageins, cow_faults, context_switches, syscalls_unix, syscalls_mach; double cpu_pct;} MonProcess;
typedef struct {char name[256], path[256], type[32]; uint64_t total, free_bytes, avail;} MonMount;
typedef struct {
    pthread_mutex_t mu;
    int stop, count, mounts, valid;
    MonProcess processes[MON_PROCS]; MonMount volumes[MON_MOUNTS];
    double cpu, load[3], mem_pct, net_in_rate, net_out_rate;
    uint64_t mem_total, mem_used, mem_active, mem_wired, mem_compressed, mem_inactive, mem_free, mem_speculative, net_in, net_out;
    double cpu_history[MON_HISTORY], mem_history[MON_HISTORY], net_history[MON_HISTORY];
    int history_pos, history_count;
    char warning[160];
} MonShared;
static MonShared S={.mu=PTHREAD_MUTEX_INITIALIZER};

/* MonThread and its state raster are defined in thread_ascii_map.h. */
typedef struct {
    int page, focus, index[5], top[5], depth, selected_pid, selected_mount, pending_g;
    MonThread threads[MON_THREADS]; int thread_count, thread_valid;
    MonRegion regions[MON_REGIONS]; int region_count, region_valid;
    int detail_index, detail_top;
    int sync_pid, sync_page; unsigned long detail_revision;
    int rusage_valid;
    uint64_t footprint, resident, wired, disk_read, disk_write, ru_pageins, idle_wakeups, interrupt_wakeups;
    UI net;
    int overview_proc_index, overview_proc_top, hardware_index, topology, map_zoom;
} MonUI;

/* Drill-down collector operates independently of curses and the overview worker.
 * It only publishes a completed snapshot for the currently requested PID/view. */
typedef struct {
    pthread_mutex_t mu;
    int stop, page, pid, pending, count, valid;
    unsigned long request_id, revision;
    MonThread threads[MON_THREADS];
    MonRegion regions[MON_REGIONS];
    int rusage_valid;
    uint64_t footprint, resident, wired, disk_read, disk_write, ru_pageins, idle_wakeups, interrupt_wakeups;
} MonDetailShared;
static MonDetailShared D={.mu=PTHREAD_MUTEX_INITIALIZER};
/* Asynchronous I/O sampling and opt-in filesystem-event stream. 
 * `iostat -d -w 2` reports an aggregate of device columns (not per volume).
 * fs_usage events are system-wide and may omit protected activity. */
typedef struct {
    pthread_mutex_t mu;
    int stop, io_valid, event_enabled, event_alive;
    pid_t event_pid, io_pid;
    double mb_s, tps, kb_t;
    char io_status[128], event_status[160];
    char events[MON_EVENTS][320];
    unsigned long event_seq;
} MonIO;
static MonIO IO={.mu=PTHREAD_MUTEX_INITIALIZER};

typedef struct {uint64_t total, used, active, wired, compressed, inactive, free_bytes, speculative;} MonMem;
static volatile sig_atomic_t mon_signal=0;
static void mon_sig(int signum){(void)signum;mon_signal=1;}
static void mon_copy(char *dest,size_t n,const char *src){if(n)snprintf(dest,n,"%s",src?src:"");}
static void mon_bytes(uint64_t x,char *out,size_t n){
    const char *unit[]={"B","K","M","G","T","P"}; double d=x;int u=0;
    while(d>=1024 && u<5){d/=1024;u++;}
    snprintf(out,n,"%.1f%s",d,unit[u]);
}
static int mon_sort_cpu(const void *a,const void *b){const MonProcess *x=a,*y=b;return (x->cpu_pct<y->cpu_pct)-(x->cpu_pct>y->cpu_pct);}
static int mon_sort_mem(const void *a,const void *b){const MonProcess *x=a,*y=b;return (x->rss<y->rss)-(x->rss>y->rss);}
static uint64_t mon_now_ns(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return (uint64_t)t.tv_sec*1000000000ULL+t.tv_nsec;}

#if defined(__APPLE__)
static int mon_collect_processes(MonProcess *out,int cap){
    int bytes=proc_listpids(PROC_ALL_PIDS,0,NULL,0);
    if(bytes<=0)return -1;
    pid_t *ids=calloc((size_t)bytes/sizeof(pid_t)+512,sizeof(pid_t));if(!ids)return -1;
    int size=bytes+(int)(512*sizeof(pid_t));
    bytes=proc_listpids(PROC_ALL_PIDS,0,ids,size);
    int count=0;
    for(int i=0;i<bytes/(int)sizeof(pid_t) && count<cap;i++){
        if(ids[i]<=0)continue;
        struct proc_taskallinfo t={0};
        if(proc_pidinfo(ids[i],PROC_PIDTASKALLINFO,0,&t,sizeof(t))!=(int)sizeof(t))continue;
        MonProcess *p=&out[count++];memset(p,0,sizeof(*p));
        p->pid=ids[i];p->uid=(int)t.pbsd.pbi_uid;p->threads=t.ptinfo.pti_threadnum;
        p->faults=t.ptinfo.pti_faults;p->pageins=t.ptinfo.pti_pageins;p->cow_faults=t.ptinfo.pti_cow_faults;
        p->context_switches=t.ptinfo.pti_csw;p->syscalls_unix=t.ptinfo.pti_syscalls_unix;p->syscalls_mach=t.ptinfo.pti_syscalls_mach;
        p->rss=t.ptinfo.pti_resident_size;p->virt=t.ptinfo.pti_virtual_size;
        p->cpu_ns=t.ptinfo.pti_total_user+t.ptinfo.pti_total_system;
        p->state=t.pbsd.pbi_status==2?'R':t.pbsd.pbi_status==3?'S':'?';
        mon_copy(p->name,sizeof(p->name),t.pbsd.pbi_name[0]?t.pbsd.pbi_name:t.pbsd.pbi_comm);
    }
    free(ids);return count;
}
/* macOS VM accounting: inactive/speculative pages are reclaimable caches.
 * The old total-free formula counted those caches as used RAM.
 * Occupied is an estimate of active + wired + compressor pages; category
 * accounting is not identical to Activity Monitor's proprietary breakdown. */
static MonMem mon_collect_mem(void){
    MonMem m={0};size_t size=sizeof m.total;
    if(sysctlbyname("hw.memsize",&m.total,&size,NULL,0)!=0)return m;
    vm_statistics64_data_t v={0};mach_msg_type_number_t n=HOST_VM_INFO64_COUNT;
    mach_port_t host=mach_host_self();vm_size_t page=0;
    if(host_page_size(host,&page)!=KERN_SUCCESS || !page)return m;
    if(host_statistics64(host,HOST_VM_INFO64,(host_info64_t)&v,&n)!=KERN_SUCCESS)return m;
    m.active=(uint64_t)v.active_count*page;
    m.wired=(uint64_t)v.wire_count*page;
    m.compressed=(uint64_t)v.compressor_page_count*page;
    m.inactive=(uint64_t)v.inactive_count*page;
    m.free_bytes=(uint64_t)v.free_count*page;
    m.speculative=(uint64_t)v.speculative_count*page;
    uint64_t occupied=m.active+m.wired+m.compressed;
    m.used=occupied>m.total?m.total:occupied;
    return m;
}
static void mon_collect_cpu(double *cpu,unsigned long long ticks[4]){
    host_cpu_load_info_data_t load={0};mach_msg_type_number_t n=HOST_CPU_LOAD_INFO_COUNT;
    if(host_statistics(mach_host_self(),HOST_CPU_LOAD_INFO,(host_info_t)&load,&n)!=KERN_SUCCESS)return;
    unsigned long long next[4];for(int i=0;i<4;i++)next[i]=load.cpu_ticks[i];
    uint64_t idle=next[CPU_STATE_IDLE]-ticks[CPU_STATE_IDLE],sum=0;
    for(int i=0;i<4;i++){sum+=next[i]-ticks[i];ticks[i]=next[i];}
    if(sum)*cpu=100.0*(double)(sum-idle)/(double)sum;
}
static void mon_collect_net(uint64_t *in,uint64_t *out){
    struct ifaddrs *list=NULL;*in=*out=0;
    if(getifaddrs(&list)!=0)return;
    for(struct ifaddrs *a=list;a;a=a->ifa_next){
        if(!a->ifa_addr || a->ifa_addr->sa_family!=AF_LINK || !a->ifa_data)continue;
        if(a->ifa_flags&IFF_LOOPBACK)continue;
        struct if_data *d=(struct if_data *)a->ifa_data;
        *in+=d->ifi_ibytes;*out+=d->ifi_obytes;
    }
    freeifaddrs(list);
}
static int mon_collect_mounts(MonMount *out,int cap){
    struct statfs *m=NULL;int n=getmntinfo(&m,MNT_NOWAIT);if(n<0)return 0;
    int count=0;for(int i=0;i<n && count<cap;i++){
        MonMount *x=&out[count++];memset(x,0,sizeof(*x));
        mon_copy(x->name,sizeof(x->name),m[i].f_mntfromname);
        mon_copy(x->path,sizeof(x->path),m[i].f_mntonname);
        mon_copy(x->type,sizeof(x->type),m[i].f_fstypename);
        x->total=(uint64_t)m[i].f_blocks*m[i].f_bsize;
        x->free_bytes=(uint64_t)m[i].f_bfree*m[i].f_bsize;
        x->avail=(uint64_t)m[i].f_bavail*m[i].f_bsize;
    }return count;
}
static int mon_collect_threads(int pid,MonThread *out){
    uint64_t *ids=calloc(MON_THREADS,sizeof(uint64_t));if(!ids)return -1;
    int bytes=proc_pidinfo(pid,PROC_PIDLISTTHREADS,0,ids,MON_THREADS*(int)sizeof(uint64_t));
    if(bytes<=0){free(ids);return -1;}
    int count=0;
    for(int i=0;i<bytes/(int)sizeof(uint64_t) && count<MON_THREADS;i++){
        struct proc_threadinfo t={0};
        if(proc_pidinfo(pid,PROC_PIDTHREADINFO,ids[i],&t,sizeof(t))<=0)continue;
        MonThread *r=&out[count++];memset(r,0,sizeof(*r));
        r->tid=ids[i];r->user_ns=t.pth_user_time;r->sys_ns=t.pth_system_time;
        r->cpu_pct=(double)t.pth_cpu_usage/10.0;
        mon_copy(r->name,sizeof(r->name),t.pth_name[0]?t.pth_name:"-");
        mon_copy(r->state,sizeof(r->state),t.pth_run_state==TH_STATE_RUNNING?"running":t.pth_run_state==TH_STATE_WAITING?"waiting":t.pth_run_state==TH_STATE_STOPPED?"stopped":"other");
    }
    free(ids);
    /* Listing IDs but failing to inspect any thread is a permissions / exit
     * failure, not an empty, valid topology. */
    if(count<=0)return -1;
    qsort(out,(size_t)count,sizeof(*out),mon_thread_cmp_tid);
    return count;
}
static int mon_collect_regions(int pid,MonRegion *out){
    task_t task=MACH_PORT_NULL;
    int borrowed_self=(pid==(int)getpid());
    if(borrowed_self)task=mach_task_self();
    else if(task_for_pid(mach_task_self(),pid,&task)!=KERN_SUCCESS)return -1;
    mach_vm_address_t addr=0;int count=0;
    while(count<MON_REGIONS){
        vm_address_t a=(vm_address_t)addr;vm_size_t size=0;
        vm_region_basic_info_data_64_t info={0};mach_msg_type_number_t n=VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj=MACH_PORT_NULL;
        kern_return_t kr=vm_region_64(task,&a,&size,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&n,&obj);
        if(obj!=MACH_PORT_NULL)mach_port_deallocate(mach_task_self(),obj);
        if(kr!=KERN_SUCCESS || !size)break;
        MonRegion *r=&out[count++];memset(r,0,sizeof(*r));r->start=a;r->end=(uint64_t)a+size;
        snprintf(r->perm,sizeof(r->perm),"%c%c%c",(info.protection&VM_PROT_READ)?'r':'-',(info.protection&VM_PROT_WRITE)?'w':'-',(info.protection&VM_PROT_EXECUTE)?'x':'-');
        proc_regionfilename(pid,a,r->path,(uint32_t)sizeof(r->path));
        addr=(mach_vm_address_t)a+size;
    }
    if(!borrowed_self)mach_port_deallocate(mach_task_self(),task);return count;
}
#elif defined(__FreeBSD__)
static int mon_collect_processes(MonProcess *out,int cap){
    int mib[4]={CTL_KERN,KERN_PROC,KERN_PROC_PROC,0};size_t bytes=0;
    if(sysctl(mib,4,NULL,&bytes,NULL,0)!=0||!bytes)return -1;
    struct kinfo_proc *items=calloc(1,bytes);if(!items)return -1;
    if(sysctl(mib,4,items,&bytes,NULL,0)!=0){free(items);return -1;}
    int count=0;size_t n=bytes/sizeof(*items);
    for(size_t i=0;i<n&&count<cap;i++){
        const struct kinfo_proc *k=&items[i];MonProcess *p=&out[count++];memset(p,0,sizeof(*p));
        p->pid=k->ki_pid;p->uid=k->ki_uid;p->threads=k->ki_numthreads;
        p->rss=(uint64_t)k->ki_rssize*(uint64_t)sysconf(_SC_PAGESIZE);p->virt=(uint64_t)k->ki_size;
        p->cpu_ns=(uint64_t)k->ki_runtime;p->faults=k->ki_rusage.ru_minflt;
        p->state=k->ki_stat==SRUN?'R':k->ki_stat==SSLEEP?'S':k->ki_stat==SSTOP?'T':'?';
        mon_copy(p->name,sizeof(p->name),k->ki_comm);
    }
    free(items);return count;
}
static MonMem mon_collect_mem(void){
    MonMem m={0};size_t size=sizeof(m.total);unsigned long free_pages=0;size_t page=(size_t)sysconf(_SC_PAGESIZE);
    if(!page||sysctlbyname("hw.physmem",&m.total,&size,NULL,0)!=0||
       sysctlbyname("vm.stats.vm.v_free_count",&free_pages,&size,NULL,0)!=0)return m;
    m.free_bytes=(uint64_t)free_pages*page;m.used=m.total>m.free_bytes?m.total-m.free_bytes:0;return m;
}
static void mon_collect_cpu(double *cpu,unsigned long long ticks[5]){
    long next[CPUSTATES]={0};size_t size=sizeof(next);
    if(sysctlbyname("kern.cp_time",next,&size,NULL,0)!=0||size<sizeof(next))return;
    unsigned long long sum=0,idle=0;
    for(int i=0;i<CPUSTATES&&i<5;i++){
        unsigned long long value=(unsigned long long)next[i];
        sum+=value-ticks[i];if(i==CP_IDLE)idle=value-ticks[i];ticks[i]=value;
    }
    if(sum)*cpu=100.0*(double)(sum-idle)/(double)sum;
}
static void mon_collect_net(uint64_t *in,uint64_t *out){
    struct ifaddrs *list=NULL;*in=*out=0;if(getifaddrs(&list)!=0)return;
    for(struct ifaddrs *a=list;a;a=a->ifa_next){
        if(!a->ifa_addr||a->ifa_addr->sa_family!=AF_LINK||!a->ifa_data||(a->ifa_flags&IFF_LOOPBACK))continue;
        struct if_data *d=(struct if_data *)a->ifa_data;*in+=d->ifi_ibytes;*out+=d->ifi_obytes;
    }
    freeifaddrs(list);
}
static int mon_collect_mounts(MonMount *out,int cap){
    struct statfs *mounts=NULL;int n=getmntinfo(&mounts,MNT_NOWAIT);if(n<0)return 0;int count=0;
    for(int i=0;i<n&&count<cap;i++){
        MonMount *x=&out[count++];memset(x,0,sizeof(*x));
        mon_copy(x->name,sizeof(x->name),mounts[i].f_mntfromname);mon_copy(x->path,sizeof(x->path),mounts[i].f_mntonname);mon_copy(x->type,sizeof(x->type),mounts[i].f_fstypename);
        x->total=(uint64_t)mounts[i].f_blocks*mounts[i].f_bsize;x->free_bytes=(uint64_t)mounts[i].f_bfree*mounts[i].f_bsize;x->avail=(uint64_t)mounts[i].f_bavail*mounts[i].f_bsize;
    }
    return count;
}
static int mon_collect_threads(int pid,MonThread *out){(void)pid;(void)out;return -1;}
static int mon_collect_regions(int pid,MonRegion *out){(void)pid;(void)out;return -1;}
#else
static int mon_collect_processes(MonProcess *out,int cap){
    DIR *dir=opendir("/proc");if(!dir)return -1;
    long ticks_per_second=sysconf(_SC_CLK_TCK);if(ticks_per_second<=0)ticks_per_second=100;
    int count=0;struct dirent *ent;
    while((ent=readdir(dir)) && count<cap){
        if(!all_digits(ent->d_name))continue;
        char path[128];snprintf(path,sizeof(path),"/proc/%s/status",ent->d_name);
        FILE *f=fopen(path,"r");if(!f)continue;
        MonProcess p={.pid=atoi(ent->d_name),.threads=1,.state='?'};char b[512];
        while(fgets(b,sizeof(b),f)){
            if(!strncmp(b,"Name:",5))sscanf(b+5," %95s",p.name);
            else if(!strncmp(b,"VmRSS:",6)){unsigned long long k=0;sscanf(b+6," %llu",&k);p.rss=k*1024;}
            else if(!strncmp(b,"VmSize:",7)){unsigned long long k=0;sscanf(b+7," %llu",&k);p.virt=k*1024;}
            else if(!strncmp(b,"Threads:",8))sscanf(b+8," %d",&p.threads);
            else if(!strncmp(b,"Uid:",4)){unsigned uid=0;if(sscanf(b+4," %u",&uid)==1)p.uid=(int)uid;}
            else if(!strncmp(b,"State:",6))sscanf(b+6," %c",&p.state);
        }
        fclose(f);
        snprintf(path,sizeof(path),"/proc/%s/stat",ent->d_name);f=fopen(path,"r");
        if(f){
            if(fgets(b,sizeof(b),f)){
                char *right=strrchr(b,')');
                if(right&&right[1]==' '){
                    char *save=NULL,*field=strtok_r(right+2," ",&save);int index=0;
                    unsigned long long user_ticks=0,system_ticks=0;
                    while(field){
                        if(index==11)user_ticks=strtoull(field,NULL,10);
                        else if(index==12){system_ticks=strtoull(field,NULL,10);break;}
                        field=strtok_r(NULL," ",&save);index++;
                    }
                    p.cpu_ns=(uint64_t)((long double)(user_ticks+system_ticks)*1000000000.0L/(long double)ticks_per_second);
                }
            }
            fclose(f);
        }
        out[count++]=p;
    }
    closedir(dir);return count;
}
static MonMem mon_collect_mem(void){
    MonMem m={0};struct sysinfo info={0};if(sysinfo(&info))return m;
    m.total=(uint64_t)info.totalram*info.mem_unit;
    m.free_bytes=(uint64_t)info.freeram*info.mem_unit;
    uint64_t available=m.free_bytes;FILE *f=fopen("/proc/meminfo","r");
    if(f){char line[160];while(fgets(line,sizeof line,f))if(!strncmp(line,"MemAvailable:",13)){
        unsigned long long kib=0;if(sscanf(line+13," %llu",&kib)==1)available=(uint64_t)kib*1024;break;
    }fclose(f);}
    if(available>m.total)available=m.total;
    m.used=m.total-available;
    return m;
}
static void mon_collect_cpu(double *cpu,unsigned long long ticks[4]){
    FILE *f=fopen("/proc/stat","r");if(!f)return;
    char b[256];if(fgets(b,sizeof b,f)){
        unsigned long long u=0,n=0,s=0,i=0,w=0,irq=0,soft=0;
        if(sscanf(b,"cpu %llu %llu %llu %llu %llu %llu %llu",&u,&n,&s,&i,&w,&irq,&soft)>=4){
            unsigned long long next[4]={u+n,s+irq+soft,i+w,0},sum=0;
            for(int k=0;k<4;k++)sum+=next[k]-ticks[k];
            if(sum)*cpu=100.*(double)(sum-(next[2]-ticks[2]))/sum;
            memcpy(ticks,next,sizeof(next));
        }
    }fclose(f);
}
static void mon_collect_net(uint64_t *in,uint64_t *out){
    FILE *f=fopen("/proc/net/dev","r");*in=*out=0;if(!f)return;
    char b[512];while(fgets(b,sizeof b,f)){
        char name[64];unsigned long long rx=0,tx=0,r1,r2,r3,r4,r5,r6,t1,t2,t3,t4,t5,t6;
        if(sscanf(b," %63[^:]: %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu",name,&rx,&r1,&r2,&r3,&r4,&r5,&r6,&t1,&tx,&t2,&t3,&t4,&t5,&t6,&r1,&r2)==17 && strcmp(name,"lo")){*in+=rx;*out+=tx;}
    }fclose(f);
}
static int mon_collect_mounts(MonMount *out,int cap){
    FILE *f=fopen("/proc/mounts","r");if(!f)return 0;char dev[256],mnt[256],type[32],opts[256];int n=0;
    while(n<cap && fscanf(f,"%255s %255s %31s %255s %*d %*d",dev,mnt,type,opts)==4){
        if(!strncmp(mnt,"/proc",5)||!strncmp(mnt,"/sys",4)||!strncmp(mnt,"/dev",4))continue;
        struct statvfs st;if(statvfs(mnt,&st))continue;
        MonMount *x=&out[n++];memset(x,0,sizeof(*x));mon_copy(x->name,sizeof(x->name),dev);mon_copy(x->path,sizeof(x->path),mnt);mon_copy(x->type,sizeof(x->type),type);
        x->total=st.f_blocks*(uint64_t)st.f_frsize;x->free_bytes=st.f_bfree*(uint64_t)st.f_frsize;x->avail=st.f_bavail*(uint64_t)st.f_frsize;
    }fclose(f);return n;
}
static int mon_collect_threads(int pid,MonThread *out){(void)pid;(void)out;return -1;}
static int mon_collect_regions(int pid,MonRegion *out){(void)pid;(void)out;return -1;}
#endif

static void mon_detail_request(int page,int pid){
    pthread_mutex_lock(&D.mu);
    if(D.page!=page || D.pid!=pid){
        D.page=page;D.pid=pid;D.pending=(pid>0);D.valid=0;D.count=0;D.rusage_valid=0;
        D.request_id++;D.revision++;
    }
    pthread_mutex_unlock(&D.mu);
}
typedef struct {
    int valid;
    uint64_t footprint,resident,wired,disk_read,disk_write,pageins,idle_wakeups,interrupt_wakeups;
} MonRusage;
static void mon_collect_rusage(int pid,MonRusage *result){
    result->valid=0;
#if defined(__APPLE__)
    struct rusage_info_v2 ru={0};
    if(proc_pid_rusage(pid,RUSAGE_INFO_V2,(rusage_info_t *)&ru)==0){
        result->valid=1;
        result->footprint=ru.ri_phys_footprint;
        result->resident=ru.ri_resident_size;
        result->wired=ru.ri_wired_size;
        result->disk_read=ru.ri_diskio_bytesread;
        result->disk_write=ru.ri_diskio_byteswritten;
        result->pageins=ru.ri_pageins;
        result->idle_wakeups=ru.ri_pkg_idle_wkups;
        result->interrupt_wakeups=ru.ri_interrupt_wkups;
    }
#else
    (void)pid;
#endif
}

static void *mon_detail_worker(void *arg){
    (void)arg;
    MonThread *threads=malloc(sizeof(MonThread)*MON_THREADS);
    MonRegion *regions=malloc(sizeof(MonRegion)*MON_REGIONS);
    if(!threads || !regions){free(threads);free(regions);return NULL;}
    int last_page=0,last_pid=0;
    uint64_t last_at=0;
    while(1){
        pthread_mutex_lock(&D.mu);
        int stop=D.stop,page=D.page,pid=D.pid,pending=D.pending;
        unsigned long request_id=D.request_id;
        pthread_mutex_unlock(&D.mu);
        if(stop)break;
        uint64_t now=mon_now_ns();
        uint64_t interval=page==1?1000000000ULL:4000000000ULL;
        if(pid>0 && (page==1||page==2) &&
           (pending || pid!=last_pid || page!=last_page || now-last_at>=interval)){
            int count=(page==1)?mon_collect_threads(pid,threads):mon_collect_regions(pid,regions);
            MonRusage resource={0};
            if(page==2)mon_collect_rusage(pid,&resource);
            pthread_mutex_lock(&D.mu);
            if(!D.stop && request_id==D.request_id && D.pid==pid && D.page==page){
                D.valid=count>=0;
                D.count=count>=0?count:0;
                if(count>0){
                    if(page==1)memcpy(D.threads,threads,(size_t)count*sizeof(*threads));
                    else memcpy(D.regions,regions,(size_t)count*sizeof(*regions));
                }
                if(page==2){
                    D.rusage_valid=resource.valid;
                    D.footprint=resource.footprint;D.resident=resource.resident;
                    D.wired=resource.wired;D.disk_read=resource.disk_read;
                    D.disk_write=resource.disk_write;D.ru_pageins=resource.pageins;
                    D.idle_wakeups=resource.idle_wakeups;
                    D.interrupt_wakeups=resource.interrupt_wakeups;
                }
                D.pending=0;D.revision++;
            }
            pthread_mutex_unlock(&D.mu);
            last_page=page;last_pid=pid;last_at=mon_now_ns();
        }
        struct timespec pause={.tv_sec=0,.tv_nsec=100000000};
        nanosleep(&pause,NULL);
    }
    free(threads);free(regions);return NULL;
}
/* UI retains its selected thread ID / region start as snapshots update. */
static void mon_detail_sync(MonUI *u){
    int page=(u->depth>0 && (u->page==1||u->page==2))?u->page:0;
    int pid=page?u->selected_pid:0;
    mon_detail_request(page,pid);
    if(!page){u->sync_pid=0;u->sync_page=0;return;}
    if(u->sync_pid!=pid || u->sync_page!=page){
        u->sync_pid=pid;u->sync_page=page;u->detail_revision=0;
        u->thread_valid=u->region_valid=0;u->rusage_valid=0;
        u->thread_count=u->region_count=0;
    }
    pthread_mutex_lock(&D.mu);
    if(D.page==page && D.pid==pid && D.revision!=u->detail_revision){
        uint64_t identity=0;
        int old_count=(page==1)?u->thread_count:u->region_count;
        if(u->detail_index>=0 && u->detail_index<old_count)
            identity=(page==1)?u->threads[u->detail_index].tid:u->regions[u->detail_index].start;
        int count=D.count;
        if(page==1){
            u->thread_count=count;u->thread_valid=D.valid;
            if(count)memcpy(u->threads,D.threads,(size_t)count*sizeof(MonThread));
        }else{
            u->region_count=count;u->region_valid=D.valid;
            u->rusage_valid=D.rusage_valid;
            u->footprint=D.footprint;u->resident=D.resident;u->wired=D.wired;
            u->disk_read=D.disk_read;u->disk_write=D.disk_write;
            u->ru_pageins=D.ru_pageins;u->idle_wakeups=D.idle_wakeups;
            u->interrupt_wakeups=D.interrupt_wakeups;
            if(count)memcpy(u->regions,D.regions,(size_t)count*sizeof(MonRegion));
        }
        int new_index=-1;
        if(identity)for(int i=0;i<count;i++){
            uint64_t key=page==1?u->threads[i].tid:u->regions[i].start;
            if(key==identity){new_index=i;break;}
        }
        if(new_index>=0)u->detail_index=new_index;
        else if(u->detail_index>=count)u->detail_index=count>0?count-1:0;
        if(u->detail_top>=count)u->detail_top=count>0?count-1:0;
        u->detail_revision=D.revision;
    }
    pthread_mutex_unlock(&D.mu);
}
static void *mon_worker(void *arg){
    (void)arg;MonProcess *cur=calloc(MON_PROCS,sizeof(*cur));MonProcess *prev=calloc(MON_PROCS,sizeof(*prev));
    MonMount *mounts=calloc(MON_MOUNTS,sizeof(*mounts));
    if(!cur||!prev||!mounts){free(cur);free(prev);free(mounts);return NULL;}
    int prev_count=0;uint64_t prev_ns=0,last_in=0,last_out=0;unsigned long long ticks[5]={0};
    for(;;){
        pthread_mutex_lock(&S.mu);int stop=S.stop;pthread_mutex_unlock(&S.mu);if(stop)break;
        uint64_t now=mon_now_ns();int n=mon_collect_processes(cur,MON_PROCS);
        double cpu=0,load[3]={0};mon_collect_cpu(&cpu,ticks);getloadavg(load,3);
        MonMem mem=mon_collect_mem();uint64_t netin=0,netout=0;
        mon_collect_net(&netin,&netout);
        int mn=mon_collect_mounts(mounts,MON_MOUNTS);
        if(n>=0 && prev_ns && now>prev_ns){
            double interval=(double)(now-prev_ns)/1.e9;
            for(int i=0;i<n;i++)for(int j=0;j<prev_count;j++)if(cur[i].pid==prev[j].pid){
                if(cur[i].cpu_ns>=prev[j].cpu_ns)
                    cur[i].cpu_pct=100.*((double)(cur[i].cpu_ns-prev[j].cpu_ns)/1.e9)/interval;
                break;
            }
        }
        pthread_mutex_lock(&S.mu);
        if(n>=0){S.count=n;memcpy(S.processes,cur,(size_t)n*sizeof(*cur));S.valid=1;}
        S.mounts=mn;memcpy(S.volumes,mounts,(size_t)mn*sizeof(*mounts));
        S.cpu=cpu;memcpy(S.load,load,sizeof(load));S.mem_total=mem.total;S.mem_used=mem.used;
        S.mem_active=mem.active;S.mem_wired=mem.wired;S.mem_compressed=mem.compressed;
        S.mem_inactive=mem.inactive;S.mem_free=mem.free_bytes;S.mem_speculative=mem.speculative;
        S.mem_pct=mem.total?100.*mem.used/mem.total:0;
        S.net_in=netin;S.net_out=netout;
        if(prev_ns && now>prev_ns && netin>=last_in && netout>=last_out){
            double dt=(double)(now-prev_ns)/1.e9;
            S.net_in_rate=(netin-last_in)/dt;S.net_out_rate=(netout-last_out)/dt;
        }
        S.cpu_history[S.history_pos]=S.cpu;S.mem_history[S.history_pos]=S.mem_pct;
        S.net_history[S.history_pos]=(S.net_in_rate+S.net_out_rate)/(1024.*1024.);
        S.history_pos=(S.history_pos+1)%MON_HISTORY;if(S.history_count<MON_HISTORY)S.history_count++;
        pthread_mutex_unlock(&S.mu);
        if(n>=0){memcpy(prev,cur,(size_t)n*sizeof(*cur));prev_count=n;}
        prev_ns=now;last_in=netin;last_out=netout;
        for(int k=0;k<10;k++){
            struct timespec t={.tv_sec=0,.tv_nsec=100000000};nanosleep(&t,NULL);
            pthread_mutex_lock(&S.mu);stop=S.stop;pthread_mutex_unlock(&S.mu);if(stop)break;
        }
    }
    free(cur);free(prev);free(mounts);return NULL;
}

static void mon_put(int y,int x,int width,const char *str,int attr){
    if(y<0||y>=LINES||x<0||x>=COLS||width<1)return;
    if(width>COLS-x)width=COLS-x;if(width<=0)return;
    /* Bright-white foreground is selected in main(), rather than dimming
       normal text to the terminal's gray ANSI white. */
    int style = (attr & ~A_DIM) | A_BOLD;
    attron(style);mvaddnstr(y,x,str,width);attroff(style);
}
static void mon_bar(int y,int x,int width,double percent){
    if(width<1)return;int fill=(int)(percent*width/100.);if(fill<0)fill=0;if(fill>width)fill=width;
    for(int i=0;i<width && x+i<COLS;i++){
        int style = A_BOLD;
        attron(style);mvaddch(y,x+i,i<fill?ACS_BLOCK:' ');
        attroff(style);
    }
}
static void mon_line(int y){if(y>=0&&y<LINES){attron(A_BOLD);mvhline(y,0,ACS_HLINE,COLS);attroff(A_BOLD);}}
static void mon_footer(const MonUI *u){
    mon_line(LINES-2);
    const char *s=u->page==0?"hjkl navigate/scroll  Tab switch  Enter inspect  1-4 pages  q quit":
      u->page==5?"j/k select  Enter inspect  Backspace return  0 overview  q quit":
      u->page==2 && u->depth==1 && u->topology?
      "j/k select region  +/- zoom  t table  Enter detail  Backspace back  q quit":
      u->page==1 && u->depth==1 && u->topology?
      "j/k select thread  t table  Enter detail  Backspace back  q quit":
      "j/k move  gg/G ends  Ctrl-d/u page  Enter/l open  h/Backspace back  q quit";
    mon_put(LINES-1,0,COLS,s,A_DIM);
}
static void mon_spark(int y,int x,int width,const double *hist,int pos,int count,double scale){
    if(width<=0||count<=0)return;
    const char *glyph=" .:-=+*#%@";
    for(int i=0;i<width && x+i<COLS;i++){
        int back=width-1-i;if(back>=count)continue;
        int idx=(pos-1-back+MON_HISTORY*2)%MON_HISTORY;
        double pct=hist[idx]/(scale>0?scale:1);int level=(int)(pct*9);
        if(level<0)level=0;if(level>9)level=9;
        attron(A_BOLD);mvaddch(y,x+i,glyph[level]);attroff(A_BOLD);
    }
}
/* Overview combines a CPU-sorted process snapshot with hardware conditions.
 * Narrow tmux splits show one lower pane at a time; Tab switches panes. */
static void mon_hw_summary(int y,int x,int w,int last,const MonHardware *h,const MonUI *u){
    if(w<8||y>last)return;
    char b[256];
    mon_put(y,x,w,"HARDWARE [Enter]",u->focus==5?A_REVERSE:0);
    int row=y+1;
    if(row<=last){
        if(h->wifi_available)snprintf(b,sizeof b,"Wi-Fi %ddBm  %s",h->wifi_rssi,
            h->wifi_rssi>=-55?"Strong":h->wifi_rssi>=-70?"Good":h->wifi_rssi>=-80?"Fair":"Weak");
        else snprintf(b,sizeof b,"Wi-Fi: %s",h->wifi_status);
        mon_put(row++,x,w,b,u->focus==5&&u->hardware_index==0?A_REVERSE:0);
    }
    if(row<=last){
        if(h->bt_available)snprintf(b,sizeof b,"Bluetooth %s  %d device(s)",h->bt_powered?"On":"Off",h->bt_connected);
        else snprintf(b,sizeof b,"Bluetooth: %s",h->bt_status);
        mon_put(row++,x,w,b,u->focus==5&&u->hardware_index==1?A_REVERSE:0);
    }
    if(row<=last){
        if(h->battery_available){
            if(h->battery_minutes>=0)snprintf(b,sizeof b,"Battery %d%%  %dh %02dm",h->battery_pct,h->battery_minutes/60,h->battery_minutes%60);
            else snprintf(b,sizeof b,"Battery %d%%  %s",h->battery_pct,h->battery_status);
        }else snprintf(b,sizeof b,"Battery: %s",h->battery_status);
        mon_put(row++,x,w,b,u->focus==5&&u->hardware_index==2?A_REVERSE:0);
    }
    if(row<=last){
        if(h->temperature_available)snprintf(b,sizeof b,"Temp %.1f C  %s",h->cpu_temperature_c,h->thermal_state);
        else if(h->thermal_available)snprintf(b,sizeof b,"Thermal: %s",h->thermal_state);
        else snprintf(b,sizeof b,"Thermal: unavailable");
        mon_put(row++,x,w,b,u->focus==5&&u->hardware_index==3?A_REVERSE:0);
    }
    if(row<=last && h->wifi_available){
        int strength=(h->wifi_rssi+95)*100/55;if(strength<0)strength=0;if(strength>100)strength=100;
        mon_bar(row++,x,w-1,(double)strength);
        if(row<=last && h->wifi_noise<0){snprintf(b,sizeof b,"Wi-Fi SNR %ddB | Noise %ddBm",h->wifi_rssi-h->wifi_noise,h->wifi_noise);mon_put(row++,x,w,b,0);}
        if(row<=last && h->wifi_tx_mbps>0){snprintf(b,sizeof b,"Link %d Mbps",h->wifi_tx_mbps);mon_put(row++,x,w,b,0);}
    }
    if(row<=last && h->battery_available){
        snprintf(b,sizeof b,"Power: %s%s",h->on_ac?"AC":"battery",h->charging?" (charging)":"");
        mon_put(row++,x,w,b,0);
    }
    if(row<=last && h->model[0])mon_put(row++,x,w,h->model,0);
    if(row<=last)mon_put(row,x,w,"Tab switch | Enter detail",0);
}
static void mon_overview(MonUI *u){
    int half=COLS/2,w=half-5;if(w<8)w=8;
    char b[256],m1[32],m2[32];
    mon_bytes(S.mem_used,m1,sizeof(m1));mon_bytes(S.mem_total,m2,sizeof(m2));
    const char *names[]={"CPU","MEMORY","NETWORK","DISK"};
    for(int i=0;i<4;i++){
        int y=1+(i/2)*7,x=2+(i%2)*half;
        int attr=u->focus==i?A_REVERSE:0;
        snprintf(b,sizeof b," %s [Enter] ",names[i]);mon_put(y,x,w,b,attr);
        if(COLS<94){
            if(i==0)snprintf(b,sizeof b,"%.1f%%  load %.1f",S.cpu,S.load[0]);
            else if(i==1)snprintf(b,sizeof b,"%s / %s",m1,m2);
            else if(i==2){char in[20],out[20];mon_bytes((uint64_t)S.net_in_rate,in,sizeof in);mon_bytes((uint64_t)S.net_out_rate,out,sizeof out);
                snprintf(b,sizeof b,"I:%s O:%s/s",in,out);}
            else snprintf(b,sizeof b,"%d mounts",S.mounts);
            mon_put(y+2,x,w,b,0);
            if(i<2)mon_bar(y+3,x,w-2,i==0?S.cpu:S.mem_pct);
            if(i==0)mon_spark(y+4,x,w-2,S.cpu_history,S.history_pos,S.history_count,100);
            if(i==1)mon_spark(y+4,x,w-2,S.mem_history,S.history_pos,S.history_count,100);
            if(i==2)mon_spark(y+4,x,w-2,S.net_history,S.history_pos,S.history_count,10);
            continue;
        }
        if(i==0){snprintf(b,sizeof b,"Usage %.1f%%  Load %.2f %.2f %.2f",S.cpu,S.load[0],S.load[1],S.load[2]);mon_put(y+2,x,w,b,0);mon_bar(y+3,x,w-2,S.cpu);mon_spark(y+4,x,w-2,S.cpu_history,S.history_pos,S.history_count,100);}
        if(i==1){if(S.mem_total)snprintf(b,sizeof b,"Occupied est. %s / %s  %.1f%%",m1,m2,S.mem_pct);else snprintf(b,sizeof b,"Memory counters unavailable");mon_put(y+2,x,w,b,0);mon_bar(y+3,x,w-2,S.mem_pct);mon_spark(y+4,x,w-2,S.mem_history,S.history_pos,S.history_count,100);}
        if(i==2){char in[32],out[32];mon_bytes((uint64_t)S.net_in_rate,in,sizeof(in));mon_bytes((uint64_t)S.net_out_rate,out,sizeof(out));snprintf(b,sizeof(b),"IN %s/s  OUT %s/s",in,out);mon_put(y+2,x,w,b,0);mon_spark(y+4,x,w-2,S.net_history,S.history_pos,S.history_count,10);}
        if(i==3){snprintf(b,sizeof(b),"%d mounted filesystems",S.mounts);mon_put(y+2,x,w,b,0);char io[96];pthread_mutex_lock(&IO.mu);
            if(IO.io_valid)snprintf(io,sizeof io,"I/O %.2f MB/s   %.0f tps",IO.mb_s,IO.tps);
            else mon_copy(io,sizeof io,"I/O sampling...");
            pthread_mutex_unlock(&IO.mu);mon_put(y+3,x,w,io,0);}
    }
    /* The last line of each overview tile was previously blank. Show extra
       snapshot data there without changing the underlying collector cadence. */
    if(LINES>15){
        int total_threads=0;
        for(int i=0;i<S.count;i++)total_threads+=S.processes[i].threads;
        snprintf(b,sizeof b,"%d processes  |  %d threads",S.count,total_threads);
        mon_put(6,2,w,b,0);
        char active[20],wired[20];
        mon_bytes(S.mem_active,active,sizeof active);
        mon_bytes(S.mem_wired,wired,sizeof wired);
        snprintf(b,sizeof b,"Active %s  |  Wired %s",active,wired);
        mon_put(6,2+half,w,b,0);
        pthread_mutex_lock(&G.mu);
        size_t sock_n=G.socket_count;
        uint64_t pkts=G.last_seq;
        pthread_mutex_unlock(&G.mu);
        snprintf(b,sizeof b,"%zu sockets  |  %llu packets",sock_n,(unsigned long long)pkts);
        mon_put(13,2,w,b,0);
        pthread_mutex_lock(&IO.mu);
        snprintf(b,sizeof b,"Filesystem events: %s",IO.event_enabled?"ON":"OFF");
        pthread_mutex_unlock(&IO.mu);
        mon_put(13,2+half,w,b,0);
    }
    const int y=15;
    if(y>=LINES-3){mon_footer(u);return;}
    mon_line(y);
    MonHardware hw;mon_hardware_snapshot(&hw);
    int split=COLS>=100;
    int pane=split?(COLS*65/100):COLS;
    int proc_visible=split||u->focus!=5;
    int proc_width=split?pane-3:COLS-4;
    int bottom_first=y+2,last=LINES-3;
    if(proc_visible){
        snprintf(b,sizeof b,"PROCESSES (%d)  [Enter]",S.count);
        mon_put(y+1,2,proc_width,b,u->focus==4?A_REVERSE:0);
        MonProcess *top=malloc(sizeof(*top)*MON_PROCS);
        if(top){int n=S.count;memcpy(top,S.processes,(size_t)n*sizeof(*top));qsort(top,(size_t)n,sizeof(*top),mon_sort_cpu);
            int slots=last-bottom_first+1;if(slots<1)slots=1;
            if(u->overview_proc_index>=n)u->overview_proc_index=n?n-1:0;
            if(u->overview_proc_index<0)u->overview_proc_index=0;
            if(u->overview_proc_index<u->overview_proc_top)u->overview_proc_top=u->overview_proc_index;
            if(u->overview_proc_index>=u->overview_proc_top+slots)u->overview_proc_top=u->overview_proc_index-slots+1;
            for(int i=0;i<slots && u->overview_proc_top+i<n;i++){
                int k=u->overview_proc_top+i;char mem[24];mon_bytes(top[k].rss,mem,sizeof mem);
                if(proc_width>=69)snprintf(b,sizeof b,"%6d %-19.19s %5.1f%% %8s %3dT",top[k].pid,top[k].name,top[k].cpu_pct,mem,top[k].threads);
                else if(proc_width>=40)snprintf(b,sizeof b,"%5d %-16.16s %5.1f%% %7s",top[k].pid,top[k].name,top[k].cpu_pct,mem);
                else snprintf(b,sizeof b,"%5d %-12.12s %4.1f%%",top[k].pid,top[k].name,top[k].cpu_pct);
                mon_put(bottom_first+i,2,proc_width,b,u->focus==4&&k==u->overview_proc_index?A_REVERSE:0);
            }
            free(top);
        }
    }
    if(split){
        for(int row=y+1;row<LINES-2;row++)mvaddch(row,pane,ACS_VLINE);
        mon_hw_summary(y+1,pane+2,COLS-pane-4,last,&hw,u);
    }else if(u->focus==5){
        mon_hw_summary(y+1,2,COLS-4,last,&hw,u);
    }
    mon_footer(u);
}
static int mon_overview_pid(const MonUI *u){
    MonProcess *rows=malloc(sizeof(*rows)*MON_PROCS);if(!rows)return 0;
    int n=S.count;memcpy(rows,S.processes,(size_t)n*sizeof(*rows));
    qsort(rows,(size_t)n,sizeof(*rows),mon_sort_cpu);
    int pid=u->overview_proc_index<n?rows[u->overview_proc_index].pid:0;
    free(rows);return pid;
}
static void mon_hardware_page(MonUI *u){
    MonHardware h;mon_hardware_snapshot(&h);
    const char *names[]={"Wi-Fi", "Bluetooth", "Battery", "Thermal / temperature"};
    char b[256];
    mon_put(1,2,COLS-4,"HARDWARE   |   Live system conditions",A_BOLD);
    if(u->depth==0){
        for(int i=0;i<4;i++){
            snprintf(b,sizeof b,"%s%s",i==u->hardware_index?"> ":"  ",names[i]);
            mon_put(3+3*i,2,COLS-4,b,i==u->hardware_index?A_REVERSE:0);
            if(i==0)snprintf(b,sizeof b,"%s",h.wifi_status);
            else if(i==1)snprintf(b,sizeof b,"%s",h.bt_status);
            else if(i==2)snprintf(b,sizeof b,"%s",h.battery_status);
            else snprintf(b,sizeof b,"%s",h.thermal_status);
            mon_put(4+3*i,4,COLS-6,b,0);
        }
        return;
    }
    int i=u->hardware_index;
    snprintf(b,sizeof b,"%s  |  %s",names[i],h.model[0]?h.model:"macOS");
    mon_put(3,2,COLS-4,b,A_BOLD);
    if(i==0){
        mon_put(5,2,COLS-4,h.wifi_status,0);
        if(!h.wifi_available)mon_put(7,2,COLS-4,"RSSI unavailable; run sudo -v before starting catscan",0);
        else{
            snprintf(b,sizeof b,"Signal: %d dBm",h.wifi_rssi);mon_put(7,2,COLS-4,b,0);
            if(h.wifi_noise<0){snprintf(b,sizeof b,"Noise: %d dBm  |  SNR: %d dB",h.wifi_noise,h.wifi_rssi-h.wifi_noise);mon_put(8,2,COLS-4,b,0);}
            int strength=(h.wifi_rssi+95)*100/55;if(strength<0)strength=0;if(strength>100)strength=100;
            mon_bar(9,2,COLS-6,strength);
        }
        if(h.wifi_ssid[0]){snprintf(b,sizeof b,"SSID: %s",h.wifi_ssid);mon_put(11,2,COLS-4,b,0);}
        if(h.wifi_channel_valid){snprintf(b,sizeof b,"Channel: %s",h.wifi_channel);mon_put(12,2,COLS-4,b,0);}
        if(h.wifi_tx_mbps>0){snprintf(b,sizeof b,"Tx link rate: %d Mbps",h.wifi_tx_mbps);mon_put(13,2,COLS-4,b,0);}
    }else if(i==1){
        mon_put(5,2,COLS-4,h.bt_status,0);
        if(h.bt_available){snprintf(b,sizeof b,"Controller: %s",h.bt_powered?"On":"Off");mon_put(7,2,COLS-4,b,0);
            snprintf(b,sizeof b,"Connected devices: %d",h.bt_connected);mon_put(8,2,COLS-4,b,0);}
        mon_put(10,2,COLS-4,"Per-device Bluetooth RSSI is not consistently exposed by macOS.",0);
    }else if(i==2){
        mon_put(5,2,COLS-4,h.battery_status,0);
        if(h.battery_available){snprintf(b,sizeof b,"Charge: %d%%",h.battery_pct);mon_put(7,2,COLS-4,b,0);
            snprintf(b,sizeof b,"Power source: %s",h.on_ac?"AC adapter":"Battery");mon_put(8,2,COLS-4,b,0);
            snprintf(b,sizeof b,"Charging: %s",h.charging?"Yes":"No");mon_put(9,2,COLS-4,b,0);
            if(h.battery_minutes>=0){snprintf(b,sizeof b,"Estimated %s: %dh %02dm",h.on_ac?"time to full":"remaining",h.battery_minutes/60,h.battery_minutes%60);mon_put(10,2,COLS-4,b,0);}}
    }else{
        mon_put(5,2,COLS-4,h.thermal_status,0);
        if(h.thermal_available){snprintf(b,sizeof b,"Thermal pressure: %s",h.thermal_state);mon_put(7,2,COLS-4,b,0);}
        if(h.temperature_available){snprintf(b,sizeof b,"CPU temperature: %.1f C",h.cpu_temperature_c);mon_put(8,2,COLS-4,b,0);}
        else mon_put(8,2,COLS-4,"CPU temperature: not exposed by this sampler/hardware",0);
    }
}
static void mon_clamp_selection(int *idx,int *top,int count,int first,int last){
    if(count<=0){*idx=*top=0;return;}
    if(*idx<0)*idx=0;if(*idx>=count)*idx=count-1;
    int visible=last-first+1;if(visible<1)visible=1;
    if(*idx<*top)*top=*idx;if(*idx>=*top+visible)*top=*idx-visible+1;
}
static int mon_render_processes(MonUI *u,int memory){
    MonProcess *rows=malloc(sizeof(MonProcess)*MON_PROCS);if(!rows)return 0;
    int n=S.count;memcpy(rows,S.processes,(size_t)n*sizeof(*rows));
    qsort(rows,(size_t)n,sizeof(*rows),memory?mon_sort_mem:mon_sort_cpu);
    int first=memory?8:4,last=LINES-3;mon_clamp_selection(&u->index[u->page],&u->top[u->page],n,first,last);
    if(memory){
        char line[256],used[28],total[28],active[28],wired[28],compressed[28],inactive[28],freeb[28],spec[28];
        mon_bytes(S.mem_used,used,sizeof used);mon_bytes(S.mem_total,total,sizeof total);
        mon_bytes(S.mem_active,active,sizeof active);mon_bytes(S.mem_wired,wired,sizeof wired);
        mon_bytes(S.mem_compressed,compressed,sizeof compressed);mon_bytes(S.mem_inactive,inactive,sizeof inactive);
        mon_bytes(S.mem_free,freeb,sizeof freeb);mon_bytes(S.mem_speculative,spec,sizeof spec);
        if(S.mem_total)snprintf(line,sizeof line,"Occupied (estimated): %s / %s  %.1f%%",used,total,S.mem_pct);else snprintf(line,sizeof line,"System memory counters unavailable");mon_put(1,2,COLS-4,line,A_BOLD);
        snprintf(line,sizeof line,"Active %s  Wired %s  Compressed %s",active,wired,compressed);mon_put(2,2,COLS-4,line,0);
        snprintf(line,sizeof line,"Inactive cache %s  Speculative %s  Free %s",inactive,spec,freeb);mon_put(3,2,COLS-4,line,0);
        mon_bar(4,2,COLS-4,S.mem_pct);
        mon_put(5,2,COLS-4,"Approx. VM page accounting; cache is not counted as occupied",A_DIM);
    }
    mon_put(memory?6:2,1,COLS-2,memory?" PID      PROCESS                    RSS       RAM%   VIRTUAL    THREADS STATE":" PID      PROCESS                    CPU%     RSS        THREADS  STATE",A_BOLD);
    for(int i=0;i<=last-first && u->top[u->page]+i<n;i++){
        int k=u->top[u->page]+i;char b[512],mem[32],virt[32];
        mon_bytes(rows[k].rss,mem,sizeof mem);mon_bytes(rows[k].virt,virt,sizeof virt);
        if(memory)snprintf(b,sizeof b," %-8d %-26.26s %-9s %5.1f%% %-10s %-7d %c",rows[k].pid,rows[k].name,mem,S.mem_total?100.0*(double)rows[k].rss/(double)S.mem_total:0.0,virt,rows[k].threads,rows[k].state);
        else snprintf(b,sizeof b," %-8d %-26.26s %-8.1f %-10s %-7d %c",rows[k].pid,rows[k].name,rows[k].cpu_pct,mem,rows[k].threads,rows[k].state);
        mon_put(first+i,0,COLS,b,k==u->index[u->page]?A_REVERSE:0);
    }
    if(n==0)mon_put(first,2,COLS-4,"Scanning processes...",A_DIM);
    free(rows);return n;
}
static int mon_process_selection(MonUI *u){
    MonProcess *rows=malloc(sizeof(MonProcess)*MON_PROCS);if(!rows)return 0;
    int n=S.count;memcpy(rows,S.processes,(size_t)n*sizeof(*rows));
    qsort(rows,(size_t)n,sizeof(*rows),u->page==2?mon_sort_mem:mon_sort_cpu);
    int selected=(n>0 && u->index[u->page]<n)?rows[u->index[u->page]].pid:0;
    free(rows);return selected;
}
static void mon_draw_threads(MonUI *u){
    int first=4,last=LINES-3;
    char b[1024];
    if(!u->thread_valid){
        mon_put(3,2,COLS-4,"THREAD MAP UNAVAILABLE",A_BOLD);
        mon_put(5,2,COLS-4,"Thread enumeration denied, process exited, or sample still loading.",0);
        mon_put(7,2,COLS-4,"Try another PID, including catscan's own process.",0);
        mon_put(9,2,COLS-4,"macOS can restrict inspection of protected processes even as root.",0);
        return;
    }
    if(u->thread_count<=0){
        mon_put(3,2,COLS-4,"No inspectable threads reported for this process.",A_BOLD);
        return;
    }
    if(u->detail_index<0)u->detail_index=0;
    if(u->detail_index>=u->thread_count)u->detail_index=u->thread_count-1;
    if(u->depth==2){
        MonThread *t=&u->threads[u->detail_index];
        snprintf(b,sizeof b,"Thread %llu  |  PID %d",(unsigned long long)t->tid,u->selected_pid);
        mon_put(3,2,COLS-4,b,A_BOLD);
        snprintf(b,sizeof b,"Name: %s",t->name);mon_put(5,2,COLS-4,b,0);
        snprintf(b,sizeof b,"State: %s",t->state);mon_put(6,2,COLS-4,b,0);
        snprintf(b,sizeof b,"CPU: %.1f%%  User: %.3f s  System: %.3f s",t->cpu_pct,t->user_ns/1.e9,t->sys_ns/1.e9);
        mon_put(7,2,COLS-4,b,0);
        mon_put(9,2,COLS-4,"Thread counters are live; these are not physical-core assignments.",0);
        return;
    }
    if(u->topology){
        int running=0,waiting=0,stopped=0,other=0;
        double cpu_sum=0.0;
        for(int i=0;i<u->thread_count;i++){
            switch(mon_thread_state_char(u->threads[i].state)){
                case 'R':running++;break;
                case 'W':waiting++;break;
                case 'S':stopped++;break;
                default:other++;break;
            }
            cpu_sum+=u->threads[i].cpu_pct;
        }
        snprintf(b,sizeof b,"THREAD STATE RASTER | PID %d | %d logical threads | t: table",u->selected_pid,u->thread_count);
        mon_put(2,2,COLS-4,b,A_BOLD);
        snprintf(b,sizeof b,"R running %d   W waiting %d   S stopped %d   ? other %d   |   sampled CPU %.1f%%",
                 running,waiting,stopped,other,cpu_sum);
        mon_put(3,2,COLS-4,b,0);
        mon_put(4,2,COLS-4,"One character = one thread, ordered by TID (not physical CPU placement).",0);
        mon_put(5,2,COLS-4,"@ selected   R running   W waiting   S stopped   ? other   . unused slot",0);
        int cols=COLS-20;
        if(cols<1)cols=1;
        if(cols>850)cols=850;
        int map_first=7;
        int map_last=LINES>=23?LINES-10:LINES-4;
        int rows=map_last-map_first+1;
        if(rows<1)return;
        int cap=cols*rows;
        if(u->detail_index<u->detail_top || u->detail_index>=u->detail_top+cap)
            u->detail_top=(u->detail_index/cap)*cap;
        if(u->detail_top<0)u->detail_top=0;
        char cells[852];
        for(int row=0;row<rows;row++){
            int start=u->detail_top+row*cols;
            if(start>=u->thread_count)break;
            if(mon_thread_ascii_row(u->threads,u->thread_count,u->detail_index,start,cols,cells,sizeof cells)!=0)break;
            snprintf(b,sizeof b,"  %6d-%-6d |%s|",start,(start+cols<u->thread_count?start+cols:u->thread_count)-1,cells);
            mon_put(map_first+row,0,COLS,b,A_BOLD);
        }
        MonThread *t=&u->threads[u->detail_index];
        snprintf(b,sizeof b,"Selected %d/%d | TID %llu | %s | CPU %.1f%% | %s",
                 u->detail_index+1,u->thread_count,(unsigned long long)t->tid,t->state,t->cpu_pct,t->name);
        mon_put(LINES-3,2,COLS-4,b,A_BOLD);
        if(LINES>=23){
            int y=LINES-8;
            mon_line(y++);
            mon_put(y++,2,COLS-4,"SELECTED THREAD / LIVE COUNTERS",A_BOLD);
            snprintf(b,sizeof b,"TID %llu  |  name %s  |  state %s",(unsigned long long)t->tid,t->name,t->state);
            mon_put(y++,2,COLS-4,b,0);
            snprintf(b,sizeof b,"CPU %.1f%%  |  user %.3f s  |  system %.3f s",t->cpu_pct,t->user_ns/1.e9,t->sys_ns/1.e9);
            mon_put(y++,2,COLS-4,b,0);
            mon_put(y++,2,COLS-4,"j/k select next thread   Enter inspect   gg/G first/last",0);
        }
        return;
    }
    mon_put(2,1,COLS-2," TID             NAME                   STATE          CPU%        USER(s)      SYSTEM(s)  [t raster]",A_BOLD);
    mon_clamp_selection(&u->detail_index,&u->detail_top,u->thread_count,first,last);
    for(int i=0;i<=last-first&&u->detail_top+i<u->thread_count;i++){
        int k=u->detail_top+i;MonThread *t=&u->threads[k];
        snprintf(b,sizeof b," %-15llu %-22.22s %-14.14s %-10.1f %-12.2f %.2f",(unsigned long long)t->tid,t->name,t->state,t->cpu_pct,t->user_ns/1.e9,t->sys_ns/1.e9);
        mon_put(first+i,0,COLS,b,k==u->detail_index?A_REVERSE:0);
    }
}
/* Address-space raster. Every character corresponds to an address interval,
 * and every address comes from vm_region_64. Gaps are literal unmapped spans.
 * This does NOT identify individual malloc/ASan allocations or physical RAM. */
static void mon_draw_vm_ascii(MonUI *u){
    if(u->region_count<=0)return;
    int title=LINES>=23?12:(LINES>=18?9:4);
    int first=title+2, last=LINES-5;
    if(last<first)return;
    int rows=last-first+1;
    int cols=COLS-24;
    if(cols<10)return;
    if(cols>4096)cols=4096;
    size_t ncells=(size_t)rows*(size_t)cols;
    char *cells=malloc(ncells);
    if(!cells)return;
    if(u->detail_index>=u->region_count)u->detail_index=u->region_count-1;
    if(u->detail_index<0)u->detail_index=0;
    MonVmWindow view={0};
    if(mon_vm_ascii_map(u->regions,u->region_count,u->detail_index,
                        u->map_zoom,cols,rows,cells,&view)!=0){free(cells);return;}
    char b[8192],sz[40],span[40];
    mon_bytes(view.end-view.start,span,sizeof span);
    snprintf(b,sizeof b,"VIRTUAL ADDRESS RASTER | t: table   +/-: zoom   j/k: region   Enter: detail");
    mon_put(title,2,COLS-4,b,A_BOLD);
    snprintf(b,sizeof b,"0x%016llx ... 0x%016llx  |  %s window  |  zoom %+d  |  region %d/%d",
             (unsigned long long)view.start,(unsigned long long)view.end,span,
             u->map_zoom,u->detail_index+1,u->region_count);
    mon_put(title+1,2,COLS-4,b,0);
    for(int r=0;r<rows;r++){
        uint64_t start=view.start+(uint64_t)(((__uint128_t)(view.end-view.start)*r)/(uint64_t)rows);
        snprintf(b,sizeof b,"  %016llx |%.*s|",(unsigned long long)start,cols,cells+(size_t)r*cols);
        mon_put(first+r,0,COLS,b,A_BOLD);
    }
    mon_put(LINES-4,2,COLS-4,COLS>=92?
       "@ SELECTED   E exec   F file   W writable anonymous   A other anonymous   * mixed   . gap":
       "@ selected  E exec  F file  W anon  A anon  * mixed  . gap",0);
    MonRegion *r=&u->regions[u->detail_index];
    mon_bytes(r->end-r->start,sz,sizeof sz);
    snprintf(b,sizeof b,"Selected: 0x%016llx  %s  %s  %s",
             (unsigned long long)r->start,sz,r->perm,r->path[0]?r->path:"anonymous region");
    mon_put(LINES-3,2,COLS-4,b,A_BOLD);
    free(cells);
}
static void mon_draw_regions(MonUI *u){
    char b[768];
    MonProcess *proc=NULL;
    for(int i=0;i<S.count;i++)if(S.processes[i].pid==u->selected_pid){proc=&S.processes[i];break;}
    if(!proc){mon_put(1,2,COLS-4,"Process exited or snapshot unavailable",A_BOLD);return;}
    char rss[32],virt[32],foot[32],resident[32],wired[32],rd[32],wr[32];
    mon_bytes(proc->rss,rss,sizeof rss);mon_bytes(proc->virt,virt,sizeof virt);
    mon_bytes(u->footprint,foot,sizeof foot);mon_bytes(u->resident,resident,sizeof resident);
    mon_bytes(u->wired,wired,sizeof wired);mon_bytes(u->disk_read,rd,sizeof rd);mon_bytes(u->disk_write,wr,sizeof wr);
    snprintf(b,sizeof b,"%s  |  PID %d  |  UID %d  |  State %c  |  %d threads",
             proc->name,proc->pid,proc->uid,proc->state,proc->threads);
    mon_put(1,2,COLS-4,b,A_BOLD);
    snprintf(b,sizeof b,"RSS %s  (%.2f%% RAM)  |  Virtual %s  |  CPU %.1f%%",
             rss,S.mem_total?100.0*(double)proc->rss/S.mem_total:0,virt,proc->cpu_pct);
    mon_put(2,2,COLS-4,b,0);
    if(u->rusage_valid){
        snprintf(b,sizeof b,"Physical footprint %s  |  rusage resident %s  |  wired %s",foot,resident,wired);
        mon_put(3,2,COLS-4,b,0);
        snprintf(b,sizeof b,"Cumulative disk I/O: read %s  |  written %s  |  page-ins %llu",
                 rd,wr,(unsigned long long)u->ru_pageins);
        mon_put(4,2,COLS-4,b,0);
        snprintf(b,sizeof b,"Wakeups: idle %llu  |  interrupt %llu",
                 (unsigned long long)u->idle_wakeups,(unsigned long long)u->interrupt_wakeups);
        mon_put(5,2,COLS-4,b,0);
    }else mon_put(3,2,COLS-4,"Extended rusage unavailable for this process",0);
    snprintf(b,sizeof b,"Faults %llu  |  COW faults %llu  |  task page-ins %llu  |  context switches %llu",
             (unsigned long long)proc->faults,(unsigned long long)proc->cow_faults,
             (unsigned long long)proc->pageins,(unsigned long long)proc->context_switches);
    mon_put(6,2,COLS-4,b,0);
    snprintf(b,sizeof b,"Cumulative syscalls: UNIX %llu  |  Mach %llu",
             (unsigned long long)proc->syscalls_unix,(unsigned long long)proc->syscalls_mach);
    mon_put(7,2,COLS-4,b,0);
    mon_line(9);
    if(!u->region_valid){
        mon_put(10,2,COLS-4,"VM MAP: unavailable (task-port access restricted or process exited)",A_BOLD);
        mon_put(12,2,COLS-4,"macOS can deny task_for_pid even when running as root.",0);
        mon_put(13,2,COLS-4,"Process and rusage counters above do not require a VM region map.",0);
        mon_put(15,2,COLS-4,"Select a process you own or catscan to test region inspection.",0);
        return;
    }
    uint64_t mapped=0,anonymous=0,backed=0,largest=0;
    int anon_n=0,backed_n=0,readable=0,writable=0,executable=0;
    for(int i=0;i<u->region_count;i++){
        const MonRegion *r=&u->regions[i];uint64_t size=r->end-r->start;mapped+=size;
        if(size>largest)largest=size;
        if(r->path[0]){backed+=size;backed_n++;}else{anonymous+=size;anon_n++;}
        if(strchr(r->perm,'r'))readable++;
        if(strchr(r->perm,'w'))writable++;
        if(strchr(r->perm,'x'))executable++;
    }
    char mapped_s[24],anon_s[24],back_s[24],large_s[24];
    mon_bytes(mapped,mapped_s,sizeof mapped_s);mon_bytes(anonymous,anon_s,sizeof anon_s);
    mon_bytes(backed,back_s,sizeof back_s);mon_bytes(largest,large_s,sizeof large_s);
    snprintf(b,sizeof b,"VM MAP: %d regions | mapped %s | anon %s (%d) | file %s (%d) | largest %s",
             u->region_count,mapped_s,anon_s,anon_n,back_s,backed_n,large_s);
    mon_put(10,2,COLS-4,b,A_BOLD);
    snprintf(b,sizeof b,"Permissions: readable %d  writable %d  executable %d",readable,writable,executable);
    mon_put(11,2,COLS-4,b,0);
    uint64_t gap_total=0,gap_largest=0;
    int gaps=0;
    for(int k=1;k<u->region_count;k++){
        if(u->regions[k].start>u->regions[k-1].end){
            uint64_t gap=u->regions[k].start-u->regions[k-1].end;
            gaps++;gap_total+=gap;
            if(gap>gap_largest)gap_largest=gap;
        }
    }
    char gap_s[32],largest_s[32];
    mon_bytes(gap_total,gap_s,sizeof gap_s);
    mon_bytes(gap_largest,largest_s,sizeof largest_s);
    snprintf(b,sizeof b,"Observed address gaps: %d  |  unmapped span %s  |  largest gap %s",gaps,gap_s,largest_s);
    mon_put(8,2,COLS-4,b,0);
    if(u->depth==2){
        if(u->detail_index>=u->region_count)return;
        MonRegion *r=&u->regions[u->detail_index];char size[32];
        mon_bytes(r->end-r->start,size,sizeof size);
        snprintf(b,sizeof b,"Region %d / %d",u->detail_index+1,u->region_count);mon_put(13,2,COLS-4,b,A_BOLD);
        snprintf(b,sizeof b,"Start 0x%016llx    End 0x%016llx",(unsigned long long)r->start,(unsigned long long)r->end);
        mon_put(14,2,COLS-4,b,0);
        snprintf(b,sizeof b,"Size %s    Permissions %s",size,r->perm);mon_put(15,2,COLS-4,b,0);
        snprintf(b,sizeof b,"Mapped file: %s",r->path[0]?r->path:"(anonymous / no path)");mon_put(17,2,COLS-4,b,0);
        if(LINES>=26){
            uint64_t before=u->detail_index>0?u->regions[u->detail_index-1].end:r->start;
            uint64_t after=u->detail_index+1<u->region_count?u->regions[u->detail_index+1].start:r->end;
            char gap_prev[24],gap_next[24];
            mon_bytes(r->start>before?r->start-before:0,gap_prev,sizeof gap_prev);
            mon_bytes(after>r->end?after-r->end:0,gap_next,sizeof gap_next);
            snprintf(b,sizeof b,"Unmapped gap before: %s  |  after: %s",gap_prev,gap_next);
            mon_put(18,2,COLS-4,b,0);
            int rows=LINES-25,cols=COLS-24;
            if(rows>8)rows=8;
            if(cols>4096)cols=4096;
            if(rows>0&&cols>10){
                char *cells=malloc((size_t)rows*cols);
                MonVmWindow window={0};
                if(cells && !mon_vm_ascii_map(u->regions,u->region_count,u->detail_index,
                                              u->map_zoom,cols,rows,cells,&window)){
                    mon_put(19,2,COLS-4,"LOCAL VIRTUAL ADDRESS CONTEXT (relative to selected region)",A_BOLD);
                    snprintf(b,sizeof b,"0x%016llx ... 0x%016llx",
                             (unsigned long long)window.start,(unsigned long long)window.end);
                    mon_put(20,2,COLS-4,b,0);
                    for(int row=0;row<rows;row++){
                        uint64_t addr=window.start+(uint64_t)(((__uint128_t)(window.end-window.start)*row)/(uint64_t)rows);
                        snprintf(b,sizeof b,"  %016llx |%.*s|",(unsigned long long)addr,cols,cells+(size_t)row*cols);
                        mon_put(21+row,0,COLS,b,0);
                    }
                }
                free(cells);
            }
        }
        return;
    }
    if(u->topology){mon_draw_vm_ascii(u);return;}
    mon_put(12,1,COLS-2," START ADDRESS        END ADDRESS          SIZE       PERM   MAPPED FILE [t topology]",A_BOLD);
    int first=13,last=LINES-3;
    mon_clamp_selection(&u->detail_index,&u->detail_top,u->region_count,first,last);
    for(int i=0;i<=last-first&&u->detail_top+i<u->region_count;i++){
        int k=u->detail_top+i;MonRegion *r=&u->regions[k];char size[32];
        mon_bytes(r->end-r->start,size,sizeof size);
        snprintf(b,sizeof b," %016llx  %016llx  %-9s %-5s %s",
                 (unsigned long long)r->start,(unsigned long long)r->end,size,r->perm,r->path);
        mon_put(first+i,0,COLS,b,k==u->detail_index?A_REVERSE:0);
    }
}
static void mon_io_publish(const char *status,double mb,double tps,double kb,int valid){
    pthread_mutex_lock(&IO.mu);
    IO.io_valid=valid;IO.mb_s=mb;IO.tps=tps;IO.kb_t=kb;
    mon_copy(IO.io_status,sizeof IO.io_status,status);
    pthread_mutex_unlock(&IO.mu);
}
/* Parse iostat's repeating KB/t tps MB/s columns. Headers are ignored.
 * First numeric sample is since boot, so it is deliberately discarded. */
static int mon_io_parse(const char *line,double *mb,double *tps,double *kb){
    double values[96];int count=0;const char *p=line;
    while(*p && count<96){
        while(*p==' '||*p=='\t')p++;
        if(!*p||*p=='\n')break;
        char *end=NULL;double v=strtod(p,&end);
        if(end==p||!isfinite(v))return 0;
        values[count++]=v;p=end;
    }
    if(count<3||count%3)return 0;
    *mb=*tps=*kb=0;
    for(int i=0;i<count;i+=3){*kb+=values[i];*tps+=values[i+1];*mb+=values[i+2];}
    return 1;
}
static void *mon_io_worker(void *arg){
    (void)arg;
#if defined(__APPLE__)
    int pipefd[2];if(pipe(pipefd)){mon_io_publish("iostat pipe failed",0,0,0,0);return NULL;}
    pid_t pid=fork();
    if(pid==0){close(pipefd[0]);dup2(pipefd[1],STDOUT_FILENO);close(pipefd[1]);
        execl("/usr/sbin/iostat","iostat","-d","-w","2",(char *)NULL);_exit(127);}
    close(pipefd[1]);
    if(pid<0){close(pipefd[0]);mon_io_publish("iostat fork failed",0,0,0,0);return NULL;}
    pthread_mutex_lock(&IO.mu);IO.io_pid=pid;pthread_mutex_unlock(&IO.mu);
    FILE *f=fdopen(pipefd[0],"r");
    if(!f){close(pipefd[0]);kill(pid,SIGTERM);waitpid(pid,NULL,0);return NULL;}
    char line[4096];int numeric=0;
    mon_io_publish("iostat sampling...",0,0,0,0);
    while(fgets(line,sizeof line,f)){
        double mb,tps,kb;
        if(mon_io_parse(line,&mb,&tps,&kb)){
            numeric++;
            if(numeric>=2)mon_io_publish("iostat live (aggregate devices)",mb,tps,kb,1);
        }
        pthread_mutex_lock(&IO.mu);int stop=IO.stop;pthread_mutex_unlock(&IO.mu);
        if(stop)break;
    }
    fclose(f);kill(pid,SIGTERM);waitpid(pid,NULL,0);
    pthread_mutex_lock(&IO.mu);IO.io_pid=0;pthread_mutex_unlock(&IO.mu);
    pthread_mutex_lock(&IO.mu);
    if(!IO.stop)mon_copy(IO.io_status,sizeof IO.io_status,"iostat exited");
    pthread_mutex_unlock(&IO.mu);
#else
    mon_io_publish("Live iostat collection is macOS-only",0,0,0,0);
#endif
    return NULL;
}
static void *mon_events_worker(void *arg){
    (void)arg;
#if defined(__APPLE__)
    for(;;){
        pthread_mutex_lock(&IO.mu);int enabled=IO.event_enabled,stop=IO.stop;
        pthread_mutex_unlock(&IO.mu);
        if(stop)break;
        if(!enabled){struct timespec t={.tv_sec=0,.tv_nsec=200000000};nanosleep(&t,NULL);continue;}
        int pfd[2];if(pipe(pfd))break;
        pid_t pid=fork();
        if(pid==0){setpgid(0,0);close(pfd[0]);dup2(pfd[1],STDOUT_FILENO);dup2(pfd[1],STDERR_FILENO);close(pfd[1]);
            execl("/usr/bin/sudo","sudo","-n","/usr/bin/fs_usage","-w","-f","filesys",(char *)NULL);_exit(127);}
        close(pfd[1]);if(pid<0){close(pfd[0]);break;}
        pthread_mutex_lock(&IO.mu);IO.event_pid=pid;IO.event_alive=1;
        mon_copy(IO.event_status,sizeof IO.event_status,"fs_usage capturing (system-wide)");
        pthread_mutex_unlock(&IO.mu);
        int flags=fcntl(pfd[0],F_GETFL);if(flags>=0)fcntl(pfd[0],F_SETFL,flags|O_NONBLOCK);
        char buf[2048],partial[320];size_t used=0;
        for(;;){
            pthread_mutex_lock(&IO.mu);int quit=IO.stop||!IO.event_enabled;pthread_mutex_unlock(&IO.mu);
            if(quit)break;
            struct pollfd p={.fd=pfd[0],.events=POLLIN|POLLHUP};
            int r=poll(&p,1,150);
            if(r<0){if(errno==EINTR)continue;break;}
            if(r==0)continue;
            ssize_t n=read(pfd[0],buf,sizeof buf);
            if(n==0)break;
            if(n<0){if(errno==EAGAIN||errno==EINTR)continue;break;}
            for(ssize_t i=0;i<n;i++){
                unsigned char c=(unsigned char)buf[i];
                if(c=='\n'){
                    partial[used]=0;
                    if(used){pthread_mutex_lock(&IO.mu);
                        IO.event_seq++;mon_copy(IO.events[IO.event_seq%MON_EVENTS],320,partial);
                        pthread_mutex_unlock(&IO.mu);}
                    used=0;
                }else if(c>=32&&c<127 && used<sizeof(partial)-1)partial[used++]=(char)c;
            }
        }
        kill(-pid,SIGTERM);kill(pid,SIGTERM);close(pfd[0]);waitpid(pid,NULL,0);
        pthread_mutex_lock(&IO.mu);IO.event_pid=0;IO.event_alive=0;
        if(IO.event_enabled && !IO.stop){
            IO.event_enabled=0;
            mon_copy(IO.event_status,sizeof IO.event_status,"fs_usage exited; run sudo -v and press f again");
        }else mon_copy(IO.event_status,sizeof IO.event_status,"fs_usage stopped");
        pthread_mutex_unlock(&IO.mu);
    }
#else
    pthread_mutex_lock(&IO.mu);
    mon_copy(IO.event_status,sizeof IO.event_status,"fs_usage is macOS-only");
    pthread_mutex_unlock(&IO.mu);
#endif
    return NULL;
}
static void mon_events_toggle(void){
    pthread_mutex_lock(&IO.mu);
    IO.event_enabled=!IO.event_enabled;
    if(IO.event_enabled){IO.event_seq=0;mon_copy(IO.event_status,sizeof IO.event_status,"starting fs_usage...");}
    pthread_mutex_unlock(&IO.mu);
}
static void mon_disk(MonUI *u){
    char b[512];int first=6,last=LINES-3;
    double mb,tps,kb;int valid;char status[128];
    pthread_mutex_lock(&IO.mu);
    mb=IO.mb_s;tps=IO.tps;kb=IO.kb_t;valid=IO.io_valid;
    mon_copy(status,sizeof status,IO.io_status);
    pthread_mutex_unlock(&IO.mu);
    if(valid)snprintf(b,sizeof b,"Disk I/O (aggregate physical devices): %.2f MB/s  |  %.1f transfers/s  |  %.1f KB/transfer",mb,tps,kb);
    else snprintf(b,sizeof b,"Disk I/O: %s",status[0]?status:"sampling...");
    mon_put(1,2,COLS-4,b,A_BOLD);
    if(u->depth==2){
        pthread_mutex_lock(&IO.mu);
        snprintf(b,sizeof b,"FILESYSTEM EVENTS (system-wide)  |  %s",IO.event_status);
        mon_put(3,2,COLS-4,b,A_BOLD);
        mon_put(4,2,COLS-4,"f toggles capture  |  Backspace returns  |  may require sudo -v",0);
        unsigned long seq=IO.event_seq;
        int count=seq<MON_EVENTS?(int)seq:MON_EVENTS;
        int show=LINES-7;if(show>count)show=count;
        for(int i=0;i<show;i++){
            unsigned long id=seq-(unsigned long)(show-1-i);
            mon_put(6+i,1,COLS-2,IO.events[id%MON_EVENTS],0);
        }
        pthread_mutex_unlock(&IO.mu);
        return;
    }
    if(u->depth==0){
        mon_put(3,2,COLS-4,"Press f for system-wide live fs_usage events (opt-in; privileges required)",0);
        mon_put(4,1,COLS-2," FILESYSTEM                 MOUNT POINT                   TOTAL       USED       FREE     USE%",A_BOLD);
        mon_clamp_selection(&u->index[4],&u->top[4],S.mounts,first,last);
        for(int i=0;i<=last-first&&u->top[4]+i<S.mounts;i++){
            int k=u->top[4]+i;MonMount *m=&S.volumes[k];char total[24],used[24],freeb[24];
            mon_bytes(m->total,total,sizeof total);mon_bytes(m->total-m->free_bytes,used,sizeof used);mon_bytes(m->avail,freeb,sizeof freeb);
            double percent=m->total?100.*(m->total-m->free_bytes)/m->total:0;
            snprintf(b,sizeof b," %-26.26s %-29.29s %-10s %-10s %-9s %4.1f%%",m->name,m->path,total,used,freeb,percent);
            mon_put(first+i,0,COLS,b,k==u->index[4]?A_REVERSE:0);
        }
    }else{
        if(u->selected_mount>=S.mounts){mon_put(4,2,COLS-4,"Volume disappeared",0);return;}
        MonMount *m=&S.volumes[u->selected_mount];char total[32],freeb[32],used[32],bfree[32];
        mon_bytes(m->total,total,sizeof total);mon_bytes(m->avail,freeb,sizeof freeb);
        mon_bytes(m->free_bytes,bfree,sizeof bfree);mon_bytes(m->total-m->free_bytes,used,sizeof used);
        snprintf(b,sizeof b,"Device: %s",m->name);mon_put(3,2,COLS-4,b,A_BOLD);
        snprintf(b,sizeof b,"Mount: %s   Filesystem: %s",m->path,m->type);mon_put(5,2,COLS-4,b,0);
        snprintf(b,sizeof b,"Capacity: %s   Occupied: %s   Available to user: %s   Free blocks: %s",total,used,freeb,bfree);
        mon_put(7,2,COLS-4,b,0);
        mon_bar(9,2,COLS-5,m->total?100.*(m->total-m->free_bytes)/m->total:0);
        mon_put(11,2,COLS-4,"I/O above aggregates devices; it is NOT attributable to this selected volume.",0);
        mon_put(13,2,COLS-4,"Press f to inspect system-wide live filesystem calls.",0);
        mon_put(15,2,COLS-4,"Directory-size scanning (du) not yet implemented.",0);
    }
}
static void mon_draw(MonUI *u){
    mon_detail_sync(u);
    erase();if(LINES<12||COLS<48){mon_put(0,0,COLS,"Increase pane to at least 48x12",A_BOLD);refresh();return;}
    if(u->page==3){
        draw(&u->net); /* preserve original netinspect screen + keyboard behavior */
        return;
    }
    pthread_mutex_lock(&S.mu);
    if(u->page==0)mon_overview(u);
    else if(u->page==1||u->page==2){
        if(!u->depth)mon_render_processes(u,u->page==2);
        else if(u->page==1)mon_draw_threads(u);
        else mon_draw_regions(u);
        mon_footer(u);
    }else if(u->page==4){mon_disk(u);mon_footer(u);}
    else if(u->page==5){mon_hardware_page(u);mon_footer(u);}
    pthread_mutex_unlock(&S.mu);refresh();
}
static void mon_open(MonUI *u){
    if(u->page==0){
        if(u->focus==4){
            pthread_mutex_lock(&S.mu);int pid=mon_overview_pid(u);pthread_mutex_unlock(&S.mu);
            if(pid>0){u->page=1;u->depth=1;u->selected_pid=pid;u->detail_index=u->detail_top=0;u->topology=1;mon_detail_sync(u);}
        }else if(u->focus==5){u->page=5;u->depth=1;}
        else {u->page=u->focus+1;u->depth=0;}
        return;
    }
    if(u->page==5){u->depth=1;return;}
    if(u->page==3){
        pthread_mutex_lock(&G.mu);restore_selection(&u->net);
        if(!u->net.screen && G.socket_count){
            u->net.inspected=G.sockets[u->net.socket_index];u->net.screen=1;
            u->net.follow=0;u->net.packet_top=0;u->net.select_seq=0;u->net.detail_scroll=0;
            Match matches[PACKET_RING];size_t n=matching_packets(&u->net.inspected,matches);
            if(n)u->net.select_seq=matches[n-1].seq;
        }else if(u->net.screen)u->net.follow=!u->net.follow;
        pthread_mutex_unlock(&G.mu);return;
    }
    if(u->page==4){
        if(u->depth==0){pthread_mutex_lock(&S.mu);if(u->index[4]<S.mounts){u->selected_mount=u->index[4];u->depth=1;}pthread_mutex_unlock(&S.mu);}return;
    }
    if(u->depth==0){
        pthread_mutex_lock(&S.mu);int pid=mon_process_selection(u);pthread_mutex_unlock(&S.mu);
        if(pid<=0)return;u->selected_pid=pid;u->depth=1;u->detail_index=u->detail_top=0;
        /* CPU and Memory both open their ASCII map by default; t shows table. */
        u->topology=1;
        u->map_zoom=0;
        /* Request an async sample. Rendering never blocks on Mach VM inspection. */
        mon_detail_sync(u);
    }else if(u->depth==1 && ((u->page==1&&u->thread_count>0)||(u->page==2&&u->region_count>0)))u->depth=2;
}
static void mon_back(MonUI *u){
    if(u->page==5){if(u->depth>0)u->depth=0;else u->page=0;return;}
    if(u->page==3){if(u->net.screen){u->net.screen=0;u->net.follow=0;}else u->page=0;return;}
    if(u->depth>0){if(u->page==4 && u->depth==2)u->depth=0;else u->depth--;}else u->page=0;
}
static void mon_move(MonUI *u,int d){
    if(u->page==0){
        if(u->focus==4){u->overview_proc_index+=d;int n;pthread_mutex_lock(&S.mu);n=S.count;pthread_mutex_unlock(&S.mu);
            if(u->overview_proc_index<0)u->overview_proc_index=0;
            if(u->overview_proc_index>=n)u->overview_proc_index=n?n-1:0;}
        else if(u->focus==5){u->hardware_index+=d;if(u->hardware_index<0)u->hardware_index=0;if(u->hardware_index>3)u->hardware_index=3;}
        else u->focus=(u->focus+d+4)%4;
        return;
    }
    if(u->page==5){if(u->depth==0){u->hardware_index+=d;
        if(u->hardware_index<0)u->hardware_index=0;if(u->hardware_index>3)u->hardware_index=3;}return;}
    if(u->page==3){
        if(u->net.screen){move_packet(&u->net,d);return;}
        pthread_mutex_lock(&G.mu);restore_selection(&u->net);
        u->net.socket_index+=d;if(u->net.socket_index<0)u->net.socket_index=0;
        if(u->net.socket_index>=(int)G.socket_count)u->net.socket_index=(int)G.socket_count-1;
        if(G.socket_count)remember_socket(&u->net,&G.sockets[u->net.socket_index]);
        pthread_mutex_unlock(&G.mu);return;
    }
    if(u->depth==1 && (u->page==1||u->page==2)){
        u->detail_index+=d;int max=u->page==1?u->thread_count:u->region_count;
        if(u->detail_index<0)u->detail_index=0;if(u->detail_index>=max)u->detail_index=max>0?max-1:0;
    }else if(u->depth==0){u->index[u->page]+=d;if(u->index[u->page]<0)u->index[u->page]=0;}
}
/* Vim-style motions. In packet detail, h/l retain horizontal scrolling. */
static int mon_list_length(MonUI *u){
    if(u->page==0){if(u->focus==4){pthread_mutex_lock(&S.mu);int n=S.count;pthread_mutex_unlock(&S.mu);return n;}return u->focus==5?4:4;}
    if(u->page==5)return 4;
    if(u->page==3){
        int n=0;pthread_mutex_lock(&G.mu);
        if(u->net.screen){Match found[PACKET_RING];n=(int)matching_packets(&u->net.inspected,found);}
        else n=(int)G.socket_count;
        pthread_mutex_unlock(&G.mu);return n;
    }
    if(u->page==1||u->page==2){
        if(u->depth==1)return u->page==1?u->thread_count:u->region_count;
        if(u->depth>=2)return 0;
        pthread_mutex_lock(&S.mu);int n=S.count;pthread_mutex_unlock(&S.mu);return n;
    }
    if(u->page==4&&u->depth==0){pthread_mutex_lock(&S.mu);int n=S.mounts;pthread_mutex_unlock(&S.mu);return n;}
    return 0;
}
static void mon_jump(MonUI *u,int to_end){
    if(u->page==0){
        if(u->focus==4)u->overview_proc_index=to_end?(mon_list_length(u)>0?mon_list_length(u)-1:0):0;
        else if(u->focus==5)u->hardware_index=to_end?3:0;
        else u->focus=to_end?3:0;
        return;
    }
    if(u->page==5){u->hardware_index=to_end?3:0;return;}
    int n=mon_list_length(u);if(!n)return;
    if(u->page==3){
        if(u->net.screen){
            pthread_mutex_lock(&G.mu);
            Match found[PACKET_RING];size_t count=matching_packets(&u->net.inspected,found);
            if(count){u->net.select_seq=found[to_end?count-1:0].seq;u->net.follow=0;u->net.detail_scroll=0;}
            pthread_mutex_unlock(&G.mu);
        }else{
            pthread_mutex_lock(&G.mu);u->net.socket_index=to_end?n-1:0;
            remember_socket(&u->net,&G.sockets[u->net.socket_index]);pthread_mutex_unlock(&G.mu);
        }
        return;
    }
    if((u->page==1||u->page==2)&&u->depth==1)u->detail_index=to_end?n-1:0;
    else if(u->depth==0)u->index[u->page]=to_end?n-1:0;
}
static void mon_keys(MonUI *u,int key){
    if(key=='q'||key=='Q'){mon_signal=1;return;}
    if(u->page==2 && u->depth==1 && u->topology && (key=='+'||key=='='||key=='-')){
        int next=u->map_zoom+(key=='-'?-1:1);
        if(next<-3)next=-3;if(next>4)next=4;
        u->map_zoom=next;
        return;
    }
    if(key=='t' && (u->page==1||u->page==2) && u->depth==1){
        u->topology=!u->topology;u->detail_top=0;return;
    }
    if(key=='f' && u->page==4){
        mon_events_toggle();u->depth=2;return;
    }
    if(key=='g'){
        if(u->pending_g){u->pending_g=0;mon_jump(u,0);}
        else u->pending_g=1;
        return;
    }
    u->pending_g=0;
    if(key=='G'){mon_jump(u,1);return;}
    if(key==KEY_BACKSPACE||key==127||key==8||key==27){mon_back(u);return;}
    if(key=='0'){u->page=0;u->depth=0;return;}
    if(key>='1'&&key<='4'){u->page=key-'0';u->depth=0;return;}
    if(key=='\n'||key=='\r'||key==KEY_ENTER){mon_open(u);return;}
    if(key==KEY_NPAGE||key==4){for(int i=0;i<8;i++)mon_move(u,1);return;}
    if(key==KEY_PPAGE||key==21){for(int i=0;i<8;i++)mon_move(u,-1);return;}
    if(u->page==3&&u->net.screen){
        if(key==']')u->net.detail_scroll+=6;
        else if(key=='['){u->net.detail_scroll-=6;if(u->net.detail_scroll<0)u->net.detail_scroll=0;}
        else if(key=='h'){u->net.detail_x-=8;if(u->net.detail_x<0)u->net.detail_x=0;}
        else if(key=='l')u->net.detail_x+=8;
        else if(key==KEY_LEFT)mon_back(u);
        else if(key==KEY_RIGHT)mon_open(u);
        else if(key==KEY_DOWN||key=='j')mon_move(u,1);
        else if(key==KEY_UP||key=='k')mon_move(u,-1);
        return;
    }
    if(u->page==0){
        if(key=='\t')u->focus=u->focus==5?4:5;
        else if(key=='p')u->focus=4;
        else if(key=='H')u->focus=5;
        else if(key==KEY_DOWN||key=='j'){
            if(u->focus<2)u->focus+=2;
            else if(u->focus<4)u->focus=4;
            else mon_move(u,1);
        }else if(key==KEY_UP||key=='k'){
            if(u->focus>=4){
                if(u->focus==4&&u->overview_proc_index==0)u->focus=2;
                else if(u->focus==5&&u->hardware_index==0)u->focus=3;
                else mon_move(u,-1);
            }else if(u->focus>=2)u->focus-=2;
        }else if(key==KEY_LEFT||key=='h'){
            if(u->focus>=4)u->focus=4;
            else if(u->focus%2)u->focus--;
        }else if(key==KEY_RIGHT||key=='l'){
            if(u->focus>=4)u->focus=5;
            else if(u->focus%2==0)u->focus++;
        }
        return;
    }
    if(u->page==5){
        if(key==KEY_DOWN||key=='j')mon_move(u,1);
        else if(key==KEY_UP||key=='k')mon_move(u,-1);
        else if(key==KEY_LEFT||key=='h')mon_back(u);
        else if(key==KEY_RIGHT||key=='l')mon_open(u);
        return;
    }
    if(key==KEY_DOWN||key=='j')mon_move(u,1);
    else if(key==KEY_UP||key=='k')mon_move(u,-1);
    else if(key==KEY_LEFT||key=='h')mon_back(u);
    else if(key==KEY_RIGHT||key=='l')mon_open(u);
}
static int mon_self_test(void){
    int rc=self_test();MonMount mounts[MON_MOUNTS];int n=mon_collect_mounts(mounts,MON_MOUNTS);
    printf("catscan filesystem collector: %d mounts\n",n);
    MonProcess *p=calloc(MON_PROCS,sizeof(*p));if(!p)return 1;
    int pn=mon_collect_processes(p,MON_PROCS);printf("catscan process collector: %d processes\n",pn);free(p);
    MonMem m=mon_collect_mem();printf("catscan memory collector: %llu total / %llu occupied bytes%s\n",
      (unsigned long long)m.total,(unsigned long long)m.used,m.total?"":" [unavailable]");
#if defined(__APPLE__)
    /* A self-process probe distinguishes general API failure from a protected
     * foreign PID. No fabricated threads are substituted for failed reads. */
    MonThread *sample=calloc(MON_THREADS,sizeof(*sample));
    if(!sample)return 1;
    int tn=mon_collect_threads((int)getpid(),sample);
    printf("catscan native thread probe (self PID %d): %d thread(s)%s\n",
           (int)getpid(),tn,tn<1?" [FAILED]":"");
    free(sample);
    if(tn<1)rc=1;
#endif
    return rc||(pn<0)||mon_hardware_self_test()?1:0;
}
int main(int argc,char **argv){
    int demo=0;for(int i=1;i<argc;i++){
        if(!strcmp(argv[i],"--demo"))demo=1;
        else if(!strcmp(argv[i],"--self-test"))return mon_self_test();
        else if(!strcmp(argv[i],"--help")){
            puts("CATSCAN v0.9.1\nUsage: catscan [--demo|--self-test]\nLive capture on macOS: sudo -v && ./catscan\nUse 1-4 to switch CPU, memory, network, disk; 0 overview.\nEnter inspect; Backspace return; t toggles topology; +/- zooms VM map; q quit.");return 0;
        }else {fprintf(stderr,"Unknown argument: %s\n",argv[i]);return 2;}
    }
#if !defined(__APPLE__) && !defined(__FreeBSD__) && !defined(__linux__)
    if(!demo){fprintf(stderr,"Live monitoring is not supported on this operating system; use --demo.\n");return 2;}
#endif
    signal(SIGINT,mon_sig);signal(SIGTERM,mon_sig);signal(SIGPIPE,SIG_IGN);
    pthread_t system_thread={0},socket_thread={0},packet_thread={0},detail_thread={0},io_thread={0},events_thread={0};
    int hardware_started=!mon_hardware_start();
    int io_started=!pthread_create(&io_thread,NULL,mon_io_worker,NULL);
    int events_started=!pthread_create(&events_thread,NULL,mon_events_worker,NULL);
    int detail_started=!pthread_create(&detail_thread,NULL,mon_detail_worker,NULL);
    int system_started=!pthread_create(&system_thread,NULL,mon_worker,NULL);
    int socket_started=0,packet_started=0;
    if(demo)demo_data();
    else{
        socket_started=!pthread_create(&socket_thread,NULL,lsof_worker,NULL);
        packet_started=!pthread_create(&packet_thread,NULL,tcpdump_worker,NULL);
    }
    if(!hardware_started || !system_started || !detail_started || !io_started || !events_started || (!demo && (!socket_started||!packet_started))){
        fprintf(stderr,"Cannot initialize one or more catscan collectors\n");mon_signal=1;
    }else{
        initscr();cbreak();noecho();keypad(stdscr,TRUE);curs_set(0);timeout(150);
        if(has_colors()){
            start_color();
            /* ANSI white (7) is often gray; ANSI bright white is 15.
               Fall back to 7 on terminals advertising only eight colors. */
            short white = COLORS >= 16 ? 15 : COLOR_WHITE;
            init_pair(1, white, COLOR_BLACK);
            bkgd(COLOR_PAIR(1));
            attrset(COLOR_PAIR(1) | A_BOLD);
        }
        MonUI *ui=calloc(1,sizeof(*ui));
        if(ui){while(!mon_signal){mon_draw(ui);int key=getch();if(key!=ERR && key!=KEY_RESIZE)mon_keys(ui,key);}free(ui);}
        endwin();
    }
    pthread_mutex_lock(&IO.mu);IO.stop=1;pid_t event_pid=IO.event_pid,io_pid=IO.io_pid;pthread_mutex_unlock(&IO.mu);
    if(io_pid>0)kill(io_pid,SIGTERM);
    if(event_pid>0){kill(-event_pid,SIGTERM);kill(event_pid,SIGTERM);}
    pthread_mutex_lock(&D.mu);D.stop=1;pthread_mutex_unlock(&D.mu);
    pthread_mutex_lock(&S.mu);S.stop=1;pthread_mutex_unlock(&S.mu);
    pthread_mutex_lock(&G.mu);G.stop=1;pid_t capture=G.capture_pid;pthread_mutex_unlock(&G.mu);
    if(capture>0){kill(-capture,SIGTERM);kill(capture,SIGTERM);}
    if(io_started)pthread_join(io_thread,NULL);
    if(events_started)pthread_join(events_thread,NULL);
    if(detail_started)pthread_join(detail_thread,NULL);
    if(system_started)pthread_join(system_thread,NULL);
    if(socket_started)pthread_join(socket_thread,NULL);
    if(packet_started)pthread_join(packet_thread,NULL);
    if(hardware_started)mon_hardware_stop();
    for(int i=0;i<PACKET_RING;i++)free(G.packets[i].text);
    return 0;
}
