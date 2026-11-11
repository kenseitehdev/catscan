#define _POSIX_C_SOURCE 200809L
#include <ncurses.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>

#define MAX_SOCKETS 2048
#define PACKET_RING 1024
#define MAX_PACKET_TEXT (128 * 1024)
#define LINE_MAX_LEN 4096

typedef struct { char address[128]; int port; int valid; int wildcard; } Endpoint;
typedef struct {
    int pid;
    char process[72], fd[24], proto[12], state[36], name[280];
    Endpoint local, remote;
    int has_remote;
} Socket;
typedef struct {
    uint64_t seq;
    int pid;
    char process[72], iface[24], direction[12], proto[12], timestamp[32];
    char summary[420];
    Endpoint src, dst;
    char *text;
    size_t len, cap;
    int truncated;
} Packet;
typedef struct {
    pthread_mutex_t mu;
    Socket sockets[MAX_SOCKETS];
    size_t socket_count;
    Packet packets[PACKET_RING];
    uint64_t last_seq;
    pid_t capture_pid;
    int capture_alive, stop, demo;
    char capture_status[200], lsof_status[160];
} Shared;

typedef struct { uint64_t seq; int quality; } Match;
typedef struct {
    int screen, socket_index, socket_top, packet_top, detail_scroll, detail_x, follow;
    Socket inspected;
    int select_pid;
    char select_fd[24], select_name[280];
    uint64_t select_seq;
} UI;

static Shared G = {.mu = PTHREAD_MUTEX_INITIALIZER, .lsof_status = "lsof: starting scan...", .capture_status = "capture starting..."};
static volatile sig_atomic_t interrupted = 0;
static void on_signal(int sig) { (void)sig; interrupted=1; }
static void copystr(char *dst, size_t n, const char *src) {
    if (!n) return;
    if (!src) src = "";
    size_t len = strnlen(src, n - 1);
    memcpy(dst, src, len);
    dst[len] = 0;
}
static char *trim(char *s) {
    while (isspace((unsigned char)*s)) s++;
    size_t n = strlen(s);
    while (n && isspace((unsigned char)s[n-1])) s[--n]=0;
    return s;
}
static int all_digits(const char *s) {
    if (!*s) return 0;
    for (; *s; s++) if (!isdigit((unsigned char)*s)) return 0;
    return 1;
}

/* lsof prints ip:port and [IPv6]:port. tcpdump prints ip.port and IPv6.port. */
static int endpoint_parse(const char *input, Endpoint *out, int tcpdump_style) {
    char buf[256]; copystr(buf,sizeof buf,input); char *s=trim(buf);
    memset(out,0,sizeof *out);
    if (!*s) return 0;
    char *sep=NULL;
    if (tcpdump_style) {
        sep=strrchr(s,'.');
    } else if (*s=='[') {
        char *close=strchr(s,']');
        if (close && close[1]==':') { *close=0; s++; sep=close+1; }
    } else {
        sep=strrchr(s,':');
    }
    if (!sep || !all_digits(sep+1)) return 0;
    *sep=0;
    long port=strtol(sep+1,NULL,10);
    if (port<0 || port>65535) return 0;
    /* Strip optional brackets from IPv6 addresses. */
    size_t n=strlen(s);
    if (n>=2 && s[0]=='[' && s[n-1]==']') {s[n-1]=0;s++;}
    copystr(out->address,sizeof out->address,s);
    out->port=(int)port;
    out->wildcard=(!strcmp(s,"*") || !strcmp(s,"0.0.0.0") || !strcmp(s,"::"));
    out->valid=1;
    return 1;
}
static void socket_parse_name(Socket *s) {
    memset(&s->local,0,sizeof s->local);
    memset(&s->remote,0,sizeof s->remote);
    s->has_remote=0;
    char buf[sizeof s->name]; copystr(buf,sizeof buf,s->name);
    char *arrow=strstr(buf,"->");
    if (arrow) { *arrow=0; arrow+=2; s->has_remote=endpoint_parse(arrow,&s->remote,0); }
    endpoint_parse(buf,&s->local,0);
}
static int socket_cmp(const void *a, const void *b) {
    const Socket *x=a,*y=b;
    int c=strcasecmp(x->process,y->process); if (c) return c;
    if (x->pid!=y->pid) return (x->pid>y->pid)-(x->pid<y->pid);
    c=strcmp(x->fd,y->fd); if (c) return c;
    return strcmp(x->name,y->name);
}
static void add_socket(Socket *out, size_t *count, Socket *s) {
    if (!s->name[0] || !s->fd[0] || *count>=MAX_SOCKETS) return;
    socket_parse_name(s);
    out[(*count)++]=*s;
}
/* Parse field-mode lsof output, not the human-readable table. */
static size_t parse_lsof(FILE *f, Socket *out) {
    char line[LINE_MAX_LEN], proc[72]=""; int pid=0, have_file=0;
    size_t count=0; Socket current={0};
    while (fgets(line,sizeof line,f)) {
        size_t n=strlen(line); while(n && (line[n-1]=='\n'||line[n-1]=='\r'))line[--n]=0;
        if (!n) continue;
        switch(line[0]) {
        case 'p':
            if(have_file) add_socket(out,&count,&current);
            have_file=0; memset(&current,0,sizeof current);
            pid=atoi(line+1); proc[0]=0;
            break;
        case 'c':
            copystr(proc,sizeof proc,line+1);
            if(have_file) copystr(current.process,sizeof current.process,proc);
            break;
        case 'f':
            if(have_file) add_socket(out,&count,&current);
            memset(&current,0,sizeof current); have_file=1;
            current.pid=pid; copystr(current.process,sizeof current.process,proc);
            copystr(current.fd,sizeof current.fd,line+1);
            break;
        case 'P': if(have_file)copystr(current.proto,sizeof current.proto,line+1); break;
        case 'n': if(have_file)copystr(current.name,sizeof current.name,line+1); break;
        case 'T':
            if(have_file && !strncmp(line+1,"ST=",3))copystr(current.state,sizeof current.state,line+4);
            break;
        default: break;
        }
    }
    if (have_file) add_socket(out,&count,&current);
    qsort(out,count,sizeof *out,socket_cmp);
    return count;
}
/* Fallback for the regular lsof table that the user confirmed works.
 * macOS line layout: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
 * Parse from the left until TCP/UDP, then consume the complete NAME tail.
 */
static size_t parse_lsof_table(FILE *f, Socket *out) {
    char line[LINE_MAX_LEN];
    size_t count=0;
    while (fgets(line,sizeof line,f)) {
        char tmp[LINE_MAX_LEN]; copystr(tmp,sizeof tmp,line);
        char *tokens[64]={0}; size_t nt=0;
        char *save=NULL;
        for(char *t=strtok_r(tmp," \t\r\n",&save);t && nt<64;t=strtok_r(NULL," \t\r\n",&save))
            tokens[nt++]=t;
        if(nt<9 || !all_digits(tokens[1]) || !strcmp(tokens[0],"COMMAND"))continue;
        size_t prot=0;
        for(size_t i=4;i+1<nt;i++) {
            if(!strcmp(tokens[i],"TCP")||!strcmp(tokens[i],"UDP")) {prot=i;break;}
        }
        if(!prot || prot+1>=nt)continue;
        Socket x={0};
        x.pid=atoi(tokens[1]);
        copystr(x.process,sizeof x.process,tokens[0]);
        copystr(x.fd,sizeof x.fd,tokens[3]);
        copystr(x.proto,sizeof x.proto,tokens[prot]);
        copystr(x.name,sizeof x.name,tokens[prot+1]);
        for(size_t j=prot+2;j<nt;j++) {
            if(tokens[j][0]=='(') {
                copystr(x.state,sizeof x.state,tokens[j]+1);
                char *end=strchr(x.state,')'); if(end)*end=0;
                break;
            }
        }
        add_socket(out,&count,&x);
    }
    qsort(out,count,sizeof *out,socket_cmp);
    return count;
}
/* A bounded lsof read keeps a stalled child from leaving the TUI blank.
 * lsof's regular table is the source of truth here; the -F form is a fallback.
 * We do not run lsof in a shell and we retain stdout/stderr for diagnostics. */
#define LSOF_READ_LIMIT (3 * 1024 * 1024)
#define LSOF_TIMEOUT_MS 8000
static long long monotonic_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC,&ts);
    return (long long)ts.tv_sec*1000 + ts.tv_nsec/1000000;
}
static size_t run_lsof_capture(int fields, char *buf, size_t cap,
                               int *exit_code,int *timed_out,int *truncated) {
    *exit_code=-1;*timed_out=0;*truncated=0;
    if(cap<2)return 0;
    buf[0]=0;
    int fds[2];
    if(pipe(fds)<0)return 0;
    pid_t pid=fork();
    if(pid<0){close(fds[0]);close(fds[1]);return 0;}
    if(pid==0){
        close(fds[0]);
        if(dup2(fds[1],STDOUT_FILENO)<0 || dup2(fds[1],STDERR_FILENO)<0)_exit(127);
        close(fds[1]);
        if(fields)execlp("lsof","lsof","-i","-P","-n","-FpcfPntT",(char *)NULL);
        else execlp("lsof","lsof","-i","-P","-n",(char *)NULL);
        _exit(127);
    }
    close(fds[1]);
    int flags=fcntl(fds[0],F_GETFL);
    if(flags>=0)fcntl(fds[0],F_SETFL,flags|O_NONBLOCK);
    size_t used=0;
    int done=0;
    long long deadline=monotonic_ms()+LSOF_TIMEOUT_MS;
    while(!done){
        long long remain=deadline-monotonic_ms();
        if(remain<=0){*timed_out=1;break;}
        struct pollfd pfd={.fd=fds[0],.events=POLLIN|POLLHUP};
        int rv=poll(&pfd,1,remain<250?(int)remain:250);
        if(rv<0){if(errno==EINTR)continue;break;}
        if(rv==0)continue;
        if(pfd.revents&(POLLIN|POLLHUP|POLLERR)) {
            for(;;){
                if(used+1>=cap){*truncated=1;done=1;break;}
                ssize_t n=read(fds[0],buf+used,cap-used-1);
                if(n>0){used+=(size_t)n;continue;}
                if(n==0){done=1;break;}
                if(errno==EINTR)continue;
                if(errno==EAGAIN || errno==EWOULDBLOCK)break;
                done=1;break;
            }
        }
        if(pfd.revents&POLLNVAL)break;
    }
    buf[used]=0;
    close(fds[0]);
    if(*timed_out || *truncated)kill(pid,SIGKILL);
    int status=0;
    while(waitpid(pid,&status,0)<0 && errno==EINTR){}
    if(WIFEXITED(status))*exit_code=WEXITSTATUS(status);
    return used;
}
static size_t parse_lsof_buffer(const char *raw,size_t len,int fields,Socket *out){
    if(!len)return 0;
    /* tmpfile instead of fmemopen for compatibility with older macOS SDKs. */
    FILE *f=tmpfile();
    if(!f)return 0;
    if(fwrite(raw,1,len,f)!=len){fclose(f);return 0;}
    rewind(f);
    size_t n=fields?parse_lsof(f,out):parse_lsof_table(f,out);
    fclose(f);
    return n;
}
static void first_line_excerpt(const char *raw,char *dst,size_t sz){
    if(!sz)return;
    size_t i=0;
    while(raw[i] && raw[i]!='\n' && raw[i]!='\r' && i<sz-1){
        dst[i]=(unsigned char)raw[i]<32?' ':raw[i];i++;
    }
    dst[i]=0;
}
static size_t collect_sockets(Socket *out,int *mode,char *diag,size_t diag_size) {
    *mode=0;diag[0]=0;
    char *raw=malloc(LSOF_READ_LIMIT);
    if(!raw){copystr(diag,diag_size,"out of memory launching lsof");return 0;}
    int rc=0,timed=0,trunc=0;
    size_t len=run_lsof_capture(0,raw,LSOF_READ_LIMIT,&rc,&timed,&trunc);
    size_t n=parse_lsof_buffer(raw,len,0,out);
    if(n){
        *mode=2;
        if(timed)snprintf(diag,diag_size,"table partial: %zu sockets (lsof timed out)",n);
        else if(trunc)snprintf(diag,diag_size,"table partial: %zu sockets (output truncated)",n);
        free(raw);return n;
    }
    if(timed)copystr(diag,diag_size,"lsof table timed out after 8s");
    else if(trunc)copystr(diag,diag_size,"lsof table exceeded 3 MiB");
    else if(rc!=0)snprintf(diag,diag_size,"lsof table failed (exit %d)",rc);
    else if(len==0)copystr(diag,diag_size,"lsof returned no output");
    else {
        char excerpt[90];first_line_excerpt(raw,excerpt,sizeof excerpt);
        snprintf(diag,diag_size,"unparsed lsof rows; first line: %.85s",excerpt);
    }
    /* Only attempt the alternate format when the primary command completed.
     * If it hung, a second lsof scan would simply compound the delay. */
    if(!timed){
        len=run_lsof_capture(1,raw,LSOF_READ_LIMIT,&rc,&timed,&trunc);
        n=parse_lsof_buffer(raw,len,1,out);
        if(n){*mode=1;diag[0]=0;}
        else if(timed)copystr(diag,diag_size,"lsof field mode timed out after 8s");
        else if(rc!=0)snprintf(diag,diag_size,"lsof field mode failed (exit %d)",rc);
    }
    free(raw);
    return n;
}
static int probe_lsof(void) {
    int mode=0;
    char diag[160]={0};
    Socket *s=calloc(MAX_SOCKETS,sizeof *s);
    if(!s)return 1;
    size_t n=collect_sockets(s,&mode,diag,sizeof diag);
    printf("netinspect lsof probe\nparsed sockets: %zu\nformat: %s\n",
           n,mode==2?"table":mode==1?"field fallback":"none");
    if(*diag)printf("diagnostic: %s\n",diag);
    for(size_t i=0;i<n && i<12;i++)
        printf("%d %-18s %-5s %-6s %s\n",s[i].pid,s[i].process,s[i].proto,s[i].fd,s[i].name);
    free(s);
    printf("\n--- exact command: lsof -i -P -n ---\n");
    char *raw=malloc(LSOF_READ_LIMIT);
    if(!raw)return 1;
    int status=0,timed=0,trunc=0;
    size_t len=run_lsof_capture(0,raw,LSOF_READ_LIMIT,&status,&timed,&trunc);
    int lines=0;
    for(size_t i=0;i<len && lines<15;i++){
        putchar(raw[i]);
        if(raw[i]=='\n')lines++;
    }
    if(!len)puts("(empty output)");
    if(timed)puts("WARNING: lsof timed out after 8s");
    if(trunc)puts("WARNING: lsof output exceeded 3 MiB");
    printf("raw output bytes: %zu, exit status: %d\n",len,status);
    free(raw);
    return n?0:1;
}
static void packet_append(Packet *p, const char *line) {
    if (p->truncated) return;
    size_t n=strlen(line);
    if (p->len+n+1>MAX_PACKET_TEXT) {
        const char *msg="\n[packet text truncated at 128 KiB; use an external pcap for full archival]\n";
        n = MAX_PACKET_TEXT>p->len+strlen(msg)+1 ? MAX_PACKET_TEXT-p->len-strlen(msg)-1:0;
        p->truncated=1;
        if(!n) return;
    }
    if (p->len+n+100>p->cap) {
        size_t nc=p->cap ? p->cap*2 : 2048;
        while(nc<p->len+n+100) nc*=2;
        if(nc>MAX_PACKET_TEXT+128)nc=MAX_PACKET_TEXT+128;
        char *b=realloc(p->text,nc);
        if(!b) {p->truncated=1;return;}
        p->text=b;p->cap=nc;
    }
    memcpy(p->text+p->len,line,n);p->len+=n;
    p->text[p->len]=0;
    if(p->truncated) {
        const char *msg="\n[packet text truncated; full capture requires pcap]\n";
        size_t m=strlen(msg);
        if(p->len+m+1<p->cap){memcpy(p->text+p->len,msg,m+1);p->len+=m;}
    }
}
static int is_packet_start(const char *line) {
    /* tcpdump's default -tt print is HH:MM:SS.fraction. */
    return strlen(line)>11 && isdigit((unsigned char)line[0]) && isdigit((unsigned char)line[1]) &&
        line[2]==':' && isdigit((unsigned char)line[3]) && isdigit((unsigned char)line[4]) &&
        line[5]==':' && isdigit((unsigned char)line[6]) && isdigit((unsigned char)line[7]) &&
        (line[8]=='.' || line[8]==' ');
}
static void process_meta(Packet *p, const char *line) {
    const char *start=strstr(line,"proc ");
    if(start) start+=5;
    else {start=strstr(line,"pid "); if(start)start+=4;}
    if(start) {
        char token[100]={0}; size_t n=0;
        while(*start && *start!=',' && *start!=')' && !isspace((unsigned char)*start) && n<sizeof token-1)
            token[n++]=*start++;
        token[n]=0;
        char *colon=strrchr(token,':'), *dot=strrchr(token,'.');
        char *sep=colon;
        if (dot && (!sep || dot>sep)) sep=dot;
        if (sep && all_digits(sep+1)) {
            p->pid=atoi(sep+1); *sep=0;
            copystr(p->process,sizeof p->process,token);
        }
    }
    const char *paren=strchr(line,'(');
    if (paren && strstr(paren,"proc ")) {
        char *comma=strchr(paren,',');
        if (comma && (size_t)(comma-paren)<sizeof p->iface)
            snprintf(p->iface,sizeof p->iface,"%.*s",(int)(comma-paren-1),paren+1);
    }
    if(strstr(line,", out,")||strstr(line,", out)"))copystr(p->direction,sizeof p->direction,"OUT");
    if(strstr(line,", in,")||strstr(line,", in)"))copystr(p->direction,sizeof p->direction,"IN");
}
static void parse_flow(Packet *p, const char *line) {
    const char *arrow=strstr(line," > ");
    if(!arrow) return;
    const char *src=arrow;
    while(src>line && !isspace((unsigned char)src[-1]))src--;
    if(src==arrow) return;
    const char *dst=arrow+3;
    const char *end=strstr(dst,": ");
    if(!end)end=strchr(dst,'\n');
    if(!end)end=dst+strlen(dst);
    char a[180],b[180];
    size_t an=(size_t)(arrow-src), bn=(size_t)(end-dst);
    if(an>=sizeof a || bn>=sizeof b)return;
    memcpy(a,src,an);a[an]=0;
    memcpy(b,dst,bn);b[bn]=0;
    endpoint_parse(a,&p->src,1); endpoint_parse(b,&p->dst,1);
    if(strstr(line,"Flags [")||strstr(line,"proto TCP"))copystr(p->proto,sizeof p->proto,"TCP");
    else if(strstr(line,"UDP")||strstr(line,"proto UDP"))copystr(p->proto,sizeof p->proto,"UDP");
    if(!p->summary[0] || !strstr(p->summary," > ")) {
        char summary[450];copystr(summary,sizeof summary,src);
        char *s=trim(summary);copystr(p->summary,sizeof p->summary,s);
    }
}
static void parse_packet_line(Packet *p, const char *line, int header) {
    packet_append(p,line);
    if(header) {
        char ts[40]={0};sscanf(line,"%39s",ts);copystr(p->timestamp,sizeof p->timestamp,ts);
        char summary[LINE_MAX_LEN];copystr(summary,sizeof summary,line);
        copystr(p->summary,sizeof p->summary,trim(summary));
        process_meta(p,line);
    }
    if(strstr(line,"proto TCP"))copystr(p->proto,sizeof p->proto,"TCP");
    if(strstr(line,"proto UDP"))copystr(p->proto,sizeof p->proto,"UDP");
    parse_flow(p,line);
}
static void push_packet(Packet *p) {
    pthread_mutex_lock(&G.mu);
    p->seq=++G.last_seq;
    Packet *slot=&G.packets[p->seq % PACKET_RING];
    free(slot->text);
    *slot=*p;
    pthread_mutex_unlock(&G.mu);
    memset(p,0,sizeof *p);
}
static int ep_eq(Endpoint x, Endpoint y) {
    if(!x.valid||!y.valid||x.port!=y.port)return 0;
    return x.wildcard || y.wildcard || !strcasecmp(x.address,y.address);
}
/* 3=PID+tuple, 2=tuple only, 1=PID only (ambiguous), 0=not matched. */
static int packet_match(const Socket *s, const Packet *p) {
    if(p->pid>0 && p->pid!=s->pid)return 0;
    if(s->proto[0] && p->proto[0] && strcasecmp(s->proto,p->proto))return 0;
    int forward=ep_eq(s->local,p->src);
    int backward=ep_eq(s->local,p->dst);
    int tuple=0;
    if(s->has_remote)
        tuple=(forward && ep_eq(s->remote,p->dst)) || (backward && ep_eq(s->remote,p->src));
    else if(s->local.valid)
        tuple=forward||backward;
    if(tuple) {
        /* A wildcard listener with missing PID could belong to anyone. */
        if(!s->has_remote && s->local.wildcard && p->pid<=0)return 0;
        return p->pid>0?3:2;
    }
    if(p->pid>0 && (!p->src.valid || !p->dst.valid || !s->local.valid))return 1;
    return 0;
}
static void *lsof_worker(void *arg) {
    (void)arg;
    Socket *tmp=calloc(MAX_SOCKETS,sizeof *tmp);
    if(!tmp)return NULL;
    while(1) {
        pthread_mutex_lock(&G.mu);int stop=G.stop;pthread_mutex_unlock(&G.mu);
        if(stop)break;
        int mode=0;char diag[160]={0};
        size_t n=collect_sockets(tmp,&mode,diag,sizeof diag);
        pthread_mutex_lock(&G.mu);
        if(mode){memcpy(G.sockets,tmp,n*sizeof *tmp);G.socket_count=n;}
        if(mode==1)snprintf(G.lsof_status,sizeof G.lsof_status,"%zu sockets (lsof fields)",n);
        else if(mode==2)snprintf(G.lsof_status,sizeof G.lsof_status,"%zu sockets (lsof table)%s",n,diag[0]?" [partial]":"");
        else snprintf(G.lsof_status,sizeof G.lsof_status,"lsof: %.145s",diag);
        pthread_mutex_unlock(&G.mu);
        for(int i=0;i<20;i++) {
            struct timespec t={.tv_sec=0,.tv_nsec=100000000};nanosleep(&t,NULL);
            pthread_mutex_lock(&G.mu);stop=G.stop;pthread_mutex_unlock(&G.mu);
            if(stop)break;
        }
    }
    free(tmp);return NULL;
}
static void *tcpdump_worker(void *arg) {
    (void)arg;
    int pipefd[2];
    if(pipe(pipefd)<0)return NULL;
    pid_t pid=fork();
    if(pid<0) {close(pipefd[0]);close(pipefd[1]);return NULL;}
    if(pid==0) {
        setpgid(0,0); /* Keep capture children in a stoppable process group. */
        close(pipefd[0]);dup2(pipefd[1],STDOUT_FILENO);dup2(pipefd[1],STDERR_FILENO);close(pipefd[1]);
        /* -n avoids prompting over curses; run `sudo -v` before launching the TUI. */
#if defined(__APPLE__)
        execl("/usr/bin/sudo","sudo","-n","/usr/sbin/tcpdump",
            "-l","-i","pktap,all","-nn","-s","0","-vvv","-XX","-k","NPDI",(char *)NULL);
#elif defined(__linux__)
        execl("/usr/bin/sudo","sudo","-n","/usr/sbin/tcpdump",
            "-l","-i","any","-nn","-s","0","-vvv","-XX",(char *)NULL);
#elif defined(__FreeBSD__)
        execl("/usr/bin/sudo","sudo","-n","/usr/sbin/tcpdump",
            "-l","-nn","-s","0","-vvv","-XX",(char *)NULL);
#else
        _exit(127);
#endif
    }
    close(pipefd[1]);
    pthread_mutex_lock(&G.mu);G.capture_pid=pid;G.capture_alive=1;
    copystr(G.capture_status,sizeof G.capture_status,"capture starting...");pthread_mutex_unlock(&G.mu);
    FILE *f=fdopen(pipefd[0],"r");
    if(!f) {close(pipefd[0]);kill(-pid,SIGTERM);kill(pid,SIGTERM);waitpid(pid,NULL,0);return NULL;}
    Packet pending={0};int have=0;char line[LINE_MAX_LEN];
    while(fgets(line,sizeof line,f)) {
        if(is_packet_start(line)) {
            if(have)push_packet(&pending);
            have=1;
            parse_packet_line(&pending,line,1);
            pthread_mutex_lock(&G.mu);
#if defined(__APPLE__)
            copystr(G.capture_status,sizeof G.capture_status,"pktap capture active");
#elif defined(__linux__)
            copystr(G.capture_status,sizeof G.capture_status,"tcpdump capture active (PID inferred by socket tuple)");
#elif defined(__FreeBSD__)
            copystr(G.capture_status,sizeof G.capture_status,"tcpdump capture active (PID inferred by socket tuple)");
#endif
            pthread_mutex_unlock(&G.mu);
        } else if(have) {
            parse_packet_line(&pending,line,0);
        } else {
            char *s=trim(line);
            if(*s && !strstr(s,"data link type") && !strstr(s,"listening on") && !strstr(s,"verbose output")) {
                pthread_mutex_lock(&G.mu);copystr(G.capture_status,sizeof G.capture_status,s);pthread_mutex_unlock(&G.mu);
            }
        }
        pthread_mutex_lock(&G.mu);int stop=G.stop;pthread_mutex_unlock(&G.mu);
        if(stop)break;
    }
    if(have)push_packet(&pending);
    fclose(f);
    int status=0;waitpid(pid,&status,0);
    pthread_mutex_lock(&G.mu);G.capture_alive=0;G.capture_pid=0;
    if(!G.stop && G.last_seq==0 && !strstr(G.capture_status,"required"))
        snprintf(G.capture_status,sizeof G.capture_status,"capture exited (status %d); run sudo -v",WIFEXITED(status)?WEXITSTATUS(status):-1);
    pthread_mutex_unlock(&G.mu);
    return NULL;
}
static int same_socket(const Socket *s, const UI *u) {
    return s->pid==u->select_pid && !strcmp(s->fd,u->select_fd) && !strcmp(s->name,u->select_name);
}
static void remember_socket(UI *u, const Socket *s) {
    u->select_pid=s->pid;copystr(u->select_fd,sizeof u->select_fd,s->fd);
    copystr(u->select_name,sizeof u->select_name,s->name);
}
static void restore_selection(UI *u) {
    if(!G.socket_count){u->socket_index=0;return;}
    for(size_t i=0;i<G.socket_count;i++)if(same_socket(&G.sockets[i],u)){u->socket_index=(int)i;return;}
    if(u->socket_index>=(int)G.socket_count)u->socket_index=(int)G.socket_count-1;
    if(u->socket_index<0)u->socket_index=0;
    remember_socket(u,&G.sockets[u->socket_index]);
}
/* All screen geometry is relative to the current tmux pane, never a fixed 80x24. */
static void line_out(int y,int x,int width,const char *s,int attr) {
    if(y<0||y>=LINES||x<0||x>=COLS||width<=0)return;
    if(width>COLS-x-1)width=COLS-x-1;
    if(width<=0)return;
    int bright = (attr & ~A_DIM) | A_BOLD;
    attron(bright);mvaddnstr(y,x,s,width);attroff(bright);
}
static void status_bar(const char *wide,const char *short_text) {
    if(LINES<2)return;
    if(LINES>=12)mvhline(LINES-2,0,ACS_HLINE,COLS);
    line_out(LINES-1,0,COLS-1,COLS>=76?wide:short_text,A_DIM);
}
static int socket_list_start(void) {return LINES>=7?2:0;}
static int list_last_row(void) {return LINES>=12?LINES-3:LINES-2;}
static void draw_sockets(UI *u) {
    char b[1024];
    int first=socket_list_start(),last=list_last_row();
    int visible=last-first+1;if(visible<1)visible=1;
    if(LINES>=7) {
        if(COLS>=74)snprintf(b,sizeof b,"%s | %llu packets | %s",G.lsof_status,
            (unsigned long long)(G.last_seq<PACKET_RING?G.last_seq:PACKET_RING),G.capture_status);
        else snprintf(b,sizeof b,"%s | %llu pkt",G.lsof_status,
            (unsigned long long)(G.last_seq<PACKET_RING?G.last_seq:PACKET_RING));
        line_out(0,0,COLS-1,b,A_DIM);
    }
    if(LINES>=12) {
        if(COLS>=100)copystr(b,sizeof b,"   PID     PROCESS             PROTO  FD       STATE         LOCAL -> REMOTE");
        else if(COLS>=68)copystr(b,sizeof b,"   PID     PROCESS        PROTO FD    STATE       ENDPOINT");
        else if(COLS>=45)copystr(b,sizeof b,"   PID    PROCESS     PROTO ENDPOINT");
        else copystr(b,sizeof b,"   PID   PROCESS     PROTO");
        line_out(1,0,COLS-1,b,A_BOLD);
    } else if(LINES>=7) {
        line_out(1,0,COLS-1,COLS>=45?"   PID    PROCESS      PROTO / ENDPOINT":"   PID    PROCESS / PROTO",A_BOLD);
    }
    if(u->socket_index<u->socket_top)u->socket_top=u->socket_index;
    if(u->socket_index>=u->socket_top+visible)u->socket_top=u->socket_index-visible+1;
    if(u->socket_top<0)u->socket_top=0;
    if(!G.socket_count)line_out(first,0,COLS-1,"No sockets. Try --probe-lsof",A_DIM);
    for(int i=0;i<visible && (size_t)(u->socket_top+i)<G.socket_count;i++) {
        const Socket *t=&G.sockets[u->socket_top+i];
        char mark=(u->socket_top+i==u->socket_index)?'>':' ';
        if(COLS>=100)
            snprintf(b,sizeof b,"%c  %-7d %-19.19s %-6.6s %-8.8s %-13.13s %s",
                mark,t->pid,t->process,t->proto,t->fd,t->state[0]?t->state:"-",t->name);
        else if(COLS>=68)
            snprintf(b,sizeof b,"%c  %-7d %-14.14s %-5.5s %-5.5s %-11.11s %s",
                mark,t->pid,t->process,t->proto,t->fd,t->state[0]?t->state:"-",t->name);
        else if(COLS>=45)
            snprintf(b,sizeof b,"%c %-6d %-12.12s %-5.5s %s",
                mark,t->pid,t->process,t->proto,t->name);
        else
            snprintf(b,sizeof b,"%c %-6d %-12.12s %-4.4s",mark,t->pid,t->process,t->proto);
        int attr=(u->socket_top+i==u->socket_index)?(A_REVERSE|A_BOLD):A_NORMAL;
        line_out(first+i,0,COLS-1,b,attr);
    }
    status_bar("j/k: select  |  Enter: packets  |  q: quit  |  collectors active",
               "j/k select | Enter inspect | q quit");
}
static size_t matching_packets(const Socket *s, Match *out) {
    size_t n=0;
    uint64_t first=G.last_seq>=PACKET_RING?G.last_seq-PACKET_RING+1:1;
    for(uint64_t seq=first;seq<=G.last_seq;seq++) {
        const Packet *p=&G.packets[seq%PACKET_RING];
        if(p->seq!=seq)continue;
        int q=packet_match(s,p);
        if(q) {out[n].seq=seq;out[n].quality=q;n++;}
    }
    return n;
}
static Packet *find_packet(uint64_t seq) {
    if(!seq)return NULL;
    Packet *p=&G.packets[seq%PACKET_RING];return p->seq==seq?p:NULL;
}
static void draw_packet_text(const Packet *p,int scroll,int start,int end,int xscroll) {
    if(!p||!p->text||start>end)return;
    const char *line=p->text;int line_no=0;
    while(*line && line_no<10000) {
        const char *e=strchr(line,'\n');if(!e)e=line+strlen(line);
        if(line_no>=scroll) {
            int row=start+(line_no-scroll);
            if(row>end)break;
            size_t len=(size_t)(e-line);
            if((size_t)xscroll<len) {
                size_t n=len-(size_t)xscroll;
                if(n>(size_t)(COLS-2))n=(size_t)(COLS-2);
                if(n>0)line_out(row,1,(int)n,line+xscroll,A_NORMAL);
            }
        }
        if(!*e)break;
        line=e+1;line_no++;
    }
}
/* Two-level layout: table and detail adapt to small split panes. */
static void draw_packets(UI *u,Match *matched,size_t count) {
    const Socket *s=&u->inspected;
    char b[1024];
    int table_start, divider, text_start, text_end, packet_header=-1;
    if(LINES>=16) {
        table_start=3;
        divider=LINES/2;
        if(divider<9)divider=9;
        if(divider>LINES-5)divider=LINES-5;
        packet_header=2;
        text_start=divider+2;
        text_end=LINES-3;
    } else if(LINES>=9) {
        table_start=3;
        divider=(LINES*3)/5;
        if(divider<5)divider=5;
        if(divider>LINES-4)divider=LINES-4;
        packet_header=2;
        text_start=divider+(LINES>=12?2:1);
        text_end=LINES>=12?LINES-3:LINES-2;
    } else {
        table_start=1;
        divider=LINES-3;
        text_start=divider+1;
        text_end=LINES-2;
    }
    int avail=divider-table_start;if(avail<1)avail=1;
    if(COLS>=60)
        snprintf(b,sizeof b,"%s [%d] %s %s %s",s->process,s->pid,s->proto,s->fd,s->name);
    else snprintf(b,sizeof b,"%s [%d] %s",s->process,s->pid,s->name);
    line_out(0,0,COLS-1,b,A_BOLD);
    size_t low=0;for(size_t i=0;i<count;i++)if(matched[i].quality<3)low++;
    if(LINES>=9) {
        if(COLS>=78)snprintf(b,sizeof b,"%zu packets (%zu weaker) | %s | %s",count,low,G.capture_status,u->follow?"FOLLOW":"HOLD");
        else snprintf(b,sizeof b,"%zu packets (%zu weaker) | %s",count,low,u->follow?"FOLLOW":"HOLD");
        line_out(1,0,COLS-1,b,A_DIM);
    }
    int idx=-1;
    for(size_t i=0;i<count;i++)if(matched[i].seq==u->select_seq){idx=(int)i;break;}
    if(count) {
        if(u->follow || idx<0) {idx=u->follow?(int)count-1:0;u->select_seq=matched[idx].seq;}
        if(idx<u->packet_top)u->packet_top=idx;
        if(idx>=u->packet_top+avail)u->packet_top=idx-avail+1;
    } else {u->select_seq=0;u->packet_top=0;}
    if(packet_header>=0) {
        if(COLS>=82)copystr(b,sizeof b,"   TIME              MATCH  DIR    PID        SUMMARY");
        else if(COLS>=45)copystr(b,sizeof b,"   TIME         MATCH  DIR  SUMMARY");
        else copystr(b,sizeof b,"   TIME     DIR  SUMMARY");
        line_out(packet_header,0,COLS-1,b,A_BOLD);
    }
    for(int r=0;r<avail && (size_t)(u->packet_top+r)<count;r++) {
        int i=u->packet_top+r;
        Packet *p=find_packet(matched[i].seq);if(!p)continue;
        const char *label=matched[i].quality==3?"PID+IP":matched[i].quality==2?"IP only":"PID only";
        if(COLS>=82)
            snprintf(b,sizeof b,"%c  %-17.17s %-7s %-5.5s %-10d %s",i==idx?'>':' ',p->timestamp,label,
                p->direction[0]?p->direction:"-",p->pid,p->summary);
        else if(COLS>=45)
            snprintf(b,sizeof b,"%c  %-12.12s %-7s %-4.4s %s",i==idx?'>':' ',p->timestamp,label,
                p->direction[0]?p->direction:"-",p->summary);
        else
            snprintf(b,sizeof b,"%c %.8s %-3.3s %s",i==idx?'>':' ',p->timestamp,
                p->direction[0]?p->direction:"-",p->summary);
        line_out(table_start+r,0,COLS-1,b,i==idx?(A_REVERSE|A_BOLD):A_NORMAL);
    }
    if(!count)line_out(table_start,0,COLS-1,"No matching packets yet",A_DIM);
    if(divider>table_start && divider<LINES-1)mvhline(divider,0,ACS_HLINE,COLS);
    if(LINES>=12)line_out(divider+1,1,COLS-2,"PACKET TEXT (PgUp/PgDn, h/l)",A_BOLD);
    draw_packet_text(find_packet(u->select_seq),u->detail_scroll,text_start,text_end,u->detail_x);
    status_bar("j/k packets | Enter follow/hold | PgUp/PgDn detail | h/l horizontal | Backspace back | q quit",
               "j/k pkt | Bksp back | PgUp/Dn text");
}
static void draw(UI *u) {
    erase();
    if(LINES<5 || COLS<20) {
        line_out(0,0,COLS-1,"netinspect: pane too small",A_BOLD);
        if(LINES>1)line_out(1,0,COLS-1,"Need 20x5; q quits",A_DIM);
        refresh();return;
    }
    pthread_mutex_lock(&G.mu);
    if(!u->screen)restore_selection(u);
    if(!u->screen)draw_sockets(u);
    else {
        Match *matches=malloc(PACKET_RING*sizeof *matches);
        if(matches){size_t n=matching_packets(&u->inspected,matches);
            draw_packets(u,matches,n);free(matches);}
    }
    pthread_mutex_unlock(&G.mu);
    refresh();
}
static void move_packet(UI *u,int dir) {
    pthread_mutex_lock(&G.mu);
    {
        Match matches[PACKET_RING];size_t n=matching_packets(&u->inspected,matches);
        if(n) {
            int index=-1;
            for(size_t i=0;i<n;i++)if(u->select_seq==matches[i].seq){index=(int)i;break;}
            if(index<0)index=(int)n-1;
            index+=dir;if(index<0)index=0;if(index>=(int)n)index=(int)n-1;
            u->select_seq=matches[index].seq;u->follow=0;u->detail_scroll=0;u->detail_x=0;
        }
    }
    pthread_mutex_unlock(&G.mu);
}
static void demo_data(void) {
    FILE *f=tmpfile();if(!f)return;
    fputs("p482\ncFirefox\nf40u\ntIPv4\nPTCP\nn192.168.1.10:53001->93.184.216.34:443\nTST=ESTABLISHED\n"
          "p641\ncssh\nf5u\ntIPv4\nPTCP\nn192.168.1.10:54322->10.0.0.8:22\nTST=ESTABLISHED\n"
          "p903\ncmDNSResponder\nf17u\ntIPv4\nPUDP\nn*:5353\n",f);
    rewind(f);G.socket_count=parse_lsof(f,G.sockets);fclose(f);
    copystr(G.lsof_status,sizeof G.lsof_status,"3 demonstration sockets");
    copystr(G.capture_status,sizeof G.capture_status,"DEMO MODE: sample data, not live capture");
    const char *samples[]={
        "11:36:13.121234 (en0, proc Firefox:482, out, so) IP 192.168.1.10.53001 > 93.184.216.34.443: Flags [P.], seq 1:89, ack 1, win 4096, length 88\n\t0x0000:  4500 0080 0001 4000 4006 0000 c0a8 010a  E.....@.@.......\n",
        "11:36:13.130123 (en0, proc Firefox:482, in, so) IP 93.184.216.34.443 > 192.168.1.10.53001: Flags [.], ack 89, win 2048, length 0\n\t0x0000:  4500 0028 0001 0000 4006 0000 5db8 d822  E..(....@...]..\n",
        "11:36:13.141988 (en0, proc ssh:641, out, so) IP 192.168.1.10.54322 > 10.0.0.8.22: Flags [P.], length 128\n\t0x0000:  4500 0044 1234 4000 4006 0000 0a00 0008  E..D.4@.@.......\n",
        "11:36:13.150129 (en0, proc mDNSResponder:903, out, so) IP 192.168.1.10.5353 > 224.0.0.251.5353: UDP, length 44\n\t0x0000:  4500 002c 0000 4000 4011 0000 c0a8 010a  E..,..@.@.......\n"
    };
    for(size_t i=0;i<sizeof samples/sizeof *samples;i++) {
        Packet p={0};parse_packet_line(&p,samples[i],1);push_packet(&p);
    }
}
static int self_test(void) {
    Endpoint e;int errs=0;
    errs += !endpoint_parse("[::1]:443",&e,0)||strcmp(e.address,"::1")||e.port!=443;
    errs += !endpoint_parse("192.168.1.2.55440",&e,1)||e.port!=55440;
    FILE *f=tmpfile();if(!f){perror("tmpfile");return 1;}
    fputs("p482\ncFirefox\nf40u\ntIPv4\nPTCP\nn192.168.1.10:53001->93.184.216.34:443\nTST=ESTABLISHED\n",f);
    rewind(f);Socket sockets[4]={0};size_t n=parse_lsof(f,sockets);fclose(f);
    errs += n!=1 || sockets[0].pid!=482 || sockets[0].local.port!=53001 || sockets[0].remote.port!=443;
    Packet p={0};
    parse_packet_line(&p,"11:36:13.121234 (en0, proc Firefox:482, out, so) IP 192.168.1.10.53001 > 93.184.216.34.443: Flags [P.], length 42\n",1);
    parse_packet_line(&p,"\t0x0000:  4500 0000 0000 4000 4006 0000\n",0);
    errs += p.pid!=482 || strcmp(p.process,"Firefox") || p.src.port!=53001 || strcmp(p.proto,"TCP") || packet_match(&sockets[0],&p)!=3;
    free(p.text);memset(&p,0,sizeof p);
    parse_packet_line(&p,"09:17:58.210959 pid dig.76987 svc BE IP 1.2.3.4.50000 > 8.8.8.8.53: UDP, length 44\n",1);
    errs += p.pid!=76987 || strcmp(p.process,"dig") || p.src.port!=50000 || strcmp(p.proto,"UDP");
    free(p.text);
    f=tmpfile();
    if(f) {
        fputs("COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"
              "Firefox 482 jay 40u IPv4 0x123 0t0 TCP 192.168.1.10:53001->93.184.216.34:443 (ESTABLISHED)\n"
              "mDNSRespo 903 jay 17u IPv6 0x124 0t0 UDP *:5353\n",f);
        rewind(f);memset(sockets,0,sizeof sockets);
        n=parse_lsof_table(f,sockets);fclose(f);
        errs+=n!=2 || sockets[0].pid!=482 || sockets[0].local.port!=53001 ||
            strcmp(sockets[0].state,"ESTABLISHED") || sockets[1].pid!=903;
    } else errs++;
    if(errs)fprintf(stderr,"self-test: %d failures\n",errs);
    else puts("self-test: endpoints, lsof field/table parsers, pktap PID, tcpdump flow, matching OK");
    return !!errs;
}
int main(int argc,char **argv) {
    int demo=0;
    for(int i=1;i<argc;i++) {
        if(!strcmp(argv[i],"--demo"))demo=1;
        else if(!strcmp(argv[i],"--self-test"))return self_test();
        else if(!strcmp(argv[i],"--probe-lsof")) return probe_lsof();
        else if(!strcmp(argv[i],"--help")) {
            puts("Usage: netinspect [--demo | --self-test | --probe-lsof]\n"
                 "  sudo -v && ./netinspect   # live on macOS\n"
                 "  ./netinspect --demo       # static UI demo without privileges\n"
                 "  ./netinspect --self-test  # parser and matching tests\n"
                 "  ./netinspect --probe-lsof # debug socket enumeration");return 0;
        } else {fprintf(stderr,"unknown option: %s\n",argv[i]);return 2;}
    }
#if !defined(__APPLE__) && !defined(__FreeBSD__) && !defined(__linux__)
    if(!demo) {fprintf(stderr,"Live pktap capture requires macOS; run --demo or --self-test here.\n");return 2;}
#endif
    signal(SIGINT,on_signal);signal(SIGTERM,on_signal);signal(SIGPIPE,SIG_IGN);
    pthread_t t1={0},t2={0};
    if(demo)demo_data();
    else {
        int rc1=pthread_create(&t1,NULL,lsof_worker,NULL);
        int rc2=pthread_create(&t2,NULL,tcpdump_worker,NULL);
        if(rc1 || rc2){
            fprintf(stderr,"Cannot start workers: lsof=%s, tcpdump=%s\n",
                rc1?strerror(rc1):"OK",rc2?strerror(rc2):"OK");
            pthread_mutex_lock(&G.mu);G.stop=1;pthread_mutex_unlock(&G.mu);
            if(!rc1)pthread_join(t1,NULL);
            if(!rc2)pthread_join(t2,NULL);
            return 1;
        }
    }
    initscr();cbreak();noecho();keypad(stdscr,TRUE);curs_set(0);timeout(150);
    UI u={0};
    while(!interrupted) {
        draw(&u);
        int c=getch();
        if(c==ERR||c==KEY_RESIZE)continue;
        if(c=='q'||c=='Q')break;
        if(!u.screen) {
            if(c==KEY_DOWN||c=='j') {
                pthread_mutex_lock(&G.mu);
                if(u.socket_index+1<(int)G.socket_count)u.socket_index++;
                if(G.socket_count)remember_socket(&u,&G.sockets[u.socket_index]);
                pthread_mutex_unlock(&G.mu);
            } else if(c==KEY_UP||c=='k') {
                pthread_mutex_lock(&G.mu);
                if(u.socket_index>0)u.socket_index--;
                if(G.socket_count)remember_socket(&u,&G.sockets[u.socket_index]);
                pthread_mutex_unlock(&G.mu);
            } else if(c=='\n'||c==KEY_ENTER||c=='\r') {
                pthread_mutex_lock(&G.mu);restore_selection(&u);
                if(G.socket_count) {u.inspected=G.sockets[u.socket_index];u.screen=1;u.follow=0;u.packet_top=0;u.select_seq=0;u.detail_scroll=0;
                    Match m[PACKET_RING];size_t n=matching_packets(&u.inspected,m);
                    if(n)u.select_seq=m[n-1].seq;
                }
                pthread_mutex_unlock(&G.mu);
            }
        } else {
            if(c==KEY_BACKSPACE||c==127||c==8) {u.screen=0;u.follow=0;}
            else if(c==KEY_DOWN||c=='j')move_packet(&u,1);
            else if(c==KEY_UP||c=='k')move_packet(&u,-1);
            else if(c==KEY_NPAGE||c==']')u.detail_scroll+=6;
            else if(c==KEY_PPAGE||c=='[') {u.detail_scroll-=6;if(u.detail_scroll<0)u.detail_scroll=0;}
            else if(c=='h') {u.detail_x-=8;if(u.detail_x<0)u.detail_x=0;}
            else if(c=='l')u.detail_x+=8;
            else if(c=='\n'||c==KEY_ENTER||c=='\r')u.follow=!u.follow;
        }
    }
    endwin();
    if(!demo) {
        pthread_mutex_lock(&G.mu);G.stop=1;pid_t pid=G.capture_pid;pthread_mutex_unlock(&G.mu);
        if(pid>0){kill(-pid,SIGTERM);kill(pid,SIGTERM);}
        pthread_join(t1,NULL);pthread_join(t2,NULL);
    }
    for(size_t i=0;i<PACKET_RING;i++)free(G.packets[i].text);
    pthread_mutex_destroy(&G.mu);
    return 0;
}
