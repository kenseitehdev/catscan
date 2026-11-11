#define _DARWIN_C_SOURCE 1
#define _DEFAULT_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#include "hardware.h"
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <pthread.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#if defined(__APPLE__)
#include <sys/sysctl.h>
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/ps/IOPowerSources.h>
#include <IOKit/ps/IOPSKeys.h>
#endif

static pthread_mutex_t hardware_lock=PTHREAD_MUTEX_INITIALIZER;
static MonHardware current={.battery_minutes=-1,.wifi_status="Wi-Fi: sampling...",
    .bt_status="Bluetooth: sampling...",.thermal_status="Thermal: sampling...",
    .battery_status="Battery: sampling..."};
static pthread_t worker;
static int hardware_started=0,hardware_stop=0;

static void copyval(char *dest,size_t size,const char *src){if(size)snprintf(dest,size,"%s",src?src:"");}
static char *strip(char *str){while(isspace((unsigned char)*str))str++;size_t n=strlen(str);while(n&&isspace((unsigned char)str[n-1]))str[--n]=0;return str;}
static int keyval(const char *line,const char *key,char *out,size_t n){
    /* Match a whole leading key, allowing whitespace before the colon. */
    while(isspace((unsigned char)*line))line++;
    size_t k=strlen(key);if(strncasecmp(line,key,k))return 0;
    line+=k;while(*line==' '||*line=='\t')line++;
    if(*line!=':')return 0;
    line++;while(*line==' '||*line=='\t')line++;
    copyval(out,n,line);return 1;
}
static void parse_wifi(const char *output,MonHardware *h){
    char *temp=strdup(output);if(!temp)return;
    char *save=NULL,*line=strtok_r(temp,"\n",&save),value[256];
    for(;line;line=strtok_r(NULL,"\n",&save)){
        if(keyval(line,"RSSI",value,sizeof value)){
            int r=atoi(value);if(r<0&&r>=-120){h->wifi_available=1;h->wifi_rssi=r;}
        }else if(keyval(line,"Noise",value,sizeof value)){
            int r=atoi(value);if(r<0&&r>=-130)h->wifi_noise=r;
        }else if(keyval(line,"Channel",value,sizeof value)){
            copyval(h->wifi_channel,sizeof h->wifi_channel,strip(value));h->wifi_channel_valid=1;
        }else if(keyval(line,"Tx Rate",value,sizeof value)||keyval(line,"Transmit Rate",value,sizeof value)){
            h->wifi_tx_mbps=atoi(value);
        }else if(keyval(line,"SSID",value,sizeof value)){
            if(strstr(value,"redacted"))copyval(h->wifi_ssid,sizeof h->wifi_ssid,"[redacted]");
            else copyval(h->wifi_ssid,sizeof h->wifi_ssid,strip(value));
        }
    }
    free(temp);
}
static void parse_bt(const char *output,MonHardware *h){
    char *temp=strdup(output);if(!temp)return;
    char *save=NULL,*line=strtok_r(temp,"\n",&save),value[256];
    for(;line;line=strtok_r(NULL,"\n",&save)){
        if(keyval(line,"State",value,sizeof value)){
            h->bt_available=1;h->bt_powered=!strncasecmp(value,"On",2);
        }else if(keyval(line,"Connected",value,sizeof value)){
            if(!strncasecmp(value,"Yes",3))h->bt_connected++;
        }
    }
    free(temp);
}
/* Capture bounded output without a shell, a terminal prompt, or long blocking reads.
 * All commands run on a collector thread, never in the ncurses render loop. */
#if defined(__APPLE__)
static int capture(char *const argv[],char *out,size_t cap,int timeout_ms){
    int p[2];if(pipe(p)<0)return -1;
    pid_t pid=fork();
    if(pid<0){close(p[0]);close(p[1]);return -1;}
    if(pid==0){setpgid(0,0);close(p[0]);dup2(p[1],STDOUT_FILENO);dup2(p[1],STDERR_FILENO);close(p[1]);
        execv(argv[0],argv);_exit(127);
    }
    close(p[1]);fcntl(p[0],F_SETFL,fcntl(p[0],F_GETFL)|O_NONBLOCK);
    size_t used=0;int elapsed=0,eof=0;
    while(elapsed<timeout_ms && used+1<cap){
        struct pollfd f={.fd=p[0],.events=POLLIN|POLLHUP};
        int ms=timeout_ms-elapsed;if(ms>200)ms=200;
        int r=poll(&f,1,ms);
        if(r<0 && errno!=EINTR)break;
        elapsed+=ms;
        if(r>0){
            for(;;){ssize_t n=read(p[0],out+used,cap-1-used);
                if(n>0){used+=(size_t)n;if(used+1>=cap)break;}
                else if(n==0){eof=1;break;}
                else if(errno!=EINTR){if(errno!=EAGAIN && errno!=EWOULDBLOCK)eof=1;break;}
            }
        }
        if(eof)break;
    }
    out[used]=0;close(p[0]);
    if(!eof || used+1>=cap){kill(-pid,SIGKILL);kill(pid,SIGKILL);}
    int status=0;while(waitpid(pid,&status,0)<0&&errno==EINTR){}
    return eof && WIFEXITED(status) && WEXITSTATUS(status)==0?0:-1;
}
static int cfnum(CFDictionaryRef d,CFStringRef key,int def){
    CFTypeRef v=CFDictionaryGetValue(d,key);
    int n=def;if(v && CFGetTypeID(v)==CFNumberGetTypeID())CFNumberGetValue((CFNumberRef)v,kCFNumberIntType,&n);
    return n;
}
static void sample_battery(MonHardware *h){
    h->battery_available=0;h->battery_minutes=-1;
    CFTypeRef source=IOPSCopyPowerSourcesInfo();if(!source)return;
    CFArrayRef sources=IOPSCopyPowerSourcesList(source);
    if(!sources){CFRelease(source);return;}
    for(CFIndex i=0;i<CFArrayGetCount(sources);i++){
        CFDictionaryRef d=IOPSGetPowerSourceDescription(source,CFArrayGetValueAtIndex(sources,i));
        if(!d)continue;
        CFTypeRef state=CFDictionaryGetValue(d,CFSTR(kIOPSPowerSourceStateKey));
        CFTypeRef present=CFDictionaryGetValue(d,CFSTR(kIOPSIsPresentKey));
        if(present && CFGetTypeID(present)==CFBooleanGetTypeID() && !CFBooleanGetValue((CFBooleanRef)present))continue;
        CFTypeRef type=CFDictionaryGetValue(d,CFSTR(kIOPSTypeKey));
        if(type && CFGetTypeID(type)==CFStringGetTypeID() && !CFEqual(type,CFSTR(kIOPSInternalBatteryType)))continue;
        h->battery_available=1;
        h->battery_pct=cfnum(d,CFSTR(kIOPSCurrentCapacityKey),0);
        h->on_ac=(state && CFEqual(state,CFSTR(kIOPSACPowerValue)));
        CFTypeRef charging=CFDictionaryGetValue(d,CFSTR(kIOPSIsChargingKey));
        h->charging=charging && CFGetTypeID(charging)==CFBooleanGetTypeID() && CFBooleanGetValue((CFBooleanRef)charging);
        h->battery_minutes=cfnum(d,(h->on_ac?CFSTR(kIOPSTimeToFullChargeKey):CFSTR(kIOPSTimeToEmptyKey)),-1);
        copyval(h->battery_status,sizeof h->battery_status,h->charging?"Charging":h->on_ac?"AC power":"On battery");
        break;
    }
    CFRelease(sources);CFRelease(source);
    if(!h->battery_available)copyval(h->battery_status,sizeof h->battery_status,"No internal battery");
}
static void sample_wifi(MonHardware *h){
    h->wifi_available=0;h->wifi_rssi=0;h->wifi_noise=0;h->wifi_tx_mbps=0;
    h->wifi_channel_valid=0;h->wifi_channel[0]=0;h->wifi_ssid[0]=0;
    char buffer[8192]={0};
    char *args[]={"/usr/bin/sudo","-n","/usr/bin/wdutil","info",NULL};
    int ok=capture(args,buffer,sizeof buffer,3500);
    parse_wifi(buffer,h);
    if(h->wifi_available){
        copyval(h->wifi_status,sizeof h->wifi_status,"Link signal from wdutil");h->wifi_samples++;
    }else if(strstr(buffer,"password")||strstr(buffer,"sudo"))
        copyval(h->wifi_status,sizeof h->wifi_status,"RSSI needs sudo -v");
    else if(ok<0)copyval(h->wifi_status,sizeof h->wifi_status,"Wi-Fi metrics unavailable");
    else copyval(h->wifi_status,sizeof h->wifi_status,"No active Wi-Fi RSSI reported");
}
static void sample_bt(MonHardware *h){
    h->bt_available=0;h->bt_powered=0;h->bt_connected=0;
    char buffer[32768]={0};
    char *args[]={"/usr/sbin/system_profiler","SPBluetoothDataType",NULL};
    int ok=capture(args,buffer,sizeof buffer,8500);
    if(ok==0){parse_bt(buffer,h);
        if(h->bt_available)snprintf(h->bt_status,sizeof h->bt_status,"%s | %d connected",h->bt_powered?"On":"Off",h->bt_connected);
        else copyval(h->bt_status,sizeof h->bt_status,"Bluetooth state not reported");
    }else copyval(h->bt_status,sizeof h->bt_status,"Bluetooth scan unavailable");
}
static void sample_thermal(MonHardware *h){
    h->thermal_available=0;h->temperature_available=0;h->thermal_state[0]=0;
    char buffer[4096]={0};
    char *args[]={"/usr/bin/sudo","-n","/usr/bin/powermetrics","--samplers","thermal","-n","1","-i","1000",NULL};
    int ok=capture(args,buffer,sizeof buffer,4300);
    if(ok==0){
        char *s=strstr(buffer,"pressure level:");
        if(s){s+=strlen("pressure level:");while(*s==' ')s++;
            char name[48];size_t i=0;while(s[i] && s[i]!='\n' && i<sizeof name-1){name[i]=s[i];i++;}name[i]=0;
            copyval(h->thermal_state,sizeof h->thermal_state,strip(name));h->thermal_available=1;
        }
        s=strstr(buffer,"CPU die temperature:");
        if(s){double t=0;if(sscanf(s+strlen("CPU die temperature:"),"%lf",&t)==1 && t>0 && t<150){h->temperature_available=1;h->cpu_temperature_c=t;}}
    }
    if(h->thermal_available)copyval(h->thermal_status,sizeof h->thermal_status,"Thermal pressure (powermetrics)");
    else copyval(h->thermal_status,sizeof h->thermal_status,"Thermal pressure unavailable (sudo -v)");
}
#endif
static void publish(const MonHardware *h){
    pthread_mutex_lock(&hardware_lock);current=*h;pthread_mutex_unlock(&hardware_lock);
}
static void *hardware_worker(void *unused){
    (void)unused;unsigned tick=0;
    while(1){
        pthread_mutex_lock(&hardware_lock);int stop=hardware_stop;pthread_mutex_unlock(&hardware_lock);
        if(stop)break;
        MonHardware next;mon_hardware_snapshot(&next);
#if defined(__APPLE__)
        if(tick==0){
            size_t size=sizeof next.model;
            if(sysctlbyname("hw.model",next.model,&size,NULL,0)!=0)copyval(next.model,sizeof next.model,"macOS");
        }
        sample_battery(&next);publish(&next);
        if(tick%10==0){sample_wifi(&next);publish(&next);}
        if(tick%30==0){sample_bt(&next);publish(&next);}
        if(tick%20==0){sample_thermal(&next);publish(&next);}
#else
        copyval(next.wifi_status,sizeof next.wifi_status,"macOS only");
        copyval(next.bt_status,sizeof next.bt_status,"macOS only");
        copyval(next.thermal_status,sizeof next.thermal_status,"macOS only");
        copyval(next.battery_status,sizeof next.battery_status,"macOS only");
#endif
        publish(&next);
        for(int i=0;i<10;i++){
            pthread_mutex_lock(&hardware_lock);stop=hardware_stop;pthread_mutex_unlock(&hardware_lock);
            if(stop)break;
            struct timespec ts={.tv_sec=0,.tv_nsec=100000000};nanosleep(&ts,NULL);
        }
        tick++;
    }
    return NULL;
}
int mon_hardware_start(void){
    pthread_mutex_lock(&hardware_lock);hardware_stop=0;pthread_mutex_unlock(&hardware_lock);
    int err=pthread_create(&worker,NULL,hardware_worker,NULL);
    if(!err)hardware_started=1;
    return err;
}
void mon_hardware_snapshot(MonHardware *out){
    pthread_mutex_lock(&hardware_lock);*out=current;pthread_mutex_unlock(&hardware_lock);
}
void mon_hardware_stop(void){
    if(!hardware_started)return;
    pthread_mutex_lock(&hardware_lock);hardware_stop=1;pthread_mutex_unlock(&hardware_lock);
    pthread_join(worker,NULL);hardware_started=0;
}
int mon_hardware_self_test(void){
    MonHardware h={0};
    parse_wifi(" RSSI: -54 dBm\n Noise: -95 dBm\n Channel: 36\n Tx Rate: 1200 Mbps\n SSID: TestLab\n",&h);
    parse_bt(" State: On\n  Connected: Yes\n  Connected: No\n  Connected: Yes\n",&h);
    int fail=!h.wifi_available || h.wifi_rssi!=-54 || h.wifi_noise!=-95 || h.wifi_tx_mbps!=1200 ||
        strcmp(h.wifi_ssid,"TestLab") || !h.bt_available || !h.bt_powered || h.bt_connected!=2;
    printf("Hardware parsers: %s\n",fail?"FAILED":"OK");
    return fail;
}
